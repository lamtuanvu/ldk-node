// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

pub(crate) mod bitcoind;
mod cbf;
mod electrum;
mod esplora;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::{Script, Transaction, Txid};
use lightning::chain::{BlockLocator, Filter};

use crate::chain::bitcoind::{BitcoindChainSource, ChainListener, UtxoSourceClient};
use crate::chain::cbf::CbfChainSource;
use crate::chain::electrum::ElectrumChainSource;
use crate::chain::esplora::EsploraChainSource;
use crate::config::{
	BackgroundSyncConfig, BitcoindRestClientConfig, Config, ElectrumSyncConfig, EsploraSyncConfig,
	WALLET_SYNC_INTERVAL_MINIMUM_SECS,
};
use crate::fee_estimator::OnchainFeeEstimator;
use crate::logger::{log_debug, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::runtime::Runtime;
use crate::types::{Broadcaster, ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, PersistedNodeMetrics};

/// We use this parent-child TRUC package to make sure the configured chain source supports
/// broadcasting packages via the `submitpackage` Bitcoin Core RPC.
const PARENT_TXID: &str = "9a015f93fac6cb203c2b994e18b85176eb0354a22a468255516f3c6002d3f696";
const PARENT_HEX: &str =
	"0300000000010160d0cdb72f2ddf719f40ca32f44614c67577fc75996140544003915683c34a310000000000fd\
	ffffff0201000000000000000451024e73876100000000000022512042731375894dad3b25092cd0f713dc5bee4\
	a71e30a95e1db3d880906d7eba1fa01409327942924218e4eb1635a7cce6706fcb37b8bbb61a2f0b86357356681\
	4e09419a3501e02252043bb237d479304632282fe9159db9e9a6ae6ec5bedea9f0f115a97b0e00";
const CHILD_TXID: &str = "d011b3ff78cdfb8b93822639ea87771847936b04bb83afc8763a7c02a386ae26";
const CHILD_HEX: &str =
	"0300000000010296f6d302603c6f515582462aa25403eb7651b8184e992b3c20cbc6fa935f019a0000000000ff\
	ffffff96f6d302603c6f515582462aa25403eb7651b8184e992b3c20cbc6fa935f019a0100000000fdffffff015\
	660000000000000225120ac18cd599a1be003595854e2eeec18dbe1c92d04b0ba05812d04445e3fcf16bc000140\
	1462a35808d77a164f0a23a84c4721d1545befd09ad19945bb8aa0ea5576953a9699038725f944b1bc429942ef4\
	7e6504a554babf022cb15db53be2d8c1dbfe5a97b0e00";

fn dummy_package() -> [bitcoin::Transaction; 2] {
	use bitcoin::consensus::Decodable;
	use bitcoin::hex::FromHex;
	use bitcoin::Transaction;
	let parent_tx_bytes = Vec::from_hex(PARENT_HEX).expect("read from a constant");
	let child_tx_bytes = Vec::from_hex(CHILD_HEX).expect("read from a constant");
	let parent =
		Transaction::consensus_decode(&mut &parent_tx_bytes[..]).expect("read from a constant");
	let child =
		Transaction::consensus_decode(&mut &child_tx_bytes[..]).expect("read from a constant");
	assert_eq!(parent.compute_txid().to_string(), PARENT_TXID);
	assert_eq!(child.compute_txid().to_string(), CHILD_TXID);
	[parent, child]
}

pub(crate) enum WalletSyncStatus {
	Completed,
	InProgress { subscribers: tokio::sync::broadcast::Sender<Result<(), Error>> },
}

impl WalletSyncStatus {
	fn register_or_subscribe_pending_sync(
		&mut self,
	) -> Option<tokio::sync::broadcast::Receiver<Result<(), Error>>> {
		match self {
			WalletSyncStatus::Completed => {
				// We're first to register for a sync.
				let (tx, _) = tokio::sync::broadcast::channel(1);
				*self = WalletSyncStatus::InProgress { subscribers: tx };
				None
			},
			WalletSyncStatus::InProgress { subscribers } => {
				// A sync is in-progress, we subscribe.
				let rx = subscribers.subscribe();
				Some(rx)
			},
		}
	}

	fn propagate_result_to_subscribers(&mut self, res: Result<(), Error>) {
		// Send the notification to any other tasks that might be waiting on it by now.
		{
			match self {
				WalletSyncStatus::Completed => {
					// No sync in-progress, do nothing.
					return;
				},
				WalletSyncStatus::InProgress { subscribers } => {
					// A sync is in-progress, we notify subscribers.
					if subscribers.receiver_count() > 0 {
						match subscribers.send(res) {
							Ok(_) => (),
							Err(e) => {
								debug_assert!(
									false,
									"Failed to send wallet sync result to subscribers: {:?}",
									e
								);
							},
						}
					}
					*self = WalletSyncStatus::Completed;
				},
			}
		}
	}
}

/// Optional external fee estimation backend for the CBF chain source.
///
/// By default CBF derives fee rates from recent blocks' coinbase outputs.
/// Setting an external source provides more accurate, per-target estimates
/// from a mempool-aware server.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CbfFeeSourceConfig {
	/// Use an Esplora HTTP server for fee rate estimation.
	Esplora(String),
	/// Use an Electrum server for fee rate estimation.
	Electrum(String),
}

/// A future resolving to per-conf-target (blocks) fee estimates in sat/vB, or `Err(())` if the
/// external chain service could not provide them this cycle.
pub type FeeEstimatesFuture = std::pin::Pin<
	Box<dyn std::future::Future<Output = Result<std::collections::HashMap<u16, f64>, ()>> + Send>,
>;
/// A future resolving to `Ok(())` if the external chain service accepted a raw-tx broadcast, or
/// `Err(())` to fall back to the node's own P2P broadcast.
pub type BroadcastFuture =
	std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ()>> + Send>>;

/// App-supplied hooks that let an external chain service short-circuit the CBF chain source's
/// native fee estimation and P2P transaction broadcast.
///
/// Only meaningful when paired with the CBF chain source (see
/// [`crate::builder::NodeBuilder::set_cbf_chain_service_hooks`]); ignored for every other chain
/// source. This type is payment-agnostic — the fork never learns about L402, or any other
/// payment protocol a caller might use to obtain fee data or relay a broadcast.
#[derive(Clone, Default)]
pub struct ChainServiceHooks {
	/// conf-target (blocks) → sat/vB. Err/None → fall through to fee_source / block-derived.
	pub fee_estimates: Option<std::sync::Arc<dyn Fn() -> FeeEstimatesFuture + Send + Sync>>,
	/// Attempt external broadcast of raw txs. Err → fall through to P2P broadcast.
	pub broadcast:
		Option<std::sync::Arc<dyn Fn(Vec<Transaction>) -> BroadcastFuture + Send + Sync>>,
}

impl std::fmt::Debug for ChainServiceHooks {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ChainServiceHooks")
			.field("fee_estimates", &self.fee_estimates.is_some())
			.field("broadcast", &self.broadcast.is_some())
			.finish()
	}
}

pub(crate) struct ChainSource {
	kind: ChainSourceKind,
	registered_txids: Mutex<HashSet<Txid>>,
	tx_broadcaster: Arc<Broadcaster>,
	logger: Arc<Logger>,
}

enum ChainSourceKind {
	Esplora(EsploraChainSource),
	Electrum(ElectrumChainSource),
	Bitcoind(BitcoindChainSource),
	Cbf(CbfChainSource),
}

impl ChainSource {
	/// Returns the shared on-chain fee estimator backing this chain source
	/// (Peerswap native primitive B6). Used by [`crate::Node`] to surface
	/// source-bearing swap feerate quotes.
	#[cfg(feature = "swaps")]
	pub(crate) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => esplora_chain_source.fee_estimator(),
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.fee_estimator()
			},
			ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
				bitcoind_chain_source.fee_estimator()
			},
			ChainSourceKind::Cbf(cbf_chain_source) => cbf_chain_source.fee_estimator(),
		}
	}

	pub(crate) fn new_esplora(
		server_url: String, headers: HashMap<String, String>, sync_config: EsploraSyncConfig,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<PersistedNodeMetrics>,
	) -> Result<(Self, Option<BlockLocator>), ()> {
		let esplora_chain_source = EsploraChainSource::new(
			server_url,
			headers,
			sync_config,
			fee_estimator,
			kv_store,
			config,
			Arc::clone(&logger),
			node_metrics,
		)?;
		let kind = ChainSourceKind::Esplora(esplora_chain_source);
		let registered_txids = Mutex::new(HashSet::new());
		Ok((Self { kind, registered_txids, tx_broadcaster, logger }, None))
	}

	pub(crate) fn new_electrum(
		server_url: String, sync_config: ElectrumSyncConfig,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<PersistedNodeMetrics>,
	) -> (Self, Option<BlockLocator>) {
		let electrum_chain_source = ElectrumChainSource::new(
			server_url,
			sync_config,
			fee_estimator,
			kv_store,
			config,
			Arc::clone(&logger),
			node_metrics,
		);
		let kind = ChainSourceKind::Electrum(electrum_chain_source);
		let registered_txids = Mutex::new(HashSet::new());
		(Self { kind, registered_txids, tx_broadcaster, logger }, None)
	}

	pub(crate) async fn new_bitcoind_rpc(
		rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<PersistedNodeMetrics>,
	) -> (Self, Option<BlockLocator>) {
		let bitcoind_chain_source = BitcoindChainSource::new_rpc(
			rpc_host,
			rpc_port,
			rpc_user,
			rpc_password,
			fee_estimator,
			kv_store,
			config,
			Arc::clone(&logger),
			node_metrics,
		);
		let best_block = bitcoind_chain_source.poll_best_block().await.ok();
		let kind = ChainSourceKind::Bitcoind(bitcoind_chain_source);
		let registered_txids = Mutex::new(HashSet::new());
		(Self { kind, registered_txids, tx_broadcaster, logger }, best_block)
	}

	pub(crate) async fn new_bitcoind_rest(
		rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, rest_client_config: BitcoindRestClientConfig,
		logger: Arc<Logger>, node_metrics: Arc<PersistedNodeMetrics>,
	) -> (Self, Option<BlockLocator>) {
		let bitcoind_chain_source = BitcoindChainSource::new_rest(
			rpc_host,
			rpc_port,
			rpc_user,
			rpc_password,
			fee_estimator,
			kv_store,
			config,
			rest_client_config,
			Arc::clone(&logger),
			node_metrics,
		);
		let best_block = bitcoind_chain_source.poll_best_block().await.ok();
		let kind = ChainSourceKind::Bitcoind(bitcoind_chain_source);
		let registered_txids = Mutex::new(HashSet::new());
		(Self { kind, registered_txids, tx_broadcaster, logger }, best_block)
	}

	pub(crate) fn new_cbf(
		peers: Vec<String>, fee_source_config: Option<CbfFeeSourceConfig>,
		wallet_rescan_from_height: Option<u32>, runtime: Arc<Runtime>,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<PersistedNodeMetrics>, chain_service_hooks: ChainServiceHooks,
	) -> Result<(Self, Option<BlockLocator>), Error> {
		let birthday_tip =
			cbf::resolve_birthday(&logger, config.network, wallet_rescan_from_height);
		let cbf_chain_source = CbfChainSource::new(
			peers,
			fee_source_config,
			runtime,
			Arc::clone(&fee_estimator),
			Arc::clone(&kv_store),
			Arc::clone(&config),
			Arc::clone(&logger),
			Arc::clone(&node_metrics),
			chain_service_hooks,
		)?;
		let kind = ChainSourceKind::Cbf(cbf_chain_source);
		let registered_txids = Mutex::new(HashSet::new());
		Ok((Self { kind, registered_txids, tx_broadcaster, logger }, birthday_tip))
	}

	pub(crate) fn start(
		&self, runtime: Arc<Runtime>, onchain_wallet: Arc<Wallet>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		match &self.kind {
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.start(runtime)?
			},
			ChainSourceKind::Cbf(cbf_chain_source) => {
				let chain_listener = ChainListener {
					onchain_wallet,
					channel_manager,
					chain_monitor,
					output_sweeper,
					logger: Arc::clone(&self.logger),
					divergence: Arc::new(Mutex::new(None)),
				};
				cbf_chain_source.start(chain_listener);
			},
			_ => {
				// Nothing to do for other chain sources.
			},
		}
		Ok(())
	}

	pub(crate) fn stop(&self) {
		match &self.kind {
			ChainSourceKind::Electrum(electrum_chain_source) => electrum_chain_source.stop(),
			ChainSourceKind::Cbf(cbf_chain_source) => cbf_chain_source.stop(),
			_ => {
				// Nothing to do for other chain sources.
			},
		}
	}

	pub(crate) fn as_utxo_source(&self) -> Option<UtxoSourceClient> {
		match &self.kind {
			ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
				Some(bitcoind_chain_source.as_utxo_source())
			},
			_ => None,
		}
	}

	pub(crate) fn registered_txids(&self) -> HashSet<Txid> {
		self.registered_txids.lock().expect("lock").clone()
	}

	pub(crate) fn is_transaction_based(&self) -> bool {
		match &self.kind {
			ChainSourceKind::Esplora(_) => true,
			ChainSourceKind::Electrum { .. } => true,
			ChainSourceKind::Bitcoind { .. } => false,
			ChainSourceKind::Cbf { .. } => false,
		}
	}

	pub(crate) async fn continuously_sync_wallets(
		&self, stop_sync_receiver: tokio::sync::watch::Receiver<()>, onchain_wallet: Arc<Wallet>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) {
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				if let Some(background_sync_config) =
					esplora_chain_source.sync_config.background_sync_config.as_ref()
				{
					self.start_tx_based_sync_loop(
						stop_sync_receiver,
						onchain_wallet,
						channel_manager,
						chain_monitor,
						output_sweeper,
						background_sync_config,
						Arc::clone(&self.logger),
					)
					.await
				} else {
					// Background syncing is disabled
					log_info!(
                        self.logger,
                        "Background syncing is disabled. Manual syncing required for onchain wallet, lightning wallet, and fee rate updates.",
                    );
					return;
				}
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				if let Some(background_sync_config) =
					electrum_chain_source.sync_config.background_sync_config.as_ref()
				{
					self.start_tx_based_sync_loop(
						stop_sync_receiver,
						onchain_wallet,
						channel_manager,
						chain_monitor,
						output_sweeper,
						background_sync_config,
						Arc::clone(&self.logger),
					)
					.await
				} else {
					// Background syncing is disabled
					log_info!(
                        self.logger,
                        "Background syncing is disabled. Manual syncing required for onchain wallet, lightning wallet, and fee rate updates.",
                    );
					return;
				}
			},
			ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
				bitcoind_chain_source
					.continuously_sync_wallets(
						stop_sync_receiver,
						onchain_wallet,
						channel_manager,
						chain_monitor,
						output_sweeper,
					)
					.await
			},
			ChainSourceKind::Cbf(cbf_chain_source) => {
				//CBF cannot run without background syncing, when the chain source is running, it
				//syncs. Thus we don't have anything similar to other chain sources.
				cbf_chain_source.continuously_update_fee_rate_estimates(stop_sync_receiver).await
			},
		}
	}

	async fn start_tx_based_sync_loop(
		&self, mut stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
		background_sync_config: &BackgroundSyncConfig, logger: Arc<Logger>,
	) {
		// Setup syncing intervals
		let onchain_wallet_sync_interval_secs = background_sync_config
			.onchain_wallet_sync_interval_secs
			.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS);
		let mut onchain_wallet_sync_interval =
			tokio::time::interval(Duration::from_secs(onchain_wallet_sync_interval_secs));
		onchain_wallet_sync_interval
			.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		let fee_rate_cache_update_interval_secs = background_sync_config
			.fee_rate_cache_update_interval_secs
			.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS);
		let mut fee_rate_update_interval =
			tokio::time::interval(Duration::from_secs(fee_rate_cache_update_interval_secs));
		// When starting up, we just blocked on updating, so skip the first tick.
		fee_rate_update_interval.reset();
		fee_rate_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		let lightning_wallet_sync_interval_secs = background_sync_config
			.lightning_wallet_sync_interval_secs
			.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS);
		let mut lightning_wallet_sync_interval =
			tokio::time::interval(Duration::from_secs(lightning_wallet_sync_interval_secs));
		lightning_wallet_sync_interval
			.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		// Start the syncing loop.
		loop {
			tokio::select! {
				_ = stop_sync_receiver.changed() => {
					log_trace!(
						logger,
						"Stopping background syncing on-chain wallet.",
					);
					return;
				}
				_ = onchain_wallet_sync_interval.tick() => {
					let _ = self.sync_onchain_wallet(Arc::clone(&onchain_wallet)).await;
				}
				_ = fee_rate_update_interval.tick() => {
					let _ = self.update_fee_rate_estimates().await;
				}
				_ = lightning_wallet_sync_interval.tick() => {
					let _ = self.sync_lightning_wallet(
						Arc::clone(&channel_manager),
						Arc::clone(&chain_monitor),
						Arc::clone(&output_sweeper),
					).await;
				}
			}
		}
	}

	// Synchronize the onchain wallet via transaction-based protocols (i.e., Esplora, Electrum,
	// etc.)
	pub(crate) async fn sync_onchain_wallet(
		&self, onchain_wallet: Arc<Wallet>,
	) -> Result<(), Error> {
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				esplora_chain_source.sync_onchain_wallet(onchain_wallet).await
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.sync_onchain_wallet(onchain_wallet).await
			},
			ChainSourceKind::Bitcoind { .. } => {
				// In BitcoindRpc mode we sync lightning and onchain wallet in one go via
				// `ChainPoller`. So nothing to do here.
				unreachable!("Onchain wallet will be synced via chain polling")
			},
			ChainSourceKind::Cbf { .. } => {
				unreachable!("Onchain wallet synchronizes in background")
			},
		}
	}

	// Synchronize the Lightning wallet via transaction-based protocols (i.e., Esplora, Electrum,
	// etc.)
	pub(crate) async fn sync_lightning_wallet(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				esplora_chain_source
					.sync_lightning_wallet(channel_manager, chain_monitor, output_sweeper)
					.await
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source
					.sync_lightning_wallet(channel_manager, chain_monitor, output_sweeper)
					.await
			},
			ChainSourceKind::Bitcoind { .. } => {
				// In BitcoindRpc mode we sync lightning and onchain wallet in one go via
				// `ChainPoller`. So nothing to do here.
				unreachable!("Lightning wallet will be synced via chain polling")
			},
			ChainSourceKind::Cbf { .. } => {
				unreachable!("Lightning wallet synchronizes in background")
			},
		}
	}

	pub(crate) async fn poll_and_update_listeners(
		&self, onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		match &self.kind {
			ChainSourceKind::Esplora { .. } => {
				// In Esplora mode we sync lightning and onchain wallets via
				// `sync_onchain_wallet` and `sync_lightning_wallet`. So nothing to do here.
				unreachable!("Listeners will be synced via transction-based syncing")
			},
			ChainSourceKind::Electrum { .. } => {
				// In Electrum mode we sync lightning and onchain wallets via
				// `sync_onchain_wallet` and `sync_lightning_wallet`. So nothing to do here.
				unreachable!("Listeners will be synced via transction-based syncing")
			},
			ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
				bitcoind_chain_source
					.poll_and_update_listeners(
						onchain_wallet,
						channel_manager,
						chain_monitor,
						output_sweeper,
					)
					.await
			},
			ChainSourceKind::Cbf(cbf_chain_source) => cbf_chain_source.wait_until_synced().await,
		}
	}

	pub(crate) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				esplora_chain_source.update_fee_rate_estimates().await
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.update_fee_rate_estimates().await
			},
			ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
				bitcoind_chain_source.update_fee_rate_estimates().await
			},
			ChainSourceKind::Cbf(cbf_chain_source) => {
				cbf_chain_source.update_fee_rate_estimates().await
			},
		}
	}

	pub(crate) async fn validate_zero_fee_commitments_support_if_required(
		&self, zero_fee_commitments_support_required: bool,
	) -> Result<(), Error> {
		if !zero_fee_commitments_support_required {
			return Ok(());
		}

		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				esplora_chain_source.validate_zero_fee_commitments_support().await
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.validate_zero_fee_commitments_support().await
			},
			ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
				bitcoind_chain_source.validate_zero_fee_commitments_support().await
			},
			ChainSourceKind::Cbf(_) => {
				log_error!(
					self.logger,
					"CBF chain sources cannot verify zero-fee commitment package relay support"
				);
				Err(Error::ChainSourceNotSupported)
			},
		}
	}

	pub(crate) async fn continuously_process_broadcast_queue(
		&self, mut stop_tx_bcast_receiver: tokio::sync::watch::Receiver<()>,
	) {
		let mut receiver = self.tx_broadcaster.get_broadcast_queue().await;
		loop {
			let tx_bcast_logger = Arc::clone(&self.logger);
			tokio::select! {
				_ = stop_tx_bcast_receiver.changed() => {
					log_debug!(
						tx_bcast_logger,
						"Stopping broadcasting transactions.",
					);
					return;
				}
				Some(next_package) = receiver.recv() => {
					// Classify funding broadcasts into payment records before sending. If
					// classification fails we skip the broadcast, since broadcasting a tx we
					// failed to record would leave it on-chain without a payment.
					let package = match self.tx_broadcaster.classify_package(next_package).await {
						Ok(package) => package,
						Err(e) => {
							log_error!(
								tx_bcast_logger,
								"Skipping broadcast: failed to persist payment records: {:?}",
								e,
							);
							continue;
						},
					};
					let package = package.into_sorted_transactions();
					match &self.kind {
						ChainSourceKind::Esplora(esplora_chain_source) => {
							esplora_chain_source.process_transaction_broadcast(package).await
						},
						ChainSourceKind::Electrum(electrum_chain_source) => {
							electrum_chain_source.process_transaction_broadcast(package).await
						},
						ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
							bitcoind_chain_source.process_transaction_broadcast(package).await
						},
						ChainSourceKind::Cbf(cbf_chain_source) => {
							cbf_chain_source
								.process_broadcast_package(package.into_inner())
								.await
						},
					}
				}
			}
		}
	}

	/// Reorg-aware confirmation/eviction query for an ARBITRARY `txid` (Peerswap
	/// native primitive B5).
	///
	/// Unlike the wallet-owned confirmation lookups, this works on a
	/// counterparty's swap opening tx that the local wallet does not own. It
	/// returns a backend-agnostic [`RawTxObservation`]; the caller
	/// ([`crate::Node::get_tx_confirmations`]) folds in the previously-observed
	/// confirmation anchor to distinguish a first `Mempool`/`Dropped` sighting
	/// from a `Reorged` un-confirmation.
	///
	/// FAIL-CLOSED (E6): any chain source that cannot answer — an unstarted
	/// backend client, a transport error, or a missing scriptPubKey for the
	/// Electrum scriptHash lookup — yields [`RawTxObservation::Unreachable`], so
	/// the public API never reports a falsely-confirmed result.
	#[cfg(feature = "swaps")]
	pub(crate) async fn swap_query_tx(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> RawTxObservation {
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				esplora_chain_source.swap_query_tx(txid).await
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.swap_query_tx(txid, script_pubkey).await
			},
			ChainSourceKind::Bitcoind(bitcoind_chain_source) => {
				bitcoind_chain_source.swap_query_tx(txid).await
			},
			ChainSourceKind::Cbf(_) => {
				// BIP157 cannot query arbitrary raw transactions; PeerSwap is
				// unavailable under CBF (fail-closed, spec E6).
				RawTxObservation::Unreachable
			},
		}
	}
}

impl Filter for ChainSource {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.registered_txids.lock().expect("lock").insert(*txid);
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				esplora_chain_source.register_tx(txid, script_pubkey)
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.register_tx(txid, script_pubkey)
			},
			ChainSourceKind::Bitcoind { .. } => (),
			ChainSourceKind::Cbf(cbf_chain_source) => {
				cbf_chain_source.register_tx(txid, script_pubkey);
			},
		}
	}
	fn register_output(&self, output: lightning::chain::WatchedOutput) {
		match &self.kind {
			ChainSourceKind::Esplora(esplora_chain_source) => {
				esplora_chain_source.register_output(output)
			},
			ChainSourceKind::Electrum(electrum_chain_source) => {
				electrum_chain_source.register_output(output)
			},
			ChainSourceKind::Bitcoind { .. } => (),
			ChainSourceKind::Cbf(cbf_chain_source) => {
				cbf_chain_source.register_output(output);
			},
		}
	}
}

#[cfg(feature = "swaps")]
use bitcoin::{Network, ScriptBuf};

// ============================================================================
// Peerswap native primitive B5 — reorg-aware per-txid confirmation tracking.
//
// `register_tx`/`onchain_tx_confirmations` only cover wallet-owned txids; a
// swap taker must verify the *counterparty's* opening tx, which the wallet does
// not own. The types and helpers below add a brand-new, reorg-aware, per-txid
// chain query over whichever chain source the deployment configured
// (Esplora/Electrum/Bitcoind), and FAIL CLOSED (never a falsely-confirmed
// result) when that source cannot answer (E6). Everything here is gated behind
// the `swaps` cargo feature so the default build is byte-for-byte unaffected.
// ============================================================================

/// Reorg-aware chain status of a watched transaction (Peerswap native
/// primitive B5).
///
/// [`ChainStatus::NoChainSource`] is the fail-closed sentinel returned when the
/// configured chain source cannot answer — it is never conflated with a
/// confirmed result (E6). [`ChainStatus::Reorged`] is reported when a tx that
/// was previously observed confirmed is no longer in the best chain, so the
/// caller can re-anchor CSV/claim deadlines (F4).
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStatus {
	/// Included in a block on the current best chain.
	Confirmed,
	/// Known to the chain source but still unconfirmed (in the mempool).
	Mempool,
	/// Previously observed confirmed, but no longer in the best chain (re-orged
	/// back to the mempool or evicted). Deadlines must be re-anchored.
	Reorged,
	/// Unknown to the chain source and never observed confirmed (never broadcast
	/// or evicted from the mempool before confirming).
	Dropped,
	/// The chain source is unconfigured/unreachable and could not answer. The
	/// caller MUST treat this as "unverifiable", never as confirmed
	/// (fail-closed, E6).
	NoChainSource,
}

#[cfg(feature = "swaps")]
impl ChainStatus {
	/// Stable lowercase string form for capability payloads and logs.
	pub fn as_str(&self) -> &'static str {
		match self {
			ChainStatus::Confirmed => "confirmed",
			ChainStatus::Mempool => "mempool",
			ChainStatus::Reorged => "reorged",
			ChainStatus::Dropped => "dropped",
			ChainStatus::NoChainSource => "no_chain_source",
		}
	}
}

/// Reorg-aware confirmation/eviction status of a watched transaction
/// (Peerswap native primitive B5).
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxStatus {
	/// Confirmation depth on the current best chain (`0` when unconfirmed,
	/// reorged, dropped, or unverifiable).
	pub confirmations: u32,
	/// Height of the confirming block, re-derived from the current best chain
	/// (`None` when unconfirmed/reorged/dropped/unverifiable).
	pub height: Option<u32>,
	/// Reorg-aware chain status.
	pub status: ChainStatus,
}

/// Backend-agnostic raw observation of a `txid` against a chain source, before
/// the previously-observed confirmation anchor is folded in (Peerswap B5).
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawTxObservation {
	/// Included in a best-chain block at the given height/depth.
	Confirmed { height: Option<u32>, confirmations: u32 },
	/// Known to the chain source but unconfirmed.
	InMempool,
	/// Unknown to the chain source.
	NotFound,
	/// The chain source could not answer (fail-closed sentinel, E6).
	Unreachable,
}

/// Fold a raw observation together with whether the tx was previously observed
/// confirmed into the reorg-aware [`TxStatus`] (Peerswap B5).
///
/// Pure function — unit-tested independently of any live chain source. The
/// load-bearing invariant: a [`RawTxObservation::Unreachable`] can never become
/// [`ChainStatus::Confirmed`], regardless of prior confirmation history.
#[cfg(feature = "swaps")]
pub(crate) fn derive_tx_status(
	observation: RawTxObservation, previously_confirmed: bool,
) -> TxStatus {
	match observation {
		RawTxObservation::Confirmed { height, confirmations } => TxStatus {
			// A tx in the tip block is 1 confirmation deep, never 0.
			confirmations: confirmations.max(1),
			height,
			status: ChainStatus::Confirmed,
		},
		RawTxObservation::InMempool => TxStatus {
			confirmations: 0,
			height: None,
			status: if previously_confirmed { ChainStatus::Reorged } else { ChainStatus::Mempool },
		},
		RawTxObservation::NotFound => TxStatus {
			confirmations: 0,
			height: None,
			status: if previously_confirmed { ChainStatus::Reorged } else { ChainStatus::Dropped },
		},
		RawTxObservation::Unreachable => {
			TxStatus { confirmations: 0, height: None, status: ChainStatus::NoChainSource }
		},
	}
}

/// In-memory registry of swap txids being watched (Peerswap B5).
///
/// Stores the scriptPubKey (required by the Electrum scriptHash lookup) and the
/// last observed confirmation height, which lets
/// [`crate::Node::get_tx_confirmations`] distinguish a first unconfirmed
/// sighting from a reorg-induced un-confirmation. Durable reorg state
/// additionally lives in the native `swap.db` on the consumer side; this cache
/// is best-effort and is rebuilt by re-registering after a restart.
#[cfg(feature = "swaps")]
pub(crate) struct SwapTxWatch {
	entries: Mutex<HashMap<Txid, SwapWatchEntry>>,
}

#[cfg(feature = "swaps")]
#[derive(Clone)]
struct SwapWatchEntry {
	script_pubkey: ScriptBuf,
	last_confirmed_height: Option<u32>,
}

#[cfg(feature = "swaps")]
impl SwapTxWatch {
	pub(crate) fn new() -> Self {
		Self { entries: Mutex::new(HashMap::new()) }
	}

	/// Register (idempotently) a txid + its scriptPubKey for watching. A repeat
	/// registration refreshes the scriptPubKey but preserves the prior
	/// confirmation anchor, so reorg detection survives a re-arm.
	pub(crate) fn register(&self, txid: Txid, script_pubkey: ScriptBuf) {
		let mut entries = self.entries.lock().unwrap();
		entries
			.entry(txid)
			.and_modify(|entry| entry.script_pubkey = script_pubkey.clone())
			.or_insert(SwapWatchEntry { script_pubkey, last_confirmed_height: None });
	}

	/// Drop the watch entry for `txid` (B5 LOW-1). Without this the map grows
	/// unbounded for the process lifetime — every distinct watched txid (each
	/// swap's opening + spend txs) accumulates forever. The consumer calls this
	/// once a swap reaches a terminal, settled state and no longer needs reorg
	/// tracking. A no-op if `txid` was never registered.
	pub(crate) fn unregister(&self, txid: &Txid) {
		self.entries.lock().unwrap().remove(txid);
	}

	/// Number of currently-watched txids (test/observability only).
	#[cfg(test)]
	pub(crate) fn len(&self) -> usize {
		self.entries.lock().unwrap().len()
	}

	/// The watched scriptPubKey for `txid`, if registered.
	pub(crate) fn script_pubkey(&self, txid: &Txid) -> Option<ScriptBuf> {
		self.entries.lock().unwrap().get(txid).map(|entry| entry.script_pubkey.clone())
	}

	/// Whether `txid` was ever observed confirmed (arms reorg detection).
	pub(crate) fn previously_confirmed(&self, txid: &Txid) -> bool {
		self.entries
			.lock()
			.unwrap()
			.get(txid)
			.map_or(false, |entry| entry.last_confirmed_height.is_some())
	}

	/// Persist the latest confirmation anchor after a query so subsequent
	/// queries can detect a reorg/un-confirmation. Only a fresh confirmation
	/// advances the anchor; a non-confirmed status never disarms it.
	pub(crate) fn record(&self, txid: &Txid, status: &TxStatus) {
		if status.status == ChainStatus::Confirmed {
			if let Some(entry) = self.entries.lock().unwrap().get_mut(txid) {
				entry.last_confirmed_height = status.height;
			}
		}
	}
}

#[cfg(all(test, feature = "swaps"))]
mod swap_b5_tests {
	use super::{derive_tx_status, ChainStatus, RawTxObservation, SwapTxWatch};
	use bitcoin::hashes::Hash;
	use bitcoin::{ScriptBuf, Txid};

	fn dummy_txid(byte: u8) -> Txid {
		Txid::from_byte_array([byte; 32])
	}

	#[test]
	fn confirmed_reports_depth_and_height() {
		let status = derive_tx_status(
			RawTxObservation::Confirmed { height: Some(100), confirmations: 6 },
			false,
		);
		assert_eq!(status.status, ChainStatus::Confirmed);
		assert_eq!(status.confirmations, 6);
		assert_eq!(status.height, Some(100));
	}

	#[test]
	fn confirmed_depth_is_floored_to_one() {
		// A tx in the tip block is 1 confirmation deep, never 0.
		let status = derive_tx_status(
			RawTxObservation::Confirmed { height: Some(100), confirmations: 0 },
			false,
		);
		assert_eq!(status.status, ChainStatus::Confirmed);
		assert_eq!(status.confirmations, 1);
	}

	#[test]
	fn first_sighting_distinguishes_mempool_from_dropped() {
		let mempool = derive_tx_status(RawTxObservation::InMempool, false);
		assert_eq!(mempool.status, ChainStatus::Mempool);
		assert_eq!(mempool.confirmations, 0);
		assert_eq!(mempool.height, None);

		let dropped = derive_tx_status(RawTxObservation::NotFound, false);
		assert_eq!(dropped.status, ChainStatus::Dropped);
		assert_eq!(dropped.confirmations, 0);
		assert_eq!(dropped.height, None);
	}

	#[test]
	fn unconfirmation_after_confirm_is_reorg() {
		// Previously confirmed, now back to the mempool or gone => Reorged,
		// not Mempool/Dropped, so the caller re-anchors deadlines (F4).
		let back_to_mempool = derive_tx_status(RawTxObservation::InMempool, true);
		assert_eq!(back_to_mempool.status, ChainStatus::Reorged);
		assert_eq!(back_to_mempool.confirmations, 0);

		let evicted = derive_tx_status(RawTxObservation::NotFound, true);
		assert_eq!(evicted.status, ChainStatus::Reorged);
		assert_eq!(evicted.confirmations, 0);
	}

	#[test]
	fn unreachable_fails_closed_and_is_never_confirmed() {
		// The load-bearing E6 invariant: an unanswerable chain source is never
		// reported as confirmed, regardless of prior confirmation history.
		for previously_confirmed in [false, true] {
			let status = derive_tx_status(RawTxObservation::Unreachable, previously_confirmed);
			assert_eq!(status.status, ChainStatus::NoChainSource);
			assert_ne!(status.status, ChainStatus::Confirmed);
			assert_eq!(status.confirmations, 0);
			assert_eq!(status.height, None);
		}
	}

	#[test]
	fn unreachable_status_string_is_stable() {
		assert_eq!(ChainStatus::NoChainSource.as_str(), "no_chain_source");
		assert_eq!(ChainStatus::Confirmed.as_str(), "confirmed");
		assert_eq!(ChainStatus::Reorged.as_str(), "reorged");
		assert_eq!(ChainStatus::Dropped.as_str(), "dropped");
		assert_eq!(ChainStatus::Mempool.as_str(), "mempool");
	}

	#[test]
	fn watch_registry_tracks_spk_and_reorg_anchor() {
		let watch = SwapTxWatch::new();
		let txid = dummy_txid(7);
		let spk = ScriptBuf::from_bytes(vec![0x00, 0x14, 0x11, 0x22, 0x33]);

		// Unregistered: no scriptPubKey, not previously confirmed.
		assert!(watch.script_pubkey(&txid).is_none());
		assert!(!watch.previously_confirmed(&txid));

		watch.register(txid, spk.clone());
		assert_eq!(watch.script_pubkey(&txid), Some(spk));
		assert!(!watch.previously_confirmed(&txid));

		// Recording a confirmation arms the reorg anchor.
		let confirmed = derive_tx_status(
			RawTxObservation::Confirmed { height: Some(200), confirmations: 3 },
			false,
		);
		watch.record(&txid, &confirmed);
		assert!(watch.previously_confirmed(&txid));

		// A later mempool sighting for the now-armed txid derives Reorged.
		let reorged =
			derive_tx_status(RawTxObservation::InMempool, watch.previously_confirmed(&txid));
		assert_eq!(reorged.status, ChainStatus::Reorged);

		// Recording a non-confirmed status does not disarm the anchor.
		watch.record(&txid, &reorged);
		assert!(watch.previously_confirmed(&txid));
	}

	#[test]
	fn unregister_drops_the_watch_entry_and_is_idempotent() {
		// B5 LOW-1: the watch map must not grow unbounded — a terminalized swap's
		// entry is dropped, and unregistering an unknown txid is a harmless no-op.
		let watch = SwapTxWatch::new();
		let a = dummy_txid(1);
		let b = dummy_txid(2);
		let spk = ScriptBuf::from_bytes(vec![0x00, 0x14, 0xaa, 0xbb]);

		watch.register(a, spk.clone());
		watch.register(b, spk.clone());
		assert_eq!(watch.len(), 2);

		watch.unregister(&a);
		assert_eq!(watch.len(), 1, "the terminalized txid's entry is dropped");
		assert!(watch.script_pubkey(&a).is_none());
		assert!(watch.script_pubkey(&b).is_some(), "unrelated entry untouched");

		// Idempotent: dropping the same (or an unknown) txid again is a no-op.
		watch.unregister(&a);
		watch.unregister(&dummy_txid(99));
		assert_eq!(watch.len(), 1);

		watch.unregister(&b);
		assert_eq!(watch.len(), 0);
	}
}
