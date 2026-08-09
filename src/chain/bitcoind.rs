// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bitcoin::transaction::Version;
use bitcoin::{BlockHash, FeeRate, Network, OutPoint, Transaction, Txid};
use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;
use lightning::chain::{BlockLocator, Listen};
use lightning::util::ser::Writeable;
use lightning_block_sync::gossip::UtxoSource;
use lightning_block_sync::http::{HttpClientError, JsonResponse};
use lightning_block_sync::init::{synchronize_listeners, validate_best_block_header};
use lightning_block_sync::poll::{ChainPoller, ChainTip, ValidatedBlockHeader};
use lightning_block_sync::rest::RestClient;
use lightning_block_sync::rpc::{RpcClient, RpcClientError};
use lightning_block_sync::{
	BlockData, BlockHeaderData, BlockSource, BlockSourceError, BlockSourceErrorKind, HeaderCache,
	SpvClient,
};
use serde::Serialize;

use super::WalletSyncStatus;
use crate::config::{
	BitcoindRestClientConfig, Config, DEFAULT_FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS,
	DEFAULT_TX_BROADCAST_TIMEOUT_SECS,
};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	ConfirmationTarget, OnchainFeeEstimator,
};
use crate::io::utils::update_and_persist_node_metrics;
use crate::logger::{log_bytes, log_debug, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::tx_broadcaster::SortedTransactions;
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, PersistedNodeMetrics};

const CHAIN_POLLING_INTERVAL_SECS: u64 = 2;
const CHAIN_POLLING_TIMEOUT_SECS: u64 = 10;

pub(super) struct BitcoindChainSource {
	api_client: Arc<BitcoindClient>,
	latest_chain_tip: RwLock<Option<ValidatedBlockHeader>>,
	wallet_polling_status: Mutex<WalletSyncStatus>,
	fee_estimator: Arc<OnchainFeeEstimator>,
	kv_store: Arc<DynStore>,
	config: Arc<Config>,
	logger: Arc<Logger>,
	node_metrics: Arc<PersistedNodeMetrics>,
}

impl BitcoindChainSource {
	pub(crate) fn new_rpc(
		rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
		fee_estimator: Arc<OnchainFeeEstimator>, kv_store: Arc<DynStore>, config: Arc<Config>,
		logger: Arc<Logger>, node_metrics: Arc<PersistedNodeMetrics>,
	) -> Self {
		let api_client = Arc::new(BitcoindClient::new_rpc(
			rpc_host.clone(),
			rpc_port.clone(),
			rpc_user.clone(),
			rpc_password.clone(),
		));

		let latest_chain_tip = RwLock::new(None);
		let wallet_polling_status = Mutex::new(WalletSyncStatus::Completed);
		Self {
			api_client,
			latest_chain_tip,
			wallet_polling_status,
			fee_estimator,
			kv_store,
			config,
			logger: Arc::clone(&logger),
			node_metrics,
		}
	}

	pub(crate) fn new_rest(
		rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
		fee_estimator: Arc<OnchainFeeEstimator>, kv_store: Arc<DynStore>, config: Arc<Config>,
		rest_client_config: BitcoindRestClientConfig, logger: Arc<Logger>,
		node_metrics: Arc<PersistedNodeMetrics>,
	) -> Self {
		let api_client = Arc::new(BitcoindClient::new_rest(
			rest_client_config.rest_host,
			rest_client_config.rest_port,
			rpc_host,
			rpc_port,
			rpc_user,
			rpc_password,
		));

		let latest_chain_tip = RwLock::new(None);
		let wallet_polling_status = Mutex::new(WalletSyncStatus::Completed);

		Self {
			api_client,
			latest_chain_tip,
			wallet_polling_status,
			fee_estimator,
			kv_store,
			config,
			logger: Arc::clone(&logger),
			node_metrics,
		}
	}

	pub(super) fn as_utxo_source(&self) -> UtxoSourceClient {
		self.api_client.utxo_source()
	}

	/// Returns the shared on-chain fee estimator backing this chain source
	/// (Peerswap native primitive B6).
	#[cfg(feature = "swaps")]
	pub(super) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		&self.fee_estimator
	}

	/// Reorg-aware confirmation/eviction query for an ARBITRARY `txid` against
	/// this Bitcoind backend (Peerswap native primitive B5). See
	/// [`super::ChainSource::swap_query_tx`] for the fail-closed contract.
	#[cfg(feature = "swaps")]
	pub(super) async fn swap_query_tx(&self, txid: Txid) -> super::RawTxObservation {
		match self.api_client.swap_tx_confirmations(&txid).await {
			Ok(Some(0)) => super::RawTxObservation::InMempool,
			Ok(Some(confirmations)) => {
				// `getrawtransaction` returns the depth but not the height; derive
				// it as `tip - (confs - 1)`. B5 LOW-2: read a FRESH best-chain tip
				// (`get_best_block`) rather than the cached `latest_chain_tip`,
				// which can lag the real tip and yield a height that is too low —
				// and thus a CSV/claim deadline armed slightly EARLY. A fresh (or
				// even a one-block-stale-newer) tip can only err on the LATE/safe
				// side. Fail-soft on the HEIGHT ONLY: the depth is already
				// authoritative, so on a tip-read error we fall back to the cached
				// tip rather than failing the whole query closed.
				let tip_height = match self.api_client.get_best_block().await {
					Ok((_, Some(h))) => Some(h),
					Ok((_, None)) => {
						self.latest_chain_tip.read().unwrap().as_ref().map(|tip| tip.height)
					},
					Err(e) => {
						log_error!(
							self.logger,
							"swap_query_tx: Bitcoind fresh-tip read failed for {} ({:?}); falling back to cached tip for height",
							txid,
							e
						);
						self.latest_chain_tip.read().unwrap().as_ref().map(|tip| tip.height)
					},
				};
				let height = tip_height.map(|t| t.saturating_sub(confirmations.saturating_sub(1)));
				super::RawTxObservation::Confirmed { height, confirmations }
			},
			Ok(None) => super::RawTxObservation::NotFound,
			Err(e) => {
				log_error!(self.logger, "swap_query_tx: Bitcoind query failed for {}: {}", txid, e);
				super::RawTxObservation::Unreachable
			},
		}
	}

	pub(super) async fn validate_zero_fee_commitments_support(&self) -> Result<(), Error> {
		let node_version_result = tokio::time::timeout(
			Duration::from_secs(CHAIN_POLLING_TIMEOUT_SECS),
			self.api_client.get_node_version(),
		)
		.await
		.map_err(|e| {
			log_error!(self.logger, "Failed to get node version: {:?}", e);
			Error::ConnectionFailed
		})?;

		let node_version = node_version_result.map_err(|e| {
			log_error!(self.logger, "Failed to get node version: {:?}", e);
			Error::ConnectionFailed
		})?;

		// v26 first shipped the `submitpackage` RPC, but we need v29 to relay ephemeral dust
		if node_version < 290000 {
			log_error!(self.logger, "Bitcoin backend MUST be greater than or equal to v29");
			return Err(Error::ChainSourceNotSupported);
		}
		Ok(())
	}

	pub(super) async fn continuously_sync_wallets(
		&self, mut stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
	) {
		// First register for the wallet polling status to make sure `Node::sync_wallets` calls
		// wait on the result before proceeding.
		{
			let mut status_lock = self.wallet_polling_status.lock().expect("lock");
			if status_lock.register_or_subscribe_pending_sync().is_some() {
				debug_assert!(false, "Sync already in progress. This should never happen.");
			}
		}

		log_info!(
			self.logger,
			"Starting initial synchronization of chain listeners. This might take a while..",
		);

		let mut backoff = CHAIN_POLLING_INTERVAL_SECS;
		const MAX_BACKOFF_SECS: u64 = 300;

		loop {
			// if the stop_sync_sender has been dropped, we should just exit
			if stop_sync_receiver.has_changed().unwrap_or(true) {
				log_trace!(self.logger, "Stopping initial chain sync.");
				return;
			}

			let onchain_wallet_best_block = onchain_wallet.current_best_block();
			let channel_manager_best_block = channel_manager.current_best_block();
			let sweeper_best_block = output_sweeper.current_best_block();

			let mut chain_listeners = vec![
				(onchain_wallet_best_block, &*onchain_wallet as &(dyn Listen + Send + Sync)),
				(channel_manager_best_block, &*channel_manager as &(dyn Listen + Send + Sync)),
				(sweeper_best_block, &*output_sweeper as &(dyn Listen + Send + Sync)),
			];

			// TODO: Eventually we might want to see if we can synchronize `ChannelMonitor`s
			// before giving them to `ChainMonitor` it the first place. However, this isn't
			// trivial as we load them on initialization (in the `Builder`) and only gain
			// network access during `start`. For now, we just make sure we get the worst known
			// block hash and sychronize them via `ChainMonitor`.
			if let Some(worst_channel_monitor_best_block) = chain_monitor
				.list_monitors()
				.iter()
				.flat_map(|channel_id| chain_monitor.get_monitor(*channel_id))
				.map(|m| m.current_best_block())
				.min_by_key(|b| b.height)
			{
				chain_listeners.push((
					worst_channel_monitor_best_block,
					&*chain_monitor as &(dyn Listen + Send + Sync),
				));
			}

			let now = SystemTime::now();
			match synchronize_listeners(
				self.api_client.as_ref(),
				self.config.network,
				chain_listeners.clone(),
			)
			.await
			{
				Ok((_header_cache, chain_tip)) => {
					{
						let elapsed_ms = now.elapsed().map(|d| d.as_millis()).unwrap_or(0);
						log_info!(
							self.logger,
							"Finished synchronizing listeners in {}ms",
							elapsed_ms,
						);
						*self.latest_chain_tip.write().expect("lock") = Some(chain_tip);
						let unix_time_secs_opt =
							SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
						update_and_persist_node_metrics(
							&self.node_metrics,
							&*self.kv_store,
							&*self.logger,
							|m| {
								m.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
								m.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
							},
						)
						.await
						.unwrap_or_else(|e| {
							log_error!(self.logger, "Failed to persist node metrics: {}", e);
						});
					}
					break;
				},

				Err(e) => {
					log_error!(self.logger, "Failed to synchronize chain listeners: {:?}", e);
					if e.kind() == BlockSourceErrorKind::Transient {
						log_info!(
									self.logger,
									"Transient error syncing chain listeners: {:?}. Retrying in {} seconds.",
									e,
									backoff
								);
						// Sleep with stop signal check to allow immediate shutdown
						tokio::select! {
							biased;
							_ = stop_sync_receiver.changed() => {
								log_trace!(
									self.logger,
									"Stopping initial chain sync.",
								);
								return;
							}
							_ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
						}
						backoff = std::cmp::min(backoff * 2, MAX_BACKOFF_SECS);
					} else {
						log_error!(
									self.logger,
									"Persistent error syncing chain listeners: {:?}. Retrying in {} seconds.",
									e,
									MAX_BACKOFF_SECS
								);
						// Sleep with stop signal check to allow immediate shutdown
						tokio::select! {
							biased;
							_ = stop_sync_receiver.changed() => {
								log_trace!(
									self.logger,
									"Stopping initial chain sync during backoff.",
								);
								return;
							}
							_ = tokio::time::sleep(Duration::from_secs(MAX_BACKOFF_SECS)) => {}
						}
					}
				},
			}
		}

		// Now propagate the initial result to unblock waiting subscribers.
		self.wallet_polling_status.lock().expect("lock").propagate_result_to_subscribers(Ok(()));

		let mut chain_polling_interval =
			tokio::time::interval(Duration::from_secs(CHAIN_POLLING_INTERVAL_SECS));
		chain_polling_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		let mut fee_rate_update_interval =
			tokio::time::interval(Duration::from_secs(CHAIN_POLLING_INTERVAL_SECS));
		// When starting up, we just blocked on updating, so skip the first tick.
		fee_rate_update_interval.reset();
		fee_rate_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		log_info!(self.logger, "Starting continuous polling for chain updates.");

		// Start the polling loop.
		let mut last_best_block_hash = None;
		loop {
			tokio::select! {
				biased;
				_ = stop_sync_receiver.changed() => {
					log_trace!(
						self.logger,
						"Stopping polling for new chain data.",
					);
					return;
				}
				_ = chain_polling_interval.tick() => {
					tokio::select! {
						biased;
						_ = stop_sync_receiver.changed() => {
							log_trace!(
								self.logger,
								"Stopping polling for new chain data.",
							);
							return;
						}
						_ = self.poll_and_update_listeners(
							Arc::clone(&onchain_wallet),
							Arc::clone(&channel_manager),
							Arc::clone(&chain_monitor),
							Arc::clone(&output_sweeper)
						) => {}
					}
				}
				_ = fee_rate_update_interval.tick() => {
					if last_best_block_hash != Some(channel_manager.current_best_block().block_hash) {
						tokio::select! {
							biased;
							_ = stop_sync_receiver.changed() => {
								log_trace!(
									self.logger,
									"Stopping polling for new chain data.",
								);
								return;
							}
							update_res = self.update_fee_rate_estimates() => {
								if update_res.is_ok() {
									last_best_block_hash = Some(channel_manager.current_best_block().block_hash);
								}
							}
						}
					}
				}
			}
		}
	}

	pub(super) async fn poll_best_block(&self) -> Result<BlockLocator, Error> {
		self.poll_chain_tip().await.map(|tip| tip.to_block_locator())
	}

	async fn poll_chain_tip(&self) -> Result<ValidatedBlockHeader, Error> {
		let validate_res = tokio::time::timeout(
			Duration::from_secs(CHAIN_POLLING_TIMEOUT_SECS),
			validate_best_block_header(self.api_client.as_ref()),
		)
		.await
		.map_err(|e| {
			log_error!(self.logger, "Failed to poll for chain data: {:?}", e);
			Error::TxSyncTimeout
		})?;

		match validate_res {
			Ok(tip) => {
				*self.latest_chain_tip.write().expect("lock") = Some(tip);
				Ok(tip)
			},
			Err(e) => {
				log_error!(self.logger, "Failed to poll for chain data: {:?}", e);
				return Err(Error::TxSyncFailed);
			},
		}
	}

	pub(super) async fn poll_and_update_listeners(
		&self, onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let receiver_res = {
			let mut status_lock = self.wallet_polling_status.lock().expect("lock");
			status_lock.register_or_subscribe_pending_sync()
		};

		if let Some(mut sync_receiver) = receiver_res {
			log_debug!(self.logger, "Sync in progress, skipping.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet polling result: {:?}", e);
				log_error!(self.logger, "Failed to receive wallet polling result: {:?}", e);
				Error::WalletOperationFailed
			})?;
		}

		let res = self
			.poll_and_update_listeners_inner(
				onchain_wallet,
				channel_manager,
				chain_monitor,
				output_sweeper,
			)
			.await;

		self.wallet_polling_status.lock().expect("lock").propagate_result_to_subscribers(res);

		res
	}

	async fn poll_and_update_listeners_inner(
		&self, onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let latest_chain_tip_opt = self.latest_chain_tip.read().expect("lock").clone();
		let chain_tip =
			if let Some(tip) = latest_chain_tip_opt { tip } else { self.poll_chain_tip().await? };

		let chain_poller = ChainPoller::new(Arc::clone(&self.api_client), self.config.network);
		let chain_listener = ChainListener {
			onchain_wallet: Arc::clone(&onchain_wallet),
			channel_manager: Arc::clone(&channel_manager),
			chain_monitor: Arc::clone(&chain_monitor),
			output_sweeper,
			logger: Arc::clone(&self.logger),
			divergence: Arc::new(Mutex::new(None)),
			replay_batch: Arc::new(Mutex::new(BTreeMap::new())),
		};
		let mut spv_client =
			SpvClient::new(chain_tip, chain_poller, HeaderCache::new(), &chain_listener);

		let now = SystemTime::now();
		match spv_client.poll_best_tip().await {
			Ok((ChainTip::Better(tip), true)) => {
				let elapsed_ms = now.elapsed().map(|d| d.as_millis()).unwrap_or(0);
				log_trace!(self.logger, "Finished polling best tip in {}ms", elapsed_ms);
				*self.latest_chain_tip.write().expect("lock") = Some(tip);
			},
			Ok(_) => {},
			Err(e) => {
				log_error!(self.logger, "Failed to poll for chain data: {:?}", e);
				return Err(Error::TxSyncFailed);
			},
		}

		let cur_height = channel_manager.current_best_block().height;

		let now = SystemTime::now();
		let bdk_unconfirmed_txids = onchain_wallet.get_unconfirmed_txids();
		match self
			.api_client
			.get_updated_mempool_transactions(cur_height, bdk_unconfirmed_txids)
			.await
		{
			Ok((unconfirmed_txs, evicted_txids)) => {
				let elapsed_ms = now.elapsed().map(|d| d.as_millis()).unwrap_or(0);
				log_trace!(
					self.logger,
					"Finished polling mempool of size {} and {} evicted transactions in {}ms",
					unconfirmed_txs.len(),
					evicted_txids.len(),
					elapsed_ms,
				);
				onchain_wallet
					.apply_mempool_txs(unconfirmed_txs, evicted_txids)
					.await
					.unwrap_or_else(|e| {
						log_error!(self.logger, "Failed to apply mempool transactions: {:?}", e);
					});
			},
			Err(e) => {
				log_error!(self.logger, "Failed to poll for mempool transactions: {:?}", e);
				return Err(Error::TxSyncFailed);
			},
		}

		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		update_and_persist_node_metrics(&self.node_metrics, &*self.kv_store, &*self.logger, |m| {
			m.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
			m.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
		})
		.await?;

		Ok(())
	}

	pub(super) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		macro_rules! get_fee_rate_update {
			($estimation_fut:expr) => {{
				let update_res = tokio::time::timeout(
					Duration::from_secs(DEFAULT_FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS),
					$estimation_fut,
				)
				.await
				.map_err(|e| {
					log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
					Error::FeerateEstimationUpdateTimeout
				})?;
				update_res
			}};
		}
		let confirmation_targets = get_all_conf_targets();

		let mut new_fee_rate_cache = HashMap::with_capacity(10);
		let now = Instant::now();
		for target in confirmation_targets {
			let fee_rate_update_res = match target {
				ConfirmationTarget::Lightning(
					LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
				) => {
					let estimation_fut = self.api_client.get_mempool_minimum_fee_rate();
					get_fee_rate_update!(estimation_fut)
				},
				ConfirmationTarget::Lightning(LdkConfirmationTarget::MaximumFeeEstimate) => {
					let num_blocks = get_num_block_defaults_for_target(target);
					let estimation_mode = FeeRateEstimationMode::Conservative;
					let estimation_fut =
						self.api_client.get_fee_estimate_for_target(num_blocks, estimation_mode);
					get_fee_rate_update!(estimation_fut)
				},
				ConfirmationTarget::Lightning(LdkConfirmationTarget::UrgentOnChainSweep) => {
					let num_blocks = get_num_block_defaults_for_target(target);
					let estimation_mode = FeeRateEstimationMode::Conservative;
					let estimation_fut =
						self.api_client.get_fee_estimate_for_target(num_blocks, estimation_mode);
					get_fee_rate_update!(estimation_fut)
				},
				_ => {
					// Otherwise, we default to economical block-target estimate.
					let num_blocks = get_num_block_defaults_for_target(target);
					let estimation_mode = FeeRateEstimationMode::Economical;
					let estimation_fut =
						self.api_client.get_fee_estimate_for_target(num_blocks, estimation_mode);
					get_fee_rate_update!(estimation_fut)
				},
			};

			let fee_rate = match (fee_rate_update_res, self.config.network) {
				(Ok(rate), _) => rate,
				(Err(e), Network::Bitcoin) => {
					// Strictly fail on mainnet.
					log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
					return Err(Error::FeerateEstimationUpdateFailed);
				},
				(Err(e), n) if n == Network::Regtest || n == Network::Signet => {
					// On regtest/signet we just fall back to the usual 1 sat/vb == 250
					// sat/kwu default.
					log_error!(
								self.logger,
								"Failed to retrieve fee rate estimates: {}. Falling back to default of 1 sat/vb.",
								e,
							);
					FeeRate::from_sat_per_kwu(250)
				},
				(Err(e), _) => {
					// On testnet `estimatesmartfee` can be unreliable so we just skip in
					// case of a failure, which will have us falling back to defaults.
					log_error!(
						self.logger,
						"Failed to retrieve fee rate estimates: {}. Falling back to defaults.",
						e,
					);
					return Ok(());
				},
			};

			// LDK 0.0.118 introduced changes to the `ConfirmationTarget` semantics that
			// require some post-estimation adjustments to the fee rates, which we do here.
			let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);

			new_fee_rate_cache.insert(target, adjusted_fee_rate);

			log_trace!(
				self.logger,
				"Fee rate estimation updated for {:?}: {} sats/kwu",
				target,
				adjusted_fee_rate.to_sat_per_kwu(),
			);
		}

		if self.fee_estimator.set_fee_rate_cache(new_fee_rate_cache) {
			// We only log if the values changed, as it might be very spammy otherwise.
			log_debug!(
				self.logger,
				"Fee rate cache update finished in {}ms.",
				now.elapsed().as_millis()
			);
		}

		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		update_and_persist_node_metrics(&self.node_metrics, &*self.kv_store, &*self.logger, |m| {
			m.latest_fee_rate_cache_update_timestamp = unix_time_secs_opt
		})
		.await?;

		Ok(())
	}

	fn log_broadcast_error(
		&self, e: impl core::fmt::Display, txids: &[Txid], txs: &SortedTransactions,
	) {
		log_error!(self.logger, "Failed to broadcast transaction(s) {:?}: {}", txids, e);
		log_trace!(self.logger, "Failed broadcast transaction bytes:");
		for tx in txs.iter() {
			log_trace!(self.logger, "{}", log_bytes!(tx.encode()));
		}
	}

	pub(crate) async fn process_transaction_broadcast(&self, txs: SortedTransactions) {
		let all_txs_are_v3 = txs.iter().all(|tx| tx.version == Version::non_standard(3));
		match txs.len() {
			2.. if all_txs_are_v3 => {
				let txids: Vec<_> = txs.iter().map(|tx| tx.compute_txid()).collect();
				let timeout_fut = tokio::time::timeout(
					Duration::from_secs(DEFAULT_TX_BROADCAST_TIMEOUT_SECS),
					self.api_client.submit_package(&txs),
				);
				match timeout_fut.await {
					Ok(res) => match res {
						Ok(result) => {
							log_trace!(self.logger, "Successfully broadcast package {:?}", txids);
							log_trace!(self.logger, "Successfully broadcast package {}", result);
						},
						Err(e) => self.log_broadcast_error(e, &txids, &txs),
					},
					Err(e) => self.log_broadcast_error(e, &txids, &txs),
				}
			},
			_ => {
				for tx in txs.iter() {
					let txid = tx.compute_txid();
					let timeout_fut = tokio::time::timeout(
						Duration::from_secs(DEFAULT_TX_BROADCAST_TIMEOUT_SECS),
						self.api_client.broadcast_transaction(tx),
					);
					match timeout_fut.await {
						Ok(res) => match res {
							Ok(id) => {
								debug_assert_eq!(id, txid);
								log_trace!(
									self.logger,
									"Successfully broadcast transaction {}",
									txid
								);
							},
							Err(e) => self.log_broadcast_error(e, &[txid], &txs),
						},
						Err(e) => self.log_broadcast_error(e, &[txid], &txs),
					}
				}
			},
		}
	}
}

#[derive(Clone)]
pub(crate) enum UtxoSourceClient {
	Rpc(Arc<RpcClient>),
	Rest(Arc<RestClient>),
}

impl BlockSource for UtxoSourceClient {
	fn get_header<'a>(
		&'a self, header_hash: &'a BlockHash, height_hint: Option<u32>,
	) -> impl Future<Output = Result<BlockHeaderData, BlockSourceError>> + 'a {
		async move {
			match self {
				Self::Rpc(client) => client.get_header(header_hash, height_hint).await,
				Self::Rest(client) => client.get_header(header_hash, height_hint).await,
			}
		}
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a BlockHash,
	) -> impl Future<Output = Result<BlockData, BlockSourceError>> + 'a {
		async move {
			match self {
				Self::Rpc(client) => client.get_block(header_hash).await,
				Self::Rest(client) => client.get_block(header_hash).await,
			}
		}
	}

	fn get_best_block<'a>(
		&'a self,
	) -> impl Future<Output = Result<(BlockHash, Option<u32>), BlockSourceError>> + 'a {
		async move {
			match self {
				Self::Rpc(client) => client.get_best_block().await,
				Self::Rest(client) => client.get_best_block().await,
			}
		}
	}
}

impl UtxoSource for UtxoSourceClient {
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> impl Future<Output = Result<BlockHash, BlockSourceError>> + 'a {
		async move {
			match self {
				Self::Rpc(client) => client.get_block_hash_by_height(block_height).await,
				Self::Rest(client) => client.get_block_hash_by_height(block_height).await,
			}
		}
	}

	fn is_output_unspent<'a>(
		&'a self, outpoint: OutPoint,
	) -> impl Future<Output = Result<bool, BlockSourceError>> + 'a {
		async move {
			match self {
				Self::Rpc(client) => client.is_output_unspent(outpoint).await,
				Self::Rest(client) => client.is_output_unspent(outpoint).await,
			}
		}
	}
}

pub enum BitcoindClient {
	Rpc {
		rpc_client: Arc<RpcClient>,
		latest_mempool_timestamp: AtomicU64,
		mempool_entries_cache: tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
		mempool_txs_cache: tokio::sync::Mutex<HashMap<Txid, (Transaction, u64)>>,
	},
	Rest {
		rest_client: Arc<RestClient>,
		rpc_client: Arc<RpcClient>,
		latest_mempool_timestamp: AtomicU64,
		mempool_entries_cache: tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
		mempool_txs_cache: tokio::sync::Mutex<HashMap<Txid, (Transaction, u64)>>,
	},
}

impl BitcoindClient {
	/// Creates a new RPC API client for the chain interactions with Bitcoin Core.
	pub(crate) fn new_rpc(host: String, port: u16, rpc_user: String, rpc_password: String) -> Self {
		let url = base_url(host, port);
		let rpc_credentials = rpc_credentials(rpc_user, rpc_password);

		let rpc_client = Arc::new(RpcClient::new(&rpc_credentials, url));

		let latest_mempool_timestamp = AtomicU64::new(0);

		let mempool_entries_cache = tokio::sync::Mutex::new(HashMap::new());
		let mempool_txs_cache = tokio::sync::Mutex::new(HashMap::new());
		Self::Rpc { rpc_client, latest_mempool_timestamp, mempool_entries_cache, mempool_txs_cache }
	}

	/// Creates a new, primarily REST API client for the chain interactions
	/// with Bitcoin Core.
	///
	/// Aside the required REST host and port, we provide RPC configuration
	/// options for necessary calls not supported by the REST interface.
	pub(crate) fn new_rest(
		rest_host: String, rest_port: u16, rpc_host: String, rpc_port: u16, rpc_user: String,
		rpc_password: String,
	) -> Self {
		let rest_url = format!("{}/rest", base_url(rest_host, rest_port));
		let rest_client = Arc::new(RestClient::new(rest_url));

		let rpc_url = base_url(rpc_host, rpc_port);
		let rpc_credentials = rpc_credentials(rpc_user, rpc_password);
		let rpc_client = Arc::new(RpcClient::new(&rpc_credentials, rpc_url));

		let latest_mempool_timestamp = AtomicU64::new(0);

		let mempool_entries_cache = tokio::sync::Mutex::new(HashMap::new());
		let mempool_txs_cache = tokio::sync::Mutex::new(HashMap::new());

		Self::Rest {
			rest_client,
			rpc_client,
			latest_mempool_timestamp,
			mempool_entries_cache,
			mempool_txs_cache,
		}
	}

	fn utxo_source(&self) -> UtxoSourceClient {
		match self {
			Self::Rpc { rpc_client, .. } => UtxoSourceClient::Rpc(Arc::clone(&rpc_client)),
			Self::Rest { rest_client, .. } => UtxoSourceClient::Rest(Arc::clone(&rest_client)),
		}
	}

	pub(crate) async fn get_node_version(&self) -> Result<u64, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_node_version_inner(Arc::clone(rpc_client))
					.await
					.map_err(BitcoindClientError::Rpc)
			},
			BitcoindClient::Rest { rpc_client, .. } => {
				// Bitcoin Core's REST interface does not support `getnetworkinfo`
				// so we use the RPC client.
				Self::get_node_version_inner(Arc::clone(rpc_client))
					.await
					.map_err(BitcoindClientError::Rpc)
			},
		}
	}

	async fn get_node_version_inner(rpc_client: Arc<RpcClient>) -> Result<u64, RpcClientError> {
		rpc_client.call_method::<serde_json::Value>("getnetworkinfo", &[]).await.and_then(|value| {
			value["version"].as_u64().ok_or(RpcClientError::InvalidData(String::from(
				"The version field in the `getnetworkinfo` response should be a u64",
			)))
		})
	}

	/// Broadcasts the provided transaction.
	pub(crate) async fn broadcast_transaction(
		&self, tx: &Transaction,
	) -> Result<Txid, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::broadcast_transaction_inner(Arc::clone(rpc_client), tx)
					.await
					.map_err(BitcoindClientError::Rpc)
			},
			BitcoindClient::Rest { rpc_client, .. } => {
				// Bitcoin Core's REST interface does not support broadcasting transactions
				// so we use the RPC client.
				Self::broadcast_transaction_inner(Arc::clone(rpc_client), tx)
					.await
					.map_err(BitcoindClientError::Rpc)
			},
		}
	}

	async fn broadcast_transaction_inner(
		rpc_client: Arc<RpcClient>, tx: &Transaction,
	) -> Result<Txid, RpcClientError> {
		let tx_serialized = bitcoin::consensus::encode::serialize_hex(tx);
		let tx_json = serde_json::json!(tx_serialized);
		rpc_client.call_method::<Txid>("sendrawtransaction", &[tx_json]).await
	}

	/// Submits the provided package
	pub(crate) async fn submit_package(
		&self, package: &SortedTransactions,
	) -> Result<String, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::submit_package_inner(Arc::clone(rpc_client), package)
					.await
					.map_err(BitcoindClientError::Rpc)
			},
			BitcoindClient::Rest { rpc_client, .. } => {
				// Bitcoin Core's REST interface does not support submitting packages
				// so we use the RPC client.
				Self::submit_package_inner(Arc::clone(rpc_client), package)
					.await
					.map_err(BitcoindClientError::Rpc)
			},
		}
	}

	async fn submit_package_inner(
		rpc_client: Arc<RpcClient>, package: &SortedTransactions,
	) -> Result<String, RpcClientError> {
		let package_serialized: Vec<_> =
			package.iter().map(|tx| bitcoin::consensus::encode::serialize_hex(tx)).collect();
		let package_json = serde_json::json!(package_serialized);
		rpc_client
			.call_method::<SubmitPackageResponse>("submitpackage", &[package_json])
			.await
			.map(|response| response.0)
	}

	/// Retrieve the fee estimate needed for a transaction to begin
	/// confirmation within the provided `num_blocks`.
	pub(crate) async fn get_fee_estimate_for_target(
		&self, num_blocks: usize, estimation_mode: FeeRateEstimationMode,
	) -> Result<FeeRate, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => Self::get_fee_estimate_for_target_inner(
				Arc::clone(rpc_client),
				num_blocks,
				estimation_mode,
			)
			.await
			.map_err(BitcoindClientError::Rpc),
			BitcoindClient::Rest { rpc_client, .. } => {
				// We rely on the internal RPC client to make this call, as this
				// operation is not supported by Bitcoin Core's REST interface.
				Self::get_fee_estimate_for_target_inner(
					Arc::clone(rpc_client),
					num_blocks,
					estimation_mode,
				)
				.await
				.map_err(BitcoindClientError::Rpc)
			},
		}
	}

	/// Estimate the fee rate for the provided target number of blocks.
	async fn get_fee_estimate_for_target_inner(
		rpc_client: Arc<RpcClient>, num_blocks: usize, estimation_mode: FeeRateEstimationMode,
	) -> Result<FeeRate, RpcClientError> {
		let num_blocks_json = serde_json::json!(num_blocks);
		let estimation_mode_json = serde_json::json!(estimation_mode);
		rpc_client
			.call_method::<FeeResponse>(
				"estimatesmartfee",
				&[num_blocks_json, estimation_mode_json],
			)
			.await
			.map(|resp| resp.0)
	}

	/// Gets the mempool minimum fee rate.
	pub(crate) async fn get_mempool_minimum_fee_rate(
		&self,
	) -> Result<FeeRate, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_mempool_minimum_fee_rate_rpc(Arc::clone(rpc_client))
					.await
					.map_err(BitcoindClientError::Rpc)
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Self::get_mempool_minimum_fee_rate_rest(Arc::clone(rest_client))
					.await
					.map_err(BitcoindClientError::Rest)
			},
		}
	}

	/// Get the mempool minimum fee rate via RPC interface.
	async fn get_mempool_minimum_fee_rate_rpc(
		rpc_client: Arc<RpcClient>,
	) -> Result<FeeRate, RpcClientError> {
		rpc_client
			.call_method::<MempoolMinFeeResponse>("getmempoolinfo", &[])
			.await
			.map(|resp| resp.0)
	}

	/// Get the mempool minimum fee rate via REST interface.
	async fn get_mempool_minimum_fee_rate_rest(
		rest_client: Arc<RestClient>,
	) -> Result<FeeRate, HttpClientError> {
		rest_client
			.request_resource::<JsonResponse, MempoolMinFeeResponse>("mempool/info.json")
			.await
			.map(|resp| resp.0)
	}

	/// Gets the raw transaction for the provided transaction ID. Returns `None` if not found.
	pub(crate) async fn get_raw_transaction(
		&self, txid: &Txid,
	) -> Result<Option<Transaction>, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_raw_transaction_rpc(Arc::clone(rpc_client), txid)
					.await
					.map_err(BitcoindClientError::Rpc)
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Self::get_raw_transaction_rest(Arc::clone(rest_client), txid)
					.await
					.map_err(BitcoindClientError::Rest)
			},
		}
	}

	/// Retrieve raw transaction for provided transaction ID via the RPC interface.
	async fn get_raw_transaction_rpc(
		rpc_client: Arc<RpcClient>, txid: &Txid,
	) -> Result<Option<Transaction>, RpcClientError> {
		let txid_hex = txid.to_string();
		let txid_json = serde_json::json!(txid_hex);
		match rpc_client
			.call_method::<GetRawTransactionResponse>("getrawtransaction", &[txid_json])
			.await
		{
			Ok(resp) => Ok(Some(resp.0)),
			// Check if it's the 'not found' error code.
			Err(RpcClientError::Rpc(rpc_error)) if rpc_error.code == -5 => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Retrieve raw transaction for provided transaction ID via the REST interface.
	async fn get_raw_transaction_rest(
		rest_client: Arc<RestClient>, txid: &Txid,
	) -> Result<Option<Transaction>, HttpClientError> {
		let txid_hex = txid.to_string();
		let tx_path = format!("tx/{}.json", txid_hex);
		match rest_client
			.request_resource::<JsonResponse, GetRawTransactionResponse>(&tx_path)
			.await
		{
			Ok(resp) => Ok(Some(resp.0)),
			// Check if it's the HTTP NOT_FOUND error code.
			Err(HttpClientError::Http(http_error)) if http_error.status_code == 404 => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Confirmation depth for an ARBITRARY `txid` via verbose `getrawtransaction`
	/// (Peerswap native primitive B5).
	///
	/// To locate a tx by its id alone (the swap case — a counterparty opening tx
	/// that is not in our wallet), the backend must be able to find it, i.e. a
	/// `-txindex` node (or the tx still resident in the mempool). Returns:
	/// - `Ok(Some(n))` with `n >= 1` for a tx confirmed `n` blocks deep,
	/// - `Ok(Some(0))` for a tx seen in the mempool but unconfirmed,
	/// - `Ok(None)` when the node does not know the tx (RPC error code -5),
	/// - `Err(..)` for any transport/other failure, so the caller fails closed.
	#[cfg(feature = "swaps")]
	pub(crate) async fn swap_tx_confirmations(&self, txid: &Txid) -> std::io::Result<Option<u32>> {
		let rpc_client = match self {
			BitcoindClient::Rpc { rpc_client, .. } => Arc::clone(rpc_client),
			BitcoindClient::Rest { rpc_client, .. } => Arc::clone(rpc_client),
		};
		// `getrawtransaction` expects the txid in RPC/display (big-endian) order —
		// exactly `Txid`'s `Display`. `consensus::encode::serialize_hex` emits the
		// INTERNAL (little-endian) bytes, i.e. the REVERSED hex, which bitcoind rejects
		// with -5 "No such transaction". That -5 is mapped to `Ok(None)` below, so the
		// swap watcher would mistake EVERY confirmed opening tx for NotFound and never
		// arm the confirmation/CSV ladder — wedging every swap on the bitcoind backend.
		let txid_hex = txid.to_string();
		let txid_json = serde_json::json!(txid_hex);
		let verbose_json = serde_json::json!(true);
		match rpc_client
			.call_method::<SwapTxConfirmationResponse>(
				"getrawtransaction",
				&[txid_json, verbose_json],
			)
			.await
		{
			Ok(resp) => Ok(Some(resp.0)),
			// -5 == "No such mempool or blockchain transaction".
			Err(RpcClientError::Rpc(rpc_error)) if rpc_error.code == -5 => Ok(None),
			Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
		}
	}

	/// Retrieves the raw mempool.
	pub(crate) async fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_raw_mempool_rpc(Arc::clone(rpc_client))
					.await
					.map_err(BitcoindClientError::Rpc)
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Self::get_raw_mempool_rest(Arc::clone(rest_client))
					.await
					.map_err(BitcoindClientError::Rest)
			},
		}
	}

	/// Retrieves the raw mempool via the RPC interface.
	async fn get_raw_mempool_rpc(rpc_client: Arc<RpcClient>) -> Result<Vec<Txid>, RpcClientError> {
		let verbose_flag_json = serde_json::json!(false);
		rpc_client
			.call_method::<GetRawMempoolResponse>("getrawmempool", &[verbose_flag_json])
			.await
			.map(|resp| resp.0)
	}

	/// Retrieves the raw mempool via the REST interface.
	async fn get_raw_mempool_rest(
		rest_client: Arc<RestClient>,
	) -> Result<Vec<Txid>, HttpClientError> {
		rest_client
			.request_resource::<JsonResponse, GetRawMempoolResponse>(
				"mempool/contents.json?verbose=false",
			)
			.await
			.map(|resp| resp.0)
	}

	/// Retrieves an entry from the mempool if it exists, else return `None`.
	pub(crate) async fn get_mempool_entry(
		&self, txid: Txid,
	) -> Result<Option<MempoolEntry>, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_mempool_entry_inner(Arc::clone(rpc_client), txid)
					.await
					.map_err(BitcoindClientError::Rpc)
			},
			BitcoindClient::Rest { rpc_client, .. } => {
				Self::get_mempool_entry_inner(Arc::clone(rpc_client), txid)
					.await
					.map_err(BitcoindClientError::Rpc)
			},
		}
	}

	/// Retrieves the mempool entry of the provided transaction ID.
	async fn get_mempool_entry_inner(
		client: Arc<RpcClient>, txid: Txid,
	) -> Result<Option<MempoolEntry>, RpcClientError> {
		let txid_hex = txid.to_string();
		let txid_json = serde_json::json!(txid_hex);

		match client.call_method::<GetMempoolEntryResponse>("getmempoolentry", &[txid_json]).await {
			Ok(resp) => Ok(Some(MempoolEntry { txid, time: resp.time, height: resp.height })),
			// Check if it's the 'not found' error code.
			Err(RpcClientError::Rpc(rpc_error)) if rpc_error.code == -5 => Ok(None),
			Err(e) => Err(e),
		}
	}

	pub(crate) async fn update_mempool_entries_cache(&self) -> Result<(), BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { mempool_entries_cache, .. } => {
				self.update_mempool_entries_cache_inner(mempool_entries_cache).await
			},
			BitcoindClient::Rest { mempool_entries_cache, .. } => {
				self.update_mempool_entries_cache_inner(mempool_entries_cache).await
			},
		}
	}

	async fn update_mempool_entries_cache_inner(
		&self, mempool_entries_cache: &tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
	) -> Result<(), BitcoindClientError> {
		let mempool_txids = self.get_raw_mempool().await?;

		let mut mempool_entries_cache = mempool_entries_cache.lock().await;
		mempool_entries_cache.retain(|txid, _| mempool_txids.contains(txid));

		if let Some(difference) = mempool_txids.len().checked_sub(mempool_entries_cache.capacity())
		{
			mempool_entries_cache.reserve(difference)
		}

		for txid in mempool_txids {
			if mempool_entries_cache.contains_key(&txid) {
				continue;
			}

			if let Some(entry) = self.get_mempool_entry(txid).await? {
				mempool_entries_cache.insert(txid, entry.clone());
			}
		}

		mempool_entries_cache.shrink_to_fit();

		Ok(())
	}

	/// Returns two `Vec`s:
	/// - mempool transactions, alongside their first-seen unix timestamps.
	/// - transactions that have been evicted from the mempool, alongside the last time they were seen absent.
	pub(crate) async fn get_updated_mempool_transactions(
		&self, best_processed_height: u32, bdk_unconfirmed_txids: Vec<Txid>,
	) -> Result<(Vec<(Transaction, u64)>, Vec<(Txid, u64)>), BitcoindClientError> {
		let mempool_txs =
			self.get_mempool_transactions_and_timestamp_at_height(best_processed_height).await?;
		let evicted_txids =
			self.get_evicted_mempool_txids_and_timestamp(bdk_unconfirmed_txids).await?;
		Ok((mempool_txs, evicted_txids))
	}

	/// Get mempool transactions, alongside their first-seen unix timestamps.
	///
	/// This method is an adapted version of `bdk_bitcoind_rpc::Emitter::mempool`. It emits each
	/// transaction only once, unless we cannot assume the transaction's ancestors are already
	/// emitted.
	pub(crate) async fn get_mempool_transactions_and_timestamp_at_height(
		&self, best_processed_height: u32,
	) -> Result<Vec<(Transaction, u64)>, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc {
				latest_mempool_timestamp,
				mempool_entries_cache,
				mempool_txs_cache,
				..
			} => {
				self.get_mempool_transactions_and_timestamp_at_height_inner(
					latest_mempool_timestamp,
					mempool_entries_cache,
					mempool_txs_cache,
					best_processed_height,
				)
				.await
			},
			BitcoindClient::Rest {
				latest_mempool_timestamp,
				mempool_entries_cache,
				mempool_txs_cache,
				..
			} => {
				self.get_mempool_transactions_and_timestamp_at_height_inner(
					latest_mempool_timestamp,
					mempool_entries_cache,
					mempool_txs_cache,
					best_processed_height,
				)
				.await
			},
		}
	}

	async fn get_mempool_transactions_and_timestamp_at_height_inner(
		&self, latest_mempool_timestamp: &AtomicU64,
		mempool_entries_cache: &tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
		mempool_txs_cache: &tokio::sync::Mutex<HashMap<Txid, (Transaction, u64)>>,
		best_processed_height: u32,
	) -> Result<Vec<(Transaction, u64)>, BitcoindClientError> {
		let prev_mempool_time = latest_mempool_timestamp.load(Ordering::Relaxed);
		let mut latest_time = prev_mempool_time;

		self.update_mempool_entries_cache().await?;

		let mempool_entries_cache = mempool_entries_cache.lock().await;
		let mut mempool_txs_cache = mempool_txs_cache.lock().await;
		mempool_txs_cache.retain(|txid, _| mempool_entries_cache.contains_key(txid));

		if let Some(difference) =
			mempool_entries_cache.len().checked_sub(mempool_txs_cache.capacity())
		{
			mempool_txs_cache.reserve(difference)
		}

		let mut txs_to_emit = Vec::with_capacity(mempool_entries_cache.len());
		for (txid, entry) in mempool_entries_cache.iter() {
			if entry.time > latest_time {
				latest_time = entry.time;
			}

			// Avoid emitting transactions that are already emitted if we can guarantee
			// blocks containing ancestors are already emitted. The bitcoind rpc interface
			// provides us with the block height that the tx is introduced to the mempool.
			// If we have already emitted the block of height, we can assume that all
			// ancestor txs have been processed by the receiver.
			let ancestor_within_height = entry.height <= best_processed_height;
			let is_already_emitted = entry.time <= prev_mempool_time;
			if is_already_emitted && ancestor_within_height {
				continue;
			}

			if let Some((cached_tx, cached_time)) = mempool_txs_cache.get(txid) {
				txs_to_emit.push((cached_tx.clone(), *cached_time));
				continue;
			}

			match self.get_raw_transaction(&entry.txid).await {
				Ok(Some(tx)) => {
					mempool_txs_cache.insert(entry.txid, (tx.clone(), entry.time));
					txs_to_emit.push((tx, entry.time));
				},
				Ok(None) => {
					continue;
				},
				Err(e) => return Err(e),
			};
		}

		if !txs_to_emit.is_empty() {
			latest_mempool_timestamp.store(latest_time, Ordering::Release);
		}
		Ok(txs_to_emit)
	}

	// Retrieve a list of Txids that have been evicted from the mempool.
	//
	// To this end, we first update our local mempool_entries_cache and then return all unconfirmed
	// wallet `Txid`s that don't appear in the mempool still.
	async fn get_evicted_mempool_txids_and_timestamp(
		&self, bdk_unconfirmed_txids: Vec<Txid>,
	) -> Result<Vec<(Txid, u64)>, BitcoindClientError> {
		match self {
			BitcoindClient::Rpc { latest_mempool_timestamp, mempool_entries_cache, .. } => {
				Self::get_evicted_mempool_txids_and_timestamp_inner(
					latest_mempool_timestamp,
					mempool_entries_cache,
					bdk_unconfirmed_txids,
				)
				.await
			},
			BitcoindClient::Rest { latest_mempool_timestamp, mempool_entries_cache, .. } => {
				Self::get_evicted_mempool_txids_and_timestamp_inner(
					latest_mempool_timestamp,
					mempool_entries_cache,
					bdk_unconfirmed_txids,
				)
				.await
			},
		}
	}

	async fn get_evicted_mempool_txids_and_timestamp_inner(
		latest_mempool_timestamp: &AtomicU64,
		mempool_entries_cache: &tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
		bdk_unconfirmed_txids: Vec<Txid>,
	) -> Result<Vec<(Txid, u64)>, BitcoindClientError> {
		let latest_mempool_timestamp = latest_mempool_timestamp.load(Ordering::Relaxed);
		let mempool_entries_cache = mempool_entries_cache.lock().await;
		let evicted_txids = bdk_unconfirmed_txids
			.into_iter()
			.filter(|txid| !mempool_entries_cache.contains_key(txid))
			.map(|txid| (txid, latest_mempool_timestamp))
			.collect();
		Ok(evicted_txids)
	}
}

impl BlockSource for BitcoindClient {
	fn get_header<'a>(
		&'a self, header_hash: &'a bitcoin::BlockHash, height_hint: Option<u32>,
	) -> impl Future<Output = Result<BlockHeaderData, BlockSourceError>> + 'a {
		async move {
			match self {
				BitcoindClient::Rpc { rpc_client, .. } => {
					rpc_client.get_header(header_hash, height_hint).await
				},
				BitcoindClient::Rest { rest_client, .. } => {
					rest_client.get_header(header_hash, height_hint).await
				},
			}
		}
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a bitcoin::BlockHash,
	) -> impl Future<Output = Result<BlockData, BlockSourceError>> + 'a {
		async move {
			match self {
				BitcoindClient::Rpc { rpc_client, .. } => rpc_client.get_block(header_hash).await,
				BitcoindClient::Rest { rest_client, .. } => {
					rest_client.get_block(header_hash).await
				},
			}
		}
	}

	fn get_best_block<'a>(
		&'a self,
	) -> impl Future<Output = Result<(bitcoin::BlockHash, Option<u32>), BlockSourceError>> + 'a {
		async move {
			match self {
				BitcoindClient::Rpc { rpc_client, .. } => rpc_client.get_best_block().await,
				BitcoindClient::Rest { rest_client, .. } => rest_client.get_best_block().await,
			}
		}
	}
}

pub(crate) struct FeeResponse(pub FeeRate);

impl TryInto<FeeResponse> for JsonResponse {
	type Error = String;
	fn try_into(self) -> Result<FeeResponse, String> {
		if !self.0["errors"].is_null() {
			return Err(self.0["errors"].to_string());
		}
		let fee_rate_btc_per_kvbyte =
			self.0["feerate"].as_f64().ok_or("Failed to parse fee rate".to_string())?;
		// Bitcoin Core gives us a feerate in BTC/KvB.
		// Thus, we multiply by 25_000_000 (10^8 / 4) to get satoshis/kwu.
		let fee_rate = {
			let fee_rate_sat_per_kwu = (fee_rate_btc_per_kvbyte * 25_000_000.0).round() as u64;
			FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu)
		};
		Ok(FeeResponse(fee_rate))
	}
}

pub(crate) struct MempoolMinFeeResponse(pub FeeRate);

impl TryInto<MempoolMinFeeResponse> for JsonResponse {
	type Error = String;
	fn try_into(self) -> Result<MempoolMinFeeResponse, String> {
		let fee_rate_btc_per_kvbyte =
			self.0["mempoolminfee"].as_f64().ok_or("Failed to parse fee rate".to_string())?;
		// Bitcoin Core gives us a feerate in BTC/KvB.
		// Thus, we multiply by 25_000_000 (10^8 / 4) to get satoshis/kwu.
		let fee_rate = {
			let fee_rate_sat_per_kwu = (fee_rate_btc_per_kvbyte * 25_000_000.0).round() as u64;
			FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu)
		};
		Ok(MempoolMinFeeResponse(fee_rate))
	}
}

pub(crate) struct GetRawTransactionResponse(pub Transaction);

impl TryInto<GetRawTransactionResponse> for JsonResponse {
	type Error = String;
	fn try_into(self) -> Result<GetRawTransactionResponse, String> {
		let tx = self
			.0
			.as_str()
			.ok_or("Failed to parse getrawtransaction response".to_string())
			.and_then(|s| {
				bitcoin::consensus::encode::deserialize_hex(s)
					.map_err(|_| "Failed to parse getrawtransaction response".to_string())
			})?;

		Ok(GetRawTransactionResponse(tx))
	}
}

/// Confirmation depth parsed from a verbose `getrawtransaction` result
/// (Peerswap native primitive B5). The `confirmations` field is absent for an
/// unconfirmed (mempool) transaction, which we map to `0`.
#[cfg(feature = "swaps")]
pub(crate) struct SwapTxConfirmationResponse(pub u32);

#[cfg(feature = "swaps")]
impl TryInto<SwapTxConfirmationResponse> for JsonResponse {
	type Error = String;
	fn try_into(self) -> Result<SwapTxConfirmationResponse, String> {
		let confirmations = self.0["confirmations"].as_u64().unwrap_or(0);
		Ok(SwapTxConfirmationResponse(confirmations as u32))
	}
}

pub struct GetRawMempoolResponse(Vec<Txid>);

impl TryInto<GetRawMempoolResponse> for JsonResponse {
	type Error = String;
	fn try_into(self) -> Result<GetRawMempoolResponse, String> {
		let res = self.0.as_array().ok_or("Failed to parse getrawmempool response".to_string())?;

		let mut mempool_transactions = Vec::with_capacity(res.len());

		for hex in res {
			let txid = if let Some(hex_str) = hex.as_str() {
				match hex_str.parse::<Txid>() {
					Ok(txid) => txid,
					Err(_) => {
						return Err("Failed to parse getrawmempool response".to_string());
					},
				}
			} else {
				return Err("Failed to parse getrawmempool response".to_string());
			};

			mempool_transactions.push(txid);
		}

		Ok(GetRawMempoolResponse(mempool_transactions))
	}
}

pub struct GetMempoolEntryResponse {
	time: u64,
	height: u32,
}

impl TryInto<GetMempoolEntryResponse> for JsonResponse {
	type Error = String;
	fn try_into(self) -> Result<GetMempoolEntryResponse, String> {
		let res =
			self.0.as_object().ok_or("Failed to parse getmempoolentry response".to_string())?;

		let time = match res["time"].as_u64() {
			Some(time) => time,
			None => {
				return Err("Failed to parse getmempoolentry response".to_string());
			},
		};

		let height = match res["height"].as_u64().and_then(|h| h.try_into().ok()) {
			Some(height) => height,
			None => {
				return Err("Failed to parse getmempoolentry response".to_string());
			},
		};

		Ok(GetMempoolEntryResponse { time, height })
	}
}

pub struct SubmitPackageResponse(String);

impl TryInto<SubmitPackageResponse> for JsonResponse {
	type Error = String;
	fn try_into(self) -> Result<SubmitPackageResponse, String> {
		let response = self.0.to_string();
		let res = self.0.as_object().ok_or("Failed to parse submitpackage response".to_string())?;

		match res["package_msg"].as_str() {
			Some("success") => Ok(SubmitPackageResponse(response)),
			Some(_) | None => {
				return Err(response);
			},
		}
	}
}

#[derive(Debug, Clone)]
pub(crate) struct MempoolEntry {
	/// The transaction id
	txid: Txid,
	/// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
	time: u64,
	/// Block height when transaction entered pool
	height: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum FeeRateEstimationMode {
	Economical,
	Conservative,
}

#[derive(Clone)]
pub(crate) struct ChainListener {
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) chain_monitor: Arc<ChainMonitor>,
	pub(crate) output_sweeper: Arc<Sweeper>,
	pub(crate) logger: Arc<Logger>,
	/// Records the first listener divergence seen since the last drain.
	///
	/// `Listen` returns `()`, so divergence cannot be propagated through the trait. The chain
	/// source drains this after each block and must stop advancing when it is set: continuing
	/// would publish a "synced" tip while a listener sits on a stale chain.
	pub(crate) divergence: Arc<Mutex<Option<String>>>,
	/// Per-listener tally of the replay batch in flight, drained at every tip boundary.
	///
	/// Exists to tell two outcomes of [`ListenerAction::ReplayUnprovable`] apart, which are
	/// indistinguishable block by block: a listener that skips a stretch it cannot prove and then
	/// *reconnects* to the chain (benign — the resume-from-minimum design), and a listener the
	/// replay can never reach at all (stranded on a fork). See
	/// [`ChainListener::record_stranded_listeners`].
	pub(crate) replay_batch: Arc<Mutex<BTreeMap<&'static str, ReplayTally>>>,
}

/// What one listener decided about the blocks of the replay batch currently in flight.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayTally {
	/// Blocks skipped because ancestry could be neither confirmed nor refuted.
	pub(crate) unprovable: u32,
	/// Decisions that could actually be proven: delivered, an exact replay, or a fork.
	pub(crate) provable: u32,
	/// The listener's own tip height as of its most recent unprovable skip.
	pub(crate) tip_height: u32,
}

/// What a listener's replay batch amounts to once the replay has reached the chain's tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchVerdict {
	/// Nothing to say: the listener was never asked about a block it could not prove.
	Ordinary,
	/// Skipped a stretch it could not prove and then reconnected to the chain. Benign — this is
	/// what the resume-from-minimum design does on every restart with skewed listener durability.
	SkippedThenReconnected,
	/// The replay ended without this listener ever reaching a block it could prove, and its own
	/// tip is at or above the tip we ended at, so no later replay of this chain can reach it
	/// either. It is on a chain we can neither extend nor refute.
	Stranded,
}

impl ReplayTally {
	/// Folds one decision into the batch tally.
	fn note(&mut self, best: &BlockLocator, action: ListenerAction) {
		match action {
			ListenerAction::ReplayUnprovable => {
				self.unprovable = self.unprovable.saturating_add(1);
				self.tip_height = best.height;
			},
			ListenerAction::Deliver | ListenerAction::AlreadyApplied | ListenerAction::Diverged => {
				self.provable = self.provable.saturating_add(1)
			},
		}
	}

	/// Judges the batch against the tip the replay ended at.
	///
	/// `provable == 0` on its own already implies the listener sits at or above `tip_height` — a
	/// replay passes through every height at or below a listener's tip, and those compare
	/// provably — but being unreachable is what actually makes the case terminal, so it is checked
	/// rather than assumed.
	fn verdict(&self, tip_height: u32) -> BatchVerdict {
		if self.unprovable == 0 {
			BatchVerdict::Ordinary
		} else if self.provable > 0 || self.tip_height < tip_height {
			BatchVerdict::SkippedThenReconnected
		} else {
			BatchVerdict::Stranded
		}
	}
}

/// Whether a listener should be handed a given block.
///
/// `ChannelManager` and `OutputSweeper` enforce LDK's `Listen` contract with `assert_eq!` on both
/// the previous block hash and `height == best + 1`, so handing either one a block it has already
/// applied panics the node rather than returning an error. Listener durability is not
/// synchronized — `ChannelManager` is persisted asynchronously by the background processor while
/// `OutputSweeper` is only marked dirty and flushed periodically — so after a crash they can be
/// durable at different heights. The chain source resumes from the *minimum* height across all
/// listeners, which replays blocks to any listener that got further ahead.
///
/// Classification is deliberately hash-aware. Deciding on height alone would treat a *different*
/// block at an already-seen height as an ordinary replay and skip it, silently stranding the
/// listener on a stale fork — a worse failure than the panic being avoided, because it is silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerAction {
	/// The listener expects exactly this block.
	Deliver,
	/// The listener already has this exact block on its chain; skip it.
	AlreadyApplied,
	/// The block sits BELOW the listener's tip, but our ancestry record does not reach that far,
	/// so we can neither confirm nor refute that it is on the listener's chain. Skip it — but,
	/// unlike [`Self::Diverged`], do NOT halt the chain source.
	///
	/// This is the *expected* case whenever listener durability skews by more than
	/// `previous_blocks.len()` (LDK's `BlockLocator` carries `ANTI_REORG_DELAY * 2` = 12
	/// ancestors, and a locator restored from persistence can carry none at all), which is
	/// exactly the situation the resume-from-minimum design above sets up. Treating it as
	/// divergence halts CBF block application permanently for a listener that is merely further
	/// ahead on the same chain.
	///
	/// The decision is deferred, not dropped — but only for as long as the replay can still reach
	/// the listener. While it climbs towards `best.height` the same-height arm will compare the
	/// block hash exactly, and at `best.height + 1` the parent hash — both PROVABLE — so a
	/// listener genuinely sitting on a fork is caught a few blocks later by a check that can
	/// decide it.
	///
	/// That argument holds only while the chain being replayed is at least as long as the
	/// listener's own chain. It does NOT cover a reorg that leaves the canonical tip *below* an
	/// ahead listener's persisted tip (needs to be deeper than the ancestry window, or any depth
	/// at all against a locator restored from persistence with no ancestors): the replay ends
	/// before it can prove anything, every block is unprovable, and deferring forever is the same
	/// as dropping. That geometry is caught at the tip boundary instead — see
	/// [`ChainListener::record_stranded_listeners`], which fails closed on it.
	ReplayUnprovable,
	/// The listener cannot accept this block without first being rewound.
	Diverged,
}

pub(crate) fn listener_action(
	best: &BlockLocator, block_hash: bitcoin::BlockHash, prev_blockhash: bitcoin::BlockHash,
	height: u32,
) -> ListenerAction {
	if height == best.height + 1 {
		// The ordinary case: extends the listener's tip.
		return if best.block_hash == prev_blockhash {
			ListenerAction::Deliver
		} else {
			ListenerAction::Diverged
		};
	}

	if height == best.height {
		// Same height: an exact replay is safe to skip, a different block is a fork.
		return if best.block_hash == block_hash {
			ListenerAction::AlreadyApplied
		} else {
			ListenerAction::Diverged
		};
	}

	if height < best.height {
		// Below the tip: only a skip if this exact block is on the listener's own chain.
		// `previous_blocks` holds ancestors in reverse chronological order starting at
		// `best.height - 1`, so the ancestor at `height` sits at index `best.height - height - 1`.
		let idx = (best.height - height - 1) as usize;
		return match best.previous_blocks.get(idx) {
			Some(Some(ancestor)) if *ancestor == block_hash => ListenerAction::AlreadyApplied,
			// An ancestor we DO hold at that height and that differs is a proven fork.
			Some(Some(_)) => ListenerAction::Diverged,
			// Empty slot (a locator restored from persistence carries no ancestry) or past the
			// end of the 12-deep window: unprovable either way, and NOT evidence of a fork. See
			// `ListenerAction::ReplayUnprovable`.
			Some(None) | None => ListenerAction::ReplayUnprovable,
		};
	}

	// height > best.height + 1: a gap. Delivering would violate the one-call-per-block contract.
	ListenerAction::Diverged
}

impl ChainListener {
	/// Logs a diverged listener. Delivering anyway would panic on LDK's chain-order assertion, and
	/// silently skipping would strand the listener on a stale chain, so the condition is surfaced
	/// loudly rather than swallowed.
	pub(crate) fn get_best_block(&self) -> BlockLocator {
		let candidates = [
			self.onchain_wallet.current_best_block(),
			self.channel_manager.current_best_block(),
			self.output_sweeper.current_best_block(),
		];
		let mut min = candidates.into_iter().min_by_key(|b| b.height).expect("non-empty");
		if let Some(worst_monitor) = self.min_monitor_best_block() {
			if worst_monitor.height < min.height {
				min = worst_monitor;
			}
		}
		min
	}

	/// The furthest-behind channel monitor, or `None` when there are no monitors.
	fn min_monitor_best_block(&self) -> Option<BlockLocator> {
		self.chain_monitor
			.list_monitors()
			.iter()
			.flat_map(|id| self.chain_monitor.get_monitor(*id))
			.map(|m| m.current_best_block())
			.min_by_key(|b| b.height)
	}

	pub(crate) fn take_divergence(&self) -> Option<String> {
		self.divergence.lock().unwrap().take()
	}

	/// Records one listener's decision about one replay block in the batch ledger, logs it, and
	/// hands it back so the caller can act on it.
	///
	/// EVERY decision must flow through here. The ledger's whole value is the contrast between a
	/// listener that skipped some blocks and one that skipped *only* blocks, so a decision that
	/// bypassed it would read as an absence of evidence.
	fn note_decision(
		&self, who: &'static str, best: &BlockLocator, height: u32, action: ListenerAction,
	) -> ListenerAction {
		self.replay_batch.lock().unwrap().entry(who).or_default().note(best, action);
		match action {
			ListenerAction::ReplayUnprovable => self.log_unprovable_replay(who, best, height),
			ListenerAction::Diverged => self.log_divergence(who, best, height),
			ListenerAction::Deliver | ListenerAction::AlreadyApplied => {},
		}
		action
	}

	/// Drains the batch ledger at a tip boundary and fails closed on any listener the replay could
	/// never prove a connection to.
	///
	/// A batch that ends at `tip_height` is the last chance a listener gets: the replay is not
	/// coming back for it. So a listener that saw nothing but [`ListenerAction::ReplayUnprovable`]
	/// across the whole batch, and whose own tip is at or above the tip we just reached, is not
	/// waiting to be caught up — it is stranded on a chain we cannot extend or refute, and the
	/// deferral promised by `ReplayUnprovable` can never be honoured. Recording it as divergence
	/// halts the chain source, which is the pre-`ReplayUnprovable` behaviour for exactly this
	/// (true-positive) case.
	///
	/// A listener that skipped a stretch and then reconnected — the ordinary consequence of the
	/// resume-from-minimum design, and the case `ReplayUnprovable` exists for — has `provable > 0`
	/// and is merely reported, at a level that does not depend on debug logging being on.
	///
	/// Returns `true` when at least one listener was recorded as stranded.
	pub(crate) fn record_stranded_listeners(&self, tip_height: u32) -> bool {
		let batch = std::mem::take(&mut *self.replay_batch.lock().unwrap());
		let mut stranded = false;
		for (who, tally) in batch {
			match tally.verdict(tip_height) {
				BatchVerdict::Ordinary => {},
				BatchVerdict::SkippedThenReconnected => log_info!(
					self.logger,
					"{} skipped {} block(s) of the replay it could not prove ancestry for, then \
					 reconnected to the chain ({} proven decision(s), listener tip {}).",
					who,
					tally.unprovable,
					tally.provable,
					tally.tip_height,
				),
				BatchVerdict::Stranded => {
					stranded = true;
					self.record_divergence(format!(
						"{} is stranded at height {} above the synced tip {} ({} block(s) \
						 replayed, none provable): the replay ended without ever reaching a block \
						 it could prove",
						who, tally.tip_height, tip_height, tally.unprovable
					));
					log_error!(
						self.logger,
						"{} sits at height {} while the chain we just synced ends at {}, and none \
						 of the {} replayed block(s) could be proven to be on its chain. It is on \
						 a chain we can neither extend nor refute, so it is stranded rather than \
						 lagging.",
						who,
						tally.tip_height,
						tip_height,
						tally.unprovable,
					);
				},
			}
		}
		stranded
	}

	/// Logs a replay this listener is too far ahead of for us to prove ancestry for.
	///
	/// Deliberately does NOT touch `self.divergence`: on its own this is the ordinary consequence
	/// of the resume-from-minimum design, not a fork. Whether it stayed ordinary is decided at the
	/// tip boundary by [`Self::record_stranded_listeners`], so this stays at debug level.
	fn log_unprovable_replay(&self, who: &str, best: &BlockLocator, height: u32) {
		log_debug!(
			self.logger,
			"{} is at height {} and holds no ancestry back to height {}; skipping the replay of \
			 that block for it (its own tip is re-checked by hash when the replay reaches it).",
			who,
			best.height,
			height,
		);
	}

	/// Records the first divergence seen since the last drain. Later ones are dropped: the chain
	/// source halts on the first, and the first is the one that explains the rest.
	fn record_divergence(&self, reason: String) {
		let mut recorded = self.divergence.lock().unwrap();
		if recorded.is_none() {
			*recorded = Some(reason);
		}
	}

	fn log_divergence(&self, who: &str, best: &BlockLocator, height: u32) {
		self.record_divergence(format!(
			"{} diverged at height {} (listener at {}, hash {})",
			who, height, best.height, best.block_hash
		));
		log_error!(
			self.logger,
			"{} cannot accept the block at height {}: it is at height {} (hash {}). It must be \
			 rewound before it can continue; skipping to avoid a chain-order panic.",
			who,
			height,
			best.height,
			best.block_hash,
		);
	}
}

impl Listen for ChainListener {
	fn filtered_block_connected(
		&self, header: &bitcoin::block::Header,
		txdata: &lightning::chain::transaction::TransactionData, height: u32,
	) {
		// The on-chain wallet is deliberately not gated. `Wallet::blocks_disconnected` is a no-op
		// because BDK expects blocks to be reconnected starting from the point of disagreement, so
		// a height-based gate would starve it of the new chain after a reorg. BDK also tolerates an
		// exact duplicate, which is the only case a gate would otherwise guard against.
		self.onchain_wallet.filtered_block_connected(header, txdata, height);

		let block_hash = header.block_hash();

		// `note_decision` does the logging and the batch tally; the arms below decide only what
		// reaches the listener.
		let cm_best = self.channel_manager.current_best_block();
		let cm_action = listener_action(&cm_best, block_hash, header.prev_blockhash, height);
		match self.note_decision("ChannelManager", &cm_best, height, cm_action) {
			ListenerAction::Deliver => {
				self.channel_manager.filtered_block_connected(header, txdata, height)
			},
			ListenerAction::AlreadyApplied
			| ListenerAction::ReplayUnprovable
			| ListenerAction::Diverged => {},
		}

		// `ChainMonitor` has no chain-order assertion of its own, but `ChannelMonitor` advances its
		// tip whenever the incoming height is greater *without validating the parent*, so replaying
		// a different chain would silently graft a stale ancestor. Gate it on the furthest-behind
		// monitor: monitors ahead of that point ignore heights at or below their own tip.
		match self.min_monitor_best_block() {
			Some(monitor_best) => {
				let action =
					listener_action(&monitor_best, block_hash, header.prev_blockhash, height);
				match self.note_decision("ChainMonitor", &monitor_best, height, action) {
					ListenerAction::Deliver | ListenerAction::AlreadyApplied => {
						self.chain_monitor.filtered_block_connected(header, txdata, height)
					},
					ListenerAction::ReplayUnprovable | ListenerAction::Diverged => {},
				}
			},
			// No monitors: nothing to strand.
			None => self.chain_monitor.filtered_block_connected(header, txdata, height),
		}

		let sweeper_best = self.output_sweeper.current_best_block();
		let sweeper_action =
			listener_action(&sweeper_best, block_hash, header.prev_blockhash, height);
		match self.note_decision("OutputSweeper", &sweeper_best, height, sweeper_action) {
			ListenerAction::Deliver => {
				self.output_sweeper.filtered_block_connected(header, txdata, height)
			},
			ListenerAction::AlreadyApplied
			| ListenerAction::ReplayUnprovable
			| ListenerAction::Diverged => {},
		}
	}

	fn block_connected(&self, block: &bitcoin::Block, height: u32) {
		self.onchain_wallet.block_connected(block, height);

		let block_hash = block.header.block_hash();

		let cm_best = self.channel_manager.current_best_block();
		let cm_action = listener_action(&cm_best, block_hash, block.header.prev_blockhash, height);
		match self.note_decision("ChannelManager", &cm_best, height, cm_action) {
			ListenerAction::Deliver => self.channel_manager.block_connected(block, height),
			ListenerAction::AlreadyApplied
			| ListenerAction::ReplayUnprovable
			| ListenerAction::Diverged => {},
		}

		match self.min_monitor_best_block() {
			Some(monitor_best) => {
				let action =
					listener_action(&monitor_best, block_hash, block.header.prev_blockhash, height);
				match self.note_decision("ChainMonitor", &monitor_best, height, action) {
					ListenerAction::Deliver | ListenerAction::AlreadyApplied => {
						self.chain_monitor.block_connected(block, height)
					},
					ListenerAction::ReplayUnprovable | ListenerAction::Diverged => {},
				}
			},
			None => self.chain_monitor.block_connected(block, height),
		}

		let sweeper_best = self.output_sweeper.current_best_block();
		let sweeper_action =
			listener_action(&sweeper_best, block_hash, block.header.prev_blockhash, height);
		match self.note_decision("OutputSweeper", &sweeper_best, height, sweeper_action) {
			ListenerAction::Deliver => self.output_sweeper.block_connected(block, height),
			ListenerAction::AlreadyApplied
			| ListenerAction::ReplayUnprovable
			| ListenerAction::Diverged => {},
		}
	}

	fn blocks_disconnected(&self, fork_point_block: lightning::chain::BlockLocator) {
		self.onchain_wallet.blocks_disconnected(fork_point_block);
		self.channel_manager.blocks_disconnected(fork_point_block);
		self.chain_monitor.blocks_disconnected(fork_point_block);
		self.output_sweeper.blocks_disconnected(fork_point_block);
		// Every listener just moved back to the fork point, so the batch tallied against their old
		// tips describes a chain none of them are on any more. The replay that follows is the one
		// that gets judged.
		self.replay_batch.lock().unwrap().clear();
	}
}

pub(crate) fn rpc_credentials(rpc_user: String, rpc_password: String) -> String {
	BASE64_STANDARD.encode(format!("{}:{}", rpc_user, rpc_password))
}

pub(crate) fn base_url(host: String, port: u16) -> String {
	format!("http://{}:{}", host, port)
}

#[derive(Debug)]
pub(crate) enum BitcoindClientError {
	Rpc(RpcClientError),
	Rest(HttpClientError),
}

impl fmt::Display for BitcoindClientError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Rpc(e) => write!(f, "bitcoind RPC error: {}", e),
			Self::Rest(e) => write!(f, "bitcoind REST error: {}", e),
		}
	}
}

impl std::error::Error for BitcoindClientError {}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::Hash;
	use bitcoin::{FeeRate, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};
	use lightning::chain::BlockLocator;
	use lightning_block_sync::http::JsonResponse;
	use proptest::arbitrary::any;
	use proptest::collection::vec;
	use proptest::{prop_assert_eq, prop_compose, proptest};
	use serde_json::json;

	use crate::chain::bitcoind::{
		listener_action, BatchVerdict, FeeResponse, GetMempoolEntryResponse, GetRawMempoolResponse,
		GetRawTransactionResponse, ListenerAction, MempoolMinFeeResponse, ReplayTally,
	};

	fn hash(byte: u8) -> bitcoin::BlockHash {
		bitcoin::BlockHash::from_byte_array([byte; 32])
	}

	/// A listener tip at `height`/`hash_byte` whose ancestors are byte-tagged `hash_byte - n`.
	fn locator(height: u32, hash_byte: u8) -> BlockLocator {
		let mut loc = BlockLocator::new(hash(hash_byte), height);
		for (i, slot) in loc.previous_blocks.iter_mut().enumerate() {
			*slot = Some(hash(hash_byte.wrapping_sub(i as u8 + 1)));
		}
		loc
	}

	#[test]
	fn listener_action_delivers_the_next_block_in_order() {
		// Extends the tip: parent matches, height is best + 1.
		assert_eq!(
			listener_action(&locator(100, 50), hash(51), hash(50), 101),
			ListenerAction::Deliver
		);
	}

	#[test]
	fn listener_action_rejects_a_next_height_block_with_the_wrong_parent() {
		assert_eq!(
			listener_action(&locator(100, 50), hash(99), hash(200), 101),
			ListenerAction::Diverged
		);
	}

	#[test]
	fn listener_action_skips_an_exact_replay_at_the_tip() {
		// The crash case the gating exists for: the resume floor is the minimum height across all
		// listeners, so a listener that persisted further ahead is replayed its own blocks.
		// `ChannelManager` and `OutputSweeper` assert on chain order, so delivering would panic.
		assert_eq!(
			listener_action(&locator(100, 50), hash(50), hash(49), 100),
			ListenerAction::AlreadyApplied
		);
	}

	#[test]
	fn listener_action_skips_an_exact_replay_below_the_tip() {
		// Two blocks back on the listener's own chain: ancestors are tagged 49, 48, ...
		assert_eq!(
			listener_action(&locator(100, 50), hash(48), hash(47), 98),
			ListenerAction::AlreadyApplied
		);
	}

	#[test]
	fn listener_action_reports_a_different_block_at_the_same_height() {
		// The bug this classifier exists to prevent. Height alone would call this an ordinary
		// replay and skip it, silently stranding the listener on the stale fork — worse than the
		// panic being avoided, because nothing reports it.
		assert_eq!(
			listener_action(&locator(100, 50), hash(0xbb), hash(0xaa), 100),
			ListenerAction::Diverged
		);
	}

	#[test]
	fn listener_action_reports_a_different_block_below_the_tip() {
		// Right height, but not the block on the listener's chain (ancestor there is tagged 48).
		assert_eq!(
			listener_action(&locator(100, 50), hash(0xbb), hash(0xaa), 98),
			ListenerAction::Diverged
		);
	}

	#[test]
	fn listener_action_reports_an_unprovable_replay_beyond_known_ancestry() {
		// `previous_blocks` holds 12 ancestors; past that we cannot prove the block is ours, so it
		// must not be assumed to be a safe replay — it is NOT `AlreadyApplied`, the block is still
		// withheld from the listener.
		//
		// It is not `Diverged` either. Resume-from-minimum deliberately replays blocks to any
		// listener that persisted further ahead (see `ListenerAction`'s own doc comment), and
		// listener durability routinely skews by more than 12 blocks — measured live at 20
		// (wallet 7871 / ChainMonitor 7888 / ChannelManager 7891, all three on the canonical
		// chain). Calling that divergence halted CBF block application PERMANENTLY on a healthy
		// node: every later restart re-derived the same minimum, re-hit the same unprovable
		// replay, and re-halted, so `sync_state` latched `failed` forever.
		assert_eq!(
			listener_action(&locator(100, 50), hash(1), hash(0), 50),
			ListenerAction::ReplayUnprovable
		);
	}

	#[test]
	fn listener_action_reports_an_unprovable_replay_when_the_locator_carries_no_ancestry() {
		// `BlockLocator::new` leaves every ancestry slot empty, which is what a listener restored
		// from persistence can look like. Inside the window but with nothing recorded is still
		// "cannot decide", not "forked".
		let no_ancestry = BlockLocator::new(hash(50), 100);
		assert_eq!(
			listener_action(&no_ancestry, hash(48), hash(47), 98),
			ListenerAction::ReplayUnprovable
		);
	}

	#[test]
	fn an_unprovable_replay_still_meets_a_provable_check_at_the_listeners_own_tip() {
		// The safety property that makes `ReplayUnprovable` safe to not halt on: the replay keeps
		// climbing, and at the listener's own height the classifier compares block hashes
		// exactly. A listener genuinely on a fork is caught there instead of below it.
		//
		// This holds only while the replay can actually GET to that height. When it cannot — a
		// chain shorter than the listener's own — the tip-boundary check below is what decides,
		// see `a_replay_that_ends_below_an_ahead_listener_strands_it`.
		let ahead = locator(100, 50);
		// Below the tip, past the ancestry window: undecidable, keep going.
		assert_eq!(listener_action(&ahead, hash(1), hash(0), 50), ListenerAction::ReplayUnprovable);
		// At the tip on the same chain: a plain replay.
		assert_eq!(
			listener_action(&ahead, hash(50), hash(49), 100),
			ListenerAction::AlreadyApplied
		);
		// At the tip on a DIFFERENT chain: still caught, still halts.
		assert_eq!(listener_action(&ahead, hash(0xbb), hash(0xaa), 100), ListenerAction::Diverged);
	}

	/// Replays the blocks of one batch over a single listener locator and returns what the batch
	/// ledger would hold, using the same fold the live path uses.
	///
	/// The locator is held fixed, so this models the listener for as long as the replay has not
	/// advanced it — which is the entire batch for a listener the replay never reaches, and up to
	/// its own tip for one it does.
	fn replay_over(
		best: &BlockLocator, from: u32, through: u32, chain: impl Fn(u32) -> bitcoin::BlockHash,
	) -> ReplayTally {
		let mut tally = ReplayTally::default();
		for height in from..=through {
			tally.note(best, listener_action(best, chain(height), chain(height - 1), height));
		}
		tally
	}

	#[test]
	fn a_replay_that_ends_below_an_ahead_listener_strands_it() {
		// The geometry the per-block classifier cannot decide: a reorg deeper than the 12-entry
		// ancestry window that leaves the canonical tip BELOW an ahead listener's persisted tip.
		// The replay walks the canonical chain and stops at 85, so it never climbs to the
		// listener's own height where a hash comparison could rule — every block is
		// `ReplayUnprovable`, and "we'll decide a few blocks later" never comes due.
		let ahead = locator(100, 100);
		let canonical = |h: u32| hash(h as u8 + 128);

		let tally = replay_over(&ahead, 76, 85, canonical);

		assert_eq!(tally.unprovable, 10, "every block of the batch was undecidable");
		assert_eq!(tally.provable, 0, "nothing in the batch could be proven either way");
		assert_eq!(
			tally.verdict(85),
			BatchVerdict::Stranded,
			"a listener at 100 that the canonical chain ends 15 blocks below is stranded, not \
			 lagging: no later replay of THIS chain reaches it either"
		);
	}

	#[test]
	fn a_replay_that_ends_below_a_listener_with_no_ancestry_strands_it_at_any_depth() {
		// The same trap without needing a deep reorg: a locator restored from persistence carries
		// no ancestors at all, so nothing below its tip is provable and the whole 12-block window
		// stops helping. Any canonical tip below the listener's own is then unreachable.
		let restored = BlockLocator::new(hash(100), 100);
		let canonical = |h: u32| hash(h as u8);

		let tally = replay_over(&restored, 90, 99, canonical);

		assert_eq!(tally.provable, 0);
		assert_eq!(tally.verdict(99), BatchVerdict::Stranded);
	}

	#[test]
	fn a_behind_listener_the_replay_catches_up_to_still_heals() {
		// The case `ReplayUnprovable` exists for, and the one a stranded-detector must not eat:
		// listener durability skews on every restart (measured live at 20 blocks), the resume
		// floor is the minimum across listeners, and a listener with no persisted ancestry cannot
		// prove ANY of the replay below its tip. It is still perfectly healthy — the proof
		// arrives when the replay reaches its own height.
		//
		// Stopping the replay at the listener's tip is the pessimistic cut: every block above it
		// is `Deliver`, which only adds proof.
		let restored = BlockLocator::new(hash(100), 100);
		let canonical = |h: u32| hash(h as u8);

		let tally = replay_over(&restored, 81, 100, canonical);

		assert_eq!(tally.unprovable, 19, "81..=99 could not be proven");
		assert_eq!(tally.provable, 1, "its own tip at 100 compares by hash, and matches");
		assert_eq!(
			tally.verdict(120),
			BatchVerdict::SkippedThenReconnected,
			"skipping a stretch and then reconnecting must never halt the chain source — that \
			 halt bricked CBF on healthy nodes"
		);
	}

	#[test]
	fn a_batch_that_proved_a_fork_is_not_also_reported_as_stranded() {
		// Divergence is a proven decision. It halts through its own path, and reporting the same
		// listener twice for the same batch would misdescribe why.
		let ahead = locator(100, 100);
		let forked = |h: u32| hash(h as u8 + 128);

		// 88..=99 are inside the ancestry window and disagree; 100 is the tip and disagrees.
		let tally = replay_over(&ahead, 80, 100, forked);

		assert!(tally.provable > 0, "the window and the tip both ruled");
		assert_eq!(tally.verdict(100), BatchVerdict::SkippedThenReconnected);
	}

	#[test]
	fn the_stranded_verdict_needs_both_no_proof_and_an_unreachable_tip() {
		let nothing_skipped = ReplayTally { unprovable: 0, provable: 5, tip_height: 0 };
		assert_eq!(nothing_skipped.verdict(90), BatchVerdict::Ordinary);

		let skipped_then_proved = ReplayTally { unprovable: 3, provable: 1, tip_height: 100 };
		assert_eq!(skipped_then_proved.verdict(90), BatchVerdict::SkippedThenReconnected);

		// Defensive: a listener below the tip the replay reached is reachable by construction, so
		// however it got here it is not the terminal case.
		let below_the_tip = ReplayTally { unprovable: 3, provable: 0, tip_height: 89 };
		assert_eq!(below_the_tip.verdict(90), BatchVerdict::SkippedThenReconnected);

		let unreachable = ReplayTally { unprovable: 3, provable: 0, tip_height: 100 };
		assert_eq!(unreachable.verdict(90), BatchVerdict::Stranded);
		assert_eq!(
			unreachable.verdict(100),
			BatchVerdict::Stranded,
			"at the tip it is still ahead"
		);
	}

	#[test]
	fn listener_action_reports_a_gap() {
		// More than one block ahead: delivering violates LDK's one-call-per-block contract.
		assert_eq!(
			listener_action(&locator(90, 50), hash(60), hash(59), 101),
			ListenerAction::Diverged
		);
	}

	prop_compose! {
		fn arbitrary_witness()(
			witness_elements in vec(vec(any::<u8>(), 0..100), 0..20)
		) -> Witness {
			let mut witness = Witness::new();
			for element in witness_elements {
				witness.push(element);
			}
			witness
		}
	}

	prop_compose! {
		fn arbitrary_txin()(
			outpoint_hash in any::<[u8; 32]>(),
			outpoint_vout in any::<u32>(),
			script_bytes in vec(any::<u8>(), 0..100),
			witness in arbitrary_witness(),
			sequence in any::<u32>()
		) -> TxIn {
			TxIn {
				previous_output: OutPoint {
					txid: Txid::from_byte_array(outpoint_hash),
					vout: outpoint_vout,
				},
				script_sig: ScriptBuf::from_bytes(script_bytes),
				sequence: bitcoin::Sequence::from_consensus(sequence),
				witness,
			}
		}
	}

	prop_compose! {
		fn arbitrary_txout()(
			value in 0u64..21_000_000_00_000_000u64,
			script_bytes in vec(any::<u8>(), 0..100)
		) -> TxOut {
			TxOut {
				value: bitcoin::Amount::from_sat(value),
				script_pubkey: ScriptBuf::from_bytes(script_bytes),
			}
		}
	}

	prop_compose! {
		fn arbitrary_transaction()(
			version in any::<i32>(),
			inputs in vec(arbitrary_txin(), 1..20),
			outputs in vec(arbitrary_txout(), 1..20),
			lock_time in any::<u32>()
		) -> Transaction {
			Transaction {
				version: bitcoin::transaction::Version(version),
				input: inputs,
				output: outputs,
				lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
			}
		}
	}

	proptest! {
		#![proptest_config(proptest::test_runner::Config::with_cases(20))]

		#[test]
		fn prop_get_raw_mempool_response_roundtrip(txids in vec(any::<[u8;32]>(), 0..10)) {
			let txid_vec: Vec<Txid> = txids.into_iter().map(Txid::from_byte_array).collect();
			let original = GetRawMempoolResponse(txid_vec.clone());

			let json_vec: Vec<String> = txid_vec.iter().map(|t| t.to_string()).collect();
			let json_val = serde_json::Value::Array(json_vec.iter().map(|s| json!(s)).collect());

			let resp = JsonResponse(json_val);
			let decoded: GetRawMempoolResponse = resp.try_into().unwrap();

			prop_assert_eq!(original.0.len(), decoded.0.len());

			prop_assert_eq!(original.0, decoded.0);
		}

		#[test]
		fn prop_get_mempool_entry_response_roundtrip(
			time in any::<u64>(),
			height in any::<u32>()
		) {
			let json_val = json!({
				"time": time,
				"height": height
			});

			let resp = JsonResponse(json_val);
			let decoded: GetMempoolEntryResponse = resp.try_into().unwrap();

			prop_assert_eq!(decoded.time, time);
			prop_assert_eq!(decoded.height, height);
		}

		#[test]
		fn prop_get_raw_transaction_response_roundtrip(tx in arbitrary_transaction()) {
			let hex = bitcoin::consensus::encode::serialize_hex(&tx);
			let json_val = serde_json::Value::String(hex.clone());

			let resp = JsonResponse(json_val);
			let decoded: GetRawTransactionResponse = resp.try_into().unwrap();

			prop_assert_eq!(decoded.0.compute_txid(), tx.compute_txid());
			prop_assert_eq!(decoded.0.compute_wtxid(), tx.compute_wtxid());

			prop_assert_eq!(decoded.0, tx);
		}

		#[test]
		fn prop_fee_response_roundtrip(fee_rate in any::<f64>()) {
			let fee_rate = fee_rate.abs();
			let json_val = json!({
				"feerate": fee_rate,
				"errors": serde_json::Value::Null
			});

			let resp = JsonResponse(json_val);
			let decoded: FeeResponse = resp.try_into().unwrap();

			let expected = {
				let fee_rate_sat_per_kwu = (fee_rate * 25_000_000.0).round() as u64;
				FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu)
			};
			prop_assert_eq!(decoded.0, expected);
		}

		#[test]
		fn prop_mempool_min_fee_response_roundtrip(fee_rate in any::<f64>()) {
			let fee_rate = fee_rate.abs();
			let json_val = json!({
				"mempoolminfee": fee_rate
			});

			let resp = JsonResponse(json_val);
			let decoded: MempoolMinFeeResponse = resp.try_into().unwrap();

			let expected = {
				let fee_rate_sat_per_kwu = (fee_rate * 25_000_000.0).round() as u64;
				FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu)
			};
			prop_assert_eq!(decoded.0, expected);
		}

	}
}
