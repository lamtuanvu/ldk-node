use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bip157::chain::ChainState;
use bip157::{
	chain::BlockHeaderChanges, Builder as KyotoBuilder, Client, Event as KyotoEvent,
	HashCheckpoint, Header, IndexedBlock, Info, Node as KyotoNode, Package, Requester, TrustedPeer,
	Warning,
};
use bitcoin::{BlockHash, FeeRate, Network, Script, ScriptBuf, Transaction, Txid};
use electrum_client::{Client as ElectrumClient, ConfigBuilder as ElectrumConfigBuilder};
use lightning::chain::{BlockLocator, Listen, WatchedOutput};

use tokio::sync::{mpsc, watch};

use crate::chain::bitcoind::ChainListener;
use crate::chain::electrum::get_electrum_fee_rate_cache_update;
use crate::chain::{CbfFeeSourceConfig, CbfSyncStatus, ChainServiceHooks};
use crate::config::{Config, DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS};
use crate::error::Error;
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_fallback_rate_for_target,
	get_num_block_defaults_for_target, ConfirmationTarget, OnchainFeeEstimator,
};
use crate::io::utils::update_and_persist_node_metrics;
use crate::logger::{log_debug, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::runtime::Runtime;
use crate::types::DynStore;
use crate::util::{cbf_percentile_for_target, coinbase_fee_rate, percentile_of_sorted};
use crate::wallet::Wallet;
use crate::PersistedNodeMetrics;

/// Walk back this many blocks from the wallet's persisted tip when deriving
/// the kyoto resume checkpoint, so a recent reorg cannot strand the node
/// above the new best chain.
const REORG_SAFETY_BLOCKS: u32 = 7;
const BLOCK_FEE_CACHE_CAPACITY: usize = REORG_SAFETY_BLOCKS as usize * 2;

/// Peer response timeout passed to kyoto's `Builder::response_timeout`.
const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 30;

/// Number of peers that must agree on filter headers before they're accepted.
const DEFAULT_REQUIRED_PEERS: u8 = 1;

/// Maximum consecutive `node.run()` failures before the restart loop gives up.
const MAX_RESTART_RETRIES: u32 = 5;

/// Initial backoff delay between restart attempts; doubles each failure.
const INITIAL_BACKOFF_MS: u64 = 500;

/// Retry matched block downloads before surfacing a CBF sync failure.
const CBF_BLOCK_FETCH_RETRIES: u8 = 3;

/// Bound on the queue between the kyoto event loop and [`BlockApplicator`].
///
/// This queue was previously unbounded. During a bulk sync, filter processing outruns listener
/// application (each applied block costs a BDK persist), so an unbounded queue lets hundreds of
/// thousands of `ChainOp` values accumulate with no backpressure — a concrete OOM risk on a
/// 512 MiB device. A bound makes the event loop wait for the applicator instead.
///
/// Kept small because a `ConnectFull` op carries an entire block: at 64 slots the worst case is
/// bounded even when every queued op is a matched block. Most ops are `ConnectFiltered`, which
/// carries only an 80-byte header, so this depth is ample for pipelining in the common case.
const CBF_CHAIN_OP_QUEUE_DEPTH: usize = 64;

/// How many applied blocks may accumulate before the deferred on-chain chain tip is written.
///
/// While catching up, the wallet's `local_chain` write is deferred (see
/// `Wallet::set_bulk_chain_persistence`) so the growing full-chain map is not re-serialized on
/// every block. Flushing every retarget period bounds how many blocks a crash can force us to
/// replay, while collapsing ~2016 full-map writes into one. Once caught up, every block is
/// followed by a `Synced` op, which flushes — so at the tip this reverts to one write per block.
const CBF_CHAIN_FLUSH_INTERVAL_BLOCKS: u32 = 2016;

const ESPLORA_TIMEOUT: u64 = 2;

/// Retries and per-request timeout for the fresh Electrum connection opened each fee cycle.
const ELECTRUM_FEE_NUM_RETRIES: u8 = 3;
const ELECTRUM_FEE_TIMEOUT_SECS: u64 = 10;

/// Timeout applied to every [`ChainServiceHooks`] invocation (both `fee_estimates` and
/// `broadcast`). Unlike the Esplora/Electrum fee paths, an app-supplied hook has no client-level
/// timeout of its own, so without this an indefinitely-hanging hook would stall the fee-update
/// cycle, or the 500-deep broadcast-queue drain loop (`CBF_CHAIN_OP_QUEUE_DEPTH`-adjacent —
/// `continuously_process_broadcast_queue` in `chain/mod.rs`), for as long as the hook never
/// resolves. A timeout is treated identically to `Err(())`: fall through to the native path.
/// Matches the file's existing 10s external-service timeouts (`ELECTRUM_FEE_TIMEOUT_SECS`,
/// `CBF_BLOCK_FETCH_TIMEOUT_SECS`).
const CHAIN_SERVICE_HOOK_TIMEOUT_SECS: u64 = 10;

/// Sat/vB bounds clamped onto every value in an accepted `ChainServiceHooks::fee_estimates`
/// result before unit conversion. Defends against a malformed/hostile hook in two ways: a value
/// below the floor would starve fee bumping/relay, and an unclamped extreme value can overflow
/// `FeeRate::to_sat_per_vb_ceil` when a swap caller later reads the cached estimate back out in
/// sat/vB. `10_000` sat/vB is roughly two orders of magnitude above any real-world mempool
/// congestion spike, so this never clips a legitimate estimate.
const CHAIN_SERVICE_HOOK_MIN_SAT_PER_VB: f64 = 1.0;
const CHAIN_SERVICE_HOOK_MAX_SAT_PER_VB: f64 = 10_000.0;

/// Runtime status of the underlying kyoto node.
enum CbfRuntimeStatus {
	Started { requester: Requester },
	Stopped,
}

#[derive(Clone, Copy)]
enum CbfSyncState {
	Active {
		/// Highest tip whose preceding chain updates have been applied to all listeners.
		applied_tip: Option<u32>,
		/// Whether kyoto has reported catching up to the network tip (via `FiltersSynced`) and
		/// the resulting blocks have been applied. `wait_until_synced` blocks until this is set.
		///
		/// This must not be derived from a locally-sampled chain tip: kyoto does not persist, so a
		/// freshly (re)started node's local header chain sits at genesis until it syncs from peers.
		/// Comparing against that would make `wait_until_synced` return before any sync happens.
		synced_to_tip: bool,
	},
	Failed(Error),
}

/// Pure mapping from the internal, error-carrying [`CbfSyncState`] to the
/// externally-consumable [`CbfSyncStatus`] — extracted so the mapping is
/// unit-testable without a live kyoto node or `watch` channel.
fn simplify_sync_state(state: CbfSyncState) -> CbfSyncStatus {
	match state {
		CbfSyncState::Active { synced_to_tip: true, .. } => CbfSyncStatus::Synced,
		CbfSyncState::Active { synced_to_tip: false, .. } => CbfSyncStatus::Syncing,
		CbfSyncState::Failed(_) => CbfSyncStatus::Failed,
	}
}

/// Marks that we are applying a block past the last `FiltersSynced` tip, so a `sync_wallets` call
/// issued after new blocks are mined waits for the next `FiltersSynced` rather than returning on a
/// stale `synced_to_tip`. Only flips (and notifies waiters) when currently set.
///
/// Called both when a new block's filter is received (before it is fetched and applied) and after
/// it is applied, so `synced_to_tip` reflects "behind by an unapplied block" as soon as we learn
/// that block exists, not only once we've finished catching up to it.
fn mark_syncing(sync_state_tx: &watch::Sender<CbfSyncState>) {
	// Copy the current state out and drop the `watch` read guard before calling `send_replace`:
	// `borrow()` holds a read lock for the lifetime of its temporary, and `send_replace` takes
	// the write lock, so holding the borrow across it deadlocks. `CbfSyncState` is `Copy`, so the
	// deref copies and the guard is released at the end of this statement.
	let current = *sync_state_tx.borrow();
	if let CbfSyncState::Active { applied_tip, synced_to_tip: true } = current {
		sync_state_tx.send_replace(CbfSyncState::Active { applied_tip, synced_to_tip: false });
	}
}

/// Struct for holding cbf chain source
pub struct CbfChainSource {
	/// Trusted peer addresses for kyoto's `Builder::add_peers`.
	trusted_peers: Vec<TrustedPeer>,
	/// Scripts tracked by LDK, onchain wallet's scripts are pulled from the onchain wallet
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	fee_source: FeeSource,
	/// Tracks whether the kyoto node is running and holds the live requester.
	cbf_runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	/// Highest CBF sync tip whose preceding chain updates have been applied to all listeners.
	sync_state_tx: watch::Sender<CbfSyncState>,
	/// Handle used to spawn the background tasks and offload blocking work.
	runtime: Arc<Runtime>,
	/// Node configuration (network, storage path).
	config: Arc<Config>,
	fee_estimator: Arc<OnchainFeeEstimator>,
	kv_store: Arc<DynStore>,
	node_metrics: Arc<PersistedNodeMetrics>,
	logger: Arc<Logger>,
	/// App-supplied external chain-service hooks (fee estimates / broadcast); empty (no-op)
	/// unless configured via [`crate::builder::NodeBuilder::set_cbf_chain_service_hooks`].
	hooks: ChainServiceHooks,
}

#[derive(Debug)]
enum ChainOp {
	ConnectFull { block: IndexedBlock },
	ConnectFiltered { header: Header, height: u32 },
	Disconnect { fork_point: BlockLocator },
	Synced { tip_height: u32 },
	Failed { error: Error },
}

struct BlockApplicator {
	chain_listener: ChainListener,
	ops_rx: mpsc::Receiver<ChainOp>,
	next_height: u32,
	/// Blocks applied since the last deferred-chain-state flush.
	blocks_since_flush: u32,
	sync_state_tx: watch::Sender<CbfSyncState>,
	/// Present only for the native CBF fee source: lets us cache the fee rate of blocks we download
	/// here, so the fee estimator doesn't have to re-download them.
	block_fee_cache: Option<BlockFeeCache>,
	kv_store: Arc<DynStore>,
	node_metrics: Arc<PersistedNodeMetrics>,
	logger: Arc<Logger>,
}

impl BlockApplicator {
	/// Writes the deferred on-chain chain tip, logging (but not propagating) a failure: the chain
	/// state is reconstructible by replay, so a failed flush must not abort block application.
	async fn flush_chain_state(&mut self) {
		match self.chain_listener.onchain_wallet.flush_chain_persistence().await {
			Ok(()) => self.blocks_since_flush = 0,
			Err(e) => {
				// Deliberately do NOT reset the counter: the chain state is still unwritten, so the
				// next applied block should retry promptly rather than wait another full interval.
				// `local_chain_dirty` likewise stays set, so no state is dropped on the floor.
				log_error!(
					self.logger,
					"Failed to flush deferred CBF chain state ({}); will retry on the next block.",
					e
				);
			},
		}
	}

	/// Drains any listener divergence recorded during the last block application.
	///
	/// Returns `true` when the applicator must stop. A diverged listener is sitting on a chain we
	/// cannot extend, so advancing `next_height` would march past it and eventually publish a
	/// "synced" tip while that listener is stale — silent, and unrecoverable without a reorg whose
	/// fork point happens to fall below it. Failing loudly instead surfaces the condition to
	/// `wait_until_synced` and stops further damage.
	async fn fail_on_divergence(&mut self) -> bool {
		let Some(reason) = self.chain_listener.take_divergence() else {
			return false;
		};
		log_error!(
			self.logger,
			"Halting CBF block application: {}. The node must be restarted to re-derive a common \
			 chain state from the persisted listener heights.",
			reason
		);
		// Publish the failure BEFORE flushing. The flush is an unbounded KV write; if it hangs, a
		// `wait_until_synced` caller would otherwise block forever waiting for a state that is
		// already decided. Signalling first makes the failure observable regardless.
		self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
		// Persist what was applied before the divergence so the resume floor reflects it.
		self.flush_chain_state().await;
		true
	}

	/// Counts an applied block and flushes once the interval has elapsed.
	async fn note_block_applied(&mut self) {
		self.blocks_since_flush += 1;
		if self.blocks_since_flush >= CBF_CHAIN_FLUSH_INTERVAL_BLOCKS {
			self.flush_chain_state().await;
		}
	}

	async fn run(mut self) {
		// Defer the wallet's full-chain map write for as long as this applicator runs. Every path
		// that leaves the catching-up state (`Synced`, `Failed`, and the periodic interval) flushes,
		// so deferral never outlives a sync boundary.
		self.chain_listener.onchain_wallet.set_bulk_chain_persistence(true).await;

		while let Some(op) = self.ops_rx.recv().await {
			match op {
				ChainOp::ConnectFull { block: ib } => {
					if ib.height != self.next_height {
						log_debug!(
							self.logger,
							"CBF skipping out-of-sequence block at height {} (expected {})",
							ib.height,
							self.next_height
						);
						continue;
					}
					self.chain_listener.block_connected(&ib.block, ib.height);
					if self.fail_on_divergence().await {
						return;
					}
					self.next_height += 1;
					self.note_block_applied().await;
					mark_syncing(&self.sync_state_tx);
					if let Some(cache) = &self.block_fee_cache {
						let fee_rate = coinbase_fee_rate(&ib.block, ib.height);
						cache
							.lock()
							.expect("lock")
							.insert(ib.height, (ib.block.block_hash(), fee_rate));
					}
				},
				ChainOp::ConnectFiltered { header, height } => {
					if height != self.next_height {
						log_debug!(
							self.logger,
							"CBF skipping out-of-sequence block at height {} (expected {})",
							height,
							self.next_height
						);
						continue;
					}
					self.chain_listener.filtered_block_connected(&header, &[], height);
					if self.fail_on_divergence().await {
						return;
					}
					self.next_height += 1;
					self.note_block_applied().await;
					mark_syncing(&self.sync_state_tx);
				},
				ChainOp::Disconnect { fork_point } => {
					self.chain_listener.blocks_disconnected(fork_point);
					self.next_height = fork_point.height + 1;
					self.sync_state_tx.send_replace(CbfSyncState::Active {
						applied_tip: Some(fork_point.height),
						synced_to_tip: false,
					});
				},
				ChainOp::Synced { tip_height } => {
					log_info!(self.logger, "CBF caught up to tip {}", tip_height);
					if self.next_height > tip_height {
						// The last chance a listener gets to be proven on this chain: the replay
						// ends here and is not coming back. A listener the replay never reached is
						// stranded, not lagging, and must not be left silently on its own chain
						// while we advertise this one as synced.
						if self.chain_listener.record_stranded_listeners(tip_height)
							&& self.fail_on_divergence().await
						{
							return;
						}
						// Reaching the tip is the durability boundary: write the deferred chain state
						// before publishing, so the tip we advertise as applied is also persisted.
						self.flush_chain_state().await;
						self.publish_synced_tip(tip_height).await;
					} else {
						log_debug!(
							self.logger,
							"CBF waiting to apply blocks through tip {} (next height {})",
							tip_height,
							self.next_height
						);
					}
					log_info!(self.logger, "we set new tip and published at {}", tip_height);
				},
				ChainOp::Failed { error } => {
					log_info!(self.logger, "we received error chain op {}", error);
					// Persist whatever we applied before the failure so the resume floor reflects it.
					self.flush_chain_state().await;
					self.sync_state_tx.send_replace(CbfSyncState::Failed(error));
				},
			}
		}

		// The channel closed, which is how a normal shutdown reaches us. Deferred chain state lives
		// only in memory, so without this flush a clean stop would silently discard every block
		// applied since the last interval flush and force them to be re-synced on next start.
		self.flush_chain_state().await;
	}

	async fn publish_synced_tip(&self, tip_height: u32) {
		let already_published = {
			let sync_state = *self.sync_state_tx.borrow();
			match sync_state {
				CbfSyncState::Active { applied_tip, .. } => applied_tip,
				CbfSyncState::Failed(_) => None,
			}
		};
		if already_published.map_or(false, |published_height| published_height >= tip_height) {
			// Even if the applied tip is unchanged, we have now confirmed we are caught up to the
			// network tip, so ensure the synced flag is set for any `wait_until_synced` waiter.
			self.sync_state_tx.send_replace(CbfSyncState::Active {
				applied_tip: already_published,
				synced_to_tip: true,
			});
			return;
		}
		self.sync_state_tx.send_replace(CbfSyncState::Active {
			applied_tip: Some(tip_height),
			synced_to_tip: true,
		});
		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		if let Err(e) = update_and_persist_node_metrics(
			&self.node_metrics,
			&*self.kv_store,
			&*self.logger,
			|m| {
				m.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
				m.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
			},
		)
		.await
		{
			log_error!(self.logger, "Failed to persist CBF sync metrics: {:?}", e);
		}
	}
}

/// Number of most recent blocks whose coinbase-derived fee rates feed the native CBF estimator.
const FEE_WINDOW_BLOCKS: u32 = BLOCK_FEE_CACHE_CAPACITY as u32;

/// Lower bound for native CBF fee estimates (1 sat/vB), matching the floor used by the Esplora and
/// Electrum fee sources. Coinbase-derived rates are frequently zero on regtest/signet.
const CBF_MIN_FEERATE_SAT_PER_KWU: u64 = 250;

/// Per-attempt timeout when downloading a block from a peer — used both for matched blocks we apply
/// to the listeners and for the coinbase-fee-rate samples. Kyoto queues the request and awaits a
/// peer response with no timeout of its own, so a slow or unresponsive peer would otherwise park the
/// fetch forever. Kept short so a single request is bounded and can be retried (or, for fees, only
/// delays one sample) rather than stalling.
const CBF_BLOCK_FETCH_TIMEOUT_SECS: u64 = 10;

/// Per-transaction timeout on the kyoto P2P broadcast handoff.
///
/// [`Requester::submit_package`] resolves only once a peer has actually PULLED the transaction:
/// kyoto announces the wtxid in an `inv` and completes the caller's oneshot when it answers the
/// peer's `getdata`. A peer that already knows the transaction never sends `getdata` — Bitcoin
/// Core logs `got inv: wtx <id> have peer=N` and drops it — so that future NEVER resolves, and
/// kyoto attaches no timeout of its own.
///
/// Re-broadcasting a transaction the network already has is routine, not exceptional: both sides
/// of a cooperative close broadcast the same closing transaction, both sides of a force close may
/// broadcast the same commitment, and LDK re-broadcasts unconfirmed transactions on a timer. Since
/// [`crate::chain::ChainSource::continuously_process_broadcast_queue`] drains SERIALLY, a single
/// unresolvable handoff would wedge every LATER broadcast for the lifetime of the node —
/// including the force-close sweeps that recover a channel balance. Hence the bound, matching the
/// file's other kyoto-request timeout ([`CBF_BLOCK_FETCH_TIMEOUT_SECS`]).
///
/// Timing out does not retract the announcement: the transaction stays in kyoto's broadcast queue
/// and is still served if a peer asks for it later, and is re-announced to every peer that
/// completes a handshake afterwards.
const CBF_P2P_BROADCAST_TIMEOUT_SECS: u64 = 10;

/// Recent per-block coinbase-derived fee rates, keyed by height so we can window on the tip, evict
/// stale entries, and detect reorged-out blocks (a height whose cached hash no longer matches the
/// canonical chain). Shared via `Arc` between the fee estimator and the [`BlockApplicator`].
type BlockFeeCache = Arc<Mutex<BTreeMap<u32, (BlockHash, FeeRate)>>>;

enum FeeSource {
	/// Derive fee rates from the coinbase reward of recent blocks.  Downloads full blocks in order to calculate fee estimation.
	///
	/// The [`BlockApplicator`] also opportunistically inserts the fee rate of any block it already
	/// downloads on a filter match, saving a re-download in the reconciliation loop.
	Cbf { block_fee_cache: BlockFeeCache },
	/// Delegate fee estimation to an Esplora HTTP server.
	Esplora { client: esplora_client::AsyncClient },
	/// Delegate fee estimation to an Electrum server.
	///
	/// A fresh connection is opened for each estimation cycle.
	Electrum { server_url: String },
}

/// Result of parsing a single configured trusted-peer entry (`ip:port` or `host:port`).
///
/// Kept distinct from [`TrustedPeer`] so the parse step is unit-testable without depending on
/// kyoto's internal representation; [`ParsedPeer::into_trusted_peer`] converts to the real type.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedPeer {
	/// A literal IPv4/IPv6 socket address.
	Addr(SocketAddr),
	/// A hostname/port pair. Resolution happens at kyoto connect time, not here.
	Hostname { host: String, port: u16 },
}

impl ParsedPeer {
	fn into_trusted_peer(self) -> TrustedPeer {
		match self {
			ParsedPeer::Addr(addr) => TrustedPeer::from_socket_addr(addr),
			ParsedPeer::Hostname { host, port } => TrustedPeer::from_hostname(host, port),
		}
	}
}

/// Parses a single configured CBF trusted-peer entry.
///
/// Tries a literal `SocketAddr` first (covers IPv4/IPv6). On failure, splits on the last `:`
/// and treats the left side as a hostname to be resolved at kyoto connect time via
/// [`TrustedPeer::from_hostname`] (backed by [`tokio::net::lookup_host`]). Returns `Err` for
/// entries with no parseable port, rather than silently dropping them — a mistyped peer should
/// surface as a startup error, not vanish from the trusted-peer list.
fn parse_trusted_peer(peer_str: &str) -> Result<ParsedPeer, Error> {
	if let Ok(addr) = peer_str.parse::<SocketAddr>() {
		return Ok(ParsedPeer::Addr(addr));
	}

	let (host, port_str) = peer_str.rsplit_once(':').ok_or(Error::InvalidSocketAddress)?;
	if host.is_empty() {
		return Err(Error::InvalidSocketAddress);
	}
	let port: u16 = port_str.parse().map_err(|_| Error::InvalidSocketAddress)?;

	Ok(ParsedPeer::Hostname { host: host.to_string(), port })
}

/// The distinct block-count keys the fee-rate cache needs — the set of
/// `get_num_block_defaults_for_target(target)` values across every [`get_all_conf_targets`]
/// entry. A `ChainServiceHooks::fee_estimates` hook result is only ever applied if it covers
/// every one of these; see [`resolve_fee_estimates`].
fn required_hook_fee_targets() -> HashSet<u16> {
	get_all_conf_targets()
		.into_iter()
		.map(|target| get_num_block_defaults_for_target(target) as u16)
		.collect()
}

/// Resolves the per-target fee-rate cache for a single fee-update cycle.
///
/// If `hooks.fee_estimates` is configured, it is tried first, bounded by `hook_timeout`
/// (production callers pass [`CHAIN_SERVICE_HOOK_TIMEOUT_SECS`]; tests inject a short duration
/// so a deliberately-hung fake hook doesn't slow the test suite down). It is applied
/// **all-or-nothing**: an `Ok(by_blocks)`
/// map (keyed by conf-target in blocks, valued in sat/vB) is only converted into the estimator's
/// internal per-[`ConfirmationTarget`] cache and returned WITHOUT calling `fallback` if it has a
/// finite value for every key in [`required_hook_fee_targets`]. Every accepted value is clamped
/// to `[CHAIN_SERVICE_HOOK_MIN_SAT_PER_VB, CHAIN_SERVICE_HOOK_MAX_SAT_PER_VB]` before unit
/// conversion.
///
/// A `by_blocks` map that is missing one or more required keys (including an empty map) is
/// **rejected in full** and treated exactly like `Err(())` — NOT partially applied. This matters
/// because [`OnchainFeeEstimator::set_fee_rate_cache`] replaces the whole cache rather than
/// merging: applying a partial map would silently pin every uncovered target to the crate's
/// static conservative fallback rate (worse than any pre-hook source) instead of falling through
/// to a live estimate from the configured source, and would also bypass that source's own
/// safety guards (e.g. the Esplora path's "empty estimates disallowed on Mainnet" check) for a
/// cycle that never actually reaches it. Because this function returns early only on full
/// acceptance, [`CbfChainSource::commit_fee_rate_cache`]'s timestamp stamp downstream is never
/// applied for a rejected/timed-out/errored hook result — only for whichever cache (hook or
/// fallback) was actually accepted.
///
/// An `Err(())` result, a timeout, an incomplete/empty map, or no hook configured at all all
/// fall through to `fallback` — the existing (Esplora / Electrum / native-CBF) fee computation,
/// unchanged.
///
/// A free function (not a method) so it is unit-testable with a fake hook and a fake fallback,
/// without a live kyoto node.
async fn resolve_fee_estimates<F, Fut>(
	hooks: &ChainServiceHooks, logger: &Logger, hook_timeout: Duration, fallback: F,
) -> Result<HashMap<ConfirmationTarget, FeeRate>, Error>
where
	F: FnOnce() -> Fut,
	Fut: std::future::Future<Output = Result<HashMap<ConfirmationTarget, FeeRate>, Error>>,
{
	if let Some(hook) = hooks.fee_estimates.as_ref() {
		let hook_result = tokio::time::timeout(hook_timeout, hook()).await;
		match hook_result {
			Ok(Ok(by_blocks)) => {
				let required = required_hook_fee_targets();
				let covers_all = required
					.iter()
					.all(|blocks| by_blocks.get(blocks).is_some_and(|v| v.is_finite()));
				if covers_all {
					let mut cache = HashMap::with_capacity(10);
					for target in get_all_conf_targets() {
						let num_blocks = get_num_block_defaults_for_target(target) as u16;
						// Presence + finiteness guaranteed by `covers_all` above.
						let sat_per_vb = by_blocks[&num_blocks].clamp(
							CHAIN_SERVICE_HOOK_MIN_SAT_PER_VB,
							CHAIN_SERVICE_HOOK_MAX_SAT_PER_VB,
						);
						// sat/vB -> sat/kwu: 1 vB = 4 WU, 1 kwu = 1000 WU, so *1000/4 == *250.
						let sat_per_kwu = (sat_per_vb * 250.0) as u64;
						let fee_rate = FeeRate::from_sat_per_kwu(sat_per_kwu);
						cache.insert(target, apply_post_estimation_adjustments(target, fee_rate));
					}
					return Ok(cache);
				}
				log_debug!(
					logger,
					"External chain-service fee-estimates hook returned an incomplete map \
					 (missing or non-finite for one or more of the {} required block-count \
					 targets); rejecting it in full and falling back to the configured fee \
					 source.",
					required.len()
				);
			},
			Ok(Err(())) => {
				log_debug!(
					logger,
					"External chain-service fee-estimates hook declined; falling back to the \
					 configured fee source."
				);
			},
			Err(_elapsed) => {
				log_debug!(
					logger,
					"External chain-service fee-estimates hook timed out after {:?}; falling \
					 back to the configured fee source.",
					hook_timeout
				);
			},
		}
	}
	fallback().await
}

/// Outcome of trying the app-supplied broadcast hook before falling back to P2P.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BroadcastOutcome {
	/// The hook accepted the package; P2P broadcast was not used.
	HookHandled,
	/// No hook configured, or the hook declined (`Err(())`); P2P broadcast handled it.
	FellThroughToP2p,
}

/// Tries the app-supplied broadcast hook before falling back to the node's own P2P broadcast.
///
/// If `hooks.broadcast` is configured, it is called with the package's transactions, bounded by
/// `hook_timeout` (production callers pass [`CHAIN_SERVICE_HOOK_TIMEOUT_SECS`]; tests inject a
/// short duration so a deliberately-hung fake hook doesn't slow the test suite down): `Ok(())`
/// means the external service accepted the broadcast, so `p2p_send` is NOT called. `Err(())`, a
/// timeout, or no hook configured at all falls through to `p2p_send` — the existing kyoto
/// `submit_package`/per-tx broadcast path, unchanged. `p2p_send` is called (and must itself
/// degrade gracefully, e.g. by logging) even when the underlying kyoto runtime is stopped —
/// only `p2p_send`'s own implementation depends on kyoto health, not this decision function.
///
/// A free function (not a method) so it is unit-testable with a fake hook and a fake
/// `p2p_send`, without a live kyoto node.
async fn dispatch_broadcast<F, Fut>(
	hooks: &ChainServiceHooks, logger: &Logger, hook_timeout: Duration, txs: Vec<Transaction>,
	p2p_send: F,
) -> BroadcastOutcome
where
	F: FnOnce(Vec<Transaction>) -> Fut,
	Fut: std::future::Future<Output = ()>,
{
	if let Some(hook) = hooks.broadcast.as_ref() {
		let hook_result = tokio::time::timeout(hook_timeout, hook(txs.clone())).await;
		match hook_result {
			Ok(Ok(())) => return BroadcastOutcome::HookHandled,
			Ok(Err(())) => {},
			Err(_elapsed) => {
				log_debug!(
					logger,
					"External chain-service broadcast hook timed out after {:?}; falling back \
					 to P2P.",
					hook_timeout
				);
			},
		}
	}
	p2p_send(txs).await;
	BroadcastOutcome::FellThroughToP2p
}

/// Awaits ONE kyoto broadcast handoff under `hold_timeout`, never propagating a failure.
///
/// `submit` is a [`Requester::submit_package`] future; `what` names the transaction (or package)
/// for the log. Returns `true` only when a peer pulled the transaction inside the budget.
///
/// The timeout is the whole point — see [`CBF_P2P_BROADCAST_TIMEOUT_SECS`] for why an unbounded
/// await here wedges the entire serial broadcast queue. Expiring is logged at INFO rather than
/// ERROR because the overwhelmingly common cause is benign (the peer already has the transaction);
/// a genuine relay failure shows up as the transaction never confirming, which the caller's own
/// re-broadcast timer keeps retrying.
///
/// A free function (not a method), generic over the future, so it is unit-testable without a live
/// kyoto node — the same pattern as [`dispatch_broadcast`].
async fn bounded_p2p_handoff<T, E, Fut>(
	logger: &Logger, hold_timeout: Duration, what: &str, submit: Fut,
) -> bool
where
	Fut: std::future::Future<Output = Result<T, E>>,
	E: std::fmt::Debug,
{
	match tokio::time::timeout(hold_timeout, submit).await {
		Ok(Ok(_)) => true,
		Ok(Err(e)) => {
			log_error!(logger, "Failed to broadcast {}: {:?}", what, e);
			false
		},
		Err(_elapsed) => {
			log_info!(
				logger,
				"No peer requested {} within {:?}; it stays queued for relay in the CBF client \
				 (a peer that already has a transaction never asks for it) and the broadcast \
				 queue moves on.",
				what,
				hold_timeout,
			);
			false
		},
	}
}

impl CbfChainSource {
	pub(crate) fn new(
		peers: Vec<String>, fee_source_config: Option<CbfFeeSourceConfig>, runtime: Arc<Runtime>,
		fee_estimator: Arc<OnchainFeeEstimator>, kv_store: Arc<DynStore>, config: Arc<Config>,
		logger: Arc<Logger>, node_metrics: Arc<PersistedNodeMetrics>, hooks: ChainServiceHooks,
	) -> Result<Self, Error> {
		let mut trusted_peers = Vec::with_capacity(peers.len());
		for peer_str in &peers {
			let parsed = parse_trusted_peer(peer_str).map_err(|e| {
				log_error!(logger, "Invalid CBF trusted peer '{}': {}", peer_str, e);
				e
			})?;
			trusted_peers.push(parsed.into_trusted_peer());
		}

		let fee_source = match fee_source_config {
			Some(CbfFeeSourceConfig::Esplora(server_url)) => {
				let mut esplora_builder = esplora_client::Builder::new(&server_url);
				esplora_builder = esplora_builder.timeout(ESPLORA_TIMEOUT);
				let client = esplora_builder.build_async().map_err(|e| {
					log_error!(logger, "Failed to build esplora client: {}", e);
					Error::ConnectionFailed
				})?;
				FeeSource::Esplora { client }
			},
			Some(CbfFeeSourceConfig::Electrum(server_url)) => FeeSource::Electrum { server_url },
			None => FeeSource::Cbf { block_fee_cache: Arc::new(Mutex::new(BTreeMap::new())) },
		};
		let registered_scripts = Arc::new(Mutex::new(HashSet::new()));
		let cbf_runtime_status = Arc::new(Mutex::new(CbfRuntimeStatus::Stopped));
		let (sync_state_tx, _) =
			watch::channel(CbfSyncState::Active { applied_tip: None, synced_to_tip: false });
		Ok(Self {
			trusted_peers,
			fee_source,
			registered_scripts,
			cbf_runtime_status,
			sync_state_tx,
			runtime,
			config,
			fee_estimator,
			kv_store,
			node_metrics,
			logger,
			hooks,
		})
	}

	fn build_kyoto(
		trusted_peers: &[TrustedPeer], config: &Config, logger: &Logger,
		chain_listener: &ChainListener,
	) -> (KyotoNode, Client) {
		let mut kyoto_builder = KyotoBuilder::new(config.network);

		let data_dir = std::path::PathBuf::from(&config.storage_dir_path).join("bip157_data");
		kyoto_builder = kyoto_builder.data_dir(data_dir);

		if !trusted_peers.is_empty() {
			kyoto_builder = kyoto_builder.add_peers(trusted_peers.to_vec());
		}

		kyoto_builder = kyoto_builder.required_peers(DEFAULT_REQUIRED_PEERS);
		kyoto_builder = kyoto_builder.fetch_witness_data();
		kyoto_builder =
			kyoto_builder.response_timeout(Duration::from_secs(DEFAULT_RESPONSE_TIMEOUT_SECS));

		if let Some(header_cp) = resume_checkpoint(logger, chain_listener) {
			log_debug!(
				logger,
				"CBF builder: resuming from checkpoint height={}, hash={}",
				header_cp.height,
				header_cp.hash,
			);
			kyoto_builder = kyoto_builder.chain_state(ChainState::Checkpoint(header_cp));
		}

		kyoto_builder.build()
	}

	/// Returns the shared on-chain fee estimator backing this chain source
	/// (Peerswap native primitive B6). CBF derives real fee-rate estimates
	/// (from an external source or recent-block coinbase outputs, see
	/// [`CbfFeeSourceConfig`]), so — unlike arbitrary raw-tx confirmation
	/// queries — feerate estimation is fully supported under CBF.
	#[cfg(feature = "swaps")]
	pub(super) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		&self.fee_estimator
	}

	/// Returns a simplified, externally-consumable snapshot of the current
	/// CBF sync state. Never blocks — reads the current value of the
	/// `watch` channel without waiting for a change.
	pub(super) fn sync_status(&self) -> CbfSyncStatus {
		simplify_sync_state(*self.sync_state_tx.borrow())
	}

	pub(crate) fn start(&self, chain_listener: ChainListener) {
		let (node, client) =
			Self::build_kyoto(&self.trusted_peers, &self.config, &self.logger, &chain_listener);
		let Client { requester, info_rx, warn_rx, event_rx } = client;

		{
			let mut status = self.cbf_runtime_status.lock().expect("lock");
			if matches!(*status, CbfRuntimeStatus::Started { .. }) {
				debug_assert!(false, "start() called while CBF chain source is already running");
				return;
			}
			*status = CbfRuntimeStatus::Started { requester };
		}

		let (ops_tx, ops_rx) = mpsc::channel(CBF_CHAIN_OP_QUEUE_DEPTH);
		let block_fee_cache = match &self.fee_source {
			FeeSource::Cbf { block_fee_cache } => Some(Arc::clone(block_fee_cache)),
			_ => None,
		};
		let best_block_height = chain_listener.get_best_block().height;
		self.sync_state_tx.send_replace(CbfSyncState::Active {
			applied_tip: Some(best_block_height),
			synced_to_tip: false,
		});
		let block_applicator = BlockApplicator {
			next_height: best_block_height + 1,
			blocks_since_flush: 0,
			sync_state_tx: self.sync_state_tx.clone(),
			chain_listener: chain_listener.clone(),
			ops_rx,
			block_fee_cache,
			kv_store: Arc::clone(&self.kv_store),
			node_metrics: Arc::clone(&self.node_metrics),
			logger: Arc::clone(&self.logger),
		};
		self.runtime.spawn_background_task(block_applicator.run());

		log_info!(self.logger, "CBF chain source started.");

		let restart_status = Arc::clone(&self.cbf_runtime_status);
		let restart_logger = Arc::clone(&self.logger);
		let restart_peers = self.trusted_peers.clone();
		let restart_config = Arc::clone(&self.config);
		let restart_listener = chain_listener;
		let restart_registered_scripts = Arc::clone(&self.registered_scripts);
		let restart_cbf_runtime_status = Arc::clone(&self.cbf_runtime_status);
		let restart_sync_state_tx = self.sync_state_tx.clone();

		self.runtime.spawn_background_task(async move {
			let mut current_node = node;
			let mut current_info_rx = info_rx;
			let mut current_warn_rx = warn_rx;
			let mut current_event_rx = event_rx;
			let mut retries = 0u32;
			let mut backoff_ms = INITIAL_BACKOFF_MS;

			loop {
				let info_handle = tokio::spawn(Self::process_info_messages(
					current_info_rx,
					Arc::clone(&restart_logger),
				));
				let warn_handle = tokio::spawn(Self::process_warn_messages(
					current_warn_rx,
					Arc::clone(&restart_logger),
				));

				let event_handle = tokio::spawn(Self::process_kyoto_events(
					Arc::clone(&restart_logger),
					current_event_rx,
					Arc::clone(&restart_registered_scripts),
					Arc::clone(&restart_cbf_runtime_status),
					ops_tx.clone(),
					Arc::clone(&restart_listener.onchain_wallet),
					restart_sync_state_tx.clone(),
				));

				match current_node.run().await {
					Ok(()) => {
						log_info!(restart_logger, "CBF node shut down cleanly.");
						*restart_status.lock().expect("lock") = CbfRuntimeStatus::Stopped;
						restart_sync_state_tx.send_replace(CbfSyncState::Failed(Error::NotRunning));
						break;
					},
					Err(e) => {
						retries += 1;
						if retries > MAX_RESTART_RETRIES {
							log_error!(
								restart_logger,
								"CBF node failed {} times, giving up: {:?}",
								retries,
								e,
							);
							*restart_status.lock().expect("lock") = CbfRuntimeStatus::Stopped;
							restart_sync_state_tx
								.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
							break;
						}
						log_error!(
							restart_logger,
							"CBF node exited with error (attempt {}/{}): {:?}. Restarting in {}ms.",
							retries,
							MAX_RESTART_RETRIES,
							e,
							backoff_ms,
						);

						// Abort the old log consumers before rebuilding.
						info_handle.abort();
						warn_handle.abort();
						event_handle.abort();

						tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
						backoff_ms = backoff_ms.saturating_mul(2);
						let (new_node, new_client) = Self::build_kyoto(
							&restart_peers,
							&restart_config,
							&restart_logger,
							&restart_listener,
						);
						let Client {
							requester: new_requester,
							info_rx: new_info_rx,
							warn_rx: new_warn_rx,
							event_rx: new_event_rx,
						} = new_client;

						{
							let mut status = restart_status.lock().expect("lock");
							if matches!(*status, CbfRuntimeStatus::Stopped) {
								let _ = new_requester.shutdown();
								restart_sync_state_tx
									.send_replace(CbfSyncState::Failed(Error::NotRunning));
								log_info!(
									restart_logger,
									"CBF restart aborted: stop() called during backoff."
								);
								break;
							}
							*status = CbfRuntimeStatus::Started { requester: new_requester };
							restart_sync_state_tx.send_replace(CbfSyncState::Active {
								applied_tip: Some(restart_listener.get_best_block().height),
								synced_to_tip: false,
							});
						}

						current_node = new_node;
						current_info_rx = new_info_rx;
						current_warn_rx = new_warn_rx;
						current_event_rx = new_event_rx;
					},
				}
			}
		});
	}

	pub(crate) fn stop(&self) {
		let requester = {
			let mut status = self.cbf_runtime_status.lock().expect("lock");
			match &*status {
				CbfRuntimeStatus::Started { requester } => {
					let requester = requester.clone();
					*status = CbfRuntimeStatus::Stopped;
					Some(requester)
				},
				CbfRuntimeStatus::Stopped => None,
			}
		};

		if let Some(requester) = requester {
			if let Err(e) = requester.shutdown() {
				log_error!(self.logger, "Failed to shut down CBF node: {:?}", e);
			}
		}
		self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::NotRunning));
	}

	pub(crate) async fn wait_until_synced(&self) -> Result<(), Error> {
		if matches!(&*self.cbf_runtime_status.lock().expect("lock"), CbfRuntimeStatus::Stopped) {
			return Err(Error::NotRunning);
		}
		let mut sync_state_rx = self.sync_state_tx.subscribe();

		// Wait for kyoto to report catching up to the network tip (a `FiltersSynced`-driven
		// `synced_to_tip`) and for the resulting blocks to be applied. We must not target a
		// locally-sampled `chain_tip()`: kyoto does not persist, so a freshly (re)started node's
		// local header chain sits at genesis until it syncs from peers, which would let this return
		// before any sync happens.
		loop {
			match *sync_state_rx.borrow() {
				CbfSyncState::Active { synced_to_tip, .. } => {
					if synced_to_tip {
						return Ok(());
					}
				},
				CbfSyncState::Failed(error) => return Err(error),
			}

			if let Err(e) = sync_state_rx.changed().await {
				debug_assert!(false, "Failed to receive CBF sync result: {:?}", e);
				log_error!(self.logger, "Failed to receive CBF sync result: {:?}", e);
				return Err(Error::TxSyncFailed);
			}
		}
	}

	async fn process_info_messages(mut info_rx: mpsc::Receiver<Info>, logger: Arc<Logger>) {
		while let Some(info) = info_rx.recv().await {
			log_debug!(logger, "CBF node info: {}", info);
		}
	}

	async fn process_warn_messages(
		mut warn_rx: mpsc::UnboundedReceiver<Warning>, logger: Arc<Logger>,
	) {
		while let Some(warning) = warn_rx.recv().await {
			log_debug!(logger, "CBF node warning: {}", warning);
		}
	}

	async fn process_kyoto_events(
		logger: Arc<Logger>, mut event_rx: mpsc::UnboundedReceiver<KyotoEvent>,
		registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
		cbf_runtime_status: Arc<Mutex<CbfRuntimeStatus>>, ops_tx: mpsc::Sender<ChainOp>,
		onchain_wallet: Arc<Wallet>, sync_state_tx: watch::Sender<CbfSyncState>,
	) {
		while let Some(event) = event_rx.recv().await {
			match event {
				KyotoEvent::IndexedFilter(indexed_filter) => {
					// A new block's filter arrived, so we're behind by at least this block until it
					// is fetched (if matched) and applied. Flip this before the fetch, not after,
					// so a `sync_wallets` call issued in between doesn't return on a stale
					// `synced_to_tip` that predates this block.
					mark_syncing(&sync_state_tx);

					// Copy the requester out and release the lock before any `.await` below: this is a
					// `std::sync::Mutex`, so holding its guard across an await point would make this
					// future non-`Send` and it could not be spawned.
					let requester_opt = match &*cbf_runtime_status.lock().expect("lock") {
						CbfRuntimeStatus::Started { requester } => Some(requester.clone()),
						CbfRuntimeStatus::Stopped => None,
					};
					let requester = match requester_opt {
						Some(requester) => requester,
						None => {
							let _ = ops_tx.send(ChainOp::Failed { error: Error::NotRunning }).await;
							return;
						},
					};
					//registered_scripts contains only LDK scripts, not onchain wallet's scripts,
					//as don't want to track them twice: once in bdk, once in CbfChainSource, thus
					//each time we receive an IndexedFilter event, we ask bdk to give us all
					//revealed scripts. We create all_scripts starting from onchain wallet's
					//scripts and extend them with LDK's ones
					let mut all_scripts = onchain_wallet.list_watched_scripts();
					all_scripts.extend(registered_scripts.lock().expect("lock").iter().cloned());

					let block_hash = indexed_filter.block_hash();
					let matched = indexed_filter.contains_any(all_scripts.iter());

					let chop: ChainOp = if matched {
						let mut attempt = 0;
						let block = loop {
							attempt += 1;
							let handle = match requester.request_block(block_hash) {
								Ok(handle) => handle,
								Err(_) => {
									log_error!(
										logger,
										"Failed to obtain receiver for matched CBF block {}; node is stopped",
										block_hash
									);
									let _ = ops_tx
										.send(ChainOp::Failed { error: Error::NotRunning })
										.await;
									return;
								},
							};

							// Bound the download so an unresponsive peer can't park the fetch forever,
							// then flatten the three error layers (timeout / receiver dropped / fetch
							// error) into a single reason so the retry-or-fail decision is written once.
							let fetched = tokio::time::timeout(
								Duration::from_secs(CBF_BLOCK_FETCH_TIMEOUT_SECS),
								handle,
							)
							.await
							.map_err(|_| {
								format!("timed out after {}s", CBF_BLOCK_FETCH_TIMEOUT_SECS)
							})
							.and_then(|recv| recv.map_err(|_| "receiver was dropped".to_string()))
							.and_then(|fetch| fetch.map_err(|e| format!("failed: {:?}", e)));

							match fetched {
								Ok(block) => break block,
								Err(reason) if attempt < CBF_BLOCK_FETCH_RETRIES => {
									log_debug!(
										logger,
										"CBF block fetch for {} {} on attempt {}; retrying",
										block_hash,
										reason,
										attempt
									);
								},
								Err(reason) => {
									log_error!(
										logger,
										"CBF block fetch for {} {} after {} attempts; giving up",
										block_hash,
										reason,
										CBF_BLOCK_FETCH_RETRIES
									);
									let _ = ops_tx
										.send(ChainOp::Failed { error: Error::TxSyncFailed })
										.await;
									return;
								},
							}
						};
						ChainOp::ConnectFull { block }
					} else {
						ChainOp::ConnectFiltered {
							header: indexed_filter.header(),
							height: indexed_filter.height(),
						}
					};
					if let Err(e) = ops_tx.send(chop).await {
						log_debug!(logger, "ops_rx gone: {}", e);
					}
				},
				KyotoEvent::FiltersSynced(sync_update) => {
					//Because application of blocks is async, the fact that kyoto synced up to the
					//tip does NOT mean that we caught everything up, that's why we send a ChainOp,
					//only processing of which means we processed all blocks up to the tip.
					log_info!(logger, "Kyoto synced up to the tip {}", sync_update.tip().height);
					let _ =
						ops_tx.send(ChainOp::Synced { tip_height: sync_update.tip().height }).await;
				},
				KyotoEvent::ChainUpdate(BlockHeaderChanges::Connected(indexed_header)) => {
					log_debug!(
						logger,
						"Kyoto connected header at height {}",
						indexed_header.height
					);
				},
				KyotoEvent::ChainUpdate(BlockHeaderChanges::Reorganized {
					reorganized,
					accepted: _,
				}) => {
					// Rewind to the fork point; kyoto will re-deliver the new chain's filters.
					if let Some(lowest) = reorganized.first() {
						let fork_point = BlockLocator::new(
							lowest.prev_blockhash(),
							lowest.height.saturating_sub(1),
						);
						let _ = ops_tx.send(ChainOp::Disconnect { fork_point }).await;
					}
				},
				KyotoEvent::ChainUpdate(BlockHeaderChanges::ForkAdded(fork)) => {
					log_debug!(logger, "Kyoto added fork header at height {}", fork.height);
				},
			}
		}
	}

	pub(crate) fn register_tx(&self, _txid: &Txid, script_pubkey: &Script) {
		self.registered_scripts.lock().expect("lock").insert(script_pubkey.into());
	}

	pub(crate) fn register_output(&self, output: WatchedOutput) {
		self.registered_scripts.lock().expect("lock").insert(output.script_pubkey);
	}

	pub(crate) async fn continuously_update_fee_rate_estimates(
		&self, mut stop_sync_receiver: watch::Receiver<()>,
	) {
		let mut fee_rate_update_interval =
			tokio::time::interval(Duration::from_secs(DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS));
		// We primed the cache once on startup, so skip the immediate first tick.
		fee_rate_update_interval.reset();
		fee_rate_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		loop {
			tokio::select! {
				_ = stop_sync_receiver.changed() => {
					log_trace!(self.logger, "Stopping CBF fee-rate update loop.");
					return;
				}
				_ = fee_rate_update_interval.tick() => {
					if let Err(e) = self.update_fee_rate_estimates().await {
						log_error!(self.logger, "Failed to update fee rate estimates: {:?}", e);
					}
				}
			}
		}
	}

	pub(crate) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		let new_fee_rate_cache = resolve_fee_estimates(
			&self.hooks,
			&self.logger,
			Duration::from_secs(CHAIN_SERVICE_HOOK_TIMEOUT_SECS),
			|| self.fee_rate_cache_from_source(),
		)
		.await?;

		self.commit_fee_rate_cache(new_fee_rate_cache).await
	}

	/// The existing (Esplora / Electrum / native-CBF) fee computation, unchanged from before the
	/// [`ChainServiceHooks`] fee-estimates hook was introduced. Called by
	/// [`update_fee_rate_estimates`](Self::update_fee_rate_estimates) as the `fallback` passed to
	/// [`resolve_fee_estimates`].
	async fn fee_rate_cache_from_source(
		&self,
	) -> Result<HashMap<ConfirmationTarget, FeeRate>, Error> {
		let new_fee_rate_cache = match &self.fee_source {
			FeeSource::Esplora { client } => {
				let estimates = client.get_fee_estimates().await.map_err(|e| {
					log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
					Error::FeerateEstimationUpdateFailed
				})?;

				if estimates.is_empty() && self.config.network == Network::Bitcoin {
					log_error!(
						self.logger,
						"Failed to retrieve fee rate: empty fee estimates are disallowed on Mainnet."
					);
					return Err(Error::FeerateEstimationUpdateFailed);
				}

				let mut new_fee_rate_cache = HashMap::with_capacity(10);
				for target in get_all_conf_targets() {
					let num_blocks = get_num_block_defaults_for_target(target);
					// Fall back to 1 sat/vb if we fail or it yields less than that, mostly to keep
					// going on signet/regtest where estimates may be missing or bogus.
					let converted_estimate_sat_vb =
						esplora_client::convert_fee_rate(num_blocks, estimates.clone())
							.map_or(1.0, |converted| converted.max(1.0));
					let fee_rate =
						FeeRate::from_sat_per_kwu((converted_estimate_sat_vb * 250.0) as u64);
					let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);
					new_fee_rate_cache.insert(target, adjusted_fee_rate);
				}
				new_fee_rate_cache
			},
			FeeSource::Electrum { server_url } => {
				let electrum_config = ElectrumConfigBuilder::new()
					.retry(ELECTRUM_FEE_NUM_RETRIES)
					.timeout(Some(Duration::from_secs(ELECTRUM_FEE_TIMEOUT_SECS)))
					.build();

				let server_url = server_url.clone();
				let electrum_client = self
					.runtime
					.spawn_blocking(move || {
						ElectrumClient::from_config(&server_url, electrum_config)
					})
					.await
					.map_err(|e| {
						log_error!(self.logger, "Fee rate estimation task panicked: {}", e);
						Error::FeerateEstimationUpdateFailed
					})?
					.map_err(|e| {
						log_error!(self.logger, "Failed to connect to electrum server: {}", e);
						Error::ConnectionFailed
					})?;

				get_electrum_fee_rate_cache_update(
					Arc::clone(&self.runtime),
					Arc::new(electrum_client),
					self.config.network,
					ELECTRUM_FEE_TIMEOUT_SECS,
					Arc::clone(&self.logger),
				)
				.await?
			},
			FeeSource::Cbf { block_fee_cache } => {
				let requester = match &*self.cbf_runtime_status.lock().expect("lock") {
					CbfRuntimeStatus::Started { requester } => requester.clone(),
					CbfRuntimeStatus::Stopped => return Err(Error::FeerateEstimationUpdateFailed),
				};
				let mut samples_sat_per_kwu: Vec<u64> = self
					.refresh_block_fee_window(&requester, block_fee_cache)
					.await
					.iter()
					.map(|rate| rate.to_sat_per_kwu())
					.collect();
				samples_sat_per_kwu.sort_unstable();

				let mut new_fee_rate_cache = HashMap::with_capacity(10);
				for target in get_all_conf_targets() {
					let fee_rate = if samples_sat_per_kwu.is_empty() {
						FeeRate::from_sat_per_kwu(get_fallback_rate_for_target(target) as u64)
					} else {
						let percentile = cbf_percentile_for_target(target);
						let sat_per_kwu = percentile_of_sorted(&samples_sat_per_kwu, percentile)
							.max(CBF_MIN_FEERATE_SAT_PER_KWU);
						FeeRate::from_sat_per_kwu(sat_per_kwu)
					};
					let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);
					new_fee_rate_cache.insert(target, adjusted_fee_rate);
				}
				new_fee_rate_cache
			},
		};

		Ok(new_fee_rate_cache)
	}

	/// Writes a freshly computed per-target fee-rate map into the estimator cache and records the
	/// update timestamp in the node metrics.
	async fn commit_fee_rate_cache(
		&self, new_fee_rate_cache: HashMap<ConfirmationTarget, FeeRate>,
	) -> Result<(), Error> {
		self.fee_estimator.set_fee_rate_cache(new_fee_rate_cache);
		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		update_and_persist_node_metrics(&self.node_metrics, &*self.kv_store, &*self.logger, |m| {
			m.latest_fee_rate_cache_update_timestamp = unix_time_secs_opt
		})
		.await?;
		Ok(())
	}

	pub(crate) async fn process_broadcast_package(&self, package: Vec<Transaction>) {
		// Read the requester (if any) up front, but do NOT bail out when the kyoto runtime is
		// stopped: the broadcast hook must still be tried (it's payment-agnostic and may be the
		// only working relay left once the CBF restart loop has given up, e.g. for a
		// time-sensitive force-close tx). Only the P2P fallback leg below actually needs a live
		// `Requester` — it degrades to an error log when there isn't one.
		let requester = match &*self.cbf_runtime_status.lock().expect("lock") {
			CbfRuntimeStatus::Started { requester } => Some(requester.clone()),
			CbfRuntimeStatus::Stopped => None,
		};
		let logger = Arc::clone(&self.logger);

		let outcome = dispatch_broadcast(
			&self.hooks,
			&self.logger,
			Duration::from_secs(CHAIN_SERVICE_HOOK_TIMEOUT_SECS),
			package,
			move |package| async move {
				let Some(requester) = requester else {
					log_error!(
						logger,
						"Cannot P2P-broadcast transaction package: CBF chain source is stopped \
						 and no external chain-service broadcast hook accepted it."
					);
					return;
				};
				let hold_timeout = Duration::from_secs(CBF_P2P_BROADCAST_TIMEOUT_SECS);
				match Package::from_vec(package.clone()) {
					Ok(kyoto_package) => {
						bounded_p2p_handoff(
							&logger,
							hold_timeout,
							"the transaction package",
							requester.submit_package(kyoto_package),
						)
						.await;
					},
					Err(_) => {
						for tx in package {
							let what = format!("transaction {}", tx.compute_txid());
							bounded_p2p_handoff(
								&logger,
								hold_timeout,
								&what,
								requester.submit_package(tx),
							)
							.await;
						}
					},
				}
			},
		)
		.await;

		if outcome == BroadcastOutcome::HookHandled {
			log_debug!(
				self.logger,
				"External chain-service broadcast hook accepted the transaction package; P2P \
				 relay skipped."
			);
		}
	}

	/// Reconciles the block-fee cache against the canonical chain and returns the per-block fee
	/// rates for the most recent [`FEE_WINDOW_BLOCKS`] blocks.
	///
	/// For each height in the window we fetch the canonical block hash; if the cached entry still
	/// matches we reuse its rate, otherwise (new block, or a block that was reorged out) we download
	/// it via [`Requester::average_fee_rate`]. Heights outside the window are evicted by replacing
	/// the cache with the freshly built window.
	///
	/// This is best-effort: a height we can't fetch a header or block for is simply skipped (so a
	/// slow or unresponsive peer can't stall or void the whole update), and an empty result just
	/// means we have no recent data yet. The window therefore fills incrementally over successive
	/// updates rather than requiring all [`FEE_WINDOW_BLOCKS`] downloads to succeed at once.
	async fn refresh_block_fee_window(
		&self, requester: &Requester, cache: &Mutex<BTreeMap<u32, (BlockHash, FeeRate)>>,
	) -> Vec<FeeRate> {
		let tip_height = match requester.chain_tip().await {
			Ok(tip) => tip.height,
			Err(e) => {
				log_error!(self.logger, "CBF fee update: failed to fetch chain tip: {:?}", e);
				return Vec::new();
			},
		};
		let lo = tip_height.saturating_sub(FEE_WINDOW_BLOCKS - 1);

		// Snapshot the cache so we never hold the std `Mutex` across an `.await`.
		let cached = cache.lock().expect("lock").clone();

		let mut window = BTreeMap::new();
		for height in lo..=tip_height {
			let canonical_hash = match requester.get_header(height).await {
				// Height not available (yet); skip it.
				Ok(None) => continue,
				Ok(Some(header)) => header.block_hash(),
				Err(e) => {
					log_debug!(
						self.logger,
						"CBF fee update: failed to fetch header at height {}, skipping: {:?}",
						height,
						e
					);
					continue;
				},
			};

			// Reuse the cached rate while the block is still canonical; otherwise download it.
			if let Some((hash, fee_rate)) = cached.get(&height) {
				if *hash == canonical_hash {
					window.insert(height, (canonical_hash, *fee_rate));
					continue;
				}
			}

			match tokio::time::timeout(
				Duration::from_secs(CBF_BLOCK_FETCH_TIMEOUT_SECS),
				requester.average_fee_rate(canonical_hash),
			)
			.await
			{
				Ok(Ok(fee_rate)) => {
					window.insert(height, (canonical_hash, fee_rate));
				},
				Ok(Err(e)) => {
					log_debug!(
						self.logger,
						"CBF fee update: failed to fetch fee rate for block {}, skipping: {:?}",
						canonical_hash,
						e
					);
				},
				Err(_) => {
					log_debug!(
						self.logger,
						"CBF fee update: timed out fetching block {} for fee estimation, skipping.",
						canonical_hash,
					);
				},
			}
		}

		let samples = window.values().map(|(_, fee_rate)| *fee_rate).collect();
		// Replacing the cache wholesale also evicts any entries that fell out of the window.
		*cache.lock().expect("lock") = window;
		samples
	}
}

fn resume_checkpoint(logger: &Logger, chain_listener: &ChainListener) -> Option<HashCheckpoint> {
	let min_best_block = chain_listener.get_best_block();
	let bdk_cp = chain_listener.onchain_wallet.latest_checkpoint();

	if let Some(bdk_at_height) = bdk_cp.get(min_best_block.height) {
		if bdk_at_height.hash() != min_best_block.block_hash {
			log_error!(
				logger,
				"CBF resume: listener best block at height {} has hash {} but BDK has {}; \
					 a component may be on a stale fork. Anchoring on BDK's chain.",
				min_best_block.height,
				min_best_block.block_hash,
				bdk_at_height.hash(),
			);
		}
	}

	// Walk BDK's checkpoint chain back to the reorg-safe anchor height.
	let target_height = min_best_block.height.saturating_sub(REORG_SAFETY_BLOCKS);
	let cursor = resume_anchor(bdk_cp, target_height);

	if cursor.height() > min_best_block.height {
		// The wallet's lowest usable checkpoint sits above a listener (e.g. a wallet anchored
		// at its birthday next to Lightning state persisted below it). Anchoring kyoto there
		// would make it emit only blocks the applicator refuses to apply — `next_height`
		// derives from the *minimum* listener — stalling sync forever without ever tripping
		// the divergence gate. Fall back to a full scan so the lagging listener can catch up.
		log_error!(
			logger,
			"CBF resume: wallet's lowest usable checkpoint (height {}) is above the \
			 furthest-behind listener (height {}); falling back to a scan from genesis.",
			cursor.height(),
			min_best_block.height,
		);
		return None;
	}

	(cursor.height() > 0).then(|| HashCheckpoint::new(cursor.height(), cursor.hash()))
}

/// Walks `bdk_cp` back toward `target_height` without ever stepping onto genesis.
///
/// On a dense chain this lands on the checkpoint at `target_height`, exactly like a plain
/// walk. The genesis guard matters for sparse chains — most importantly a fresh wallet whose
/// only real anchor is its birthday checkpoint (`[genesis, birthday]`): stepping onto genesis
/// there would make [`resume_checkpoint`] return `None` and silently demote the node to a full
/// filter scan from block 1, with every block below the birthday discarded on arrival.
fn resume_anchor(bdk_cp: bdk_chain::CheckPoint, target_height: u32) -> bdk_chain::CheckPoint {
	let mut cursor = bdk_cp;
	while cursor.height() > target_height {
		match cursor.prev() {
			Some(prev) if prev.height() > 0 => cursor = prev,
			_ => break,
		}
	}
	cursor
}

/// Returns the highest checkpoint compiled into the `bip157` crate strictly below
/// `first_scan_height`, or `None` when the wallet should root at genesis.
///
/// Strictly below, because everything downstream — the initial BDK checkpoint, the listeners'
/// best block, kyoto's `ChainState::Checkpoint` — treats the anchor as already applied, and
/// scanning begins at the block after it. An anchor *at* `first_scan_height` would silently
/// skip that block's filters, losing a transaction confirmed exactly there.
///
/// Only compiled-in constants are used: CBF has no chain backend at build time, and consulting
/// a third-party tip oracle would reintroduce exactly the dependency this chain source removes.
/// Rounding down can only extend the scanned range, never shrink it. Mainnet ships three such
/// anchors — 481,823 (one block before SegWit activation), 709,631 (one block before taproot
/// activation) and 965,999 (see [`anchor_965_999`]); all other networks resolve to `None`.
pub(crate) fn birthday_checkpoint(
	network: Network, first_scan_height: u32,
) -> Option<HashCheckpoint> {
	if network != Network::Bitcoin {
		return None;
	}
	mainnet_anchors()
		.into_iter()
		.map(|(cp, _)| cp)
		.filter(|cp| cp.height < first_scan_height)
		.max_by_key(|cp| cp.height)
}

/// Mainnet block 965,999 (mined 2026-09-08), the newest compiled birthday anchor: a wallet
/// born at block 966,000 or later scans nothing older than that, instead of falling through to
/// the taproot anchor and ~256,000 blocks of filters. The hash was cross-checked against three
/// independent explorers (mempool.space, blockstream.info, blockcypher.com) on 2026-09-09,
/// about 100 blocks below the tip, so no reorg can reach it. Add a newer entry to
/// [`mainnet_anchors`] when a later birthday is wanted; never edit an existing one — wallets
/// already anchored on it would latch divergence at the next start.
fn anchor_965_999() -> HashCheckpoint {
	let hash = "00000000000000000000dbb4d1e55ad22ed5b5a7d81d4c0fe992fceb8a5302d0"
		.parse::<bitcoin::BlockHash>()
		.expect("compiled block hash");
	HashCheckpoint::new(965_999, hash)
}

/// Every compiled mainnet birthday anchor, ascending, with the provenance label the startup
/// log prints beside it.
fn mainnet_anchors() -> [(HashCheckpoint, &'static str); 3] {
	[
		(HashCheckpoint::segwit_activation(), "bip157 segwit_activation constant"),
		(HashCheckpoint::taproot_activation(), "bip157 taproot_activation constant"),
		(anchor_965_999(), "ldk-node block 965,999 constant"),
	]
}

/// Resolves a configured `wallet_rescan_from_height` into the initial chain tip handed to the
/// builder, logging the anchor and its provenance.
///
/// The returned locator seeds the initial BDK checkpoint of a wallet whose persisted chain
/// state is still rooted at genesis, the best block of a freshly created `ChannelManager` and
/// sweeper, and — through them — kyoto's resume checkpoint and the block applicator's
/// `next_height`. A wallet with a persisted block is never rewound, but absent Lightning
/// components are still initialized from it.
pub(crate) fn resolve_birthday(
	logger: &Logger, network: Network, wallet_rescan_from_height: Option<u32>,
) -> Option<BlockLocator> {
	let requested = wallet_rescan_from_height?;
	match birthday_checkpoint(network, requested) {
		Some(cp) => {
			let provenance = mainnet_anchors()
				.into_iter()
				.find(|(anchor, _)| *anchor == cp)
				.map(|(_, label)| label)
				.unwrap_or("compiled anchor");
			log_info!(
				logger,
				"CBF wallet birthday: requested height {} resolved to compiled checkpoint at \
				 height {} (hash {}, {}); scanning starts at height {}. Applied only while the \
				 wallet's persisted chain state is still rooted at genesis.",
				requested,
				cp.height,
				cp.hash,
				provenance,
				cp.height + 1,
			);
			Some(BlockLocator::new(cp.hash, cp.height))
		},
		None => {
			log_info!(
				logger,
				"CBF wallet birthday: no compiled checkpoint strictly below requested height {} \
				 on {}; a fresh wallet will scan from genesis.",
				requested,
				network,
			);
			None
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::Hash;

	// ------------------------------------------------------------------------------------------
	// simplify_sync_state: internal CbfSyncState -> public CbfSyncStatus mapping.
	// ------------------------------------------------------------------------------------------

	#[test]
	fn simplify_sync_state_active_not_synced_is_syncing() {
		let state = CbfSyncState::Active { applied_tip: Some(100), synced_to_tip: false };
		assert_eq!(simplify_sync_state(state), CbfSyncStatus::Syncing);
	}

	#[test]
	fn simplify_sync_state_active_no_applied_tip_is_syncing() {
		// Freshly constructed state before `start()` ever ran.
		let state = CbfSyncState::Active { applied_tip: None, synced_to_tip: false };
		assert_eq!(simplify_sync_state(state), CbfSyncStatus::Syncing);
	}

	#[test]
	fn simplify_sync_state_active_synced_to_tip_is_synced() {
		let state = CbfSyncState::Active { applied_tip: Some(900_000), synced_to_tip: true };
		assert_eq!(simplify_sync_state(state), CbfSyncStatus::Synced);
	}

	#[test]
	fn simplify_sync_state_failed_is_failed_regardless_of_error_variant() {
		assert_eq!(
			simplify_sync_state(CbfSyncState::Failed(Error::NotRunning)),
			CbfSyncStatus::Failed
		);
		assert_eq!(
			simplify_sync_state(CbfSyncState::Failed(Error::TxSyncFailed)),
			CbfSyncStatus::Failed
		);
	}

	#[test]
	fn parse_peer_accepts_hostname() {
		let p = parse_trusted_peer("bitcoind.local:18444").expect("hostname peer");
		// shape assertion only — resolution happens at connect time
		assert!(
			matches!(p, ParsedPeer::Hostname { ref host, port } if host == "bitcoind.local" && port == 18444)
		);
		let p2 = parse_trusted_peer("127.0.0.1:18444").expect("socketaddr peer");
		assert!(matches!(p2, ParsedPeer::Addr(_)));
		assert!(parse_trusted_peer("no-port-here").is_err());
	}

	#[test]
	fn birthday_anchors_strictly_below_the_first_scan_height() {
		let newest = anchor_965_999();
		let taproot = HashCheckpoint::taproot_activation();
		let segwit = HashCheckpoint::segwit_activation();

		assert_eq!(birthday_checkpoint(Network::Bitcoin, u32::MAX), Some(newest));
		// A wallet born at block 966,000 anchors one block below it and scans from 966,000.
		assert_eq!(birthday_checkpoint(Network::Bitcoin, 966_000), Some(newest));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, newest.height + 1), Some(newest));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, newest.height), Some(taproot));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, 900_000), Some(taproot));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, taproot.height + 1), Some(taproot));
		// Scanning starts strictly after the anchor, so a first transaction exactly at a
		// compiled anchor height must fall through to the next-lower anchor or that block's
		// filters would never be checked.
		assert_eq!(birthday_checkpoint(Network::Bitcoin, taproot.height), Some(segwit));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, segwit.height + 1), Some(segwit));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, segwit.height), None);
		assert_eq!(birthday_checkpoint(Network::Bitcoin, 0), None);
	}

	#[test]
	fn birthday_is_mainnet_only() {
		for network in [Network::Testnet, Network::Signet, Network::Regtest] {
			assert_eq!(birthday_checkpoint(network, u32::MAX), None);
		}
	}

	#[test]
	fn newest_anchor_is_block_965_999_with_its_published_hash() {
		let newest = anchor_965_999();
		assert_eq!(newest.height, 965_999);
		assert_eq!(
			newest.hash.to_string(),
			"00000000000000000000dbb4d1e55ad22ed5b5a7d81d4c0fe992fceb8a5302d0"
		);
	}

	#[test]
	fn mainnet_anchors_are_distinct_and_ascend() {
		let anchors = mainnet_anchors();
		for pair in anchors.windows(2) {
			assert!(pair[0].0.height < pair[1].0.height, "anchors must ascend: {:?}", anchors);
			assert_ne!(pair[0].0.hash, pair[1].0.hash);
		}
	}

	#[test]
	fn resolve_birthday_anchors_a_966_000_birthday_at_block_965_999() {
		let logger = test_logger();
		let anchor =
			resolve_birthday(&logger, Network::Bitcoin, Some(966_000)).expect("a mainnet anchor");
		assert_eq!(anchor.height, 965_999);
		assert_eq!(anchor.block_hash, anchor_965_999().hash);
		// `None` and non-mainnet networks still root a fresh wallet at genesis.
		assert!(resolve_birthday(&logger, Network::Bitcoin, None).is_none());
		assert!(resolve_birthday(&logger, Network::Regtest, Some(966_000)).is_none());
	}

	fn chain_of(heights: &[u32]) -> bdk_chain::CheckPoint {
		bdk_chain::CheckPoint::from_block_ids(
			heights
				.iter()
				.map(|h| bdk_chain::BlockId { height: *h, hash: bitcoin::BlockHash::all_zeros() }),
		)
		.expect("strictly increasing heights")
	}

	#[test]
	fn resume_anchor_walks_dense_chains_to_the_target() {
		let heights: Vec<u32> = (0..=10).collect();
		let cp = chain_of(&heights);
		assert_eq!(resume_anchor(cp.clone(), 3).height(), 3);
		assert_eq!(resume_anchor(cp.clone(), 10).height(), 10);
		// Target 0 stops at height 1: the anchor never falls onto genesis.
		assert_eq!(resume_anchor(cp, 0).height(), 1);
	}

	#[test]
	fn resume_anchor_never_falls_onto_genesis_on_sparse_chains() {
		// A fresh wallet with a birthday checkpoint: [genesis, birthday]. The reorg-safety
		// walk-back must anchor on the birthday, not slide onto genesis and force a full
		// scan from block 1.
		let cp = chain_of(&[0, 709_631]);
		assert_eq!(resume_anchor(cp, 709_624).height(), 709_631);

		let genesis_only = chain_of(&[0]);
		assert_eq!(resume_anchor(genesis_only, 0).height(), 0);
	}

	// ------------------------------------------------------------------------------------------
	// ChainServiceHooks (Task 5 + fix round 1): fee-estimates and broadcast decision functions.
	// ------------------------------------------------------------------------------------------

	use std::sync::atomic::{AtomicBool, Ordering};

	use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;

	use crate::chain::{BroadcastFuture, FeeEstimatesFuture};

	fn test_logger() -> Logger {
		Logger::new_log_facade()
	}

	/// Generous timeout for tests where the hook resolves immediately — long enough to never be
	/// mistaken for the hung-hook case, short enough to never meaningfully slow the suite down.
	fn generous_test_timeout() -> Duration {
		Duration::from_secs(5)
	}

	/// A full, valid `fee_estimates` map: one entry per distinct block-count target the
	/// estimator needs (`1, 3, 6, 12, 144, 1008`), each with a different sat/vB value so
	/// per-target application can be told apart in assertions.
	fn full_by_blocks_map() -> HashMap<u16, f64> {
		let mut by_blocks = HashMap::new();
		by_blocks.insert(1u16, 50.0);
		by_blocks.insert(3u16, 30.0);
		by_blocks.insert(6u16, 20.0);
		by_blocks.insert(12u16, 15.0);
		by_blocks.insert(144u16, 10.0);
		by_blocks.insert(1008u16, 5.0);
		by_blocks
	}

	/// Mirrors `resolve_fee_estimates`'s own sat/vB -> sat/kwu conversion + post-estimation
	/// adjustment, so tests assert against the real formula instead of a hardcoded, driftable
	/// number.
	fn expected_rate(sat_per_vb: f64, target: ConfirmationTarget) -> FeeRate {
		apply_post_estimation_adjustments(
			target,
			FeeRate::from_sat_per_kwu((sat_per_vb * 250.0) as u64),
		)
	}

	#[test]
	fn required_hook_fee_targets_is_the_six_distinct_block_counts() {
		// Sanity check on the fixture used by every full-map test below: if the per-target
		// block-count defaults ever change, this (and `full_by_blocks_map`) should be the first
		// thing to fail, not a confusing downstream assertion.
		let required = required_hook_fee_targets();
		let mut expected: Vec<u16> = vec![1, 3, 6, 12, 144, 1008];
		expected.sort_unstable();
		let mut actual: Vec<u16> = required.into_iter().collect();
		actual.sort_unstable();
		assert_eq!(actual, expected);
	}

	#[tokio::test]
	async fn chain_service_hooks_fee_estimates_full_map_is_applied_per_target() {
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: Some(Arc::new(|| -> FeeEstimatesFuture {
				Box::pin(async { Ok(full_by_blocks_map()) })
			})),
			broadcast: None,
		};

		let cache = resolve_fee_estimates(&hooks, &logger, generous_test_timeout(), || async {
			panic!("fallback must not run once the map covers every required target")
		})
		.await
		.expect("hook path succeeds");

		// Every one of the 10 conf-targets must be present -- a full map is applied in full.
		assert_eq!(cache.len(), get_all_conf_targets().len());

		let max_fee = ConfirmationTarget::Lightning(LdkConfirmationTarget::MaximumFeeEstimate);
		assert_eq!(cache[&max_fee], expected_rate(50.0, max_fee));

		assert_eq!(
			cache[&ConfirmationTarget::ChannelFunding],
			expected_rate(30.0, ConfirmationTarget::ChannelFunding)
		);

		assert_eq!(
			cache[&ConfirmationTarget::OnchainPayment],
			expected_rate(20.0, ConfirmationTarget::OnchainPayment)
		);
		let urgent_sweep = ConfirmationTarget::Lightning(LdkConfirmationTarget::UrgentOnChainSweep);
		assert_eq!(cache[&urgent_sweep], expected_rate(20.0, urgent_sweep));

		let non_anchor_fee =
			ConfirmationTarget::Lightning(LdkConfirmationTarget::NonAnchorChannelFee);
		assert_eq!(cache[&non_anchor_fee], expected_rate(15.0, non_anchor_fee));
		let output_spending =
			ConfirmationTarget::Lightning(LdkConfirmationTarget::OutputSpendingFee);
		assert_eq!(cache[&output_spending], expected_rate(15.0, output_spending));

		// The special-cased adjustment (trims towards the relay floor) still applies to a
		// hook-sourced rate, exactly as it does for the native sources.
		let min_non_anchor = ConfirmationTarget::Lightning(
			LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
		);
		assert_eq!(cache[&min_non_anchor], expected_rate(10.0, min_non_anchor));
		let close_min = ConfirmationTarget::Lightning(LdkConfirmationTarget::ChannelCloseMinimum);
		assert_eq!(cache[&close_min], expected_rate(10.0, close_min));

		let min_anchor =
			ConfirmationTarget::Lightning(LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee);
		assert_eq!(cache[&min_anchor], expected_rate(5.0, min_anchor));
		let anchor_fee = ConfirmationTarget::Lightning(LdkConfirmationTarget::AnchorChannelFee);
		assert_eq!(cache[&anchor_fee], expected_rate(5.0, anchor_fee));
	}

	#[tokio::test]
	async fn chain_service_hooks_fee_estimates_sparse_map_falls_through_to_fallback() {
		let logger = test_logger();
		// Covers every required block count except 1008 -- a realistic "hook forgot one tier"
		// scenario, not just a totally empty map.
		let hooks = ChainServiceHooks {
			fee_estimates: Some(Arc::new(|| -> FeeEstimatesFuture {
				Box::pin(async {
					let mut by_blocks = full_by_blocks_map();
					by_blocks.remove(&1008u16);
					Ok(by_blocks)
				})
			})),
			broadcast: None,
		};

		let mut configured_source_cache = HashMap::new();
		configured_source_cache
			.insert(ConfirmationTarget::OnchainPayment, FeeRate::from_sat_per_kwu(999));
		let expected = configured_source_cache.clone();

		let fallback_called = Arc::new(AtomicBool::new(false));
		let fallback_called_clone = Arc::clone(&fallback_called);
		let cache = resolve_fee_estimates(&hooks, &logger, generous_test_timeout(), move || {
			let fallback_called = Arc::clone(&fallback_called_clone);
			let configured_source_cache = configured_source_cache.clone();
			async move {
				fallback_called.store(true, Ordering::SeqCst);
				Ok(configured_source_cache)
			}
		})
		.await
		.expect("fallback succeeds");

		assert!(
			fallback_called.load(Ordering::SeqCst),
			"a map missing even one required block-count target must be rejected in full, not \
			 partially applied"
		);
		assert_eq!(cache, expected);
	}

	#[tokio::test]
	async fn chain_service_hooks_fee_estimates_empty_map_falls_through_to_fallback() {
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: Some(Arc::new(|| -> FeeEstimatesFuture {
				Box::pin(async { Ok(HashMap::new()) })
			})),
			broadcast: None,
		};

		let mut configured_source_cache = HashMap::new();
		configured_source_cache
			.insert(ConfirmationTarget::OnchainPayment, FeeRate::from_sat_per_kwu(999));
		let expected = configured_source_cache.clone();

		let fallback_called = Arc::new(AtomicBool::new(false));
		let fallback_called_clone = Arc::clone(&fallback_called);
		let cache = resolve_fee_estimates(&hooks, &logger, generous_test_timeout(), move || {
			let fallback_called = Arc::clone(&fallback_called_clone);
			let configured_source_cache = configured_source_cache.clone();
			async move {
				fallback_called.store(true, Ordering::SeqCst);
				Ok(configured_source_cache)
			}
		})
		.await
		.expect("fallback succeeds");

		assert!(
			fallback_called.load(Ordering::SeqCst),
			"an empty hook map must fall through to the configured source, never be silently \
			 committed as a no-op cache with a fresh timestamp"
		);
		// `resolve_fee_estimates` has exactly one return path per call: since the empty hook
		// result was rejected, the only cache that could ever reach `commit_fee_rate_cache`
		// (and therefore ever get a timestamp stamped) is this fallback cache.
		assert_eq!(cache, expected);
	}

	#[tokio::test]
	async fn chain_service_hooks_fee_estimates_out_of_range_values_are_clamped() {
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: Some(Arc::new(|| -> FeeEstimatesFuture {
				Box::pin(async {
					let mut by_blocks = full_by_blocks_map();
					// Below the floor -> must clamp to CHAIN_SERVICE_HOOK_MIN_SAT_PER_VB, not to
					// whatever a post-conversion `.max()` in sat/kwu units would have floored it
					// to (that was 250x weaker than intended).
					by_blocks.insert(3u16, 0.000_001);
					// Absurdly large -> must clamp to CHAIN_SERVICE_HOOK_MAX_SAT_PER_VB rather
					// than risk an overflow downstream in `FeeRate::to_sat_per_vb_ceil`.
					by_blocks.insert(12u16, 1.0e12);
					Ok(by_blocks)
				})
			})),
			broadcast: None,
		};

		let cache = resolve_fee_estimates(&hooks, &logger, generous_test_timeout(), || async {
			panic!("fallback must not run once the map covers every required target")
		})
		.await
		.expect("hook path succeeds (all required targets present, just out of range)");

		assert_eq!(
			cache[&ConfirmationTarget::ChannelFunding],
			expected_rate(CHAIN_SERVICE_HOOK_MIN_SAT_PER_VB, ConfirmationTarget::ChannelFunding)
		);
		let non_anchor_fee =
			ConfirmationTarget::Lightning(LdkConfirmationTarget::NonAnchorChannelFee);
		assert_eq!(
			cache[&non_anchor_fee],
			expected_rate(CHAIN_SERVICE_HOOK_MAX_SAT_PER_VB, non_anchor_fee)
		);
	}

	#[tokio::test]
	async fn chain_service_hooks_fee_estimates_hook_error_falls_through() {
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: Some(Arc::new(|| -> FeeEstimatesFuture { Box::pin(async { Err(()) }) })),
			broadcast: None,
		};

		let mut configured_source_cache = HashMap::new();
		configured_source_cache
			.insert(ConfirmationTarget::OnchainPayment, FeeRate::from_sat_per_kwu(999));
		let expected = configured_source_cache.clone();

		let fallback_called = Arc::new(AtomicBool::new(false));
		let fallback_called_clone = Arc::clone(&fallback_called);
		let cache = resolve_fee_estimates(&hooks, &logger, generous_test_timeout(), move || {
			let fallback_called = Arc::clone(&fallback_called_clone);
			let configured_source_cache = configured_source_cache.clone();
			async move {
				fallback_called.store(true, Ordering::SeqCst);
				Ok(configured_source_cache)
			}
		})
		.await
		.expect("fallback succeeds");

		assert!(
			fallback_called.load(Ordering::SeqCst),
			"an errored hook must fall through to the configured fee source"
		);
		assert_eq!(cache, expected);
	}

	#[tokio::test]
	async fn chain_service_hooks_fee_estimates_no_hook_falls_through() {
		let logger = test_logger();
		let hooks = ChainServiceHooks::default();

		let fallback_called = Arc::new(AtomicBool::new(false));
		let fallback_called_clone = Arc::clone(&fallback_called);
		let _ = resolve_fee_estimates(&hooks, &logger, generous_test_timeout(), move || {
			let fallback_called = Arc::clone(&fallback_called_clone);
			async move {
				fallback_called.store(true, Ordering::SeqCst);
				Ok(HashMap::new())
			}
		})
		.await
		.expect("fallback succeeds");

		assert!(fallback_called.load(Ordering::SeqCst), "no hook configured must fall through");
	}

	#[tokio::test]
	async fn chain_service_hooks_fee_estimates_hook_timeout_falls_through() {
		let logger = test_logger();
		// Never resolves -- combined with a short injected timeout below, this proves the
		// timeout actually fires rather than hanging the fee-update cycle forever.
		let hooks = ChainServiceHooks {
			fee_estimates: Some(Arc::new(|| -> FeeEstimatesFuture {
				Box::pin(std::future::pending())
			})),
			broadcast: None,
		};

		let mut configured_source_cache = HashMap::new();
		configured_source_cache
			.insert(ConfirmationTarget::OnchainPayment, FeeRate::from_sat_per_kwu(999));
		let expected = configured_source_cache.clone();

		let fallback_called = Arc::new(AtomicBool::new(false));
		let fallback_called_clone = Arc::clone(&fallback_called);
		let cache = resolve_fee_estimates(&hooks, &logger, Duration::from_millis(10), move || {
			let fallback_called = Arc::clone(&fallback_called_clone);
			let configured_source_cache = configured_source_cache.clone();
			async move {
				fallback_called.store(true, Ordering::SeqCst);
				Ok(configured_source_cache)
			}
		})
		.await
		.expect("fallback succeeds");

		assert!(
			fallback_called.load(Ordering::SeqCst),
			"a hung hook must time out and fall through"
		);
		assert_eq!(cache, expected);
	}

	#[tokio::test]
	async fn chain_service_hooks_broadcast_hook_ok_skips_p2p() {
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: None,
			broadcast: Some(Arc::new(|_txs| -> BroadcastFuture { Box::pin(async { Ok(()) }) })),
		};
		let p2p_called = Arc::new(AtomicBool::new(false));
		let p2p_called_clone = Arc::clone(&p2p_called);

		let outcome =
			dispatch_broadcast(&hooks, &logger, generous_test_timeout(), Vec::new(), move |_txs| {
				let p2p_called = Arc::clone(&p2p_called_clone);
				async move {
					p2p_called.store(true, Ordering::SeqCst);
				}
			})
			.await;

		assert_eq!(outcome, BroadcastOutcome::HookHandled);
		assert!(
			!p2p_called.load(Ordering::SeqCst),
			"P2P broadcast must not run when the hook accepts the package"
		);
	}

	#[tokio::test]
	async fn chain_service_hooks_broadcast_hook_err_falls_through_to_p2p() {
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: None,
			broadcast: Some(Arc::new(|_txs| -> BroadcastFuture { Box::pin(async { Err(()) }) })),
		};
		let p2p_called = Arc::new(AtomicBool::new(false));
		let p2p_called_clone = Arc::clone(&p2p_called);

		let outcome =
			dispatch_broadcast(&hooks, &logger, generous_test_timeout(), Vec::new(), move |_txs| {
				let p2p_called = Arc::clone(&p2p_called_clone);
				async move {
					p2p_called.store(true, Ordering::SeqCst);
				}
			})
			.await;

		assert_eq!(outcome, BroadcastOutcome::FellThroughToP2p);
		assert!(
			p2p_called.load(Ordering::SeqCst),
			"P2P broadcast must run when the hook declines the package"
		);
	}

	#[tokio::test]
	async fn chain_service_hooks_broadcast_no_hook_falls_through_to_p2p() {
		let logger = test_logger();
		let hooks = ChainServiceHooks::default();
		let p2p_called = Arc::new(AtomicBool::new(false));
		let p2p_called_clone = Arc::clone(&p2p_called);

		let outcome =
			dispatch_broadcast(&hooks, &logger, generous_test_timeout(), Vec::new(), move |_txs| {
				let p2p_called = Arc::clone(&p2p_called_clone);
				async move {
					p2p_called.store(true, Ordering::SeqCst);
				}
			})
			.await;

		assert_eq!(outcome, BroadcastOutcome::FellThroughToP2p);
		assert!(p2p_called.load(Ordering::SeqCst), "no hook configured must fall through to P2P");
	}

	#[tokio::test]
	async fn chain_service_hooks_broadcast_hook_timeout_falls_through_to_p2p() {
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: None,
			broadcast: Some(Arc::new(|_txs| -> BroadcastFuture {
				Box::pin(std::future::pending())
			})),
		};
		let p2p_called = Arc::new(AtomicBool::new(false));
		let p2p_called_clone = Arc::clone(&p2p_called);

		let outcome = dispatch_broadcast(
			&hooks,
			&logger,
			Duration::from_millis(10),
			Vec::new(),
			move |_txs| {
				let p2p_called = Arc::clone(&p2p_called_clone);
				async move {
					p2p_called.store(true, Ordering::SeqCst);
				}
			},
		)
		.await;

		assert_eq!(outcome, BroadcastOutcome::FellThroughToP2p);
		assert!(
			p2p_called.load(Ordering::SeqCst),
			"a hung broadcast hook must time out and fall through to P2P"
		);
	}

	#[tokio::test]
	async fn chain_service_hooks_broadcast_hook_succeeds_when_requester_unavailable() {
		// Models `process_broadcast_package` once the CBF restart loop has given up
		// (`CbfRuntimeStatus::Stopped`, no live `Requester`): the broadcast hook must still be
		// tried, and if it accepts the package, the P2P leg (which needs the unavailable
		// requester) is never reached at all. This is the fix for I-1: previously
		// `process_broadcast_package` bailed out before even trying the hook once kyoto had
		// given up -- exactly when an external hook might be the only working relay left (e.g.
		// for a time-sensitive force-close tx).
		let logger = test_logger();
		let hooks = ChainServiceHooks {
			fee_estimates: None,
			broadcast: Some(Arc::new(|_txs| -> BroadcastFuture { Box::pin(async { Ok(()) }) })),
		};
		let p2p_attempted = Arc::new(AtomicBool::new(false));
		let p2p_attempted_clone = Arc::clone(&p2p_attempted);

		let outcome =
			dispatch_broadcast(&hooks, &logger, generous_test_timeout(), Vec::new(), move |_txs| {
				let p2p_attempted = Arc::clone(&p2p_attempted_clone);
				async move {
					// Stands in for `process_broadcast_package`'s real closure when there is no
					// live `Requester` -- it would log an error and return without broadcasting.
					p2p_attempted.store(true, Ordering::SeqCst);
				}
			})
			.await;

		assert_eq!(outcome, BroadcastOutcome::HookHandled);
		assert!(
			!p2p_attempted.load(Ordering::SeqCst),
			"the broadcast hook must succeed without the (unavailable) P2P leg ever running"
		);
	}

	// ------------------------------------------------------------------------------------------
	// P2P broadcast handoff (defect P2). `Requester::submit_package` completes only when a peer
	// PULLS the transaction, so it never completes for a transaction the peer already has — and
	// `continuously_process_broadcast_queue` drains serially, so one such handoff used to wedge
	// every broadcast behind it (measured live: a cooperative-close re-broadcast stalled the
	// queue, and NONE of the force-close sweeps generated over the next nine minutes ever
	// reached the network).
	// ------------------------------------------------------------------------------------------

	/// Stand-in for `Requester::submit_package` against a peer that already knows the
	/// transaction: kyoto queued the announcement, Bitcoin Core answered the `inv` with silence
	/// (`got inv: wtx <id> have peer=N`), and the oneshot is therefore never completed.
	fn never_pulled_by_a_peer() -> impl std::future::Future<Output = Result<(), ()>> {
		std::future::pending()
	}

	/// Short enough that the never-pulled cases cost the suite nothing, long enough that the
	/// pulled cases below are never mistaken for one.
	fn short_handoff_timeout() -> Duration {
		Duration::from_millis(50)
	}

	#[tokio::test]
	async fn a_handoff_no_peer_pulls_is_abandoned_rather_than_awaited_forever() {
		let logger = test_logger();

		// The outer timeout is what makes this a test rather than a hang: without the bound
		// inside `bounded_p2p_handoff` the inner future is `Pending` forever.
		let relayed = tokio::time::timeout(
			Duration::from_secs(5),
			bounded_p2p_handoff(
				&logger,
				short_handoff_timeout(),
				"the transaction under test",
				never_pulled_by_a_peer(),
			),
		)
		.await
		.expect(
			"the P2P handoff must return on its own; an unbounded await here is the P2 wedge \
			 that stops every later broadcast, force-close sweeps included",
		);

		assert!(!relayed, "a transaction no peer asked for was not relayed");
	}

	#[tokio::test]
	async fn a_handoff_a_peer_does_pull_is_awaited_to_completion() {
		// Non-vacuity for the bound: it must not turn every handoff into a timeout.
		let logger = test_logger();

		let relayed = bounded_p2p_handoff(
			&logger,
			generous_test_timeout(),
			"the transaction under test",
			async {
				tokio::time::sleep(Duration::from_millis(5)).await;
				Ok::<(), ()>(())
			},
		)
		.await;

		assert!(relayed, "a transaction a peer pulled must be reported as relayed");
	}

	#[tokio::test]
	async fn a_handoff_rejected_by_the_cbf_client_reports_failure_without_stalling() {
		// `submit_package` errors when the kyoto node has stopped. That is a fast, honest
		// failure and must stay distinct from the timeout path.
		let logger = test_logger();

		let relayed = bounded_p2p_handoff(
			&logger,
			generous_test_timeout(),
			"the transaction under test",
			async { Err::<(), &str>("the CBF node has stopped") },
		)
		.await;

		assert!(!relayed, "a submit error must not be reported as a relay");
	}

	#[tokio::test]
	async fn a_handoff_no_peer_pulls_does_not_wedge_the_broadcasts_behind_it() {
		// The scenario-10 shape in miniature: the node re-broadcasts a cooperative-close
		// transaction its counterparty already relayed (so no peer ever pulls it), and the
		// force-close sweeps queued behind it must still go out. This is the property that
		// makes the bound load-bearing, because the real drain loop is serial.
		let logger = test_logger();
		let relayed: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(Vec::new()));

		// (what, will a peer pull it?)
		let queue = vec![
			("the duplicate cooperative-close tx", false),
			("force-close sweep #1", true),
			("force-close sweep #2", true),
		];

		let drained = tokio::time::timeout(Duration::from_secs(5), async {
			for (what, pulled) in queue {
				let ok = if pulled {
					bounded_p2p_handoff(&logger, short_handoff_timeout(), what, async {
						Ok::<(), ()>(())
					})
					.await
				} else {
					bounded_p2p_handoff(
						&logger,
						short_handoff_timeout(),
						what,
						never_pulled_by_a_peer(),
					)
					.await
				};
				if ok {
					relayed.lock().expect("lock").push(what);
				}
			}
		})
		.await;

		assert!(
			drained.is_ok(),
			"the serial broadcast drain must finish; hanging here is exactly the fund-safety \
			 defect (sweeps generated forever, none relayed)"
		);
		assert_eq!(
			*relayed.lock().expect("lock"),
			vec!["force-close sweep #1", "force-close sweep #2"],
			"every broadcast queued behind an un-pulled one must still reach a peer"
		);
	}
}
