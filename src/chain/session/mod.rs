// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The provider session: which Pro node this host follows, swappable while it runs.
//!
//! ```text
//!   candidates, pin ──► ChainProviderSession ──► status
//!   (from whoever matches)       │
//!                                │ is the ChainDataProvider, FilterSource and BundleTransport
//!                                │ the chain layer was built on; each call goes to the active Pro
//!                                ▼
//!                     ProviderConnector::connect(node_id)    (the embedding app's transport)
//! ```
//!
//! [`ChainProviderSession`] is the seam. The chain layer holds one provider for the life of the
//! process and never knows it moves: every engine, adapter and sync loop above it runs unchanged,
//! because the proven contract of these ports already covers a provider coming and going. With no
//! active Pro, each call fails as unreachable, which is what the same code already does when one
//! dies. So a node can boot with none at all.
//!
//! [`machine`] decides, purely. The driver here performs what it asks for, on the host's runtime,
//! from the first node attaching to the last leaving, and feeds the results back. This layer
//! never reads gossip and knows no prices; candidates come in, status goes out.
//!
//! The list, the pin and the last good Pro are saved beside the chain host's other files
//! ([`store`]) and read back at construction, so a restart resumes with no app involved.
//!
//! # Who hears of a transaction
//!
//! The Pro in the seat can answer yes to a broadcast and drop it, then say it holds it when asked.
//! A penalty dropped that way loses the channel, with every check of filters and headers agreeing:
//! they do not touch this path. So **a transaction goes to [`WITNESSES_TOLD`] others on the list as
//! well**, on every tier, and they take turns, so a transaction LDK sends again every 30 s reaches
//! the rest of the list within minutes. That is the protection when one honest Pro is on the list.
//!
//! * What they learn: the transaction, which is public once sent, from this node's id, as the
//!   active Pro does. No script, no address, no wallet state. A pinned or Dependent node gives up
//!   that much as well, as what it sends may be a penalty and its Pro may be away.
//! * Nothing waits for them: a separate task sends, in order, so a dead witness costs a broadcast
//!   nothing, and one that did not answer loses its turn for [`WITNESS_REST_AFTER_FAILURE`].
//! * What it costs: one call per witness per transaction, at most once per
//!   [`WITNESS_RESEND_EVERY`] for the same transaction. No fee: fees are decided before this.
//! * **With nobody else on the list**, a pinned node tells its pin alone. An owner's own Pro is
//!   trusted: it can drop anything, and nothing here can see that. That is what pinning means.
//! * With the seat empty, the list is told all the same and the first yes is the answer.
//!
//! Whether an own transaction is still out there is asked of a witness as well
//! ([`ChainProviderSession::second_opinion_on_own_txs`]). A Dependent node has no such check: it
//! believes its source about its wallet, by design.

pub(crate) mod cross_check;
pub mod machine;
pub(crate) mod store;
pub mod trace;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "cbf")]
use std::sync::Weak;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use bdk_chain::BlockId;

use bitcoin::block::Header;
use bitcoin::{Block, BlockHash, Network, Transaction, Txid};

use serde::Serialize;

use tokio::sync::{mpsc, watch, Notify};

use crate::chain::cbf::source::{FilterHeaders, FilterSource, IndexedFilter, SourceError};
#[cfg(feature = "cbf")]
use crate::chain::cbf::source_sync::{
	lock_headers, prove_more_work, BranchProof, SharedHeaderChain, SyncEvent, SyncObserver,
};
use crate::chain::provider::{
	BundleTransport, ChainDataProvider, ChainProviderError, WireAckStatus, WireBlockId,
	WireBlockUpdateAck, WireBlockUpdates, WireBroadcastRequest, WireFeeEstimates,
	WireLightningSyncRequest, WireLightningSyncResponse, WireMempoolRequest, WireMempoolResponse,
	WireSinceRequest, WireSubscribeRequest, WireSubscribeResponse, WireSyncRequest,
	WireTxStatusRequest, WireTxStatusResponse, WireUpdate, CHAIN_WIRE_VERSION,
};
use crate::chain::wire_convert::{
	block_id_from_wire, block_id_to_wire, check_version, tx_to_wire, txid_to_wire,
};
use crate::logger::{log_debug, log_info, log_warn, LdkLogger, Logger};
use crate::Error;

use machine::{
	normalise_node_id, Action, CrossCheckOutcome, ProbeOutcome, ProviderSession, PushVerdict, SubscribeOutcome,
	TipCheckOutcome, LEASE_SECS, PROBE_TIMEOUT,
};
#[cfg(feature = "cbf")]
use machine::SyncReport;
pub use machine::{
	BehindWitness, CrossCheckStatus, Delivery, DeliveryPreference, DeliveryRefusal, DroppedPro,
	ConflictState, FilterConflict, MoveBy, ProbeStatus, SessionState, SourceMove, SyncLoopStatus, TipStale,
};
use store::SessionStore;
use trace::{SessionObserver, SpanEnd, TraceOrigin, Tracer};

/// Bound on a `subscribe`, and on a release: above the app's 10 s serve timeout.
const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on each question of a cross-check: above the app's serve timeout on raw routes.
const CROSS_CHECK_CALL_TIMEOUT: Duration = Duration::from_secs(50);

/// How often the driver looks at what is due. Cheap: it reads a few integers.
const DRIVER_TICK: Duration = Duration::from_secs(1);

/// How long a witness's fee estimates count as what the market was, read at a cross-check.
const WITNESS_FEE_MAX_AGE: Duration = Duration::from_secs(3 * 60 * 60);

/// How many others on the list are handed each transaction, besides the active Pro.
pub(crate) const WITNESSES_TOLD: usize = 2;

/// Bound on handing a witness a transaction: the app's ceiling on a chain call.
const WITNESS_SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// Bound on asking a witness about this node's own transactions. The wallet pass waits for it, once
/// per block at most.
const OWN_TX_CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// A witness that did not answer is passed over for this long, so that it costs a package no more
/// than one wait.
const WITNESS_REST_AFTER_FAILURE: Duration = Duration::from_secs(60);

/// The same transaction goes to witnesses at most this often, however often LDK sends it again.
const WITNESS_RESEND_EVERY: Duration = Duration::from_secs(60);

/// Most transactions waiting to go to witnesses. Past this one is not told now, and is the next time
/// it is sent.
const WITNESS_SEND_QUEUE: usize = 256;

/// Pushed blocks whose checks can be waiting at once. A block's span is lost past this, never a block.
const MAX_BLOCK_CHECKS_WAITING: usize = 8;

/// A pushed block not gone through in this long is told as such: a sync loop stuck has its own say.
const BLOCK_CHECK_GIVEN_UP_AFTER: Duration = Duration::from_secs(10 * 60);

/// What marks a cross-check's result in the log.
pub(crate) const CROSS_CHECK_LOG_TARGET: &str = "chain.cross_check";

/// The refusal a Pro gives for a `from` off its best chain: an answer, not a failure.
pub(crate) const NOT_ON_BEST_CHAIN: &str = "not on best chain";
/// What a Pro's refusal says when its node is up and its raw source cannot serve.
const NOT_READY: &str = "not ready";

/// One Pro node, reached over the embedding app's transport.
#[derive(Clone)]
pub struct ProviderEndpoints {
	/// Fees, broadcast, transaction status, wallet and Lightning sync, mempool.
	pub chain: Arc<dyn ChainDataProvider>,
	/// Raw BIP157/158 data.
	pub filters: Arc<dyn FilterSource>,
	/// Per-block bundles and the lease.
	pub bundles: Arc<dyn BundleTransport>,
}

/// Reaches any Pro by its node id: how the session stays free of the transport. Implemented by
/// the embedding app. Building the endpoints must not touch the network.
pub trait ProviderConnector: Send + Sync {
	/// The endpoints of `node_id`.
	fn connect(&self, node_id: &str) -> ProviderEndpoints;
}

/// A session's state, for an application's status surface. Never blocks on the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainSessionStatus {
	/// Where the session stands with its Pro.
	pub state: SessionState,
	/// How blocks arrive.
	pub delivery: Delivery,
	/// The Pro being followed.
	pub active_node_id: Option<String>,
	/// The list the Selector walks.
	pub candidates: Vec<String>,
	/// Those on it known longest; see [`machine::SessionMemory::longest_known`].
	pub longest_known: Vec<String>,
	/// The owner's pinned source, which wins over the list.
	pub pinned_node_id: Option<String>,
	/// The last Pro that answered; a restart resumes there.
	pub last_good: Option<String>,
	/// When a Pro last answered, in seconds since the UNIX epoch.
	pub last_ok_at: Option<u64>,
	/// This node's own place on the chain. Kept through any outage.
	pub cursor: Option<WireBlockId>,
	/// Nothing is answering chain questions: what is known may be old.
	pub chain_stale: bool,
	/// The Pros proven lying, and until when they stay out.
	pub dropped: Vec<DroppedPro>,
	/// What comparing filter headers with a second Pro has seen.
	pub cross_check: CrossCheckStatus,
	/// The owner's choice for now, while the node is on it: not pinned, so it still fails over.
	pub used_for_now: Option<String>,
	/// The latest moves between sources, oldest first. Not kept across a restart.
	pub moves: Vec<SourceMove>,
	/// What it is waiting to ask next, while something is wrong.
	pub probe: Option<ProbeStatus>,
	/// Why this Pro is not pushing, if it said no.
	pub refused: Option<DeliveryRefusal>,
	/// The newest block this node took and when it saw it. `None` until a block arrives after a
	/// start: what it holds from before then has no time this session could truthfully give.
	pub last_block: Option<LastBlock>,
	/// The tip this node is caught up on is too old to believe. Nobody is blamed: a witness may
	/// have nothing newer.
	pub tip_stale: Option<TipStale>,
	/// A second Pro has shown, with proof of work, more than this node holds, and the active Pro
	/// has not caught up. See [`machine`], "A Pro that does not show the chain".
	pub behind_witness: Option<BehindWitness>,
	/// No step of the sync loop has completed for a long time.
	pub sync_stuck: bool,
	/// Whether the sync loop runs, and how often it had to be started again.
	pub sync_loop: SyncLoopStatus,
	/// The active Pro is one proven lying, which only a pin keeps it on: see [`Self::dropped`].
	pub on_proven_liar: bool,
	/// This node checks its Pro against another, and nobody else is there to ask, so nothing has
	/// compared what it says.
	pub no_witness: bool,
	/// This node's own host has been refusing to send to the Pro for a long time.
	pub host_not_sending: bool,
	/// Whether this node takes a source off the list by itself: see [`machine`], "Who chooses".
	pub picks_by_itself: bool,
	/// It has no source, and will not take one until its owner says.
	pub needs_owner_choice: bool,
}

/// What a provider's fee estimates can be held against; see
/// [`crate::chain::adapters::dependent::provider_rate_for`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeReference {
	/// What a second Pro said lately.
	pub witness: Option<WireFeeEstimates>,
	/// The typical rate of the blocks this node read itself, in sat/kwu.
	pub local_sat_per_kwu: Option<u64>,
}

/// What came of checking a tip someone claims; see [`ChainProviderSession::verify_tip_claim`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TipClaimCheck {
	/// Headers reaching the claim itself, every check passed, with more work than this node holds.
	pub verified: bool,
	/// How far they reached, every check passed. `None` with nothing shown.
	pub proven_height: Option<u32>,
	/// Where this node stands. `None` when it holds no chain to check against.
	pub cursor: Option<WireBlockId>,
	/// `proven`, `proven_part_way`, `at_or_below_cursor`, `no_more_work`, `forged_header`,
	/// `no_answer`, `no_header_chain` or `invalid_claim`.
	pub result: &'static str,
}

/// What a witness says of this node's own transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnTxOpinion {
	/// Who said it.
	pub witness: String,
	/// Those of the transactions asked about that it holds.
	pub held: HashSet<Txid>,
}

/// See [`ChainSessionStatus::last_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LastBlock {
	/// Its height.
	pub height: u32,
	/// When this node saw it, in milliseconds since the UNIX epoch, to the second.
	pub at_ms: u64,
}

/// What the session needs of the sync loop that reads bundles. A node with no such loop, a
/// Dependent one, has none.
pub(crate) trait PushSink: cross_check::HeldFilters {
	/// Takes pushed blocks and wakes the loop. The newest block held, or else verified.
	fn ingest(&self, push: &WireBlockUpdates) -> Result<Option<BlockId>, ChainProviderError>;
	/// The newest block the node has verified.
	fn verified_tip(&self) -> Option<BlockId>;
	/// The Pro says this is its tip. Wakes the loop if that is news.
	fn note_tip(&self, tip: BlockId);
	/// What the Pro last said about its tip is off its best chain.
	fn forget_tip(&self);
	/// Everything held came from another Pro. Wakes the loop.
	fn target_changed(&self);
	/// Whether the Pro's pushes are live truth, so the tip need not be asked.
	fn set_push_trusted(&self, trusted: bool);
	/// What this node took for the filters from `from` up is not to be believed: read those
	/// blocks again. Takes effect between two steps of the loop, and disconnects nothing.
	fn rewind_filters(&self, from: BlockId);
	/// The chain the sync loop verified.
	#[cfg(feature = "cbf")]
	fn verified_chain(&self) -> SharedHeaderChain;
	/// Who hears how the sync loop fares.
	#[cfg(feature = "cbf")]
	fn set_sync_observer(&self, observer: Weak<dyn SyncObserver>);
	/// The typical fee rate of the blocks this node read itself, in sat/kwu, if enough of them.
	fn local_fee_rate(&self) -> Option<u64>;
}

struct Target {
	node_id: String,
	endpoints: ProviderEndpoints,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Logged {
	state: SessionState,
	delivery: Delivery,
	active: Option<String>,
}

/// A pushed block the sync loop has yet to go through.
struct BlockCheck {
	height: u32,
	since: Instant,
	span: trace::ActionSpan,
}

/// See the module docs.
pub struct ChainProviderSession {
	connector: Arc<dyn ProviderConnector>,
	machine: Mutex<ProviderSession>,
	target: RwLock<Option<Target>>,
	sink: RwLock<Option<Arc<dyn PushSink>>>,
	store: SessionStore,
	genesis: WireBlockId,
	/// For a node with no sync loop to ask: the Pro's tip as last seen.
	seen_tip: Mutex<Option<WireBlockId>>,
	epoch: Instant,
	notify: Notify,
	logged: Mutex<Logged>,
	logger: Arc<Logger>,
	tracer: Tracer,
	last_block: Mutex<BlockWatch>,
	network: Network,
	/// Moves with every retarget: [`FilterSource::epoch`].
	provider_epoch: AtomicU64,
	/// What a second Pro said fees are, and when it was asked.
	witness_fees: Mutex<Option<(WireFeeEstimates, Instant)>>,
	/// What is to go to witnesses, in order; the driver's sender task reads it.
	to_witnesses: Mutex<Option<mpsc::Sender<WireBroadcastRequest>>>,
	/// Pushed blocks the sync loop has yet to go through.
	block_checks: Mutex<VecDeque<BlockCheck>>,
	/// How far the blocks in doubt have been read, and with whose filters.
	read_with_witness: Mutex<Option<(String, cross_check::ReadSoFar)>>,
	/// When each transaction last went to witnesses.
	told_witnesses_at: Mutex<HashMap<String, Instant>>,
	/// Witnesses that did not answer lately.
	resting_witnesses: Mutex<HashMap<String, Instant>>,
}

#[derive(Default)]
struct BlockWatch {
	looked: bool,
	height: u32,
	at_ms: Option<u64>,
}

impl ChainProviderSession {
	/// A session in `storage_dir`, resuming from what it saved there: on the pin, else on the
	/// last good Pro, else with no provider. Nothing is asked until a node attaches to the host
	/// it was given to.
	pub fn new(
		connector: Arc<dyn ProviderConnector>, preference: DeliveryPreference, network: Network,
		storage_dir: &str, logger: Arc<Logger>,
	) -> Arc<Self> {
		let store = SessionStore::in_dir(storage_dir);
		let memory = store.load().unwrap_or_else(|problem| {
			log_warn!(
				logger,
				"Chain provider session: the saved state is {}; starting with none, and taking no source by itself until the owner says.",
				problem
			);
			// What is lost may be the owner's word: the file was there, so nothing about a stranger
			// being acceptable can be assumed. A config pin is applied again by the app.
			machine::SessionMemory { auto_source: Some(false), ..Default::default() }
		});
		let epoch = Instant::now();
		let machine = ProviderSession::new(preference, memory, now_at(epoch));
		let target = machine
			.active()
			.map(|id| Target { node_id: id.to_string(), endpoints: connector.connect(id) });
		let genesis = bitcoin::blockdata::constants::genesis_block(network).block_hash();
		let logged = Logged {
			state: machine.state(),
			delivery: machine.delivery(),
			active: machine.active().map(str::to_string),
		};
		log_info!(
			logger,
			"Chain provider session: starting {} on {}.",
			machine.state().as_str(),
			machine.active().unwrap_or("no provider")
		);
		Arc::new(Self {
			connector,
			machine: Mutex::new(machine),
			target: RwLock::new(target),
			sink: RwLock::new(None),
			store,
			genesis: WireBlockId { height: 0, hash: genesis.to_string() },
			seen_tip: Mutex::new(None),
			epoch,
			notify: Notify::new(),
			logged: Mutex::new(logged),
			logger,
			tracer: Tracer::default(),
			last_block: Mutex::new(BlockWatch::default()),
			network,
			provider_epoch: AtomicU64::new(0),
			witness_fees: Mutex::new(None),
			to_witnesses: Mutex::new(None),
			block_checks: Mutex::new(VecDeque::new()),
			read_with_witness: Mutex::new(None),
			told_witnesses_at: Mutex::new(HashMap::new()),
			resting_witnesses: Mutex::new(HashMap::new()),
		})
	}

	fn now(&self) -> machine::Now {
		now_at(self.epoch)
	}

	fn machine(&self) -> MutexGuard<'_, ProviderSession> {
		self.machine.lock().unwrap_or_else(|e| e.into_inner())
	}

	fn sink(&self) -> Option<Arc<dyn PushSink>> {
		self.sink.read().unwrap_or_else(|e| e.into_inner()).clone()
	}

	/// What the session hands pushes to, and what makes a cross-check possible: a node with no
	/// sync loop holds no filter headers to compare.
	pub(crate) fn attach_sink(self: &Arc<Self>, sink: Arc<dyn PushSink>) {
		#[cfg(feature = "cbf")]
		{
			let observer: Weak<ChainProviderSession> = Arc::downgrade(self);
			sink.set_sync_observer(observer);
		}
		*self.sink.write().unwrap_or_else(|e| e.into_inner()) = Some(sink);
		let now = self.now();
		self.machine().enable_cross_check(now);
	}

	/// This session as the provider a chain host is built on.
	pub(crate) fn as_chain_provider(self: &Arc<Self>) -> Arc<dyn ChainDataProvider> {
		Arc::clone(self) as Arc<dyn ChainDataProvider>
	}

	/// This session as a host's filter source.
	#[cfg(feature = "cbf")]
	pub(crate) fn as_filter_source(self: &Arc<Self>) -> Arc<dyn FilterSource> {
		Arc::clone(self) as Arc<dyn FilterSource>
	}

	/// This session as a host's bundle transport.
	#[cfg(feature = "cbf")]
	pub(crate) fn as_bundle_transport(self: &Arc<Self>) -> Arc<dyn BundleTransport> {
		Arc::clone(self) as Arc<dyn BundleTransport>
	}

	/// The ordered list the Selector walks; see [`ProviderSession::set_candidates`]. Saved before
	/// it returns.
	pub fn set_candidates(&self, candidates: Vec<String>) {
		let now = self.now();
		self.machine().set_candidates(candidates, now);
		self.settled();
	}

	/// Who on the list is known longest; see [`machine::SessionMemory::longest_known`].
	pub fn set_longest_known(&self, known: Vec<String>) {
		self.machine().set_longest_known(known);
		self.settled();
	}

	/// The owner's choice of one source, or `None` to clear it; see
	/// [`ProviderSession::set_pin`]. Saved before it returns.
	pub fn set_source(&self, node_id: Option<String>) {
		self.set_source_traced(node_id, None);
	}

	/// [`Self::set_source`] as part of a trace another part of this node started. `true` when the
	/// session now owns that trace's root span: it closes once the move has settled, and everything
	/// the move does is in it.
	pub fn set_source_traced(&self, node_id: Option<String>, origin: Option<TraceOrigin>) -> bool {
		let adopted = self.tracer.begin_switch(origin, node_id.as_deref());
		let now = self.now();
		self.machine().set_pin(node_id, now);
		self.settled();
		adopted
	}

	/// The owner's choice of a source for now: the node moves to it at once, is not pinned to it,
	/// and fails over if it dies; see [`machine::SessionMemory::used_for_now`]. `None`, and nothing
	/// changes, for a dropped Pro. Otherwise whether the session owns the trace, as
	/// [`Self::set_source_traced`].
	pub fn use_source_traced(&self, node_id: String, origin: Option<TraceOrigin>) -> Option<bool> {
		let now = self.now();
		let id = normalise_node_id(&node_id);
		if id.is_empty() || self.machine().is_dropped(&id, now) {
			return None;
		}
		let adopted = self.tracer.begin_switch(origin, Some(&id));
		let taken = self.machine().use_now(id, now);
		self.settled();
		taken.then_some(adopted)
	}

	/// Whether the node may take a source off the list by itself; `None` is the default, whether it
	/// can check what a source says. See [`machine`], "Who chooses". Saved before it returns.
	pub fn set_auto_source(&self, allowed: Option<bool>) {
		let now = self.now();
		self.machine().set_auto_source(allowed, now);
		self.settled();
	}

	/// The owner's word on [`Self::set_auto_source`] as it stands; `None` if nobody has said.
	pub fn auto_source(&self) -> Option<bool> {
		self.machine().memory().auto_source
	}

	/// Where this session tells what it does from now on. See [`trace`].
	pub fn set_observer(&self, observer: Arc<dyn SessionObserver>) {
		self.tracer.set_observer(observer);
	}

	/// The gossip card of `node_id` was last seen `age` ago: an old card of the active Pro brings
	/// a probe forward, and that is all it can do.
	pub fn note_card_age(&self, node_id: &str, age: Duration) {
		let now = self.now();
		self.machine().card_age_hint(node_id, age, now);
		self.settled();
	}

	/// A cross-check now rather than at its time.
	#[cfg(test)]
	pub(crate) fn check_soon(&self) {
		let now = self.now();
		self.machine().check_soon(now);
		self.settled();
	}

	fn last_block_seen(&self) -> Option<LastBlock> {
		let seen = self.last_block.lock().unwrap_or_else(|e| e.into_inner());
		seen.at_ms.map(|at_ms| LastBlock { height: seen.height, at_ms })
	}

	/// Compared on the driver's tick, so a block's time is good to about a second. The first look
	/// only learns where the node stands.
	fn watch_last_block(&self) {
		let Some(cursor) = self.cursor() else { return };
		let mut seen = self.last_block.lock().unwrap_or_else(|e| e.into_inner());
		let moved = seen.looked && cursor.height != seen.height;
		if moved {
			seen.at_ms = Some(self.now().unix_secs.saturating_mul(1000));
		}
		seen.height = cursor.height;
		seen.looked = true;
		drop(seen);
		if moved {
			let now = self.now();
			self.machine().note_block(now);
		}
	}

	/// Where the session stands.
	pub fn status(&self) -> ChainSessionStatus {
		let cursor = self.cursor();
		let now = self.now();
		let machine = self.machine();
		let memory = machine.memory();
		ChainSessionStatus {
			state: machine.state(),
			delivery: machine.delivery(),
			active_node_id: machine.active().map(str::to_string),
			candidates: memory.candidates.clone(),
			longest_known: memory.longest_known.clone(),
			pinned_node_id: memory.pinned.clone(),
			last_good: memory.last_good.clone(),
			last_ok_at: machine.last_ok_at(),
			cursor,
			chain_stale: machine.chain_stale(),
			dropped: memory.dropped.clone(),
			cross_check: machine.cross_check().clone(),
			used_for_now: memory.used_for_now.clone(),
			moves: machine.moves().iter().cloned().collect(),
			probe: machine.probe_status(now),
			refused: machine.refused().cloned(),
			last_block: self.last_block_seen(),
			tip_stale: machine.tip_stale(),
			behind_witness: machine.behind_witness(),
			sync_stuck: machine.sync_stuck(),
			sync_loop: machine.sync_loop().clone(),
			on_proven_liar: machine.on_proven_liar(),
			no_witness: machine.no_witness(now),
			host_not_sending: machine.host_not_sending(),
			picks_by_itself: machine.picks_by_itself(),
			needs_owner_choice: machine.needs_owner_choice(),
		}
	}

	/// Whether `claim`, a tip `node_id` says it has, is backed by headers it will show, on this
	/// node's own checks: for whoever weighs what candidates claim. A claim at or below this node's
	/// own tip proves nothing either way. Costs that Pro one call, or a few if its chain has forked.
	/// Only a node that verifies headers can tell.
	#[cfg(feature = "cbf")]
	pub async fn verify_tip_claim(&self, node_id: &str, claim: WireBlockId) -> TipClaimCheck {
		let check = |proven_height, cursor, verified, result| TipClaimCheck {
			verified,
			proven_height,
			cursor,
			result,
		};
		let Some(chain) = self.sink().map(|sink| sink.verified_chain()) else {
			return check(None, None, false, "no_header_chain");
		};
		let Some(cursor) = lock_headers(&chain).tip() else {
			return check(None, None, false, "no_header_chain");
		};
		let at = Some(block_id_to_wire(&cursor));
		let Ok(claim) = block_id_from_wire(&claim) else {
			return check(None, at, false, "invalid_claim");
		};
		if claim.height <= cursor.height {
			return check(None, at, false, "at_or_below_cursor");
		}
		let endpoints = self.connector.connect(&normalise_node_id(node_id));
		match prove_more_work(
			&*endpoints.filters,
			&chain,
			self.network,
			claim,
			CROSS_CHECK_CALL_TIMEOUT,
			true,
		)
		.await
		{
			BranchProof::Proven { height, reached_claim: true } => {
				check(Some(height), at, true, "proven")
			},
			BranchProof::Proven { height, reached_claim: false } => {
				check(Some(height), at, false, "proven_part_way")
			},
			BranchProof::NotAhead => check(None, at, false, "no_more_work"),
			BranchProof::Forged { .. } => check(None, at, false, "forged_header"),
			BranchProof::Unanswered => check(None, at, false, "no_answer"),
		}
	}

	/// See the other build of this: with no filter engine there is no header chain to check against.
	#[cfg(not(feature = "cbf"))]
	pub async fn verify_tip_claim(&self, _node_id: &str, _claim: WireBlockId) -> TipClaimCheck {
		TipClaimCheck { verified: false, proven_height: None, cursor: None, result: "no_header_chain" }
	}

	/// What a provider's fees can be held against now.
	pub(crate) fn fee_reference(&self) -> FeeReference {
		let witness = self
			.witness_fees
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.as_ref()
			.filter(|(_, at)| at.elapsed() < WITNESS_FEE_MAX_AGE)
			.map(|(fees, _)| fees.clone());
		FeeReference { witness, local_sat_per_kwu: self.sink().and_then(|s| s.local_fee_rate()) }
	}

	/// Takes a block update from `caller`, as the transport verified it: only from the active
	/// Pro. From anyone else, or with nothing here to read it, the ack says `not_subscribed`, and
	/// that Pro drops the lease at once. [`Error::ChainServeFailed`] for one that does not decode:
	/// the Pro counts that as a failed push.
	pub fn receive_block_update(
		&self, caller: &str, push: &WireBlockUpdates,
	) -> Result<WireBlockUpdateAck, Error> {
		self.receive_block_update_traced(caller, push, None)
	}

	/// [`Self::receive_block_update`], with what it does under `inbound`, the row kept of this call.
	pub fn receive_block_update_traced(
		&self, caller: &str, push: &WireBlockUpdates, inbound: Option<&trace::InboundSpan>,
	) -> Result<WireBlockUpdateAck, Error> {
		let not_subscribed = || WireBlockUpdateAck {
			version: CHAIN_WIRE_VERSION,
			status: WireAckStatus::NotSubscribed,
			applied_tip: None,
		};
		let Some(sink) = self.sink() else {
			return Ok(not_subscribed());
		};
		let now = self.now();
		let verdict = self.machine().on_push(caller, push.lease_until, now);
		if verdict == PushVerdict::NotSubscribed {
			log_debug!(
				self.logger,
				"Chain provider session: a block update from {}, not followed.",
				caller
			);
			self.settled();
			return Ok(not_subscribed());
		}
		self.note_bundle_fees(caller, push);
		// Trust follows the machine first, so the loop the ingest wakes finds the tip in memory.
		self.settled();
		let check = inbound.and_then(|inbound| {
			self.tracer.under_inbound(trace::NAME_BLOCK_CHECK, caller, inbound)
		});
		let applied = match sink.ingest(push) {
			Ok(applied) => applied,
			Err(e) => {
				log_info!(self.logger, "Refusing a block update from {}: {}", caller, e);
				self.tracer.finish(check, SpanEnd::failed("block_refused", Some(e.to_string())));
				return Err(Error::ChainServeFailed);
			},
		};
		self.await_block_check(check, push, sink.verified_tip());
		let ack = inbound.and_then(|inbound| {
			self.tracer.under_inbound(trace::NAME_BLOCK_ACK, caller, inbound)
		});
		let reply = WireBlockUpdateAck {
			version: CHAIN_WIRE_VERSION,
			status: WireAckStatus::Applied,
			applied_tip: applied.as_ref().map(block_id_to_wire),
		};
		let told = applied.map(|tip| format!("applied_tip={}", tip.height));
		self.tracer.finish(ack, SpanEnd::ok(told));
		Ok(reply)
	}

	/// The check of a pushed block ends when the sync loop has been through it, which is after the
	/// ack: the loop takes it from here, between its own steps. The span is what happened, so it ends
	/// then ([`Self::end_block_checks`]). A block already past when it came was checked by then, with
	/// no check of this push's to tell of.
	fn await_block_check(
		&self, check: Option<trace::ActionSpan>, push: &WireBlockUpdates, verified: Option<BlockId>,
	) {
		let Some(check) = check else { return };
		let height = push.updates.iter().map(|update| update.height).max();
		let Some(height) = height.filter(|h| verified.map_or(true, |tip| *h > tip.height)) else {
			return;
		};
		let mut waiting = self.block_checks.lock().unwrap_or_else(|e| e.into_inner());
		if waiting.len() >= MAX_BLOCK_CHECKS_WAITING {
			waiting.pop_front();
		}
		waiting.push_back(BlockCheck { height, since: Instant::now(), span: check });
	}

	/// The checks of pushed blocks that came to `end`. Nothing is held on the way: a block's worth of
	/// spans, a line per block.
	fn end_block_checks(&self, which: impl Fn(&BlockCheck) -> bool, end: impl Fn() -> SpanEnd) {
		let ended: VecDeque<BlockCheck> = {
			let mut waiting = self.block_checks.lock().unwrap_or_else(|e| e.into_inner());
			if waiting.is_empty() {
				return;
			}
			let (ended, left): (VecDeque<_>, VecDeque<_>) =
				std::mem::take(&mut *waiting).into_iter().partition(which);
			*waiting = left;
			ended
		};
		for check in ended {
			self.tracer.finish(Some(check.span), end());
		}
	}

	/// Saves what changed, tells the sink what it may trust, logs a change, wakes the driver.
	fn settled(&self) {
		let (dirty, trusted, logged, memory, dropped) = {
			let mut machine = self.machine();
			let dirty = machine.take_dirty();
			let dropped = machine.take_newly_dropped();
			let logged = Logged {
				state: machine.state(),
				delivery: machine.delivery(),
				active: machine.active().map(str::to_string),
			};
			let memory = dirty.then(|| machine.memory().clone());
			(dirty, machine.push_is_trusted(), logged, memory, dropped)
		};
		if let (true, Some(memory)) = (dirty, memory) {
			if let Err(e) = self.store.save(&memory) {
				log_warn!(self.logger, "Chain provider session: could not save its state: {}", e);
			}
		}
		if let Some(sink) = self.sink() {
			sink.set_push_trusted(trusted);
		}
		let mut last = self.logged.lock().unwrap_or_else(|e| e.into_inner());
		if *last != logged {
			self.tracer.on_change(&last, &logged);
			if matches!(logged.state, SessionState::NoProvider | SessionState::Unreachable) {
				log_warn!(
					self.logger,
					"Chain provider session: no Pro answers ({}); chain data may be old and new channels are refused until one does.",
					logged.state.as_str()
				);
			}
			log_info!(
				self.logger,
				"Chain provider session: {} on {}, delivery {} (was {} on {}, delivery {}).",
				logged.state.as_str(),
				logged.active.as_deref().unwrap_or("no provider"),
				logged.delivery.as_str(),
				last.state.as_str(),
				last.active.as_deref().unwrap_or("no provider"),
				last.delivery.as_str()
			);
			*last = logged;
		}
		drop(last);
		// After the change above, so what it did is under the move it brought on.
		for one in dropped {
			let detail = format!("reason={} height={}", one.reason, one.height);
			self.tracer.source_dropped(&one.node_id, detail);
		}
		self.notify.notify_one();
	}

	/// The driver: until `stop` changes, performs what the machine asks for. A stop is noticed
	/// within [`DRIVER_TICK`], which is soon enough for what it has left to do: nothing.
	pub(crate) async fn run(self: Arc<Self>, stop: watch::Receiver<()>) {
		// The sink came after the session, so it has not been told yet.
		self.settled();
		self.start_witness_sender();
		loop {
			let _ = tokio::time::timeout(DRIVER_TICK, self.notify.notified()).await;
			if !matches!(stop.has_changed(), Ok(false)) {
				log_debug!(self.logger, "Chain provider session: stopping.");
				return;
			}
			self.step();
		}
	}

	/// The task that hands witnesses what the active Pro was handed. One task, so each gets them in
	/// the order they were sent: a child before its parent would be refused. On the driver's runtime,
	/// so a new run brings a new one, and the old one ends with its sender.
	fn start_witness_sender(self: &Arc<Self>) {
		let (sender, mut sends) = mpsc::channel(WITNESS_SEND_QUEUE);
		*self.to_witnesses.lock().unwrap_or_else(|e| e.into_inner()) = Some(sender);
		let session = Arc::downgrade(self);
		tokio::spawn(async move {
			while let Some(req) = sends.recv().await {
				let Some(session) = session.upgrade() else { return };
				session.tell_witnesses(&req).await;
			}
		});
	}

	/// Who is next to be told, leaving out those resting.
	fn next_witnesses(&self, count: usize) -> Vec<String> {
		let resting: Vec<String> = {
			let mut resting = self.resting_witnesses.lock().unwrap_or_else(|e| e.into_inner());
			resting.retain(|_, at| at.elapsed() < WITNESS_REST_AFTER_FAILURE);
			resting.keys().cloned().collect()
		};
		let now = self.now();
		self.machine().next_to_tell(count, &resting, now)
	}

	/// One witness told of one transaction. Whether it answered, for one that did not to rest.
	async fn tell_witness(self: &Arc<Self>, witness: String, req: WireBroadcastRequest) -> bool {
		let endpoints = self.connector.connect(&witness);
		let span = self.tracer.standalone(trace::NAME_WITNESS_BROADCAST, &witness);
		let scope = span.as_ref().map(trace::ActionSpan::scope);
		let answer = tokio::time::timeout(
			WITNESS_SEND_TIMEOUT,
			trace::scoped(scope, endpoints.chain.broadcast(req)),
		)
		.await
		.unwrap_or_else(|_| Err(ChainProviderError::Unreachable("timed out".into())));
		let answered = !matches!(answer, Err(ChainProviderError::Unreachable(_)));
		let end = match &answer {
			Ok(()) => SpanEnd::ok(None),
			Err(e) => SpanEnd::failed("witness_broadcast", Some(e.to_string())),
		};
		self.tracer.finish(span, end);
		if !answered {
			log_debug!(self.logger, "Chain provider session: witness {} did not answer.", witness);
			self.resting_witnesses
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.insert(witness, Instant::now());
		}
		answered
	}

	/// See the module docs: the next witnesses at once, and the turn moves on past any that fail.
	async fn tell_witnesses(self: &Arc<Self>, req: &WireBroadcastRequest) {
		let mut sends = tokio::task::JoinSet::new();
		for witness in self.next_witnesses(WITNESSES_TOLD) {
			let session = Arc::clone(self);
			let req = req.clone();
			sends.spawn(async move { session.tell_witness(witness, req).await });
		}
		while sends.join_next().await.is_some() {}
	}

	/// A transaction is on its way to the active Pro: it goes to witnesses too. Never waits.
	fn queue_for_witnesses(&self, req: &WireBroadcastRequest) {
		{
			let mut told = self.told_witnesses_at.lock().unwrap_or_else(|e| e.into_inner());
			if told.get(&req.tx_hex).map_or(false, |at| at.elapsed() < WITNESS_RESEND_EVERY) {
				return;
			}
			told.retain(|_, at| at.elapsed() < WITNESS_RESEND_EVERY);
			told.insert(req.tx_hex.clone(), Instant::now());
		}
		let sender = self.to_witnesses.lock().unwrap_or_else(|e| e.into_inner());
		if sender.as_ref().map_or(false, |sender| sender.try_send(req.clone()).is_err()) {
			log_debug!(
				self.logger,
				"Chain provider session: too many transactions waiting to go to witnesses; this one goes the next time it is sent."
			);
		}
	}

	/// With the seat empty the witnesses are all there is, so the answer is theirs: the first yes.
	async fn broadcast_with_no_active(
		&self, req: WireBroadcastRequest,
	) -> Result<(), ChainProviderError> {
		let mut sends = tokio::task::JoinSet::new();
		for witness in self.next_witnesses(WITNESSES_TOLD) {
			let endpoints = self.connector.connect(&witness);
			let req = req.clone();
			sends.spawn(async move {
				tokio::time::timeout(WITNESS_SEND_TIMEOUT, endpoints.chain.broadcast(req)).await
			});
		}
		let mut told = false;
		while let Some(answer) = sends.join_next().await {
			told |= matches!(answer, Ok(Ok(Ok(()))));
			if told {
				// The others go on by themselves: nothing below is worth cancelling them for.
				sends.detach_all();
			}
		}
		if told {
			Ok(())
		} else {
			Err(ChainProviderError::Unreachable("no chain provider selected".into()))
		}
	}

	fn step(self: &Arc<Self>) {
		self.end_block_checks(
			|check| check.since.elapsed() >= BLOCK_CHECK_GIVEN_UP_AFTER,
			|| SpanEnd::failed("block_check_timed_out", None),
		);
		self.watch_last_block();
		let now = self.now();
		let actions = self.machine().poll(now);
		for action in actions {
			match action {
				Action::Retarget(node_id) => self.retarget(node_id),
				Action::Probe(target) => {
					let session = Arc::clone(self);
					let span = self.tracer.action(trace::NAME_PROBE, &target);
					tokio::spawn(async move { session.probe(target, span).await });
				},
				Action::Subscribe(target) => {
					let session = Arc::clone(self);
					let span = self.tracer.action(trace::NAME_SUBSCRIBE, &target);
					tokio::spawn(async move { session.subscribe(target, span).await });
				},
				Action::Release(target) => {
					let session = Arc::clone(self);
					let span = self.tracer.action(trace::NAME_RELEASE, &target);
					tokio::spawn(async move { session.release(target, span).await });
				},
				Action::CrossCheck { active, witness } => {
					let session = Arc::clone(self);
					let span = self.tracer.standalone(trace::NAME_CROSS_CHECK, &witness);
					tokio::spawn(async move { session.cross_check(active, witness, span).await });
				},
				Action::TieBreak { active, witness, third, height } => {
					let session = Arc::clone(self);
					let span = self.tracer.standalone(trace::NAME_TIE_BREAK, &third);
					tokio::spawn(async move {
						let scope = span.as_ref().map(trace::ActionSpan::scope);
						let answer = trace::scoped(
							scope,
							session.ask_third(&active, &witness, &third, height),
						)
						.await;
						log_warn!(
							session.logger,
							"{}: active={} witness={} differ at {}; third={} says {:?}.",
							CROSS_CHECK_LOG_TARGET,
							active,
							witness,
							height,
							third,
							answer
						);
						session.machine().on_tie_break(&active, &witness, answer);
						session.settled();
						session.tracer.finish(span, SpanEnd::ok(Some(format!("{:?}", answer))));
					});
				},
				Action::TipCheck { active, witness } => {
					let session = Arc::clone(self);
					let span = self.tracer.standalone(trace::NAME_TIP_CHECK, &witness);
					tokio::spawn(async move {
						let scope = span.as_ref().map(trace::ActionSpan::scope);
						let outcome = trace::scoped(scope, session.weigh_tip(&active, &witness)).await;
						session.heard_tip_check(&active, &witness, outcome);
						let detail = Some(format!("active={} {:?}", active, outcome));
						session.tracer.finish(span, SpanEnd::ok(detail));
					});
				},
			}
		}
		let state = self.machine().state();
		self.tracer.tick(state, Instant::now());
	}

	fn retarget(&self, node_id: Option<String>) {
		self.tracer.mark(trace::NAME_RETARGET, node_id.as_deref(), None);
		let next = node_id.map(|node_id| {
			let endpoints = self.connector.connect(&node_id);
			Target { node_id, endpoints }
		});
		*self.target.write().unwrap_or_else(|e| e.into_inner()) = next;
		*self.seen_tip.lock().unwrap_or_else(|e| e.into_inner()) = None;
		self.end_block_checks(|_| true, || SpanEnd::failed("source_moved", None));
		self.provider_epoch.fetch_add(1, Ordering::AcqRel);
		if let Some(sink) = self.sink() {
			sink.target_changed();
		}
	}

	/// With no filter engine a session has no sink, and asks nobody this.
	#[cfg(not(feature = "cbf"))]
	async fn ask_third(&self, _: &str, _: &str, _: &str, _: u32) -> machine::TieBreak {
		machine::TieBreak::NoAnswer
	}

	/// With no filter engine a session has no sink, and asks nobody this.
	#[cfg(not(feature = "cbf"))]
	async fn weigh_tip(&self, _: &str, _: &str) -> TipCheckOutcome {
		TipCheckOutcome::Unanswered
	}

	/// Whose filter header at `height` a third Pro's matches. The block is named by its hash, so
	/// each has one right answer. See [`machine`].
	#[cfg(feature = "cbf")]
	async fn ask_third(
		&self, active: &str, witness: &str, third: &str, height: u32,
	) -> machine::TieBreak {
		let held = self.sink().map(|sink| sink.verified_chain());
		let Some(hash) = held.and_then(|chain| lock_headers(&chain).hash(height)) else {
			return machine::TieBreak::NoAnswer;
		};
		let header_of = |id: &str| {
			let filters = self.connector.connect(id).filters;
			async move {
				let asked = tokio::time::timeout(
					CROSS_CHECK_CALL_TIMEOUT,
					filters.filter_headers(height, hash),
				)
				.await;
				asked.ok().and_then(Result::ok).and_then(|told| told.headers.first().copied())
			}
		};
		let Some(says) = header_of(third).await else {
			return machine::TieBreak::NoAnswer;
		};
		if header_of(active).await == Some(says) {
			machine::TieBreak::SidesWithActive
		} else if header_of(witness).await == Some(says) {
			machine::TieBreak::SidesWithWitness
		} else {
			machine::TieBreak::NoAnswer
		}
	}

	/// What `witness` can show above this node's tip, on proof of work, and what the active Pro
	/// says of its own tip when that matters. See [`machine`].
	#[cfg(feature = "cbf")]
	async fn weigh_tip(&self, active: &str, witness: &str) -> TipCheckOutcome {
		let Some(chain) = self.sink().map(|sink| sink.verified_chain()) else {
			return TipCheckOutcome::Unanswered;
		};
		let witness_filters = self.connector.connect(witness).filters;
		let asked = tokio::time::timeout(CROSS_CHECK_CALL_TIMEOUT, witness_filters.tip()).await;
		let Ok(Ok(claim)) = asked else {
			return TipCheckOutcome::Unanswered;
		};
		let proof = prove_more_work(
			&*witness_filters,
			&chain,
			self.network,
			claim,
			CROSS_CHECK_CALL_TIMEOUT,
			true,
		)
		.await;
		match proof {
			BranchProof::NotAhead => TipCheckOutcome::NotAhead,
			BranchProof::Unanswered => TipCheckOutcome::Unanswered,
			BranchProof::Forged { height } => TipCheckOutcome::Forged { height },
			BranchProof::Proven { height, .. } => {
				let active_filters = self.connector.connect(active).filters;
				let said =
					tokio::time::timeout(CROSS_CHECK_CALL_TIMEOUT, active_filters.tip()).await;
				TipCheckOutcome::Ahead {
					witness_height: height,
					active_tip: said.ok().and_then(Result::ok).map(|tip| tip.height),
					cursor: lock_headers(&chain).tip().map_or(0, |tip| tip.height),
				}
			},
		}
	}

	fn heard_tip_check(&self, active: &str, witness: &str, outcome: TipCheckOutcome) {
		match outcome {
			TipCheckOutcome::Ahead { witness_height, cursor, .. } => {
				log_warn!(
					self.logger,
					"Chain provider session: {} shows blocks to {}, this node holds {} from {}.",
					witness,
					witness_height,
					cursor,
					active
				);
			},
			TipCheckOutcome::Forged { height } => {
				log_warn!(
					self.logger,
					"Chain provider session: {} served a header at {} that fails proof of work.",
					witness,
					height
				);
			},
			TipCheckOutcome::Unanswered | TipCheckOutcome::NotAhead => {},
		}
		let now = self.now();
		self.machine().on_tip_check(active, witness, outcome, now);
		self.settled();
	}

	/// Where the node is, for a `since` or a `subscribe` to continue from.
	fn cursor(&self) -> Option<WireBlockId> {
		let verified = self.sink().and_then(|sink| sink.verified_tip());
		verified
			.map(|tip| block_id_to_wire(&tip))
			.or_else(|| self.seen_tip.lock().unwrap_or_else(|e| e.into_inner()).clone())
	}

	async fn probe(self: Arc<Self>, target: String, span: Option<trace::ActionSpan>) {
		let endpoints = self.connector.connect(&target);
		let from = self.cursor().unwrap_or_else(|| self.genesis.clone());
		let req = WireSinceRequest {
			version: CHAIN_WIRE_VERSION,
			from: from.clone(),
			max_blocks: 1,
			filter_offset: 0,
		};
		let scope = span.as_ref().map(trace::ActionSpan::scope);
		let answer = tokio::time::timeout(
			PROBE_TIMEOUT,
			trace::scoped(scope, endpoints.bundles.since(req)),
		)
		.await
		.unwrap_or_else(|_| Err(ChainProviderError::Unreachable("probe timed out".into())));
		let reason = answer.as_ref().err().map(ToString::to_string);
		let outcome = self.read_probe(&target, &from, answer);
		log_debug!(self.logger, "Chain provider session: probed {}: {:?}.", target, outcome);
		let end = match &outcome {
			ProbeOutcome::Answered { missed_blocks } => {
				SpanEnd::ok(Some(format!("from={} missed_blocks={}", from.height, missed_blocks)))
			},
			ProbeOutcome::Unsupported => SpanEnd::failed("probe_unsupported", reason),
			ProbeOutcome::NotSent => SpanEnd::failed("transport_unavailable", reason),
			ProbeOutcome::Failed => SpanEnd::failed("probe_failed", reason),
		};
		let now = self.now();
		self.machine().on_probe(&target, outcome, now);
		self.settled();
		self.tracer.finish(span, end);
	}

	fn read_probe(
		&self, target: &str, from: &WireBlockId,
		answer: Result<WireBlockUpdates, ChainProviderError>,
	) -> ProbeOutcome {
		let is_active = || self.machine().active() == Some(target);
		match answer {
			Ok(reply) => {
				let tip = check_version(reply.version).and_then(|_| block_id_from_wire(&reply.tip));
				let Ok(tip) = tip else {
					return ProbeOutcome::Failed;
				};
				if is_active() {
					*self.seen_tip.lock().unwrap_or_else(|e| e.into_inner()) =
						Some(reply.tip.clone());
					if let Some(sink) = self.sink() {
						sink.note_tip(tip);
					}
				}
				ProbeOutcome::Answered { missed_blocks: reply.tip.height > from.height }
			},
			Err(ChainProviderError::Refused(reason)) if reason.contains(NOT_ON_BEST_CHAIN) => {
				if is_active() {
					*self.seen_tip.lock().unwrap_or_else(|e| e.into_inner()) = None;
					if let Some(sink) = self.sink() {
						sink.forget_tip();
					}
				}
				ProbeOutcome::Answered { missed_blocks: true }
			},
			Err(ChainProviderError::Refused(reason)) if reason.starts_with("unsupported") => {
				ProbeOutcome::Unsupported
			},
			Err(ChainProviderError::NotSent(_)) => ProbeOutcome::NotSent,
			Err(e) => {
				log_debug!(
					self.logger,
					"Chain provider session: probe of {} failed: {}",
					target,
					e
				);
				ProbeOutcome::Failed
			},
		}
	}

	async fn subscribe(self: Arc<Self>, target: String, span: Option<trace::ActionSpan>) {
		let endpoints = self.connector.connect(&target);
		let req = self.subscribe_request(LEASE_SECS);
		let scope = span.as_ref().map(trace::ActionSpan::scope);
		let answer = tokio::time::timeout(
			SUBSCRIBE_TIMEOUT,
			trace::scoped(scope, endpoints.bundles.subscribe(req)),
		)
		.await
		.unwrap_or_else(|_| Err(ChainProviderError::Unreachable("subscribe timed out".into())));
		let end = match &answer {
			Ok(WireSubscribeResponse::Granted(granted)) => {
				SpanEnd::ok(Some(format!("granted until={}", granted.lease_until)))
			},
			Ok(WireSubscribeResponse::Refused(refused)) => {
				SpanEnd::failed("subscribe_refused", Some(format!("{:?}", refused.code)))
			},
			Ok(WireSubscribeResponse::Released(_)) => {
				SpanEnd::failed("subscribe_refused", Some("released".to_string()))
			},
			Err(e @ ChainProviderError::NotSent(_)) => {
				SpanEnd::failed("transport_unavailable", Some(e.to_string()))
			},
			Err(e) => SpanEnd::failed("subscribe_failed", Some(e.to_string())),
		};
		let outcome = match answer {
			Ok(WireSubscribeResponse::Granted(granted)) => {
				let current = self.machine().active() == Some(target.as_str());
				if let (true, Ok(tip), Some(sink)) =
					(current, block_id_from_wire(&granted.tip), self.sink())
				{
					sink.note_tip(tip);
				}
				SubscribeOutcome::Granted { lease_until_unix: granted.lease_until }
			},
			Ok(WireSubscribeResponse::Refused(refused)) => {
				if self.machine().active() == Some(target.as_str()) {
					if let Ok(serde_json::Value::String(code)) = serde_json::to_value(refused.code) {
						let now = self.now();
						self.machine().note_refused(&code, now);
					}
				}
				log_info!(
					self.logger,
					"Chain provider session: {} will not push ({:?}); pulling from it.",
					target,
					refused.code
				);
				SubscribeOutcome::Refused {
					retry_after: refused.retry_after.map(Duration::from_secs),
				}
			},
			// Only a release is answered this way: nothing granted, so nothing is pushed.
			Ok(WireSubscribeResponse::Released(_)) => {
				SubscribeOutcome::Refused { retry_after: None }
			},
			Err(ChainProviderError::Refused(reason)) if reason.starts_with("unsupported") => {
				SubscribeOutcome::Unsupported
			},
			Err(ChainProviderError::NotSent(_)) => SubscribeOutcome::NotSent,
			Err(e) => {
				log_debug!(
					self.logger,
					"Chain provider session: subscribe to {} failed: {}",
					target,
					e
				);
				SubscribeOutcome::Failed
			},
		};
		let now = self.now();
		self.machine().on_subscribe(&target, outcome, now);
		self.settled();
		self.tracer.finish(span, end);
	}

	/// Asks a second Pro, judges a difference, drops whoever is proven lying, and if this node took
	/// anything from such a Pro, moves off it first and then scans those blocks again.
	async fn cross_check(
		self: Arc<Self>, active: String, witness: String, span: Option<trace::ActionSpan>,
	) {
		let now = self.now();
		let Some(sink) = self.sink() else {
			self.machine().on_cross_check(&active, &witness, CrossCheckOutcome::NotYet, now);
			self.tracer.finish(span, SpanEnd::ok(Some("nothing to compare".to_string())));
			return;
		};
		let scope = span.as_ref().map(trace::ActionSpan::scope);
		let weighed = trace::scoped(scope.clone(), self.weigh_tip(&active, &witness)).await;
		self.heard_tip_check(&active, &witness, weighed);
		trace::scoped(scope.clone(), self.read_witness_fees(&witness)).await;
		// Moving off the active Pro answers more than comparing it could.
		if self.machine().active() != Some(active.as_str()) {
			let now = self.now();
			self.machine().on_cross_check(&active, &witness, CrossCheckOutcome::NotYet, now);
			self.settled();
			self.tracer.finish(span, SpanEnd::ok(Some("moved".to_string())));
			return;
		}
		let (active_filters, witness_filters) =
			(self.connector.connect(&active).filters, self.connector.connect(&witness).filters);
		let so_far = self
			.read_with_witness
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.as_ref()
			.filter(|(with, _)| *with == witness)
			.map(|(_, so_far)| *so_far);
		let epoch = self.provider_epoch.load(Ordering::Acquire);
		let report = trace::scoped(
			scope,
			cross_check::cross_check(
				&*sink,
				&*active_filters,
				&*witness_filters,
				epoch,
				so_far,
				CROSS_CHECK_CALL_TIMEOUT,
			),
		)
		.await;
		let cross_check::CrossCheckReport { outcome, rewind, unread_from, read_so_far, progressed } =
			report;
		// A witness not answering says nothing of what is left to read, and loses nobody's place. Nor
		// does another witness with nothing to read.
		let learned_nothing =
			matches!(outcome, CrossCheckOutcome::NotYet | CrossCheckOutcome::Inconclusive);
		if !learned_nothing {
			let mut kept = self.read_with_witness.lock().unwrap_or_else(|e| e.into_inner());
			match read_so_far {
				Some(so_far) => *kept = Some((witness.clone(), so_far)),
				None if kept.as_ref().map_or(false, |(with, _)| *with == witness) => *kept = None,
				None => {},
			}
		}
		self.report_cross_check(&active, &witness, &outcome);
		let detail = Some(format!("active={} {:?}", active, outcome));
		self.tracer.finish(
			span,
			match &outcome {
				CrossCheckOutcome::NotYet
				| CrossCheckOutcome::Agreed { .. }
				| CrossCheckOutcome::Inconclusive => SpanEnd::ok(detail),
				_ => SpanEnd::failed("cross_check_difference", detail),
			},
		);
		let now = self.now();
		let take_back = {
			let mut machine = self.machine();
			let take_back = machine.on_cross_check(&active, &witness, outcome, now);
			if !learned_nothing {
				machine.note_reading(&witness, unread_from, progressed, now);
			}
			take_back
		};
		self.settled();
		// The move comes first, or the loop would take the same blocks from the same Pro again.
		self.step();
		if let (true, Some(from)) = (take_back, rewind) {
			log_warn!(
				self.logger,
				"{}: scanning again from block {} at height {}.",
				CROSS_CHECK_LOG_TARGET,
				from.hash,
				from.height
			);
			sink.rewind_filters(from);
		}
	}

	/// One more call on an hourly check, for what the active Pro's fees are held against. What is
	/// out of bounds or refused leaves what was known.
	async fn read_witness_fees(&self, witness: &str) {
		if self.machine().owner_chose_source() {
			*self.witness_fees.lock().unwrap_or_else(|e| e.into_inner()) = None;
			return;
		}
		let endpoints = self.connector.connect(witness);
		let asked =
			tokio::time::timeout(CROSS_CHECK_CALL_TIMEOUT, endpoints.chain.fee_estimates()).await;
		let Ok(Ok(fees)) = asked else { return };
		if crate::chain::adapters::dependent::fees_out_of_bounds(&fees).is_none()
			&& !fees.targets.is_empty()
		{
			*self.witness_fees.lock().unwrap_or_else(|e| e.into_inner()) =
				Some((fees, Instant::now()));
		}
	}

	fn report_cross_check(&self, active: &str, witness: &str, outcome: &CrossCheckOutcome) {
		let line = format!(
			"{}: active={} witness={} result={:?}",
			CROSS_CHECK_LOG_TARGET, active, witness, outcome
		);
		match outcome {
			CrossCheckOutcome::NotYet | CrossCheckOutcome::Inconclusive => {
				log_debug!(self.logger, "{}", line);
			},
			CrossCheckOutcome::Agreed { .. } => {
				log_info!(self.logger, "{}", line);
			},
			_ => {
				log_warn!(self.logger, "{}", line);
			},
		}
	}

	/// Best effort: lost, the next push's ack says `not_subscribed`.
	async fn release(self: Arc<Self>, target: String, span: Option<trace::ActionSpan>) {
		let endpoints = self.connector.connect(&target);
		let req = self.subscribe_request(0);
		let scope = span.as_ref().map(trace::ActionSpan::scope);
		let answer = tokio::time::timeout(
			SUBSCRIBE_TIMEOUT,
			trace::scoped(scope, endpoints.bundles.subscribe(req)),
		)
		.await;
		let end = match answer {
			Ok(Ok(_)) => {
				log_debug!(self.logger, "Chain provider session: released {}.", target);
				SpanEnd::ok(None)
			},
			Ok(Err(e)) => {
				log_debug!(
					self.logger,
					"Chain provider session: release of {} lost: {}",
					target,
					e
				);
				SpanEnd::failed("release_lost", Some(e.to_string()))
			},
			Err(_) => {
				log_debug!(self.logger, "Chain provider session: release of {} timed out.", target);
				SpanEnd::failed("release_lost", Some("timed out".to_string()))
			},
		};
		self.tracer.finish(span, end);
	}

	fn subscribe_request(&self, lease_secs: u32) -> WireSubscribeRequest {
		WireSubscribeRequest {
			version: CHAIN_WIRE_VERSION,
			from: self.cursor().unwrap_or_else(|| self.genesis.clone()),
			lease_secs,
			want: vec![crate::chain::provider::SUBSCRIBE_WANT_BLOCKS.to_string()],
		}
	}

	/// The Pro to ask now, or the failure every call has with none.
	fn current(&self) -> Result<(String, ProviderEndpoints), ChainProviderError> {
		let target = self.target.read().unwrap_or_else(|e| e.into_inner());
		match target.as_ref() {
			Some(target) => Ok((normalise_node_id(&target.node_id), target.endpoints.clone())),
			None => Err(ChainProviderError::Unreachable("no chain provider selected".into())),
		}
	}

	fn current_name(&self) -> String {
		self.target
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.as_ref()
			.map_or_else(|| "no-chain-provider".to_string(), |target| target.node_id.clone())
	}

	/// What an ordinary call says about the Pro. A refusal says nothing, a Pro can decline one
	/// route and serve the rest, unless it says its source is not ready: that is a Pro up and not
	/// serving the chain, as good a reason to ask now as no answer at all.
	fn observed<T>(&self, target: &str, answer: &Result<T, ChainProviderError>) {
		match answer {
			Ok(_) => self.call_answered(target),
			Err(ChainProviderError::Unreachable(_)) => self.call_unreachable(target),
			Err(ChainProviderError::Refused(reason)) if reason.contains(NOT_READY) => {
				self.call_unreachable(target)
			},
			Err(_) => {},
		}
	}

	fn source_observed<T>(&self, target: &str, answer: &Result<T, SourceError>) {
		match answer {
			// Not there is still an answer: the usual sign of a raced reorg.
			Ok(_) | Err(SourceError::NotFound(_)) => self.call_answered(target),
			Err(SourceError::Unavailable { .. }) => self.call_unreachable(target),
			Err(SourceError::Invalid(_)) => {},
		}
	}

	/// A Pro's fee answer with a rate outside the bounds is refused whole on its way in, and the fee
	/// chain falls through; this tells of it.
	fn note_fees(&self, target: &str, fees: &WireFeeEstimates) {
		if let Some(detail) = crate::chain::adapters::dependent::fees_out_of_bounds(fees) {
			self.tracer.fee_rejected(target, detail, Instant::now());
		}
	}

	fn note_bundle_fees(&self, target: &str, bundles: &WireBlockUpdates) {
		if let Some(fees) = bundles.updates.iter().rev().find_map(|u| u.fee_estimates.as_ref()) {
			self.note_fees(target, fees);
		}
	}

	fn call_answered(&self, target: &str) {
		let now = self.now();
		self.machine().on_call_answered(target, now);
		self.settled();
	}

	fn call_unreachable(&self, target: &str) {
		let now = self.now();
		self.machine().on_call_unreachable(target, now);
		self.settled();
	}
}

fn now_at(epoch: Instant) -> machine::Now {
	machine::Now {
		mono_ms: epoch.elapsed().as_millis() as u64,
		unix_secs: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
	}
}

#[cfg(feature = "cbf")]
impl SyncObserver for ChainProviderSession {
	/// See [`machine::ProviderSession::on_sync_event`]. What is about a Pro counts only for the Pro
	/// it came from: the loop may have asked it before a move.
	fn sync_event(&self, epoch: u64, event: SyncEvent) {
		let current = epoch == self.provider_epoch.load(Ordering::Acquire);
		let report = match event {
			SyncEvent::Healthy if current => SyncReport::Healthy,
			SyncEvent::ReadingAgain if current => SyncReport::ReadingAgain,
			SyncEvent::StaleTip { height, age_secs } if current => {
				SyncReport::StaleTip { height, age_secs }
			},
			SyncEvent::Stuck if current => SyncReport::Stuck,
			SyncEvent::Evidence { kind, height } if current => {
				log_warn!(
					self.logger,
					"Chain provider session: {} served what proves it wrong ({}) at height {}.",
					self.current_name(),
					kind.as_str(),
					height
				);
				self.end_block_checks(
					|_| true,
					|| SpanEnd::failed("block_refused", Some(format!("{} at {}", kind.as_str(), height))),
				);
				SyncReport::Evidence { kind, height }
			},
			SyncEvent::Ended { reason } => SyncReport::Ended { reason },
			SyncEvent::Restarted => SyncReport::Restarted,
			_ => return,
		};
		let now = self.now();
		self.machine().on_sync_event(report, now);
		self.settled();
	}

	fn checked_through(&self, through: u32) {
		self.end_block_checks(
			|check| check.height <= through,
			|| SpanEnd::ok(Some(format!("checked_through={}", through))),
		);
	}

	fn saved_filter_headers(&self) -> Vec<crate::chain::cbf::source_sync::SavedFilterHeader> {
		self.store.load_filter_headers().unwrap_or_else(|problem| {
			log_warn!(self.logger, "Chain provider session: the saved filter headers are {}.", problem);
			Vec::new()
		})
	}

	fn save_filter_headers(&self, headers: &[crate::chain::cbf::source_sync::SavedFilterHeader]) {
		if let Err(e) = self.store.save_filter_headers(headers) {
			log_warn!(self.logger, "Chain provider session: could not save filter headers: {}", e);
		}
	}
}

#[async_trait]
impl ChainDataProvider for ChainProviderSession {
	fn name(&self) -> String {
		self.current_name()
	}

	fn fee_reference(&self) -> FeeReference {
		ChainProviderSession::fee_reference(self)
	}

	fn is_available(&self) -> bool {
		self.target.read().unwrap_or_else(|e| e.into_inner()).is_some()
	}

	fn can_broadcast(&self) -> bool {
		self.is_available() || !self.machine().memory().candidates.is_empty()
	}

	async fn second_opinion_on_own_txs(&self, txs: &[Transaction]) -> Option<OwnTxOpinion> {
		// A stranger's "held" does not outweigh the source the owner chose, and asking it would tell
		// it which wallets on this device are one owner's.
		if self.machine().owner_chose_source() {
			return None;
		}
		let witness = self.next_witnesses(1).pop()?;
		let endpoints = self.connector.connect(&witness);
		let req = WireMempoolRequest {
			version: CHAIN_WIRE_VERSION,
			spks: Vec::new(),
			known_unconfirmed: txs.iter().map(|tx| txid_to_wire(&tx.compute_txid())).collect(),
		};
		let span = self.tracer.standalone(trace::NAME_OWN_TX_CHECK, &witness);
		let scope = span.as_ref().map(trace::ActionSpan::scope);
		let asked = tokio::time::timeout(
			OWN_TX_CHECK_TIMEOUT,
			trace::scoped(scope, endpoints.chain.mempool(req)),
		)
		.await;
		let answer = match asked {
			Ok(Ok(answer)) if check_version(answer.version).is_ok() => answer,
			Ok(Ok(answer)) => {
				let detail = format!("wire version {}", answer.version);
				self.tracer.finish(span, SpanEnd::failed("own_tx_check", Some(detail)));
				return None;
			},
			Ok(Err(e)) => {
				self.tracer.finish(span, SpanEnd::failed("own_tx_check", Some(e.to_string())));
				return None;
			},
			Err(_) => {
				let detail = Some("timed out".to_string());
				self.tracer.finish(span, SpanEnd::failed("own_tx_check", detail));
				self.resting_witnesses
					.lock()
					.unwrap_or_else(|e| e.into_inner())
					.insert(witness, Instant::now());
				return None;
			},
		};
		let (lacks, held): (Vec<&Transaction>, Vec<&Transaction>) = txs
			.iter()
			.partition(|tx| answer.evicted.contains(&txid_to_wire(&tx.compute_txid())));
		self.tracer.finish(
			span,
			SpanEnd::ok(Some(format!("holds={} lacks={}", held.len(), lacks.len()))),
		);
		let lacks: Vec<WireBroadcastRequest> = lacks
			.into_iter()
			.map(|tx| WireBroadcastRequest { version: CHAIN_WIRE_VERSION, tx_hex: tx_to_wire(tx) })
			.collect();
		if !lacks.is_empty() {
			let chain = endpoints.chain;
			// In order, and nothing waits for it.
			tokio::spawn(async move {
				for req in lacks {
					let _ = tokio::time::timeout(WITNESS_SEND_TIMEOUT, chain.broadcast(req)).await;
				}
			});
		}
		Some(OwnTxOpinion {
			witness,
			held: held.into_iter().map(|tx| tx.compute_txid()).collect(),
		})
	}

	async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
		let (target, endpoints) = self.current()?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.chain.fee_estimates()).await;
		if let Ok(fees) = &answer {
			self.note_fees(&target, fees);
		}
		// A Pro answers fees from its cache with its bitcoind gone, so a reply proves nothing.
		if answer.is_err() {
			self.observed(&target, &answer);
		}
		answer
	}

	async fn broadcast(&self, req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
		let Ok((target, endpoints)) = self.current() else {
			return self.broadcast_with_no_active(req).await;
		};
		self.queue_for_witnesses(&req);
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.chain.broadcast(req)).await;
		self.observed(&target, &answer);
		answer
	}

	async fn tx_status(
		&self, req: WireTxStatusRequest,
	) -> Result<WireTxStatusResponse, ChainProviderError> {
		let (target, endpoints) = self.current()?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.chain.tx_status(req)).await;
		self.observed(&target, &answer);
		answer
	}

	async fn wallet_sync(&self, req: WireSyncRequest) -> Result<WireUpdate, ChainProviderError> {
		let (target, endpoints) = self.current()?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.chain.wallet_sync(req)).await;
		self.observed(&target, &answer);
		answer
	}

	async fn lightning_sync(
		&self, req: WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, ChainProviderError> {
		let (target, endpoints) = self.current()?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.chain.lightning_sync(req)).await;
		self.observed(&target, &answer);
		answer
	}

	async fn mempool(
		&self, req: WireMempoolRequest,
	) -> Result<WireMempoolResponse, ChainProviderError> {
		let (target, endpoints) = self.current()?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.chain.mempool(req)).await;
		self.observed(&target, &answer);
		answer
	}
}

#[async_trait]
impl BundleTransport for ChainProviderSession {
	fn name(&self) -> String {
		self.current_name()
	}

	fn fee_reference(&self) -> FeeReference {
		ChainProviderSession::fee_reference(self)
	}

	async fn since(&self, req: WireSinceRequest) -> Result<WireBlockUpdates, ChainProviderError> {
		let (target, endpoints) = self.current()?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.bundles.since(req)).await;
		if let Ok(bundles) = &answer {
			self.note_bundle_fees(&target, bundles);
		}
		self.observed(&target, &answer);
		answer
	}

	async fn subscribe(
		&self, req: WireSubscribeRequest,
	) -> Result<WireSubscribeResponse, ChainProviderError> {
		let (_, endpoints) = self.current()?;
		trace::scoped(self.tracer.ordinary_scope(), endpoints.bundles.subscribe(req)).await
	}
}

fn no_provider() -> SourceError {
	SourceError::unavailable("no chain provider selected")
}

#[async_trait]
impl FilterSource for ChainProviderSession {
	fn name(&self) -> &'static str {
		"provider-session"
	}

	fn epoch(&self) -> u64 {
		self.provider_epoch.load(Ordering::Acquire)
	}

	async fn tip(&self) -> Result<BlockId, SourceError> {
		let (target, endpoints) = self.current().map_err(|_| no_provider())?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.filters.tip()).await;
		self.source_observed(&target, &answer);
		answer
	}

	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		let (target, endpoints) = self.current().map_err(|_| no_provider())?;
		let answer =
			trace::scoped(self.tracer.ordinary_scope(), endpoints.filters.headers(from_height, count))
				.await;
		self.source_observed(&target, &answer);
		answer
	}

	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		let (target, endpoints) = self.current().map_err(|_| no_provider())?;
		let answer = trace::scoped(
			self.tracer.ordinary_scope(),
			endpoints.filters.filter_headers(start_height, stop_hash),
		)
		.await;
		self.source_observed(&target, &answer);
		answer
	}

	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let (target, endpoints) = self.current().map_err(|_| no_provider())?;
		let answer = trace::scoped(
			self.tracer.ordinary_scope(),
			endpoints.filters.filters(start_height, stop_hash),
		)
		.await;
		self.source_observed(&target, &answer);
		answer
	}

	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		let (target, endpoints) = self.current().map_err(|_| no_provider())?;
		let answer = trace::scoped(self.tracer.ordinary_scope(), endpoints.filters.block(hash)).await;
		self.source_observed(&target, &answer);
		answer
	}
}

#[cfg(all(test, feature = "cbf"))]
mod tests;
