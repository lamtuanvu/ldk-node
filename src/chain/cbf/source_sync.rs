// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A BIP157 client that follows the chain through a [`FilterSource`] — typically one other
//! node — instead of the Bitcoin P2P network, and verifies what it can of what it is handed.
//!
//! The loop feeds the same [`BlockApplicator`](crate::chain::cbf::applicator::BlockApplicator)
//! kyoto does, with the same [`ChainOp`]s, so the per-listener gates, the resume anchor, the
//! [`WatchLedger`](crate::chain::cbf::WatchLedger) and the sync-state publishing are shared.
//! What differs is where the data comes from and who checks it: kyoto checks what its peers
//! send and can compare them; here the source is a single node that may be broken or lying.
//!
//! # What is verified
//!
//! * **Headers** — each links to the one below, carries its proof of work, claims exactly the
//!   target the network rules require (the 2016-block retarget, testnet's minimum-difficulty
//!   rule, regtest's none), and has a timestamp above the median of the eleven before it. One
//!   more than two hours past this node's clock is waited out, not held against the source.
//!   See [`header_verify`](super::header_verify).
//! * **Fork choice** — a branch the source switches to replaces ours only when it has more
//!   work.
//! * **Filters against filter headers** — the served span continues the filter-header chain
//!   already verified, and every filter hashes to its served filter header.
//! * **Filters against headers** — each belongs to the block our header chain has at that
//!   height.
//! * **Blocks** — the header is ours, the merkle root holds, the first transaction is the only
//!   coinbase, no transaction is 64 bytes without its witness, none appears twice, and the
//!   witness data matches the coinbase commitment (or there is none and no commitment).
//!
//! # What is trusted: inclusion
//!
//! Nothing in a block header commits to its filter, and BIP157's defence — asking several
//! peers and comparing their filter headers — needs more than one source. So a source can
//! serve a filter and filter-header chain that is consistent with itself, from any height,
//! whose filters leave a transaction out: a payment to this node, or a spend of an output it
//! watches — a revoked commitment spending a channel's funding outpoint, say. This node then
//! never fetches that block and never sees the transaction, and nothing here can tell.
//!
//! In short: node mode verifies headers (proof of work, difficulty), block contents, and that
//! filters and filter headers agree, but it **trusts the source for transaction inclusion in
//! filters** — for not omitting anything. A lying source cannot make this node accept a
//! header, a chain or a block that is not valid; it can make it miss transactions.
//! [`CbfSource::trusts_source_for_inclusion`] says so to the embedding app, which decides where
//! that trust is acceptable — it should not be where the source gains from a missed
//! transaction, such as on mainnet when the source node is also a channel counterparty.
//!
//! The filter headers of the last [`FILTER_HEADERS_SAVED`] blocks are saved, through the
//! [`SyncObserver`], and held again on a resume: a filter header commits to every filter below it,
//! so without them a restart would forget a lie told before it, for good. A source now saying
//! otherwise of the blocks below the anchor is not proven wrong, as who gave the saved ones is not
//! known; those blocks are read again ([`SourceSync::held_from_another`]), and a witness is asked
//! soon. The anchor is the lowest of the listeners', so blocks above it are taken again, and a
//! listener already past one skips it: where what is taken now differs from what was saved, what
//! the filter matches there is handed over to read as well. Failing closed and starting over keeps every one held: a source is held to what it said
//! ([`SourceSync::start_over`]). Another provider's chain that differs from what is held is not
//! evidence against it, and the blocks where they differ are read again, off its filters.
//!
//! # Who hears of it
//!
//! Nothing here chooses a source. A [`SyncObserver`] hears a stale tip, a loop stuck, and whatever
//! the source served that proves it wrong: all of it what a provider session needs to leave a Pro,
//! none of it visible to it otherwise. Nothing a source says ends the loop: it fails closed and
//! starts over, and if the loop does end the engine starts it again.
//!
//! # Memory
//!
//! Headers and filter headers are held in RAM from the resume anchor (see [`HeaderChain`]),
//! pruned to the last [`SourceTuning::held_headers`]; filters and blocks are dropped once
//! used. The resume point comes from the wallet and LDK stores, as it does for kyoto.
//!
//! # Replays
//!
//! A listener can join while the loop runs — a wallet created at runtime, a node started after
//! the one that launched the sync — and the blocks already queued may be above its tip. The
//! engine then asks for a replay from the listener's tip ([`ReplaySender`]). Between two steps,
//! never inside one, the loop takes the requests made since. When the lowest is below the
//! headers held — a node that fell behind the one that launched the sync, below its resume
//! anchor even — the headers between are fetched and held too, authenticated as ancestors of the
//! held chain by their hashes, as the headers a resume holds below its anchor are by the
//! anchor's; no replay reaches more than [`SourceTuning::max_replay_depth`] below the tip held.
//! A request whose block is not the one held at its height is on another chain: nothing is
//! replayed for it. Then, when blocks above the lowest tip were queued, the loop queues
//! [`ChainOp::Rescan`] and every block above it again, fetched and verified as on the first pass
//! and matched against the scripts as they are now. The applicator rewinds on the rescan; the
//! gated fan-out lets each listener already past a block skip it and the one that joined take it.
//!
//! [`CbfSource::trusts_source_for_inclusion`]: crate::config::CbfSource::trusts_source_for_inclusion

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bip157::IndexedBlock;

use bdk_chain::BlockId;

use bitcoin::bip158::FilterHeader;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Network, ScriptBuf, Work};

use tokio::sync::{mpsc, watch, Notify, OwnedSemaphorePermit, Semaphore};

use async_trait::async_trait;

use crate::chain::cbf::applicator::ChainOp;
use crate::chain::cbf::fee_sampler::{BlockFetch, FeeBlockSource, SampleFailure};
use crate::chain::cbf::header_verify::{
	retarget_interval, verify_header, HeaderCheck, MEDIAN_TIME_SPAN,
};
use crate::chain::cbf::source::{
	FilterSource, SourceError, MAX_FILTERS_PER_REQUEST, MAX_HEADERS_PER_REQUEST,
};
use crate::chain::cbf::{mark_syncing, CbfSyncState};
use crate::chain::session::cross_check::{first_difference, HeldBlock, HeldChain};
use crate::chain::session::machine::LieKind;
use crate::logger::{log_debug, log_error, log_info, log_warn, LdkLogger, Logger};
use crate::Error;

/// How often the loop asks the source for its tip once caught up.
pub(crate) const SOURCE_TIP_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on any one call to the source. Implementations apply their own timeouts; this is the
/// backstop that keeps a wedged one from parking the loop.
pub(crate) const SOURCE_CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Consecutive invalid answers — data that fails a check, or that the source itself calls
/// invalid — before the loop gives up on the source and fails closed.
pub(crate) const MAX_INVALID_STRIKES: u32 = 3;

/// How long a `node,p2p` node waits on an unavailable node source before it starts kyoto.
pub(crate) const NODE_SOURCE_FALLBACK_AFTER: Duration = Duration::from_secs(5 * 60);

/// A verified tip whose timestamp is older than this, by this node's clock, is not reported
/// as synced: the source has most likely stopped following the chain. Three hours without a
/// block happens on mainnet about once in decades; regtest is exempt.
pub(crate) const STALE_TIP_AFTER: Duration = Duration::from_secs(3 * 60 * 60);

/// The first wait before a node-mode sync that failed closed on invalid data starts over.
pub(crate) const SOURCE_RESTART_FIRST_BACKOFF: Duration = Duration::from_secs(60);

/// The longest wait between two such restarts.
pub(crate) const SOURCE_RESTART_MAX_BACKOFF: Duration = Duration::from_secs(10 * 60);

/// How many headers are held below the tip. Two retarget periods: the retarget and the
/// minimum-difficulty rules need the current period's first header, the median-time rule the
/// last eleven, and a reorg can be followed only as deep as the chain held.
pub(crate) const HELD_HEADERS: u32 = 2 * 2016;

/// How far the header chain may run ahead of the filters. Bounds the RAM a long catch-up
/// takes: headers are fetched a batch ahead, then the filters catch up to them.
pub(crate) const HEADER_LOOKAHEAD: u32 = MAX_HEADERS_PER_REQUEST;

/// The first window of a reorg walk-back, doubled on every miss.
const REORG_WALK_FIRST_WINDOW: u32 = 16;

/// How many blocks' filter headers are saved across a restart: a day of them, what a commitment's
/// delay gives this node to act in at the shortest it is usually set. A lie told longer before a
/// restart than this, with no check finding it first, is not found by this.
pub(crate) const FILTER_HEADERS_SAVED: u32 = 144;

/// With no step completed for this long, the loop tells whoever watches it that it is stuck. Well
/// past what a slow Pro or a restart costs.
pub(crate) const SYNC_STUCK_AFTER: Duration = Duration::from_secs(10 * 60);

/// What a sync loop tells whoever watches it. See [`SyncObserver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncEvent {
	/// Steps complete again: anything said below no longer stands.
	Healthy,
	/// Caught up with the source, on a tip too old to believe.
	StaleTip { height: u32, age_secs: u64 },
	/// Nothing has completed for [`SYNC_STUCK_AFTER`].
	Stuck,
	/// It is reading blocks again on the source's word, as what it held differs.
	ReadingAgain,
	/// What the source served proves it wrong: enough to act on.
	Evidence { kind: LieKind, height: u32 },
	/// The loop ended, for this reason.
	Ended { reason: String },
	/// The engine started it again.
	Restarted,
}

/// Who hears from a sync loop. An event is about the source at `epoch`
/// ([`FilterSource::epoch`]): one from before a move says nothing about the next source.
pub(crate) trait SyncObserver: Send + Sync {
	/// See the trait docs.
	fn sync_event(&self, epoch: u64, event: SyncEvent);
	/// What an earlier run saved; see the module docs.
	fn saved_filter_headers(&self) -> Vec<SavedFilterHeader> {
		Vec::new()
	}
	/// Keep these across a restart, in place of what was kept.
	fn save_filter_headers(&self, _headers: &[SavedFilterHeader]) {}
	/// Everything up to `through` has passed every check here.
	fn checked_through(&self, _through: u32) {}
}

/// The filter header taken for one block, as kept across a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SavedFilterHeader {
	pub(crate) height: u32,
	pub(crate) hash: BlockHash,
	pub(crate) filter_header: FilterHeader,
}

/// A contiguous run of verified headers, from the lowest held up to the tip, with the filter
/// header of every block whose filter has been verified.
#[derive(Clone, Default)]
pub(crate) struct HeaderChain {
	base: u32,
	headers: Vec<Header>,
	hashes: Vec<BlockHash>,
	filter_headers: Vec<Option<FilterHeader>>,
	/// Under which source each was taken; `None` for one an earlier run saved.
	taken_under: Vec<Option<u64>>,
	/// Scan the blocks from this one up again: what was taken for them is not to be believed.
	pending_rewind: Option<BlockId>,
	/// Blocks to read again, in hand and checked, with their heights; see [`ChainOp::ScanBlock`].
	pending_scans: Vec<(u32, Arc<Block>)>,
}

impl HeaderChain {
	fn from_headers(base: u32, headers: Vec<Header>) -> Self {
		let hashes = headers.iter().map(Header::block_hash).collect();
		let filter_headers = vec![None; headers.len()];
		let taken_under = vec![None; headers.len()];
		Self {
			base,
			headers,
			hashes,
			filter_headers,
			taken_under,
			pending_rewind: None,
			pending_scans: Vec::new(),
		}
	}

	fn index(&self, height: u32) -> Option<usize> {
		let index = height.checked_sub(self.base)? as usize;
		(index < self.headers.len()).then_some(index)
	}

	/// The best block held, or `None` before the loop has resumed.
	pub(crate) fn tip(&self) -> Option<BlockId> {
		let hash = *self.hashes.last()?;
		Some(BlockId { height: self.base + self.headers.len() as u32 - 1, hash })
	}

	/// The lowest height held.
	pub(crate) fn base(&self) -> u32 {
		self.base
	}

	pub(crate) fn header(&self, height: u32) -> Option<Header> {
		self.index(height).map(|i| self.headers[i])
	}

	pub(crate) fn hash(&self, height: u32) -> Option<BlockHash> {
		self.index(height).map(|i| self.hashes[i])
	}

	/// The height of `hash` in the held chain. Searched from the tip down, where every caller
	/// looks.
	pub(crate) fn height_of(&self, hash: &BlockHash) -> Option<u32> {
		self.hashes.iter().rposition(|h| h == hash).map(|i| self.base + i as u32)
	}

	/// Holds `header` on top, unverified: for tests that need a chain held.
	#[cfg(test)]
	pub(crate) fn push_for_test(&mut self, header: Header) {
		let hash = header.block_hash();
		self.push(header, hash);
	}

	fn push(&mut self, header: Header, hash: BlockHash) {
		self.headers.push(header);
		self.hashes.push(hash);
		self.filter_headers.push(None);
		self.taken_under.push(None);
	}

	/// Drops everything above `height`.
	fn truncate_to(&mut self, height: u32) {
		let keep = (height + 1).saturating_sub(self.base) as usize;
		self.headers.truncate(keep);
		self.hashes.truncate(keep);
		self.filter_headers.truncate(keep);
		self.taken_under.truncate(keep);
	}

	/// Holds `headers`, the run just below the lowest held, the first of them at `base`.
	fn prepend(&mut self, base: u32, headers: Vec<Header>) {
		debug_assert_eq!(base as usize + headers.len(), self.base as usize);
		let mut hashes: Vec<BlockHash> = headers.iter().map(Header::block_hash).collect();
		hashes.append(&mut self.hashes);
		let mut filter_headers = vec![None; headers.len()];
		filter_headers.append(&mut self.filter_headers);
		let mut taken_under = vec![None; headers.len()];
		taken_under.append(&mut self.taken_under);
		let mut held = headers;
		held.append(&mut self.headers);
		let pending_rewind = self.pending_rewind;
		let pending_scans = std::mem::take(&mut self.pending_scans);
		*self = Self {
			base,
			headers: held,
			hashes,
			filter_headers,
			taken_under,
			pending_rewind,
			pending_scans,
		};
	}

	/// Drops everything below `height`, keeping at least the tip.
	fn prune_below(&mut self, height: u32) {
		let drop =
			(height.saturating_sub(self.base) as usize).min(self.headers.len().saturating_sub(1));
		if drop == 0 {
			return;
		}
		self.headers.drain(..drop);
		self.hashes.drain(..drop);
		self.filter_headers.drain(..drop);
		self.taken_under.drain(..drop);
		self.base += drop as u32;
	}

	fn filter_header(&self, height: u32) -> Option<FilterHeader> {
		self.index(height).and_then(|i| self.filter_headers[i])
	}

	/// Asks the loop to scan the blocks from `from` up again; see [`SourceSync::serve_rewind`].
	/// A second request keeps the lower of the two.
	pub(crate) fn request_rewind(&mut self, from: BlockId) {
		let lower = self.pending_rewind.map_or(true, |known| from.height < known.height);
		if lower {
			self.pending_rewind = Some(from);
		}
	}

	/// Asks the loop to hand `block`, checked against the header held at `height`, to the listeners
	/// to read again.
	pub(crate) fn request_scan(&mut self, height: u32, block: Block) {
		self.pending_scans.push((height, Arc::new(block)));
	}

	/// The newest block at least `bury` below the tip with a filter header taken.
	pub(crate) fn check_point(&self, bury: u32) -> Option<(BlockId, FilterHeader)> {
		let top = self.tip()?.height.checked_sub(bury)?;
		(self.base..=top).rev().find_map(|height| {
			let filter_header = self.filter_header(height)?;
			Some((BlockId { height, hash: self.hash(height)? }, filter_header))
		})
	}

	/// How many blocks wait to be read again; see [`Self::request_scan`].
	pub(crate) fn scans_waiting(&self) -> usize {
		self.pending_scans.len()
	}

	/// The chain up to `through`, for a cross-check that found a difference.
	pub(crate) fn held_chain(&self, through: u32) -> Option<HeldChain> {
		let blocks: Vec<HeldBlock> = (self.base..=through)
			.map(|height| {
				let i = self.index(height)?;
				Some(HeldBlock {
					hash: self.hashes[i],
					header: self.headers[i],
					filter_header: self.filter_headers[i],
					taken_under: self.taken_under[i],
				})
			})
			.collect::<Option<_>>()?;
		Some(HeldChain { base: self.base, blocks })
	}

	/// Forgets the filter headers from `height` up.
	fn clear_filter_headers_from(&mut self, height: u32) {
		let from = height.saturating_sub(self.base) as usize;
		self.filter_headers.iter_mut().skip(from).for_each(|fh| *fh = None);
		self.taken_under.iter_mut().skip(from).for_each(|under| *under = None);
	}

	fn set_filter_header(&mut self, height: u32, filter_header: FilterHeader, under: u64) {
		if let Some(i) = self.index(height) {
			self.filter_headers[i] = Some(filter_header);
			self.taken_under[i] = Some(under);
		}
	}

	/// Holds what an earlier run saved, up to `through`, for the blocks that are still these. Whose
	/// word they were is not known any more.
	fn hold_saved(&mut self, through: u32, saved: &[SavedFilterHeader]) {
		for row in saved.iter().filter(|row| row.height <= through) {
			if let (Some(i), true) = (self.index(row.height), self.hash(row.height) == Some(row.hash)) {
				self.filter_headers[i] = Some(row.filter_header);
				self.taken_under[i] = None;
			}
		}
	}

	/// What to keep across a restart: the newest [`FILTER_HEADERS_SAVED`] up to `through`.
	fn to_save(&self, through: u32) -> Vec<SavedFilterHeader> {
		let lowest = through.saturating_sub(FILTER_HEADERS_SAVED - 1).max(self.base);
		(lowest..=through)
			.filter_map(|height| {
				Some(SavedFilterHeader {
					height,
					hash: self.hash(height)?,
					filter_header: self.filter_header(height)?,
				})
			})
			.collect()
	}

	/// Whether the filter header held at `height` was taken from the source at `epoch`.
	fn taken_from(&self, height: u32, epoch: u64) -> bool {
		self.index(height).map_or(false, |i| self.taken_under[i] == Some(epoch))
	}

	/// The total work of the held headers above `height`.
	fn work_above(&self, height: u32) -> Work {
		let from = (height + 1).saturating_sub(self.base) as usize;
		self.headers
			.iter()
			.skip(from)
			.fold(Work::from_be_bytes([0; 32]), |sum, header| sum + header.work())
	}
}

/// The verified header chain, shared between the sync loop that extends it and the readers —
/// the fee source and `is_on_chain` — that answer from it. Never held across an `.await`.
pub(crate) type SharedHeaderChain = Arc<Mutex<HeaderChain>>;

pub(crate) fn new_shared_header_chain() -> SharedHeaderChain {
	Arc::new(Mutex::new(HeaderChain::default()))
}

pub(crate) fn lock_headers(chain: &SharedHeaderChain) -> MutexGuard<'_, HeaderChain> {
	chain.lock().unwrap_or_else(|e| e.into_inner())
}

/// Asks a running [`SourceSync`] to queue every block above a listener's tip again: what a
/// listener that joined below the blocks already queued needs. Each request names the tip, so a
/// listener on another chain is told apart. The engine holds the sender for as long as the loop
/// runs; see [`SourceSync::serve_replays`].
pub(crate) type ReplaySender = mpsc::UnboundedSender<BlockId>;

/// The loop's end of a [`ReplaySender`].
pub(crate) type ReplayReceiver = mpsc::UnboundedReceiver<BlockId>;

/// The replay requests of one [`SourceSync`].
pub(crate) fn replay_channel() -> (ReplaySender, ReplayReceiver) {
	mpsc::unbounded_channel()
}

/// The deepest a replay reaches below the tip held: a year of blocks. The headers between are
/// held while the replay passes them, under 8 MiB at the start of the deepest one.
pub(crate) const MAX_REPLAY_DEPTH: u32 = 365 * 144;

/// The scripts every filter is matched against — the wallet's and LDK's — behind a seam so the
/// loop can be driven without a wallet.
pub(crate) trait WatchedScripts: Send + Sync {
	/// Sizes of the underlying sets. Both only grow, so an unchanged pair means an unchanged
	/// set, and the cached copy stands.
	fn counts(&self) -> (usize, usize);
	/// Every watched script.
	fn scripts(&self) -> Vec<ScriptBuf>;
}

/// The watched scripts, copied once and refreshed only when a set grew; see the kyoto event
/// loop's `MatchSet`, whose reasoning this repeats.
#[derive(Default)]
struct ScriptCache {
	counts: Option<(usize, usize)>,
	scripts: Vec<ScriptBuf>,
}

impl ScriptCache {
	fn current(&mut self, watched: &dyn WatchedScripts) -> &[ScriptBuf] {
		let counts = watched.counts();
		if self.counts != Some(counts) {
			self.scripts = watched.scripts();
			self.counts = Some(counts);
		}
		&self.scripts
	}
}

/// A check the source's data failed. Nothing that failed one is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyFailure {
	/// A header failed a consensus check.
	Header(HeaderCheck),
	/// A run of headers the source served does not link up.
	BatchLink { height: u32 },
	/// The headers below the resume anchor do not end at the anchor.
	Anchor { height: u32, expected: BlockHash, got: BlockHash },
	/// A filter-header span of the wrong length.
	FilterHeaderCount { start: u32, expected: usize, got: usize },
	/// The span does not continue the verified filter-header chain.
	FilterHeaderChain { height: u32 },
	/// A filter span of the wrong length.
	FilterCount { start: u32, expected: usize, got: usize },
	/// A filter for another block or height than the one our header chain holds there.
	FilterBlock { height: u32 },
	/// A filter that does not hash to its filter header.
	FilterHeader { height: u32 },
	/// A filter that could not be decoded.
	FilterDecode { height: u32 },
	/// A block whose header is not the one our chain holds.
	BlockHeader { height: u32 },
	/// A block whose transactions do not hash to its merkle root.
	MerkleRoot { height: u32 },
	/// A block that lists a transaction twice (the CVE-2012-2459 malleation).
	DuplicateTransactions { height: u32 },
	/// A block whose witness data does not match its coinbase commitment, or that carries
	/// witness data without a commitment (Core's `CheckWitnessMalleation`).
	WitnessCommitment { height: u32 },
	/// A block whose first transaction is not its only coinbase.
	Coinbase { height: u32 },
	/// A block with a transaction exactly 64 bytes long without its witness: such a
	/// transaction can pass for an inner merkle node (CVE-2017-12842).
	SixtyFourByteTransaction { height: u32 },
}

impl VerifyFailure {
	/// The name of the check, for logs.
	pub(crate) fn name(&self) -> &'static str {
		match self {
			Self::Header(check) => check.name(),
			Self::BatchLink { .. } => "header batch link",
			Self::Anchor { .. } => "resume anchor",
			Self::FilterHeaderCount { .. } => "filter header count",
			Self::FilterHeaderChain { .. } => "filter header chain",
			Self::FilterCount { .. } => "filter count",
			Self::FilterBlock { .. } => "filter block hash",
			Self::FilterHeader { .. } => "filter hash vs filter header",
			Self::FilterDecode { .. } => "filter decoding",
			Self::BlockHeader { .. } => "block header",
			Self::MerkleRoot { .. } => "merkle root",
			Self::DuplicateTransactions { .. } => "duplicate transactions",
			Self::WitnessCommitment { .. } => "witness commitment",
			Self::Coinbase { .. } => "coinbase",
			Self::SixtyFourByteTransaction { .. } => "64-byte transaction",
		}
	}
}

impl fmt::Display for VerifyFailure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Header(check) => write!(f, "{}", check),
			Self::Anchor { height, expected, got } => write!(
				f,
				"{} check failed: the source has {} at height {}, this node resumes from {}",
				self.name(),
				got,
				height,
				expected
			),
			Self::FilterHeaderCount { start, expected, got }
			| Self::FilterCount { start, expected, got } => write!(
				f,
				"{} check failed for the span from {}: {} served, {} expected",
				self.name(),
				start,
				got,
				expected
			),
			Self::BatchLink { height }
			| Self::FilterHeaderChain { height }
			| Self::FilterBlock { height }
			| Self::FilterHeader { height }
			| Self::FilterDecode { height }
			| Self::BlockHeader { height }
			| Self::MerkleRoot { height }
			| Self::DuplicateTransactions { height }
			| Self::WitnessCommitment { height }
			| Self::Coinbase { height }
			| Self::SixtyFourByteTransaction { height } => {
				write!(f, "{} check failed at height {}", self.name(), height)
			},
		}
	}
}

/// The first bytes of a witness commitment output: `OP_RETURN`, a 36-byte push, and the
/// BIP141 commitment header `aa21a9ed`.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// The shortest script a witness commitment output can have: the prefix and 32 bytes.
const WITNESS_COMMITMENT_MIN_LEN: usize = 38;

/// The size, without witness, a transaction must not have: 64 bytes is the size of an inner
/// merkle node, so such a transaction could stand in for one (CVE-2017-12842).
const MERKLE_NODE_SIZED_TX: usize = 64;

/// Bitcoin Core's `CheckWitnessMalleation`, for a block whose coinbase is `txdata[0]`.
///
/// rust-bitcoin's `Block::check_witness_commitment` accepts any block in which no input
/// carries a witness, so a block with its witnesses stripped would pass it. Here, as in
/// Core: when the coinbase has a commitment (its last output starting with
/// [`WITNESS_COMMITMENT_PREFIX`]), the coinbase input must carry exactly one 32-byte witness
/// item — the reserved value — and the witness merkle root (coinbase wtxid zero) hashed with
/// it must equal the commitment; without a commitment, no transaction may carry a witness.
fn witness_data_is_committed(block: &Block) -> bool {
	let Some(coinbase) = block.txdata.first() else { return false };
	let commitment = coinbase.output.iter().rev().find_map(|output| {
		let script = output.script_pubkey.as_bytes();
		(script.len() >= WITNESS_COMMITMENT_MIN_LEN
			&& script[..WITNESS_COMMITMENT_PREFIX.len()] == WITNESS_COMMITMENT_PREFIX)
			.then(|| &script[WITNESS_COMMITMENT_PREFIX.len()..WITNESS_COMMITMENT_MIN_LEN])
	});
	let Some(commitment) = commitment else {
		return block.txdata.iter().all(|tx| tx.input.iter().all(|input| input.witness.is_empty()));
	};
	let Some(input) = coinbase.input.first() else { return false };
	let reserved = match input.witness.nth(0) {
		Some(item) if input.witness.len() == 1 && item.len() == 32 => item,
		_ => return false,
	};
	let Some(root) = block.witness_root() else { return false };
	Block::compute_witness_commitment(&root, reserved).as_byte_array()[..] == *commitment
}

/// Checks a full block against the header our chain holds at `height`: the header, the
/// merkle root, the coinbase, no merkle-node-sized transaction, no duplicate transaction, and
/// the witness data against its commitment. What this cannot show — that the block's
/// transactions are valid — the header's proof of work vouches for.
pub(crate) fn verify_block(
	block: &Block, height: u32, header: &Header,
) -> Result<(), VerifyFailure> {
	if block.header != *header {
		return Err(VerifyFailure::BlockHeader { height });
	}
	if !block.check_merkle_root() {
		return Err(VerifyFailure::MerkleRoot { height });
	}
	let only_first_is_coinbase = block.txdata.first().is_some_and(|tx| tx.is_coinbase())
		&& !block.txdata.iter().skip(1).any(|tx| tx.is_coinbase());
	if !only_first_is_coinbase {
		return Err(VerifyFailure::Coinbase { height });
	}
	if block.txdata.iter().any(|tx| tx.base_size() == MERKLE_NODE_SIZED_TX) {
		return Err(VerifyFailure::SixtyFourByteTransaction { height });
	}
	let mut txids = HashSet::with_capacity(block.txdata.len());
	if !block.txdata.iter().all(|tx| txids.insert(tx.compute_txid())) {
		return Err(VerifyFailure::DuplicateTransactions { height });
	}
	if !witness_data_is_committed(block) {
		return Err(VerifyFailure::WitnessCommitment { height });
	}
	Ok(())
}

/// Why one step of the loop did not complete.
#[derive(Debug)]
enum StepError {
	/// The source did not answer, or answered that it lacks the data, or called its own data
	/// invalid.
	Source(SourceError),
	/// The source's data failed a check.
	Verify(VerifyFailure),
	/// The source is on a branch with no more work than ours: behind, or lying. Waited out.
	LessWork { fork: u32 },
	/// The source's chain forks from ours below the lowest header held.
	ReorgTooDeep { held_from: u32 },
	/// Caught up with the source, but its tip is older than [`SourceTuning::stale_tip_after`]:
	/// the source has probably stopped following the chain. Not synced.
	StaleTip { height: u32, age_secs: u64 },
	/// The full-block permits were closed.
	PermitsClosed,
	/// The applicator is gone: it halted on a divergence and published the failure itself.
	ApplicatorGone,
}

impl fmt::Display for StepError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Source(e) => write!(f, "{}", e),
			Self::Verify(failure) => write!(f, "{}", failure),
			Self::LessWork { fork } => write!(
				f,
				"the source's branch from height {} has no more work than this node's",
				fork
			),
			Self::ReorgTooDeep { held_from } => write!(
				f,
				"the source's chain forks from this node's below height {}, the lowest header held",
				held_from
			),
			Self::StaleTip { height, age_secs } => write!(
				f,
				"the source's tip {} is {} minutes old by this node's clock; it has probably stopped following the chain",
				height,
				age_secs / 60
			),
			Self::PermitsClosed => f.write_str("the full-block permits were closed"),
			Self::ApplicatorGone => f.write_str("the block applicator is gone"),
		}
	}
}

impl StepError {
	/// A failed check that says nothing against the source: a header timestamped too far
	/// ahead of this node's clock (Core does not mark such a header invalid either, it waits),
	/// or an ancestor this node does not hold (its own bookkeeping). Retried later, never a
	/// strike.
	fn is_retry_later(&self) -> bool {
		matches!(
			self,
			Self::Verify(VerifyFailure::Header(
				HeaderCheck::FutureTime { .. } | HeaderCheck::MissingAncestor { .. }
			))
		)
	}

	/// Invalid data: the source's own admission, or a check it failed.
	fn is_invalid(&self) -> bool {
		matches!(self, Self::Source(SourceError::Invalid(_)) | Self::Verify(_))
			&& !self.is_retry_later()
	}

	/// What this holds against the source, when it holds anything: what it was caught at, and at
	/// which block. A resume anchor it does not hold is this node's own state against the chain,
	/// and a source that did not answer has said nothing.
	fn evidence(&self) -> Option<(LieKind, u32)> {
		let failure = match self {
			Self::ReorgTooDeep { held_from } => return Some((LieKind::WrongChain, *held_from)),
			Self::Source(SourceError::Invalid(_)) => return Some((LieKind::InvalidReply, 0)),
			Self::Verify(_) if self.is_retry_later() => return None,
			Self::Verify(failure) => failure,
			_ => return None,
		};
		match failure {
			VerifyFailure::Anchor { .. } => None,
			VerifyFailure::Header(check) => Some((LieKind::BadHeader, check.height())),
			VerifyFailure::BatchLink { height } => Some((LieKind::BadHeader, *height)),
			VerifyFailure::FilterHeaderCount { start, .. }
			| VerifyFailure::FilterCount { start, .. } => Some((LieKind::InvalidFilterData, *start)),
			VerifyFailure::FilterHeaderChain { height }
			| VerifyFailure::FilterBlock { height }
			| VerifyFailure::FilterHeader { height }
			| VerifyFailure::FilterDecode { height } => Some((LieKind::InvalidFilterData, *height)),
			VerifyFailure::BlockHeader { height }
			| VerifyFailure::MerkleRoot { height }
			| VerifyFailure::DuplicateTransactions { height }
			| VerifyFailure::WitnessCommitment { height }
			| VerifyFailure::Coinbase { height }
			| VerifyFailure::SixtyFourByteTransaction { height } => {
				Some((LieKind::InvalidBlock, *height))
			},
		}
	}

	/// Evidence with no need of a second look: no race and no restart makes a header that fails
	/// proof of work or claims the wrong difficulty.
	fn convicts_at_once(&self) -> bool {
		matches!(
			self,
			Self::Verify(VerifyFailure::Header(
				HeaderCheck::ProofOfWork { .. } | HeaderCheck::Difficulty { .. }
			))
		)
	}
}

impl From<VerifyFailure> for StepError {
	fn from(failure: VerifyFailure) -> Self {
		Self::Verify(failure)
	}
}

/// What a step achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
	/// Headers, filters or a reorg were taken: step again at once.
	Advanced,
	/// Caught up with the source: poll its tip again later.
	Idle,
}

/// How the loop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceSyncEnd {
	/// Asked to stop.
	Stopped,
	/// The applicator halted on a divergence and published the failure.
	ApplicatorGone,
	/// The source kept failing verification, or forked below what is held: the sync failed
	/// closed. The reason names the check.
	Failed(String),
	/// The node source stayed unavailable past [`SourceTuning::fallback_after`]: the caller
	/// starts kyoto.
	FallBack,
}

/// The loop's knobs. [`SourceTuning::production`] in the engine; shortened in the tests.
#[derive(Debug, Clone)]
pub(crate) struct SourceTuning {
	pub(crate) poll_interval: Duration,
	pub(crate) call_timeout: Duration,
	pub(crate) initial_backoff: Duration,
	pub(crate) max_backoff: Duration,
	/// While the source is unavailable, how often that is reported at warn.
	pub(crate) wait_report_interval: Duration,
	pub(crate) max_invalid_strikes: u32,
	/// `Some` for `node,p2p`: how long an unavailable source is waited on before falling back.
	/// A `node,p2p` node also falls back, at once, when the source fails verification
	/// [`SourceTuning::max_invalid_strikes`] times in a row or its tip goes stale.
	pub(crate) fallback_after: Option<Duration>,
	pub(crate) header_lookahead: u32,
	pub(crate) held_headers: u32,
	/// A caught-up tip older than this is not synced; `None` never judges (regtest).
	pub(crate) stale_tip_after: Option<Duration>,
	/// How often a stale tip is reported at warn.
	pub(crate) stale_report_interval: Duration,
	/// `Some((first, max))`: after failing closed on invalid data, `node` mode starts over after
	/// `first`, doubling up to `max`, rather than staying failed until the node restarts.
	pub(crate) restart_backoff: Option<(Duration, Duration)>,
	/// How far below the tip held a replay may reach; see [`MAX_REPLAY_DEPTH`].
	pub(crate) max_replay_depth: u32,
}

impl SourceTuning {
	pub(crate) fn production(fall_back_to_p2p: bool, network: Network) -> Self {
		use crate::chain::engine::cbf::{
			CBF_MAX_BACKOFF_MS, CBF_PEER_WAIT_REPORT_INTERVAL, INITIAL_BACKOFF_MS,
		};
		Self {
			poll_interval: SOURCE_TIP_POLL_INTERVAL,
			call_timeout: SOURCE_CALL_TIMEOUT,
			initial_backoff: Duration::from_millis(INITIAL_BACKOFF_MS),
			max_backoff: Duration::from_millis(CBF_MAX_BACKOFF_MS),
			wait_report_interval: CBF_PEER_WAIT_REPORT_INTERVAL,
			max_invalid_strikes: MAX_INVALID_STRIKES,
			fallback_after: fall_back_to_p2p.then_some(NODE_SOURCE_FALLBACK_AFTER),
			header_lookahead: HEADER_LOOKAHEAD,
			held_headers: HELD_HEADERS,
			stale_tip_after: (network != Network::Regtest).then_some(STALE_TIP_AFTER),
			stale_report_interval: CBF_PEER_WAIT_REPORT_INTERVAL,
			restart_backoff: Some((SOURCE_RESTART_FIRST_BACKOFF, SOURCE_RESTART_MAX_BACKOFF)),
			max_replay_depth: MAX_REPLAY_DEPTH,
		}
	}
}

/// How a failed step is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryReport {
	/// The source became unavailable just now, or has been for another report interval.
	WaitingWarn,
	/// Still unavailable, reported recently.
	WaitingQuiet,
	/// Invalid data: an error, counted.
	Invalid,
	/// A check that is retried later (see [`StepError::is_retry_later`]), or a stale tip:
	/// reported at warn once per interval.
	LaterWarn,
	/// The same, reported recently.
	LaterQuiet,
}

/// What to do after a failed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryDecision {
	Retry { backoff: Duration, report: RetryReport },
	FallBack,
	Fail,
}

/// The retry rules, apart from the loop so they can be checked without a source.
///
/// Unavailable (and not-found, the sign of a raced reorg) is retried forever on a doubling
/// backoff capped like kyoto's network waits, reported once and then once per interval —
/// except on `node,p2p`, which falls back to kyoto once the wait outlasts
/// [`SourceTuning::fallback_after`]. Invalid data is retried too, but
/// [`SourceTuning::max_invalid_strikes`] in a row fail the sync closed. A completed step
/// resets both.
///
/// A check retried later ([`StepError::is_retry_later`]) is never a strike and never a reason
/// to fall back. A stale tip is waited out at the poll interval — on `node,p2p` it is a reason
/// to fall back at once, as are the strikes, rather than to fail closed. An equal-work branch
/// is re-polled no slower than the tip is.
struct SourceRetryPolicy {
	tuning: SourceTuning,
	backoff: Duration,
	strikes: u32,
	waiting_since: Option<Instant>,
	last_report: Option<Instant>,
	last_later_report: Option<Instant>,
}

impl SourceRetryPolicy {
	fn new(tuning: SourceTuning) -> Self {
		let backoff = tuning.initial_backoff;
		Self {
			tuning,
			backoff,
			strikes: 0,
			waiting_since: None,
			last_report: None,
			last_later_report: None,
		}
	}

	fn later_report(&mut self, now: Instant, interval: Duration) -> RetryReport {
		match self.last_later_report {
			Some(last) if now.saturating_duration_since(last) < interval => RetryReport::LaterQuiet,
			_ => {
				self.last_later_report = Some(now);
				RetryReport::LaterWarn
			},
		}
	}

	/// A step completed. How long the source had been unavailable, if it had.
	fn succeeded(&mut self) -> Option<Duration> {
		self.strikes = 0;
		self.backoff = self.tuning.initial_backoff;
		self.last_report = None;
		self.waiting_since.take().map(|since| since.elapsed())
	}

	fn next_backoff(&mut self) -> Duration {
		let backoff = self.backoff;
		self.backoff = self.backoff.saturating_mul(2).min(self.tuning.max_backoff);
		backoff
	}

	fn wait_report(&mut self, now: Instant) -> RetryReport {
		match self.last_report {
			Some(last)
				if now.saturating_duration_since(last) < self.tuning.wait_report_interval =>
			{
				RetryReport::WaitingQuiet
			},
			_ => {
				self.last_report = Some(now);
				RetryReport::WaitingWarn
			},
		}
	}

	fn decide(&mut self, error: &StepError, now: Instant) -> RetryDecision {
		if error.is_retry_later() {
			let report = self.later_report(now, self.tuning.wait_report_interval);
			return RetryDecision::Retry { backoff: self.next_backoff(), report };
		}
		match error {
			StepError::Source(SourceError::Unavailable { .. })
			| StepError::Source(SourceError::NotFound(_)) => {
				let since = *self.waiting_since.get_or_insert(now);
				if let Some(after) = self.tuning.fallback_after {
					if now.saturating_duration_since(since) >= after {
						return RetryDecision::FallBack;
					}
				}
				RetryDecision::Retry { backoff: self.next_backoff(), report: self.wait_report(now) }
			},
			StepError::LessWork { .. } => {
				// An equal-work race is settled by the next block: look again at the tip poll's
				// pace at the latest, never at the unavailable-source backoff's.
				let backoff = self.next_backoff().min(self.tuning.poll_interval);
				RetryDecision::Retry { backoff, report: self.wait_report(now) }
			},
			StepError::StaleTip { .. } => {
				if self.tuning.fallback_after.is_some() {
					return RetryDecision::FallBack;
				}
				let report = self.later_report(now, self.tuning.stale_report_interval);
				RetryDecision::Retry { backoff: self.tuning.poll_interval, report }
			},
			StepError::Source(SourceError::Invalid(_)) | StepError::Verify(_) => {
				self.strikes += 1;
				if self.strikes >= self.tuning.max_invalid_strikes {
					if self.tuning.fallback_after.is_some() {
						return RetryDecision::FallBack;
					}
					return RetryDecision::Fail;
				}
				RetryDecision::Retry { backoff: self.next_backoff(), report: RetryReport::Invalid }
			},
			StepError::ReorgTooDeep { .. } if self.tuning.fallback_after.is_some() => {
				RetryDecision::FallBack
			},
			StepError::ReorgTooDeep { .. }
			| StepError::PermitsClosed
			| StepError::ApplicatorGone => RetryDecision::Fail,
		}
	}

	fn waiting_for(&self, now: Instant) -> Duration {
		self.waiting_since.map(|since| now.saturating_duration_since(since)).unwrap_or_default()
	}
}

/// Runs a source call under `limit`; a call that runs out is an unavailable source.
async fn bounded<T>(
	limit: Duration, call: impl Future<Output = Result<T, SourceError>>,
) -> Result<T, StepError> {
	match tokio::time::timeout(limit, call).await {
		Ok(answer) => answer.map_err(StepError::Source),
		Err(_elapsed) => Err(StepError::Source(SourceError::Unavailable {
			reason: format!("no answer within {}s", limit.as_secs()),
			timed_out: true,
		})),
	}
}

fn now_secs() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Checks that `headers` link up among themselves, the first at `first_height`.
fn check_batch_links(first_height: u32, headers: &[Header]) -> Result<(), VerifyFailure> {
	for (i, pair) in headers.windows(2).enumerate() {
		if pair[1].prev_blockhash != pair[0].block_hash() {
			return Err(VerifyFailure::BatchLink { height: first_height + i as u32 + 1 });
		}
	}
	Ok(())
}

/// Verifies `headers`, starting at `first_height`, onto the tip of `chain`, pushing each one
/// that passes. A failure leaves the headers before it in place: they passed.
fn extend_verified(
	chain: &mut HeaderChain, network: Network, first_height: u32, headers: &[Header], now: u64,
) -> Result<(), VerifyFailure> {
	for (i, header) in headers.iter().enumerate() {
		let height = first_height + i as u32;
		let prev = chain.tip().map(|tip| tip.hash).unwrap_or_else(BlockHash::all_zeros);
		let hash = {
			let held: &HeaderChain = chain;
			verify_header(network, height, header, prev, |h| held.header(h), now)
				.map_err(VerifyFailure::Header)?
		};
		chain.push(*header, hash);
	}
	Ok(())
}

/// Whether `header` can be on a chain with real work behind it, before anything is decided on it:
/// its hash meets its target, its target is within the network's limit and, where the network has
/// no minimum-difficulty blocks, no easier than two retargets from the header held at that height.
/// [`extend_verified`] then holds a branch to the exact rules, but it starts from the fork, and
/// finding the fork comes first. A branch's first header below the rules' target needs two whole
/// retarget periods of its own to get there, and the chain held is that long.
pub(crate) fn check_fork_header(
	network: Network, height: u32, header: &Header, held_at_height: Option<&Header>,
) -> Result<(), VerifyFailure> {
	let params = bitcoin::consensus::Params::new(network);
	let target = header.target();
	let within_limit = target <= params.max_attainable_target;
	if !within_limit || header.validate_pow(target).is_err() {
		return Err(VerifyFailure::Header(HeaderCheck::ProofOfWork { height }));
	}
	if let Some(held) = held_at_height.filter(|_| !params.allow_min_difficulty_blocks) {
		let once = held.target().max_transition_threshold(&params);
		if target > once.max_transition_threshold(&params) {
			return Err(VerifyFailure::Header(HeaderCheck::Difficulty {
				height,
				expected: held.bits,
				got: header.bits,
			}));
		}
	}
	Ok(())
}

/// The highest height where `source`'s chain and `chain` agree, walking down from `start` in
/// growing windows, every header checked before it counts for anything ([`check_fork_header`]).
/// Fails closed below the lowest header held.
async fn find_fork<S: FilterSource + ?Sized>(
	source: &S, chain: &SharedHeaderChain, network: Network, start: u32, call_timeout: Duration,
) -> Result<u32, StepError> {
	let base = lock_headers(chain).base();
	let mut hi = start;
	let mut window = REORG_WALK_FIRST_WINDOW;
	loop {
		if hi < base {
			return Err(StepError::ReorgTooDeep { held_from: base });
		}
		let lo = hi.saturating_sub(window - 1).max(base);
		let fetched = bounded(call_timeout, source.headers(lo, hi - lo + 1)).await?;
		if fetched.is_empty() {
			return Err(StepError::Source(SourceError::Invalid(format!(
				"no headers from height {} though this sync holds the chain from {}",
				lo, base
			))));
		}
		let fetched = &fetched[..fetched.len().min((hi - lo + 1) as usize)];
		check_batch_links(lo, fetched)?;
		{
			let held = lock_headers(chain);
			for (i, header) in fetched.iter().enumerate() {
				let height = lo + i as u32;
				check_fork_header(network, height, header, held.header(height).as_ref())?;
			}
			for (i, header) in fetched.iter().enumerate().rev() {
				let height = lo + i as u32;
				if held.hash(height) == Some(header.block_hash()) {
					return Ok(height);
				}
			}
		}
		if lo == base {
			return Err(StepError::ReorgTooDeep { held_from: base });
		}
		hi = lo - 1;
		window = window.saturating_mul(2).min(MAX_HEADERS_PER_REQUEST);
	}
}

/// What a source's headers prove against the chain held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BranchProof {
	/// Its headers, every check passed, carry more work than the chain held, up to `height`.
	Proven {
		/// The highest verified.
		height: u32,
		/// They reached what it claimed.
		reached_claim: bool,
	},
	/// It has shown nothing past what is held.
	NotAhead,
	/// A header it served failed proof of work or difficulty, at `height`.
	Forged { height: u32 },
	/// It did not answer.
	Unanswered,
}

/// See [`BranchProof`]. `claim` is the tip `source` says it has. Only its headers count: each has
/// to pass everything a header of this node's own chain does, on a copy of the chain held. With
/// `to_the_claim` they are read as far as one request goes, otherwise until they outweigh the
/// chain held, which is usually the first. Costs the source one or two calls.
pub(crate) async fn prove_more_work<S: FilterSource + ?Sized>(
	source: &S, chain: &SharedHeaderChain, network: Network, claim: BlockId,
	call_timeout: Duration, to_the_claim: bool,
) -> BranchProof {
	let Some(ours) = lock_headers(chain).tip() else {
		return BranchProof::NotAhead;
	};
	if claim.height <= ours.height {
		return BranchProof::NotAhead;
	}
	let fail = |error: StepError| match error {
		StepError::Verify(VerifyFailure::Header(check))
			if matches!(
				check,
				HeaderCheck::ProofOfWork { .. } | HeaderCheck::Difficulty { .. }
			) =>
		{
			BranchProof::Forged { height: check.height() }
		},
		StepError::Source(SourceError::Unavailable { .. }) => BranchProof::Unanswered,
		_ => BranchProof::NotAhead,
	};
	let count = (claim.height - ours.height).min(MAX_HEADERS_PER_REQUEST);
	let next = match bounded(call_timeout, source.headers(ours.height + 1, count)).await {
		Ok(headers) => headers,
		Err(error) => return fail(error),
	};
	let Some(first) = next.first() else { return BranchProof::NotAhead };
	let (fork, above) = if first.prev_blockhash == ours.hash {
		(ours.height, Some(next))
	} else {
		match find_fork(source, chain, network, ours.height, call_timeout).await {
			Ok(fork) => (fork, None),
			Err(error) => return fail(error),
		}
	};
	let (mut branch, held_work) = {
		let held = lock_headers(chain);
		let mut branch = held.clone();
		branch.truncate_to(fork);
		(branch, held.work_above(fork))
	};
	let top = claim.height.min(fork + MAX_HEADERS_PER_REQUEST);
	let mut height = fork + 1;
	let mut pending = above;
	while height <= top {
		let batch = match pending.take() {
			Some(batch) => batch,
			None => {
				let count = (top - height + 1).min(MAX_HEADERS_PER_REQUEST);
				match bounded(call_timeout, source.headers(height, count)).await {
					Ok(batch) => batch,
					Err(error) => {
						if branch.work_above(fork) > held_work {
							break;
						}
						return fail(error);
					},
				}
			},
		};
		if batch.is_empty() {
			break;
		}
		let batch = &batch[..batch.len().min((top - height + 1) as usize)];
		if let Err(failure) = extend_verified(&mut branch, network, height, batch, now_secs()) {
			match failure {
				// A header it may yet be right about, or this node's own gap: no more to read.
				VerifyFailure::Header(
					HeaderCheck::FutureTime { .. } | HeaderCheck::MissingAncestor { .. },
				) => break,
				failure => {
					// What is forged from the top down still counts against it, whatever came first.
					if matches!(
						failure,
						VerifyFailure::Header(
							HeaderCheck::ProofOfWork { .. } | HeaderCheck::Difficulty { .. }
						)
					) {
						return fail(StepError::Verify(failure));
					}
					return BranchProof::NotAhead;
				},
			}
		}
		height += batch.len() as u32;
		if !to_the_claim && branch.work_above(fork) > held_work {
			break;
		}
	}
	let verified = branch.tip().map_or(fork, |tip| tip.height);
	if branch.work_above(fork) <= held_work {
		return BranchProof::NotAhead;
	}
	let reached_claim = branch.hash(claim.height) == Some(claim.hash);
	BranchProof::Proven { height: verified, reached_claim }
}

/// The sync loop over a [`FilterSource`]. Owned by one task; see the module docs.
pub(crate) struct SourceSync {
	source: Arc<dyn FilterSource>,
	network: Network,
	/// The block the sync resumes from: trusted, from this node's own persisted state.
	anchor: BlockId,
	chain: SharedHeaderChain,
	resumed: bool,
	/// Every filter up to this height has been verified and its op queued.
	filters_through: u32,
	/// Every block up to this height has had its op queued on the chain held: above
	/// `filters_through` while a replay queues again what the listeners already took, which a
	/// reorg must disconnect too.
	queued_through: u32,
	/// The tip a `Synced` op was last queued for; cleared by anything that moves the chain.
	synced_at: Option<BlockHash>,
	scripts: Arc<dyn WatchedScripts>,
	script_cache: ScriptCache,
	ops_tx: mpsc::Sender<ChainOp>,
	/// Replay requests; see [`Self::serve_replays`].
	replay_rx: ReplayReceiver,
	/// Whether a request can still come: with every sender gone, the idle wait stops listening.
	replay_open: bool,
	/// The replays asked for and not yet served.
	pending_replays: Vec<BlockId>,
	/// Rung by a pushed block or a new provider: neither waits for the next poll or retry.
	wake: Arc<Notify>,
	sync_state_tx: watch::Sender<CbfSyncState>,
	full_block_permits: Arc<Semaphore>,
	stop_rx: watch::Receiver<bool>,
	tuning: SourceTuning,
	logger: Arc<Logger>,
	/// Whoever watches this loop; see [`SyncObserver`].
	observer: Option<Arc<dyn SyncObserver>>,
	/// The source this step is asking.
	step_epoch: u64,
	/// Blocks being read again, none of them disconnected; see [`Self::serve_rewind`].
	rescan: Option<Rescan>,
	/// What an earlier run took above where this run resumed; see the module docs.
	saved_above_anchor: HashMap<u32, SavedFilterHeader>,
	/// What is taken now has differed from what was saved: read what the filters match, as well.
	differs_from_saved: bool,
	/// Last told the observer something other than healthy.
	told_unwell: bool,
	/// When a step last completed.
	last_completed: Instant,
}

/// The blocks left to read again, with `next <= through`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rescan {
	next: u32,
	through: u32,
}

impl SourceSync {
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		source: Arc<dyn FilterSource>, network: Network, anchor: BlockId, chain: SharedHeaderChain,
		scripts: Arc<dyn WatchedScripts>, ops_tx: mpsc::Sender<ChainOp>, replay_rx: ReplayReceiver,
		wake: Arc<Notify>, sync_state_tx: watch::Sender<CbfSyncState>,
		full_block_permits: Arc<Semaphore>,
		stop_rx: watch::Receiver<bool>, tuning: SourceTuning, logger: Arc<Logger>,
	) -> Self {
		Self {
			source,
			network,
			anchor,
			chain,
			resumed: false,
			filters_through: anchor.height,
			queued_through: anchor.height,
			synced_at: None,
			scripts,
			script_cache: ScriptCache::default(),
			ops_tx,
			replay_rx,
			replay_open: true,
			pending_replays: Vec::new(),
			wake,
			sync_state_tx,
			full_block_permits,
			stop_rx,
			tuning,
			logger,
			observer: None,
			step_epoch: 0,
			rescan: None,
			saved_above_anchor: HashMap::new(),
			differs_from_saved: false,
			told_unwell: false,
			last_completed: Instant::now(),
		}
	}

	fn tell(&mut self, event: SyncEvent) {
		if !matches!(event, SyncEvent::Healthy | SyncEvent::ReadingAgain) {
			self.told_unwell = true;
		}
		if let Some(observer) = &self.observer {
			observer.sync_event(self.step_epoch, event);
		}
	}

	fn tell_healthy(&mut self) {
		self.last_completed = Instant::now();
		if std::mem::take(&mut self.told_unwell) {
			self.tell(SyncEvent::Healthy);
			self.told_unwell = false;
		}
	}

	/// What a failed step tells: what it holds against the source once it has the weight to act
	/// on, and that nothing is moving, or that the tip is old.
	fn tell_failure(&mut self, error: &StepError, decision: &RetryDecision, now: Instant) {
		let decided = matches!(decision, RetryDecision::Fail | RetryDecision::FallBack);
		if decided || error.convicts_at_once() {
			if let Some((kind, height)) = error.evidence() {
				self.tell(SyncEvent::Evidence { kind, height });
			}
		}
		if let StepError::StaleTip { height, age_secs } = error {
			self.tell(SyncEvent::StaleTip { height: *height, age_secs: *age_secs });
		} else if now.saturating_duration_since(self.last_completed) >= SYNC_STUCK_AFTER {
			self.tell(SyncEvent::Stuck);
		}
	}

	/// Waits `duration` out unless told to stop or the source moves; `false` when stopped.
	async fn wait_or_move(&mut self, duration: Duration) -> bool {
		let deadline = tokio::time::Instant::now() + duration;
		loop {
			let interrupted = tokio::select! {
				biased;
				_ = self.stop_rx.changed() => true,
				_ = self.wake.notified() => false,
				_ = tokio::time::sleep_until(deadline) => return !*self.stop_rx.borrow(),
			};
			if interrupted || *self.stop_rx.borrow() {
				return false;
			}
			if self.source.epoch() != self.step_epoch {
				return true;
			}
		}
	}

	/// Tells `observer` how the loop fares.
	pub(crate) fn observed_by(mut self, observer: Arc<dyn SyncObserver>) -> Self {
		self.observer = Some(observer);
		self
	}

	/// Runs until stopped, until the applicator is gone, until the source is given up on, or —
	/// on `node,p2p` — until it is time to fall back to kyoto.
	///
	/// With [`SourceTuning::restart_backoff`], failing closed on what a source served is not the
	/// end: the failure is published and logged, and after the backoff, or as soon as the source
	/// moves, the loop starts over with no strikes. Everything it verified stays, headers and
	/// filter headers both.
	///
	/// Replay requests are served at the start of every step ([`Self::serve_replays`]); one
	/// that arrives while the loop waits for the next tip poll cuts the wait short. Before
	/// handing over to kyoto the loop takes no more, and rewinds the applicator for the ones
	/// already made ([`Self::rewind_for_handover`]).
	pub(crate) async fn run(mut self) -> SourceSyncEnd {
		let mut policy = SourceRetryPolicy::new(self.tuning.clone());
		let mut restart_backoff = self.tuning.restart_backoff.map(|(first, _)| first);
		loop {
			if *self.stop_rx.borrow() {
				return SourceSyncEnd::Stopped;
			}
			let mut stop_rx = self.stop_rx.clone();
			self.step_epoch = self.source.epoch();
			let step = tokio::select! {
				biased;
				_ = stop_rx.changed() => return SourceSyncEnd::Stopped,
				step = self.step() => step,
			};
			if self.source.epoch() != self.step_epoch {
				// What came back came from another source, or half of it did. The new one owes
				// nothing for it.
				policy = SourceRetryPolicy::new(self.tuning.clone());
				restart_backoff = self.tuning.restart_backoff.map(|(first, _)| first);
				self.synced_at = None;
				if matches!(step, Err(StepError::ApplicatorGone)) {
					return SourceSyncEnd::ApplicatorGone;
				}
				continue;
			}
			match step {
				Ok(progress) => {
					self.tell_healthy();
					if let Some(waited) = policy.succeeded() {
						log_info!(
							self.logger,
							"CBF filter source '{}' answering again after {}s.",
							self.source.name(),
							waited.as_secs()
						);
					}
					if progress == Progress::Idle {
						restart_backoff = self.tuning.restart_backoff.map(|(first, _)| first);
						if !self.idle(self.tuning.poll_interval).await {
							return SourceSyncEnd::Stopped;
						}
					}
				},
				Err(StepError::ApplicatorGone) => return SourceSyncEnd::ApplicatorGone,
				Err(error) => {
					// Whatever failed, the source's tip is not known to be ours any more.
					self.synced_at = None;
					mark_syncing(&self.sync_state_tx);
					let now = Instant::now();
					let decision = policy.decide(&error, now);
					self.tell_failure(&error, &decision, now);
					match decision {
						RetryDecision::Retry { backoff, report } => {
							self.report_retry(
								&error,
								report,
								backoff,
								policy.waiting_for(now),
								&policy,
							);
							if !self.sleep(backoff, true).await {
								return SourceSyncEnd::Stopped;
							}
						},
						RetryDecision::FallBack => {
							let why = if error.is_invalid() {
								format!("kept sending data that failed verification ({})", error)
							} else if matches!(error, StepError::StaleTip { .. }) {
								format!("is not following the chain: {}", error)
							} else {
								format!(
									"has been unavailable for {}s ({})",
									policy.waiting_for(now).as_secs(),
									error
								)
							};
							log_warn!(
								self.logger,
								"CBF filter source '{}' {}; falling back to the P2P network.",
								self.source.name(),
								why
							);
							self.rewind_for_handover().await;
							return SourceSyncEnd::FallBack;
						},
						RetryDecision::Fail => {
							let reason = error.to_string();
							self.sync_state_tx
								.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
							let on_the_source =
								error.is_invalid() || matches!(error, StepError::ReorgTooDeep { .. });
							let restart = restart_backoff.filter(|_| on_the_source);
							let Some(wait) = restart else {
								log_error!(
									self.logger,
									"CBF filter source '{}': {}; nothing from it was applied. Giving up on it: the CBF sync has failed closed.",
									self.source.name(),
									reason
								);
								return SourceSyncEnd::Failed(reason);
							};
							log_error!(
								self.logger,
								"CBF filter source '{}': {}; nothing from it was applied. The CBF sync has failed closed; starting over in {}s.",
								self.source.name(),
								reason,
								wait.as_secs()
							);
							if !self.wait_or_move(wait).await {
								return SourceSyncEnd::Stopped;
							}
							restart_backoff = self
								.tuning
								.restart_backoff
								.map(|(_, max)| wait.saturating_mul(2).min(max));
							policy = SourceRetryPolicy::new(self.tuning.clone());
							self.start_over();
						},
					}
				},
			}
		}
	}

	/// After failing closed: publish that the sync is running again, from the blocks already
	/// queued. Every filter header verified stays: a source is held to what it said, so a story
	/// that only holds with those forgotten stays refused. A source that was repaired and differs
	/// from what is held needs the owner to take it up again, which a move does.
	fn start_over(&mut self) {
		self.synced_at = None;
		self.sync_state_tx.send_replace(CbfSyncState::Active {
			applied_tip: Some(self.filters_through),
			synced_to_tip: false,
		});
		log_info!(
			self.logger,
			"CBF starting over with filter source '{}' from height {}.",
			self.source.name(),
			self.filters_through
		);
	}

	fn report_retry(
		&self, error: &StepError, report: RetryReport, backoff: Duration, waited: Duration,
		policy: &SourceRetryPolicy,
	) {
		let name = self.source.name();
		match report {
			RetryReport::WaitingWarn => log_warn!(
				self.logger,
				"CBF filter source '{}' cannot serve the sync: {}; waiting {}s so far, next retry in {}s.",
				name,
				error,
				waited.as_secs(),
				backoff.as_secs().max(1)
			),
			RetryReport::WaitingQuiet | RetryReport::LaterQuiet => log_debug!(
				self.logger,
				"CBF filter source '{}' still cannot serve the sync: {}; next retry in {}ms.",
				name,
				error,
				backoff.as_millis()
			),
			RetryReport::LaterWarn => log_warn!(
				self.logger,
				"CBF filter source '{}': {}; not synced, not held against the source; retrying in {}s.",
				name,
				error,
				backoff.as_secs().max(1)
			),
			RetryReport::Invalid => log_error!(
				self.logger,
				"CBF filter source '{}' sent data that failed verification: {}; not applied. Strike {}/{}, retrying in {}ms.",
				name,
				error,
				policy.strikes,
				self.tuning.max_invalid_strikes,
				backoff.as_millis()
			),
		}
	}

	/// Sleeps `duration` unless told to stop first; `false` when stopped. With `wakeable`, the
	/// wake cuts it short: a node given a provider or sent a block must not sit out a retry's
	/// backoff from before that.
	async fn sleep(&mut self, duration: Duration, wakeable: bool) -> bool {
		// A dropped sender is a stop too.
		let interrupted = tokio::select! {
			biased;
			_ = self.stop_rx.changed() => true,
			_ = self.wake.notified(), if wakeable => false,
			_ = tokio::time::sleep(duration) => false,
		};
		!interrupted && !*self.stop_rx.borrow()
	}

	/// Waits out the tip poll interval; `false` when told to stop. A replay request cuts the
	/// wait short: a listener that joined must not wait a whole poll for its blocks. So does the
	/// wake: a pushed block must not wait for the next poll either.
	async fn idle(&mut self, duration: Duration) -> bool {
		let deadline = tokio::time::Instant::now() + duration;
		loop {
			tokio::select! {
				biased;
				// A dropped sender is a stop too.
				_ = self.stop_rx.changed() => return false,
				request = self.replay_rx.recv(), if self.replay_open => match request {
					Some(request) => {
						self.pending_replays.push(request);
						break;
					},
					// Every sender is gone: nobody can ask any more.
					None => self.replay_open = false,
				},
				_ = self.wake.notified() => break,
				_ = tokio::time::sleep_until(deadline) => break,
			}
		}
		!*self.stop_rx.borrow()
	}

	/// Serves the replays asked for since the last step: one, from the lowest tip asked.
	///
	/// When that tip is below the headers held, the headers between are held first
	/// ([`Self::hold_headers_from`]); a failure there is a failed step, retried with the
	/// requests kept. Nothing is replayed for a tip more than [`SourceTuning::max_replay_depth`]
	/// below the tip held, nor for one whose block is not the block held at its height: that
	/// listener is on another chain.
	///
	/// When blocks above the replay's start were queued, [`ChainOp::Rescan`] goes first, on the
	/// same queue — the applicator must expect the replayed heights before the first of them
	/// arrives — and the filter batches that follow fetch, verify and queue every block above
	/// it again. A start at or above everything queued so far fetches nothing again — the blocks
	/// after it are still to come — but the rescan is queued all the same: the applicator can
	/// have started above that start, and would drop the blocks the listener needs.
	async fn serve_replays(&mut self) -> Result<(), StepError> {
		while let Ok(request) = self.replay_rx.try_recv() {
			self.pending_replays.push(request);
		}
		if self.pending_replays.is_empty() {
			return Ok(());
		}
		let held_tip = lock_headers(&self.chain).tip().map_or(self.anchor.height, |tip| tip.height);
		let floor = held_tip.saturating_sub(self.tuning.max_replay_depth);
		let reachable = self.pending_replays.iter().map(|request| request.height);
		if let Some(lowest) = reachable.filter(|height| *height >= floor).min() {
			self.hold_headers_from(lowest).await?;
		}

		let mut from: Option<u32> = None;
		for request in std::mem::take(&mut self.pending_replays) {
			if request.height < floor {
				log_warn!(
					self.logger,
					"CBF replay refused for the listener at height {}: it is more than {} blocks below the tip held, {}; nothing is queued again for it.",
					request.height,
					self.tuning.max_replay_depth,
					held_tip
				);
				continue;
			}
			let held = lock_headers(&self.chain).hash(request.height);
			if let Some(held) = held.filter(|held| *held != request.hash) {
				log_error!(
					self.logger,
					"CBF replay refused for the listener at height {}: its block {} is not the one filter source '{}' gave this sync there ({}), so it is on another chain; nothing is queued again for it.",
					request.height,
					request.hash,
					self.source.name(),
					held
				);
				continue;
			}
			from = Some(from.map_or(request.height, |from| from.min(request.height)));
		}
		let Some(from) = from else {
			return Ok(());
		};
		if from >= self.filters_through {
			// Nothing above it is queued by this loop yet, so nothing is fetched again: the
			// blocks after it are still to come. The applicator may be past it all the same:
			// it starts above the lowest tip of the nodes in the launch, which can lie above
			// both the anchor this loop resumed from and the tip of a node that joined after
			// the launch — a secondary an app starts right after its primary, a few blocks
			// behind it (a mainnet Pi Zero, 2026-10-31). Without the rescan the applicator
			// drops the blocks that node needs as out of sequence, and it waits for ever. The
			// applicator ignores a rescan that starts at or above the block it expects next.
			log_debug!(
				self.logger,
				"CBF replay from height {} asked; nothing above it is queued yet (queued through {}), so only the applicator is told to expect height {}.",
				from,
				self.filters_through,
				from + 1
			);
			self.send(ChainOp::Rescan { from_height: from }).await?;
			return Ok(());
		}
		log_info!(
			self.logger,
			"CBF queueing blocks {}..={} from filter source '{}' again for a listener that joined late.",
			from + 1,
			self.filters_through,
			self.source.name()
		);
		self.send(ChainOp::Rescan { from_height: from }).await?;
		self.filters_through = from;
		self.synced_at = None;
		mark_syncing(&self.sync_state_tx);
		Ok(())
	}

	/// Holds every header from `height` up. Below the lowest held, the headers between are
	/// fetched, checked to link up into the held chain and to carry their proof of work, and
	/// held: they are authenticated as its ancestors by their hashes alone, as the headers a
	/// resume holds below its anchor are by the anchor's. Pruning drops them again once the
	/// filters have passed them.
	async fn hold_headers_from(&mut self, height: u32) -> Result<(), StepError> {
		let (base, lowest_held) = {
			let chain = lock_headers(&self.chain);
			match chain.header(chain.base()) {
				Some(header) => (chain.base(), header),
				// Nothing held yet: the resume holds what the first replay needs.
				None => return Ok(()),
			}
		};
		if height >= base {
			return Ok(());
		}
		let count = base - height;
		let mut headers: Vec<Header> = Vec::with_capacity(count as usize);
		while (headers.len() as u32) < count {
			let next = height + headers.len() as u32;
			let ask = (count - headers.len() as u32).min(MAX_HEADERS_PER_REQUEST);
			let batch = bounded(self.tuning.call_timeout, self.source.headers(next, ask)).await?;
			if batch.is_empty() {
				return Err(StepError::Source(SourceError::Invalid(format!(
					"no headers from height {} though this sync holds the chain from {}",
					next, base
				))));
			}
			headers.extend(batch.into_iter().take(ask as usize));
		}
		check_batch_links(height, &headers)?;
		if headers.last().map(Header::block_hash) != Some(lowest_held.prev_blockhash) {
			return Err(VerifyFailure::BatchLink { height: base }.into());
		}
		for (i, header) in headers.iter().enumerate() {
			if header.validate_pow(header.target()).is_err() {
				let height = height + i as u32;
				return Err(VerifyFailure::Header(HeaderCheck::ProofOfWork { height }).into());
			}
		}
		lock_headers(&self.chain).prepend(height, headers);
		log_info!(
			self.logger,
			"CBF holding headers from height {} (from {} until now) through filter source '{}', for a replay.",
			height,
			base,
			self.source.name()
		);
		Ok(())
	}

	/// The loop hands over to kyoto: no request is taken any more — a late one fails at the
	/// engine, which then refuses its target — and for the ones already made the applicator is
	/// rewound now, without asking the source the loop is giving up on: kyoto, resuming from
	/// the lowest listener, replays into it from there.
	async fn rewind_for_handover(&mut self) {
		self.replay_rx.close();
		while let Ok(request) = self.replay_rx.try_recv() {
			self.pending_replays.push(request);
		}
		let pending = std::mem::take(&mut self.pending_replays);
		let Some(lowest) = pending.iter().map(|request| request.height).min() else {
			return;
		};
		// Sent even when this loop queued nothing above `lowest`: the applicator may have
		// started above it all the same (see `serve_replays`), and ignores a rescan it does
		// not need.
		log_info!(
			self.logger,
			"CBF rewinding to height {} before the P2P fallback, for a listener that joined late.",
			lowest
		);
		if self.send(ChainOp::Rescan { from_height: lowest }).await.is_err() {
			log_debug!(self.logger, "CBF rewind before the P2P fallback dropped: no applicator.");
		}
	}

	/// One unit of progress: resume, a header batch, a reorg, a filter batch, or the `Synced`
	/// that ends a catch-up — after the replays asked for since the last step are served.
	async fn step(&mut self) -> Result<Progress, StepError> {
		if !self.resumed {
			self.resume().await?;
			self.resumed = true;
			return Ok(Progress::Advanced);
		}
		self.serve_scans().await?;
		self.serve_rewind();
		self.serve_replays().await?;

		// Re-read every step: after any failure, a stop hash taken from an older tip may no
		// longer be on the source's chain.
		let tip = bounded(self.tuning.call_timeout, self.source.tip()).await?;
		let (ours, tip_on_our_chain) = {
			let chain = lock_headers(&self.chain);
			let ours = chain.tip().expect("resumed");
			(ours, chain.hash(tip.height) == Some(tip.hash))
		};

		if !tip_on_our_chain {
			if tip.height <= ours.height {
				return self.reorg(tip, ours).await;
			}
			// A source whose headers come with their filters has the filters of the headers
			// held in hand: use them before asking for more of both.
			let room = if self.source.headers_come_with_filters()
				&& self.filters_through < ours.height
			{
				0
			} else {
				(self.filters_through + self.tuning.header_lookahead).saturating_sub(ours.height)
			};
			if room > 0 {
				let count = (tip.height - ours.height).min(room).min(MAX_HEADERS_PER_REQUEST);
				let headers =
					bounded(self.tuning.call_timeout, self.source.headers(ours.height + 1, count))
						.await?;
				let Some(first) = headers.first() else {
					return Err(StepError::Source(SourceError::Invalid(format!(
						"no headers above height {} though its tip is at {}",
						ours.height, tip.height
					))));
				};
				if first.prev_blockhash != ours.hash {
					return self.reorg(tip, ours).await;
				}
				let headers = &headers[..headers.len().min(count as usize)];
				if let Err(error) = self.extend(ours.height + 1, headers) {
					// A header to retry later (one from the future, say) need not hold up the
					// filters of the headers below it: take those first.
					let held = lock_headers(&self.chain).tip().expect("resumed").height;
					if !error.is_retry_later() || self.filters_through >= held {
						return Err(error);
					}
					self.filter_batch(held).await?;
				}
				return Ok(Progress::Advanced);
			}
		}

		if let Some(rescan) = self.rescan {
			if let Err(error) = self.rescan_batch(rescan).await {
				if !tip_on_our_chain && self.next_header_left(ours).await {
					return self.reorg(tip, ours).await;
				}
				return Err(error);
			}
			return Ok(Progress::Advanced);
		}

		if self.filters_through < ours.height {
			if let Err(error) = self.filter_batch(ours.height).await {
				// With no room for headers nothing above has looked at the next one, and a batch
				// whose stop hash left the best chain fails until something does.
				if !tip_on_our_chain && self.next_header_left(ours).await {
					return self.reorg(tip, ours).await;
				}
				return Err(error);
			}
			return Ok(Progress::Advanced);
		}
		if !tip_on_our_chain {
			// The header lookahead was full and the filters have caught up with it.
			return Ok(Progress::Advanced);
		}

		if let Some(after) = self.tuning.stale_tip_after {
			let time = lock_headers(&self.chain).header(ours.height).map(|h| u64::from(h.time));
			let age_secs = time.map_or(0, |time| now_secs().saturating_sub(time));
			if age_secs > after.as_secs() {
				return Err(StepError::StaleTip { height: ours.height, age_secs });
			}
		}
		if self.synced_at != Some(ours.hash) {
			log_info!(
				self.logger,
				"CBF synced to tip {} from filter source '{}'.",
				ours.height,
				self.source.name()
			);
			self.send(ChainOp::Synced { tip_height: ours.height }).await?;
			self.synced_at = Some(ours.hash);
		} else {
			// The tip was just asked for and nothing is new: that is a fresh proof the node is
			// caught up, and the wallet sync timestamps must say so between blocks too. A failed
			// tip check never gets here, so an outage still shows as stalled.
			self.send(ChainOp::TipConfirmed { tip_height: ours.height }).await?;
		}
		Ok(Progress::Idle)
	}

	async fn send(&self, op: ChainOp) -> Result<(), StepError> {
		self.ops_tx.send(op).await.map_err(|_| StepError::ApplicatorGone)
	}

	/// Fetches the headers from the start of the anchor's retarget period (and at least the
	/// eleven below it) up to the anchor, checks they link and end at the anchor, and holds
	/// them. They are authenticated by the anchor alone, which this node trusts; every header
	/// above it is fully verified.
	async fn resume(&mut self) -> Result<(), StepError> {
		let anchor = self.anchor;
		let interval = retarget_interval(self.network);
		let period_start = anchor.height - anchor.height % interval;
		let lowest = period_start.min(anchor.height.saturating_sub(MEDIAN_TIME_SPAN));

		let mut headers: Vec<Header> = Vec::with_capacity((anchor.height - lowest + 1) as usize);
		while (headers.len() as u32) < anchor.height - lowest + 1 {
			let next = lowest + headers.len() as u32;
			let count = (anchor.height - next + 1).min(MAX_HEADERS_PER_REQUEST);
			let batch = bounded(self.tuning.call_timeout, self.source.headers(next, count)).await?;
			if batch.is_empty() {
				return Err(StepError::Source(SourceError::Invalid(format!(
					"no headers from height {} though the resume anchor is at {}",
					next, anchor.height
				))));
			}
			headers.extend(batch.into_iter().take(count as usize));
		}
		check_batch_links(lowest, &headers)?;
		for (i, header) in headers.iter().enumerate() {
			if header.validate_pow(header.target()).is_err() {
				let height = lowest + i as u32;
				return Err(VerifyFailure::Header(HeaderCheck::ProofOfWork { height }).into());
			}
		}
		let top = headers.last().expect("at least the anchor").block_hash();
		if top != anchor.hash {
			return Err(VerifyFailure::Anchor {
				height: anchor.height,
				expected: anchor.hash,
				got: top,
			}
			.into());
		}

		let mut chain = HeaderChain::from_headers(lowest, headers);
		if let Some(observer) = &self.observer {
			let saved = observer.saved_filter_headers();
			chain.hold_saved(anchor.height, &saved);
			self.saved_above_anchor = saved
				.into_iter()
				.filter(|row| row.height > anchor.height)
				.map(|row| (row.height, row))
				.collect();
		}
		*lock_headers(&self.chain) = chain;
		self.filters_through = anchor.height;
		self.queued_through = anchor.height;
		log_info!(
			self.logger,
			"CBF resuming from height {} ({}) through filter source '{}'; holding headers from {}.",
			anchor.height,
			anchor.hash,
			self.source.name(),
			lowest
		);
		Ok(())
	}

	/// Verifies `headers` onto the tip and prunes what is no longer needed.
	fn extend(&mut self, first_height: u32, headers: &[Header]) -> Result<(), StepError> {
		let result = {
			let mut chain = lock_headers(&self.chain);
			extend_verified(&mut chain, self.network, first_height, headers, now_secs())
		};
		self.synced_at = None;
		self.prune();
		result.map_err(StepError::from)
	}

	/// Drops held headers below the last [`SourceTuning::held_headers`], never one whose
	/// filter is still to be processed.
	fn prune(&self) {
		let mut chain = lock_headers(&self.chain);
		if let Some(tip) = chain.tip() {
			let keep_from =
				(tip.height + 1).saturating_sub(self.tuning.held_headers).min(self.filters_through);
			chain.prune_below(keep_from);
		}
	}

	/// Whether the source's next header no longer builds on `ours`. Anything but a clear yes is a
	/// no: the caller then reports the failure it already has.
	async fn next_header_left(&self, ours: BlockId) -> bool {
		match bounded(self.tuning.call_timeout, self.source.headers(ours.height + 1, 1)).await {
			Ok(headers) => headers.first().map_or(false, |h| h.prev_blockhash != ours.hash),
			Err(_) => false,
		}
	}

	/// Reads again from a block whose filter this node now knows it should not have believed: the
	/// filter headers from it up are forgotten and taken again, and what the new filters match is
	/// fetched and handed over with [`ChainOp::ScanBlock`]. **Nothing is disconnected:** these
	/// headers remain the chain of most work, and disconnecting a block un-confirms what is in it,
	/// which closes any channel funded there. Whoever asks for this, however wrongly, can make the
	/// node read blocks and no more. A block no longer on the chain held is a reorg's business.
	fn serve_rewind(&mut self) {
		let top = self.filters_through;
		let mut chain = lock_headers(&self.chain);
		let Some(from) = chain.pending_rewind.take() else {
			return;
		};
		if chain.hash(from.height) != Some(from.hash) {
			return;
		}
		chain.clear_filter_headers_from(from.height);
		drop(chain);
		self.synced_at = None;
		mark_syncing(&self.sync_state_tx);
		if from.height <= top {
			let next = self.rescan.map_or(from.height, |known| known.next.min(from.height));
			self.rescan = Some(Rescan { next, through: top });
		}
	}

	/// Hands over the blocks asked to be read again, while they are still on the chain.
	async fn serve_scans(&mut self) -> Result<(), StepError> {
		let scans = {
			let mut chain = lock_headers(&self.chain);
			let scans = std::mem::take(&mut chain.pending_scans);
			scans
				.into_iter()
				.filter(|(height, block)| chain.hash(*height) == Some(block.block_hash()))
				.collect::<Vec<_>>()
		};
		for (height, block) in scans {
			let permit = Arc::clone(&self.full_block_permits)
				.acquire_owned()
				.await
				.map_err(|_| StepError::PermitsClosed)?;
			let block = Arc::try_unwrap(block).unwrap_or_else(|shared| (*shared).clone());
			self.send(ChainOp::ScanBlock { block: IndexedBlock { height, block }, permit }).await?;
		}
		Ok(())
	}

	/// The next span of blocks being read again; see [`Self::serve_rewind`].
	async fn rescan_batch(&mut self, rescan: Rescan) -> Result<(), StepError> {
		let (lowest, top_held) = {
			let chain = lock_headers(&self.chain);
			(chain.base(), chain.tip().map_or(0, |tip| tip.height))
		};
		let next = rescan.next.max(lowest.max(1));
		let through = rescan.through.min(top_held);
		if next > through {
			self.rescan = None;
			return Ok(());
		}
		let planned = self.verified_span(next, through, false).await?;
		let mut reached = next;
		for (height, header, hash, filter_header, matched) in planned.into_iter().flatten() {
			if matched {
				let (block, permit) = self.fetch_block(height, header, hash).await?;
				self.send(ChainOp::ScanBlock { block, permit }).await?;
			}
			lock_headers(&self.chain).set_filter_header(height, filter_header, self.step_epoch);
			reached = height + 1;
		}
		self.rescan = (reached <= through).then_some(Rescan { next: reached, through });
		if self.rescan.is_none() {
			self.save_filter_headers();
		}
		Ok(())
	}

	/// What is held does not continue what the source says now, and what is held came from another
	/// source. Neither is shown wrong. The lowest block where they differ is where to read again
	/// from: asked of this source, and if it comes to that, everything held.
	async fn held_from_another(&mut self, start: u32) -> Result<(), StepError> {
		let top = start.saturating_sub(1);
		let held = lock_headers(&self.chain).held_chain(top);
		let mut differs = None;
		if let Some(held) = held.filter(|held| !held.blocks.is_empty()) {
			let call_timeout = self.tuning.call_timeout;
			differs = first_difference(&held, &*self.source, call_timeout)
				.await
				.map_err(StepError::Source)?
				.map(|from| from.height);
		}
		let height = differs.unwrap_or_else(|| lock_headers(&self.chain).base().max(1).min(top));
		let asked = {
			let mut chain = lock_headers(&self.chain);
			let hash = chain.hash(height);
			if let Some(hash) = hash {
				chain.request_rewind(BlockId { height, hash });
			}
			hash.is_some()
		};
		if asked {
			log_warn!(
				self.logger,
				"CBF filter source '{}' differs from what this node took from another source, from height {}; reading those blocks again.",
				self.source.name(),
				height
			);
			self.tell(SyncEvent::ReadingAgain);
		}
		Ok(())
	}

	/// Follows the source onto another branch: finds where it forks from ours, verifies the
	/// branch, and — if it has more work — disconnects ours tip-first and holds the branch.
	async fn reorg(&mut self, tip: BlockId, ours: BlockId) -> Result<Progress, StepError> {
		let fork = find_fork(
			&*self.source,
			&self.chain,
			self.network,
			ours.height.min(tip.height),
			self.tuning.call_timeout,
		)
		.await?;

		// The source's branch above the fork, verified onto a copy of ours cut at the fork.
		let (mut branch, old_work) = {
			let chain = lock_headers(&self.chain);
			let mut branch = chain.clone();
			branch.truncate_to(fork);
			(branch, chain.work_above(fork))
		};
		let cap = fork + (ours.height - fork) + self.tuning.header_lookahead;
		let mut next = fork + 1;
		while next <= tip.height.min(cap) && branch.work_above(fork) <= old_work {
			let count = (tip.height.min(cap) - next + 1).min(MAX_HEADERS_PER_REQUEST);
			let batch = bounded(self.tuning.call_timeout, self.source.headers(next, count)).await?;
			if batch.is_empty() {
				return Err(StepError::Source(SourceError::Invalid(format!(
					"no headers from height {} though its tip is at {}",
					next, tip.height
				))));
			}
			let batch = &batch[..batch.len().min(count as usize)];
			extend_verified(&mut branch, self.network, next, batch, now_secs())?;
			next += batch.len() as u32;
		}
		if branch.work_above(fork) <= old_work {
			return Err(StepError::LessWork { fork });
		}

		// Ours above the fork, as far as ops were queued for it, tip first: during a replay
		// that is above the filters the replay has reached.
		let abandoned: Vec<(Header, u32)> = {
			let mut chain = lock_headers(&self.chain);
			let abandoned = ((fork + 1)..=ours.height.min(self.queued_through))
				.rev()
				.filter_map(|height| chain.header(height).map(|header| (header, height)))
				.collect();
			branch.pending_rewind = chain.pending_rewind.take();
			*chain = branch;
			abandoned
		};
		log_warn!(
			self.logger,
			"CBF reorg from filter source '{}': this node's blocks {}..={} replaced by a branch with more work; the fork point is {}.",
			self.source.name(),
			fork + 1,
			ours.height,
			fork
		);
		self.filters_through = self.filters_through.min(fork);
		self.queued_through = self.queued_through.min(fork);
		self.synced_at = None;
		self.rescan = self.rescan.and_then(|rescan| {
			(rescan.next <= fork).then_some(Rescan { next: rescan.next, through: fork })
		});
		if !abandoned.is_empty() {
			self.send(ChainOp::Disconnect { headers: abandoned }).await?;
		}
		Ok(Progress::Advanced)
	}

	/// Verifies the next span of filter headers and filters up to `top`, then queues one op per
	/// block: the full block when its filter matches a watched script, the header otherwise.
	/// Nothing is queued unless the whole span taken verified.
	///
	/// The source may answer a prefix of the span asked — a serving node bounds its replies
	/// by size — and the next batch continues from where it ended. Only an empty answer, or
	/// one longer than asked, is a failure; a prefix that is not one shows up as a filter for
	/// the wrong block or a filter header that does not match.
	async fn filter_batch(&mut self, top: u32) -> Result<(), StepError> {
		let start = self.filters_through + 1;
		let Some(planned) = self.verified_span(start, top, true).await? else {
			return Ok(());
		};
		for (height, header, hash, filter_header, matched) in planned {
			// We are behind by this block until it is applied; see `mark_syncing`.
			mark_syncing(&self.sync_state_tx);
			let saved = self.saved_above_anchor.remove(&height);
			if let Some(saved) = saved.filter(|saved| saved.hash == hash) {
				if saved.filter_header != filter_header && !self.differs_from_saved {
					self.differs_from_saved = true;
					log_warn!(
						self.logger,
						"CBF filter source '{}' differs at height {} from what this node took before it restarted; reading what its filters match there again.",
						self.source.name(),
						height
					);
					self.tell(SyncEvent::ReadingAgain);
				}
				if self.differs_from_saved && matched {
					let (block, permit) = self.fetch_block(height, header, hash).await?;
					self.send(ChainOp::ScanBlock { block, permit }).await?;
				}
			}
			let op = if matched {
				let (block, permit) = self.fetch_block(height, header, hash).await?;
				ChainOp::ConnectFull { block, permit }
			} else {
				ChainOp::ConnectFiltered { header, height }
			};
			self.send(op).await?;
			lock_headers(&self.chain).set_filter_header(height, filter_header, self.step_epoch);
			self.filters_through = height;
			self.queued_through = self.queued_through.max(height);
		}
		self.save_filter_headers();
		self.prune();
		if let Some(observer) = &self.observer {
			observer.checked_through(self.filters_through);
		}
		Ok(())
	}

	/// What a restart must not forget. Written once a batch: at the tip, once a block.
	fn save_filter_headers(&self) {
		if let Some(observer) = &self.observer {
			let rows = lock_headers(&self.chain).to_save(self.filters_through);
			observer.save_filter_headers(&rows);
		}
	}

	/// The next span from `start` up to `top`, its filter headers and filters verified and matched
	/// against the watched scripts, nothing queued. `None` when what is held came from another
	/// source and differs: with `reconcile` a rewind is asked for and the caller comes back after
	/// it, without it the span is taken on the source's word, as the first after a resume is.
	async fn verified_span(
		&mut self, start: u32, top: u32, reconcile: bool,
	) -> Result<Option<Vec<(u32, Header, BlockHash, FilterHeader, bool)>>, StepError> {
		let stop = top.min(start + MAX_FILTERS_PER_REQUEST - 1);
		let asked = (stop - start + 1) as usize;
		let (stop_hash, verified_previous) = {
			let chain = lock_headers(&self.chain);
			(chain.hash(stop).expect("held"), chain.filter_header(start - 1))
		};

		let served =
			bounded(self.tuning.call_timeout, self.source.filter_headers(start, stop_hash)).await?;
		if served.headers.is_empty() || served.headers.len() > asked {
			return Err(VerifyFailure::FilterHeaderCount {
				start,
				expected: asked,
				got: served.headers.len(),
			}
			.into());
		}
		match verified_previous {
			Some(previous) if previous != served.previous => {
				if lock_headers(&self.chain).taken_from(start - 1, self.step_epoch) {
					return Err(VerifyFailure::FilterHeaderChain { height: start }.into());
				}
				if reconcile {
					self.held_from_another(start).await?;
					return Ok(None);
				}
				log_warn!(
					self.logger,
					"CBF filter source '{}' continues from another filter header at height {} than an earlier source gave; taking it, as nothing shows either wrong.",
					self.source.name(),
					start
				);
			},
			Some(_) => {},
			None => log_debug!(
				self.logger,
				"CBF taking the filter header below height {} from source '{}' unverified: the first span after a resume has no verified predecessor.",
				start,
				self.source.name()
			),
		}

		// Ask the filters only for the blocks whose filter headers came.
		let with_headers = served.headers.len();
		let filters_stop = start + with_headers as u32 - 1;
		let filters_stop_hash = if filters_stop == stop {
			stop_hash
		} else {
			lock_headers(&self.chain).hash(filters_stop).expect("held")
		};
		let filters =
			bounded(self.tuning.call_timeout, self.source.filters(start, filters_stop_hash))
				.await?;
		if filters.is_empty() || filters.len() > with_headers {
			return Err(VerifyFailure::FilterCount {
				start,
				expected: with_headers,
				got: filters.len(),
			}
			.into());
		}
		let expected = filters.len();
		if expected < asked {
			log_debug!(
				self.logger,
				"CBF filter source '{}' served {} of {} blocks from height {}; continuing from there.",
				self.source.name(),
				expected,
				asked,
				start
			);
		}

		// Verify and match the whole span before queueing any of it.
		let scripts = self.script_cache.current(&*self.scripts);
		let mut planned: Vec<(u32, Header, BlockHash, FilterHeader, bool)> =
			Vec::with_capacity(expected);
		{
			let chain = lock_headers(&self.chain);
			let mut previous = served.previous;
			for (i, indexed) in filters.iter().enumerate() {
				let height = start + i as u32;
				let (header, hash) = match (chain.header(height), chain.hash(height)) {
					(Some(header), Some(hash)) => (header, hash),
					_ => unreachable!("every height up to the tip is held"),
				};
				if indexed.height != height || indexed.block_hash != hash {
					return Err(VerifyFailure::FilterBlock { height }.into());
				}
				let computed = indexed.filter.filter_header(&previous);
				if computed != served.headers[i] {
					return Err(VerifyFailure::FilterHeader { height }.into());
				}
				previous = computed;
				let matched = !scripts.is_empty()
					&& indexed
						.filter
						.match_any(&hash, scripts.iter().map(|s| s.as_bytes()))
						.map_err(|_| VerifyFailure::FilterDecode { height })?;
				planned.push((height, header, hash, computed, matched));
			}
		}
		Ok(Some(planned))
	}

	/// Fetches a matched block under one of the full-block permits and verifies it against our
	/// header; the permit rides in the op until the applicator drops it.
	async fn fetch_block(
		&self, height: u32, header: Header, hash: BlockHash,
	) -> Result<(IndexedBlock, OwnedSemaphorePermit), StepError> {
		let permit = Arc::clone(&self.full_block_permits)
			.acquire_owned()
			.await
			.map_err(|_| StepError::PermitsClosed)?;
		let block = bounded(self.tuning.call_timeout, self.source.block(hash)).await?;
		verify_block(&block, height, &header)?;
		log_debug!(self.logger, "CBF fetched matched block {} at height {}", hash, height);
		Ok((IndexedBlock { height, block }, permit))
	}
}

/// The verified header chain and a [`FilterSource`] as a [`FeeBlockSource`]: the fee window is
/// read from headers this node checked, and each sampled block is fetched through the source
/// and checked against them, under a free full-block permit.
///
/// The source has none of kyoto's five-second re-request behaviour, so the sampler's cooldown
/// after a slow block only ever costs a little time; it is kept so the sampling rules are the
/// same whichever source runs.
pub(crate) struct SourceFeeSource {
	source: Arc<dyn FilterSource>,
	chain: SharedHeaderChain,
	sync_state_rx: watch::Receiver<CbfSyncState>,
	full_block_permits: Arc<Semaphore>,
	/// Bound on a block fetch, as on every call the sync loop makes.
	call_timeout: Duration,
}

impl SourceFeeSource {
	pub(crate) fn new(
		source: Arc<dyn FilterSource>, chain: SharedHeaderChain,
		sync_state_rx: watch::Receiver<CbfSyncState>, full_block_permits: Arc<Semaphore>,
	) -> Self {
		Self { source, chain, sync_state_rx, full_block_permits, call_timeout: SOURCE_CALL_TIMEOUT }
	}
}

#[async_trait]
impl FeeBlockSource for SourceFeeSource {
	async fn tip_height(&self) -> Result<u32, SampleFailure> {
		lock_headers(&self.chain).tip().map(|tip| tip.height).ok_or(SampleFailure::NodeGone)
	}

	async fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SampleFailure> {
		Ok(lock_headers(&self.chain).hash(height))
	}

	fn can_fetch(&self) -> bool {
		matches!(*self.sync_state_rx.borrow(), CbfSyncState::Active { synced_to_tip: true, .. })
	}

	fn request_block(&self, hash: BlockHash) -> Result<BlockFetch, SampleFailure> {
		let (height, header) = {
			let chain = lock_headers(&self.chain);
			let height = chain.height_of(&hash).ok_or_else(|| {
				SampleFailure::FetchFailed("not in the verified header chain".to_string())
			})?;
			(height, chain.header(height).expect("held"))
		};
		let permit = Arc::clone(&self.full_block_permits)
			.try_acquire_owned()
			.map_err(|_| SampleFailure::NoPermit)?;
		let source = Arc::clone(&self.source);
		let call_timeout = self.call_timeout;
		Ok(Box::pin(async move {
			let _permit = permit;
			let block = bounded(call_timeout, source.block(hash))
				.await
				.map_err(|e| SampleFailure::FetchFailed(e.to_string()))?;
			verify_block(&block, height, &header).map_err(|_| SampleFailure::Mismatch)?;
			Ok((height, block))
		}))
	}
}

#[cfg(test)]
pub(crate) mod test_support {
	//! A deterministic in-memory [`FilterSource`] over regtest-difficulty blocks mined in the
	//! test, with switches to make it fail or lie.
	use super::*;

	use std::collections::HashMap;

	use bitcoin::bip158::BlockFilter;
	use bitcoin::block::Version;
	use bitcoin::{
		absolute, transaction, Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut,
		Witness,
	};

	use crate::chain::cbf::source::{FilterHeaders, IndexedFilter};

	pub(crate) const REGTEST_BITS: u32 = 0x207f_ffff;
	/// A recent, fixed timestamp for the first mined block.
	pub(crate) const BASE_TIME: u32 = 1_700_000_000;

	pub(crate) fn other_script(seed: u8) -> ScriptBuf {
		ScriptBuf::from_bytes(vec![0x51, 0x01, seed])
	}

	pub(crate) fn watched_script() -> ScriptBuf {
		ScriptBuf::from_bytes(vec![0x00, 0x14, 0xab, 0xcd, 0xef])
	}

	fn coinbase(height: u32, pay_to: ScriptBuf, salt: u8) -> Transaction {
		let mut script_sig = height.to_le_bytes().to_vec();
		script_sig.push(salt);
		Transaction {
			version: transaction::Version::ONE,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::from_bytes(script_sig),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey: pay_to }],
		}
	}

	/// Mines a regtest block at `height` on `prev`: the nonce is searched until the proof of
	/// work holds, which at the regtest limit takes a couple of tries.
	pub(crate) fn mine(
		prev: BlockHash, height: u32, time: u32, pay_to: ScriptBuf, salt: u8,
	) -> Block {
		mine_with(prev, height, time, pay_to, salt, Vec::new())
	}

	/// [`mine`], with `txs` after the coinbase.
	pub(crate) fn mine_with(
		prev: BlockHash, height: u32, time: u32, pay_to: ScriptBuf, salt: u8, txs: Vec<Transaction>,
	) -> Block {
		let mut txdata = vec![coinbase(height, pay_to, salt)];
		txdata.extend(txs);
		let mut block = Block {
			header: Header {
				version: Version::TWO,
				prev_blockhash: prev,
				merkle_root: bitcoin::TxMerkleNode::all_zeros(),
				time,
				bits: CompactTarget::from_consensus(REGTEST_BITS),
				nonce: 0,
			},
			txdata,
		};
		block.header.merkle_root = block.compute_merkle_root().expect("one transaction");
		while block.header.validate_pow(block.header.target()).is_err() {
			block.header.nonce += 1;
		}
		block
	}

	pub(crate) fn filter_of(block: &Block) -> BlockFilter {
		BlockFilter::new_script_filter(block, |_| {
			Ok::<ScriptBuf, bitcoin::bip158::Error>(ScriptBuf::new())
		})
		.expect("a coinbase-only block")
	}

	/// What the source lies about.
	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub(crate) enum Lie {
		None,
		/// The served filter header at this height is garbage.
		FilterHeaderAt(u32),
		/// The served `previous` of every filter-header span is garbage.
		FilterHeaderPrevious,
		/// The block served at this height has a transaction the header does not commit to.
		MerkleAt(u32),
		/// Both of the above lies about filter headers: garbage here, and below every span.
		FilterHeaderAndPreviousAt(u32),
		/// From this height on the source serves a chain that holds together, built on a filter
		/// that leaves out the block's outputs.
		OmitOutputsFrom(u32),
		/// The same, on a filter with everything in it and one element more: what cannot be told
		/// apart from an honest filter with the block alone.
		ExtraElementFrom(u32),
		/// The filter of this one block leaves out the block's outputs, and the chain above it is
		/// true filters on the filter headers that follow from that.
		OmitOutputsOnlyAt(u32),
		/// The tip it names is a block of another chain at its own height, and every header from
		/// the given height up is made up: linked, and short of the proof of work they claim.
		ForgedHeadersFrom(u32),
		/// It stops at this height: says so for the tip, and has nothing above.
		WithholdFrom(u32),
	}

	/// The filter `st` serves for the block at `height`, lies included.
	fn served_filter(st: &FakeState, height: usize) -> BlockFilter {
		let block = &st.blocks[height];
		if st.differing_filters.contains(&(height as u32)) {
			return filter_with_one_more(block, &ScriptBuf::from_bytes(vec![0x51, 0x51]));
		}
		if let Some(script) = st.includes.get(&(height as u32)) {
			return filter_with_one_more(block, script);
		}
		match st.lie {
			Lie::OmitOutputsFrom(from) if height == from as usize => BlockFilter::new(&[0x00]),
			Lie::OmitOutputsOnlyAt(at) if height == at as usize => BlockFilter::new(&[0x00]),
			Lie::ExtraElementFrom(from) if height == from as usize => {
				filter_with_one_more(block, &ScriptBuf::from_bytes(vec![0x51, 0x51]))
			},
			_ => filter_of(block),
		}
	}

	fn filter_with_one_more(block: &Block, script: &ScriptBuf) -> BlockFilter {
		let mut scripts: Vec<ScriptBuf> = block
			.txdata
			.iter()
			.flat_map(|tx| tx.output.iter().map(|out| out.script_pubkey.clone()))
			.collect();
		scripts.push(script.clone());
		let mut content = Vec::new();
		let mut writer = bitcoin::bip158::BlockFilterWriter::new(&mut content, block);
		for script in &scripts {
			writer.add_element(script.as_bytes());
		}
		writer.finish().expect("to a vec");
		BlockFilter::new(&content)
	}

	pub(crate) struct FakeState {
		/// The best chain, genesis at index 0.
		pub(crate) blocks: Vec<Block>,
		/// Every block ever mined, stale ones included, so a stale block is still servable.
		pub(crate) all: HashMap<BlockHash, Block>,
		pub(crate) unavailable_calls: u32,
		pub(crate) lie: Lie,
		pub(crate) calls: HashMap<&'static str, usize>,
		/// Most filter headers one answer carries: a prefix of the span beyond.
		pub(crate) filter_headers_cap: Option<usize>,
		/// Most filters one answer carries: a prefix of the span beyond.
		pub(crate) filters_cap: Option<usize>,
		/// Blocks whose filter carries one element more, whatever the lie.
		pub(crate) differing_filters: Vec<u32>,
		/// Blocks whose filter also carries these scripts, as one with a spent script in it does.
		pub(crate) includes: HashMap<u32, ScriptBuf>,
		/// `block` never answers.
		pub(crate) hang_blocks: bool,
		/// `block` answers once this is cleared again.
		pub(crate) hold_blocks: bool,
		/// `filter_headers` is down while this is set; headers still answer.
		pub(crate) hold_filter_headers: bool,
		pub(crate) epoch: u64,
	}

	/// Headers linked from `prev`, the first at `height`, each short of the proof of work it
	/// claims. The regtest target passes every other hash, so the nonce is searched for a miss.
	pub(crate) fn forged_headers(prev: BlockHash, height: u32, count: u32) -> Vec<Header> {
		let mut out: Vec<Header> = Vec::with_capacity(count as usize);
		let mut below = prev;
		for i in 0..count {
			let mut header = Header {
				version: Version::TWO,
				prev_blockhash: below,
				merkle_root: bitcoin::TxMerkleNode::all_zeros(),
				time: BASE_TIME + (height + i) * 600,
				bits: CompactTarget::from_consensus(REGTEST_BITS),
				nonce: 7,
			};
			while header.validate_pow(header.target()).is_ok() {
				header.nonce += 1;
			}
			below = header.block_hash();
			out.push(header);
		}
		out
	}

	pub(crate) struct FakeSource {
		pub(crate) state: Mutex<FakeState>,
	}

	impl FakeSource {
		/// A chain of `len` blocks (heights `0..len`); the block at each height in `matched`
		/// pays the watched script.
		pub(crate) fn new(len: u32, matched: &[u32]) -> Self {
			let source = Self {
				state: Mutex::new(FakeState {
					blocks: Vec::new(),
					all: HashMap::new(),
					unavailable_calls: 0,
					lie: Lie::None,
					calls: HashMap::new(),
					filter_headers_cap: None,
					filters_cap: None,
					differing_filters: Vec::new(),
					includes: HashMap::new(),
					hang_blocks: false,
					hold_blocks: false,
					hold_filter_headers: false,
					epoch: 0,
				}),
			};
			source.mine(len, matched, 0);
			source
		}

		pub(crate) fn hold_filter_headers(&self, hold: bool) {
			self.st().hold_filter_headers = hold;
		}

		fn st(&self) -> MutexGuard<'_, FakeState> {
			self.state.lock().unwrap()
		}

		/// Mines `count` more blocks on the best chain.
		pub(crate) fn mine(&self, count: u32, matched: &[u32], salt: u8) {
			let mut st = self.st();
			for _ in 0..count {
				let height = st.blocks.len() as u32;
				let prev = st.blocks.last().map_or(BlockHash::all_zeros(), |b| b.block_hash());
				let pay_to = if matched.contains(&height) {
					watched_script()
				} else {
					other_script(height as u8)
				};
				let block = mine(prev, height, BASE_TIME + height * 600, pay_to, salt);
				st.all.insert(block.block_hash(), block.clone());
				st.blocks.push(block);
			}
		}

		/// Mines one block on the best chain, timestamped `time`.
		pub(crate) fn mine_at(&self, time: u32) {
			let mut st = self.st();
			let height = st.blocks.len() as u32;
			let prev = st.blocks.last().map_or(BlockHash::all_zeros(), |b| b.block_hash());
			let block = mine(prev, height, time, other_script(height as u8), 0);
			st.all.insert(block.block_hash(), block.clone());
			st.blocks.push(block);
		}

		/// Replaces the top `depth` blocks with `new_len` others.
		pub(crate) fn reorg(&self, depth: u32, new_len: u32) {
			{
				let mut st = self.st();
				let keep = st.blocks.len() - depth as usize;
				st.blocks.truncate(keep);
			}
			self.mine(new_len, &[], 0xee);
		}

		/// Puts a block on the best chain as it is, without mining or checking it.
		pub(crate) fn push_raw(&self, block: Block) {
			let mut st = self.st();
			st.all.insert(block.block_hash(), block.clone());
			st.blocks.push(block);
		}

		pub(crate) fn block_at(&self, height: u32) -> Block {
			self.st().blocks[height as usize].clone()
		}

		/// What an honest source says the filter header at `height` is.
		pub(crate) fn true_filter_header(&self, height: u32) -> Option<FilterHeader> {
			let st = self.st();
			let mut previous = FilterHeader::all_zeros();
			for block in st.blocks.iter().take(height as usize + 1) {
				previous = filter_of(block).filter_header(&previous);
			}
			Some(previous)
		}

		pub(crate) fn tip_id(&self) -> BlockId {
			let st = self.st();
			let last = st.blocks.len() - 1;
			BlockId { height: last as u32, hash: st.blocks[last].block_hash() }
		}

		pub(crate) fn set_lie(&self, lie: Lie) {
			self.st().lie = lie;
		}

		/// What each of `heights` serves as a filter has one element more.
		/// The filter at `height` also holds `script`, whatever the block shows.
		pub(crate) fn set_includes_at(&self, height: u32, script: ScriptBuf) {
			self.st().includes.insert(height, script);
		}

		/// The filters at `heights` also hold `script`, whatever their blocks show.
		pub(crate) fn set_includes_all(&self, heights: &[u32], script: ScriptBuf) {
			for height in heights {
				self.set_includes_at(*height, script.clone());
			}
		}

		pub(crate) fn set_differing_filters(&self, heights: &[u32]) {
			self.st().differing_filters = heights.to_vec();
		}

		/// As a session does on a move: what it says from here on is another Pro's.
		pub(crate) fn next_epoch(&self) {
			self.st().epoch += 1;
		}

		/// Answers at most `filter_headers` filter headers and `filters` filters at a time.
		pub(crate) fn cap_replies(&self, filter_headers: Option<usize>, filters: Option<usize>) {
			let mut st = self.st();
			st.filter_headers_cap = filter_headers;
			st.filters_cap = filters;
		}

		pub(crate) fn fail_next(&self, calls: u32) {
			self.st().unavailable_calls = calls;
		}

		pub(crate) fn calls(&self, method: &'static str) -> usize {
			self.st().calls.get(method).copied().unwrap_or(0)
		}

		fn enter(&self, method: &'static str) -> Result<MutexGuard<'_, FakeState>, SourceError> {
			let mut st = self.st();
			*st.calls.entry(method).or_default() += 1;
			if st.unavailable_calls > 0 {
				st.unavailable_calls -= 1;
				return Err(SourceError::unavailable("the fake is down"));
			}
			Ok(st)
		}

		fn span(
			st: &FakeState, start: u32, stop: BlockHash,
		) -> Result<(usize, usize), SourceError> {
			let stop = st
				.blocks
				.iter()
				.position(|b| b.block_hash() == stop)
				.ok_or_else(|| SourceError::NotFound("stop hash".into()))?;
			Ok((start as usize, stop))
		}

		fn filter_header_chain(st: &FakeState, through: usize) -> Vec<FilterHeader> {
			let mut out: Vec<FilterHeader> = Vec::with_capacity(through + 1);
			for height in 0..=through {
				let previous = out.last().copied().unwrap_or_else(FilterHeader::all_zeros);
				out.push(served_filter(st, height).filter_header(&previous));
			}
			out
		}
	}

	#[async_trait]
	impl FilterSource for FakeSource {
		fn name(&self) -> &'static str {
			"fake"
		}

		fn epoch(&self) -> u64 {
			self.st().epoch
		}

		async fn tip(&self) -> Result<BlockId, SourceError> {
			let st = self.enter("tip")?;
			let last = st.blocks.len() - 1;
			match st.lie {
				Lie::ForgedHeadersFrom(from) => {
					let below = st.blocks[from as usize - 1].block_hash();
					let forged = forged_headers(below, from, last as u32 - from + 1);
					let hash = forged.last().expect("at least one").block_hash();
					Ok(BlockId { height: last as u32, hash })
				},
				Lie::WithholdFrom(from) => {
					let top = (from as usize - 1).min(last);
					Ok(BlockId { height: top as u32, hash: st.blocks[top].block_hash() })
				},
				_ => Ok(BlockId { height: last as u32, hash: st.blocks[last].block_hash() }),
			}
		}

		async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
			let st = self.enter("headers")?;
			let from = from_height as usize;
			if from >= st.blocks.len() {
				return Err(SourceError::NotFound("above tip".into()));
			}
			match st.lie {
				Lie::ForgedHeadersFrom(forged_from) => {
					let forged_from_at = forged_from as usize;
					let below = st.blocks[forged_from_at - 1].block_hash();
					let forged = forged_headers(
						below,
						forged_from,
						(st.blocks.len() - forged_from_at) as u32,
					);
					let chain: Vec<Header> = st.blocks[..forged_from_at]
						.iter()
						.map(|b| b.header)
						.chain(forged)
						.collect();
					return Ok(chain[from..].iter().take(count as usize).copied().collect());
				},
				Lie::WithholdFrom(withheld) if from >= withheld as usize => {
					return Err(SourceError::NotFound("above tip".into()));
				},
				_ => {},
			}
			Ok(st.blocks[from..].iter().take(count as usize).map(|b| b.header).collect())
		}

		async fn filter_headers(
			&self, start_height: u32, stop_hash: BlockHash,
		) -> Result<FilterHeaders, SourceError> {
			let st = self.enter("filter_headers")?;
			if st.hold_filter_headers {
				return Err(SourceError::unavailable("filter headers are held"));
			}
			let (start, stop) = Self::span(&st, start_height, stop_hash)?;
			let chain = Self::filter_header_chain(&st, stop);
			let mut previous =
				if start == 0 { FilterHeader::all_zeros() } else { chain[start - 1] };
			let mut headers = chain[start..=stop].to_vec();
			match st.lie {
				Lie::FilterHeaderAt(height) if (start..=stop).contains(&(height as usize)) => {
					headers[height as usize - start] = FilterHeader::from_byte_array([0x42; 32]);
				},
				Lie::FilterHeaderPrevious => previous = FilterHeader::from_byte_array([0x24; 32]),
				Lie::FilterHeaderAndPreviousAt(height) => {
					previous = FilterHeader::from_byte_array([0x24; 32]);
					if (start..=stop).contains(&(height as usize)) {
						headers[height as usize - start] = FilterHeader::from_byte_array([0x42; 32]);
					}
				},
				_ => {},
			}
			if let Some(cap) = st.filter_headers_cap {
				headers.truncate(cap);
			}
			Ok(FilterHeaders { previous, headers })
		}

		async fn filters(
			&self, start_height: u32, stop_hash: BlockHash,
		) -> Result<Vec<IndexedFilter>, SourceError> {
			let st = self.enter("filters")?;
			let (start, stop) = Self::span(&st, start_height, stop_hash)?;
			let cap = st.filters_cap.unwrap_or(usize::MAX);
			Ok((start..=stop)
				.take(cap)
				.map(|h| IndexedFilter {
					height: h as u32,
					block_hash: st.blocks[h].block_hash(),
					filter: served_filter(&st, h),
				})
				.collect())
		}

		async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
			let hang = self.enter("block")?.hang_blocks;
			if hang {
				std::future::pending::<()>().await;
			}
			while self.st().hold_blocks {
				tokio::time::sleep(Duration::from_millis(1)).await;
			}
			let st = self.st();
			let mut block =
				st.all.get(&hash).cloned().ok_or_else(|| SourceError::NotFound("block".into()))?;
			if let Lie::MerkleAt(height) = st.lie {
				if st.blocks.get(height as usize).map(|b| b.block_hash()) == Some(hash) {
					block.txdata[0].output[0].value = Amount::from_sat(21_000_000);
				}
			}
			Ok(block)
		}
	}

	/// A fixed script set for the loop to match against.
	pub(crate) struct FixedScripts(pub(crate) Vec<ScriptBuf>);

	impl WatchedScripts for FixedScripts {
		fn counts(&self) -> (usize, usize) {
			(self.0.len(), 0)
		}
		fn scripts(&self) -> Vec<ScriptBuf> {
			self.0.clone()
		}
	}

	/// Short waits all round, so a test sees retries and failures in milliseconds.
	pub(crate) fn fast_tuning() -> SourceTuning {
		SourceTuning {
			poll_interval: Duration::from_millis(20),
			call_timeout: Duration::from_secs(5),
			initial_backoff: Duration::from_millis(5),
			max_backoff: Duration::from_millis(20),
			wait_report_interval: Duration::from_secs(60),
			max_invalid_strikes: MAX_INVALID_STRIKES,
			fallback_after: None,
			header_lookahead: HEADER_LOOKAHEAD,
			held_headers: HELD_HEADERS,
			stale_tip_after: None,
			stale_report_interval: Duration::from_secs(60),
			restart_backoff: None,
			max_replay_depth: MAX_REPLAY_DEPTH,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::test_support::*;
	use super::*;

	use std::sync::RwLock;

	use bitcoin::CompactTarget;

	use crate::chain::cbf::applicator::CBF_FULL_BLOCK_PERMITS;
	use crate::chain::cbf::bundle_source::test_support::ServerTransport;
	use crate::chain::cbf::bundle_source::{BundleFilterSource, BundleTuning};
	use crate::chain::provider::{BundleTransport, ChainProviderError};
	use crate::NodeMetrics;

	/// Any single wait in these tests; a test that would otherwise hang fails instead.
	const WAIT: Duration = Duration::from_secs(20);

	/// What an op did, without its payload.
	#[derive(Debug, Clone, PartialEq, Eq)]
	enum Op {
		Full(u32),
		Filtered(u32),
		Disconnect(Vec<u32>),
		Synced(u32),
		TipConfirmed(u32),
		Rescan(u32),
		Scan(u32),
	}

	struct Harness {
		source: Arc<FakeSource>,
		chain: SharedHeaderChain,
		ops_rx: mpsc::Receiver<ChainOp>,
		/// What the engine holds for a listener that joins: asks the loop for a replay.
		replay_tx: ReplaySender,
		sync_state_tx: watch::Sender<CbfSyncState>,
		stop_tx: watch::Sender<bool>,
		permits: Arc<Semaphore>,
		task: tokio::task::JoinHandle<SourceSyncEnd>,
		/// Disconnected headers, by height, as the last `Disconnect` carried them.
		last_disconnect: Vec<(Header, u32)>,
	}

	fn start(source: FakeSource, anchor_height: u32, tuning: SourceTuning) -> Harness {
		let source = Arc::new(source);
		let filter_source = Arc::clone(&source) as Arc<dyn FilterSource>;
		let chain = new_shared_header_chain();
		start_over(source, filter_source, chain, Arc::new(Notify::new()), anchor_height, tuning)
	}

	/// What a loop told its observer.
	#[derive(Default)]
	struct Heard {
		events: Mutex<Vec<SyncEvent>>,
	}

	impl SyncObserver for Heard {
		fn sync_event(&self, _epoch: u64, event: SyncEvent) {
			self.events.lock().unwrap().push(event);
		}
	}

	impl Heard {
		async fn wait_for(&self, matching: impl Fn(&SyncEvent) -> bool) {
			let looked = async {
				while !self.events.lock().unwrap().iter().any(&matching) {
					tokio::time::sleep(Duration::from_millis(5)).await;
				}
			};
			tokio::time::timeout(WAIT, looked).await.expect("told in time");
		}

		fn evidence(&self) -> Vec<LieKind> {
			let events = self.events.lock().unwrap();
			events
				.iter()
				.filter_map(|event| match event {
					SyncEvent::Evidence { kind, .. } => Some(*kind),
					_ => None,
				})
				.collect()
		}
	}

	fn start_observed(
		source: Arc<FakeSource>, anchor_height: u32, tuning: SourceTuning, observer: Arc<Heard>,
	) -> Harness {
		start_observed_woken(source, anchor_height, tuning, observer, Arc::new(Notify::new()))
	}

	fn start_observed_woken(
		source: Arc<FakeSource>, anchor_height: u32, tuning: SourceTuning, observer: Arc<Heard>,
		wake: Arc<Notify>,
	) -> Harness {
		let filter_source = Arc::clone(&source) as Arc<dyn FilterSource>;
		start_watched(
			source,
			filter_source,
			new_shared_header_chain(),
			wake,
			anchor_height,
			tuning,
			Some(observer as Arc<dyn SyncObserver>),
		)
	}

	/// The loop over `filter_source` — which reads `source`'s chain, a wrapper of it say —
	/// verifying into `chain` and woken by `wake`.
	fn start_over(
		source: Arc<FakeSource>, filter_source: Arc<dyn FilterSource>, chain: SharedHeaderChain,
		wake: Arc<Notify>, anchor_height: u32, tuning: SourceTuning,
	) -> Harness {
		start_watched(source, filter_source, chain, wake, anchor_height, tuning, None)
	}

	#[allow(clippy::too_many_arguments)]
	fn start_watched(
		source: Arc<FakeSource>, filter_source: Arc<dyn FilterSource>, chain: SharedHeaderChain,
		wake: Arc<Notify>, anchor_height: u32, tuning: SourceTuning,
		observer: Option<Arc<dyn SyncObserver>>,
	) -> Harness {
		let anchor =
			BlockId { height: anchor_height, hash: source.block_at(anchor_height).block_hash() };
		let (ops_tx, ops_rx) = mpsc::channel(1024);
		let (sync_state_tx, _) = watch::channel(CbfSyncState::Active {
			applied_tip: Some(anchor_height),
			synced_to_tip: false,
		});
		let (stop_tx, stop_rx) = watch::channel(false);
		let (replay_tx, replay_rx) = replay_channel();
		let permits = Arc::new(Semaphore::new(CBF_FULL_BLOCK_PERMITS));
		let sync = SourceSync::new(
			filter_source,
			Network::Regtest,
			anchor,
			Arc::clone(&chain),
			Arc::new(FixedScripts(vec![watched_script()])),
			ops_tx,
			replay_rx,
			wake,
			sync_state_tx.clone(),
			Arc::clone(&permits),
			stop_rx,
			tuning,
			Arc::new(Logger::new_log_facade()),
		);
		let sync = match observer {
			Some(observer) => sync.observed_by(observer as Arc<dyn SyncObserver>),
			None => sync,
		};
		let task = tokio::spawn(sync.run());
		Harness {
			source,
			chain,
			ops_rx,
			replay_tx,
			sync_state_tx,
			stop_tx,
			permits,
			task,
			last_disconnect: Vec::new(),
		}
	}

	impl Harness {
		/// Asks for a replay from the source's block at `height`, as the engine does for a
		/// listener whose tip it is.
		fn ask_replay(&self, height: u32) {
			let hash = self.source.block_at(height).block_hash();
			self.replay_tx.send(BlockId { height, hash }).unwrap();
		}

		/// The next op that moves the chain or ends a catch-up. A `TipConfirmed` moves nothing
		/// and comes on every idle poll, so it is skipped here; [`Self::next_any_op`] sees it.
		async fn next_op(&mut self) -> Op {
			loop {
				let op = self.next_any_op().await;
				if !matches!(op, Op::TipConfirmed(_)) {
					return op;
				}
			}
		}

		async fn next_any_op(&mut self) -> Op {
			let op = tokio::time::timeout(WAIT, self.ops_rx.recv())
				.await
				.expect("an op in time")
				.expect("the loop is running");
			match op {
				ChainOp::ConnectFull { block, permit: _permit } => {
					assert_eq!(
						block.block.block_hash(),
						self.source.block_at(block.height).block_hash(),
						"the full block is the source's at that height"
					);
					Op::Full(block.height)
				},
				ChainOp::ScanBlock { block, permit: _permit } => Op::Scan(block.height),
				ChainOp::ConnectFiltered { header, height } => {
					// The chain may have been pruned or moved on since; the source's best chain
					// only changes when a test says so.
					assert_eq!(header.block_hash(), self.source.block_at(height).block_hash());
					Op::Filtered(height)
				},
				ChainOp::Disconnect { headers } => {
					let heights = headers.iter().map(|(_, h)| *h).collect();
					self.last_disconnect = headers;
					Op::Disconnect(heights)
				},
				ChainOp::Synced { tip_height } => Op::Synced(tip_height),
				ChainOp::Rescan { from_height } => Op::Rescan(from_height),
				ChainOp::TipConfirmed { tip_height } => Op::TipConfirmed(tip_height),
			}
		}

		/// Ops until (and including) the next `Synced`.
		async fn ops_until_synced(&mut self) -> Vec<Op> {
			let mut ops = Vec::new();
			loop {
				let op = self.next_op().await;
				let done = matches!(op, Op::Synced(_));
				ops.push(op);
				if done {
					return ops;
				}
			}
		}

		/// The loop's end, bounded.
		async fn end(self) -> SourceSyncEnd {
			tokio::time::timeout(WAIT, self.task).await.expect("the loop ended in time").unwrap()
		}

		async fn stop(self) -> SourceSyncEnd {
			self.stop_tx.send_replace(true);
			self.end().await
		}

		/// No op that moves the chain arrives for a while; `TipConfirmed`s may.
		async fn assert_quiet(&mut self) {
			let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
			while let Ok(op) = tokio::time::timeout_at(deadline, self.ops_rx.recv()).await {
				assert!(
					matches!(op, Some(ChainOp::TipConfirmed { .. })),
					"no op expected, got {:?}",
					op
				);
			}
		}

		/// Makes every source call fail from now on, and returns once a tip check has failed:
		/// every op from a step that began before is queued by then, and is drained here.
		async fn take_the_source_down(&mut self) {
			let tips = self.source.calls("tip");
			self.source.fail_next(u32::MAX);
			tokio::time::timeout(WAIT, async {
				while self.source.calls("tip") <= tips {
					tokio::time::sleep(Duration::from_millis(1)).await;
				}
			})
			.await
			.expect("a tip check in time");
			while self.ops_rx.try_recv().is_ok() {}
		}
	}

	fn filtered(range: std::ops::RangeInclusive<u32>) -> Vec<Op> {
		range.map(Op::Filtered).collect()
	}

	#[tokio::test]
	async fn syncs_to_the_tip_fetching_only_matched_blocks_then_follows_new_blocks() {
		let mut h = start(FakeSource::new(30, &[20]), 10, fast_tuning());

		let mut expected = filtered(11..=19);
		expected.push(Op::Full(20));
		expected.extend(filtered(21..=29));
		expected.push(Op::Synced(29));
		assert_eq!(h.ops_until_synced().await, expected);
		assert_eq!(h.source.calls("block"), 1, "only the matched block is downloaded");
		assert_eq!(
			h.permits.available_permits(),
			CBF_FULL_BLOCK_PERMITS,
			"its permit was released"
		);
		h.assert_quiet().await;

		// New blocks on the source: picked up on the next tip poll.
		h.source.mine(2, &[31], 0);
		assert_eq!(
			h.ops_until_synced().await,
			vec![Op::Filtered(30), Op::Full(31), Op::Synced(31)]
		);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// The ops of a replay from `from`: the rescan, then every block above it to 29 again (20
	/// matched, when `with_match`), ending in `Synced(29)`.
	fn replay_ops(from: u32, with_match: bool) -> Vec<Op> {
		let mut ops = vec![Op::Rescan(from)];
		ops.extend((from + 1..=29).map(|h| {
			if with_match && h == 20 {
				Op::Full(h)
			} else {
				Op::Filtered(h)
			}
		}));
		ops.push(Op::Synced(29));
		ops
	}

	#[tokio::test]
	async fn a_replay_request_queues_a_rescan_then_every_block_above_it_again() {
		let mut h = start(FakeSource::new(30, &[20]), 10, fast_tuning());
		h.ops_until_synced().await;
		assert_eq!(h.source.calls("block"), 1);

		// A listener joined at 15: the rescan goes first, then the filters after 15 come again,
		// verified and matched anew, and the matched block is fetched again.
		h.ask_replay(15);
		assert_eq!(h.ops_until_synced().await, replay_ops(15, true));
		assert_eq!(h.source.calls("block"), 2, "the matched block was fetched again");
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { .. }), "no strike");

		// From the tip on, the loop follows the chain as before.
		h.source.mine(1, &[], 0);
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_replay_request_cuts_the_wait_for_the_next_tip_poll_short() {
		let tuning = SourceTuning { poll_interval: Duration::from_secs(3600), ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		h.ops_until_synced().await;

		// Caught up, the loop waits an hour for its next tip poll; a request does not.
		h.ask_replay(27);
		assert_eq!(
			h.ops_until_synced().await,
			vec![Op::Rescan(27), Op::Filtered(28), Op::Filtered(29), Op::Synced(29)]
		);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// The loop over per-block bundles: `node` is the inner source the raw routes answer from,
	/// `pro` an identical chain the bundles come from. Mine on both to move the chain.
	fn start_bundled(
		matched: &[u32], tuning: SourceTuning,
	) -> (Harness, Arc<BundleFilterSource>, Arc<ServerTransport>, Arc<FakeSource>) {
		start_bundled_tuned(matched, tuning, BundleTuning::default())
	}

	fn start_bundled_tuned(
		matched: &[u32], tuning: SourceTuning, bundle_tuning: BundleTuning,
	) -> (Harness, Arc<BundleFilterSource>, Arc<ServerTransport>, Arc<FakeSource>) {
		let node = Arc::new(FakeSource::new(30, matched));
		let pro = Arc::new(FakeSource::new(30, matched));
		let transport = Arc::new(ServerTransport::new(Arc::clone(&pro) as Arc<dyn FilterSource>));
		let chain = new_shared_header_chain();
		let wake = Arc::new(Notify::new());
		let bundles = Arc::new(BundleFilterSource::new(
			Arc::clone(&node) as Arc<dyn FilterSource>,
			Arc::clone(&transport) as Arc<dyn BundleTransport>,
			Arc::clone(&chain),
			Arc::clone(&wake),
			bundle_tuning,
			Arc::new(Logger::new_log_facade()),
		));
		let h = start_over(
			node,
			Arc::clone(&bundles) as Arc<dyn FilterSource>,
			chain,
			wake,
			10,
			tuning,
		);
		(h, bundles, transport, pro)
	}

	use crate::chain::session::PushSink;

	/// Catches up with the first pull, then starts being pushed to, as the session would.
	async fn start_pushed(matched: &[u32], tuning: SourceTuning) -> (Harness, Arc<BundleFilterSource>, Arc<ServerTransport>, Arc<FakeSource>) {
		let (mut h, bundles, transport, pro) = start_bundled(matched, tuning);
		h.ops_until_synced().await;
		bundles.note_tip(pro.tip_id());
		bundles.set_push_trusted(true);
		(h, bundles, transport, pro)
	}

	#[tokio::test]
	async fn a_pushed_loop_follows_pushes_asking_no_tip_and_a_push_wakes_it() {
		// A poll that would never come on its own: only the wake can explain the blocks.
		let tuning = SourceTuning { poll_interval: Duration::from_secs(3600), ..fast_tuning() };
		let (mut h, bundles, transport, pro) = start_pushed(&[], tuning).await;
		h.source.mine(1, &[], 0);
		pro.mine(1, &[], 0);
		let polled = |source: &FakeSource| ["tip", "headers", "filter_headers", "filters"].map(|m| source.calls(m));
		let before = polled(&h.source);
		let since_before = transport.calls("since");

		bundles.ingest(&transport.push(30..=30).await).unwrap();
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(polled(&h.source), before, "nothing went to the raw routes, the tip included");
		assert_eq!(transport.calls("since"), since_before, "nor to a pull");
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn on_push_the_idle_loop_asks_no_tip_on_the_wire_however_often_it_looks() {
		let (h, bundles, _transport, _pro) = start_pushed(&[], fast_tuning()).await;
		let tips = h.source.calls("tip");
		tokio::time::sleep(Duration::from_millis(100)).await;
		assert_eq!(h.source.calls("tip"), tips, "fast_tuning polls many times in this wait");
		// When the session stops trusting pushes, the poll is back at once.
		bundles.set_push_trusted(false);
		tokio::time::sleep(Duration::from_millis(100)).await;
		assert!(h.source.calls("tip") > tips);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_push_that_skips_a_block_is_filled_by_one_pull() {
		let tuning = SourceTuning { poll_interval: Duration::from_secs(3600), ..fast_tuning() };
		let (mut h, bundles, transport, pro) = start_pushed(&[], tuning).await;
		h.source.mine(2, &[], 0);
		pro.mine(2, &[], 0);
		let since_before = transport.calls("since");
		bundles.ingest(&transport.push(31..=31).await).unwrap();
		assert_eq!(
			h.ops_until_synced().await,
			vec![Op::Filtered(30), Op::Filtered(31), Op::Synced(31)]
		);
		assert_eq!(transport.calls("since"), since_before + 1, "the gap's");
		assert_eq!(h.source.calls("filters"), 0);
		assert_eq!(h.source.calls("filter_headers"), 0);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_push_on_another_branch_clears_what_is_held_and_the_loop_follows_the_reorg() {
		let tuning = SourceTuning { poll_interval: Duration::from_secs(3600), ..fast_tuning() };
		let (mut h, bundles, transport, pro) = start_pushed(&[], tuning).await;
		h.source.reorg(2, 3);
		pro.reorg(2, 3);
		bundles.ingest(&transport.push(30..=30).await).unwrap();
		assert_eq!(
			h.ops_until_synced().await,
			vec![
				Op::Disconnect(vec![29, 28]),
				Op::Filtered(28),
				Op::Filtered(29),
				Op::Filtered(30),
				Op::Synced(30)
			]
		);
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_new_provider_cuts_the_retry_backoff_short() {
		// A backoff far longer than the test: only the wake can end it.
		let tuning = SourceTuning {
			initial_backoff: Duration::from_secs(3600),
			max_backoff: Duration::from_secs(3600),
			..fast_tuning()
		};
		let (mut h, bundles, _transport, _pro) = start_bundled(&[], tuning);
		h.source.fail_next(1);
		tokio::time::sleep(Duration::from_millis(50)).await;
		bundles.target_changed();
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(29)));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// The raw reads of the data a bundle carries.
	fn raw_bundle_reads(source: &FakeSource) -> [usize; 2] {
		["filter_headers", "filters"].map(|m| source.calls(m))
	}

	#[tokio::test]
	async fn a_new_block_arrives_through_one_since_and_no_raw_read_of_its_data() {
		let (mut h, _bundles, transport, pro) = start_bundled(&[25], fast_tuning());
		let mut expected: Vec<Op> = (11..=29)
			.map(|height| if height == 25 { Op::Full(height) } else { Op::Filtered(height) })
			.collect();
		expected.push(Op::Synced(29));
		assert_eq!(h.ops_until_synced().await, expected);
		assert_eq!(transport.calls("since"), 1, "one reply carried the whole catch-up");
		let headers_at_resume = h.source.calls("headers");
		assert_eq!(raw_bundle_reads(&h.source), [0, 0]);
		assert_eq!(h.source.calls("block"), 1, "a matched block is fetched as before");
		assert!(h.source.calls("tip") >= 1, "the tip is polled");

		for (i, height) in [30u32, 31, 32].into_iter().enumerate() {
			h.source.mine(1, &[], 0);
			pro.mine(1, &[], 0);
			assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(height), Op::Synced(height)]);
			assert_eq!(transport.calls("since"), 2 + i, "one per new block");
		}
		assert_eq!(raw_bundle_reads(&h.source), [0, 0]);
		assert_eq!(h.source.calls("headers"), headers_at_resume);
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// A long absence: more blocks than one `since` may carry. Several pulls, each continuing
	/// where the last ended, and still no raw read.
	#[tokio::test]
	async fn a_node_far_behind_catches_up_over_several_pulls() {
		let (mut h, _bundles, transport, pro) = start_bundled(&[], fast_tuning());
		h.ops_until_synced().await;
		h.source.mine(400, &[], 0);
		pro.mine(400, &[], 0);
		let ops = h.ops_until_synced().await;
		assert_eq!(ops.last(), Some(&Op::Synced(429)));
		assert_eq!(ops.len(), 401);
		assert_eq!(transport.calls("since"), 1 + 3, "400 blocks at 144 a reply, after the first");
		assert_eq!(raw_bundle_reads(&h.source), [0, 0]);
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// A reorg: the tip moved off the verified chain. The refused pull leaves no backoff, the raw
	/// routes find the fork, and the next pull continues from it.
	#[tokio::test]
	async fn a_reorg_is_followed_through_the_raw_routes_then_bundles_resume() {
		let (mut h, _bundles, transport, pro) = start_bundled(&[], fast_tuning());
		h.ops_until_synced().await;
		let raw_headers_before = h.source.calls("headers");
		let pulls_before = transport.calls("since");

		h.source.reorg(2, 3);
		pro.reorg(2, 3);
		assert_eq!(
			h.ops_until_synced().await,
			vec![
				Op::Disconnect(vec![29, 28]),
				Op::Filtered(28),
				Op::Filtered(29),
				Op::Filtered(30),
				Op::Synced(30)
			]
		);
		assert!(h.source.calls("headers") > raw_headers_before, "the fork search reads raw");
		assert!(transport.calls("since") > pulls_before, "the new branch came as bundles");

		h.source.mine(1, &[], 0);
		pro.mine(1, &[], 0);
		let pulls = transport.calls("since");
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(31), Op::Synced(31)]);
		assert_eq!(transport.calls("since"), pulls + 1);
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// Waits until the loop holds headers through `height` and has been refused the filter
	/// headers above what it verified: its filters are behind its headers.
	async fn filters_behind_at(h: &Harness, height: u32) {
		let refused = h.source.calls("filter_headers");
		tokio::time::timeout(WAIT, async {
			while lock_headers(&h.chain).tip().map(|t| t.height) != Some(height)
				|| h.source.calls("filter_headers") <= refused
			{
				tokio::time::sleep(Duration::from_millis(5)).await;
			}
		})
		.await
		.expect("the headers moved on while the filters stayed behind");
	}

	/// The stop hash of the next filter batch left the best chain while the filters were behind.
	/// Every filter call now fails, so a loop that only reads headers once the filters caught up
	/// never sees why. Raw routes under a source whose headers come with their filters.
	#[tokio::test]
	async fn a_reorg_while_the_filters_are_behind_recovers_on_the_raw_routes() {
		let (mut h, _bundles, transport, pro) = start_bundled(&[], fast_tuning());
		transport
			.refuse_with(Some(ChainProviderError::Refused("unsupported: unknown route".into())));
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(29)));

		h.source.hold_filter_headers(true);
		h.source.mine(2, &[], 0);
		pro.mine(2, &[], 0);
		filters_behind_at(&h, 31).await;

		h.source.reorg(2, 4);
		pro.reorg(2, 4);
		h.source.hold_filter_headers(false);
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(33)));
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// The same with `since` answering again by the time of the reorg: the look for the next
	/// header goes through a pull the Pro refuses, the raw routes find the fork, bundles resume.
	#[tokio::test]
	async fn a_reorg_while_the_filters_are_behind_recovers_when_bundles_answer_again() {
		let bundle_tuning =
			BundleTuning { retry_after: Duration::from_millis(10), ..BundleTuning::default() };
		let (mut h, _bundles, transport, pro) =
			start_bundled_tuned(&[], fast_tuning(), bundle_tuning);
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(29)));

		transport.refuse_with(Some(ChainProviderError::Refused("failed: down".into())));
		h.source.hold_filter_headers(true);
		h.source.mine(2, &[], 0);
		pro.mine(2, &[], 0);
		filters_behind_at(&h, 31).await;

		h.source.reorg(2, 4);
		pro.reorg(2, 4);
		h.source.hold_filter_headers(false);
		transport.refuse_with(None);
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(33)));
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));

		h.source.mine(1, &[], 0);
		pro.mine(1, &[], 0);
		let pulls = transport.calls("since");
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(34), Op::Synced(34)]);
		assert_eq!(transport.calls("since"), pulls + 1, "the next block came as a bundle");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// No bundles at all: a full header lookahead leaves no room to read a header either.
	#[tokio::test]
	async fn a_reorg_with_the_header_lookahead_full_recovers() {
		let tuning = SourceTuning { header_lookahead: 2, ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(29)));

		h.source.hold_filter_headers(true);
		h.source.mine(2, &[], 0);
		filters_behind_at(&h, 31).await;

		h.source.reorg(2, 4);
		h.source.hold_filter_headers(false);
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(33)));
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// A failed filter batch with the tip still on our chain is only a failed batch.
	#[tokio::test]
	async fn a_failed_filter_batch_without_a_reorg_keeps_every_block() {
		let (mut h, _bundles, transport, pro) = start_bundled(&[], fast_tuning());
		transport
			.refuse_with(Some(ChainProviderError::Refused("unsupported: unknown route".into())));
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(29)));

		h.source.hold_filter_headers(true);
		h.source.mine(2, &[], 0);
		pro.mine(2, &[], 0);
		filters_behind_at(&h, 31).await;
		h.source.mine(1, &[], 0);
		pro.mine(1, &[], 0);
		let reads = h.source.calls("filter_headers");
		tokio::time::timeout(WAIT, async {
			while h.source.calls("filter_headers") < reads + 3 {
				tokio::time::sleep(Duration::from_millis(5)).await;
			}
		})
		.await
		.unwrap();
		h.source.hold_filter_headers(false);
		assert_eq!(
			h.ops_until_synced().await,
			vec![Op::Filtered(30), Op::Filtered(31), Op::Filtered(32), Op::Synced(32)]
		);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_pro_without_the_route_is_followed_through_the_raw_routes() {
		let (mut h, _bundles, transport, pro) = start_bundled(&[], fast_tuning());
		transport
			.refuse_with(Some(ChainProviderError::Refused("unsupported: unknown route".into())));
		assert_eq!(h.ops_until_synced().await.last(), Some(&Op::Synced(29)));
		h.source.mine(1, &[], 0);
		pro.mine(1, &[], 0);
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(transport.calls("since"), 1, "not asked again inside the backoff");
		assert!(h.source.calls("filters") >= 2, "the raw routes answered");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_replay_request_at_or_above_what_was_queued_fetches_nothing_again() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;
		let (filters, filter_headers) =
			(h.source.calls("filters"), h.source.calls("filter_headers"));

		// At the tip, and above it: every block a listener there needs is still to come, so
		// nothing is fetched or queued again. Only the rescan goes out, from the lowest asked:
		// the applicator, which may have started above it, rewinds to it or ignores it.
		h.ask_replay(29);
		h.replay_tx.send(BlockId { height: 45, hash: BlockHash::all_zeros() }).unwrap();
		assert_eq!(h.next_op().await, Op::Rescan(29));
		h.assert_quiet().await;
		assert_eq!(h.source.calls("filters"), filters, "nothing was fetched again");
		assert_eq!(h.source.calls("filter_headers"), filter_headers);
		// Still synced to the same tip: it is confirmed, not announced again.
		assert_eq!(h.next_any_op().await, Op::TipConfirmed(29));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// The Pi2 boot order (2026-10-31): a node joins while the loop is still on its way up from
	/// the anchor it resumed from, with its tip above that anchor. Nothing above the node's tip
	/// is queued yet, so nothing is queued again — but the rescan still goes out first, for an
	/// applicator that started above the node's tip, followed by every block from the anchor
	/// up as on any catch-up.
	#[tokio::test]
	async fn a_replay_asked_before_the_loop_passed_it_still_queues_the_rescan_first() {
		let source = FakeSource::new(30, &[]);
		// The source refuses the first call, as a provider refused chain.headers for 21 s on
		// the Pi; the request comes in while the loop waits to resume.
		source.fail_next(1);
		let mut h = start(source, 10, fast_tuning());
		h.ask_replay(15);
		let mut expected = vec![Op::Rescan(15)];
		expected.extend(filtered(11..=29));
		expected.push(Op::Synced(29));
		assert_eq!(h.ops_until_synced().await, expected);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_replay_request_below_the_resume_anchor_replays_from_it() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;

		// A listener that fell behind the one the sync resumed for, at 3: the headers held
		// from the start of the anchor's retarget period cover it.
		h.ask_replay(3);
		assert_eq!(h.ops_until_synced().await, replay_ops(3, false));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_replay_below_the_headers_held_holds_them_down_to_it_first() {
		let tuning = SourceTuning { held_headers: 5, ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		h.ops_until_synced().await;
		assert_eq!(lock_headers(&h.chain).base(), 25, "pruned to the last five");

		// The headers from 12 are fetched, linked into the held chain and held, then the
		// filters above 12 come again; once they have passed, pruning drops the headers again.
		h.ask_replay(12);
		assert_eq!(h.ops_until_synced().await, replay_ops(12, false));
		assert_eq!(lock_headers(&h.chain).base(), 25, "pruned again behind the replay");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_replay_deeper_than_the_cap_or_off_the_held_chain_queues_nothing() {
		let tuning = SourceTuning { max_replay_depth: 10, ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		h.ops_until_synced().await;
		let filters = h.source.calls("filters");

		// 12 is 17 below the tip; at 22 the block named is not the one held.
		h.ask_replay(12);
		h.replay_tx.send(BlockId { height: 22, hash: BlockHash::all_zeros() }).unwrap();
		h.assert_quiet().await;
		assert_eq!(h.source.calls("filters"), filters, "nothing was fetched again");

		// One within the cap and on the chain is still served.
		h.ask_replay(24);
		assert_eq!(h.ops_until_synced().await, replay_ops(24, false));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn the_lowest_of_the_replays_asked_together_is_served_once() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;

		// Three listeners joined between two steps: one replay, from the lowest.
		h.ask_replay(25);
		h.ask_replay(18);
		h.ask_replay(21);
		assert_eq!(h.ops_until_synced().await, replay_ops(18, false));
		h.assert_quiet().await;
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_replay_the_source_cannot_serve_before_a_fall_back_still_rewinds_the_applicator() {
		let tuning = SourceTuning {
			held_headers: 5,
			fallback_after: Some(Duration::from_millis(100)),
			..fast_tuning()
		};
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		h.ops_until_synced().await;

		// The source goes down, and a listener joins below the headers held, which cannot be
		// fetched now. Before handing over to kyoto — which replays from the lowest listener —
		// the loop still rewinds the applicator for it.
		h.take_the_source_down().await;
		h.ask_replay(12);
		assert_eq!(h.next_op().await, Op::Rescan(12));
		assert_eq!(h.end().await, SourceSyncEnd::FallBack);
	}

	#[tokio::test]
	async fn a_reorg_during_a_replay_disconnects_every_block_the_listeners_took() {
		// A call bound that gives up on a hung block fetch quickly.
		let tuning = SourceTuning { call_timeout: Duration::from_millis(200), ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[20]), 10, tuning);
		h.ops_until_synced().await;
		let old_28 = h.source.block_at(28).header;
		let old_29 = h.source.block_at(29).header;

		// The replay stalls at the matched block 20, having queued 16..=19 again.
		h.source.state.lock().unwrap().hang_blocks = true;
		h.ask_replay(15);
		let mut ops = Vec::new();
		for _ in 0..5 {
			ops.push(h.next_op().await);
		}
		let mut expected = vec![Op::Rescan(15)];
		expected.extend(filtered(16..=19));
		assert_eq!(ops, expected);

		// Meanwhile the source replaces 28 and 29. The listeners already past the replay took
		// them before it began, so they are disconnected though the replay never reached them;
		// then the replay goes on along the new branch.
		h.source.reorg(2, 3);
		h.source.state.lock().unwrap().hang_blocks = false;
		let mut expected = vec![Op::Disconnect(vec![29, 28]), Op::Full(20)];
		expected.extend(filtered(21..=30));
		expected.push(Op::Synced(30));
		assert_eq!(h.ops_until_synced().await, expected);
		assert_eq!(h.last_disconnect, vec![(old_29, 29), (old_28, 28)], "the abandoned headers");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn headers_are_fetched_only_a_lookahead_ahead_of_the_filters() {
		let tuning = SourceTuning { header_lookahead: 4, ..fast_tuning() };
		let mut h = start(FakeSource::new(40, &[]), 10, tuning);
		let mut expected = filtered(11..=39);
		expected.push(Op::Synced(39));
		assert_eq!(h.ops_until_synced().await, expected);
		assert!(h.source.calls("headers") >= (39 - 10) / 4, "headers came in lookahead-sized runs");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_source_answering_prefixes_is_followed_to_the_tip() {
		let source = FakeSource::new(40, &[25]);
		source.cap_replies(Some(7), Some(3));
		let mut h = start(source, 10, fast_tuning());
		let mut expected = filtered(11..=24);
		expected.push(Op::Full(25));
		expected.extend(filtered(26..=39));
		expected.push(Op::Synced(39));
		assert_eq!(h.ops_until_synced().await, expected, "every block, in order, none twice");
		assert!(h.source.calls("filters") >= 29 / 3, "in prefix-sized steps");
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { .. }), "no strike");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn an_empty_filters_answer_is_a_strike() {
		let source = FakeSource::new(30, &[]);
		source.cap_replies(None, Some(0));
		let mut h = start(source, 10, fast_tuning());
		let end = h.end_after_no_ops().await;
		assert!(
			matches!(&end, SourceSyncEnd::Failed(reason) if reason.contains("filter count")),
			"{:?}",
			end
		);
	}

	#[tokio::test]
	async fn a_served_filter_header_that_does_not_match_its_filter_is_rejected() {
		let source = FakeSource::new(30, &[]);
		source.set_lie(Lie::FilterHeaderAt(25));
		let mut h = start(source, 10, fast_tuning());
		let end = h.end_after_no_ops().await;
		assert!(
			matches!(&end, SourceSyncEnd::Failed(reason) if reason.contains("filter hash vs filter header")),
			"{:?}",
			end
		);
	}

	impl Harness {
		/// The loop's end, asserting no op at all was queued.
		async fn end_after_no_ops(&mut self) -> SourceSyncEnd {
			let task = &mut self.task;
			let end = tokio::time::timeout(WAIT, task).await.expect("ended in time").unwrap();
			assert!(self.ops_rx.try_recv().is_err(), "nothing was queued from unverified data");
			assert!(
				matches!(*self.sync_state_tx.borrow(), CbfSyncState::Failed(_)),
				"failed closed"
			);
			end
		}
	}

	#[tokio::test]
	async fn a_filter_header_span_that_does_not_continue_the_verified_chain_is_rejected() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;

		// The source now claims a different filter header below its spans.
		h.source.set_lie(Lie::FilterHeaderPrevious);
		h.source.mine(1, &[], 0);
		let end = tokio::time::timeout(WAIT, &mut h.task).await.expect("ended").unwrap();
		assert!(
			matches!(&end, SourceSyncEnd::Failed(reason) if reason.contains("filter header chain")),
			"{:?}",
			end
		);
		assert!(h.ops_rx.try_recv().is_err(), "block 30 was never queued");
	}

	#[tokio::test]
	async fn a_header_without_its_proof_of_work_is_rejected() {
		let source = FakeSource::new(30, &[]);
		let prev = source.block_at(29).block_hash();
		let mut bad = mine(prev, 30, BASE_TIME + 30 * 600, other_script(30), 0);
		// Walk the nonce until the hash misses the target.
		while bad.header.validate_pow(bad.header.target()).is_ok() {
			bad.header.nonce += 1;
		}
		source.push_raw(bad);
		let mut h = start(source, 10, fast_tuning());

		// Headers are taken before filters, so the sync fails closed at the bad header before
		// any block is queued; the good headers below it stay verified.
		let end = h.end_after_no_ops().await;
		assert!(
			matches!(&end, SourceSyncEnd::Failed(r) if r.contains("proof of work")),
			"{:?}",
			end
		);
	}

	#[tokio::test]
	async fn a_header_with_the_wrong_difficulty_is_rejected() {
		let source = FakeSource::new(30, &[]);
		let prev = source.block_at(29).block_hash();
		let mut bad = mine(prev, 30, BASE_TIME + 30 * 600, other_script(30), 0);
		// Mainnet's limit, far harder than regtest's: the rules require the parent's bits.
		bad.header.bits = CompactTarget::from_consensus(0x1d00_ffff);
		source.push_raw(bad);
		let mut h = start(source, 10, fast_tuning());
		let end = h.end_after_no_ops().await;
		assert!(matches!(&end, SourceSyncEnd::Failed(r) if r.contains("difficulty")), "{:?}", end);
	}

	#[tokio::test]
	async fn a_matched_block_whose_merkle_root_does_not_hold_is_rejected() {
		let source = FakeSource::new(30, &[20]);
		source.set_lie(Lie::MerkleAt(20));
		let mut h = start(source, 10, fast_tuning());
		let mut ops = Vec::new();
		for _ in 11..=19 {
			ops.push(h.next_op().await);
		}
		assert_eq!(ops, filtered(11..=19));
		let end = h.end_after_no_ops().await;
		assert!(matches!(&end, SourceSyncEnd::Failed(r) if r.contains("merkle root")), "{:?}", end);
		assert_eq!(h.permits.available_permits(), CBF_FULL_BLOCK_PERMITS, "no permit leaked");
	}

	/// H1: taking back what a filter hid must not un-confirm what stands. Headers still on the
	/// chain of most work are not disconnected: a channel funded above `from` would be force closed.
	#[tokio::test]
	async fn a_rewind_disconnects_nothing_and_finds_what_a_lying_source_hid() {
		let source = FakeSource::new(30, &[20, 25]);
		source.set_lie(Lie::OmitOutputsOnlyAt(20));
		let mut h = start(source, 0, fast_tuning());
		let first = h.ops_until_synced().await;
		assert!(first.contains(&Op::Filtered(20)), "the lie hid the matched block: {:?}", first);
		assert!(first.contains(&Op::Full(25)), "a true filter above it matched: {:?}", first);

		// The next source is honest; the loop would otherwise refuse its filter-header chain.
		h.source.set_lie(Lie::None);
		let hash = h.source.block_at(20).block_hash();
		lock_headers(&h.chain).request_rewind(BlockId { height: 20, hash });
		h.source.mine(1, &[], 0);
		let ops = h.ops_until_synced().await;
		assert!(
			!ops.iter().any(|op| matches!(op, Op::Disconnect(_))),
			"the headers stay on the chain of most work, so nothing is disconnected: {:?}",
			ops
		);
		assert!(ops.contains(&Op::Scan(20)), "what the filter hid is read: {:?}", ops);
		assert!(ops.contains(&Op::Scan(25)), "and all that the new filters match: {:?}", ops);
		assert!(ops.contains(&Op::Filtered(30)), "and the chain carries on: {:?}", ops);
		assert!(
			!ops.iter().any(|op| matches!(op, Op::Filtered(h) | Op::Full(h) if *h <= 29)),
			"nothing connects twice: {:?}",
			ops
		);
		assert_eq!(lock_headers(&h.chain).filter_header(29), h.source.true_filter_header(29));
		assert!(!matches!(*h.sync_state_tx.borrow(), CbfSyncState::Failed(_)));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// A true reorg still follows the normal rules, even with a rewind in the air.
	#[tokio::test]
	async fn a_true_reorg_during_a_rewind_disconnects_only_what_left_the_chain() {
		let source = FakeSource::new(30, &[]);
		source.set_lie(Lie::OmitOutputsOnlyAt(20));
		let mut h = start(source, 0, fast_tuning());
		h.ops_until_synced().await;
		h.source.set_lie(Lie::None);
		let hash = h.source.block_at(20).block_hash();
		lock_headers(&h.chain).request_rewind(BlockId { height: 20, hash });
		h.source.reorg(2, 4);
		let ops = h.ops_until_synced().await;
		let disconnects: Vec<&Op> =
			ops.iter().filter(|op| matches!(op, Op::Disconnect(_))).collect();
		assert_eq!(disconnects, vec![&Op::Disconnect(vec![29, 28])], "{:?}", ops);
		assert!(ops.contains(&Op::Filtered(31)), "the new branch connects: {:?}", ops);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// B2: a forged tip and made-up headers cost the sender and never decide a reorg.
	#[tokio::test]
	async fn a_forged_tip_on_unproven_headers_convicts_the_sender_and_the_loop_lives() {
		let tuning = SourceTuning {
			restart_backoff: Some((Duration::from_millis(20), Duration::from_millis(40))),
			..fast_tuning()
		};
		let source = Arc::new(FakeSource::new(30, &[]));
		let observer = Arc::new(Heard::default());
		let mut h = start_observed(Arc::clone(&source), 10, tuning, Arc::clone(&observer));
		h.ops_until_synced().await;

		source.set_lie(Lie::ForgedHeadersFrom(12));
		observer.wait_for(|event| {
			matches!(
				event,
				SyncEvent::Evidence { kind: LieKind::BadHeader, .. }
			)
		})
		.await;
		tokio::time::sleep(Duration::from_millis(200)).await;
		assert!(!h.task.is_finished(), "a peer's word does not end the loop");
		h.assert_quiet().await;

		// Whoever answers next is followed, with no restart of anything.
		source.set_lie(Lie::None);
		source.mine(1, &[], 0);
		let ops = h.ops_until_synced().await;
		assert_eq!(ops, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// B2 with real proof of work: a chain this node cannot follow is a reason to leave that Pro,
	/// and no reason to stop following the chain.
	#[tokio::test]
	async fn a_fork_below_the_headers_held_does_not_end_a_supervised_loop() {
		let tuning = SourceTuning {
			held_headers: 5,
			restart_backoff: Some((Duration::from_millis(20), Duration::from_millis(40))),
			..fast_tuning()
		};
		let source = Arc::new(FakeSource::new(30, &[]));
		let observer = Arc::new(Heard::default());
		let mut h = start_observed(Arc::clone(&source), 10, tuning, Arc::clone(&observer));
		h.ops_until_synced().await;
		source.reorg(10, 12);
		observer
			.wait_for(|event| matches!(event, SyncEvent::Evidence { kind: LieKind::WrongChain, .. }))
			.await;
		tokio::time::sleep(Duration::from_millis(200)).await;
		assert!(!h.task.is_finished());
		h.assert_quiet().await;
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// H2: strikes are evidence against the source, and starting over keeps every check.
	#[tokio::test]
	async fn failing_closed_tells_the_session_and_starting_over_keeps_the_filter_headers() {
		let tuning = SourceTuning {
			restart_backoff: Some((Duration::from_millis(20), Duration::from_millis(40))),
			..fast_tuning()
		};
		let source = Arc::new(FakeSource::new(30, &[]));
		let observer = Arc::new(Heard::default());
		let mut h = start_observed(Arc::clone(&source), 10, tuning, Arc::clone(&observer));
		h.ops_until_synced().await;
		let held = lock_headers(&h.chain).filter_header(29);
		assert!(held.is_some());

		// One Pro, the same Pro: first a span that does not hash.
		source.set_lie(Lie::FilterHeaderAt(30));
		source.mine(1, &[], 0);
		observer
			.wait_for(|event| matches!(event, SyncEvent::Evidence { kind: LieKind::InvalidFilterData, .. }))
			.await;
		let mut state = h.sync_state_tx.subscribe();
		tokio::time::timeout(WAIT, state.wait_for(|s| matches!(s, CbfSyncState::Failed(_))))
			.await
			.expect("failed closed in time")
			.expect("alive");
		// Long enough for a start-over or two.
		tokio::time::sleep(Duration::from_millis(150)).await;
		assert_eq!(lock_headers(&h.chain).filter_header(29), held, "kept through the start-over");

		// Then a story of its own from below: consistent with itself, not with what it said.
		source.set_lie(Lie::OmitOutputsFrom(25));
		h.assert_quiet().await;
		tokio::time::sleep(Duration::from_millis(150)).await;
		h.assert_quiet().await;
		assert_eq!(lock_headers(&h.chain).tip().unwrap().height, 30);
		assert_eq!(lock_headers(&h.chain).filter_header(30), None, "nothing of it was taken");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// The Pro is one whose filter chain this node has not yet heard: another Pro's history may
	/// disagree, and that is no evidence against this one. Those blocks are read again from it.
	#[tokio::test]
	async fn the_next_pros_filter_chain_is_not_held_against_it_and_what_differs_is_read_again() {
		let source = Arc::new(FakeSource::new(30, &[22]));
		source.set_lie(Lie::OmitOutputsOnlyAt(22));
		let observer = Arc::new(Heard::default());
		let mut h = start_observed(Arc::clone(&source), 10, fast_tuning(), Arc::clone(&observer));
		let first = h.ops_until_synced().await;
		assert!(first.contains(&Op::Filtered(22)));

		// The session moved: the same chain, an honest Pro.
		source.set_lie(Lie::None);
		source.next_epoch();
		source.mine(1, &[], 0);
		let ops = h.ops_until_synced().await;
		assert!(ops.contains(&Op::Scan(22)), "what the old Pro hid is read: {:?}", ops);
		assert!(!ops.iter().any(|op| matches!(op, Op::Disconnect(_))), "{:?}", ops);
		assert!(ops.contains(&Op::Filtered(30)), "{:?}", ops);
		assert_eq!(observer.evidence(), Vec::<LieKind>::new(), "no evidence against the honest one");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// What a loop keeps across a restart.
	#[derive(Default)]
	struct Remembering {
		heard: Heard,
		kept: Mutex<Vec<SavedFilterHeader>>,
	}

	impl SyncObserver for Remembering {
		fn sync_event(&self, epoch: u64, event: SyncEvent) {
			self.heard.sync_event(epoch, event);
		}
		fn saved_filter_headers(&self) -> Vec<SavedFilterHeader> {
			self.kept.lock().unwrap().clone()
		}
		fn save_filter_headers(&self, headers: &[SavedFilterHeader]) {
			*self.kept.lock().unwrap() = headers.to_vec();
		}
	}

	fn start_remembering(
		source: Arc<FakeSource>, anchor_height: u32, observer: Arc<Remembering>,
	) -> Harness {
		let filter_source = Arc::clone(&source) as Arc<dyn FilterSource>;
		start_watched(
			source,
			filter_source,
			new_shared_header_chain(),
			Arc::new(Notify::new()),
			anchor_height,
			fast_tuning(),
			Some(observer as Arc<dyn SyncObserver>),
		)
	}

	/// N4. A Pro hides a spend at 22, and the node restarts above it before any check. Its listeners
	/// resume at 29, and the Pro now serves the true chain: without what was saved, the block is
	/// never read again and no check ever differs. With it, the first span does not continue what
	/// this node saw, and the blocks where they part are read.
	#[tokio::test]
	async fn a_restart_does_not_forget_what_a_pro_said_before_it() {
		let source = Arc::new(FakeSource::new(30, &[22]));
		source.set_lie(Lie::OmitOutputsOnlyAt(22));
		let memory = Arc::new(Remembering::default());
		let mut h = start_remembering(Arc::clone(&source), 10, Arc::clone(&memory));
		let first = h.ops_until_synced().await;
		assert!(first.contains(&Op::Filtered(22)), "the lie worked: {:?}", first);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
		let kept = memory.kept.lock().unwrap().clone();
		assert_eq!(kept.last().map(|row| row.height), Some(29));

		// The restart. The listeners stand at 29. It says the truth now.
		source.set_lie(Lie::None);
		source.mine(1, &[], 0);
		let mut h = start_remembering(Arc::clone(&source), 29, Arc::clone(&memory));
		let ops = h.ops_until_synced().await;
		assert!(ops.contains(&Op::Scan(22)), "what it hid is read: {:?}", ops);
		assert!(!ops.iter().any(|op| matches!(op, Op::Disconnect(_))), "{:?}", ops);
		assert_eq!(memory.heard.evidence(), Vec::<LieKind>::new(), "who said what is not known");
		memory
			.heard
			.wait_for(|event| matches!(event, SyncEvent::ReadingAgain))
			.await;
		assert_eq!(lock_headers(&h.chain).filter_header(29), source.true_filter_header(29));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// N4 as it went on the wire: the anchor is the lowest listener's, below the lie, and the listener
	/// the money is for stands above it. The block comes again from the true chain, and the gate skips
	/// it for that listener. Where what is taken differs from what was saved, it is read as well.
	#[tokio::test]
	async fn a_restart_anchored_below_the_lie_reads_the_block_a_listener_would_skip() {
		let source = Arc::new(FakeSource::new(30, &[27]));
		source.set_lie(Lie::OmitOutputsOnlyAt(27));
		let memory = Arc::new(Remembering::default());
		let mut h = start_remembering(Arc::clone(&source), 10, Arc::clone(&memory));
		let first = h.ops_until_synced().await;
		assert!(first.contains(&Op::Filtered(27)), "the lie worked: {:?}", first);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);

		source.set_lie(Lie::None);
		let mut h = start_remembering(Arc::clone(&source), 25, Arc::clone(&memory));
		let ops = h.ops_until_synced().await;
		assert!(ops.contains(&Op::Full(27)), "{:?}", ops);
		assert!(ops.contains(&Op::Scan(27)), "read for whoever would skip it: {:?}", ops);
		assert!(!ops.iter().any(|op| matches!(op, Op::Disconnect(_))), "{:?}", ops);
		memory.heard.wait_for(|event| matches!(event, SyncEvent::ReadingAgain)).await;
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);

		// With nothing differing, nothing is read twice.
		let mut h = start_remembering(Arc::clone(&source), 25, Arc::clone(&memory));
		let ops = h.ops_until_synced().await;
		assert!(!ops.contains(&Op::Scan(27)), "{:?}", ops);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// What it saved is still held if it goes on with the same lie, so a witness can differ.
	#[tokio::test]
	async fn a_restart_holds_the_saved_filter_headers_for_a_check_to_compare() {
		let source = Arc::new(FakeSource::new(30, &[22]));
		source.set_lie(Lie::OmitOutputsOnlyAt(22));
		let memory = Arc::new(Remembering::default());
		let mut h = start_remembering(Arc::clone(&source), 10, Arc::clone(&memory));
		h.ops_until_synced().await;
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
		let lied = memory.kept.lock().unwrap().last().unwrap().filter_header;

		let mut h = start_remembering(Arc::clone(&source), 29, Arc::clone(&memory));
		let ops = h.ops_until_synced().await;
		assert!(!ops.contains(&Op::Scan(22)), "it says what it said: {:?}", ops);
		{
			let chain = lock_headers(&h.chain);
			assert_eq!(chain.filter_header(29), Some(lied));
			let held = chain.held_chain(29).unwrap();
			let at_29 = (29 - held.base) as usize;
			assert_eq!(held.blocks[at_29].taken_under, None, "whose word is not known");
		}
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// B1: the loop tells of a stale tip and of being stuck, and clears it.
	#[tokio::test]
	async fn a_stale_tip_is_told_to_the_observer_and_a_fresh_one_clears_it() {
		let source = Arc::new(FakeSource::new(30, &[]));
		let tuning = SourceTuning {
			stale_tip_after: Some(Duration::from_secs(60)),
			..fast_tuning()
		};
		let observer = Arc::new(Heard::default());
		let h = start_observed(Arc::clone(&source), 10, tuning, Arc::clone(&observer));
		observer.wait_for(|event| matches!(event, SyncEvent::StaleTip { height: 29, .. })).await;
		source.mine_at(now_secs() as u32);
		observer.wait_for(|event| matches!(event, SyncEvent::Healthy)).await;
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// What a move does to strikes: the old Pro's do not count against the new one.
	#[tokio::test]
	async fn a_move_clears_the_strikes_and_what_came_from_before_it_is_not_told() {
		let tuning = SourceTuning {
			max_invalid_strikes: 2,
			restart_backoff: Some((Duration::from_secs(600), Duration::from_secs(600))),
			..fast_tuning()
		};
		let source = Arc::new(FakeSource::new(30, &[]));
		let observer = Arc::new(Heard::default());
		let wake = Arc::new(Notify::new());
		let mut h = start_observed_woken(
			Arc::clone(&source),
			10,
			tuning,
			Arc::clone(&observer),
			Arc::clone(&wake),
		);
		h.ops_until_synced().await;
		source.set_lie(Lie::FilterHeaderAt(30));
		source.mine(1, &[], 0);
		observer.wait_for(|e| matches!(e, SyncEvent::Evidence { .. })).await;

		// In the long wait of a restart: the move must not wait it out.
		source.set_lie(Lie::None);
		source.next_epoch();
		wake.notify_one();
		let ops = tokio::time::timeout(Duration::from_secs(5), h.ops_until_synced())
			.await
			.expect("a new Pro does not sit out the old one's wait");
		assert_eq!(ops, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// B1, B3's seam: a claim counts only with the headers to back it, and bad ones convict.
	#[tokio::test]
	async fn more_work_is_proven_by_headers_or_not_at_all() {
		let ours = Arc::new(FakeSource::new(30, &[]));
		let chain = new_shared_header_chain();
		let source_for_chain = Arc::clone(&ours) as Arc<dyn FilterSource>;
		let mut h =
			start_over(Arc::clone(&ours), source_for_chain, Arc::clone(&chain), Arc::new(Notify::new()), 10, fast_tuning());
		h.ops_until_synced().await;
		let _ = h.stop().await;

		// The same chain and three blocks more: the fake mines the same blocks every time.
		let witness = FakeSource::new(33, &[]);
		let claim = witness.tip_id();
		let proof = prove_more_work(&witness, &chain, Network::Regtest, claim, WAIT, true).await;
		assert_eq!(proof, BranchProof::Proven { height: 32, reached_claim: true });

		// A claim from nothing: tip high, no header to show for it.
		let empty = FakeSource::new(30, &[]);
		let false_claim = BlockId { height: 500, hash: BlockHash::all_zeros() };
		let proof = prove_more_work(&empty, &chain, Network::Regtest, false_claim, WAIT, true).await;
		assert_eq!(proof, BranchProof::NotAhead);

		// Made-up headers, however high.
		let forger = FakeSource::new(40, &[]);
		forger.set_lie(Lie::ForgedHeadersFrom(30));
		let claim = forger.tip().await.unwrap();
		let proof = prove_more_work(&forger, &chain, Network::Regtest, claim, WAIT, true).await;
		assert!(matches!(proof, BranchProof::Forged { height: 30 }), "{:?}", proof);

		// A claim the same height as ours, or under it, proves nothing.
		let tie = BlockId { height: 29, hash: BlockHash::all_zeros() };
		let proof = prove_more_work(&empty, &chain, Network::Regtest, tie, WAIT, true).await;
		assert_eq!(proof, BranchProof::NotAhead);
	}

	/// The checks a made-up header cannot pass, on the network's rules.
	#[test]
	fn a_header_at_an_easy_target_does_not_pass_on_mainnet() {
		// Self-consistent at the regtest limit, as forged headers are cheap to be.
		let easy = mine(BlockHash::all_zeros(), 800_000, BASE_TIME, other_script(1), 0).header;
		let failure = check_fork_header(Network::Bitcoin, 800_000, &easy, None);
		assert!(
			matches!(failure, Err(VerifyFailure::Header(HeaderCheck::ProofOfWork { .. }))),
			"{:?}",
			failure
		);
		assert!(check_fork_header(Network::Regtest, 800_000, &easy, None).is_ok());
	}

	#[tokio::test]
	async fn a_rewind_for_a_block_no_longer_on_the_chain_is_nothing() {
		let mut h = start(FakeSource::new(30, &[]), 0, fast_tuning());
		h.ops_until_synced().await;
		lock_headers(&h.chain).request_rewind(BlockId { height: 20, hash: BlockHash::all_zeros() });
		h.source.mine(1, &[], 0);
		let ops = h.ops_until_synced().await;
		assert_eq!(ops, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_reorg_of_depth_two_disconnects_tip_first_and_connects_the_new_branch() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;
		let old_28 = h.source.block_at(28).header;
		let old_29 = h.source.block_at(29).header;

		// 28 and 29 replaced by three new blocks: more work.
		h.source.reorg(2, 3);
		let ops = h.ops_until_synced().await;
		assert_eq!(
			ops,
			vec![
				Op::Disconnect(vec![29, 28]),
				Op::Filtered(28),
				Op::Filtered(29),
				Op::Filtered(30),
				Op::Synced(30)
			]
		);
		assert_eq!(h.last_disconnect, vec![(old_29, 29), (old_28, 28)], "our abandoned headers");
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_branch_with_no_more_work_is_not_followed() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;
		let ours = lock_headers(&h.chain).tip();

		// Two blocks replaced by two: equal work, and ours came first.
		h.source.reorg(2, 2);
		h.assert_quiet().await;
		assert_eq!(lock_headers(&h.chain).tip(), ours, "the chain held did not move");
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { .. }), "not failed");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_reorg_below_the_headers_held_fails_closed() {
		let tuning = SourceTuning { held_headers: 5, ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		h.ops_until_synced().await;
		assert_eq!(lock_headers(&h.chain).base(), 25, "pruned to the last five");

		h.source.reorg(10, 12);
		let end = tokio::time::timeout(WAIT, &mut h.task).await.expect("ended").unwrap();
		assert!(
			matches!(&end, SourceSyncEnd::Failed(r) if r.contains("forks from this node's below height 25")),
			"{:?}",
			end
		);
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Failed(_)));
		assert!(h.ops_rx.try_recv().is_err(), "nothing disconnected on an unfollowable reorg");
	}

	#[tokio::test]
	async fn an_unavailable_source_is_retried_until_it_answers() {
		let source = FakeSource::new(30, &[]);
		source.fail_next(7);
		let mut h = start(source, 10, fast_tuning());
		let mut expected = filtered(11..=29);
		expected.push(Op::Synced(29));
		assert_eq!(h.ops_until_synced().await, expected);
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { .. }));

		// Down again once synced: retried, never failed, and back when it answers.
		h.source.fail_next(5);
		h.source.mine(1, &[], 0);
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn an_unchanged_tip_is_confirmed_on_every_poll_and_a_failed_tip_check_confirms_nothing() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;

		// Nothing new on the source: each poll proves the node caught up again.
		assert_eq!(h.next_any_op().await, Op::TipConfirmed(29));
		assert_eq!(h.next_any_op().await, Op::TipConfirmed(29));

		// The source goes down: the tip checks fail, and none of them vouches for the node.
		h.take_the_source_down().await;
		let op = tokio::time::timeout(Duration::from_millis(150), h.ops_rx.recv()).await;
		assert!(op.is_err(), "a failed tip check sends nothing, got {:?}", op);

		// Back: the tip is no longer known to be ours, so it is `Synced` again before it is
		// confirmed again.
		h.source.fail_next(0);
		assert_eq!(h.next_any_op().await, Op::Synced(29));
		assert_eq!(h.next_any_op().await, Op::TipConfirmed(29));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	/// A fan-out with nothing behind it: the source loop and the real applicator, end to end,
	/// down to the node metrics.
	struct NoListeners;

	impl crate::chain::cbf::applicator::ChainFanout for NoListeners {
		fn connect_block(&self, _block: &Block, _height: u32) {}
		fn connect_filtered(&self, _header: &Header, _height: u32) {}
		fn disconnect(&self, _header: &Header, _height: u32) {}
		fn scan_block(&self, _block: &Block, _height: u32) {}
		fn take_divergence(&self) -> Option<String> {
			None
		}
		fn record_stranded_listeners(&self, _tip_height: u32) -> bool {
			false
		}
		fn set_bulk_chain_persistence(&self, _enabled: bool) {}
		fn flush_chain_persistence(&self) -> Result<(), Error> {
			Ok(())
		}
	}

	/// A timestamp no real sync writes, to tell a refresh from a stale value.
	const OLD_STAMP: Option<u64> = Some(1);

	fn stamps(metrics: &RwLock<NodeMetrics>) -> (Option<u64>, Option<u64>) {
		let m = metrics.read().unwrap();
		(m.latest_onchain_wallet_sync_timestamp, m.latest_lightning_wallet_sync_timestamp)
	}

	fn age_stamps(metrics: &RwLock<NodeMetrics>) {
		let mut m = metrics.write().unwrap();
		m.latest_onchain_wallet_sync_timestamp = OLD_STAMP;
		m.latest_lightning_wallet_sync_timestamp = OLD_STAMP;
	}

	async fn wait_for_fresh_stamps(metrics: &RwLock<NodeMetrics>) {
		tokio::time::timeout(WAIT, async {
			loop {
				let (onchain, lightning) = stamps(metrics);
				if onchain > OLD_STAMP && lightning > OLD_STAMP {
					return;
				}
				tokio::time::sleep(Duration::from_millis(2)).await;
			}
		})
		.await
		.expect("both sync timestamps refreshed in time");
	}

	/// The source loop at 10 on a 30-block chain, feeding the real applicator; returns once
	/// it has caught up to 29.
	async fn start_applying(
		source: FakeSource,
	) -> (Arc<FakeSource>, Arc<RwLock<NodeMetrics>>, watch::Sender<bool>) {
		use crate::chain::cbf::applicator::{BlockApplicator, CBF_CHAIN_OP_QUEUE_DEPTH};
		use crate::chain::cbf::fee::new_block_fee_cache;
		use crate::chain::cbf::WatchLedger;
		use lightning::util::test_utils::TestStore;
		use crate::chain::target::test_support::target_spec;
		use crate::chain::target::TargetRegistry;
		use crate::chain::test_wallet::fresh_regtest_wallet;
		use crate::fee_estimator::OnchainFeeEstimator;
		use crate::tx_broadcaster::TransactionBroadcaster;
		use crate::types::DynStore;

		let source = Arc::new(source);
		let anchor = BlockId { height: 10, hash: source.block_at(10).block_hash() };
		let (ops_tx, ops_rx) = mpsc::channel(CBF_CHAIN_OP_QUEUE_DEPTH);
		let (sync_state_tx, _) =
			watch::channel(CbfSyncState::Active { applied_tip: Some(10), synced_to_tip: false });
		let (stop_tx, stop_rx) = watch::channel(false);
		let (_replay_tx, replay_rx) = replay_channel();
		let metrics = Arc::new(RwLock::new(NodeMetrics::default()));
		let logger = Arc::new(Logger::new_log_facade());
		// The applicator stamps every registered target's metrics: one regtest target that
		// shares `metrics`, so the stamps the test reads are the ones the applicator wrote.
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_regtest_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let mut spec =
			target_spec("t", wallet, kv_store, broadcaster, fee_estimator, Arc::clone(&logger));
		spec.node_metrics = Arc::clone(&metrics);
		let targets = Arc::new(TargetRegistry::new());
		targets.register(spec);
		let applicator = BlockApplicator::new(
			Arc::new(NoListeners),
			ops_rx,
			11,
			sync_state_tx.clone(),
			new_block_fee_cache(),
			Arc::new(WatchLedger::new()),
			targets,
			Arc::clone(&logger),
		);
		tokio::spawn(applicator.run());
		let sync = SourceSync::new(
			Arc::clone(&source) as Arc<dyn FilterSource>,
			Network::Regtest,
			anchor,
			new_shared_header_chain(),
			Arc::new(FixedScripts(vec![watched_script()])),
			ops_tx,
			replay_rx,
			Arc::new(Notify::new()),
			sync_state_tx.clone(),
			Arc::new(Semaphore::new(CBF_FULL_BLOCK_PERMITS)),
			stop_rx,
			fast_tuning(),
			logger,
		);
		tokio::spawn(sync.run());
		let mut rx = sync_state_tx.subscribe();
		tokio::time::timeout(
			WAIT,
			rx.wait_for(|s| {
				matches!(s, CbfSyncState::Active { applied_tip: Some(29), synced_to_tip: true })
			}),
		)
		.await
		.expect("synced in time")
		.expect("the sync state channel is open");
		(source, metrics, stop_tx)
	}

	#[tokio::test]
	async fn a_tip_check_that_finds_nothing_new_refreshes_the_sync_timestamps() {
		let (_source, metrics, stop_tx) = start_applying(FakeSource::new(30, &[])).await;
		assert!(stamps(&metrics).0.is_some(), "catching up to the tip stamps them");

		// No block arrives; the next tip poll alone must refresh both.
		age_stamps(&metrics);
		wait_for_fresh_stamps(&metrics).await;
		stop_tx.send_replace(true);
	}

	#[tokio::test]
	async fn a_failed_tip_check_leaves_the_sync_timestamps_to_age() {
		let (source, metrics, stop_tx) = start_applying(FakeSource::new(30, &[])).await;

		// The source goes down; let a confirmation already queued land before aging the stamps.
		let tips = source.calls("tip");
		source.fail_next(u32::MAX);
		tokio::time::timeout(WAIT, async {
			while source.calls("tip") < tips + 2 {
				tokio::time::sleep(Duration::from_millis(1)).await;
			}
		})
		.await
		.expect("failed tip checks in time");
		tokio::time::sleep(Duration::from_millis(20)).await;
		age_stamps(&metrics);

		// Many failed polls later, nothing has vouched for the node: an outage reads as stalled.
		tokio::time::sleep(Duration::from_millis(200)).await;
		assert!(source.calls("tip") > tips + 4, "the source kept being asked");
		assert_eq!(stamps(&metrics), (OLD_STAMP, OLD_STAMP));

		// Back up: the next good tip check refreshes them again.
		source.fail_next(0);
		wait_for_fresh_stamps(&metrics).await;
		stop_tx.send_replace(true);
	}

	#[tokio::test]
	async fn node_then_p2p_falls_back_once_the_source_stays_unavailable() {
		let source = FakeSource::new(30, &[]);
		source.fail_next(u32::MAX);
		let tuning =
			SourceTuning { fallback_after: Some(Duration::from_millis(100)), ..fast_tuning() };
		let h = start(source, 10, tuning);
		assert_eq!(h.end().await, SourceSyncEnd::FallBack);
	}

	fn now_u32() -> u32 {
		now_secs() as u32
	}

	#[tokio::test]
	async fn a_header_from_the_future_is_waited_out_not_struck() {
		let source = FakeSource::new(30, &[]);
		source.mine_at(now_u32() + 3 * 60 * 60);
		let mut h = start(source, 10, fast_tuning());
		// The filters below the header from the future are taken...
		let mut ops = Vec::new();
		for _ in 11..=29 {
			ops.push(h.next_op().await);
		}
		assert_eq!(ops, filtered(11..=29));
		// ...then the loop waits, far past what three strikes would take, without failing.
		h.assert_quiet().await;
		assert!(
			matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { synced_to_tip: false, .. }),
			"waiting, neither synced nor failed"
		);
		assert_eq!(lock_headers(&h.chain).tip().map(|t| t.height), Some(29));

		// The source moves to a branch with a sane timestamp and more work: followed.
		h.source.reorg(1, 2);
		assert_eq!(
			h.ops_until_synced().await,
			vec![Op::Filtered(30), Op::Filtered(31), Op::Synced(31)]
		);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[test]
	fn a_clock_or_bookkeeping_check_is_never_a_strike() {
		let now = Instant::now();
		let mut policy = SourceRetryPolicy::new(fast_tuning());
		for check in [
			HeaderCheck::FutureTime { height: 5, time: u32::MAX },
			HeaderCheck::MissingAncestor { height: 5, needed: 4 },
		] {
			let error = StepError::Verify(VerifyFailure::Header(check));
			for _ in 0..100 {
				assert!(matches!(policy.decide(&error, now), RetryDecision::Retry { .. }));
			}
		}
		assert_eq!(policy.strikes, 0);
		// On `node,p2p` it is no reason to fall back either.
		let tuning = SourceTuning { fallback_after: Some(Duration::ZERO), ..fast_tuning() };
		let mut policy = SourceRetryPolicy::new(tuning);
		let future = StepError::Verify(VerifyFailure::Header(HeaderCheck::FutureTime {
			height: 5,
			time: u32::MAX,
		}));
		assert!(matches!(policy.decide(&future, now), RetryDecision::Retry { .. }));
	}

	#[test]
	fn an_equal_work_race_is_polled_no_slower_than_the_tip() {
		let now = Instant::now();
		let tuning = SourceTuning {
			poll_interval: Duration::from_secs(30),
			max_backoff: Duration::from_secs(300),
			initial_backoff: Duration::from_secs(1),
			..fast_tuning()
		};
		let mut policy = SourceRetryPolicy::new(tuning);
		for _ in 0..20 {
			match policy.decide(&StepError::LessWork { fork: 3 }, now) {
				RetryDecision::Retry { backoff, .. } => {
					assert!(backoff <= Duration::from_secs(30), "{:?}", backoff)
				},
				other => panic!("{:?}", other),
			}
		}
	}

	#[tokio::test]
	async fn a_stale_tip_is_not_reported_synced_until_a_fresh_block_arrives() {
		// The fake chain is timestamped in 2023: stale by any clock today.
		let tuning = SourceTuning { stale_tip_after: Some(STALE_TIP_AFTER), ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		let mut ops = Vec::new();
		for _ in 11..=29 {
			ops.push(h.next_op().await);
		}
		assert_eq!(ops, filtered(11..=29));
		h.assert_quiet().await;
		assert!(
			matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { synced_to_tip: false, .. }),
			"syncing, not synced"
		);

		h.source.mine_at(now_u32());
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn node_then_p2p_falls_back_on_a_stale_tip() {
		let tuning = SourceTuning {
			stale_tip_after: Some(STALE_TIP_AFTER),
			fallback_after: Some(Duration::from_secs(3600)),
			..fast_tuning()
		};
		let h = start(FakeSource::new(30, &[]), 10, tuning);
		assert_eq!(h.end().await, SourceSyncEnd::FallBack);
	}

	#[tokio::test]
	async fn node_then_p2p_falls_back_on_invalid_data_instead_of_failing_closed() {
		let source = FakeSource::new(30, &[]);
		source.set_lie(Lie::FilterHeaderAt(25));
		let tuning =
			SourceTuning { fallback_after: Some(Duration::from_secs(3600)), ..fast_tuning() };
		let mut h = start(source, 10, tuning);
		let task = &mut h.task;
		let end = tokio::time::timeout(WAIT, task).await.expect("ended in time").unwrap();
		assert_eq!(end, SourceSyncEnd::FallBack);
		assert!(h.ops_rx.try_recv().is_err(), "nothing was queued from unverified data");
	}

	#[tokio::test]
	async fn node_mode_starts_over_after_failing_closed() {
		let source = FakeSource::new(30, &[]);
		source.set_lie(Lie::FilterHeaderAt(25));
		let tuning = SourceTuning {
			restart_backoff: Some((Duration::from_millis(50), Duration::from_millis(100))),
			..fast_tuning()
		};
		let mut h = start(source, 10, tuning);
		let mut state = h.sync_state_tx.subscribe();
		tokio::time::timeout(WAIT, state.wait_for(|s| matches!(s, CbfSyncState::Failed(_))))
			.await
			.expect("failed closed in time")
			.expect("the sender is alive");
		assert!(!h.task.is_finished(), "failed, but supervised: the loop runs on");

		// The source stops lying: the next start-over syncs.
		h.source.set_lie(Lie::None);
		let mut expected = filtered(11..=29);
		expected.push(Op::Synced(29));
		assert_eq!(h.ops_until_synced().await, expected);
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { .. }));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[test]
	fn invalid_data_fails_closed_after_the_strikes_and_unavailable_never_does() {
		let now = Instant::now();
		let mut policy = SourceRetryPolicy::new(fast_tuning());
		let unavailable = StepError::Source(SourceError::unavailable("down"));
		for _ in 0..1000 {
			assert!(matches!(policy.decide(&unavailable, now), RetryDecision::Retry { .. }));
		}
		let invalid = StepError::Verify(VerifyFailure::MerkleRoot { height: 1 });
		assert!(matches!(
			policy.decide(&invalid, now),
			RetryDecision::Retry { report: RetryReport::Invalid, .. }
		));
		// An unavailable answer in between does not reset the strikes...
		policy.decide(&unavailable, now);
		assert!(matches!(policy.decide(&invalid, now), RetryDecision::Retry { .. }));
		assert_eq!(policy.decide(&invalid, now), RetryDecision::Fail);
		// ...a completed step does.
		policy.succeeded();
		assert!(matches!(policy.decide(&invalid, now), RetryDecision::Retry { .. }));
	}

	#[test]
	fn a_wait_is_reported_once_then_once_per_interval() {
		let now = Instant::now();
		let mut policy = SourceRetryPolicy::new(fast_tuning());
		let unavailable = StepError::Source(SourceError::unavailable("down"));
		let report = |d: RetryDecision| match d {
			RetryDecision::Retry { report, .. } => report,
			other => panic!("{:?}", other),
		};
		assert_eq!(report(policy.decide(&unavailable, now)), RetryReport::WaitingWarn);
		assert_eq!(report(policy.decide(&unavailable, now)), RetryReport::WaitingQuiet);
		let later = now + Duration::from_secs(61);
		assert_eq!(report(policy.decide(&unavailable, later)), RetryReport::WaitingWarn);
	}

	#[test]
	fn the_header_chain_prunes_truncates_and_sums_work() {
		let source = FakeSource::new(10, &[]);
		let headers: Vec<Header> = (0..10).map(|h| source.block_at(h).header).collect();
		let mut chain = HeaderChain::from_headers(0, headers.clone());
		assert_eq!(chain.tip().map(|t| t.height), Some(9));
		assert_eq!(chain.height_of(&headers[4].block_hash()), Some(4));
		assert!(chain.work_above(7) < chain.work_above(6));
		chain.prune_below(5);
		assert_eq!((chain.base(), chain.header(4)), (5, None));
		assert_eq!(chain.header(5), Some(headers[5]));
		chain.truncate_to(6);
		assert_eq!(chain.tip().map(|t| t.height), Some(6));
		chain.prune_below(100);
		assert_eq!(chain.tip().map(|t| t.height), Some(6), "pruning keeps the tip");
	}

	/// A block with a segwit spend: the coinbase carries the reserved value and the commitment.
	fn segwit_block() -> Block {
		use bitcoin::block::Version;
		use bitcoin::{
			absolute, transaction, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut,
		};
		use bitcoin::{Txid, Witness};

		let reserved = [0u8; 32];
		let coinbase = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::from_bytes(vec![0x01, 0x07, 0x51]),
				sequence: Sequence::MAX,
				witness: Witness::from_slice(&[reserved.to_vec()]),
			}],
			output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey: other_script(1) }],
		};
		let spend = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 },
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::from_slice(&[vec![0xaa; 72], vec![0x02; 33]]),
			}],
			output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: watched_script() }],
		};
		let mut block = Block {
			header: Header {
				version: Version::TWO,
				prev_blockhash: BlockHash::all_zeros(),
				merkle_root: bitcoin::TxMerkleNode::all_zeros(),
				time: BASE_TIME,
				bits: CompactTarget::from_consensus(REGTEST_BITS),
				nonce: 0,
			},
			txdata: vec![coinbase, spend],
		};
		// The coinbase's wtxid counts as zero, so adding the commitment does not move the root.
		let root = block.witness_root().expect("transactions");
		let commitment = Block::compute_witness_commitment(&root, &reserved);
		let mut script = WITNESS_COMMITMENT_PREFIX.to_vec();
		script.extend_from_slice(commitment.as_byte_array());
		block.txdata[0]
			.output
			.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(script) });
		reseal(&mut block);
		block
	}

	fn reseal(block: &mut Block) {
		block.header.merkle_root = block.compute_merkle_root().expect("transactions");
	}

	fn verify(block: &Block) -> Result<(), VerifyFailure> {
		verify_block(block, 7, &block.header)
	}

	#[test]
	fn an_intact_segwit_block_passes() {
		let block = segwit_block();
		assert!(block.check_witness_commitment());
		assert_eq!(verify(&block), Ok(()));
		// A block without witness data needs no commitment.
		let plain = FakeSource::new(3, &[2]).block_at(2);
		assert_eq!(verify(&plain), Ok(()));
	}

	#[test]
	fn a_block_with_its_witnesses_stripped_is_rejected() {
		let mut block = segwit_block();
		for tx in &mut block.txdata {
			for input in &mut tx.input {
				input.witness.clear();
			}
		}
		reseal(&mut block);
		assert!(
			block.check_witness_commitment(),
			"rust-bitcoin's own check accepts a block with no witness at all"
		);
		assert_eq!(verify(&block), Err(VerifyFailure::WitnessCommitment { height: 7 }));

		// Only the spend stripped: the reserved value is there, the commitment no longer holds.
		let mut block = segwit_block();
		block.txdata[1].input[0].witness.clear();
		reseal(&mut block);
		assert_eq!(verify(&block), Err(VerifyFailure::WitnessCommitment { height: 7 }));

		// The reserved value must be exactly one 32-byte item.
		let mut block = segwit_block();
		block.txdata[0].input[0].witness.push([0u8; 32]);
		assert_eq!(verify(&block), Err(VerifyFailure::WitnessCommitment { height: 7 }));
	}

	#[test]
	fn a_block_with_witness_data_and_no_commitment_is_rejected() {
		let mut block = segwit_block();
		block.txdata[0].output.pop();
		reseal(&mut block);
		assert_eq!(verify(&block), Err(VerifyFailure::WitnessCommitment { height: 7 }));
	}

	#[test]
	fn the_first_transaction_must_be_the_only_coinbase() {
		let mut swapped = segwit_block();
		swapped.txdata.swap(0, 1);
		reseal(&mut swapped);
		assert_eq!(verify(&swapped), Err(VerifyFailure::Coinbase { height: 7 }));

		let mut two = segwit_block();
		let mut second = two.txdata[0].clone();
		second.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0x08, 0x52]);
		two.txdata.push(second);
		reseal(&mut two);
		assert_eq!(verify(&two), Err(VerifyFailure::Coinbase { height: 7 }));
	}

	#[test]
	fn a_block_with_a_64_byte_transaction_is_rejected() {
		use bitcoin::{
			absolute, transaction, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut,
		};

		let mut block = FakeSource::new(3, &[]).block_at(2);
		let merkle_node_sized = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint {
					txid: bitcoin::Txid::from_byte_array([3; 32]),
					vout: 1,
				},
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: bitcoin::Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(1),
				script_pubkey: ScriptBuf::from_bytes(vec![0x51; 4]),
			}],
		};
		assert_eq!(merkle_node_sized.base_size(), 64);
		block.txdata.push(merkle_node_sized);
		reseal(&mut block);
		assert!(block.check_merkle_root());
		assert_eq!(verify(&block), Err(VerifyFailure::SixtyFourByteTransaction { height: 7 }));
	}

	#[tokio::test]
	async fn the_fee_source_reads_the_verified_chain_and_checks_the_block() {
		let source = Arc::new(FakeSource::new(12, &[]));
		let chain = new_shared_header_chain();
		*lock_headers(&chain) =
			HeaderChain::from_headers(0, (0..12).map(|h| source.block_at(h).header).collect());
		let (_tx, rx) =
			watch::channel(CbfSyncState::Active { applied_tip: Some(11), synced_to_tip: true });
		let permits = Arc::new(Semaphore::new(1));
		let fee = SourceFeeSource::new(
			Arc::clone(&source) as Arc<dyn FilterSource>,
			Arc::clone(&chain),
			rx,
			Arc::clone(&permits),
		);
		assert_eq!(fee.tip_height().await, Ok(11));
		assert_eq!(fee.block_hash_at(3).await, Ok(Some(source.block_at(3).block_hash())));
		assert!(fee.can_fetch());

		let hash = source.block_at(11).block_hash();
		let fetch = fee.request_block(hash).unwrap();
		assert!(
			matches!(fee.request_block(hash), Err(SampleFailure::NoPermit)),
			"one permit, held by the first fetch"
		);
		let (height, block) = tokio::time::timeout(WAIT, fetch).await.unwrap().unwrap();
		assert_eq!((height, block.block_hash()), (11, hash));
		assert_eq!(permits.available_permits(), 1);

		source.set_lie(Lie::MerkleAt(11));
		let fetch = fee.request_block(hash).unwrap();
		assert_eq!(tokio::time::timeout(WAIT, fetch).await.unwrap(), Err(SampleFailure::Mismatch));
		assert!(matches!(
			fee.request_block(BlockHash::all_zeros()),
			Err(SampleFailure::FetchFailed(_))
		));

		// A fetch the source never answers is cut at the call bound, and its permit freed.
		source.set_lie(Lie::None);
		source.state.lock().unwrap().hang_blocks = true;
		let fee = SourceFeeSource { call_timeout: Duration::from_millis(50), ..fee };
		let fetch = fee.request_block(hash).unwrap();
		match tokio::time::timeout(WAIT, fetch).await.expect("bounded") {
			Err(SampleFailure::FetchFailed(reason)) => {
				assert!(reason.contains("no answer within"), "{}", reason)
			},
			other => panic!("{:?}", other.map(|(h, _)| h)),
		}
		assert_eq!(permits.available_permits(), 1);
	}
}
