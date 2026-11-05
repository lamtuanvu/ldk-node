// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A hybrid node's [`FilterSource`] that takes one bundle per new block from its Pro node,
//! pushed under a lease or pulled.
//!
//! Over the raw routes alone, a new block costs the Pro node three questions after the tip
//! poll that noticed it: its headers, filter headers and filters. A `chain.since` answers all
//! three, plus the Pro's fee estimates, in one reply:
//!
//! ```text
//!   Pro node                                    this node
//!   ────────                                    ─────────
//!   chain.tip     ◄──────────────────────────── tip(): every poll, on delivery pull
//!   chain.block_update ───────────────────────► ingest(): on delivery push; wakes the loop
//!   chain.since   ◄──────────────────────────── headers(): the block above the verified chain
//!                                               is not held, so pull from the verified tip
//!                 ──── bundles, `more`, fee ──► held until the filters are served
//!                       SourceSync ─► headers / filter_headers / filters answered from them
//! ```
//!
//! [`BundleFilterSource`] wraps the node's own [`FilterSource`] — the one that asks the Pro
//! over the raw routes — and is itself one, so the sync loop and every check it makes (proof of
//! work, the filter-header chain, filter against filter header) are unchanged: a bundle is
//! verified exactly as raw data is. The Pro keeps nothing per node; the node's verified chain
//! is the only cursor.
//!
//! The Pro can push the same bundles ([`BundleFilterSource::ingest`]); the provider session
//! ([`crate::chain::session`]) decides that from who holds a lease, and says whether what was
//! pushed may be trusted:
//!
//! * **Delivery pull:** `tip()` is always the inner source, on the sync loop's 30 s poll. That
//!   poll is 96% of what a follower costs its Pro.
//! * **Delivery push, session active:** `tip()` is answered from memory and goes on no wire. The
//!   tip poll stops being what drives the loop; a push wakes it. The liveness check is the
//!   session's probe after 10 min with no push, and a reply to that refreshes what is known. If
//!   the driver stopped refreshing, [`BUNDLE_PUSHED_TIP_MAX_AGE`] ends the trust by itself, and
//!   the loop polls again.
//! * **Push, session suspect or worse:** as pull, so an outage shows as a stalled sync at once.
//!
//! Everything else below is the same on both:
//!
//! * `tip()`: as above.
//! * `headers()`: what is held, a prefix of the span when that is all there is. Not held, and
//!   the span continues the verified chain: one `since` from the verified tip. A reply that
//!   stopped short (`more`) needs no bookkeeping: once its bundles are used, the next block is
//!   again not held, and the next pull starts from where the verified chain now ends.
//! * `filter_headers()` / `filters()`: what is held on the verified chain, a prefix when that
//!   is all there is; not held, one `since` from the block below the span. Served filters are
//!   forgotten, so a catch-up holds at most one reply's worth.
//! * `block()`: always the inner source.
//!
//! Anything a bundle cannot answer goes to the inner source: a Pro without the route (asked
//! again after [`BUNDLE_UNSUPPORTED_RETRY_AFTER`]; the host answers the same for a Pro too old
//! to know it and for one whose app is restarting), a failed call (after
//! [`BUNDLE_RETRY_AFTER`]), a verified tip off the Pro's best chain (at once: the reorg handling
//! over the raw routes finds the fork and the next pull starts from it), and everything below
//! the verified tip.
//!
//! # A filter larger than one reply
//!
//! A reply must fit [`MAX_PEER_REPLY_BYTES`](crate::chain::provider::MAX_PEER_REPLY_BYTES). The
//! Pro sends a filter that does not as pieces, and [`BundleFilterSource`] asks for the rest
//! with `filter_offset`, all inside one pull, then checks the filter header commits to the
//! whole. No block consensus allows comes near that: see
//! `the_largest_filter_a_block_can_carry_fits_one_reply` in `raw_serve`. Pieces exist so a
//! bound changing — a smaller transport cap, say — slows a node down instead of stopping it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use bdk_chain::BlockId;

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::block::Header;
use bitcoin::{Block, BlockHash, ScriptBuf};

use tokio::sync::Notify;

use crate::chain::cbf::source::{FilterHeaders, FilterSource, IndexedFilter, SourceError};
use crate::chain::cbf::fee::BlockFeeCache;
use crate::chain::cbf::source_sync::{
	lock_headers, verify_block, SharedHeaderChain, SyncObserver, WatchedScripts,
};
use crate::chain::session::cross_check::{HeldChain, HeldFilters};
use crate::chain::session::{PushSink, NOT_ON_BEST_CHAIN};
use crate::chain::provider::{
	BundleTransport, ChainProviderError, WireBlockUpdates, WireFeeEstimates, WireSinceRequest,
	CHAIN_WIRE_VERSION, FEE_ESTIMATES_MAX_AGE_SECS, MAX_UPDATES_PER_SINCE,
};
use crate::chain::wire_convert::{
	block_id_from_wire, block_id_to_wire, block_update_from_wire, check_version, BlockBundle,
};
use crate::logger::{log_debug, log_info, log_warn, LdkLogger, Logger};

/// After a failed `since`, it is not asked again for this long; the raw routes answer meanwhile.
pub(crate) const BUNDLE_RETRY_AFTER: Duration = Duration::from_secs(2 * 60);

/// After a `since` refused as `unsupported`, it is not asked again for this long; the raw
/// routes answer meanwhile. Not for the rest of the run: the host answers the same for a Pro
/// too old to know the route and for a Pro whose app is restarting, and a node that gave up on
/// the second would stay on the raw routes until it restarted itself. Long, because the first
/// is the common case and each retry costs it a refused call.
pub(crate) const BUNDLE_UNSUPPORTED_RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

/// Fee estimates a bundle carried older than this are not used.
pub(crate) const BUNDLE_FEE_MAX_AGE: Duration = Duration::from_secs(FEE_ESTIMATES_MAX_AGE_SECS);

/// With delivery push, a tip heard no later than this ago is answered from memory. Just over the
/// session's 10 min probe, whose answer refreshes it: this only comes into play if the driver
/// stopped, and then the node falls back to asking rather than trust silence.
pub(crate) const BUNDLE_PUSHED_TIP_MAX_AGE: Duration = Duration::from_secs(11 * 60);

/// Bound on a `since`: above the app's 45 s serve timeout.
const SINCE_TIMEOUT: Duration = Duration::from_secs(50);

/// The largest filter a pull assembles from pieces: well past what any block can carry, so a
/// Pro cannot make this node hold more by naming a larger total.
const MAX_ASSEMBLED_FILTER_BYTES: u32 = 8 * 1024 * 1024;

/// The knobs of a [`BundleFilterSource`]; shortened in the tests.
#[derive(Clone, Debug)]
pub(crate) struct BundleTuning {
	pub(crate) retry_after: Duration,
	pub(crate) unsupported_retry_after: Duration,
	pub(crate) since_timeout: Duration,
	pub(crate) fee_max_age: Duration,
	pub(crate) pushed_tip_max_age: Duration,
}

impl Default for BundleTuning {
	fn default() -> Self {
		Self {
			retry_after: BUNDLE_RETRY_AFTER,
			unsupported_retry_after: BUNDLE_UNSUPPORTED_RETRY_AFTER,
			since_timeout: SINCE_TIMEOUT,
			fee_max_age: BUNDLE_FEE_MAX_AGE,
			pushed_tip_max_age: BUNDLE_PUSHED_TIP_MAX_AGE,
		}
	}
}

#[derive(Default)]
struct BundleState {
	/// One contiguous run of bundles, ascending, each linked to the one below.
	held: Vec<Arc<BlockBundle>>,
	/// `since` has been refused as `unsupported` this run: repeats log quietly.
	unsupported_seen: bool,
	/// Not before this, after a failed `since`.
	retry_at: Option<Instant>,
	/// The newest fee estimates a bundle carried, and when.
	fee: Option<(WireFeeEstimates, Instant)>,
	/// The Pro's best block, as it last said in a push, a grant or a probe's answer; and when.
	heard_tip: Option<(BlockId, Instant)>,
}

impl BundleState {
	fn get(&self, height: u32) -> Option<&Arc<BlockBundle>> {
		let base = self.held.first()?.height;
		self.held.get(height.checked_sub(base)? as usize)
	}

	/// Fits a pushed `run` — consecutive, linked, non-empty — onto what is held. One that leaves
	/// a gap replaces it: the next pull fills from the verified tip. One on another branch clears
	/// it: the sync loop's reorg handling over the inner source decides.
	fn merge_pushed(&mut self, run: Vec<Arc<BlockBundle>>) {
		let (Some(first), Some(last)) = (run.first(), run.last()) else {
			return;
		};
		let (Some(base), Some(top)) = (self.held.first(), self.held.last()) else {
			self.held = run;
			self.trim();
			return;
		};
		let (lo, hi) = (base.height, top.height);
		if first.height > hi + 1 || last.height + 1 < lo {
			self.held = run;
			self.trim();
			return;
		}
		let agrees = run.iter().all(|b| self.get(b.height).map_or(true, |held| held.hash == b.hash))
			&& (first.height != hi + 1 || first.header.prev_blockhash == top.hash)
			&& (last.height + 1 != lo || base.header.prev_blockhash == last.hash);
		if !agrees {
			self.held.clear();
			return;
		}
		let new_lo = lo.min(first.height);
		let new_hi = hi.max(last.height);
		let mut joined = Vec::with_capacity((new_hi - new_lo + 1) as usize);
		for height in new_lo..=new_hi {
			let bundle = match self.get(height) {
				Some(held) => Arc::clone(held),
				None => Arc::clone(&run[(height - first.height) as usize]),
			};
			joined.push(bundle);
		}
		self.held = joined;
		self.trim();
	}

	/// Keeps the newest day of blocks: what one reply may carry, unlike pushes, which arrive one
	/// by one with nothing to stop them piling up while the loop is busy.
	fn trim(&mut self) {
		let excess = self.held.len().saturating_sub(MAX_UPDATES_PER_SINCE as usize);
		self.held.drain(..excess);
	}
}

/// See the module docs.
pub(crate) struct BundleFilterSource {
	inner: Arc<dyn FilterSource>,
	transport: Arc<dyn BundleTransport>,
	/// The sync loop's verified header chain: where the node is.
	chain: SharedHeaderChain,
	/// Cuts the sync loop's waits short: a push, or a new provider.
	wake: Arc<Notify>,
	state: Mutex<BundleState>,
	/// Whether the session says delivery is push and the Pro is healthy; see the module docs.
	push_trusted: AtomicBool,
	tuning: BundleTuning,
	logger: Arc<Logger>,
	/// Who hears how the sync loop fares; handed to it at launch.
	observer: Mutex<Option<Weak<dyn SyncObserver>>>,
	/// The blocks handed over to be read again, newest last, so none is read twice.
	scanned: Mutex<VecDeque<BlockHash>>,
	/// The fee rates of the blocks this node read itself.
	block_fees: Mutex<Option<BlockFeeCache>>,
	/// What this node watches, for a cross-check to match against; handed over at launch.
	watched: Mutex<Option<Arc<dyn WatchedScripts>>>,
}

/// How many read blocks are remembered: more than a window of them per check.
const SCANNED_REMEMBERED: usize = 512;

/// How many read blocks may wait for the sync loop at once: a small device holds few whole blocks,
/// and a check that finds no room goes on next time.
const SCANS_WAITING_AT_MOST: usize = 2;

/// How few samples of its own the node takes for a rate worth holding a provider to.
const LOCAL_FEE_MIN_SAMPLES: usize = 6;

impl BundleFilterSource {
	pub(crate) fn new(
		inner: Arc<dyn FilterSource>, transport: Arc<dyn BundleTransport>,
		chain: SharedHeaderChain, wake: Arc<Notify>, tuning: BundleTuning, logger: Arc<Logger>,
	) -> Self {
		Self {
			inner,
			transport,
			chain,
			wake,
			state: Mutex::new(BundleState::default()),
			push_trusted: AtomicBool::new(false),
			tuning,
			logger,
			observer: Mutex::new(None),
			scanned: Mutex::new(VecDeque::new()),
			block_fees: Mutex::new(None),
			watched: Mutex::new(None),
		}
	}

	/// Who hears how the sync loop fares, while they are around.
	pub(crate) fn sync_observer(&self) -> Option<Arc<dyn SyncObserver>> {
		self.observer.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(Weak::upgrade)
	}

	/// What this node watches.
	pub(crate) fn set_watched(&self, watched: Arc<dyn WatchedScripts>) {
		*self.watched.lock().unwrap_or_else(|e| e.into_inner()) = Some(watched);
	}

	/// Where the fee rates of the blocks this node read itself are kept.
	pub(crate) fn set_block_fees(&self, cache: BlockFeeCache) {
		*self.block_fees.lock().unwrap_or_else(|e| e.into_inner()) = Some(cache);
	}

	fn state(&self) -> MutexGuard<'_, BundleState> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// What a provider's fees can be held against now.
	pub(crate) fn fee_reference(&self) -> crate::chain::session::FeeReference {
		self.transport.fee_reference()
	}

	/// The newest fee estimates a bundle carried, while they are fresh.
	pub(crate) fn fresh_fee_estimates(&self) -> Option<WireFeeEstimates> {
		let state = self.state();
		let (fee, at) = state.fee.as_ref()?;
		(at.elapsed() < self.tuning.fee_max_age).then(|| fee.clone())
	}

	/// The tip to answer without asking: only on delivery push, with the session active, and
	/// recently heard. See the module docs.
	fn pushed_tip(&self) -> Option<BlockId> {
		if !self.push_trusted.load(Ordering::Acquire) {
			return None;
		}
		let state = self.state();
		let (tip, heard) = state.heard_tip?;
		(heard.elapsed() < self.tuning.pushed_tip_max_age).then_some(tip)
	}

	/// Whether `since` may be asked now.
	fn may_ask(&self) -> bool {
		self.state().retry_at.map_or(true, |at| Instant::now() >= at)
	}

	/// Notes a failed `since`. The raw routes answer this pass, whatever the failure; what
	/// differs is when `since` is asked again.
	fn failed(&self, e: &ChainProviderError) {
		let mut state = self.state();
		if let ChainProviderError::Refused(reason) = e {
			if reason.contains(NOT_ON_BEST_CHAIN) {
				log_debug!(
					self.logger,
					"Chain bundles: '{}' says this node is off its best chain; following '{}' through the reorg.",
					self.transport.name(),
					self.inner.name()
				);
				return;
			}
			if reason.starts_with("unsupported") {
				let wait = self.tuning.unsupported_retry_after;
				state.retry_at = Some(Instant::now() + wait);
				if !state.unsupported_seen {
					state.unsupported_seen = true;
					log_info!(
						self.logger,
						"Chain bundles: '{}' does not serve them ({}); using '{}', asking again in {}s.",
						self.transport.name(),
						e,
						self.inner.name(),
						wait.as_secs()
					);
				} else {
					log_debug!(
						self.logger,
						"Chain bundles: '{}' still does not serve them ({}); using '{}', asking again in {}s.",
						self.transport.name(),
						e,
						self.inner.name(),
						wait.as_secs()
					);
				}
				return;
			}
		}
		state.retry_at = Some(Instant::now() + self.tuning.retry_after);
		log_warn!(
			self.logger,
			"Chain bundles: since through '{}' failed: {}; using '{}', asking again in {}s.",
			self.transport.name(),
			e,
			self.inner.name(),
			self.tuning.retry_after.as_secs()
		);
	}

	async fn ask(
		&self, from: BlockId, filter_offset: u32,
	) -> Result<WireBlockUpdates, ChainProviderError> {
		let req = WireSinceRequest {
			version: CHAIN_WIRE_VERSION,
			from: block_id_to_wire(&from),
			max_blocks: MAX_UPDATES_PER_SINCE,
			filter_offset,
		};
		tokio::time::timeout(self.tuning.since_timeout, self.transport.since(req))
			.await
			.unwrap_or_else(|_| Err(ChainProviderError::Unreachable("since timed out".into())))
	}

	/// Asks for the bundles above `from`, however many calls an oversized filter takes.
	async fn fetch(&self, from: BlockId) -> Result<Pulled, ChainProviderError> {
		let mut pulled = decode_reply(&self.ask(from, 0).await?)?;
		if matches!(pulled.run.first(), Some(b) if b.height != from.height + 1 || b.header.prev_blockhash != from.hash)
		{
			return Err(ChainProviderError::Malformed(format!(
				"the updates do not continue height {}",
				from.height
			)));
		}
		if let Some(mut open) = pulled.open_filter.take() {
			let target = pulled.run.last().map_or(from, |b| BlockId { height: b.height, hash: b.hash });
			while (open.bundle.filter.content.len() as u32) < open.total {
				let have = open.bundle.filter.content.len() as u32;
				let reply = self.ask(target, have).await?;
				check_version(reply.version)?;
				let piece = match reply.updates.as_slice() {
					[piece] => piece,
					updates => {
						return Err(ChainProviderError::Malformed(format!(
							"{} updates continuing the filter at height {}",
							updates.len(),
							open.bundle.height
						)))
					},
				};
				let more = block_update_from_wire(piece)?;
				let fits = more.hash == open.bundle.hash
					&& piece.filter_total == Some(open.total)
					&& piece.filter_offset == have
					&& !more.filter.content.is_empty()
					&& have as u64 + more.filter.content.len() as u64 <= open.total as u64;
				if !fits {
					return Err(ChainProviderError::Malformed(format!(
						"a piece that does not continue the filter at height {} from byte {}",
						open.bundle.height, have
					)));
				}
				open.bundle.filter.content.extend_from_slice(&more.filter.content);
				if piece.fee_estimates.is_some() {
					pulled.fee = piece.fee_estimates.clone();
				}
			}
			if !open.bundle.is_self_consistent() {
				return Err(ChainProviderError::Malformed(format!(
					"the assembled filter at height {} does not match its filter header",
					open.bundle.height
				)));
			}
			log_debug!(
				self.logger,
				"Chain bundles: assembled a {}-byte filter at height {} from pieces.",
				open.total,
				open.bundle.height
			);
			pulled.run.push(Arc::new(open.bundle));
		}
		Ok(pulled)
	}

	/// One pull from `from`, a block of the verified chain, replacing whatever is held above it.
	/// `None` when `since` may not be asked now, or the call failed.
	async fn pull(&self, from: BlockId) -> Option<()> {
		if !self.may_ask() {
			return None;
		}
		let epoch = self.epoch();
		let pulled = match self.fetch(from).await {
			Ok(pulled) => pulled,
			Err(e) => {
				self.failed(&e);
				return None;
			},
		};
		// The node moved while this was on its way. Taken now, the old Pro's word would count as
		// the new one's, which a liar could arrange on purpose.
		if self.epoch() != epoch {
			return None;
		}
		let count = pulled.run.len();
		let mut state = self.state();
		state.held.retain(|b| b.height <= from.height);
		if state.held.last().map(|b| b.hash) != Some(from.hash) {
			state.held.clear();
		}
		state.held.extend(pulled.run);
		if let Some(fee) = pulled.fee {
			state.fee = Some((fee, Instant::now()));
		}
		drop(state);
		log_debug!(
			self.logger,
			"Chain bundles: {} blocks above height {} from '{}'; its tip is {}{}.",
			count,
			from.height,
			self.transport.name(),
			pulled.tip.height,
			if pulled.more { ", more to pull" } else { "" }
		);
		Some(())
	}

	/// The held headers from `from_height`, at most `count`, when they continue the verified
	/// chain.
	fn held_headers(&self, from_height: u32, count: u32) -> Option<Vec<Header>> {
		let below = from_height.checked_sub(1).and_then(|h| lock_headers(&self.chain).hash(h))?;
		let state = self.state();
		let headers: Vec<Header> = (0..count)
			.map_while(|i| state.get(from_height.checked_add(i)?).map(|b| b.header))
			.collect();
		// Only a span that continues the verified chain; the sync loop finds a fork itself.
		(headers.first()?.prev_blockhash == below).then_some(headers)
	}

	/// The bundles for `start..=height(stop_hash)` on the verified chain, from the start —
	/// `None` when `start` is not held on that chain.
	fn held_span(&self, start: u32, stop_hash: BlockHash) -> Option<Vec<Arc<BlockBundle>>> {
		let chain = lock_headers(&self.chain);
		let stop = chain.height_of(&stop_hash)?;
		if stop < start {
			return None;
		}
		let state = self.state();
		let mut out = Vec::new();
		for height in start..=stop {
			match (state.get(height), chain.hash(height)) {
				(Some(bundle), Some(hash)) if bundle.hash == hash => out.push(Arc::clone(bundle)),
				_ => break,
			}
		}
		(!out.is_empty()).then_some(out)
	}

	/// [`Self::held_span`], after one pull from the block below `start` when it is not held.
	async fn span(&self, start: u32, stop_hash: BlockHash) -> Option<Vec<Arc<BlockBundle>>> {
		if let Some(span) = self.held_span(start, stop_hash) {
			return Some(span);
		}
		let below = {
			let chain = lock_headers(&self.chain);
			// A span the sync loop has not verified the headers of is not one to pull.
			chain.height_of(&stop_hash)?;
			let height = start.checked_sub(1)?;
			BlockId { height, hash: chain.hash(height)? }
		};
		self.pull(below).await?;
		self.held_span(start, stop_hash)
	}
}

/// A filter that did not fit one reply, with the bytes that came so far.
struct OpenFilter {
	bundle: BlockBundle,
	total: u32,
}

/// A `since` reply, decoded: the Pro's tip, its whole updates as one linked run, an oversized
/// filter still being fetched, and the newest fee estimates it carries.
struct Pulled {
	tip: BlockId,
	run: Vec<Arc<BlockBundle>>,
	open_filter: Option<OpenFilter>,
	fee: Option<WireFeeEstimates>,
	more: bool,
}

fn decode_reply(reply: &WireBlockUpdates) -> Result<Pulled, ChainProviderError> {
	check_version(reply.version)?;
	let tip = block_id_from_wire(&reply.tip)?;
	let mut run: Vec<Arc<BlockBundle>> = Vec::with_capacity(reply.updates.len());
	let mut open_filter = None;
	for (i, update) in reply.updates.iter().enumerate() {
		let bundle = block_update_from_wire(update)?;
		if let Some(below) = run.last() {
			if bundle.height != below.height + 1 || bundle.header.prev_blockhash != below.hash {
				return Err(ChainProviderError::Malformed(format!(
					"update at height {} does not follow the one at height {}",
					bundle.height, below.height
				)));
			}
		}
		match update.filter_total {
			None => run.push(Arc::new(bundle)),
			Some(total) => {
				if i + 1 != reply.updates.len()
					|| update.filter_offset != 0
					|| bundle.filter.content.is_empty()
					|| total > MAX_ASSEMBLED_FILTER_BYTES
					|| (bundle.filter.content.len() as u64) > total as u64
				{
					return Err(ChainProviderError::Malformed(format!(
						"a bad first piece of the filter at height {} ({} bytes)",
						bundle.height, total
					)));
				}
				open_filter = Some(OpenFilter { bundle, total });
			},
		}
	}
	let fee = reply.updates.iter().rev().find_map(|u| u.fee_estimates.clone());
	Ok(Pulled { tip, run, open_filter, fee, more: reply.more })
}

#[async_trait]
impl FilterSource for BundleFilterSource {
	fn name(&self) -> &'static str {
		"bundles"
	}

	fn epoch(&self) -> u64 {
		self.inner.epoch()
	}

	/// See [`FilterSource::headers_come_with_filters`]: one reply holds both.
	fn headers_come_with_filters(&self) -> bool {
		true
	}

	/// The one question delivery changes: on healthy push this goes on no wire. See the module
	/// docs.
	async fn tip(&self) -> Result<BlockId, SourceError> {
		match self.pushed_tip() {
			Some(tip) => Ok(tip),
			None => self.inner.tip().await,
		}
	}

	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		if let Some(headers) = self.held_headers(from_height, count) {
			return Ok(headers);
		}
		// Only the next block up: a lookup below the tip is the sync loop looking for a fork.
		let verified = lock_headers(&self.chain).tip();
		if let Some(from) = verified.filter(|tip| tip.height.checked_add(1) == Some(from_height)) {
			if self.pull(from).await.is_some() {
				if let Some(headers) = self.held_headers(from_height, count) {
					return Ok(headers);
				}
			}
		}
		self.inner.headers(from_height, count).await
	}

	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		match self.span(start_height, stop_hash).await {
			Some(span) => Ok(FilterHeaders {
				previous: span[0].previous_filter_header,
				headers: span.iter().map(|b| b.filter_header).collect(),
			}),
			None => self.inner.filter_headers(start_height, stop_hash).await,
		}
	}

	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		match self.span(start_height, stop_hash).await {
			Some(span) => {
				let served: Vec<IndexedFilter> = span
					.iter()
					.map(|b| IndexedFilter {
						height: b.height,
						block_hash: b.hash,
						filter: BlockFilter { content: b.filter.content.clone() },
					})
					.collect();
				// Filters are asked last, and a block's filter once: nothing below this is
				// needed again unless something failed, and then a pull is cheap.
				if let Some(last) = span.last() {
					self.state().held.retain(|b| b.height > last.height);
				}
				Ok(served)
			},
			None => self.inner.filters(start_height, stop_hash).await,
		}
	}

	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		self.inner.block(hash).await
	}
}

impl HeldFilters for BundleFilterSource {
	fn check_point(&self, bury: u32) -> Option<(BlockId, FilterHeader)> {
		lock_headers(&self.chain).check_point(bury)
	}

	fn held_chain(&self, through: u32) -> Option<HeldChain> {
		lock_headers(&self.chain).held_chain(through)
	}

	fn block_is_valid(&self, block: &Block, height: u32, header: &Header) -> bool {
		verify_block(block, height, header).is_ok()
	}

	fn scan_block(&self, height: u32, block: Block) {
		let hash = block.block_hash();
		lock_headers(&self.chain).request_scan(height, block);
		let mut scanned = self.scanned.lock().unwrap_or_else(|e| e.into_inner());
		scanned.push_back(hash);
		while scanned.len() > SCANNED_REMEMBERED {
			scanned.pop_front();
		}
		drop(scanned);
		self.wake.notify_one();
	}

	fn scanned_already(&self, hash: &BlockHash) -> bool {
		self.scanned.lock().unwrap_or_else(|e| e.into_inner()).contains(hash)
	}

	fn watched_scripts(&self) -> Vec<ScriptBuf> {
		let watched = self.watched.lock().unwrap_or_else(|e| e.into_inner()).clone();
		watched.map_or_else(Vec::new, |watched| watched.scripts())
	}

	fn room_to_scan(&self) -> bool {
		lock_headers(&self.chain).scans_waiting() < SCANS_WAITING_AT_MOST
	}
}

impl PushSink for BundleFilterSource {
	/// Fits pushed blocks onto what is held, notes the Pro's tip and fee estimates, and wakes the
	/// sync loop, which verifies them as it verifies anything. A filter that came as a first piece
	/// is not kept: the loop pulls it, in as many calls as it takes.
	fn ingest(&self, push: &WireBlockUpdates) -> Result<Option<BlockId>, ChainProviderError> {
		let pulled = decode_reply(push)?;
		let held = {
			let mut state = self.state();
			state.merge_pushed(pulled.run);
			state.heard_tip = Some((pulled.tip, Instant::now()));
			if let Some(fee) = pulled.fee {
				state.fee = Some((fee, Instant::now()));
			}
			state.held.last().map(|b| BlockId { height: b.height, hash: b.hash })
		};
		self.wake.notify_one();
		Ok(held.or_else(|| lock_headers(&self.chain).tip()))
	}

	fn verified_tip(&self) -> Option<BlockId> {
		lock_headers(&self.chain).tip()
	}

	fn note_tip(&self, tip: BlockId) {
		let moved = {
			let mut state = self.state();
			let moved = state.heard_tip.map_or(true, |(known, _)| known != tip);
			state.heard_tip = Some((tip, Instant::now()));
			moved
		};
		if moved {
			self.wake.notify_one();
		}
	}

	fn forget_tip(&self) {
		self.state().heard_tip = None;
		self.wake.notify_one();
	}

	fn target_changed(&self) {
		*self.state() = BundleState::default();
		self.push_trusted.store(false, Ordering::Release);
		self.wake.notify_one();
	}

	fn set_push_trusted(&self, trusted: bool) {
		self.push_trusted.store(trusted, Ordering::Release);
	}

	fn rewind_filters(&self, from: BlockId) {
		lock_headers(&self.chain).request_rewind(from);
		self.state().held.clear();
		self.wake.notify_one();
	}

	fn verified_chain(&self) -> SharedHeaderChain {
		Arc::clone(&self.chain)
	}

	fn set_sync_observer(&self, observer: Weak<dyn SyncObserver>) {
		*self.observer.lock().unwrap_or_else(|e| e.into_inner()) = Some(observer);
	}

	/// The median of the blocks read whose hash is still the one on the chain.
	fn local_fee_rate(&self) -> Option<u64> {
		let cache = self.block_fees.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
		let cached = cache.lock().unwrap_or_else(|e| e.into_inner()).clone();
		let chain = lock_headers(&self.chain);
		let mut rates: Vec<u64> = cached
			.iter()
			.filter(|(height, (hash, _))| chain.hash(**height) == Some(*hash))
			.map(|(_, (_, rate))| rate.to_sat_per_kwu())
			.collect();
		drop(chain);
		if rates.len() < LOCAL_FEE_MIN_SAMPLES {
			return None;
		}
		rates.sort_unstable();
		rates.get(rates.len() / 2).copied()
	}
}

#[cfg(test)]
pub(crate) mod test_support {
	//! A Pro node for a [`BundleFilterSource`] to talk to: a [`RawChainServer`] over a filter
	//! source, behind a [`BundleTransport`] that counts its calls and can be told to refuse them.

	use std::collections::HashMap;

	use super::*;
	use crate::chain::provider::{WireSubscribeRequest, WireSubscribeResponse};
	use crate::chain::raw_serve::{RawChainServer, RawServeLimits};
	use crate::chain::subscription::SubscriptionRegistry;
	use crate::Error;

	pub(crate) fn now_unix() -> u64 {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	}

	pub(crate) struct ServerTransport {
		pub(crate) server: RawChainServer,
		/// When set, every call fails with this.
		pub(crate) refuse: Mutex<Option<ChainProviderError>>,
		calls: Mutex<HashMap<&'static str, usize>>,
		/// The biggest JSON reply, in bytes.
		pub(crate) largest_reply: Mutex<usize>,
		/// Serves `subscribe` from this, as if the caller were this node. Otherwise an older Pro,
		/// which does not know the route.
		pub(crate) registry: Mutex<Option<(Arc<SubscriptionRegistry>, String)>>,
	}

	impl ServerTransport {
		pub(crate) fn new(source: Arc<dyn FilterSource>) -> Self {
			Self::with_limits(source, RawServeLimits::default())
		}

		pub(crate) fn with_limits(source: Arc<dyn FilterSource>, limits: RawServeLimits) -> Self {
			Self {
				server: RawChainServer::with_limits(
					source,
					limits,
					Arc::new(Logger::new_log_facade()),
				),
				refuse: Mutex::new(None),
				calls: Mutex::new(HashMap::new()),
				largest_reply: Mutex::new(0),
				registry: Mutex::new(None),
			}
		}

		pub(crate) fn calls(&self, method: &'static str) -> usize {
			self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
		}

		pub(crate) fn refuse_with(&self, e: Option<ChainProviderError>) {
			*self.refuse.lock().unwrap() = e;
		}

		/// What the Pro would push for the blocks at `heights`.
		pub(crate) async fn push(&self, heights: std::ops::RangeInclusive<u32>) -> WireBlockUpdates {
			let mut updates = Vec::new();
			for height in heights {
				updates.push(self.server.serve_block_update(height).await.expect("a bundle"));
			}
			let tip = self.server.serve_tip().await.expect("a tip").tip;
			WireBlockUpdates {
				version: CHAIN_WIRE_VERSION,
				tip,
				updates,
				more: false,
				lease_until: None,
			}
		}

		fn enter(&self, method: &'static str) -> Result<(), ChainProviderError> {
			*self.calls.lock().unwrap().entry(method).or_default() += 1;
			match self.refuse.lock().unwrap().clone() {
				Some(e) => Err(e),
				None => Ok(()),
			}
		}
	}

	fn wire_error(e: Error) -> ChainProviderError {
		match e {
			Error::ChainServeNotOnBestChain => {
				ChainProviderError::Refused("failed: not on best chain".into())
			},
			other => ChainProviderError::Unreachable(other.to_string()),
		}
	}

	#[async_trait]
	impl BundleTransport for ServerTransport {
		fn name(&self) -> String {
			"test-pro".into()
		}

		async fn subscribe(
			&self, req: WireSubscribeRequest,
		) -> Result<WireSubscribeResponse, ChainProviderError> {
			self.enter("subscribe")?;
			let registry = self.registry.lock().unwrap().clone();
			let Some((registry, caller)) = registry else {
				return Err(ChainProviderError::Refused("unsupported: no such route".into()));
			};
			registry.set_tip(self.server.serve_tip().await.map_err(wire_error)?.tip);
			Ok(registry.subscribe(&caller, &req, now_unix()))
		}

		async fn since(
			&self, req: WireSinceRequest,
		) -> Result<WireBlockUpdates, ChainProviderError> {
			self.enter("since")?;
			assert!(req.max_blocks <= MAX_UPDATES_PER_SINCE);
			let reply = self.server.serve_since(&req).await.map_err(wire_error)?;
			let size = serde_json::to_vec(&reply).unwrap().len();
			let mut largest = self.largest_reply.lock().unwrap();
			*largest = (*largest).max(size);
			Ok(reply)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::test_support::ServerTransport;
	use super::*;

	use crate::chain::cbf::source_sync::new_shared_header_chain;
	use crate::chain::cbf::source_sync::test_support::FakeSource;
	use crate::chain::provider::{WireBlockId, WireFeeTarget, MAX_PEER_REPLY_BYTES};
	use crate::chain::raw_serve::RawServeLimits;
	use crate::chain::wire_convert::block_update_to_wire;

	/// A chain of 30 blocks the "node" has verified through height 20, a source over a Pro on an
	/// identical chain, and the Pro's transport.
	async fn setup(tuning: BundleTuning) -> (BundleFilterSource, Arc<FakeSource>, Arc<ServerTransport>) {
		let pro = Arc::new(FakeSource::new(30, &[]));
		let transport = Arc::new(ServerTransport::new(Arc::clone(&pro) as Arc<dyn FilterSource>));
		let (source, node) = over(tuning, Arc::clone(&transport)).await;
		(source, node, transport)
	}

	async fn over(
		tuning: BundleTuning, transport: Arc<ServerTransport>,
	) -> (BundleFilterSource, Arc<FakeSource>) {
		let node = Arc::new(FakeSource::new(30, &[]));
		let chain = new_shared_header_chain();
		{
			let headers = node.headers(0, 21).await.unwrap();
			let mut held = lock_headers(&chain);
			for header in headers {
				held.push_for_test(header);
			}
		}
		let source = BundleFilterSource::new(
			Arc::clone(&node) as Arc<dyn FilterSource>,
			transport as Arc<dyn BundleTransport>,
			chain,
			Arc::new(Notify::new()),
			tuning,
			Arc::new(Logger::new_log_facade()),
		);
		(source, node)
	}

	fn raw_calls(node: &FakeSource) -> [usize; 2] {
		["filter_headers", "filters"].map(|m| node.calls(m))
	}

	/// Headers the setup read itself, before the source existed.
	const SETUP_HEADER_READS: usize = 1;

	/// Review 3's stale pull. A `since` on its way when the node moves must not land under the next
	/// Pro's name: a liar could keep one on its way on purpose, and frame whoever comes next.
	#[tokio::test]
	async fn a_pull_on_its_way_when_the_node_moves_is_not_taken() {
		struct MovesWhileAsked(Arc<ServerTransport>, Arc<FakeSource>);
		#[async_trait]
		impl BundleTransport for MovesWhileAsked {
			fn name(&self) -> String {
				"moves".into()
			}
			async fn subscribe(
				&self, req: crate::chain::provider::WireSubscribeRequest,
			) -> Result<crate::chain::provider::WireSubscribeResponse, ChainProviderError> {
				self.0.subscribe(req).await
			}
			async fn since(
				&self, req: WireSinceRequest,
			) -> Result<WireBlockUpdates, ChainProviderError> {
				let reply = self.0.since(req).await;
				self.1.next_epoch();
				reply
			}
		}
		let pro = Arc::new(FakeSource::new(30, &[]));
		let inner = Arc::new(ServerTransport::new(Arc::clone(&pro) as Arc<dyn FilterSource>));
		let node = Arc::new(FakeSource::new(30, &[]));
		let chain = new_shared_header_chain();
		let headers = node.headers(0, 21).await.unwrap();
		{
			let mut held = lock_headers(&chain);
			for header in headers {
				held.push_for_test(header);
			}
		}
		let source = BundleFilterSource::new(
			Arc::clone(&node) as Arc<dyn FilterSource>,
			Arc::new(MovesWhileAsked(inner, Arc::clone(&node))),
			chain,
			Arc::new(Notify::new()),
			BundleTuning::default(),
			Arc::new(Logger::new_log_facade()),
		);
		let from = BlockId { height: 20, hash: node.block_at(20).block_hash() };
		assert_eq!(source.pull(from).await, None, "the answer is thrown away");
		assert!(source.state().held.is_empty());
	}

	#[tokio::test]
	async fn the_tip_is_always_polled_and_never_pulls() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		for _ in 0..5 {
			assert_eq!(source.tip().await.unwrap(), node.tip_id());
		}
		assert_eq!(node.calls("tip"), 5);
		assert_eq!(transport.calls("since"), 0);
	}

	#[tokio::test]
	async fn the_tip_goes_unasked_only_while_pushes_are_trusted_and_recently_heard() {
		let tuning = BundleTuning { pushed_tip_max_age: Duration::from_millis(40), ..Default::default() };
		let (source, node, transport) = setup(tuning).await;
		let heard = BlockId { height: 25, hash: node.block_at(25).block_hash() };

		// Heard, but delivery is pull.
		source.note_tip(heard);
		assert_eq!(source.tip().await.unwrap(), node.tip_id());
		assert_eq!(node.calls("tip"), 1);

		// Trusted: from memory, nothing on the wire.
		source.set_push_trusted(true);
		assert_eq!(source.tip().await.unwrap(), heard);
		assert_eq!(node.calls("tip"), 1);
		assert_eq!(transport.calls("since"), 0);

		// Trusted, with silence past the bound: the driver must have stopped, so ask.
		tokio::time::sleep(Duration::from_millis(50)).await;
		assert_eq!(source.tip().await.unwrap(), node.tip_id());
		assert_eq!(node.calls("tip"), 2);

		// Trusted, but nothing known.
		source.forget_tip();
		assert_eq!(source.tip().await.unwrap(), node.tip_id());
		assert_eq!(node.calls("tip"), 3);

		// Heard again, then the session goes suspect: the wire again, so an outage shows at once.
		source.note_tip(heard);
		assert_eq!(source.tip().await.unwrap(), heard);
		source.set_push_trusted(false);
		assert_eq!(source.tip().await.unwrap(), node.tip_id());
	}

	#[test]
	fn the_pushed_tip_outlives_the_ten_minute_probe_but_not_by_much() {
		assert_eq!(BUNDLE_PUSHED_TIP_MAX_AGE.as_secs(), 11 * 60);
		assert!(BUNDLE_PUSHED_TIP_MAX_AGE > crate::chain::session::machine::NO_SIGNAL_PROBE_AFTER);
	}

	#[tokio::test]
	async fn a_push_is_held_and_answers_every_question_with_no_call() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		let push = transport.push(21..=22).await;
		let held = source.ingest(&push).unwrap();
		assert_eq!(held.map(|b| b.height), Some(22), "the ack's applied tip");
		let headers = source.headers(21, 2).await.unwrap();
		assert_eq!(headers.len(), 2);
		assert_eq!(headers[0].block_hash(), node.block_at(21).block_hash());
		assert_eq!(transport.calls("since"), 0);
		assert_eq!(raw_calls(&node), [0, 0]);
	}

	#[tokio::test]
	async fn pushes_join_up_a_gap_starts_again_and_another_branch_clears() {
		let (source, _node, transport) = setup(BundleTuning::default()).await;
		source.ingest(&transport.push(21..=21).await).unwrap();
		source.ingest(&transport.push(22..=23).await).unwrap();
		source.ingest(&transport.push(23..=23).await).unwrap();
		assert_eq!(
			source.state().held.iter().map(|b| b.height).collect::<Vec<_>>(),
			vec![21, 22, 23],
			"a repeat changes nothing"
		);
		// A gap: what is held no longer links up.
		source.ingest(&transport.push(26..=26).await).unwrap();
		assert_eq!(source.state().held.iter().map(|b| b.height).collect::<Vec<_>>(), vec![26]);

		// Another block at a height held.
		let other = Arc::new(FakeSource::new(27, &[]));
		other.reorg(1, 1);
		let other_transport = ServerTransport::new(other as Arc<dyn FilterSource>);
		let applied = source.ingest(&other_transport.push(26..=26).await).unwrap();
		assert!(source.state().held.is_empty());
		assert_eq!(
			applied.map(|b| b.height),
			Some(20),
			"nothing held: the verified tip, for the ack"
		);
	}

	#[tokio::test]
	async fn a_push_is_never_applied_before_it_is_verified_and_garbage_is_refused() {
		let (source, _node, transport) = setup(BundleTuning::default()).await;
		let mut bad = transport.push(21..=22).await;
		bad.updates.swap(0, 1);
		assert!(matches!(source.ingest(&bad), Err(ChainProviderError::Malformed(_))));
		assert!(source.state().held.is_empty());
		let mut other_version = transport.push(21..=21).await;
		other_version.version += 1;
		assert!(source.ingest(&other_version).is_err());
	}

	#[tokio::test]
	async fn a_new_target_forgets_everything_the_old_one_said() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		source.ingest(&transport.push(21..=21).await).unwrap();
		source.set_push_trusted(true);
		source.state().retry_at = Some(Instant::now() + Duration::from_secs(3600));
		source.target_changed();
		{
			let state = source.state();
			assert!(state.held.is_empty());
			assert!(state.heard_tip.is_none());
			assert!(state.retry_at.is_none(), "the new Pro owes nothing for the old one's failures");
		}
		assert_eq!(source.tip().await.unwrap(), node.tip_id(), "and trust starts over");
	}

	#[tokio::test]
	async fn one_pull_answers_headers_filter_headers_and_filters() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		let headers = source.headers(21, 9).await.unwrap();
		assert_eq!(headers.len(), 9);
		assert_eq!(headers[0].prev_blockhash, node.block_at(20).block_hash());
		assert_eq!(transport.calls("since"), 1);
		assert_eq!(node.calls("headers"), SETUP_HEADER_READS, "no raw read");
	}

	#[tokio::test]
	async fn headers_below_the_verified_tip_never_pull() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		source.headers(10, 2).await.unwrap();
		assert_eq!(transport.calls("since"), 0);
		assert_eq!(node.calls("headers"), SETUP_HEADER_READS + 1, "the fork search reads raw");
	}

	#[tokio::test]
	async fn an_unsupported_refusal_uses_the_raw_routes_and_asks_again_after_the_backoff() {
		let tuning = BundleTuning {
			unsupported_retry_after: Duration::from_millis(200),
			..BundleTuning::default()
		};
		let (source, node, transport) = setup(tuning).await;
		transport
			.refuse_with(Some(ChainProviderError::Refused("unsupported: unknown route".into())));
		for _ in 0..3 {
			assert_eq!(source.headers(21, 2).await.unwrap().len(), 2);
		}
		assert_eq!(transport.calls("since"), 1, "not asked again inside the backoff");
		assert_eq!(node.calls("headers"), SETUP_HEADER_READS + 3, "raw instead");

		// The Pro answers now (an app that was restarting), but the backoff still holds.
		transport.refuse_with(None);
		source.headers(21, 2).await.unwrap();
		assert_eq!(transport.calls("since"), 1);

		// After it, the bundles are asked for again.
		tokio::time::sleep(Duration::from_millis(250)).await;
		source.headers(21, 2).await.unwrap();
		assert_eq!(transport.calls("since"), 2);
		assert_eq!(node.calls("headers"), SETUP_HEADER_READS + 4, "not read raw once it answered");
	}

	#[test]
	fn the_backoffs_are_two_minutes_and_half_an_hour_by_default() {
		let tuning = BundleTuning::default();
		assert_eq!(tuning.unsupported_retry_after, Duration::from_secs(30 * 60));
		assert_eq!(tuning.retry_after, Duration::from_secs(2 * 60));
		assert_eq!(tuning.fee_max_age, Duration::from_secs(30 * 60));
	}

	#[tokio::test]
	async fn a_failed_pull_uses_the_raw_routes_and_waits_before_asking_again() {
		let tuning =
			BundleTuning { retry_after: Duration::from_millis(200), ..BundleTuning::default() };
		let (source, node, transport) = setup(tuning).await;
		transport.refuse_with(Some(ChainProviderError::Unreachable("down".into())));
		source.headers(21, 1).await.unwrap();
		source.headers(21, 1).await.unwrap();
		assert_eq!(transport.calls("since"), 1, "not asked again inside the wait");
		assert_eq!(node.calls("headers"), SETUP_HEADER_READS + 2);

		transport.refuse_with(None);
		tokio::time::sleep(Duration::from_millis(250)).await;
		source.headers(21, 1).await.unwrap();
		assert_eq!(transport.calls("since"), 2);
		assert_eq!(node.calls("headers"), SETUP_HEADER_READS + 2);
	}

	/// A verified tip off the Pro's chain is what the reorg handling is for, not a Pro at fault:
	/// the next pull, from the fork, must not wait.
	#[tokio::test]
	async fn a_from_off_the_best_chain_leaves_no_backoff() {
		let (source, _node, transport) = setup(BundleTuning::default()).await;
		transport.refuse_with(Some(ChainProviderError::Refused(
			"chain.since refused by 02pro: {\"error\":\"failed: not on best chain\"}".into(),
		)));
		source.headers(21, 1).await.unwrap();
		source.headers(21, 1).await.unwrap();
		assert_eq!(transport.calls("since"), 2);
	}

	#[tokio::test]
	async fn served_filters_are_forgotten_so_a_catch_up_holds_one_reply() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		for header in source.headers(21, 9).await.unwrap().into_iter().take(5) {
			lock_headers(&source.chain).push_for_test(header);
		}
		let stop = node.block_at(25).block_hash();
		source.filter_headers(21, stop).await.unwrap();
		source.filters(21, stop).await.unwrap();
		let held: Vec<u32> = source.state().held.iter().map(|b| b.height).collect();
		assert_eq!(held, (26..=29).collect::<Vec<_>>());
		assert_eq!(transport.calls("since"), 1);
		assert_eq!(raw_calls(&node), [0, 0]);
	}

	/// An uncached filter span pulls from the block below it, as a retry after a failure does.
	#[tokio::test]
	async fn a_filter_span_not_held_pulls_from_the_block_below_it() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		let stop = node.block_at(15).block_hash();
		let served = source.filters(11, stop).await.unwrap();
		assert_eq!(served[0].height, 11);
		assert_eq!(transport.calls("since"), 1);
		assert_eq!(raw_calls(&node), [0, 0]);
	}

	#[tokio::test]
	async fn the_estimates_a_bundle_carries_are_used_only_while_fresh() {
		let tuning =
			BundleTuning { fee_max_age: Duration::from_millis(100), ..BundleTuning::default() };
		let (source, node, transport) = setup(tuning).await;
		assert!(source.fresh_fee_estimates().is_none());
		let fee = WireFeeEstimates {
			version: CHAIN_WIRE_VERSION,
			targets: vec![WireFeeTarget { target: "anchor_channel".into(), sat_per_kwu: 500 }],
		};
		let mut reply = transport
			.server
			.serve_since(&WireSinceRequest {
				version: CHAIN_WIRE_VERSION,
				from: WireBlockId {
					height: 20,
					hash: node.block_at(20).block_hash().to_string(),
				},
				max_blocks: 2,
				filter_offset: 0,
			})
			.await
			.unwrap();
		reply.updates.last_mut().unwrap().fee_estimates = Some(fee.clone());
		let pulled = decode_reply(&reply).unwrap();
		assert_eq!(pulled.fee, Some(fee.clone()));
		source.state().fee = Some((fee.clone(), Instant::now()));
		assert_eq!(source.fresh_fee_estimates(), Some(fee));
		tokio::time::sleep(Duration::from_millis(150)).await;
		assert_eq!(source.fresh_fee_estimates(), None);
	}

	#[tokio::test]
	async fn a_reply_that_is_not_one_linked_run_is_refused() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		let reply = |max_blocks| WireSinceRequest {
			version: CHAIN_WIRE_VERSION,
			from: WireBlockId { height: 20, hash: node.block_at(20).block_hash().to_string() },
			max_blocks,
			filter_offset: 0,
		};
		let mut gapped = transport.server.serve_since(&reply(3)).await.unwrap();
		gapped.updates.remove(1);
		assert!(matches!(decode_reply(&gapped), Err(ChainProviderError::Malformed(_))));

		let mut lying = transport.server.serve_since(&reply(1)).await.unwrap();
		lying.updates[0].block_hash = node.block_at(5).block_hash().to_string();
		assert!(matches!(decode_reply(&lying), Err(ChainProviderError::Malformed(_))));
		assert!(source.state().held.is_empty());
	}

	#[test]
	fn a_bundle_round_trips_through_the_wire() {
		use crate::chain::cbf::source_sync::test_support::filter_of;
		use bitcoin::hashes::Hash;
		let source = FakeSource::new(5, &[]);
		let block = source.block_at(3);
		let filter = filter_of(&block);
		let previous = bitcoin::bip158::FilterHeader::all_zeros();
		let bundle = BlockBundle {
			height: 3,
			hash: block.header.block_hash(),
			header: block.header,
			previous_filter_header: previous,
			filter_header: filter.filter_header(&previous),
			filter,
		};
		let wire = block_update_to_wire(&bundle, None);
		let json = serde_json::to_string(&wire).unwrap();
		assert!(!json.contains("fee_estimates"), "absent, not null");
		assert!(!json.contains("filter_total"), "absent on a whole filter");
		assert!(!json.contains("filter_offset"), "absent on a whole filter");
		let back: crate::chain::provider::WireBlockUpdate = serde_json::from_str(&json).unwrap();
		assert_eq!(block_update_from_wire(&back).unwrap(), bundle);
		assert!(bundle.is_self_consistent());
	}

	/// The host adds the caller's node id to every request it hands the serving app, and an
	/// asker that knows nothing of pieces sends no offset.
	#[test]
	fn requests_tolerate_fields_the_host_adds() {
		let since: WireSinceRequest = serde_json::from_str(
			r#"{"version":1,"from":{"height":5,"hash":"00"},"max_blocks":10,"caller_node_id":"02ab"}"#,
		)
		.unwrap();
		assert_eq!(since.max_blocks, 10);
		assert_eq!(since.filter_offset, 0);
	}

	/// A filter larger than one reply arrives through more calls, every reply under the cap,
	/// and is whole — its filter header commits to it — when the sync loop reads it.
	#[tokio::test]
	async fn a_filter_larger_than_one_reply_arrives_in_pieces() {
		use crate::chain::raw_serve::MockFilterSource;
		let mut big = MockFilterSource::new(30, 10);
		big.filter_bytes = Some(MAX_PEER_REPLY_BYTES + 200 * 1024);
		let pro = Arc::new(big);
		let transport = Arc::new(ServerTransport::with_limits(
			Arc::clone(&pro) as Arc<dyn FilterSource>,
			RawServeLimits::default(),
		));
		let node = Arc::new(FakeSource::new(1, &[]));
		let chain = new_shared_header_chain();
		{
			let mut held = lock_headers(&chain);
			for block in &pro.blocks[..=20] {
				held.push_for_test(block.header);
			}
		}
		let source = BundleFilterSource::new(
			node as Arc<dyn FilterSource>,
			Arc::clone(&transport) as Arc<dyn BundleTransport>,
			Arc::clone(&chain),
			Arc::new(Notify::new()),
			BundleTuning::default(),
			Arc::new(Logger::new_log_facade()),
		);

		let headers = source.headers(21, 2).await.unwrap();
		assert_eq!(headers.len(), 1, "the first reply stops at the oversized block");
		assert!(transport.calls("since") >= 4, "{} calls", transport.calls("since"));
		let largest = *transport.largest_reply.lock().unwrap();
		assert!(largest < MAX_PEER_REPLY_BYTES, "{} bytes", largest);

		lock_headers(&chain).push_for_test(headers[0]);
		let stop = pro.blocks[21].block_hash();
		let filters = source.filters(21, stop).await.unwrap();
		assert_eq!(filters.len(), 1);
		assert_eq!(filters[0].filter, pro.filter(21));
		assert_eq!(filters[0].filter.content.len(), MAX_PEER_REPLY_BYTES + 200 * 1024);
	}

	/// A Pro that names a filter too large to hold, or sends pieces that do not continue it, is
	/// a failed pull: the node is on the raw routes, and holds nothing.
	#[tokio::test]
	async fn pieces_that_do_not_add_up_are_a_failed_pull() {
		let (source, node, transport) = setup(BundleTuning::default()).await;
		let mut reply = transport
			.server
			.serve_since(&WireSinceRequest {
				version: CHAIN_WIRE_VERSION,
				from: WireBlockId {
					height: 20,
					hash: node.block_at(20).block_hash().to_string(),
				},
				max_blocks: 1,
				filter_offset: 0,
			})
			.await
			.unwrap();
		reply.updates[0].filter_total = Some(MAX_ASSEMBLED_FILTER_BYTES + 1);
		assert!(matches!(decode_reply(&reply), Err(ChainProviderError::Malformed(_))));
		assert!(source.state().held.is_empty());
	}
}
