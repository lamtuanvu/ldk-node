// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A hybrid node's [`FilterSource`] that pulls one bundle per new block from its Pro node.
//!
//! Over the raw routes alone, a new block costs the Pro node three questions after the tip
//! poll that noticed it: its headers, filter headers and filters. A `chain.since` answers all
//! three, plus the Pro's fee estimates, in one reply:
//!
//! ```text
//!   Pro node                                    this node
//!   ────────                                    ─────────
//!   chain.tip     ◄──────────────────────────── tip(): every poll, unchanged
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
//! * `tip()`: always the inner source. The poll interval is the sync loop's.
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

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use bdk_chain::BlockId;

use bitcoin::bip158::BlockFilter;
use bitcoin::block::Header;
use bitcoin::{Block, BlockHash};

use crate::chain::cbf::source::{FilterHeaders, FilterSource, IndexedFilter, SourceError};
use crate::chain::cbf::source_sync::{lock_headers, SharedHeaderChain};
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

/// Bound on a `since`: above the app's 45 s serve timeout.
const SINCE_TIMEOUT: Duration = Duration::from_secs(50);

/// The largest filter a pull assembles from pieces: well past what any block can carry, so a
/// Pro cannot make this node hold more by naming a larger total.
const MAX_ASSEMBLED_FILTER_BYTES: u32 = 8 * 1024 * 1024;

/// The reason a Pro gives for a `from` off its best chain. Not a failure: the reorg handling
/// over the raw routes takes it from there, and the next pull continues from the fork.
const NOT_ON_BEST_CHAIN: &str = "not on best chain";

/// The knobs of a [`BundleFilterSource`]; shortened in the tests.
#[derive(Clone, Debug)]
pub(crate) struct BundleTuning {
	pub(crate) retry_after: Duration,
	pub(crate) unsupported_retry_after: Duration,
	pub(crate) since_timeout: Duration,
	pub(crate) fee_max_age: Duration,
}

impl Default for BundleTuning {
	fn default() -> Self {
		Self {
			retry_after: BUNDLE_RETRY_AFTER,
			unsupported_retry_after: BUNDLE_UNSUPPORTED_RETRY_AFTER,
			since_timeout: SINCE_TIMEOUT,
			fee_max_age: BUNDLE_FEE_MAX_AGE,
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
}

impl BundleState {
	fn get(&self, height: u32) -> Option<&Arc<BlockBundle>> {
		let base = self.held.first()?.height;
		self.held.get(height.checked_sub(base)? as usize)
	}
}

/// See the module docs.
pub(crate) struct BundleFilterSource {
	inner: Arc<dyn FilterSource>,
	transport: Arc<dyn BundleTransport>,
	/// The sync loop's verified header chain: where the node is.
	chain: SharedHeaderChain,
	state: Mutex<BundleState>,
	tuning: BundleTuning,
	logger: Arc<Logger>,
}

impl BundleFilterSource {
	pub(crate) fn new(
		inner: Arc<dyn FilterSource>, transport: Arc<dyn BundleTransport>,
		chain: SharedHeaderChain, tuning: BundleTuning, logger: Arc<Logger>,
	) -> Self {
		Self { inner, transport, chain, state: Mutex::new(BundleState::default()), tuning, logger }
	}

	fn state(&self) -> MutexGuard<'_, BundleState> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// The newest fee estimates a bundle carried, while they are fresh.
	pub(crate) fn fresh_fee_estimates(&self) -> Option<WireFeeEstimates> {
		let state = self.state();
		let (fee, at) = state.fee.as_ref()?;
		(at.elapsed() < self.tuning.fee_max_age).then(|| fee.clone())
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
		let pulled = match self.fetch(from).await {
			Ok(pulled) => pulled,
			Err(e) => {
				self.failed(&e);
				return None;
			},
		};
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

	/// See [`FilterSource::headers_come_with_filters`]: one reply holds both.
	fn headers_come_with_filters(&self) -> bool {
		true
	}

	async fn tip(&self) -> Result<BlockId, SourceError> {
		self.inner.tip().await
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

#[cfg(test)]
pub(crate) mod test_support {
	//! A Pro node for a [`BundleFilterSource`] to talk to: a [`RawChainServer`] over a filter
	//! source, behind a [`BundleTransport`] that counts its calls and can be told to refuse them.

	use std::collections::HashMap;

	use super::*;
	use crate::chain::raw_serve::{RawChainServer, RawServeLimits};
	use crate::Error;

	pub(crate) struct ServerTransport {
		pub(crate) server: RawChainServer,
		/// When set, every call fails with this.
		pub(crate) refuse: Mutex<Option<ChainProviderError>>,
		calls: Mutex<HashMap<&'static str, usize>>,
		/// The biggest JSON reply, in bytes.
		pub(crate) largest_reply: Mutex<usize>,
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
			}
		}

		pub(crate) fn calls(&self, method: &'static str) -> usize {
			self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
		}

		pub(crate) fn refuse_with(&self, e: Option<ChainProviderError>) {
			*self.refuse.lock().unwrap() = e;
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
