// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Checks what this node took from the active Pro against a second Pro's filter headers, and finds
//! what a difference hid.
//!
//! Nothing in a block header commits to a filter, so one Pro can serve a filter chain that holds
//! together and leaves out whatever it likes: the output paying this node, the spend of its
//! channel. Two Pros differing is how that shows. It does not show who: with two, and anyone free
//! to tag themselves a Pro, counting opinions would hand one attacker the eviction of an honest
//! Pro. So BIP157's rule: find the first block they differ at, take the block, which proof of work
//! vouches for whoever served it, and hold each Pro's own filter against it.
//!
//! # What a block proves
//!
//! BIP158 puts two things in a basic filter: the scripts a block's outputs pay to, and the scripts
//! its inputs spend. **A block carries the first and not the second**, and a client with no UTXO
//! set and no undo data cannot get the second in any way it could check. A script guessed from a
//! witness or a scriptSig would not do: a taproot script path or an unknown witness version can be
//! built to look like anything, and that guess would convict the honest filter. So the judgement
//! is what is certain and no more:
//!
//! * A filter that does not hash to the header its Pro claimed for it: proven.
//! * A filter that lacks a script the block's outputs pay to: proven.
//! * What this node took from this Pro, against what this Pro says now of the same block: proven.
//!   One block by hash has one filter header, so it said two things ([`LieKind::AnswerChanged`]).
//! * Otherwise nothing is proven, and nobody is dropped. An honest filter passes all of these,
//!   always, so **an honest Pro cannot be convicted**, whatever anyone else serves.
//!
//! What this node watches is no proof either. The script of an inbound channel's funding output is
//! paired with an outpoint the peer named in `funding_created`, unchecked until the funding
//! confirms, so a stranger can pair the channel's script with any output it controls, spend that,
//! and honest filters for the block lack the script. A hidden spend is what the read below finds.
//!
//! # What a difference is worth without knowing who
//!
//! What this node needs is what is in those blocks, not who was right about them. A filter chain
//! differs from the first difference up, so every block from there is in doubt, and **nothing the
//! active Pro says now decides which of them get read**: it can answer the check honestly and have
//! told the sync loop otherwise, name a decoy lower down, or refuse to answer at all. So the blocks
//! come from the witness's story alone ([`first_difference`], [`read_through`]): its filter headers
//! are compared with what this node holds, without the active Pro's help; its filters from the first
//! difference up, each checked against its own filter headers, are matched against what this node
//! watches; and the blocks they match are read, whichever Pro serves them, proof of work vouching.
//! A spend of a channel's funding output is seen then whatever the active Pro's filter said, as a
//! block's inputs name the outpoints they spend, and LDK and the wallet match those themselves.
//!
//! **What this closes:** a spend hidden from this node by one Pro, however it answers afterwards,
//! with an honest Pro on the list when a check asks it. **What stays open:** only one Pro to ask (the
//! status says `no_witness`), or every Pro asked leaves out the same script: inherent to BIP157 with
//! no honest peer. And a witness's filters are believed for what they match: one matching too much
//! costs reads, one that is a liar too finds nothing, and the next witness asks again.
//!
//! The reading has a budget, a check at most [`MAX_READ_PAGES`] pages of filters, one in memory at a
//! time, and [`MAX_CONFLICT_SCANS`] blocks. It goes newest first, as a spend close to the tip has the
//! least of its delay left, a page is what a Pro's reply holds, about 15 mainnet filters, and it
//! goes on where it stopped ([`ReadSoFar`]). So one check covers more than a day of blocks wherever
//! the first difference is, and the whole chain held takes about a dozen checks.
//! [`CrossCheckReport::unread_from`] says what is left: the status and the owner's copy must not say
//! a block was read unless it was. Nobody is dropped for a difference alone: see [`super::machine`].
//!
//! # Not a lie
//!
//! Every question names a block by hash, and a filter header is a function of the chain below
//! that hash. So the same hash has one right answer, whichever Pro is asked and whenever. A Pro
//! that is behind or on another branch does not have the block and says so, which is
//! [`CrossCheckOutcome::Inconclusive`]; so is any failure to answer. Heights are never compared.
//!
//! # Cost
//!
//! One `chain.filter_headers` call to the witness, for a span of one block. See
//! [`CROSS_CHECK_INTERVAL`] for how often. Only a difference costs more: a dozen such calls to find
//! where it starts, as a filter header commits to everything below it, a filter from each Pro and a
//! block to judge, then what the reading above takes.
//!
//! [`CROSS_CHECK_INTERVAL`]: crate::chain::session::machine::CROSS_CHECK_INTERVAL

use std::future::Future;
use std::time::Duration;

use bdk_chain::BlockId;

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::block::Header;
use bitcoin::{Block, BlockHash, ScriptBuf};

use crate::chain::cbf::source::{FilterSource, SourceError, MAX_FILTERS_PER_REQUEST};
use crate::chain::session::machine::{CrossCheckOutcome, LieKind, CROSS_CHECK_BURY};

/// One block of the chain this node verified, with the filter header it took for it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldBlock {
	/// The block's hash.
	pub(crate) hash: BlockHash,
	/// The block's header, which carried the proof of work.
	pub(crate) header: Header,
	/// The filter header this node took, `None` where it has not taken one.
	pub(crate) filter_header: Option<FilterHeader>,
	/// Under which source it was taken: [`FilterSource::epoch`]. `None` for one saved by an earlier
	/// run, whose source is not known any more.
	pub(crate) taken_under: Option<u64>,
}

/// A run of the verified chain, ascending, the first of it at `base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldChain {
	/// The height of the first block in `blocks`.
	pub(crate) base: u32,
	/// The blocks.
	pub(crate) blocks: Vec<HeldBlock>,
}

/// What a cross-check needs of the sync loop that holds the chain.
pub(crate) trait HeldFilters: Send + Sync {
	/// The newest block at least `bury` below the tip with a filter header taken: its height, its
	/// hash, its filter header.
	fn check_point(&self, bury: u32) -> Option<(BlockId, FilterHeader)>;
	/// The chain held, up to `through`.
	fn held_chain(&self, through: u32) -> Option<HeldChain>;
	/// Whether `block` is the one the proof of work committed to at `height`.
	fn block_is_valid(&self, block: &Block, height: u32, header: &Header) -> bool;
	/// Hands `block`, valid at `height`, to the listeners to read for what they watch.
	fn scan_block(&self, height: u32, block: Block);
	/// Whether this block has been handed over already.
	fn scanned_already(&self, hash: &BlockHash) -> bool;
	/// The scripts a filter is matched against.
	fn watched_scripts(&self) -> Vec<ScriptBuf>;
	/// Whether another block can be handed over now. Blocks wait in memory for the sync loop to take
	/// them, and a small device holds few.
	fn room_to_scan(&self) -> bool {
		true
	}
}

/// Most pages of filters one check reads with the witness: 24 replies of at most
/// [`FILTER_BYTES_PER_REPLY`], one held at a time, about 330 blocks at 25 KB a filter.
///
/// [`FILTER_BYTES_PER_REPLY`]: crate::chain::raw_serve::FILTER_BYTES_PER_REPLY
pub(crate) const MAX_READ_PAGES: u32 = 24;

/// How many blocks' filters are asked for at a time. A Pro answers a prefix of what is asked, so
/// reading newest first takes asking near the top, and this is about a page's worth.
const READ_CHUNK: u32 = 14;

/// Most blocks read per check on the strength of a difference, past the first. A sequence of checks
/// covers more, as a block is read once.
pub(crate) const MAX_CONFLICT_SCANS: u32 = 16;

/// How far the reading has gone with one witness: every block from `low` to `high` that its filters
/// matched has been read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadSoFar {
	pub(crate) low: u32,
	pub(crate) high: u32,
}

/// What came of a check. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CrossCheckReport {
	/// How it came back.
	pub(crate) outcome: CrossCheckOutcome,
	/// The lowest block this node should scan again, if any.
	pub(crate) rewind: Option<BlockId>,
	/// The lowest block in doubt that has not been read through yet. `None` with nothing left.
	pub(crate) unread_from: Option<u32>,
	/// Where the reading got to, for the next check with this witness.
	pub(crate) read_so_far: Option<ReadSoFar>,
	/// Whether the reading got further than the last check's.
	pub(crate) progressed: bool,
}

impl CrossCheckReport {
	fn just(outcome: CrossCheckOutcome) -> Self {
		Self { outcome, rewind: None, unread_from: None, read_so_far: None, progressed: false }
	}
}

/// See the module docs. `epoch` is the active Pro's: what was taken under it, it said itself.
pub(crate) async fn cross_check<H: HeldFilters + ?Sized>(
	held: &H, active: &dyn FilterSource, witness: &dyn FilterSource, epoch: u64,
	so_far: Option<ReadSoFar>, call_timeout: Duration,
) -> CrossCheckReport {
	let Some((point, ours)) = held.check_point(CROSS_CHECK_BURY) else {
		return CrossCheckReport::just(CrossCheckOutcome::NotYet);
	};
	let told = bounded(call_timeout, witness.filter_headers(point.height, point.hash)).await;
	let Some(theirs) = told.ok().and_then(|told| told.headers.first().copied()) else {
		return CrossCheckReport::just(CrossCheckOutcome::Inconclusive);
	};
	if theirs == ours {
		return CrossCheckReport::just(CrossCheckOutcome::Agreed { height: point.height });
	}
	let interrupted = CrossCheckOutcome::Interrupted { height: point.height };
	let Some(chain) = held.held_chain(point.height).filter(|chain| !chain.blocks.is_empty()) else {
		return CrossCheckReport::just(interrupted);
	};
	// From here on what is read depends on nothing the active Pro says.
	let from = match first_difference(&chain, witness, call_timeout).await {
		Ok(Some(from)) => from,
		// The witness changed its answer between two questions: that is all this shows.
		Ok(None) => return CrossCheckReport::just(CrossCheckOutcome::Inconclusive),
		Err(_) => {
			return CrossCheckReport {
				unread_from: Some(point.height),
				read_so_far: so_far,
				..CrossCheckReport::just(interrupted)
			};
		},
	};
	let (outcome, rewind) = judge(held, &chain, from, active, witness, epoch, call_timeout)
		.await
		.unwrap_or((interrupted, None));
	if witness_convicted(&outcome) || outcome == CrossCheckOutcome::Inconclusive {
		return CrossCheckReport { rewind, ..CrossCheckReport::just(outcome) };
	}

	let read = read_through(held, &chain, from.height, active, witness, so_far, call_timeout).await;
	let unread_from = (!read.complete).then_some(from.height);
	let outcome = with_what_the_reading_proved(outcome, &read);
	let take_back = matches!(
		outcome,
		CrossCheckOutcome::HeldWasWrong { .. }
			| CrossCheckOutcome::Judged { active_lied: Some(_), .. }
	);
	CrossCheckReport {
		outcome,
		rewind: take_back.then_some(from).or(rewind),
		unread_from,
		read_so_far: read.so_far,
		progressed: read.progressed,
	}
}

fn witness_convicted(outcome: &CrossCheckOutcome) -> bool {
	matches!(outcome, CrossCheckOutcome::Judged { witness_lied: Some(_), .. })
}

/// What the blocks read showed of each Pro's filter, on top of what the check came to.
fn with_what_the_reading_proved(outcome: CrossCheckOutcome, read: &ReadThrough) -> CrossCheckOutcome {
	if read.active_lied.is_none() && read.witness_lied.is_none() {
		return outcome;
	}
	let at = |seen: Option<(LieKind, u32)>| seen.map(|(_, height)| height);
	let height = at(read.active_lied).or(at(read.witness_lied)).unwrap_or(0);
	match outcome {
		CrossCheckOutcome::Judged { height: judged, active_lied, witness_lied } => {
			CrossCheckOutcome::Judged {
				height: judged,
				active_lied: active_lied.or(read.active_lied.map(|(lie, _)| lie)),
				witness_lied: witness_lied.or(read.witness_lied.map(|(lie, _)| lie)),
			}
		},
		_ => CrossCheckOutcome::Judged {
			height,
			active_lied: read.active_lied.map(|(lie, _)| lie),
			witness_lied: read.witness_lied.map(|(lie, _)| lie),
		},
	}
}

/// Whether what the active Pro says now of `row` is not what it said when this node took it. The
/// block is named by its hash, so the two cannot both be right, and an earlier Pro cannot be
/// blamed. What an earlier run saved has no source known.
fn it_changed_its_answer(row: &HeldBlock, says: &FilterHeader, epoch: u64) -> bool {
	row.taken_under == Some(epoch) && row.filter_header.map_or(false, |took| took != *says)
}

/// What a Pro says of one block: the filter header below it and its own.
async fn one_row(
	source: &dyn FilterSource, at: BlockId, call_timeout: Duration,
) -> Result<(FilterHeader, FilterHeader), SourceError> {
	let told = bounded(call_timeout, source.filter_headers(at.height, at.hash)).await?;
	let says = told.headers.first().copied();
	says.map(|says| (told.previous, says))
		.ok_or_else(|| SourceError::unavailable("no filter header in the answer"))
}

/// What the two Pros say of `from`, the first block this node holds otherwise than the witness.
/// `None` when a Pro did not answer what it takes.
async fn judge<H: HeldFilters + ?Sized>(
	held: &H, chain: &HeldChain, from: BlockId, active: &dyn FilterSource,
	witness: &dyn FilterSource, epoch: u64, call_timeout: Duration,
) -> Option<(CrossCheckOutcome, Option<BlockId>)> {
	let height = from.height;
	let index = (height - chain.base) as usize;
	let row = &chain.blocks[index];
	let (witness_previous, witness_says) = one_row(witness, from, call_timeout).await.ok()?;
	let (active_previous, active_says) = one_row(active, from, call_timeout).await.ok()?;
	let judged = |height, active_lied, witness_lied| CrossCheckOutcome::Judged {
		height,
		active_lied,
		witness_lied,
	};
	let below = index.checked_sub(1).map(|below| &chain.blocks[below]);
	if let Some(took) = below.and_then(|below| below.filter_header) {
		// `first_difference` just heard this from the witness.
		if witness_previous != took {
			return Some((judged(height, None, Some(LieKind::BrokenFilterHeaderChain)), None));
		}
		if active_previous != took && below.map_or(false, |b| it_changed_its_answer(b, &active_previous, epoch)) {
			return Some((judged(height - 1, Some(LieKind::AnswerChanged), None), Some(from)));
		}
	}
	if witness_previous != active_previous {
		// They part below what can be named here.
		return Some((judged(height, None, None), None));
	}
	if active_says == witness_says {
		if row.filter_header == Some(active_says) {
			// What this node holds is what both say: the witness has just said something else of it.
			// All that shows is the witness, and no rescan or reading is owed to it.
			return Some((CrossCheckOutcome::Inconclusive, None));
		}
		// Both say the same. What this node holds is not that: either it came from an earlier Pro
		// and these two are not to blame, or it came from this one, which has now said both.
		let outcome = if it_changed_its_answer(row, &active_says, epoch) {
			judged(height, Some(LieKind::AnswerChanged), None)
		} else {
			CrossCheckOutcome::HeldWasWrong { height }
		};
		return Some((outcome, Some(from)));
	}
	let changed = it_changed_its_answer(row, &active_says, epoch);
	let claims = Claims { previous: witness_previous, active: active_says, witness: witness_says };
	let Some((active_lied, witness_lied)) =
		hold_to_block(held, height, row, &claims, active, witness, call_timeout).await
	else {
		return Some((CrossCheckOutcome::Interrupted { height }, None));
	};
	let active_lied = active_lied.or(changed.then_some(LieKind::AnswerChanged));
	Some((judged(height, active_lied, witness_lied), active_lied.map(|_| from)))
}

/// What the two Pros say about the block they part at.
struct Claims {
	previous: FilterHeader,
	active: FilterHeader,
	witness: FilterHeader,
}

/// Each Pro's own filter for the block, against its claim and against the block. What each was
/// caught at, active first, or `None` when a Pro did not answer what it takes.
async fn hold_to_block<H: HeldFilters + ?Sized>(
	held: &H, height: u32, row: &HeldBlock, claims: &Claims, active: &dyn FilterSource,
	witness: &dyn FilterSource, call_timeout: Duration,
) -> Option<(Option<LieKind>, Option<LieKind>)> {
	let witness_filter = read_filter(witness, height, row.hash, call_timeout).await?;
	let active_filter = read_filter(active, height, row.hash, call_timeout).await?;
	let mut witness_lied = hash_lie(&witness_filter, &claims.previous, &claims.witness);
	let mut active_lied = hash_lie(&active_filter, &claims.previous, &claims.active);
	let judged_by_hash = witness_lied.is_some() && active_lied.is_some();
	match read_block(held, height, row, active, witness, call_timeout).await {
		Some(block) => {
			witness_lied = witness_lied.or_else(|| block_lie(&witness_filter, &row.hash, &block));
			active_lied = active_lied.or_else(|| block_lie(&active_filter, &row.hash, &block));
			// Whatever either filter says, and whoever is right about it.
			if !held.scanned_already(&row.hash) {
				held.scan_block(height, block);
			}
		},
		None if judged_by_hash => {},
		None => return None,
	}
	Some((active_lied, witness_lied))
}

/// The lowest block whose filter header this node took and `source` says otherwise of, asked of it
/// alone. `None` when it says otherwise of nothing. A filter header commits to everything below it,
/// so where two chains differ they differ all the way up, and halving finds it at a question per
/// doubling of the chain, however long that is and however little a Pro's replies hold.
pub(crate) async fn first_difference(
	chain: &HeldChain, source: &dyn FilterSource, call_timeout: Duration,
) -> Result<Option<BlockId>, SourceError> {
	let rows: Vec<(u32, &HeldBlock, FilterHeader)> = chain
		.blocks
		.iter()
		.enumerate()
		.filter_map(|(i, row)| Some((chain.base + i as u32, row, row.filter_header?)))
		.collect();
	let (mut agree_below, mut differ_from) = (0, rows.len());
	while agree_below < differ_from {
		let middle = (agree_below + differ_from) / 2;
		let (height, row, took) = rows[middle];
		let (_, says) = one_row(source, BlockId { height, hash: row.hash }, call_timeout).await?;
		if says == took {
			agree_below = middle + 1;
		} else {
			differ_from = middle;
		}
	}
	Ok(rows.get(differ_from).map(|(height, row, _)| BlockId { height: *height, hash: row.hash }))
}

/// What came of going through the witness's filters.
#[derive(Debug, Default)]
struct ReadThrough {
	/// All there was to read, from the first difference up, has been read.
	complete: bool,
	progressed: bool,
	so_far: Option<ReadSoFar>,
	active_lied: Option<(LieKind, u32)>,
	witness_lied: Option<(LieKind, u32)>,
}

/// See the module docs: the witness's filters from the top of what is held down to `from`, within
/// this check's budget, and the blocks they match. What was gone through before is not gone through
/// again. A stretch of new blocks too long for one check takes the place of what was known, which
/// costs filters to read again and no block twice.
async fn read_through<H: HeldFilters + ?Sized>(
	held: &H, chain: &HeldChain, from: u32, active: &dyn FilterSource, witness: &dyn FilterSource,
	so_far: Option<ReadSoFar>, call_timeout: Duration,
) -> ReadThrough {
	let top = chain.base + chain.blocks.len() as u32 - 1;
	let mut known =
		so_far.filter(|known| known.low >= from && known.high <= top && known.low <= known.high);
	let mut report = ReadThrough::default();
	let scripts = held.watched_scripts();
	let mut budget = ReadBudget { pages: MAX_READ_PAGES, scans: MAX_CONFLICT_SCANS };
	// Every block from here to the top has been gone through.
	let mut reached = top + 1;
	loop {
		if let Some(joined) = known.filter(|known| reached <= known.high + 1) {
			reached = reached.min(joined.low);
			known = None;
		}
		if reached <= from {
			break;
		}
		let start = reached.saturating_sub(READ_CHUNK).max(from);
		let span = (start, reached - 1);
		if !read_span(held, chain, span, active, witness, &scripts, &mut budget, &mut report, call_timeout)
			.await
		{
			break;
		}
		reached = start;
		report.progressed = true;
	}
	report.so_far = if reached <= top { Some(ReadSoFar { low: reached, high: top }) } else { known };
	report.complete = reached <= from;
	report
}

/// What is left of a check's reading.
struct ReadBudget {
	pages: u32,
	scans: u32,
}

/// One span of [`read_through`]. Whether every block in it the filters matched has been read;
/// if not, it is gone through again next time.
#[allow(clippy::too_many_arguments)]
async fn read_span<H: HeldFilters + ?Sized>(
	held: &H, chain: &HeldChain, span: (u32, u32), active: &dyn FilterSource,
	witness: &dyn FilterSource, scripts: &[ScriptBuf], budget: &mut ReadBudget,
	report: &mut ReadThrough, call_timeout: Duration,
) -> bool {
	let Some(matched) =
		matched_in_span(chain, span, witness, scripts, budget, report, call_timeout).await
	else {
		return false;
	};
	let mut unread = false;
	// Newest first: a spend close to the tip has the least of its delay left.
	for (height, witness_filter) in matched.into_iter().rev() {
		let row = &chain.blocks[(height - chain.base) as usize];
		if held.scanned_already(&row.hash) {
			continue;
		}
		if budget.scans == 0 || !held.room_to_scan() {
			unread = true;
			continue;
		}
		let Some(block) = read_block(held, height, row, active, witness, call_timeout).await else {
			unread = true;
			continue;
		};
		if report.witness_lied.is_none() {
			report.witness_lied =
				block_lie(&witness_filter, &row.hash, &block).map(|lie| (lie, height));
		}
		if report.active_lied.is_none() {
			let filter = read_filter(active, height, row.hash, call_timeout).await;
			report.active_lied = filter
				.and_then(|filter| block_lie(&filter, &row.hash, &block))
				.map(|lie| (lie, height));
		}
		held.scan_block(height, block);
		budget.scans -= 1;
		report.progressed = true;
	}
	!unread
}

/// The witness's filters for `span`, each held to its own filter headers, and those matching what
/// this node watches, lowest first. A filter that does not hold is the witness caught. `None` when
/// it did not give all of them within the budget: it answers in prefixes, or not at all.
async fn matched_in_span(
	chain: &HeldChain, span: (u32, u32), witness: &dyn FilterSource, scripts: &[ScriptBuf],
	budget: &mut ReadBudget, report: &mut ReadThrough, call_timeout: Duration,
) -> Option<Vec<(u32, BlockFilter)>> {
	let mut matched = Vec::new();
	let mut start = span.0;
	while start <= span.1 {
		budget.pages = budget.pages.checked_sub(1)?;
		let stop = span.1.min(start + MAX_FILTERS_PER_REQUEST - 1);
		let stop_hash = chain.blocks[(stop - chain.base) as usize].hash;
		let told = bounded(call_timeout, witness.filter_headers(start, stop_hash)).await.ok()?;
		let filters = bounded(call_timeout, witness.filters(start, stop_hash)).await.ok()?;
		let read = told.headers.len().min(filters.len()).min((stop - start + 1) as usize);
		if read == 0 {
			return None;
		}
		let mut previous = told.previous;
		for (i, indexed) in filters.into_iter().take(read).enumerate() {
			let height = start + i as u32;
			let hash = chain.blocks[(height - chain.base) as usize].hash;
			if indexed.height != height || indexed.block_hash != hash {
				return None;
			}
			if let Some(lie) = hash_lie(&indexed.filter, &previous, &told.headers[i]) {
				report.witness_lied = Some((lie, height));
				return None;
			}
			previous = told.headers[i];
			match indexed.filter.match_any(&hash, scripts.iter().map(|script| script.as_bytes())) {
				Ok(true) => matched.push((height, indexed.filter)),
				Ok(false) => {},
				Err(_) => {
					report.witness_lied = Some((LieKind::FilterDoesNotDecode, height));
					return None;
				},
			}
		}
		start += read as u32;
	}
	Some(matched)
}

async fn read_filter(
	source: &dyn FilterSource, height: u32, hash: BlockHash, call_timeout: Duration,
) -> Option<BlockFilter> {
	let served = bounded(call_timeout, source.filters(height, hash)).await.ok()?;
	let first = served.into_iter().next()?;
	(first.height == height && first.block_hash == hash).then_some(first.filter)
}

/// From whoever has it. A block that fails its proof of work is not used, and convicts nobody:
/// the filters are what is being judged.
async fn read_block<H: HeldFilters + ?Sized>(
	held: &H, height: u32, row: &HeldBlock, active: &dyn FilterSource, witness: &dyn FilterSource,
	call_timeout: Duration,
) -> Option<Block> {
	for source in [witness, active] {
		if let Ok(block) = bounded(call_timeout, source.block(row.hash)).await {
			if held.block_is_valid(&block, height, &row.header) {
				return Some(block);
			}
		}
	}
	None
}

/// The elements of a block's filter that the block itself shows: every script its outputs pay
/// to, leaving out what BIP158 leaves out. Spent scripts of outputs made in the same block are
/// among them already.
fn certain_elements(block: &Block) -> Vec<ScriptBuf> {
	let mut scripts: Vec<ScriptBuf> = Vec::new();
	for tx in &block.txdata {
		for output in &tx.output {
			let script = &output.script_pubkey;
			if !script.is_empty() && !script.is_op_return() {
				scripts.push(script.clone());
			}
		}
	}
	scripts
}

fn hash_lie(filter: &BlockFilter, previous: &FilterHeader, claimed: &FilterHeader) -> Option<LieKind> {
	(filter.filter_header(previous) != *claimed).then_some(LieKind::FilterDoesNotHashToHeader)
}

/// What `filter` is caught at by `block`: see the module docs.
fn block_lie(filter: &BlockFilter, hash: &BlockHash, block: &Block) -> Option<LieKind> {
	let outputs = certain_elements(block);
	match filter.match_all(hash, outputs.iter().map(|script| script.as_bytes())) {
		Ok(true) => None,
		Ok(false) => Some(LieKind::FilterLacksBlockOutput),
		Err(_) => Some(LieKind::FilterDoesNotDecode),
	}
}

async fn bounded<T>(
	timeout: Duration, call: impl Future<Output = Result<T, SourceError>>,
) -> Result<T, SourceError> {
	tokio::time::timeout(timeout, call).await.unwrap_or_else(|_| {
		Err(SourceError::Unavailable { reason: "timed out".into(), timed_out: true })
	})
}

#[cfg(all(test, feature = "cbf"))]
#[path = "cross_check_real_size.rs"]
mod real_size;

#[cfg(all(test, feature = "cbf"))]
mod tests {
	use super::*;

	use std::sync::Arc;

	use bitcoin::hashes::Hash;

	use crate::chain::cbf::source::{FilterHeaders, IndexedFilter};
	use crate::chain::cbf::source_sync::test_support::{watched_script, FakeSource, Lie};

	const TIMEOUT: Duration = Duration::from_secs(5);
	const LEN: u32 = 30;
	const BURY: u32 = 2;
	const EPOCH: u64 = 7;

	/// A chain as a node following `source` would hold it, every filter header taken, under the
	/// Pro at [`EPOCH`] unless a test says otherwise.
	struct Held {
		chain: HeldChain,
		scans: std::sync::Mutex<Vec<(u32, BlockHash)>>,
		watched: Vec<ScriptBuf>,
	}

	impl Held {
		async fn following_uncapped(source: &FakeSource) -> Self {
			let caps = {
				let st = source.state.lock().unwrap();
				(st.filter_headers_cap, st.filters_cap)
			};
			source.cap_replies(None, None);
			let held = Self::following(source).await;
			source.cap_replies(caps.0, caps.1);
			held
		}

		async fn following(source: &FakeSource) -> Self {
			let tip = source.tip_id().height;
			let stop = source.tip_id().hash;
			let served = source.filter_headers(0, stop).await.unwrap();
			let blocks = (0..=tip)
				.map(|height| {
					let block = source.block_at(height);
					HeldBlock {
						hash: block.block_hash(),
						header: block.header,
						filter_header: Some(served.headers[height as usize]),
						taken_under: Some(EPOCH),
					}
				})
				.collect();
			Self {
				chain: HeldChain { base: 0, blocks },
				scans: Default::default(),
				watched: vec![watched_script()],
			}
		}

		/// What it holds came from an earlier Pro.
		fn held_from_an_earlier_pro(mut self) -> Self {
			self.chain.blocks.iter_mut().for_each(|row| row.taken_under = Some(EPOCH - 1));
			self
		}
	}

	impl HeldFilters for Held {
		fn check_point(&self, bury: u32) -> Option<(BlockId, FilterHeader)> {
			let at = (self.chain.blocks.len() as u32 - 1).checked_sub(bury)?;
			let block = &self.chain.blocks[at as usize];
			Some((BlockId { height: at, hash: block.hash }, block.filter_header?))
		}
		fn held_chain(&self, through: u32) -> Option<HeldChain> {
			let mut chain = self.chain.clone();
			chain.blocks.truncate(through as usize + 1);
			Some(chain)
		}
		fn block_is_valid(&self, block: &Block, height: u32, header: &Header) -> bool {
			crate::chain::cbf::source_sync::verify_block(block, height, header).is_ok()
		}
		fn scan_block(&self, height: u32, block: Block) {
			self.scans.lock().unwrap().push((height, block.block_hash()));
		}
		fn scanned_already(&self, hash: &BlockHash) -> bool {
			self.scans.lock().unwrap().iter().any(|(_, seen)| seen == hash)
		}
		fn watched_scripts(&self) -> Vec<ScriptBuf> {
			self.watched.clone()
		}
	}

	impl Held {
		fn scanned(&self) -> Vec<u32> {
			let mut heights: Vec<u32> =
				self.scans.lock().unwrap().iter().map(|(height, _)| *height).collect();
			heights.sort_unstable();
			heights
		}
	}

	/// The source whose filters watch `matched` heights: they pay the watched script.
	fn honest_paying(matched: &[u32]) -> Arc<FakeSource> {
		Arc::new(FakeSource::new(LEN, matched))
	}

	/// B4: the money case. Neither filter shows who is right; the block is read all the same, and
	/// the rule on who is dropped is not this function's.
	#[tokio::test]
	async fn at_a_difference_nobody_can_attribute_the_block_itself_is_read() {
		let active = honest();
		let witness = lying(Lie::ExtraElementFrom(20));
		let held = Held::following(&active).await;
		let (outcome, _) = check(&held, &active, &witness).await;
		assert_eq!(
			outcome,
			CrossCheckOutcome::Judged { height: 20, active_lied: None, witness_lied: None }
		);
		assert_eq!(held.scanned(), vec![20]);
	}

	/// N3. As the sync loop took it, the Pro's chain has a harmless extra element at 20 and leaves
	/// out the watched script at 25. At the check it names 20 as the difference and serves honest
	/// bytes for 25, so comparing what the two serve now shows nothing at 25. What the witness's
	/// own filter matches is read all the same.
	#[tokio::test]
	async fn a_decoy_below_and_honest_bytes_at_the_check_do_not_keep_the_hidden_block_unread() {
		let active = honest_paying(&[25]);
		active.set_differing_filters(&[20]);
		active.set_lie(Lie::OmitOutputsOnlyAt(25));
		let held = Held::following(&active).await;
		active.set_lie(Lie::None);
		let witness = honest_paying(&[25]);
		let report = report_of(&held, &active, &witness).await;
		assert!(
			matches!(report.outcome, CrossCheckOutcome::Judged { height: 20, witness_lied: None, .. }),
			"{:?}",
			report.outcome
		);
		assert_eq!(held.scanned(), vec![20, 25]);
		assert_eq!(report.unread_from, None, "all read, so the owner may be told so");
	}

	/// N2. A Pro that told the sync loop one thing and tells the check another has said two things
	/// about one block, whatever the witness says. It is caught for that, and what it hid is read
	/// through the witness's filters, not its own.
	#[tokio::test]
	async fn a_pro_that_answers_the_check_honestly_is_caught_by_what_it_told_the_sync_loop() {
		let active = honest_paying(&[25]);
		active.set_lie(Lie::OmitOutputsOnlyAt(25));
		let held = Held::following(&active).await;
		active.set_lie(Lie::None);
		let witness = honest_paying(&[25]);
		let report = report_of(&held, &active, &witness).await;
		assert_eq!(
			report.outcome,
			CrossCheckOutcome::Judged {
				height: 25,
				active_lied: Some(LieKind::AnswerChanged),
				witness_lied: None,
			}
		);
		assert_eq!(held.scanned(), vec![25]);
		assert_eq!(active.calls("block"), 0, "the witness served it");
		assert_eq!(report.rewind.map(|id| id.height), Some(25));
		assert_eq!(report.unread_from, None);
	}

	/// The same shape with the held data from an earlier Pro: nobody here is to blame, and what it
	/// hid is read just the same.
	#[tokio::test]
	async fn what_an_earlier_pro_hid_is_read_through_the_witness_and_nobody_here_is_blamed() {
		let earlier = honest_paying(&[25]);
		earlier.set_lie(Lie::OmitOutputsOnlyAt(25));
		let held = Held::following(&earlier).await.held_from_an_earlier_pro();
		let (active, witness) = (honest_paying(&[25]), honest_paying(&[25]));
		let report = report_of(&held, &active, &witness).await;
		assert_eq!(report.outcome, CrossCheckOutcome::HeldWasWrong { height: 25 });
		assert_eq!(held.scanned(), vec![25]);
	}

	/// The same attacker, changing one answer: it refuses the check. No verdict then, and the
	/// witness's word on what to read does not need it.
	#[tokio::test]
	async fn a_pro_that_will_not_answer_the_check_does_not_keep_the_block_unread() {
		let active = honest_paying(&[25]);
		active.set_lie(Lie::OmitOutputsOnlyAt(25));
		let held = Held::following(&active).await;
		active.state.lock().unwrap().hold_filter_headers = true;
		let witness = honest_paying(&[25]);
		let report = report_of(&held, &active, &witness).await;
		assert_eq!(held.scanned(), vec![25]);
		// And its filter, which it still serves, is caught by the block the witness pointed at.
		assert!(
			matches!(
				report.outcome,
				CrossCheckOutcome::Judged {
					height: 25,
					active_lied: Some(LieKind::FilterLacksBlockOutput),
					witness_lied: None,
				}
			),
			"{:?}",
			report.outcome
		);
	}

	/// Changing another: it gives a `previous` of its own, so they part below everything held.
	#[tokio::test]
	async fn a_pro_that_parts_below_everything_held_does_not_keep_the_block_unread() {
		let active = honest_paying(&[25]);
		active.set_lie(Lie::OmitOutputsOnlyAt(25));
		let mut held = Held::following(&active).await;
		held.chain.blocks.drain(..10);
		held.chain.base = 10;
		struct From10(Held);
		impl HeldFilters for From10 {
			fn check_point(&self, _: u32) -> Option<(BlockId, FilterHeader)> {
				let block = self.0.chain.blocks.last()?;
				let height = self.0.chain.base + self.0.chain.blocks.len() as u32 - 1;
				Some((BlockId { height, hash: block.hash }, block.filter_header?))
			}
			fn held_chain(&self, _: u32) -> Option<HeldChain> {
				Some(self.0.chain.clone())
			}
			fn block_is_valid(&self, _: &Block, _: u32, _: &Header) -> bool {
				true
			}
			fn scan_block(&self, height: u32, block: Block) {
				self.0.scan_block(height, block)
			}
			fn scanned_already(&self, hash: &BlockHash) -> bool {
				self.0.scanned_already(hash)
			}
			fn watched_scripts(&self) -> Vec<ScriptBuf> {
				self.0.watched_scripts()
			}
		}
		active.set_lie(Lie::FilterHeaderPrevious);
		let witness = honest_paying(&[25]);
		let held = From10(held);
		let report = cross_check(&held, &*active, &*witness, EPOCH, None, TIMEOUT).await;
		assert_eq!(held.0.scanned(), vec![25], "{:?}", report);
	}

	/// Review 3's F1 at this level, the regtest run being `tests/funding_attack.rs`. A witness whose
	/// filter holds a script the honest filter lacks convicts nobody, whichever seat the attacker has:
	/// that script is only what a stranger's channel pairs with an output it named.
	#[tokio::test]
	async fn a_script_a_stranger_named_convicts_nobody_from_either_seat() {
		let (honest_pro, attacker) = (honest(), honest());
		attacker.set_includes_at(20, watched_script());
		let held = Held::following(&honest_pro).await;
		let report = report_of(&held, &honest_pro, &attacker).await;
		assert_eq!(
			report.outcome,
			CrossCheckOutcome::Judged { height: 20, active_lied: None, witness_lied: None }
		);
		assert_eq!(held.scanned(), vec![20], "and the block is read all the same");

		let held = Held::following(&attacker).await;
		let report = report_of(&held, &attacker, &honest_pro).await;
		assert_eq!(
			report.outcome,
			CrossCheckOutcome::Judged { height: 20, active_lied: None, witness_lied: None }
		);
	}

	/// A witness whose filter does not hash to the header it gave is caught reading them too.
	#[tokio::test]
	async fn a_witness_matching_everything_costs_reads_within_the_budget_and_the_next_check_goes_on() {
		let active = honest();
		let witness = honest();
		let every: Vec<u32> = (5..=27).collect();
		witness.set_includes_all(&every, watched_script());
		let held = Held::following(&active).await;
		let first = report_of(&held, &active, &witness).await;
		assert_eq!(held.scanned().len() as u32, MAX_CONFLICT_SCANS + 1, "{:?}", held.scanned());
		assert!(first.unread_from.is_some(), "what is left is not called read");
		assert!(first.progressed);
		let second = cross_check(&held, &*active, &*witness, EPOCH, first.read_so_far, TIMEOUT).await;
		assert_eq!(held.scanned(), every, "all of them, none twice");
		assert_eq!(second.unread_from, None);
	}

	/// A long way down it goes a check's pages at a time, newest first, and takes up where it was.
	#[tokio::test]
	async fn a_difference_far_down_is_read_a_day_at_a_time_from_the_top() {
		let len = READ_CHUNK * MAX_READ_PAGES * 2 + 20;
		let hidden = [10, len - 10];
		let active = Arc::new(FakeSource::new(len, &hidden));
		active.set_differing_filters(&[5]);
		let held = Held::following(&active).await;
		active.set_differing_filters(&[]);
		let witness = Arc::new(FakeSource::new(len, &hidden));
		let first = report_of(&held, &active, &witness).await;
		assert_eq!(held.scanned(), vec![len - 10], "the newest first");
		assert!(first.unread_from.is_some());
		let second = cross_check(&held, &*active, &*witness, EPOCH, first.read_so_far, TIMEOUT).await;
		assert!(second.unread_from.is_some(), "{:?}", second.read_so_far);
		let third = cross_check(&held, &*active, &*witness, EPOCH, second.read_so_far, TIMEOUT).await;
		assert_eq!(third.unread_from, None);
		assert_eq!(held.scanned(), vec![10, len - 10]);
		assert_eq!(witness.calls("block"), 2);
	}

	/// What a proof settles needs no more reading than the block it is about.
	#[tokio::test]
	async fn a_proven_difference_reads_no_more_than_its_block() {
		let (active, witness) = (honest(), lying(Lie::OmitOutputsFrom(20)));
		let held = Held::following(&active).await;
		check(&held, &active, &witness).await;
		assert_eq!(held.scanned(), vec![20]);
		assert_eq!(active.calls("filters"), 1, "the one filter judged");
	}

	fn honest() -> Arc<FakeSource> {
		Arc::new(FakeSource::new(LEN, &[]))
	}

	/// The same chain as `honest`, serving `lie`.
	fn lying(lie: Lie) -> Arc<FakeSource> {
		let source = honest();
		source.set_lie(lie);
		source
	}

	async fn report_of(held: &Held, active: &FakeSource, witness: &FakeSource) -> CrossCheckReport {
		cross_check(held, active, witness, EPOCH, None, TIMEOUT).await
	}

	async fn check(
		held: &Held, active: &FakeSource, witness: &FakeSource,
	) -> (CrossCheckOutcome, Option<BlockId>) {
		let report = report_of(held, active, witness).await;
		(report.outcome, report.rewind)
	}

	#[tokio::test]
	async fn two_honest_pros_agree_for_one_call_to_the_witness_and_none_to_the_active() {
		let (active, witness) = (honest(), honest());
		let held = Held::following(&active).await;
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(outcome, CrossCheckOutcome::Agreed { height: LEN - 1 - BURY });
		assert_eq!(rewind, None);
		assert_eq!(witness.calls("filter_headers"), 1, "the budget: one question a check");
		assert_eq!(active.calls("filter_headers"), 1, "only the set-up reads the active's");
		assert_eq!(active.calls("block") + witness.calls("block"), 0);
	}

	#[tokio::test]
	async fn a_witness_behind_this_node_is_not_a_liar() {
		let active = honest();
		let witness = Arc::new(FakeSource::new(LEN - 5, &[]));
		let held = Held::following(&active).await;
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(outcome, CrossCheckOutcome::Inconclusive);
		assert_eq!(rewind, None);
	}

	#[tokio::test]
	async fn a_witness_on_another_branch_is_not_a_liar() {
		let active = honest();
		let witness = honest();
		witness.reorg(6, 8);
		let held = Held::following(&active).await;
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(outcome, CrossCheckOutcome::Inconclusive);
		assert_eq!(rewind, None);
	}

	#[tokio::test]
	async fn a_witness_that_does_not_answer_says_nothing() {
		let (active, witness) = (honest(), honest());
		witness.fail_next(1);
		let held = Held::following(&active).await;
		assert_eq!(check(&held, &active, &witness).await.0, CrossCheckOutcome::Inconclusive);
	}

	#[tokio::test]
	async fn an_active_pro_leaving_outputs_out_is_convicted_by_the_block_and_the_node_rescans() {
		let active = lying(Lie::OmitOutputsFrom(20));
		let witness = honest();
		let held = Held::following(&active).await;
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(
			outcome,
			CrossCheckOutcome::Judged {
				height: 20,
				active_lied: Some(LieKind::FilterLacksBlockOutput),
				witness_lied: None,
			}
		);
		assert_eq!(rewind.map(|id| id.height), Some(20));
	}

	#[tokio::test]
	async fn a_witness_leaving_outputs_out_cannot_evict_the_honest_active_pro() {
		let active = honest();
		let witness = lying(Lie::OmitOutputsFrom(20));
		let held = Held::following(&active).await;
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(
			outcome,
			CrossCheckOutcome::Judged {
				height: 20,
				active_lied: None,
				witness_lied: Some(LieKind::FilterLacksBlockOutput),
			}
		);
		assert_eq!(rewind, None, "nothing the honest Pro said is taken back");
	}

	#[tokio::test]
	async fn a_filter_that_does_not_hash_to_its_header_convicts_whoever_served_it() {
		let active = honest();
		let at = LEN - 1 - BURY;
		let witness = lying(Lie::FilterHeaderAt(at));
		let held = Held::following(&active).await;
		// Its own filter is honest, so the header it claims is not what its filter hashes to.
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(
			outcome,
			CrossCheckOutcome::Judged {
				height: at,
				active_lied: None,
				witness_lied: Some(LieKind::FilterDoesNotHashToHeader),
			}
		);
		assert_eq!(rewind, None);
	}

	#[tokio::test]
	async fn two_filters_the_block_cannot_tell_apart_convict_nobody() {
		// BIP158 commits to the scripts a block's inputs spend, and a block alone does not carry
		// them. So an extra element, or a spent script left out, is out of reach: if a difference
		// here dropped anyone, one attacker could drop an honest Pro.
		let active = honest();
		let witness = lying(Lie::ExtraElementFrom(20));
		let held = Held::following(&active).await;
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(
			outcome,
			CrossCheckOutcome::Judged { height: 20, active_lied: None, witness_lied: None }
		);
		assert_eq!(rewind, None);
	}

	#[tokio::test]
	async fn with_nobody_to_supply_the_block_nobody_is_judged() {
		let active = honest();
		let witness = lying(Lie::OmitOutputsFrom(20));
		let held = Held::following(&active).await;
		active.state.lock().unwrap().all.clear();
		witness.state.lock().unwrap().all.clear();
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(outcome, CrossCheckOutcome::Interrupted { height: 20 });
		assert_eq!(rewind, None);
	}

	#[tokio::test]
	async fn a_block_the_proof_of_work_does_not_vouch_for_convicts_nobody_and_judges_nothing() {
		let active = honest();
		let witness = lying(Lie::OmitOutputsFrom(20));
		let held = Held::following(&active).await;
		active.set_lie(Lie::MerkleAt(20));
		// The witness's own block is fine, so the judgement still happens, and only on filters.
		let (outcome, _) = check(&held, &active, &witness).await;
		assert!(
			matches!(outcome, CrossCheckOutcome::Judged { active_lied: None, witness_lied: Some(_), .. }),
			"{:?}",
			outcome
		);
	}

	#[tokio::test]
	async fn when_both_pros_agree_it_is_what_this_node_holds_that_goes_not_either_of_them() {
		// The filter headers came from an earlier Pro. This one and the witness are honest.
		let earlier = lying(Lie::OmitOutputsFrom(20));
		let (active, witness) = (honest(), honest());
		let held = Held::following(&earlier).await.held_from_an_earlier_pro();
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(outcome, CrossCheckOutcome::HeldWasWrong { height: 20 });
		assert_eq!(rewind.map(|id| id.height), Some(20));
	}

	/// Above `honest_through` says something else of a block the first time it is asked. Asked a
	/// second time, which only `judge` does, it tells the truth, and tells it from then on.
	struct TwoFaced {
		honest: Arc<FakeSource>,
		honest_through: u32,
		asked: std::sync::Mutex<Vec<BlockHash>>,
	}

	#[async_trait::async_trait]
	impl FilterSource for TwoFaced {
		fn name(&self) -> &'static str {
			"two-faced"
		}
		async fn tip(&self) -> Result<BlockId, SourceError> {
			self.honest.tip().await
		}
		async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
			self.honest.headers(from_height, count).await
		}
		async fn filter_headers(
			&self, from_height: u32, stop: BlockHash,
		) -> Result<FilterHeaders, SourceError> {
			let mut told = self.honest.filter_headers(from_height, stop).await?;
			let mut asked = self.asked.lock().unwrap();
			let repeated = asked.contains(&stop);
			asked.push(stop);
			if !repeated && from_height > self.honest_through && asked.iter().all(|seen| seen != &BlockHash::all_zeros()) {
				told.headers.iter_mut().for_each(|header| *header = Hash::all_zeros());
			}
			if repeated {
				// The truth from here on: it has what it came for.
				asked.push(BlockHash::all_zeros());
			}
			Ok(told)
		}
		async fn filters(
			&self, from_height: u32, stop: BlockHash,
		) -> Result<Vec<IndexedFilter>, SourceError> {
			self.honest.filters(from_height, stop).await
		}
		async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
			self.honest.block(hash).await
		}
	}

	/// The fourth review's M1. A free stranger used to cost a pinned node a full rescan from its own
	/// Pro, and a false "what you were told differs", each time its turn came, by saying something
	/// else and then the truth. What this node holds is what both say: nothing is wrong with it.
	#[tokio::test]
	async fn a_witness_that_says_two_things_costs_no_rescan_and_no_reading() {
		let active = honest_paying(&[12]);
		let held = Held::following(&active).await;
		let witness = TwoFaced {
			honest: honest_paying(&[12]),
			honest_through: 3,
			asked: Default::default(),
		};
		let report = cross_check(&held, &*active, &witness, EPOCH, None, TIMEOUT).await;
		assert_eq!(report.outcome, CrossCheckOutcome::Inconclusive);
		assert_eq!(report.rewind, None);
		assert_eq!(report.unread_from, None);
		assert_eq!(held.scanned(), Vec::<u32>::new());
		assert_eq!(active.calls("block"), 0);
	}

	#[tokio::test]
	async fn a_conflict_below_every_block_held_is_undecided() {
		let (active, witness) = (honest(), lying(Lie::OmitOutputsFrom(5)));
		let mut held = Held::following(&active).await;
		held.chain.blocks.drain(..10);
		held.chain.base = 10;
		struct From10(Held);
		impl HeldFilters for From10 {
			fn check_point(&self, _: u32) -> Option<(BlockId, FilterHeader)> {
				let block = self.0.chain.blocks.last()?;
				let height = self.0.chain.base + self.0.chain.blocks.len() as u32 - 1;
				Some((BlockId { height, hash: block.hash }, block.filter_header?))
			}
			fn held_chain(&self, _: u32) -> Option<HeldChain> {
				Some(self.0.chain.clone())
			}
			fn block_is_valid(&self, _: &Block, _: u32, _: &Header) -> bool {
				true
			}
			fn scan_block(&self, _: u32, _: Block) {}
			fn scanned_already(&self, _: &BlockHash) -> bool {
				false
			}
			fn watched_scripts(&self) -> Vec<ScriptBuf> {
				Vec::new()
			}
		}
		let report = cross_check(&From10(held), &*active, &*witness, EPOCH, None, TIMEOUT).await;
		assert_eq!(
			report.outcome,
			CrossCheckOutcome::Judged { height: 10, active_lied: None, witness_lied: None }
		);
		assert_eq!(report.rewind, None);
	}

	#[tokio::test]
	async fn a_span_that_does_not_continue_the_last_convicts_whoever_served_it() {
		let (active, witness) = (honest(), lying(Lie::FilterHeaderAndPreviousAt(LEN - 1 - BURY)));
		let held = Held::following(&active).await;
		let (outcome, rewind) = check(&held, &active, &witness).await;
		assert_eq!(
			outcome,
			CrossCheckOutcome::Judged {
				height: LEN - 1 - BURY,
				active_lied: None,
				witness_lied: Some(LieKind::BrokenFilterHeaderChain),
			}
		);
		assert_eq!(rewind, None);
	}

	#[tokio::test]
	async fn a_conflict_found_on_a_longer_chain_needs_more_pages_and_still_lands_on_the_block() {
		let (active, witness) = (honest(), lying(Lie::OmitOutputsFrom(25)));
		active.cap_replies(Some(7), None);
		witness.cap_replies(Some(7), None);
		let held = Held::following_uncapped(&active).await;
		let (outcome, _) = check(&held, &active, &witness).await;
		assert_eq!(
			outcome,
			CrossCheckOutcome::Judged {
				height: 25,
				active_lied: None,
				witness_lied: Some(LieKind::FilterLacksBlockOutput),
			}
		);
	}
}
