// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The cross-check at the sizes it meets: 4,032 blocks held, 200 filter headers a reply, 25 KB
//! filters and 384 KiB a reply. Thirty blocks of tiny filters hid two ways of never reading a
//! block; nothing about scale is taken from those tests.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bdk_chain::BlockId;
use bitcoin::bip158::{BlockFilter, BlockFilterWriter, FilterHeader};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, ScriptBuf};

use super::*;
use crate::chain::cbf::source::{FilterHeaders, IndexedFilter};
use crate::chain::cbf::source_sync::test_support::{mine, other_script, watched_script};
use crate::chain::cbf::source_sync::verify_block;
use crate::chain::raw_serve::{FILTER_BYTES_PER_REPLY, FILTER_HEADERS_PER_REPLY};

const HELD: u32 = 4032;
const FILTER_BYTES: usize = 25_000;
const EPOCH: u64 = 7;
const TIMEOUT: Duration = Duration::from_secs(5);
/// At 21 bits or so an element, what fits the size without running out of bits.
const ELEMENTS: u64 = (FILTER_BYTES as u64 * 8) / 26;

/// A filter of the real size: real elements where a block is going to be read and held to it,
/// otherwise bytes that decode as elements nothing matches, which hash no faster than real ones.
fn filter_at(block: &Block, height: u32, real: bool, extra: Option<&ScriptBuf>, salt: u64) -> BlockFilter {
	if !real && extra.is_none() {
		let mut content = Vec::with_capacity(FILTER_BYTES);
		bitcoin::consensus::encode::VarInt(ELEMENTS).consensus_encode(&mut content).unwrap();
		let mut state = (height as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt;
		while content.len() < FILTER_BYTES {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			content.extend_from_slice(&state.to_le_bytes());
		}
		return BlockFilter::new(&content);
	}
	let mut content = Vec::with_capacity(FILTER_BYTES);
	let mut writer = BlockFilterWriter::new(&mut content, block);
	writer.add_output_scripts();
	for i in 0..ELEMENTS {
		writer.add_element(&(i ^ salt).to_le_bytes());
	}
	if let Some(extra) = extra {
		writer.add_element(extra.as_bytes());
	}
	writer.finish().unwrap();
	BlockFilter::new(&content)
}

use bitcoin::consensus::Encodable;

/// The chain itself, shared by every Pro.
struct Chain {
	blocks: Vec<Block>,
	index: HashMap<BlockHash, u32>,
}

impl Chain {
	fn new() -> Arc<Self> {
		let mut blocks: Vec<Block> = Vec::with_capacity(HELD as usize);
		let mut index = HashMap::new();
		for height in 0..HELD {
			let prev = blocks.last().map_or(BlockHash::all_zeros(), |b| b.block_hash());
			let block = mine(prev, height, 1_700_000_000 + height * 600, other_script(height as u8), 0);
			index.insert(block.block_hash(), height);
			blocks.push(block);
		}
		Arc::new(Self { blocks, index })
	}
}

/// What one Pro serves. Honest unless told otherwise, and bound as a real Pro's replies are.
struct Pro {
	chain: Arc<Chain>,
	/// Blocks whose filter has real elements in every Pro's answer.
	real: HashSet<u32>,
	/// Blocks where this Pro's filter differs from an honest one by this script.
	extra: HashMap<u32, ScriptBuf>,
	/// Blocks where this Pro's filter leaves out what an honest filter there has: `honest_extra`.
	honest_extra: HashMap<u32, ScriptBuf>,
	headers: Vec<FilterHeader>,
	/// Most filters in a reply, for a Pro answering in prefixes on purpose.
	filters_at_most: Option<usize>,
	refuses_headers: Mutex<bool>,
	refuses_all: Mutex<bool>,
	header_calls: AtomicUsize,
	filter_calls: AtomicUsize,
	block_calls: AtomicUsize,
	bytes_served: AtomicU64,
	largest_reply: AtomicUsize,
}

impl Pro {
	/// `honest_extra`: what the honest filter holds at a height, as a spent script is. A Pro with
	/// `hides` leaves those out; `decoys` are harmless elements of its own.
	fn new(
		chain: &Arc<Chain>, real: &[u32], honest_extra: &[(u32, ScriptBuf)], hides: &[u32],
		decoys: &[u32],
	) -> Arc<Self> {
		let mut real: HashSet<u32> = real.iter().copied().collect();
		let mut extra = HashMap::new();
		let mut kept = HashMap::new();
		for (height, script) in honest_extra {
			real.insert(*height);
			if !hides.contains(height) {
				kept.insert(*height, script.clone());
			}
		}
		for height in decoys {
			extra.insert(*height, ScriptBuf::from_bytes(vec![0x51, 0x51]));
		}
		let mut pro = Self {
			chain: Arc::clone(chain),
			real,
			extra,
			honest_extra: kept,
			headers: Vec::new(),
			filters_at_most: None,
			refuses_headers: Mutex::new(false),
			refuses_all: Mutex::new(false),
			header_calls: AtomicUsize::new(0),
			filter_calls: AtomicUsize::new(0),
			block_calls: AtomicUsize::new(0),
			bytes_served: AtomicU64::new(0),
			largest_reply: AtomicUsize::new(0),
		};
		let mut previous = FilterHeader::all_zeros();
		for height in 0..HELD {
			previous = pro.filter(height).filter_header(&previous);
			pro.headers.push(previous);
		}
		Arc::new(pro)
	}

	fn filter(&self, height: u32) -> BlockFilter {
		let block = &self.chain.blocks[height as usize];
		let real = self.real.contains(&height);
		let extra = self.extra.get(&height).or_else(|| self.honest_extra.get(&height));
		filter_at(block, height, real, extra, 0)
	}

	fn height_of(&self, hash: &BlockHash) -> Result<u32, SourceError> {
		self.chain.index.get(hash).copied().ok_or_else(|| SourceError::NotFound("no such block".into()))
	}

	fn check_up(&self) -> Result<(), SourceError> {
		if *self.refuses_all.lock().unwrap() {
			return Err(SourceError::unavailable("down"));
		}
		Ok(())
	}
}

#[async_trait]
impl FilterSource for Pro {
	fn name(&self) -> &'static str {
		"real-size"
	}
	async fn tip(&self) -> Result<BlockId, SourceError> {
		let hash = self.chain.blocks[HELD as usize - 1].block_hash();
		Ok(BlockId { height: HELD - 1, hash })
	}
	async fn headers(&self, from: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		let blocks = self.chain.blocks.iter().skip(from as usize).take(count as usize);
		Ok(blocks.map(|block| block.header).collect())
	}
	async fn filter_headers(&self, start: u32, stop: BlockHash) -> Result<FilterHeaders, SourceError> {
		self.check_up()?;
		self.header_calls.fetch_add(1, Ordering::Relaxed);
		if *self.refuses_headers.lock().unwrap() {
			return Err(SourceError::unavailable("will not say"));
		}
		let stop = self.height_of(&stop)?;
		let previous = match start {
			0 => FilterHeader::all_zeros(),
			height => self.headers[height as usize - 1],
		};
		let last = stop.min(start + FILTER_HEADERS_PER_REPLY - 1);
		Ok(FilterHeaders { previous, headers: self.headers[start as usize..=last as usize].to_vec() })
	}
	async fn filters(&self, start: u32, stop: BlockHash) -> Result<Vec<IndexedFilter>, SourceError> {
		self.check_up()?;
		self.filter_calls.fetch_add(1, Ordering::Relaxed);
		let stop = self.height_of(&stop)?;
		let mut bytes = 0;
		let mut out = Vec::new();
		for height in start..=stop {
			let filter = self.filter(height);
			bytes += filter.content.len();
			if !out.is_empty()
				&& (bytes > FILTER_BYTES_PER_REPLY
					|| self.filters_at_most.map_or(false, |most| out.len() >= most))
			{
				bytes -= filter.content.len();
				break;
			}
			let block_hash = self.chain.blocks[height as usize].block_hash();
			out.push(IndexedFilter { height, block_hash, filter });
		}
		self.bytes_served.fetch_add(bytes as u64, Ordering::Relaxed);
		self.largest_reply.fetch_max(bytes, Ordering::Relaxed);
		Ok(out)
	}
	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		self.check_up()?;
		self.block_calls.fetch_add(1, Ordering::Relaxed);
		Ok(self.chain.blocks[self.height_of(&hash)? as usize].clone())
	}
}

/// What a node following `source` holds, every row taken under [`EPOCH`].
struct Held {
	chain: Arc<Chain>,
	rows: Vec<HeldBlock>,
	scans: Mutex<Vec<u32>>,
	room: Mutex<bool>,
}

impl Held {
	fn following(source: &Pro) -> Self {
		let rows = (0..HELD as usize)
			.map(|height| {
				let block = &source.chain.blocks[height];
				HeldBlock {
					hash: block.block_hash(),
					header: block.header,
					filter_header: Some(source.headers[height]),
					taken_under: Some(EPOCH),
				}
			})
			.collect();
		Self {
			chain: Arc::clone(&source.chain),
			rows,
			scans: Mutex::new(Vec::new()),
			room: Mutex::new(true),
		}
	}

	fn scanned(&self) -> Vec<u32> {
		let mut heights = self.scans.lock().unwrap().clone();
		heights.sort_unstable();
		heights
	}
}

impl HeldFilters for Held {
	fn check_point(&self, bury: u32) -> Option<(BlockId, FilterHeader)> {
		let at = self.rows.len() as u32 - 1 - bury;
		let row = &self.rows[at as usize];
		Some((BlockId { height: at, hash: row.hash }, row.filter_header?))
	}
	fn held_chain(&self, through: u32) -> Option<HeldChain> {
		Some(HeldChain { base: 0, blocks: self.rows[..=through as usize].to_vec() })
	}
	fn block_is_valid(&self, block: &Block, height: u32, header: &Header) -> bool {
		verify_block(block, height, header).is_ok()
	}
	fn scan_block(&self, height: u32, _block: Block) {
		self.scans.lock().unwrap().push(height);
	}
	fn scanned_already(&self, hash: &BlockHash) -> bool {
		let scans = self.scans.lock().unwrap();
		let height = self.chain.index[hash];
		scans.contains(&height)
	}
	fn watched_scripts(&self) -> Vec<ScriptBuf> {
		vec![watched_script()]
	}
	fn room_to_scan(&self) -> bool {
		*self.room.lock().unwrap()
	}
}

/// Checks with the same witness, as the session runs them while they get somewhere, until done or
/// `at_most` of them have run. The reports, in order.
async fn check_on(
	held: &Held, active: &Pro, witness: &Pro, at_most: usize,
) -> Vec<CrossCheckReport> {
	let mut reports = Vec::new();
	let mut so_far = None;
	for _ in 0..at_most {
		let report = cross_check(held, active, witness, EPOCH, so_far, TIMEOUT).await;
		so_far = report.read_so_far;
		let done = report.unread_from.is_none();
		reports.push(report);
		if done {
			break;
		}
	}
	reports
}

fn spent_at(heights: &[u32]) -> Vec<(u32, ScriptBuf)> {
	heights.iter().map(|height| (*height, watched_script())).collect()
}

/// F2 and F3. A liar keeps a harmless difference low down and hides a spend near the tip of a chain
/// of 4,032. The first check reads the spend, on a page budget a Pi can hold, and the rest follows
/// without starting over.
#[tokio::test]
async fn a_spend_near_the_tip_of_a_real_chain_is_read_at_once_past_an_old_decoy() {
	let chain = Chain::new();
	let (decoy, spend) = (100, HELD - 10);
	let real = [decoy];
	let hidden = spent_at(&[spend]);
	let active = Pro::new(&chain, &real, &hidden, &[spend], &[decoy]);
	let witness = Pro::new(&chain, &real, &hidden, &[], &[]);
	let held = Held::following(&active);

	let reports = check_on(&held, &active, &witness, 1).await;
	assert!(held.scanned().contains(&spend), "read in the first check: {:?}", held.scanned());
	let first = &reports[0];
	assert!(first.progressed);
	assert_eq!(first.unread_from, Some(decoy), "and what is left is not called read");
	let so_far = first.read_so_far.expect("where it got to");
	assert!(HELD - 3 - so_far.low >= 144, "more than a day of blocks in a check: {:?}", so_far);

	let pages = witness.filter_calls.load(Ordering::Relaxed);
	assert!(pages as u32 <= MAX_READ_PAGES + 1, "{} pages", pages);
	assert!(witness.largest_reply.load(Ordering::Relaxed) <= FILTER_BYTES_PER_REPLY);
	let served = witness.bytes_served.load(Ordering::Relaxed);
	assert!(served <= MAX_READ_PAGES as u64 * FILTER_BYTES_PER_REPLY as u64 + 64_000, "{} bytes", served);

	// The rest, in the checks that follow. Bounded, and each filter once but for a cut chunk.
	let before = witness.filter_calls.load(Ordering::Relaxed);
	let mut so_far = first.read_so_far;
	let mut checks = 1;
	loop {
		let report = cross_check(&held, &*active, &*witness, EPOCH, so_far, TIMEOUT).await;
		checks += 1;
		so_far = report.read_so_far;
		if report.unread_from.is_none() {
			break;
		}
		assert!(report.progressed, "at check {}: {:?}", checks, report);
		assert!(checks <= 20, "the whole chain held takes a bounded number of checks");
	}
	let _ = before;
	let pages = HELD as usize / READ_CHUNK as usize;
	assert!(
		witness.filter_calls.load(Ordering::Relaxed) <= pages + checks * 2,
		"no starting over: {} pages",
		witness.filter_calls.load(Ordering::Relaxed)
	);
	assert_eq!(so_far.map(|known| known.low), Some(decoy));
	assert_eq!(held.scanned().len(), 2, "the decoy's block and the spend's");
}

/// A spend old enough to be on no first page is still reached, the decoy lower yet.
#[tokio::test]
async fn an_old_spend_under_an_older_decoy_is_read_in_the_checks_that_follow() {
	let chain = Chain::new();
	let (decoy, spend) = (3, 900);
	let hidden = spent_at(&[spend]);
	let active = Pro::new(&chain, &[decoy], &hidden, &[spend], &[decoy]);
	let witness = Pro::new(&chain, &[decoy], &hidden, &[], &[]);
	let held = Held::following(&active);
	let reports = check_on(&held, &active, &witness, 20).await;
	assert!(held.scanned().contains(&spend), "after {} checks: {:?}", reports.len(), held.scanned());
	assert_eq!(reports.last().unwrap().unread_from, None);
	assert!(reports.iter().all(|report| report.progressed), "no check came to nothing");
}

/// The same attacker changing one answer: it will not answer the check at all. What is read never
/// depended on it.
#[tokio::test]
async fn a_liar_refusing_the_check_at_a_real_size_keeps_nothing_unread() {
	let chain = Chain::new();
	let (decoy, spend) = (100, HELD - 10);
	let hidden = spent_at(&[spend]);
	let active = Pro::new(&chain, &[decoy], &hidden, &[spend], &[decoy]);
	let witness = Pro::new(&chain, &[decoy], &hidden, &[], &[]);
	let held = Held::following(&active);
	*active.refuses_all.lock().unwrap() = true;
	check_on(&held, &active, &witness, 1).await;
	assert!(held.scanned().contains(&spend));
	assert_eq!(witness.block_calls.load(Ordering::Relaxed), 1);
}

/// A witness that will not go on reads as not read, and as not getting anywhere: the session says so
/// instead of saying it is reading.
#[tokio::test]
async fn a_limit_reached_is_said_and_not_called_read() {
	let chain = Chain::new();
	let (decoy, spend) = (HELD - 100, HELD - 10);
	let hidden = spent_at(&[spend]);
	let active = Pro::new(&chain, &[decoy], &hidden, &[spend], &[decoy]);
	let witness = Pro::new(&chain, &[decoy], &hidden, &[], &[]);
	let held = Held::following(&active);
	*held.room.lock().unwrap() = false;
	let report = cross_check(&held, &*active, &*witness, EPOCH, None, TIMEOUT).await;
	assert!(!held.scanned().contains(&spend));
	assert!(report.unread_from.is_some(), "no room for the block is not a block read: {:?}", report);
	assert!(!report.progressed, "and not getting anywhere is what it says");
	*held.room.lock().unwrap() = true;
	let report = cross_check(&held, &*active, &*witness, EPOCH, report.read_so_far, TIMEOUT).await;
	assert!(held.scanned().contains(&spend), "room again, and it goes on");
	assert!(report.progressed);

	let mut slow = Pro::new(&chain, &[decoy], &hidden, &[], &[]);
	Arc::get_mut(&mut slow).unwrap().filters_at_most = Some(1);
	let held = Held::following(&active);
	let mut so_far = None;
	let mut reached_it = false;
	for _ in 0..3 {
		let report = cross_check(&held, &*active, &*slow, EPOCH, so_far, TIMEOUT).await;
		so_far = report.read_so_far;
		reached_it |= held.scanned().contains(&spend);
		assert!(report.unread_from.is_some());
	}
	assert!(reached_it, "one filter a reply still gets to the newest within a check");

	let held = Held::following(&active);
	let gone = Pro::new(&chain, &[decoy], &hidden, &[], &[]);
	let told = cross_check(&held, &*active, &*gone, EPOCH, None, TIMEOUT).await;
	assert!(told.progressed);
	*gone.refuses_headers.lock().unwrap() = false;
	*gone.refuses_all.lock().unwrap() = true;
	let report = cross_check(&held, &*active, &*gone, EPOCH, told.read_so_far, TIMEOUT).await;
	assert_eq!(report.outcome, CrossCheckOutcome::Inconclusive, "first question unanswered");
}

/// No honest Pro is ever convicted at these sizes: not by two honest ones comparing, not by a witness
/// with a difference of its own at any depth, through every check that takes to read.
#[tokio::test]
async fn an_honest_pro_is_never_convicted_at_a_real_size() {
	let chain = Chain::new();
	let (active, witness) = (Pro::new(&chain, &[], &[], &[], &[]), Pro::new(&chain, &[], &[], &[], &[]));
	let held = Held::following(&active);
	let report = cross_check(&held, &*active, &*witness, EPOCH, None, TIMEOUT).await;
	assert_eq!(report.outcome, CrossCheckOutcome::Agreed { height: HELD - 3 });
	assert_eq!(witness.header_calls.load(Ordering::Relaxed), 1, "one question");
	assert_eq!(witness.filter_calls.load(Ordering::Relaxed), 0);

	// A witness differing low down, and matching what this node watches in many blocks: every
	// block read holds the honest filter to it. Nobody is convicted.
	let many: Vec<u32> = (0..60).map(|i| 50 + i * 60).collect();
	let mut honest_pro = Pro::new(&chain, &many, &[], &[], &[]);
	Arc::get_mut(&mut honest_pro).unwrap().filters_at_most = None;
	let mut liar = Pro::new(&chain, &many, &spent_at(&many), &[], &[]);
	Arc::get_mut(&mut liar).unwrap().filters_at_most = None;
	let held = Held::following(&honest_pro);
	let reports = check_on(&held, &honest_pro, &liar, 25).await;
	assert_eq!(reports.last().unwrap().unread_from, None, "it finishes: {}", reports.len());
	for report in &reports {
		assert!(
			matches!(
				report.outcome,
				CrossCheckOutcome::Judged { active_lied: None, witness_lied: None, .. }
			),
			"{:?}",
			report.outcome
		);
	}
	assert_eq!(held.scanned(), many);

	// It restarted: the same answers, and what it said before has no epoch to be held to.
	let mut held = Held::following(&honest_pro);
	held.rows.iter_mut().for_each(|row| row.taken_under = None);
	for row in &mut held.rows[..(HELD - 144) as usize] {
		row.filter_header = None;
	}
	let report = cross_check(&held, &*honest_pro, &*witness_like(&chain, &honest_pro), EPOCH, None, TIMEOUT).await;
	assert_eq!(report.outcome, CrossCheckOutcome::Agreed { height: HELD - 3 });

	// It serves nothing for a while: nobody is convicted for not answering.
	let held = Held::following(&honest_pro);
	*honest_pro.refuses_all.lock().unwrap() = true;
	let report = cross_check(&held, &*honest_pro, &*liar, EPOCH, None, TIMEOUT).await;
	assert!(
		matches!(report.outcome, CrossCheckOutcome::Interrupted { .. }),
		"{:?}",
		report.outcome
	);
}

fn witness_like(chain: &Arc<Chain>, pro: &Pro) -> Arc<Pro> {
	let real: Vec<u32> = pro.real.iter().copied().collect();
	Pro::new(chain, &real, &[], &[], &[])
}

/// An honest Pro after a reorg does not have what this node holds above the fork, by hash: that is
/// no answer. And below the fork what it says has not changed.
#[tokio::test]
async fn an_honest_pro_after_a_reorg_is_not_convicted_at_a_real_size() {
	let chain = Chain::new();
	let active = Pro::new(&chain, &[], &[], &[], &[]);
	let mut held = Held::following(&active);
	// This node holds a branch of the top blocks nobody else has any more.
	for height in HELD - 6..HELD {
		let row = &mut held.rows[height as usize];
		let block = mine(row.hash, height, 1_800_000_000 + height, other_script(1), 0xee);
		row.hash = block.block_hash();
		row.header = block.header;
		row.filter_header = Some(FilterHeader::from_byte_array([height as u8; 32]));
	}
	let witness = Pro::new(&chain, &[], &[], &[], &[]);
	let report = cross_check(&held, &*active, &*witness, EPOCH, None, TIMEOUT).await;
	assert_eq!(report.outcome, CrossCheckOutcome::Inconclusive);
	assert_eq!(report.rewind, None);
}
