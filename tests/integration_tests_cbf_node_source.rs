// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! End to end: a regtest bitcoind with `-blockfilterindex=1` → a Pro node serving raw BIP157
//! data from it (`Node::chain_serve_*`) → a hybrid node following the chain by compact block
//! filters from that Pro node alone (`CbfSource::Node`), all in one process.
//!
//! The filter source here is what an embedding app's network-backed source is, minus the
//! network: every answer goes through the Pro node's public serve functions and the public wire
//! conversions in `ldk_node::chain_filter_source`, so the hybrid sees exactly the bytes it would
//! see over a relay.
//!
//! The last test runs several hybrid nodes on one [`ChainHost`], as an app runs its wallets,
//! starts some of them after the host's sync launched, and restarts them in an app's boot
//! order: the primary first, then a secondary with a wallet and a channel on disk.

#![cfg(feature = "cbf")]

mod common;

use common::random_config;

use ldk_node::chain_filter_source::{
	chain_tip_from_wire, filter_headers_from_wire, filters_from_wire, headers_from_wire,
	BlockChunkAssembler, BlockFilter, BlockId, FilterHeaders, FilterSource, IndexedFilter,
	SourceError,
};
use ldk_node::chain_provider::{
	ChainDataProvider, ChainProviderError, WireBlockRequest, WireBroadcastRequest,
	WireFeeEstimates, WireFilterHeadersRequest, WireFiltersRequest, WireHeadersRequest,
	WireLightningSyncRequest, WireLightningSyncResponse, WireMempoolRequest, WireMempoolResponse,
	WireSyncRequest, WireTxStatusRequest, WireTxStatusResponse, WireUpdate, CHAIN_WIRE_VERSION,
};
use ldk_node::config::Config;
use ldk_node::lightning::chain::BestBlock;
use ldk_node::logger::{LogLevel, Logger};
use ldk_node::payment::{ConfirmationStatus, PaymentKind};
use ldk_node::{
	BroadcastQueueState, Builder, CbfConfig, CbfSource, CbfSyncStatus, ChainHost, ChainHostBuilder,
	Node, NodeError,
};

use bitcoin::block::Header;
use bitcoin::{Address, Amount, Block, BlockHash, FeeRate, Txid};

use electrsd::corepc_node::Node as BitcoinD;
use electrsd::corepc_node::{self, Client as BitcoindClient};

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long any one condition is waited on. The hybrid polls its source's tip every 30s, so a
/// new block can take that long to be noticed; this leaves room for a few polls.
const WAIT: Duration = Duration::from_secs(150);

fn setup_bitcoind() -> BitcoinD {
	setup_bitcoind_with(&[])
}

fn setup_bitcoind_with(extra: &[&'static str]) -> BitcoinD {
	let exe = std::env::var("BITCOIND_EXE")
		.ok()
		.or_else(|| corepc_node::downloaded_exe_path().ok())
		.expect(
			"you need to provide an env var BITCOIND_EXE or specify a bitcoind version feature",
		);
	let mut conf = corepc_node::Conf::default();
	conf.network = "regtest";
	conf.args.push("-blockfilterindex=1");
	conf.args.extend_from_slice(extra);
	BitcoinD::with_conf(exe, &conf).unwrap()
}

fn mine(client: &BitcoindClient, count: usize, to: &Address) -> Vec<BlockHash> {
	let res = client.generate_to_address(count, to).expect("generatetoaddress");
	res.0.iter().map(|h| h.parse().expect("block hash")).collect()
}

/// Waits for bitcoind's block filter index to reach its tip: the Pro node's raw source reads
/// filters through `getblockfilter`, which answers only for indexed blocks.
fn wait_for_filter_index(client: &BitcoindClient) {
	let deadline = Instant::now() + WAIT;
	loop {
		let tip: BlockHash = client.best_block_hash().unwrap();
		if client.call::<serde_json::Value>("getblockfilter", &[tip.to_string().into()]).is_ok() {
			return;
		}
		assert!(Instant::now() < deadline, "bitcoind never indexed the filter of its tip");
		std::thread::sleep(Duration::from_millis(200));
	}
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
	let deadline = Instant::now() + WAIT;
	while !cond() {
		assert!(Instant::now() < deadline, "timed out after {:?} waiting for {}", WAIT, what);
		std::thread::sleep(Duration::from_millis(250));
	}
}

/// A Pro node: follows regtest over bitcoind RPC, like the harness's nodes, and serves raw
/// BIP157 data read from the same bitcoind.
fn setup_pro_node(bitcoind: &BitcoinD) -> Arc<Node> {
	let config = random_config(true);
	let mut builder = Builder::from_config(config.node_config.clone());
	let rpc = bitcoind.params.rpc_socket;
	let cookie = bitcoind.params.get_cookie_values().unwrap().unwrap();
	builder.set_chain_source_bitcoind_rpc(
		rpc.ip().to_string(),
		rpc.port(),
		cookie.user.clone(),
		cookie.password.clone(),
	);
	builder.set_raw_chain_source_bitcoind_rpc(
		format!("http://{}", rpc),
		cookie.user,
		cookie.password,
		None,
	);
	builder.set_filesystem_logger(None, Some(LogLevel::Debug));
	let node = Arc::new(builder.build().unwrap());
	node.start().unwrap();
	node
}

/// A hybrid node that follows the chain by filters from `source` alone.
fn setup_hybrid_node(source: Arc<dyn FilterSource>) -> (Node, String) {
	let config = random_config(true);
	let storage_dir = config.node_config.storage_dir_path.clone();
	let mut builder = Builder::from_config(config.node_config.clone());
	builder.set_chain_source_cbf(
		vec![],
		CbfConfig { source: CbfSource::Node, wallet_birthday_height: None, ..Default::default() },
	);
	builder.set_cbf_filter_source(source);
	builder.set_filesystem_logger(None, Some(LogLevel::Debug));
	let node = builder.build().unwrap();
	node.start().unwrap();
	(node, storage_dir)
}

/// A [`FilterSource`] over a Pro node's public raw serves and the public wire conversions — the
/// shape of the app's network-backed source, minus the network. Counts the calls it makes.
///
/// `Node::chain_serve_*` block on the Pro node's own runtime, so each call leaves the hybrid's
/// async context for a blocking thread first, as a transport handler would run on its own.
struct ProNodeFilterSource {
	pro: Arc<Node>,
	calls: Mutex<HashMap<&'static str, usize>>,
	/// When set, the last filter of every span is replaced by a different, well-formed filter:
	/// a source that lies about what a block holds.
	corrupt_filters: AtomicBool,
}

impl ProNodeFilterSource {
	fn new(pro: Arc<Node>) -> Self {
		Self { pro, calls: Mutex::new(HashMap::new()), corrupt_filters: AtomicBool::new(false) }
	}

	fn calls(&self, method: &'static str) -> usize {
		self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
	}

	async fn serve<T: Send + 'static>(
		&self, method: &'static str, f: impl FnOnce(&Node) -> Result<T, NodeError> + Send + 'static,
	) -> Result<T, SourceError> {
		*self.calls.lock().unwrap().entry(method).or_default() += 1;
		let pro = Arc::clone(&self.pro);
		tokio::task::spawn_blocking(move || f(&pro))
			.await
			.map_err(|e| SourceError::unavailable(format!("serve task failed: {}", e)))?
			.map_err(|e| SourceError::unavailable(format!("pro node: {}", e)))
	}
}

#[async_trait::async_trait]
impl FilterSource for ProNodeFilterSource {
	fn name(&self) -> &'static str {
		"pro-node"
	}

	async fn tip(&self) -> Result<BlockId, SourceError> {
		let wire = self.serve("tip", |pro| pro.chain_serve_tip()).await?;
		Ok(chain_tip_from_wire(&wire)?)
	}

	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		let req = WireHeadersRequest { version: CHAIN_WIRE_VERSION, from_height, count };
		let wire = self.serve("headers", move |pro| pro.chain_serve_headers(&req)).await?;
		Ok(headers_from_wire(&wire)?)
	}

	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		let req = WireFilterHeadersRequest {
			version: CHAIN_WIRE_VERSION,
			start_height,
			stop_hash: stop_hash.to_string(),
		};
		let wire =
			self.serve("filter_headers", move |pro| pro.chain_serve_filter_headers(&req)).await?;
		Ok(filter_headers_from_wire(&wire)?)
	}

	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let req = WireFiltersRequest {
			version: CHAIN_WIRE_VERSION,
			start_height,
			stop_hash: stop_hash.to_string(),
		};
		let wire = self.serve("filters", move |pro| pro.chain_serve_filters(&req)).await?;
		let mut filters = filters_from_wire(&wire)?;
		if self.corrupt_filters.load(Ordering::Acquire) {
			if let Some(last) = filters.last_mut() {
				let mut content = last.filter.content.clone();
				content.push(0x00);
				last.filter = BlockFilter::new(&content);
			}
		}
		Ok(filters)
	}

	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		let mut assembler = BlockChunkAssembler::new(hash);
		loop {
			let req = WireBlockRequest {
				version: CHAIN_WIRE_VERSION,
				hash: hash.to_string(),
				chunk: assembler.next_chunk(),
			};
			let chunk = self.serve("block", move |pro| pro.chain_serve_block(&req)).await?;
			if let Some(block) = assembler.push(&chunk)? {
				return Ok(block);
			}
		}
	}
}

fn hybrid_best_block(node: &Node) -> BlockId {
	let best = node.status().current_best_block;
	BlockId { height: best.height, hash: best.block_hash }
}

fn bitcoind_tip(client: &BitcoindClient) -> BlockId {
	let hash = client.best_block_hash().unwrap();
	let height = client.get_block_count().unwrap().0 as u32;
	BlockId { height, hash }
}

fn wait_for_hybrid_at_tip(hybrid: &Node, client: &BitcoindClient, what: &str) {
	let want = bitcoind_tip(client);
	wait_until(what, || {
		hybrid.cbf_sync_status() == Some(CbfSyncStatus::Synced) && hybrid_best_block(hybrid) == want
	});
}

fn log_contains(storage_dir: &str, needle: &str) -> bool {
	let path = Path::new(storage_dir).join(ldk_node::config::DEFAULT_LOG_FILENAME);
	std::fs::read_to_string(&path).map(|log| log.contains(needle)).unwrap_or(false)
}

#[test]
fn hybrid_node_follows_regtest_through_a_pro_nodes_raw_routes() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);

	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	let (hybrid, hybrid_dir) = setup_hybrid_node(Arc::clone(&source) as Arc<dyn FilterSource>);

	// (a) A fresh regtest wallet has nothing to anchor on but genesis, and syncs from it.
	wait_for_hybrid_at_tip(&hybrid, client, "the hybrid to sync to bitcoind's tip");
	assert!(log_contains(&hybrid_dir, "no birthday on regtest; scanning from genesis"));
	assert_eq!(hybrid.chain_slot_adapters().engine, "cbf(node)");
	assert!(
		!Path::new(&hybrid_dir).join("bip157_data").exists(),
		"a node-source hybrid must never build kyoto"
	);
	println!(
		"(a) hybrid synced to {:?} over the Pro node's raw routes",
		hybrid_best_block(&hybrid)
	);

	// (b) Coins sent to the hybrid are found by filter match, fetched as a full block through
	// the Pro node, checked against the merkle root, and applied.
	let addr = hybrid.onchain_payment().new_address().unwrap();
	let amount = Amount::from_sat(250_000);
	let txid: bitcoin::Txid = client.send_to_address(&addr, amount).unwrap().0.parse().unwrap();
	let funding_block = mine(client, 1, &miner)[0];
	mine(client, 5, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&hybrid, client, "the hybrid to sync past the funding block");
	wait_until("the hybrid's wallet to see the funding", || {
		hybrid.list_balances().spendable_onchain_balance_sats == amount.to_sat()
	});
	assert!(source.calls("block") >= 1, "the funding block must have been fetched");
	println!(
		"(b) funding {} confirmed in {}; hybrid balance {} sat",
		txid,
		funding_block,
		amount.to_sat()
	);

	// (c) Reorg: drop every block from the funding block up and mine a longer branch. The
	// funding transaction falls back to bitcoind's mempool and is mined again on the new
	// branch, so the hybrid must disconnect, follow, and re-confirm it.
	let old_tip = bitcoind_tip(client);
	client.invalidate_block(funding_block).unwrap();
	let fork_height = bitcoind_tip(client).height;
	let new_branch = mine(client, 8, &miner);
	wait_for_filter_index(client);
	let new_tip = bitcoind_tip(client);
	assert!(new_tip.height > old_tip.height && new_tip.hash != old_tip.hash);
	let refunded_in: BlockHash = {
		let tx = client.get_transaction(txid).unwrap();
		tx.block_hash.expect("re-mined").parse().unwrap()
	};
	assert!(new_branch.contains(&refunded_in), "the funding must be re-mined on the new branch");
	wait_for_hybrid_at_tip(&hybrid, client, "the hybrid to follow the reorg");
	wait_until("the hybrid's wallet to re-confirm the funding", || {
		hybrid.list_balances().spendable_onchain_balance_sats == amount.to_sat()
	});
	hybrid.sync_wallets().unwrap();
	assert_eq!(hybrid.list_balances().spendable_onchain_balance_sats, amount.to_sat());
	assert!(log_contains(&hybrid_dir, "CBF reorg from filter source 'pro-node'"));
	println!(
		"(c) reorg from height {} ({}) at fork {} to {:?}; funding re-confirmed in {}",
		old_tip.height, old_tip.hash, fork_height, new_tip, refunded_in
	);

	// (d) Everything came through the Pro node's serves.
	println!(
		"(d) served calls: tip={} headers={} filter_headers={} filters={} block={}",
		source.calls("tip"),
		source.calls("headers"),
		source.calls("filter_headers"),
		source.calls("filters"),
		source.calls("block")
	);
	for method in ["tip", "headers", "filter_headers", "filters", "block"] {
		assert!(source.calls(method) >= 1, "no {} call reached the Pro node", method);
	}

	hybrid.stop().unwrap();
	pro.stop().unwrap();
}

/// A node-source CBF host for several nodes in this process, logging to its own directory.
fn setup_shared_host(source: Arc<dyn FilterSource>) -> (Arc<ChainHost>, String) {
	let config = random_config(true).node_config;
	let dir = config.storage_dir_path.clone();
	let log_file = Path::new(&dir).join(ldk_node::config::DEFAULT_LOG_FILENAME);
	let logger = Logger::new_fs_writer(log_file.to_string_lossy().into_owned(), LogLevel::Debug)
		.expect("the host's log file");
	let mut builder = ChainHostBuilder::from_config(config);
	builder.set_logger(Arc::new(logger));
	builder.set_chain_source_cbf(
		vec![],
		CbfConfig { source: CbfSource::Node, wallet_birthday_height: None, ..Default::default() },
	);
	builder.set_cbf_filter_source(source);
	(builder.build().unwrap(), dir)
}

/// A node on `host` with `config`'s store, built but not started, seeded at `birthday` when
/// one is given — as an app builds a secondary, at every start.
fn node_on_host(host: &Arc<ChainHost>, config: &Config, birthday: Option<BestBlock>) -> Node {
	let mut builder = Builder::from_config(config.clone());
	builder.set_chain_host(Arc::clone(host));
	if let Some(birthday) = birthday {
		builder.set_wallet_birthday(birthday);
	}
	builder.set_filesystem_logger(None, Some(LogLevel::Debug));
	builder.build().unwrap()
}

fn best_block_at(tip: BlockId) -> BestBlock {
	BestBlock::new(tip.hash, tip.height)
}

#[test]
fn a_node_started_beside_a_running_node_source_sync_joins_it() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);

	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	let (host, host_dir) = setup_shared_host(Arc::clone(&source) as Arc<dyn FilterSource>);
	// Nodes sharing a host share a runtime: the host's tasks run on the first one's.
	let runtime =
		Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());

	// The first node launches the host's sync.
	let first_config = random_config(true).node_config;
	let first = node_on_host(&host, &first_config, None);
	first.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&first, client, "the first node to sync to bitcoind's tip");

	// (f) A second node, built and started on the running sync as a wallet created at
	// runtime is, seeded at the first node's best block. It used to be refused until the app
	// restarted; it joins at the tip, with nothing to replay, and takes the next blocks.
	let birthday = first.status().current_best_block;
	let second_config = random_config(true).node_config;
	let second = node_on_host(&host, &second_config, Some(birthday));
	second.start_with_runtime(Arc::clone(&runtime)).expect("joins the running node-source sync");
	assert_eq!(second.status().current_best_block, birthday, "seeded at its birthday");

	let second_addr = second.onchain_payment().new_address().unwrap();
	let second_amount = Amount::from_sat(200_000);
	client.send_to_address(&second_addr, second_amount).unwrap();
	mine(client, 6, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&second, client, "the second node to follow the sync it joined");
	wait_until("the second node's wallet to see its funding", || {
		second.list_balances().spendable_onchain_balance_sats == second_amount.to_sat()
	});
	wait_for_hybrid_at_tip(&first, client, "the first node to follow on");
	assert_eq!(first.list_balances().total_onchain_balance_sats, 0, "not the first node's coins");
	// The host's log is buffered: it is read once the line has been written out.
	wait_until("the host to log the join at the tip", || {
		log_contains(&host_dir, "joined the running node-source sync at height")
	});
	println!("(f) second node joined at {} and took its funding", birthday.height);

	// (g) A third node seeded below the tip, whose funding confirmed after its birthday but
	// before it started: the running sync queues the filters after its birthday again, and
	// the replay finds the funding.
	let third_birthday = best_block_at(bitcoind_tip(client));
	let third = node_on_host(&host, &random_config(true).node_config, Some(third_birthday));
	let third_addr = third.onchain_payment().new_address().unwrap();
	let third_amount = Amount::from_sat(300_000);
	client.send_to_address(&third_addr, third_amount).unwrap();
	mine(client, 3, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&first, client, "the running sync to pass the third node's funding");
	let block_calls = source.calls("block");
	third.start_with_runtime(Arc::clone(&runtime)).expect("joins below the running sync's tip");
	wait_for_hybrid_at_tip(&third, client, "the third node to be replayed to the tip");
	wait_until("the third node's wallet to find its funding in the replay", || {
		third.list_balances().spendable_onchain_balance_sats == third_amount.to_sat()
	});
	wait_until("the host to log the replay", || {
		log_contains(&host_dir, "again for a listener that joined late")
	});
	assert!(source.calls("block") > block_calls, "the funding block was fetched for the replay");
	wait_for_hybrid_at_tip(&second, client, "the second node to stay at the tip");
	assert_eq!(second.list_balances().spendable_onchain_balance_sats, second_amount.to_sat());
	assert_eq!(first.list_balances().total_onchain_balance_sats, 0);
	println!(
		"(g) third node seeded at {} was replayed to {:?} and found its funding",
		third_birthday.height,
		hybrid_best_block(&third)
	);

	// (h) An app's boot order: the primary starts and launches the sync, and a secondary — a
	// wallet and a confirmed private channel on disk, and behind the primary — starts right
	// after, on the running sync. It was refused on every retry ("Failed to join the chain
	// host: Node is not running", a mainnet Pi, 2026-10-31).
	//
	// The Pro node opens the second node's channel: funds for the Pro node first.
	let pro_addr = pro.onchain_payment().new_address().unwrap();
	client.send_to_address(&pro_addr, Amount::from_sat(500_000)).unwrap();
	mine(client, 1, &miner);
	wait_until("the Pro node to see its funds", || {
		pro.sync_wallets().is_ok() && pro.list_balances().spendable_onchain_balance_sats > 0
	});
	let second_listens_on = second.listening_addresses().unwrap()[0].clone();
	pro.open_channel(second.node_id(), second_listens_on, 100_000, None, None).unwrap();
	wait_until("the channel's funding to reach bitcoind's mempool", || {
		let funding = pro.list_channels().first().and_then(|c| c.funding_txo);
		let mempool: Vec<String> =
			client.call("getrawmempool", &[]).expect("bitcoind answers getrawmempool");
		funding.is_some_and(|txo| mempool.contains(&txo.txid.to_string()))
	});
	mine(client, 6, &miner);
	wait_for_filter_index(client);
	wait_until("the channel to be ready on the second node", || {
		second.list_channels().first().is_some_and(|c| c.is_channel_ready)
	});
	let second_onchain = second.list_balances().total_onchain_balance_sats;
	println!("(h) a private channel from the Pro node is ready on the second node");

	// The second node stops, and falls behind while the others run on.
	second.stop().unwrap();
	let stopped_at = second.status().current_best_block;
	mine(client, 12, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&first, client, "the first node to run on without the second");

	// The app stops and starts again: a new host, the nodes rebuilt from their stores.
	third.stop().unwrap();
	first.stop().unwrap();
	let (host, host_dir) = setup_shared_host(Arc::clone(&source) as Arc<dyn FilterSource>);
	let first = node_on_host(&host, &first_config, None);
	first.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&first, client, "the first node to launch the sync again");
	// The first node resumed a few blocks below its own tip, so the second is below the anchor
	// of the sync it joins: no header held there was ever verified for it.
	let restarted_at = bitcoind_tip(client).height;
	assert!(stopped_at.height + 7 < restarted_at, "the second node is below the launch anchor");
	let second = node_on_host(&host, &second_config, Some(birthday));
	assert_eq!(second.status().current_best_block, stopped_at, "where it stopped");
	second.start_with_runtime(Arc::clone(&runtime)).expect("the secondary joins after the primary");
	wait_for_hybrid_at_tip(&second, client, "the second node to be replayed to the tip");
	// From its own lowest tip: its channel monitor may have been persisted a block or so
	// behind its `ChannelManager`.
	wait_until("the host to log the replay from where the second node stopped", || {
		log_contains(&host_dir, "joined the running node-source sync; replaying filters after")
	});
	assert_eq!(second.list_balances().total_onchain_balance_sats, second_onchain);
	assert!(second.list_channels().first().is_some_and(|c| c.is_channel_ready));

	// Both follow the chain on.
	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&second, client, "the second node to follow the next block");
	wait_for_hybrid_at_tip(&first, client, "the first node to follow the next block");
	println!(
		"(h) restarted: the second node, stopped at {}, joined the sync the first launched and follows it at {:?}",
		stopped_at.height,
		hybrid_best_block(&second)
	);

	second.stop().unwrap();
	first.stop().unwrap();
	pro.stop().unwrap();
	if let Ok(runtime) = Arc::try_unwrap(runtime) {
		runtime.shutdown_timeout(Duration::from_secs(10));
	}
}

#[test]
fn hybrid_node_refuses_a_filter_that_does_not_match_its_header() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);

	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	source.corrupt_filters.store(true, Ordering::Release);
	let (hybrid, hybrid_dir) = setup_hybrid_node(Arc::clone(&source) as Arc<dyn FilterSource>);

	// (e) Every span's last filter disagrees with the served filter-header chain: nothing is
	// applied, three strikes fail the sync closed, and the log names the check.
	wait_until("the hybrid to fail closed", || {
		hybrid.cbf_sync_status() == Some(CbfSyncStatus::Failed)
	});
	assert_eq!(hybrid_best_block(&hybrid).height, 0, "nothing from the lying source was applied");
	assert!(log_contains(&hybrid_dir, "failed verification"));
	assert!(log_contains(&hybrid_dir, "failed closed"));
	println!(
		"(e) corrupted filters refused after {} filters calls; hybrid stayed at genesis",
		source.calls("filters")
	);

	hybrid.stop().unwrap();
	pro.stop().unwrap();
}

/// A [`ChainDataProvider`] over a Pro node's public serves, as the app's network-backed provider
/// is, minus the network. Keeps every mempool question it was asked, and can refuse them.
struct ProNodeProvider {
	pro: Arc<Node>,
	calls: Mutex<HashMap<&'static str, usize>>,
	mempool_questions: Mutex<Vec<WireMempoolRequest>>,
	refuse_mempool: AtomicBool,
}

impl ProNodeProvider {
	fn new(pro: Arc<Node>) -> Self {
		Self {
			pro,
			calls: Mutex::new(HashMap::new()),
			mempool_questions: Mutex::new(Vec::new()),
			refuse_mempool: AtomicBool::new(false),
		}
	}

	fn calls(&self, route: &'static str) -> usize {
		self.calls.lock().unwrap().get(route).copied().unwrap_or(0)
	}

	fn mempool_questions(&self) -> Vec<WireMempoolRequest> {
		self.mempool_questions.lock().unwrap().clone()
	}

	async fn serve<T: Send + 'static>(
		&self, route: &'static str, f: impl FnOnce(&Node) -> Result<T, NodeError> + Send + 'static,
	) -> Result<T, ChainProviderError> {
		*self.calls.lock().unwrap().entry(route).or_default() += 1;
		let pro = Arc::clone(&self.pro);
		tokio::task::spawn_blocking(move || f(&pro))
			.await
			.map_err(|e| ChainProviderError::Unreachable(format!("serve task failed: {}", e)))?
			.map_err(|e| ChainProviderError::Refused(format!("{}: {}", route, e)))
	}
}

#[async_trait::async_trait]
impl ChainDataProvider for ProNodeProvider {
	fn name(&self) -> String {
		"pro-node".to_string()
	}

	async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
		self.serve("fee_estimates", |pro| pro.chain_serve_fee_estimates()).await
	}

	async fn broadcast(&self, req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
		self.serve("broadcast", move |pro| pro.chain_serve_broadcast(&req)).await
	}

	#[allow(unused_variables)]
	async fn tx_status(
		&self, req: WireTxStatusRequest,
	) -> Result<WireTxStatusResponse, ChainProviderError> {
		#[cfg(feature = "swaps")]
		{
			self.serve("tx_status", move |pro| pro.chain_serve_tx_status(&req)).await
		}
		#[cfg(not(feature = "swaps"))]
		{
			Err(ChainProviderError::Refused("unsupported".into()))
		}
	}

	async fn wallet_sync(&self, req: WireSyncRequest) -> Result<WireUpdate, ChainProviderError> {
		self.serve("wallet_sync", move |pro| pro.chain_serve_wallet_sync(&req)).await
	}

	async fn lightning_sync(
		&self, req: WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, ChainProviderError> {
		self.serve("lightning_sync", move |pro| pro.chain_serve_lightning_sync(&req)).await
	}

	async fn mempool(
		&self, req: WireMempoolRequest,
	) -> Result<WireMempoolResponse, ChainProviderError> {
		self.mempool_questions.lock().unwrap().push(req.clone());
		if self.refuse_mempool.load(Ordering::Acquire) {
			*self.calls.lock().unwrap().entry("mempool").or_default() += 1;
			return Err(ChainProviderError::Refused("mempool: refused by the test".into()));
		}
		self.serve("mempool", move |pro| pro.chain_serve_mempool(&req)).await
	}
}

/// A node-source CBF host whose MEMPOOL, BROADCAST and FEE slots borrow from `provider`.
fn setup_host_with_provider(
	source: Arc<dyn FilterSource>, provider: Arc<ProNodeProvider>,
) -> Arc<ChainHost> {
	let config = random_config(true).node_config;
	let log_file =
		Path::new(&config.storage_dir_path).join(ldk_node::config::DEFAULT_LOG_FILENAME);
	let logger = Logger::new_fs_writer(log_file.to_string_lossy().into_owned(), LogLevel::Debug)
		.expect("the host's log file");
	let mut builder = ChainHostBuilder::from_config(config);
	builder.set_logger(Arc::new(logger));
	builder.set_chain_source_cbf(
		vec![],
		CbfConfig { source: CbfSource::Node, wallet_birthday_height: None, ..Default::default() },
	);
	builder.set_cbf_filter_source(source);
	builder.set_chain_provider_fallback(provider);
	builder.build().unwrap()
}

fn shared_runtime() -> Arc<tokio::runtime::Runtime> {
	Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap())
}

fn onchain_status(node: &Node, txid: Txid) -> Option<ConfirmationStatus> {
	node.list_payments().into_iter().find_map(|p| match p.kind {
		PaymentKind::Onchain { txid: t, status } if t == txid => Some(status),
		_ => None,
	})
}

/// One block with nothing from the mempool in it.
fn mine_empty(client: &BitcoindClient, to: &Address) -> BlockHash {
	let res: serde_json::Value = client
		.call("generateblock", &[to.to_string().into(), serde_json::json!([])])
		.expect("generateblock");
	res["hash"].as_str().unwrap().parse().unwrap()
}

fn in_mempool(client: &BitcoindClient, txid: Txid) -> bool {
	client.call::<serde_json::Value>("getmempoolentry", &[txid.to_string().into()]).is_ok()
}

/// DECISION 2026-11-05: a filter node hands a Pro none of its scripts. What it sends is shown
/// from its own record, on every wallet of the device, a restart included, and it asks about it
/// at most once per new block or check-in.
#[test]
fn a_filter_node_names_no_script_and_shows_its_own_transaction_from_its_own_record() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);

	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	let provider = Arc::new(ProNodeProvider::new(Arc::clone(&pro)));
	let host = setup_host_with_provider(
		Arc::clone(&source) as Arc<dyn FilterSource>,
		Arc::clone(&provider),
	);
	let runtime = shared_runtime();
	let primary_config = random_config(true).node_config;
	let sibling_config = random_config(true).node_config;
	let primary = node_on_host(&host, &primary_config, None);
	primary.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&primary, client, "the primary to sync");
	let birthday = primary.status().current_best_block;
	let sibling = node_on_host(&host, &sibling_config, Some(birthday));
	sibling.start_with_runtime(Arc::clone(&runtime)).unwrap();

	// (a) An address handed out and a deposit from outside: nothing is asked, and the money
	// shows at its first confirmation.
	let deposit_addr = primary.onchain_payment().new_address().unwrap();
	let deposit = 400_000;
	client.send_to_address(&deposit_addr, Amount::from_sat(deposit)).unwrap();
	primary.sync_wallets().unwrap();
	assert_eq!(provider.calls("mempool"), 0, "no mempool question for an address given out");
	assert_eq!(primary.list_balances().total_onchain_balance_sats, 0, "shows when it confirms");
	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&primary, client, "the primary to take the deposit's block");
	assert_eq!(primary.list_balances().spendable_onchain_balance_sats, deposit);
	primary.sync_wallets().unwrap();
	assert_eq!(provider.calls("mempool"), 0, "nothing own pending: still no question");
	println!("(a) deposit shown at its first confirmation, 0 mempool calls");

	// (b) The primary pays the sibling. From the broadcast on both show it, and no mempool call
	// made that so.
	let sibling_addr = sibling.onchain_payment().new_address().unwrap();
	let paid = 150_000;
	let txid = primary.onchain_payment().send_to_address(&sibling_addr, paid, None).unwrap();
	wait_until("the sibling to show the payment", || {
		sibling.list_balances().total_onchain_balance_sats == paid
	});
	assert!(in_mempool(client, txid), "out through the Pro node");
	assert_eq!(provider.calls("mempool"), 0, "the record is local: no mempool call for this");
	assert_eq!(sibling.list_balances().spendable_onchain_balance_sats, 0, "not spendable yet");
	assert_eq!(onchain_status(&sibling, txid), Some(ConfirmationStatus::Unconfirmed));
	assert_eq!(onchain_status(&primary, txid), Some(ConfirmationStatus::Unconfirmed));
	let primary_total = primary.list_balances().total_onchain_balance_sats;
	assert!(primary_total < deposit - paid + 1, "the spend left the primary's balance");
	println!("(b) payment {} on both wallets, 0 mempool calls", txid);

	// (c) The app stops and starts again, the Pro refusing every mempool question: both wallets
	// still show it, from what they stored.
	provider.refuse_mempool.store(true, Ordering::Release);
	sibling.stop().unwrap();
	primary.stop().unwrap();
	let host = setup_host_with_provider(
		Arc::clone(&source) as Arc<dyn FilterSource>,
		Arc::clone(&provider),
	);
	let primary = node_on_host(&host, &primary_config, None);
	primary.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&primary, client, "the primary to launch the sync again");
	let sibling = node_on_host(&host, &sibling_config, Some(birthday));
	sibling.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&sibling, client, "the sibling to rejoin");
	assert_eq!(sibling.list_balances().total_onchain_balance_sats, paid);
	assert_eq!(primary.list_balances().total_onchain_balance_sats, primary_total);
	assert_eq!(onchain_status(&sibling, txid), Some(ConfirmationStatus::Unconfirmed));
	assert_eq!(onchain_status(&primary, txid), Some(ConfirmationStatus::Unconfirmed));
	provider.refuse_mempool.store(false, Ordering::Release);
	println!("(c) restarted with mempool refused: both still show {}", txid);

	// (d) While it is pending: at most one question per new block, whoever syncs how often, and
	// the question names the transaction and no script.
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&primary, client, "the primary to take an empty block");
	primary.sync_wallets().unwrap();
	let after_block = provider.calls("mempool");
	for _ in 0..3 {
		std::thread::sleep(Duration::from_secs(6));
		primary.sync_wallets().unwrap();
		sibling.sync_wallets().unwrap();
	}
	assert_eq!(provider.calls("mempool"), after_block, "the same block: no second question");
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&primary, client, "the primary to take another empty block");
	primary.sync_wallets().unwrap();
	sibling.sync_wallets().unwrap();
	assert_eq!(provider.calls("mempool"), after_block + 1, "one for the new block");
	let questions = provider.mempool_questions();
	assert!(questions.iter().all(|q| q.spks.is_empty()), "never a script");
	assert_eq!(
		questions.last().unwrap().known_unconfirmed,
		vec![txid.to_string()],
		"one transaction, asked once for both wallets"
	);
	assert_eq!(sibling.list_balances().total_onchain_balance_sats, paid, "still in the mempool");
	println!("(d) {} questions over the test, none with a script", questions.len());

	// (e) It confirms, by filters. Nothing is left to ask about.
	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&sibling, client, "the sibling to take the confirming block");
	wait_for_hybrid_at_tip(&primary, client, "the primary to take the confirming block");
	assert!(matches!(
		onchain_status(&sibling, txid),
		Some(ConfirmationStatus::Confirmed { .. })
	));
	assert!(matches!(
		onchain_status(&primary, txid),
		Some(ConfirmationStatus::Confirmed { .. })
	));
	let settled = provider.calls("mempool");
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&primary, client, "the primary to take one more block");
	primary.sync_wallets().unwrap();
	assert_eq!(provider.calls("mempool"), settled, "nothing pending: no question");
	println!("(e) confirmed by filters; no question after it");

	sibling.stop().unwrap();
	primary.stop().unwrap();
	pro.stop().unwrap();
	if let Ok(runtime) = Arc::try_unwrap(runtime) {
		runtime.shutdown_timeout(Duration::from_secs(10));
	}
}

/// A question that names no script is answered from the mempool's word on those transactions,
/// with no walk of the mempool: the answer names only what is gone, and it does not wait for
/// this node's own first load of the mempool. One with scripts gets the answer it always got.
#[test]
fn a_pro_answers_a_question_with_no_script_without_walking_its_mempool() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);
	let pro = setup_pro_node(&bitcoind);
	wait_until("the Pro node to sync", || pro.status().current_best_block.height == 101);

	let there_addr = client.new_address().unwrap();
	let there: Txid =
		client.send_to_address(&there_addr, Amount::from_sat(30_000)).unwrap().0.parse().unwrap();
	let gone = Txid::from_str("ab".repeat(32).as_str()).unwrap();

	let known = vec![there.to_string(), gone.to_string()];
	let no_script = WireMempoolRequest {
		version: CHAIN_WIRE_VERSION,
		spks: Vec::new(),
		known_unconfirmed: known.clone(),
	};
	let answer = pro.chain_serve_mempool(&no_script).expect("answered at once");
	assert!(answer.unconfirmed.is_empty(), "no transaction comes back: {:?}", answer.unconfirmed);
	assert_eq!(answer.evicted, vec![gone.to_string()], "only what the mempool does not hold");
	assert_eq!(answer.tip.height, 101, "anchored as ever");

	// What an older asker sends: every script, and it gets what it always got. It waits for the
	// Pro's own mempool load, as it always did.
	let spk = there_addr.script_pubkey();
	let with_script = WireMempoolRequest {
		version: CHAIN_WIRE_VERSION,
		spks: vec![spk.to_hex_string()],
		known_unconfirmed: known,
	};
	wait_until("the Pro node's mempool load", || pro.chain_serve_mempool(&with_script).is_ok());
	let answer = pro.chain_serve_mempool(&with_script).unwrap();
	assert_eq!(answer.unconfirmed.len(), 1, "the transaction comes back");
	assert_eq!(answer.evicted, vec![gone.to_string()]);
	pro.stop().unwrap();
}

/// Reorg: a block dropped takes what it confirmed back to unconfirmed, what this node sent and a
/// payment from outside alike, and the filters confirm them again on the new branch. Nothing
/// leaves the total on the way.
#[test]
fn a_dropped_block_takes_a_transaction_back_and_filters_confirm_it_again() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);
	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	let provider = Arc::new(ProNodeProvider::new(Arc::clone(&pro)));
	let host = setup_host_with_provider(
		Arc::clone(&source) as Arc<dyn FilterSource>,
		Arc::clone(&provider),
	);
	let runtime = shared_runtime();
	let node = node_on_host(&host, &random_config(true).node_config, None);
	node.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&node, client, "the node to sync");

	let addr = node.onchain_payment().new_address().unwrap();
	client.send_to_address(&addr, Amount::from_sat(500_000)).unwrap();
	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take its coin");

	// Sent by this node, and a deposit from outside, both confirmed in one block.
	let outside = client.new_address().unwrap();
	let sent = node.onchain_payment().send_to_address(&outside, 100_000, None).unwrap();
	wait_until("the send to reach bitcoind", || in_mempool(client, sent));
	let again = node.onchain_payment().new_address().unwrap();
	let deposit: Txid =
		client.send_to_address(&again, Amount::from_sat(70_000)).unwrap().0.parse().unwrap();
	let block = mine(client, 1, &miner)[0];
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take the block");
	assert!(matches!(onchain_status(&node, sent), Some(ConfirmationStatus::Confirmed { .. })));
	assert!(matches!(onchain_status(&node, deposit), Some(ConfirmationStatus::Confirmed { .. })));
	let confirmed_total = node.list_balances().total_onchain_balance_sats;

	client.invalidate_block(block).unwrap();
	mine_empty(client, &miner);
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to follow the longer branch");
	assert!(
		node.list_broadcast_queue().is_empty()
			|| !node.list_broadcast_queue().iter().any(|e| e.txid == sent),
		"nothing to queue: it is back in the mempool"
	);
	assert!(in_mempool(client, sent));
	let balances = node.list_balances();
	assert_eq!(balances.total_onchain_balance_sats, confirmed_total, "never counted as lost");
	assert_eq!(
		balances.spendable_onchain_balance_sats,
		confirmed_total - 70_000,
		"its own change it may spend; a payment from outside waits for a block"
	);
	assert_eq!(onchain_status(&node, sent), Some(ConfirmationStatus::Unconfirmed));
	assert_eq!(onchain_status(&node, deposit), Some(ConfirmationStatus::Unconfirmed));
	let question_before = provider.mempool_questions().len();
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take an empty block");
	node.sync_wallets().unwrap();
	let questions = provider.mempool_questions();
	assert!(questions.len() > question_before, "the send is pending again: it is asked about");
	let known = &questions.last().unwrap().known_unconfirmed;
	assert!(known.contains(&sent.to_string()) && known.contains(&deposit.to_string()));
	assert!(questions.iter().all(|q| q.spks.is_empty()));
	println!("reorg: {} and {} back to unconfirmed", sent, deposit);

	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take the confirming block");
	assert_eq!(node.list_balances().total_onchain_balance_sats, confirmed_total);
	assert!(matches!(onchain_status(&node, sent), Some(ConfirmationStatus::Confirmed { .. })));
	assert!(matches!(onchain_status(&node, deposit), Some(ConfirmationStatus::Confirmed { .. })));
	println!("reorg: both confirmed again by filters");

	node.stop().unwrap();
	pro.stop().unwrap();
	if let Ok(runtime) = Arc::try_unwrap(runtime) {
		runtime.shutdown_timeout(Duration::from_secs(10));
	}
}

/// Pushes the mempool over `-maxmempool` with large transactions paying `sat_per_vb`, until
/// `victim` is out. Spends one coinbase each, so nothing chains on anything.
fn evict_by_filling_the_mempool(client: &BitcoindClient, victim: Txid, sat_per_vb: u32) -> usize {
	let data = "ab".repeat(90_000);
	let mut sent = 0;
	while in_mempool(client, victim) {
		assert!(sent < 400, "{} is still in the mempool after {} fillers", victim, sent);
		let raw: String = client
			.call(
				"createrawtransaction",
				&[serde_json::json!([]), serde_json::json!([{ "data": data }])],
			)
			.expect("createrawtransaction");
		let funded: serde_json::Value = client
			.call(
				"fundrawtransaction",
				&[raw.into(), serde_json::json!({ "fee_rate": sat_per_vb })],
			)
			.expect("fundrawtransaction");
		let signed: serde_json::Value = client
			.call("signrawtransactionwithwallet", &[funded["hex"].clone()])
			.expect("signrawtransactionwithwallet");
		let accepted: Result<String, _> =
			client.call("sendrawtransaction", &[signed["hex"].clone(), serde_json::json!(0)]);
		sent += 1;
		if let Err(e) = accepted {
			// Before cluster mempool the newest of equal feerate is trimmed first: the filler
			// that pushes the victim out can go out with it, answering "mempool full".
			assert!(format!("{:?}", e).contains("mempool full"), "{:?}", e);
		}
	}
	sent
}

/// DECISION 2026-11-05, item 5, a real low-fee eviction: a transaction dropped from the Pro's
/// mempool cannot be seen from blocks. It is noticed within one block and goes back to the
/// broadcast queue with its inputs reserved, and it is never counted as lost: when it can enter
/// the mempool again it does, and it confirms.
#[test]
fn a_transaction_evicted_from_the_pros_mempool_is_noticed_within_a_block_and_queued() {
	let bitcoind = setup_bitcoind_with(&["-maxmempool=5", "-datacarriersize=100000"]);
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 300, &miner);
	wait_for_filter_index(client);
	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	let provider = Arc::new(ProNodeProvider::new(Arc::clone(&pro)));
	let host = setup_host_with_provider(
		Arc::clone(&source) as Arc<dyn FilterSource>,
		Arc::clone(&provider),
	);
	let runtime = shared_runtime();
	let node = node_on_host(&host, &random_config(true).node_config, None);
	node.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&node, client, "the node to sync");

	let coin = 500_000;
	let addr = node.onchain_payment().new_address().unwrap();
	client.send_to_address(&addr, Amount::from_sat(coin)).unwrap();
	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take its coin");

	let outside = client.new_address().unwrap();
	let low = FeeRate::from_sat_per_vb(1).unwrap();
	let sent_at = Instant::now();
	let txid = node.onchain_payment().send_to_address(&outside, 100_000, Some(low)).unwrap();
	wait_until("the send to reach bitcoind", || in_mempool(client, txid));
	let spent_total = node.list_balances().total_onchain_balance_sats;

	let fillers = evict_by_filling_the_mempool(client, txid, 25);
	let info: serde_json::Value = client.call("getmempoolinfo", &[]).unwrap();
	println!("evicted {} after {} fillers, mempoolminfee {}", txid, fillers, info["mempoolminfee"]);
	assert!(!in_mempool(client, txid), "really gone");

	// Fresh own broadcasts are shielded: the Pro may simply not have it yet.
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take a block inside the grace");
	node.sync_wallets().unwrap();
	assert!(
		!node.list_broadcast_queue().iter().any(|e| e.txid == txid),
		"inside the grace nothing happens"
	);
	assert_eq!(node.list_balances().total_onchain_balance_sats, spent_total);

	// Past the grace, one block is all it takes.
	let grace = Duration::from_secs(10 * 60 + 5);
	if let Some(left) = grace.checked_sub(sent_at.elapsed()) {
		std::thread::sleep(left);
	}
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take the first block past the grace");
	wait_until("the transaction to be queued", || {
		node.list_broadcast_queue()
			.iter()
			.any(|e| e.txid == txid && e.state == BroadcastQueueState::Waiting)
	});
	let entry =
		node.list_broadcast_queue().into_iter().find(|e| e.txid == txid).expect("queued");
	println!("queued {:?}", entry);
	assert!(entry.expires_at_secs.is_some(), "it is given up in the end, by the queue's rule");
	assert_eq!(
		node.list_balances().total_onchain_balance_sats,
		spent_total,
		"inputs reserved, and the money is not shown as gone a second time"
	);
	// Spending again cannot take the same coin: only the change of this transaction is on offer.
	assert!(node.list_balances().spendable_onchain_balance_sats <= spent_total);

	// The queue acts: refused while the mempool's floor is above it, tried again...
	wait_until("a second attempt", || {
		node.list_broadcast_queue().iter().any(|e| e.txid == txid && e.attempts >= 2)
	});
	let refused =
		node.list_broadcast_queue().into_iter().find(|e| e.txid == txid).expect("queued");
	println!("refused again {:?}", refused);
	assert!(!in_mempool(client, txid));

	// ...and taken once the floor is down. Blocks drain the fillers; a jump of the clock lets
	// the rolling floor decay.
	mine(client, 8, &miner);
	wait_for_filter_index(client);
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	let _: serde_json::Value =
		client.call("setmocktime", &[(now + 14 * 24 * 60 * 60).into()]).unwrap();
	let info: serde_json::Value = client.call("getmempoolinfo", &[]).unwrap();
	let _: serde_json::Value = client.call("setmocktime", &[0.into()]).unwrap();
	println!("after the jump mempoolminfee {}", info["mempoolminfee"]);
	wait_until("the queue to get it back in", || in_mempool(client, txid));
	wait_until("the queue to let it go", || {
		!node.list_broadcast_queue().iter().any(|e| e.txid == txid)
	});

	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take the confirming block");
	assert!(matches!(onchain_status(&node, txid), Some(ConfirmationStatus::Confirmed { .. })));
	assert_eq!(node.list_balances().total_onchain_balance_sats, spent_total);
	println!("confirmed; no sat counted lost at any step");

	node.stop().unwrap();
	pro.stop().unwrap();
	if let Ok(runtime) = Arc::try_unwrap(runtime) {
		runtime.shutdown_timeout(Duration::from_secs(10));
	}
}

/// DECISION 2026-11-05, item 7: a channel funding the Pro's mempool will not take does not sit
/// silently. The node holds it in the broadcast queue, with its inputs reserved, says why, and
/// keeps trying; the channel stays pending.
#[test]
fn a_funding_the_pros_mempool_refuses_is_held_and_says_so() {
	// A relay floor above what regtest's estimates fall back to: 1 sat/vB.
	let bitcoind = setup_bitcoind_with(&["-minrelaytxfee=0.0002"]);
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);
	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	let provider = Arc::new(ProNodeProvider::new(Arc::clone(&pro)));
	let host = setup_host_with_provider(
		Arc::clone(&source) as Arc<dyn FilterSource>,
		Arc::clone(&provider),
	);
	let runtime = shared_runtime();
	let node = node_on_host(&host, &random_config(true).node_config, None);
	node.start_with_runtime(Arc::clone(&runtime)).unwrap();
	wait_for_hybrid_at_tip(&node, client, "the node to sync");

	// Inbound anchor channels want a reserve on the Pro node.
	let pro_addr = pro.onchain_payment().new_address().unwrap();
	client.send_to_address(&pro_addr, Amount::from_sat(100_000)).unwrap();
	let coin = 500_000;
	let addr = node.onchain_payment().new_address().unwrap();
	client.send_to_address(&addr, Amount::from_sat(coin)).unwrap();
	mine(client, 1, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&node, client, "the node to take its coin");
	wait_until("the Pro node's reserve", || {
		pro.sync_wallets().is_ok() && pro.list_balances().spendable_onchain_balance_sats > 0
	});

	let pro_door = pro.listening_addresses().unwrap()[0].clone();
	node.open_channel(pro.node_id(), pro_door, 100_000, None, None).unwrap();
	wait_until("the funding to be held", || {
		node.list_broadcast_queue().iter().any(|e| e.state == BroadcastQueueState::Waiting)
	});
	let entry = node
		.list_broadcast_queue()
		.into_iter()
		.find(|e| e.state == BroadcastQueueState::Waiting)
		.unwrap();
	println!("held funding: {:?}", entry);
	assert!(!in_mempool(client, entry.txid), "the Pro's mempool has not taken it");
	assert!(entry.last_error.is_some(), "it says why");
	assert!(entry.expires_at_secs.is_some());
	assert!(entry.next_attempt_at_secs.is_some(), "and it tries again");
	let channel = node.list_channels().into_iter().next().expect("the channel");
	assert!(!channel.is_channel_ready, "pending, and the queue row says why");
	assert_eq!(channel.funding_txo.map(|txo| txo.txid), Some(entry.txid));
	wait_until("a second attempt", || {
		node.list_broadcast_queue().iter().any(|e| e.txid == entry.txid && e.attempts >= 2)
	});

	node.stop().unwrap();
	pro.stop().unwrap();
	if let Ok(runtime) = Arc::try_unwrap(runtime) {
		runtime.shutdown_timeout(Duration::from_secs(10));
	}
}
