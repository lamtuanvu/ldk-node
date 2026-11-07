// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A cooperative close is counted once, end to end on regtest with an Electrum chain source.
//!
//! The closing transaction pays each side to its own wallet's shutdown script. From the moment a
//! wallet sees it, `total_onchain_balance_sats` counts the closing output while the channel's
//! monitor still reports the same coin in `total_lightning_balance_sats`:
//! - before the close confirms, as `ClaimableOnChannelClose` (Electrum shows the mempool);
//! - after it confirms, as `ClaimableAwaitingConfirmations { source: CoopClose }` until it is
//!   `ANTI_REORG_DELAY` deep.
//!
//! `Node::channels_closed_into_onchain_wallet` names the channel through both windows, so a caller
//! adding the two totals can leave the monitor's share out and count the coin once.
#![cfg(not(feature = "uniffi"))]

mod common;

use common::{
	expect_channel_pending_event, expect_channel_ready_event, expect_event,
	generate_blocks_and_wait, premine_and_distribute_funds, setup_bitcoind_and_electrsd,
	setup_two_nodes, wait_for_outpoint_spend, wait_for_tx, TestChainSource,
};

use ldk_node::payment::{ConfirmationStatus, PaymentKind};
use ldk_node::{BalanceDetails, Event, LightningBalance, Node};

use lightning::chain::channelmonitor::BalanceSource;
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::types::ChannelId;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Txid};
use electrum_client::ElectrumApi;

use std::time::{Duration, Instant};

const PREMINE_SAT: u64 = 2_125_000;
const FUNDING_SAT: u64 = 1_000_000;
/// B's side of the channel, so both sides close into their own wallet.
const PUSH_MSAT: u64 = 400_000_000;
/// Fees the closer's side pays on its way out (the commitment fee and anchors it no longer
/// holds back, less the closing fee). B, who did not fund the channel, pays none.
const FEE_BUFFER_SAT: u64 = 5_000;

/// What LDK's `Balance::claimable_amount_satoshis` adds to `total_lightning_balance_sats`.
fn claimable_sats(balance: &LightningBalance) -> u64 {
	match balance {
		LightningBalance::ClaimableOnChannelClose { amount_satoshis, .. }
		| LightningBalance::ClaimableAwaitingConfirmations { amount_satoshis, .. }
		| LightningBalance::ContentiousClaimable { amount_satoshis, .. }
		| LightningBalance::CounterpartyRevokedOutputClaimable { amount_satoshis, .. } => {
			*amount_satoshis
		},
		LightningBalance::MaybeTimeoutClaimableHTLC {
			amount_satoshis, outbound_payment, ..
		} => {
			if *outbound_payment {
				0
			} else {
				*amount_satoshis
			}
		},
		LightningBalance::MaybePreimageClaimableHTLC { .. } => 0,
	}
}

fn channel_of(balance: &LightningBalance) -> ChannelId {
	match balance {
		LightningBalance::ClaimableOnChannelClose { channel_id, .. }
		| LightningBalance::ClaimableAwaitingConfirmations { channel_id, .. }
		| LightningBalance::ContentiousClaimable { channel_id, .. }
		| LightningBalance::MaybeTimeoutClaimableHTLC { channel_id, .. }
		| LightningBalance::MaybePreimageClaimableHTLC { channel_id, .. }
		| LightningBalance::CounterpartyRevokedOutputClaimable { channel_id, .. } => *channel_id,
	}
}

/// The share of `total_lightning_balance_sats` the on-chain wallet already counts: a cooperative
/// close awaiting its confirmations, and every balance of a channel whose close is in the
/// wallet's view.
fn counted_on_chain_too(balances: &BalanceDetails, closed: &[ChannelId]) -> u64 {
	balances
		.lightning_balances
		.iter()
		.filter(|balance| {
			matches!(
				balance,
				LightningBalance::ClaimableAwaitingConfirmations {
					source: BalanceSource::CoopClose,
					..
				}
			) || closed.contains(&channel_of(balance))
		})
		.map(claimable_sats)
		.sum()
}

/// What the node owns, each coin counted once.
fn owned_once(node: &Node) -> u64 {
	let balances = node.list_balances();
	let closed = node.channels_closed_into_onchain_wallet();
	let once = balances.total_onchain_balance_sats + balances.total_lightning_balance_sats
		- counted_on_chain_too(&balances, &closed);
	println!(
		"{}: on-chain {} + lightning {} - counted on chain too {} = {} (closed into wallet: {:?})",
		node.node_id(),
		balances.total_onchain_balance_sats,
		balances.total_lightning_balance_sats,
		counted_on_chain_too(&balances, &closed),
		once,
		closed
	);
	once
}

fn assert_about(actual: u64, expected: u64, what: &str) {
	assert!(
		actual.abs_diff(expected) <= FEE_BUFFER_SAT,
		"{}: {} is not within {} sat of {}",
		what,
		actual,
		FEE_BUFFER_SAT,
		expected
	);
}

/// `wait_for_outpoint_spend` returns once the funding script has any history, and the funding
/// transaction itself is history: wait until the spend is in electrs, mempool included, and
/// return its txid.
fn wait_for_spend_in_electrs<E: ElectrumApi>(electrs: &E, outpoint: OutPoint) -> Txid {
	let funding = electrs.transaction_get(&outpoint.txid).unwrap();
	let script = funding.output[outpoint.vout as usize].script_pubkey.clone();
	let start = Instant::now();
	loop {
		let history = electrs.script_get_history(&script).unwrap();
		if let Some(entry) = history.iter().find(|entry| entry.tx_hash != outpoint.txid) {
			return entry.tx_hash;
		}
		assert!(
			start.elapsed() < Duration::from_secs(60),
			"the funding spend never reached electrs"
		);
		std::thread::sleep(Duration::from_millis(250));
	}
}

#[test]
fn a_coop_close_is_counted_once_from_the_mempool_to_maturity_electrum() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Electrum(&electrsd);
	let (node_a, node_b) = setup_two_nodes(&chain_source, false, true, false);

	let addr_a = node_a.onchain_payment().new_address().unwrap();
	let addr_b = node_b.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![addr_a, addr_b],
		Amount::from_sat(PREMINE_SAT),
	);
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();

	println!("\nA -- open_channel -> B");
	node_a
		.open_announced_channel(
			node_b.node_id(),
			node_b.listening_addresses().unwrap().first().unwrap().clone(),
			FUNDING_SAT,
			Some(PUSH_MSAT),
			None,
		)
		.unwrap();
	let funding_txo = expect_channel_pending_event!(node_a, node_b.node_id());
	expect_channel_pending_event!(node_b, node_a.node_id());
	wait_for_tx(&electrsd.client, funding_txo.txid);
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6);
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();
	let user_channel_id = expect_channel_ready_event!(node_a, node_b.node_id());
	expect_channel_ready_event!(node_b, node_a.node_id());
	let channel_id = node_a.list_channels()[0].channel_id;

	// Open: nothing is closed into either wallet, and the plain sum counts every coin once.
	let nodes = [&node_a, &node_b];
	let mut owned_before = Vec::new();
	for node in nodes {
		assert!(node.channels_closed_into_onchain_wallet().is_empty());
		let balances = node.list_balances();
		assert_eq!(counted_on_chain_too(&balances, &[]), 0);
		assert!(balances.total_lightning_balance_sats > 0);
		owned_before
			.push(balances.total_onchain_balance_sats + balances.total_lightning_balance_sats);
	}

	println!("\nA close_channel");
	node_a.close_channel(&user_channel_id, node_b.node_id()).unwrap();
	expect_event!(node_a, ChannelClosed);
	expect_event!(node_b, ChannelClosed);
	wait_for_outpoint_spend(&electrsd.client, funding_txo);
	let closing_txid = wait_for_spend_in_electrs(&electrsd.client, funding_txo);
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();

	// Before the close confirms: each wallet holds its closing output, unconfirmed, and the
	// monitor still reports the channel as claimable on close.
	for (node, before) in nodes.into_iter().zip(owned_before.iter().copied()) {
		let closing = node.payment(&PaymentId(closing_txid.to_byte_array())).expect("seen");
		assert!(matches!(
			closing.kind,
			PaymentKind::Onchain { status: ConfirmationStatus::Unconfirmed, .. }
		));
		assert_eq!(node.channels_closed_into_onchain_wallet(), vec![channel_id]);

		let balances = node.list_balances();
		assert!(!balances.lightning_balances.is_empty());
		for balance in &balances.lightning_balances {
			assert!(matches!(balance, LightningBalance::ClaimableOnChannelClose { .. }));
			assert_eq!(channel_of(balance), channel_id);
		}
		let twice = counted_on_chain_too(&balances, &[channel_id]);
		assert!(twice > 0);
		assert_eq!(twice, balances.total_lightning_balance_sats);
		assert_eq!(
			counted_on_chain_too(&balances, &[]),
			0,
			"before it confirms, only the wallet's view names the close"
		);
		assert_about(owned_once(node), before, "owned once, close in the mempool");
		assert!(
			balances.total_onchain_balance_sats + balances.total_lightning_balance_sats
				>= before + twice - FEE_BUFFER_SAT,
			"the plain sum counts the closing output twice"
		);
	}

	println!("\nThe close confirms");
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1);
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();

	// After it confirms: the monitor reports a CoopClose balance awaiting confirmations, and the
	// wallet still holds the output, now confirmed.
	let mut maturity_height = 0;
	for (node, before) in nodes.into_iter().zip(owned_before.iter().copied()) {
		assert_eq!(node.channels_closed_into_onchain_wallet(), vec![channel_id]);
		let balances = node.list_balances();
		assert_eq!(balances.lightning_balances.len(), 1);
		match balances.lightning_balances[0] {
			LightningBalance::ClaimableAwaitingConfirmations {
				channel_id: id,
				amount_satoshis,
				confirmation_height,
				source: BalanceSource::CoopClose,
				..
			} => {
				assert_eq!(id, channel_id);
				assert_eq!(counted_on_chain_too(&balances, &[]), amount_satoshis);
				maturity_height = maturity_height.max(confirmation_height);
			},
			ref other => panic!("unexpected balance once the close confirmed: {:?}", other),
		}
		assert_about(owned_once(node), before, "owned once, close confirmed");
	}

	println!("\nThe close matures");
	let tip = node_a.status().current_best_block.height;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, (maturity_height - tip) as usize);
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();

	// The monitor's balance is gone: the on-chain wallet alone holds the coin, once.
	for (node, before) in nodes.into_iter().zip(owned_before.iter().copied()) {
		let balances = node.list_balances();
		assert!(balances.lightning_balances.is_empty());
		assert_eq!(balances.total_lightning_balance_sats, 0);
		assert_eq!(owned_once(node), balances.total_onchain_balance_sats);
		assert_about(balances.total_onchain_balance_sats, before, "on-chain once matured");
		assert_eq!(node.next_event(), None);
	}

	node_a.stop().unwrap();
	node_b.stop().unwrap();
}
