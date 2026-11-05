// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Chain ability adapters for a node with no chain source of its own.
//!
//! Every slot is filled from a single [`ChainDataProvider`]: the node asks
//! another node and believes the answer. There is no verification step here
//! and that is the design — a Dependent node that could check the answer
//! would not need to ask.
//!
//! What it does not offer is a UTXO source. It could ask its provider to check
//! the UTXO set, but an announcement "verified" by asking the same node that
//! supplied it is not verified; not implementing [`UtxoCapability`] makes the
//! node log, at startup, that its routing graph carries unchecked capacities —
//! which is the honest position.
//!
//! [`UtxoCapability`]: crate::chain::seam::UtxoCapability
//!
//! What it does *not* do is pretend. Every path below distinguishes "the
//! provider said no" from "I could not ask", because the second is not
//! evidence of anything.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::{FeeRate, Transaction};

use crate::chain::provider::{
	ChainDataProvider, WireBroadcastRequest, WireFeeEstimates, WireSyncRequest, CHAIN_WIRE_VERSION,
};
use crate::chain::seam::{
	ActionResult, Anchored, BroadcastAction, BroadcastRejection, ChainActionError, FeeAction,
	FeeUpdate, MempoolAction, MempoolAnswer, MempoolQuery, PackageOutcomes, ScriptHistoryAction,
	TxBroadcastOutcome, ADAPTER_BUDGET_MARGIN, MAX_BROADCAST_PACKAGE_TXS,
};
use crate::chain::session::FeeReference;
use crate::chain::wire_convert::{
	check_version, mempool_query_to_wire, tx_to_wire, wire_to_mempool_answer, wire_update_to_bdk,
};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, conf_target_from_wire_name, ConfirmationTarget,
};
use crate::logger::{log_error, log_trace, LdkLogger, Logger};
use lightning::chain::chaininterface::{
	ConfirmationTarget as LdkConfirmationTarget, FEERATE_FLOOR_SATS_PER_KW,
};

#[cfg(feature = "swaps")]
use crate::chain::provider::WireTxStatusRequest;
#[cfg(feature = "swaps")]
use crate::chain::seam::TxStatusAction;
#[cfg(feature = "swaps")]
use crate::chain::wire_convert::{block_hash_from_wire, script_to_wire, txid_to_wire};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// The ceiling the embedding app puts on one [`ChainDataProvider`] call:
/// `CHAIN_CALL_TIMEOUT_SECS` in node-app-ldk-node's `src/chain_provider.rs`
/// (1.6.0), "deliberately shorter than ldk-node's own wallet-sync timeout, so
/// a slow provider surfaces as a provider problem there rather than as a
/// sync timeout two layers up". Mirrored here because it is the app's
/// constant: every provider call this adapter makes has either answered or
/// failed within it, whatever the serving node's own backend takes, so the
/// seam's budgets are that ceiling plus the margin — never shorter, or the
/// seam would fire first and the app's own timeout, and its attribution of
/// where the time went, would never be seen.
const PROVIDER_CALL_TIMEOUT_SECS: u64 = 20;

/// One provider call plus the margin.
const DEPENDENT_CALL_BUDGET: Duration =
	Duration::from_secs(PROVIDER_CALL_TIMEOUT_SECS + ADAPTER_BUDGET_MARGIN.as_secs());

/// FEE budget: one provider call.
const DEPENDENT_FEE_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// BROADCAST budget: the wire carries one transaction per request, so a
/// package is as many provider calls as it has transactions. Sized for the
/// largest package, like the backends' own budgets.
const DEPENDENT_BROADCAST_BUDGET: Duration =
	Duration::from_secs(MAX_BROADCAST_PACKAGE_TXS * DEPENDENT_CALL_BUDGET.as_secs());

/// TX_STATUS budget: one provider call. The serving node runs its own
/// TX_STATUS chain behind it, through whichever adapter it has, but the app
/// bounds the call regardless of how long that chain may take.
#[cfg(feature = "swaps")]
const DEPENDENT_TX_STATUS_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// MEMPOOL budget: one provider call, which answers completely and
/// filtered, so its size is the asker's own transactions, not the mempool.
const DEPENDENT_MEMPOOL_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// SCRIPT_HISTORY budget: one provider call. The serving node runs a real
/// scan behind it, which is the heaviest thing a provider does, but the app
/// bounds the call at its ceiling regardless — as it does for the Dependent
/// engine's own wallet sync, which is the same route.
const DEPENDENT_SCRIPT_HISTORY_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// Fills the FEE, TX_STATUS and BROADCAST slots from a remote node, and the
/// MEMPOOL and SCRIPT_HISTORY slots of a hybrid node that follows the chain
/// itself but has no mempool and no script index to scan.
pub(crate) struct DependentChainAdapter {
	provider: Arc<dyn ChainDataProvider>,
	logger: Arc<Logger>,
}

impl DependentChainAdapter {
	pub(crate) fn new(provider: Arc<dyn ChainDataProvider>, logger: Arc<Logger>) -> Self {
		Self { provider, logger }
	}

	/// The pre-chain fee fetch, unchanged: the provider's answer, checked and
	/// re-floored locally. Provider errors map straight onto the seam's error
	/// — `Unreachable` is the timeout, as it was pre-chain — with no `Error`
	/// in between.
	async fn fetch_fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		let estimates = self.provider.fee_estimates().await.map_err(|e| {
			log_error!(self.logger, "Failed to retrieve fee rate estimates from provider: {}", e);
			ChainActionError::from(e)
		})?;

		fee_update_from_wire(&estimates, &self.provider.fee_reference(), &self.logger)
	}
}

/// The most a provider's word can set any fee rate to: 1,000 sat/vB, above every sustained rate
/// so far and low enough that one lying number cannot burn a wallet. An honest Pro in a spike
/// above this has its whole answer refused, and the chain falls through to the next adapter.
pub(crate) const MAX_PROVIDER_FEE_SAT_PER_KWU: u64 = 250_000;

/// The least a provider's word can say: LDK's relay floor, 1 sat/vB rounded up. A Pro serves
/// through [`OnchainFeeEstimator`], which floors every read here, so an honest one never sends
/// less, and anything lower (a 0 meant to sink a sweep) is a lie or a bug.
///
/// [`OnchainFeeEstimator`]: crate::fee_estimator::OnchainFeeEstimator
pub(crate) const MIN_PROVIDER_FEE_SAT_PER_KWU: u64 = FEERATE_FLOOR_SATS_PER_KW as u64;

/// 1 sat/vB in sat/kwu.
const SAT_PER_VB: u64 = 250;

/// What a provider can make this node pay on its own say, on what spends the wallet's coins: a
/// channel open at this costs about 20,000 sat in fees where the outer bound costs about 200,000.
/// An honest Pro in a spike above it costs a delay on something that can wait.
pub(crate) const SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU: u64 = 100 * SAT_PER_VB;

/// With a reference for what fees are, a spend pays at most this many times it...
pub(crate) const SPEND_CAP_RATIO: u64 = 4;
/// ...and may always pay this, as a reference can sit low on a quiet stretch.
pub(crate) const SPEND_CAP_LEAST_SAT_PER_KWU: u64 = 10 * SAT_PER_VB;

/// An urgent claim is not capped as hard: paying too much to take what is at stake is the lesser
/// loss, and a spike is when it matters. On a provider's own word, at most this...
pub(crate) const URGENT_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU: u64 = 250 * SAT_PER_VB;
/// ...with a reference, up to this many times it.
pub(crate) const URGENT_CAP_RATIO: u64 = 16;

/// The least an urgent claim is built at when nothing says otherwise. A penalty costs about 2,500
/// sat at this, and at the relay floor it would sit while what it races goes first. LDK raises a
/// claim as blocks pass; this sets where it starts.
pub(crate) const URGENT_FLOOR_ON_ITS_OWN_WORD_SAT_PER_KWU: u64 = 5 * SAT_PER_VB;
/// With a reference, the urgent floor is half of it, if that is more...
pub(crate) const URGENT_FLOOR_RATIO: u64 = 2;
/// ...up to this, so a second stranger cannot set this node's claims high by itself.
pub(crate) const URGENT_FLOOR_MOST_SAT_PER_KWU: u64 = 100 * SAT_PER_VB;

/// What a second Pro says of `target`. A word: anyone on the list can say anything.
fn witness_rate(target: ConfirmationTarget, reference: &FeeReference) -> Option<u64> {
	reference.witness.as_ref().and_then(|fees| {
		fees.targets
			.iter()
			.find(|entry| conf_target_from_wire_name(&entry.target) == Some(target))
			.map(|entry| entry.sat_per_kwu)
	})
}

/// The cap on what spends the wallet's coins and can wait. **Only blocks lift it above
/// [`SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU`]:** the rate of blocks this node read itself took real
/// proof of work to move, while a witness is a word, and with the Pro in the seat it would be two
/// free keys lifting a channel open to the outer bound. A witness can only hold the cap down, which
/// costs a delay on something that can wait.
fn spend_cap(witness: Option<u64>, local: Option<u64>) -> u64 {
	let of = |rate: u64| rate.saturating_mul(SPEND_CAP_RATIO).max(SPEND_CAP_LEAST_SAT_PER_KWU);
	let on_word = witness.map_or(SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU, |rate| {
		of(rate).min(SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU)
	});
	local.map_or(on_word, |rate| of(rate).max(on_word.min(of(rate))))
}

/// The floor and the cap on an urgent claim. **The errors do not cost the same, so nothing here can
/// be talked down:** a claim that does not confirm before its deadline can lose the whole channel,
/// and a claim overpaid loses part of what it is rescuing, once, and only on a node that has a claim
/// at all. So a reference moves the floor and the cap up only, never below what holds on the
/// provider's word alone: a low witness cannot sink a penalty in a spike, with too few blocks read
/// here for this node to know better. A high one costs at worst the outer bound, on a claim.
fn urgent_bounds(seen: Option<u64>) -> (u64, u64) {
	let floor = seen.map_or(URGENT_FLOOR_ON_ITS_OWN_WORD_SAT_PER_KWU, |rate| {
		(rate / URGENT_FLOOR_RATIO)
			.clamp(URGENT_FLOOR_ON_ITS_OWN_WORD_SAT_PER_KWU, URGENT_FLOOR_MOST_SAT_PER_KWU)
	});
	let cap = seen.map_or(URGENT_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU, |rate| {
		rate.saturating_mul(URGENT_CAP_RATIO).max(URGENT_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU)
	});
	(floor, cap)
}

/// What a provider's rate, in bounds, sets `target` to.
///
/// The two targets a peer's `update_fee` is held to are not the provider's to raise: below them LDK
/// force-closes the channel, so one number from a lying provider would close every channel this
/// node has. Whatever it says, they stay at the floor, which is also what a node with no estimate
/// at all uses, so a peer's commitment fee is taken down to the relay floor. Anchors are what pays
/// for a commitment that is too low then.
///
/// The rest is the provider's word within what it cannot abuse. An out-of-bounds number has already
/// refused the whole answer: this is about numbers that pass. Everything that spends is capped, so
/// a stranger cannot burn funds on an open; an urgent claim also has a floor, so a stranger cannot
/// leave a penalty at 1 sat/vB. [`FeeReference`] tightens both. With no reference, as on a Dependent
/// node, the fixed bounds are all there is.
pub(crate) fn provider_rate_for(
	target: ConfirmationTarget, bounded_sat_per_kwu: u64, reference: &FeeReference,
) -> u64 {
	let witness = witness_rate(target, reference);
	let local = reference.local_sat_per_kwu;
	match target {
		ConfirmationTarget::Lightning(
			LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee
			| LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
		) => FEERATE_FLOOR_SATS_PER_KW as u64,
		ConfirmationTarget::Lightning(LdkConfirmationTarget::MaximumFeeEstimate) => {
			bounded_sat_per_kwu
		},
		ConfirmationTarget::Lightning(LdkConfirmationTarget::UrgentOnChainSweep) => {
			let (floor, cap) = urgent_bounds(witness.max(local));
			bounded_sat_per_kwu.clamp(floor.min(cap), cap)
		},
		_ => bounded_sat_per_kwu.min(spend_cap(witness, local)),
	}
}

/// The rates for which [`fee_update_from_wire`] would refuse `estimates`, for telling of it. A
/// target this build does not know is skipped there, so it is not named here.
pub(crate) fn fees_out_of_bounds(estimates: &WireFeeEstimates) -> Option<String> {
	let outside: Vec<String> = estimates
		.targets
		.iter()
		.filter(|entry| {
			conf_target_from_wire_name(&entry.target).is_some()
				&& !(MIN_PROVIDER_FEE_SAT_PER_KWU..=MAX_PROVIDER_FEE_SAT_PER_KWU)
					.contains(&entry.sat_per_kwu)
		})
		.map(|entry| format!("{} {}", entry.target, entry.sat_per_kwu))
		.collect();
	(!outside.is_empty()).then(|| outside.join(", "))
}

/// A provider's fee estimates as a fee-cache update: checked, and re-floored
/// locally. Shared by every adapter that takes another node's estimates — asked
/// for, or carried by a block bundle. One known target out of bounds refuses the whole answer, so
/// nothing of it is applied and the fee chain falls through to its next adapter.
pub(crate) fn fee_update_from_wire(
	estimates: &WireFeeEstimates, reference: &FeeReference, logger: &Logger,
) -> ActionResult<FeeUpdate> {
	check_version(estimates.version).map_err(|e| {
		log_error!(logger, "Rejecting fee rate estimates from provider: {}", e);
		ChainActionError::unavailable(e.to_string())
	})?;

	let mut new_fee_rate_cache = HashMap::with_capacity(estimates.targets.len());
	for entry in &estimates.targets {
		let Some(target) = conf_target_from_wire_name(&entry.target) else {
			// A target this build does not know. Skipping it is right —
			// guessing which local target it meant would silently apply
			// the wrong rate — but it must be visible.
			log_trace!(
				logger,
				"Ignoring unknown confirmation target '{}' from chain provider",
				entry.target
			);
			continue;
		};

		if !(MIN_PROVIDER_FEE_SAT_PER_KWU..=MAX_PROVIDER_FEE_SAT_PER_KWU)
			.contains(&entry.sat_per_kwu)
		{
			log_error!(
				logger,
				"Rejecting fee rate estimates from provider: {} is {} sat/kwu, outside {}..={}",
				entry.target,
				entry.sat_per_kwu,
				MIN_PROVIDER_FEE_SAT_PER_KWU,
				MAX_PROVIDER_FEE_SAT_PER_KWU
			);
			return Err(ChainActionError::unavailable("provider fee rate out of bounds"));
		}

		// The serving node has already applied its own per-target policy;
		// the post-estimation adjustments are this node's own floors and
		// caps, so they still belong here.
		let fee_rate =
			FeeRate::from_sat_per_kwu(provider_rate_for(target, entry.sat_per_kwu, reference));
		new_fee_rate_cache.insert(target, apply_post_estimation_adjustments(target, fee_rate));
	}

	// An empty cache would leave every target at its hardcoded fallback
	// while looking like a successful update, so refuse it outright.
	if new_fee_rate_cache.is_empty() {
		log_error!(
			logger,
			"Chain provider returned no usable fee rate estimates; keeping the previous cache"
		);
		return Err(ChainActionError::unavailable("no usable fee rate estimates"));
	}

	Ok(FeeUpdate::Apply { cache: new_fee_rate_cache, log_unchanged: false })
}

#[async_trait]
impl FeeAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_FEE_BUDGET)
	}

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		self.fetch_fee_rate_update().await
	}
}

#[async_trait]
impl BroadcastAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_BROADCAST_BUDGET)
	}

	/// Not with nobody to ask: what the drain holds waits in the queue, where a provider arriving
	/// later finds it.
	async fn ready(&self) -> bool {
		self.provider.can_broadcast()
	}

	/// One request per transaction, since the wire carries one.
	///
	/// This adapter never answers `Rejected`. The wire (frozen at
	/// `CHAIN_WIRE_VERSION` 1) cannot express a rejection: the serving node
	/// fails the call whether its own chain could not broadcast or the network
	/// refused the transaction, and both reach this node as the same
	/// [`ChainProviderError::Refused`]. `Refused` means only that the provider
	/// would not serve, so it is `Unavailable` like every other provider
	/// error, and the chain advances.
	async fn broadcast_package(
		&self, txs: &[Transaction],
	) -> ActionResult<PackageOutcomes, BroadcastRejection> {
		let mut outcomes = Vec::with_capacity(txs.len());
		for tx in txs {
			outcomes.push((tx.compute_txid(), self.broadcast_tx(tx).await));
		}
		Ok(outcomes)
	}
}

impl DependentChainAdapter {
	/// The pre-seam per-transaction send and its log levels. A provider error
	/// maps straight onto the seam's error — `Unreachable` is the timeout, as
	/// it was pre-chain — and from there onto the per-transaction outcome.
	async fn broadcast_tx(&self, tx: &Transaction) -> TxBroadcastOutcome {
		let txid = tx.compute_txid();
		let req = WireBroadcastRequest { version: CHAIN_WIRE_VERSION, tx_hex: tx_to_wire(tx) };

		match self.provider.broadcast(req).await {
			Ok(()) => {
				log_trace!(
					self.logger,
					"Chain provider accepted transaction {} for broadcast",
					txid
				);
				TxBroadcastOutcome::Accepted
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Chain provider failed to broadcast transaction {}: {}",
					txid,
					e
				);
				ChainActionError::from(e).into()
			},
		}
	}
}

/// Anchored at `(tip_height, tip_hash)` when the answer carries both — a
/// serving node that read the tip it answered at says which block it was —
/// so a hybrid node checks the answer against its own chain. An answer with
/// either missing is unanchored, as every answer was before the hash was on
/// the wire; one whose hash does not parse is unusable and fails closed.
#[cfg(feature = "swaps")]
#[async_trait]
impl TxStatusAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_TX_STATUS_BUDGET)
	}

	async fn tx_status(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> ActionResult<Anchored<RawTxObservation>> {
		let req = WireTxStatusRequest {
			version: CHAIN_WIRE_VERSION,
			txid: txid_to_wire(&txid),
			script_hex: script_pubkey.map(script_to_wire),
		};

		let resp = match self.provider.tx_status(req).await {
			Ok(resp) => resp,
			Err(e) => {
				// FAIL CLOSED (E6). No answer is not the same as "not
				// confirmed", and callers arm CSV deadlines off this.
				log_error!(
					self.logger,
					"swap_query_tx: chain provider could not answer for {}: {}",
					txid,
					e
				);
				return Err(e.into());
			},
		};

		if check_version(resp.version).is_err() {
			log_error!(
				self.logger,
				"swap_query_tx: chain provider answered for {} with wire version {} (expected {}); failing closed",
				txid,
				resp.version,
				CHAIN_WIRE_VERSION
			);
			return Err(ChainActionError::unavailable(format!(
				"wire version {} (expected {})",
				resp.version, CHAIN_WIRE_VERSION
			)));
		}

		let tip = match wire_tip(&resp) {
			Ok(tip) => tip,
			Err(e) => {
				log_error!(
					self.logger,
					"swap_query_tx: chain provider answered for {} with an unusable tip hash; failing closed: {}",
					txid,
					e
				);
				return Err(ChainActionError::unavailable(format!("unusable tip hash: {}", e)));
			},
		};
		let anchored = |value| Ok(Anchored { value, tip });

		if !resp.confirmed {
			return anchored(if resp.in_mempool {
				RawTxObservation::InMempool
			} else {
				RawTxObservation::NotFound
			});
		}

		// Confirmed, so the answer must carry a height and a tip to derive
		// depth from. A confirmation without them is incoherent; treat it as
		// no answer rather than inventing a depth.
		let (Some(height), Some(tip_height)) = (resp.confirmation_height, resp.tip_height) else {
			log_error!(
				self.logger,
				"swap_query_tx: chain provider reported {} confirmed without a height/tip pair; failing closed",
				txid
			);
			return Err(ChainActionError::unavailable("confirmed without a height/tip pair"));
		};

		if tip_height < height {
			// The same inconsistency the Esplora adapter guards against (B5
			// LOW-2): a tip below the confirming block cannot happen on one
			// consistent chain.
			log_error!(
				self.logger,
				"swap_query_tx: chain provider tip {} below confirming-block height {} for {} (reorg/race); failing closed",
				tip_height,
				height,
				txid
			);
			return Err(ChainActionError::unavailable(format!(
				"tip {} below confirming-block height {}",
				tip_height, height
			)));
		}

		let confirmations = tip_height.saturating_sub(height).saturating_add(1);
		anchored(RawTxObservation::Confirmed { height: Some(height), confirmations })
	}
}

/// The block a TX_STATUS answer was taken at, when the answer names both its
/// height and its hash; `None` when either is missing.
#[cfg(feature = "swaps")]
fn wire_tip(
	resp: &crate::chain::provider::WireTxStatusResponse,
) -> Result<Option<bdk_chain::BlockId>, crate::chain::provider::ChainProviderError> {
	match (resp.tip_height, resp.tip_hash.as_deref()) {
		(Some(height), Some(hash)) => {
			Ok(Some(bdk_chain::BlockId { height, hash: block_hash_from_wire(hash)? }))
		},
		_ => Ok(None),
	}
}

/// The provider answers completely every time, whatever scope the query
/// asks — it remembers nothing about this node — and the answer is anchored
/// to the tip it reports, which a hybrid node checks against its own chain.
#[async_trait]
impl MempoolAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_MEMPOOL_BUDGET)
	}

	async fn mempool(&self, query: &MempoolQuery) -> ActionResult<Anchored<MempoolAnswer>> {
		let req = mempool_query_to_wire(query);
		let resp = self.provider.mempool(req).await.map_err(|e| {
			log_error!(self.logger, "Chain provider could not answer a mempool question: {}", e);
			ChainActionError::from(e)
		})?;

		let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		let (answer, tip) = wire_to_mempool_answer(&resp, now).map_err(|e| {
			log_error!(self.logger, "Chain provider returned an unusable mempool answer: {}", e);
			ChainActionError::unavailable(e.to_string())
		})?;
		Ok(Anchored { value: answer, tip: Some(tip) })
	}

	async fn second_opinion(&self, txs: &[Transaction]) -> Option<std::collections::HashSet<bitcoin::Txid>> {
		self.provider.second_opinion_on_own_txs(txs).await.map(|opinion| opinion.held)
	}
}

/// The wide scan, run on the provider: the same route the Dependent engine's
/// own wallet sync takes, phrased on the wire request the engine already
/// builds with [`sync_request_to_wire`] and
/// [`full_scan_request_batch_to_wire`].
///
/// The request carries scripts only, so the update's `last_active_indices`
/// is empty: which keys the scripts came from is the asking wallet's own
/// knowledge, and the caller that owns the wallet derives the indices from
/// the returned transactions and its `revealed_spk_index`, as the engine
/// does. The answer is anchored to the update's checkpoint tip, if the scan
/// produced one.
///
/// [`sync_request_to_wire`]: crate::chain::wire_convert::sync_request_to_wire
/// [`full_scan_request_batch_to_wire`]: crate::chain::wire_convert::full_scan_request_batch_to_wire
#[async_trait]
impl ScriptHistoryAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_SCRIPT_HISTORY_BUDGET)
	}

	async fn script_history(
		&self, req: WireSyncRequest,
	) -> ActionResult<Anchored<bdk_wallet::Update>> {
		let spk_count = req.spks.len();
		let wire_update = self.provider.wallet_sync(req).await.map_err(|e| {
			log_error!(
				self.logger,
				"Chain provider could not scan {} scripts' history: {}",
				spk_count,
				e
			);
			ChainActionError::from(e)
		})?;

		let update = wire_update_to_bdk(&wire_update, &HashMap::new()).map_err(|e| {
			log_error!(self.logger, "Chain provider returned an unusable update: {}", e);
			ChainActionError::unavailable(e.to_string())
		})?;
		let tip = update.chain.as_ref().map(|checkpoint| checkpoint.block_id());
		Ok(Anchored { value: update, tip })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::chain::provider::{
		ChainProviderError, WireFeeEstimates, WireFeeTarget, WireLightningSyncRequest,
		WireLightningSyncResponse, WireTxStatusRequest, WireTxStatusResponse, WireUpdate,
	};
	use crate::chain::seam::MempoolScope;
	use crate::logger::Logger;

	fn wire_fees(entries: &[(&str, u64)]) -> WireFeeEstimates {
		WireFeeEstimates {
			version: CHAIN_WIRE_VERSION,
			targets: entries
				.iter()
				.map(|(target, sat_per_kwu)| WireFeeTarget {
					target: (*target).to_string(),
					sat_per_kwu: *sat_per_kwu,
				})
				.collect(),
		}
	}

	fn fee_update(entries: &[(&str, u64)]) -> ActionResult<FeeUpdate> {
		fee_update_from_wire(&wire_fees(entries), &Default::default(), &Logger::new_log_facade())
	}

	fn applied(entries: &[(&str, u64)]) -> HashMap<ConfirmationTarget, FeeRate> {
		match fee_update(entries) {
			Ok(FeeUpdate::Apply { cache, .. }) => cache,
			other => panic!("expected an update, got {:?}", other.map(|_| ())),
		}
	}

	#[test]
	fn the_provider_fee_bounds_are_the_relay_floor_and_1000_sat_per_vb() {
		assert_eq!(MIN_PROVIDER_FEE_SAT_PER_KWU, 253);
		assert_eq!(MAX_PROVIDER_FEE_SAT_PER_KWU, 1_000 * 250);
	}

	/// One number out of bounds says the whole answer cannot be trusted: nothing of it is
	/// applied, and the refusal is one the fee chain falls through.
	#[test]
	fn a_provider_fee_out_of_bounds_rejects_the_whole_update() {
		for bad in [0, 1, 252, 250_001, 10_000_000, u64::MAX] {
			let update =
				fee_update(&[("onchain_payment", 1_000), ("ldk.urgent_onchain_sweep", bad)]);
			assert!(
				matches!(update, Err(ChainActionError::Unavailable { .. })),
				"{bad} must be refused and fall through"
			);
		}
	}

	#[test]
	fn a_provider_fee_at_the_bounds_is_not_refused_and_does_not_get_to_burn_funds() {
		let cache = applied(&[("onchain_payment", 253), ("channel_funding", 250_000)]);
		assert_eq!(cache[&ConfirmationTarget::OnchainPayment].to_sat_per_kwu(), 253);
		assert_eq!(
			cache[&ConfirmationTarget::ChannelFunding].to_sat_per_kwu(),
			SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU
		);
	}

	fn urgent() -> ConfirmationTarget {
		ConfirmationTarget::Lightning(LdkConfirmationTarget::UrgentOnChainSweep)
	}

	fn funding() -> ConfirmationTarget {
		ConfirmationTarget::ChannelFunding
	}

	fn witness_says(sat_per_kwu: u64) -> FeeReference {
		let names = ["channel_funding", "ldk.urgent_onchain_sweep"];
		let entries: Vec<(&str, u64)> = names.iter().map(|name| (*name, sat_per_kwu)).collect();
		FeeReference { witness: Some(wire_fees(&entries)), local_sat_per_kwu: None }
	}

	/// H4: a channel open costs about 200 vB. On a stranger's word alone, at most 100 sat/vB.
	#[test]
	fn on_its_own_word_a_provider_burns_tens_of_thousands_at_most_not_hundreds() {
		let none = FeeReference::default();
		let open_vb: u64 = 200;
		let burn = provider_rate_for(funding(), 250_000, &none) / SAT_PER_VB * open_vb;
		assert_eq!(burn, 20_000);
		// Whatever is under the cap it may say.
		assert_eq!(provider_rate_for(funding(), 1_000, &none), 1_000);
		assert_eq!(provider_rate_for(ConfirmationTarget::OnchainPayment, 250_000, &none), 25_000);
	}

	/// H4: at 1 sat/vB a penalty sits while what it races goes first.
	#[test]
	fn on_its_own_word_a_provider_cannot_leave_an_urgent_claim_at_the_relay_floor() {
		let none = FeeReference::default();
		assert_eq!(provider_rate_for(urgent(), 253, &none), 5 * SAT_PER_VB);
		assert_eq!(provider_rate_for(urgent(), 10_000, &none), 10_000);
		assert_eq!(provider_rate_for(urgent(), 250_000, &none), 250 * SAT_PER_VB);
		let cache = applied(&[("ldk.urgent_onchain_sweep", 253)]);
		assert_eq!(cache[&urgent()].to_sat_per_kwu(), 5 * SAT_PER_VB);
	}

	#[test]
	fn a_reference_holds_both_ends_to_what_fees_are_now() {
		// A quiet market, 4 sat/vB.
		let quiet = witness_says(1_000);
		assert_eq!(provider_rate_for(funding(), 250_000, &quiet), 10 * SAT_PER_VB + 1_500);
		assert_eq!(provider_rate_for(urgent(), 253, &quiet), URGENT_FLOOR_ON_ITS_OWN_WORD_SAT_PER_KWU);
		// A spike a witness speaks of, 300 sat/vB: urgent follows it. Spending does not on a word.
		let spike = witness_says(75_000);
		assert_eq!(provider_rate_for(urgent(), 250_000, &spike), 250_000);
		assert_eq!(provider_rate_for(funding(), 250_000, &spike), SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU);
		// Blocks this node read itself saying so, it does.
		let blocks = FeeReference { witness: None, local_sat_per_kwu: Some(75_000) };
		assert_eq!(provider_rate_for(funding(), 250_000, &blocks), 250_000);
		// Below, the provider's number stands: a cap and a floor, no more.
		assert_eq!(provider_rate_for(funding(), 2_000, &quiet), 2_000);
	}

	#[test]
	fn the_blocks_this_node_read_itself_count_and_the_higher_word_wins() {
		let local = FeeReference { witness: None, local_sat_per_kwu: Some(2_000) };
		assert_eq!(provider_rate_for(funding(), 250_000, &local), 8_000);
		assert_eq!(provider_rate_for(urgent(), 253, &local), URGENT_FLOOR_ON_ITS_OWN_WORD_SAT_PER_KWU);
		let both = FeeReference { local_sat_per_kwu: Some(2_000), ..witness_says(1_000) };
		assert_eq!(provider_rate_for(funding(), 250_000, &both), 8_000);
	}

	/// The reference may be a stranger too: it can move these, within limits of their own.
	#[test]
	fn a_lying_reference_cannot_set_a_claim_high_or_a_spend_below_a_working_rate() {
		let high = witness_says(250_000);
		assert_eq!(provider_rate_for(urgent(), 253, &high), URGENT_FLOOR_MOST_SAT_PER_KWU);
		let low = witness_says(253);
		assert_eq!(provider_rate_for(funding(), 10_000, &low), SPEND_CAP_LEAST_SAT_PER_KWU);
	}

	/// H4. The Pro in the seat and one sybil witness saying 62,500 sat/kwu must not lift a channel
	/// open to the outer bound: on words alone it stays at what one word gets.
	#[test]
	fn a_witness_cannot_lift_the_spend_cap() {
		let high = witness_says(250_000);
		assert_eq!(provider_rate_for(funding(), 250_000, &high), SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU);
		let exactly = witness_says(62_500);
		assert_eq!(provider_rate_for(funding(), 250_000, &exactly), SPEND_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU);
	}

	/// H4, the other way. A low witness and a low Pro, in a spike, with no blocks read here: an urgent
	/// claim does not go below what holds on no reference at all, at either end.
	#[test]
	fn a_low_witness_cannot_sink_an_urgent_claim() {
		let low = witness_says(253);
		assert_eq!(provider_rate_for(urgent(), 253, &low), URGENT_FLOOR_ON_ITS_OWN_WORD_SAT_PER_KWU);
		assert_eq!(provider_rate_for(urgent(), 62_500, &low), URGENT_CAP_ON_ITS_OWN_WORD_SAT_PER_KWU);
	}

	/// The fix for the force-close route holds whatever a reference says.
	#[test]
	fn no_reference_raises_what_this_node_demands_of_its_peers() {
		let anchors = ConfirmationTarget::Lightning(
			LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
		);
		assert_eq!(provider_rate_for(anchors, 250_000, &witness_says(250_000)), 253);
	}

	/// A peer's `update_fee` below these is a force close (`check_remote_fee`), so a provider's
	/// word never raises them, not even inside the bounds.
	#[test]
	fn a_provider_can_never_raise_the_fee_this_node_demands_of_its_peers() {
		let cache = applied(&[
			("ldk.min_allowed_anchor_channel_remote_fee", 250_000),
			("ldk.min_allowed_non_anchor_channel_remote_fee", 250_000),
		]);
		assert_eq!(cache.len(), 2);
		assert!(cache.values().all(|rate| rate.to_sat_per_kwu() == 253), "{cache:?}");
	}

	/// A target this build does not know is skipped before it is judged: a newer Pro's new
	/// target must not cost this node the rest of the answer.
	#[test]
	fn an_unknown_target_out_of_bounds_costs_nothing() {
		let cache = applied(&[("onchain_payment", 1_000), ("from_the_future", u64::MAX)]);
		assert_eq!(cache.len(), 1);
	}

	/// What the session tells of and what the update refuses are one judgement: a told rejection
	/// that nothing rejected would blame a newer Pro for a target this build does not know.
	#[test]
	fn what_is_told_as_rejected_is_exactly_what_the_update_rejects() {
		let answers: [&[(&str, u64)]; 6] = [
			&[("onchain_payment", 1_000)],
			&[("onchain_payment", 253), ("channel_funding", 250_000)],
			&[("onchain_payment", 252)],
			&[("onchain_payment", 1_000), ("ldk.urgent_onchain_sweep", 250_001)],
			&[("onchain_payment", 1_000), ("from_the_future", u64::MAX)],
			&[("ldk.min_allowed_anchor_channel_remote_fee", u64::MAX)],
		];
		for answer in answers {
			assert_eq!(
				fees_out_of_bounds(&wire_fees(answer)).is_some(),
				fee_update(answer).is_err(),
				"{answer:?}"
			);
		}
	}

	/// A provider built against the port as it shipped: it implements the
	/// five original calls and inherits `mempool`'s refusing default.
	struct OlderProvider;

	#[async_trait]
	impl ChainDataProvider for OlderProvider {
		fn name(&self) -> String {
			"older".into()
		}

		async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn broadcast(&self, _req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn tx_status(
			&self, _req: WireTxStatusRequest,
		) -> Result<WireTxStatusResponse, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn wallet_sync(
			&self, _req: WireSyncRequest,
		) -> Result<WireUpdate, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn lightning_sync(
			&self, _req: WireLightningSyncRequest,
		) -> Result<WireLightningSyncResponse, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}
	}

	/// N4: a provider that does not carry the mempool route refuses, and the
	/// adapter reports that as `Unavailable` — not timed out, and never an
	/// empty mempool — so the chain advances past it.
	#[tokio::test]
	async fn dependent_mempool_maps_refused_to_unavailable() {
		let adapter =
			DependentChainAdapter::new(Arc::new(OlderProvider), Arc::new(Logger::new_log_facade()));
		let query = MempoolQuery {
			scripts: Vec::new(),
			known_unconfirmed: Vec::new(),
			scope: MempoolScope::Complete,
		};

		let err = adapter.mempool(&query).await.unwrap_err();

		assert_eq!(
			err,
			ChainActionError::Unavailable {
				reason: ChainProviderError::Refused("unsupported".into()).to_string(),
				timed_out: false,
			}
		);
	}

	/// A provider whose TX_STATUS answer is fixed.
	#[cfg(feature = "swaps")]
	struct AnsweringProvider(WireTxStatusResponse);

	#[cfg(feature = "swaps")]
	#[async_trait]
	impl ChainDataProvider for AnsweringProvider {
		fn name(&self) -> String {
			"answering".into()
		}

		async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn broadcast(&self, _req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn tx_status(
			&self, _req: WireTxStatusRequest,
		) -> Result<WireTxStatusResponse, ChainProviderError> {
			Ok(self.0.clone())
		}

		async fn wallet_sync(
			&self, _req: WireSyncRequest,
		) -> Result<WireUpdate, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn lightning_sync(
			&self, _req: WireLightningSyncRequest,
		) -> Result<WireLightningSyncResponse, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}
	}

	/// The answer is anchored at the serving node's tip when the wire names
	/// both its height and its hash — so a hybrid node's tip check has
	/// something to check — unanchored when either is missing, and refused
	/// when the hash is garbage.
	#[cfg(feature = "swaps")]
	#[tokio::test]
	async fn dependent_tx_status_is_anchored_when_the_wire_names_the_tip() {
		use bitcoin::hashes::Hash;

		let tip_hash = bitcoin::BlockHash::from_byte_array([0x42; 32]);
		let confirmed = WireTxStatusResponse {
			version: CHAIN_WIRE_VERSION,
			confirmed: true,
			in_mempool: false,
			confirmation_height: Some(100),
			tip_height: Some(102),
			tip_hash: Some(tip_hash.to_string()),
		};
		let ask = |resp: WireTxStatusResponse| async move {
			let adapter = DependentChainAdapter::new(
				Arc::new(AnsweringProvider(resp)),
				Arc::new(Logger::new_log_facade()),
			);
			adapter.tx_status(Txid::from_byte_array([1u8; 32]), None).await
		};

		let answer = ask(confirmed.clone()).await.unwrap();
		assert_eq!(
			answer.value,
			RawTxObservation::Confirmed { height: Some(100), confirmations: 3 }
		);
		assert_eq!(answer.tip, Some(bdk_chain::BlockId { height: 102, hash: tip_hash }));

		let in_mempool = WireTxStatusResponse {
			confirmed: false,
			in_mempool: true,
			confirmation_height: None,
			..confirmed.clone()
		};
		let answer = ask(in_mempool).await.unwrap();
		assert_eq!(answer.value, RawTxObservation::InMempool);
		assert_eq!(answer.tip, Some(bdk_chain::BlockId { height: 102, hash: tip_hash }));

		let no_hash = WireTxStatusResponse { tip_hash: None, ..confirmed.clone() };
		let answer = ask(no_hash).await.unwrap();
		assert_eq!(answer.tip, None, "an answer from an older provider is unanchored");
		assert_eq!(
			answer.value,
			RawTxObservation::Confirmed { height: Some(100), confirmations: 3 }
		);

		let garbage = WireTxStatusResponse { tip_hash: Some("not a hash".into()), ..confirmed };
		assert!(matches!(
			ask(garbage).await,
			Err(ChainActionError::Unavailable { timed_out: false, .. })
		));
	}

	/// The budgets are the app's per-call ceiling plus the margin, so the
	/// app's own timeout always fires first.
	#[test]
	fn budgets_outlast_the_apps_provider_call_timeout() {
		let app_ceiling = Duration::from_secs(PROVIDER_CALL_TIMEOUT_SECS);
		assert!(DEPENDENT_FEE_BUDGET > app_ceiling);
		assert_eq!(DEPENDENT_FEE_BUDGET, Duration::from_secs(21));
		assert_eq!(DEPENDENT_BROADCAST_BUDGET, Duration::from_secs(21 * MAX_BROADCAST_PACKAGE_TXS));
		assert_eq!(DEPENDENT_BROADCAST_BUDGET, Duration::from_secs(525));
		assert_eq!(DEPENDENT_MEMPOOL_BUDGET, Duration::from_secs(21));
		assert_eq!(DEPENDENT_SCRIPT_HISTORY_BUDGET, Duration::from_secs(21));
		#[cfg(feature = "swaps")]
		{
			assert!(DEPENDENT_TX_STATUS_BUDGET > app_ceiling);
			assert_eq!(DEPENDENT_TX_STATUS_BUDGET, Duration::from_secs(21));
		}
	}
}
