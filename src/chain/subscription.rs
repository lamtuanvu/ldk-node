// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Who a Pro node pushes blocks to: the serving half of subscribe + pull.
//!
//! A node asks with `chain.subscribe` and holds a lease; while it does, each new block is pushed
//! with `chain.block_update`. Everything a push carries can be pulled with `chain.since`, so a
//! Pro holds no per-node height, and a lease lost in any way costs a node at most a late block:
//!
//! ```text
//!   released by the node    subscribe with lease_secs 0, when it moves to another Pro
//!   release lost            the next push's ack says not_subscribed: dropped at once
//!   node dead               MAX_PUSH_FAILURES failed pushes in a row, or the lease runs out
//!   Pro restarted           leases are in memory only; its nodes see the silence and ask again
//! ```
//!
//! [`AdmissionPolicy`] is the seam where a Pro will one day decide who it serves. Today
//! [`AlwaysAdmit`] grants everyone: no slot limit, since the fan-out is bounded by
//! [`MAX_PUSHES_IN_FLIGHT`] rather than by a count of subscribers. The refusal codes stay on the
//! wire so a node of today knows what to do with a Pro of later.
//!
//! This holds the state and the rules. The embedding app owns the push loop and the transport,
//! as it owns every other peer call. Time comes in as an argument.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::chain::provider::{
	WireBlockId, WireRefusalCode, WireSubscribeGranted, WireSubscribeRefused,
	WireSubscribeReleased, WireSubscribeRequest, WireSubscribeResponse, CHAIN_WIRE_VERSION,
};
use crate::chain::session::machine::normalise_node_id;

/// Longest lease granted; a node asks for an hour.
pub const MAX_LEASE_SECS: u64 = 3600;
/// Shortest lease granted, so a very short ask still gets a push or two. Zero is a release.
pub const MIN_LEASE_SECS: u64 = 60;
/// Consecutive failed pushes after which a lease is dropped.
pub const MAX_PUSH_FAILURES: u32 = 2;
/// Pushes in flight at once, however many leases there are.
pub const MAX_PUSHES_IN_FLIGHT: usize = 8;
/// When a Pro has not read its source's tip yet, how long a node is told to wait.
const TIP_UNKNOWN_RETRY_AFTER_SECS: u64 = 30;

/// What is known about one ask when deciding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionRequest<'a> {
	/// The asker, as the transport verified it.
	pub node_id: &'a str,
	/// Whether the asker holds a lease already.
	pub is_renewal: bool,
	/// How many leases are held now.
	pub active_leases: usize,
}

/// The decision on one ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
	/// Grant the lease.
	Grant,
	/// Refuse, saying why. The asker keeps this Pro and pulls.
	Refuse {
		/// Why, on the wire.
		code: WireRefusalCode,
		/// When to ask again, in seconds.
		retry_after: Option<u64>,
		/// Other Pros the asker might try.
		alternatives: Vec<String>,
	},
}

/// Whether a Pro serves a node. See the module docs.
pub trait AdmissionPolicy: Send + Sync {
	/// Decides one ask. Must not block: it answers a peer call, from memory.
	fn decide(&self, request: &AdmissionRequest<'_>) -> Admission;
}

/// Grants everyone.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysAdmit;

impl AdmissionPolicy for AlwaysAdmit {
	fn decide(&self, _request: &AdmissionRequest<'_>) -> Admission {
		Admission::Grant
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
	id: String,
	until_unix: u64,
	/// The length granted, which an acknowledged push renews.
	secs: u64,
	failures: u32,
}

#[derive(Default)]
struct RegistryState {
	leases: HashMap<String, Lease>,
	/// The source's best block as the pusher last read it: a subscribe answers from here rather
	/// than wait on bitcoind.
	tip: Option<WireBlockId>,
	grants: u64,
}

/// Who holds a lease on this Pro node. In memory only, keyed by the caller's node id as the
/// host verified it.
pub struct SubscriptionRegistry {
	policy: Arc<dyn AdmissionPolicy>,
	state: Mutex<RegistryState>,
}

impl Default for SubscriptionRegistry {
	fn default() -> Self {
		Self::new(Arc::new(AlwaysAdmit))
	}
}

impl SubscriptionRegistry {
	/// A registry deciding asks by `policy`.
	pub fn new(policy: Arc<dyn AdmissionPolicy>) -> Self {
		Self { policy, state: Mutex::new(RegistryState::default()) }
	}

	fn lock(&self) -> MutexGuard<'_, RegistryState> {
		self.state.lock().unwrap_or_else(|p| p.into_inner())
	}

	/// The tip a grant answers with.
	pub fn tip(&self) -> Option<WireBlockId> {
		self.lock().tip.clone()
	}

	/// The source's best block, from the push loop.
	pub fn set_tip(&self, tip: WireBlockId) {
		self.lock().tip = Some(tip);
	}

	/// Answers `chain.subscribe` from `node_id`, as the transport verified it.
	///
	/// `lease_secs: 0` releases whatever it holds and is never refused. Otherwise the policy
	/// decides; a grant takes or renews the lease for what was asked, clamped to
	/// [`MIN_LEASE_SECS`]..=[`MAX_LEASE_SECS`], and clears its failure count. A refusal also ends
	/// any lease held: a Pro's no is a no to pushing.
	pub fn subscribe(
		&self, node_id: &str, request: &WireSubscribeRequest, now_unix: u64,
	) -> WireSubscribeResponse {
		let key = normalise_node_id(node_id);
		let mut state = self.lock();
		state.leases.retain(|_, lease| lease.until_unix > now_unix);

		if request.lease_secs == 0 {
			let released = state.leases.remove(&key).is_some();
			return WireSubscribeResponse::Released(WireSubscribeReleased {
				version: CHAIN_WIRE_VERSION,
				released,
			});
		}
		let refused = |code, retry_after, alternatives| {
			WireSubscribeResponse::Refused(WireSubscribeRefused {
				version: CHAIN_WIRE_VERSION,
				code,
				retry_after,
				alternatives,
			})
		};
		if request.version != CHAIN_WIRE_VERSION {
			return refused(WireRefusalCode::Policy, None, Vec::new());
		}
		let decision = self.policy.decide(&AdmissionRequest {
			node_id: &key,
			is_renewal: state.leases.contains_key(&key),
			active_leases: state.leases.len(),
		});
		if let Admission::Refuse { code, retry_after, alternatives } = decision {
			state.leases.remove(&key);
			return refused(code, retry_after, alternatives);
		}
		let Some(tip) = state.tip.clone() else {
			return refused(
				WireRefusalCode::Draining,
				Some(TIP_UNKNOWN_RETRY_AFTER_SECS),
				Vec::new(),
			);
		};
		let secs = u64::from(request.lease_secs).clamp(MIN_LEASE_SECS, MAX_LEASE_SECS);
		let until_unix = now_unix + secs;
		let id = match state.leases.get(&key) {
			Some(lease) => lease.id.clone(),
			None => {
				state.grants += 1;
				format!("{:x}-{:x}", now_unix, state.grants)
			},
		};
		state.leases.insert(key, Lease { id: id.clone(), until_unix, secs, failures: 0 });
		WireSubscribeResponse::Granted(WireSubscribeGranted {
			version: CHAIN_WIRE_VERSION,
			lease_id: id,
			lease_until: until_unix,
			tip,
		})
	}

	/// The leases alive at `now_unix`, with the end an acknowledged push will grant each: what
	/// the push tells the node. Sorted, so a round's order is stable.
	pub fn live(&self, now_unix: u64) -> Vec<(String, u64)> {
		let state = self.lock();
		let mut live: Vec<(String, u64)> = state
			.leases
			.iter()
			.filter(|(_, lease)| lease.until_unix > now_unix)
			.map(|(id, lease)| (id.clone(), now_unix + lease.secs))
			.collect();
		live.sort();
		live
	}

	/// A push to `node_id` was applied: the lease runs its length from `now_unix`, and its
	/// failures are forgiven. `None` when it was dropped meanwhile; a late ack revives nothing.
	pub fn acked(&self, node_id: &str, now_unix: u64) -> Option<u64> {
		let mut state = self.lock();
		let lease = state.leases.get_mut(&normalise_node_id(node_id))?;
		lease.until_unix = now_unix + lease.secs;
		lease.failures = 0;
		Some(lease.until_unix)
	}

	/// A push's ack said `not_subscribed`: the node left, and its release was lost. Dropped at
	/// once. Returns whether there was a lease.
	pub fn not_subscribed(&self, node_id: &str) -> bool {
		self.lock().leases.remove(&normalise_node_id(node_id)).is_some()
	}

	/// A push to `node_id` failed. Returns `true` when that dropped the lease
	/// ([`MAX_PUSH_FAILURES`] in a row).
	pub fn failed(&self, node_id: &str) -> bool {
		let mut state = self.lock();
		let key = normalise_node_id(node_id);
		let Some(lease) = state.leases.get_mut(&key) else {
			return false;
		};
		lease.failures += 1;
		if lease.failures >= MAX_PUSH_FAILURES {
			state.leases.remove(&key);
			true
		} else {
			false
		}
	}

	/// Forgets the leases that ran out. Returns how many.
	pub fn sweep(&self, now_unix: u64) -> usize {
		let mut state = self.lock();
		let before = state.leases.len();
		state.leases.retain(|_, lease| lease.until_unix > now_unix);
		before - state.leases.len()
	}

	/// Leases held, live or not yet swept.
	pub fn len(&self) -> usize {
		self.lock().leases.len()
	}

	/// Whether no lease is held.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn bid(height: u32) -> WireBlockId {
		WireBlockId { height, hash: format!("{:064x}", height) }
	}

	fn ask(lease_secs: u32) -> WireSubscribeRequest {
		WireSubscribeRequest {
			version: CHAIN_WIRE_VERSION,
			from: bid(90),
			lease_secs,
			want: vec!["blocks".into()],
		}
	}

	fn registry() -> SubscriptionRegistry {
		let r = SubscriptionRegistry::default();
		r.set_tip(bid(100));
		r
	}

	fn granted(response: WireSubscribeResponse) -> WireSubscribeGranted {
		match response {
			WireSubscribeResponse::Granted(granted) => granted,
			other => panic!("not granted: {:?}", other),
		}
	}

	/// The cross-repo contract, as JSON: what the app and an older or newer peer see.
	#[test]
	fn the_wire_reads_as_the_contract_writes_it() {
		use crate::chain::provider::{WireAckStatus, WireBlockUpdateAck, WireBlockUpdates};
		use serde_json::json;

		let from = json!({"height": 90, "hash": "aa"});
		// The host adds the caller's id to what it hands the app.
		let asked: WireSubscribeRequest = serde_json::from_value(json!({
			"version": 1, "from": from, "lease_secs": 3600, "want": ["blocks"],
			"caller_node_id": "02a",
		}))
		.unwrap();
		assert_eq!(asked.lease_secs, 3600);
		assert_eq!(asked.want, vec![crate::chain::provider::SUBSCRIBE_WANT_BLOCKS.to_string()]);
		let bare: WireSubscribeRequest =
			serde_json::from_value(json!({"version": 1, "from": from, "lease_secs": 0})).unwrap();
		assert!(bare.want.is_empty(), "a release need not say what it wanted");

		let tip = json!({"height": 100, "hash": "bb"});
		let granted = json!({"version": 1, "lease_id": "x", "lease_until": 5, "tip": tip});
		let reply: WireSubscribeResponse = serde_json::from_value(granted.clone()).unwrap();
		assert!(matches!(reply, WireSubscribeResponse::Granted(_)));
		assert_eq!(serde_json::to_value(&reply).unwrap(), granted);

		for code in ["full", "policy", "payment_required", "draining"] {
			let refused = json!({
				"version": 1, "code": code, "retry_after": 60, "alternatives": ["02c"],
			});
			let reply: WireSubscribeResponse = serde_json::from_value(refused.clone()).unwrap();
			assert!(matches!(reply, WireSubscribeResponse::Refused(_)), "{}", code);
			assert_eq!(serde_json::to_value(&reply).unwrap(), refused);
		}
		let plain: WireSubscribeResponse =
			serde_json::from_value(json!({"version": 1, "code": "policy"})).unwrap();
		assert_eq!(
			serde_json::to_value(&plain).unwrap(),
			json!({"version": 1, "code": "policy"}),
			"optional parts stay off the wire"
		);
		// A code from a newer Pro is still a refusal.
		let newer: WireSubscribeResponse =
			serde_json::from_value(json!({"version": 1, "code": "maintenance"})).unwrap();
		assert!(matches!(
			newer,
			WireSubscribeResponse::Refused(WireSubscribeRefused {
				code: WireRefusalCode::Unknown,
				..
			})
		));

		let released = json!({"version": 1, "released": true});
		let reply: WireSubscribeResponse = serde_json::from_value(released.clone()).unwrap();
		assert!(matches!(reply, WireSubscribeResponse::Released(_)));
		assert_eq!(serde_json::to_value(&reply).unwrap(), released);

		let ack = WireBlockUpdateAck {
			version: 1,
			status: WireAckStatus::NotSubscribed,
			applied_tip: None,
		};
		assert_eq!(
			serde_json::to_value(&ack).unwrap(),
			json!({"version": 1, "status": "not_subscribed"})
		);
		let applied: WireBlockUpdateAck = serde_json::from_value(json!({
			"version": 1, "status": "applied", "applied_tip": tip,
		}))
		.unwrap();
		assert_eq!(applied.status, WireAckStatus::Applied);

		// A `since` reply carries no lease, and one from an older Pro reads without it.
		let pulled = json!({"version": 1, "tip": tip, "updates": [], "more": false});
		let reply: WireBlockUpdates = serde_json::from_value(pulled.clone()).unwrap();
		assert_eq!(reply.lease_until, None);
		assert_eq!(serde_json::to_value(&reply).unwrap(), pulled);
	}

	#[test]
	fn there_is_no_slot_limit_by_default() {
		let r = registry();
		for i in 0..1000 {
			granted(r.subscribe(&format!("02{:04x}", i), &ask(3600), 1000));
		}
		assert_eq!(r.len(), 1000);
		assert_eq!(MAX_PUSHES_IN_FLIGHT, 8, "what bounds the fan-out instead");
	}

	#[test]
	fn a_lease_is_at_most_an_hour_and_at_least_a_minute() {
		let r = registry();
		let long = granted(r.subscribe("02a", &ask(86_400), 1000));
		assert_eq!(long.lease_until, 1000 + MAX_LEASE_SECS);
		assert_eq!(long.tip, bid(100));
		assert!(!long.lease_id.is_empty());
		let short = granted(r.subscribe("02b", &ask(1), 1000));
		assert_eq!(short.lease_until, 1000 + MIN_LEASE_SECS);
		assert_ne!(long.lease_id, short.lease_id);
	}

	#[test]
	fn a_renewal_keeps_the_lease_id_in_any_case_of_hex_and_clears_failures() {
		let r = registry();
		let first = granted(r.subscribe("02a", &ask(600), 1000));
		assert!(!r.failed("02a"));
		let again = granted(r.subscribe(" 02A ", &ask(600), 1100));
		assert_eq!(first.lease_id, again.lease_id);
		assert_eq!(again.lease_until, 1700);
		assert_eq!(r.len(), 1);
		assert!(!r.failed("02a"), "the renewal reset the count");
	}

	#[test]
	fn lease_secs_zero_releases_and_is_never_refused() {
		struct Never;
		impl AdmissionPolicy for Never {
			fn decide(&self, _: &AdmissionRequest<'_>) -> Admission {
				Admission::Refuse {
					code: WireRefusalCode::Policy,
					retry_after: None,
					alternatives: Vec::new(),
				}
			}
		}
		let r = registry();
		granted(r.subscribe("02a", &ask(600), 1000));
		assert_eq!(
			r.subscribe("02a", &ask(0), 1001),
			WireSubscribeResponse::Released(WireSubscribeReleased {
				version: CHAIN_WIRE_VERSION,
				released: true
			})
		);
		assert!(r.is_empty(), "the old Pro drops it at once");
		assert_eq!(
			r.subscribe("02a", &ask(0), 1002),
			WireSubscribeResponse::Released(WireSubscribeReleased {
				version: CHAIN_WIRE_VERSION,
				released: false
			}),
			"releasing twice is fine"
		);

		// Not even without a tip, nor with a policy that refuses everything.
		let r = SubscriptionRegistry::new(Arc::new(Never));
		assert!(matches!(r.subscribe("02a", &ask(0), 1), WireSubscribeResponse::Released(_)));
	}

	#[test]
	fn a_policy_can_refuse_with_a_code_and_that_ends_a_lease_held() {
		struct NoSecondHolder;
		impl AdmissionPolicy for NoSecondHolder {
			fn decide(&self, request: &AdmissionRequest<'_>) -> Admission {
				if request.node_id == "02a" && (request.is_renewal || request.active_leases == 0) {
					return Admission::Grant;
				}
				Admission::Refuse {
					code: WireRefusalCode::Full,
					retry_after: Some(120),
					alternatives: vec!["02c".into()],
				}
			}
		}
		let r = SubscriptionRegistry::new(Arc::new(NoSecondHolder));
		r.set_tip(bid(1));
		granted(r.subscribe("02a", &ask(600), 1));
		granted(r.subscribe("02a", &ask(600), 2));
		assert_eq!(
			r.subscribe("02b", &ask(600), 3),
			WireSubscribeResponse::Refused(WireSubscribeRefused {
				version: CHAIN_WIRE_VERSION,
				code: WireRefusalCode::Full,
				retry_after: Some(120),
				alternatives: vec!["02c".into()],
			})
		);
		assert_eq!(r.len(), 1);
	}

	#[test]
	fn no_grant_before_the_tip_is_known_or_for_another_wire_version() {
		let r = SubscriptionRegistry::default();
		match r.subscribe("02a", &ask(600), 1) {
			WireSubscribeResponse::Refused(refused) => {
				assert_eq!(refused.code, WireRefusalCode::Draining);
				assert_eq!(refused.retry_after, Some(TIP_UNKNOWN_RETRY_AFTER_SECS));
			},
			other => panic!("{:?}", other),
		}
		assert!(r.is_empty());

		let r = registry();
		let other_version = WireSubscribeRequest { version: CHAIN_WIRE_VERSION + 1, ..ask(600) };
		assert!(matches!(
			r.subscribe("02a", &other_version, 1),
			WireSubscribeResponse::Refused(WireSubscribeRefused {
				code: WireRefusalCode::Policy,
				..
			})
		));
	}

	#[test]
	fn an_ack_renews_the_lease_and_forgives_a_failure() {
		let r = registry();
		granted(r.subscribe("02a", &ask(600), 1000));
		assert!(!r.failed("02a"), "one failure keeps the lease");
		assert_eq!(r.acked("02a", 1500), Some(2100));
		assert!(!r.failed("02a"), "the ack reset the count");
		assert_eq!(r.live(1500), vec![("02a".to_string(), 2100)]);
	}

	#[test]
	fn two_failed_pushes_in_a_row_drop_the_lease_and_a_late_ack_revives_nothing() {
		assert_eq!(MAX_PUSH_FAILURES, 2);
		let r = registry();
		granted(r.subscribe("02a", &ask(600), 1000));
		assert!(!r.failed("02a"));
		assert!(r.failed("02a"));
		assert!(r.is_empty());
		assert_eq!(r.acked("02a", 1001), None);
		assert!(!r.failed("02unknown"));
	}

	#[test]
	fn a_not_subscribed_ack_drops_the_lease_at_once() {
		let r = registry();
		granted(r.subscribe("02a", &ask(600), 1000));
		granted(r.subscribe("02b", &ask(600), 1000));
		assert!(r.not_subscribed("02A"));
		assert_eq!(r.live(1001), vec![("02b".to_string(), 1601)]);
		assert!(!r.not_subscribed("02a"), "nothing left to drop");
	}

	#[test]
	fn an_expired_lease_is_not_live_and_a_sweep_forgets_only_those() {
		let r = registry();
		granted(r.subscribe("02a", &ask(60), 1000));
		granted(r.subscribe("02b", &ask(600), 1000));
		assert_eq!(r.live(1059).len(), 2);
		assert_eq!(r.live(1060).len(), 1, "not pushed to, even before a sweep");
		assert_eq!(r.sweep(1060), 1);
		assert_eq!(r.live(1060), vec![("02b".to_string(), 1660)]);
		assert_eq!(r.acked("02a", 1061), None);
	}
}
