// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Per-payment capture of the last `PaymentPathFailed` LDK event.
//!
//! LDK reports *which* hop of a path failed and *why* through
//! [`Event::PaymentPathFailed`], but LDK Node historically dropped that event on the
//! floor and only surfaced the terminal `PaymentFailed`. Callers that drive routes by
//! hand (the cooperative cycle-balance primitive, `Node::send_along_route`) need the
//! per-hop detail to decide what to avoid next time. This module keeps a small,
//! bounded, in-memory record of the most recent path failure per [`PaymentId`] so a
//! caller can ask "for payment X, which hop broke and why?" after observing the
//! payment fail.
//!
//! Nothing here is persisted and no new user-facing [`crate::Event`] is emitted.
//!
//! [`Event::PaymentPathFailed`]: lightning::events::Event::PaymentPathFailed

use lightning::events::PathFailure;
use lightning::ln::channelmanager::PaymentId;
use lightning::routing::gossip::NetworkUpdate;
use lightning::routing::router::Path;

use bitcoin::secp256k1::PublicKey;

use std::collections::VecDeque;
use std::sync::Mutex;

/// Upper bound on the number of payments whose last path failure is retained.
///
/// Once full, the oldest record is evicted on insert.
pub const PATH_FAILURE_STORE_CAPACITY: usize = 256;

/// Coarse classification of why a payment path failed.
///
/// Derived from [`PathFailure`] and the optional [`NetworkUpdate`] it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFailureClass {
	/// A hop reported that the failing channel is gone for good
	/// (`NetworkUpdate::ChannelFailure { is_permanent: true }`). LDK's background
	/// processor removes it from the network graph.
	ChannelClosed,
	/// A hop reported that a node on the path is unreachable or misbehaving
	/// (`NetworkUpdate::NodeFailure`, permanent or not).
	NodeDown,
	/// A hop failed the HTLC in a way that may recover: a temporary channel failure
	/// (`NetworkUpdate::ChannelFailure { is_permanent: false }`) or an on-path error
	/// carrying no graph update at all (fee/CLTV mismatch, liquidity, etc.).
	Transient,
	/// Our own node refused to send before any HTLC was committed
	/// ([`PathFailure::InitialSend`]), e.g. the first hop channel is not usable.
	Local,
	/// No path failure is recorded for the payment. Never produced by the
	/// capture itself; reserved for consumers that need a "nothing known" value.
	Unknown,
}

impl PathFailureClass {
	/// Stable snake_case name for logs and wire payloads.
	pub fn as_str(&self) -> &'static str {
		match self {
			PathFailureClass::ChannelClosed => "channel_closed",
			PathFailureClass::NodeDown => "node_down",
			PathFailureClass::Transient => "transient",
			PathFailureClass::Local => "local",
			PathFailureClass::Unknown => "unknown",
		}
	}
}

/// What LDK told us about the last failed path of a payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFailureInfo {
	/// The channel LDK blamed for the failure, if it named one.
	///
	/// For the first hop or for route hints this may be an SCID alias rather than a
	/// channel present in the public graph.
	pub short_channel_id: Option<u64>,
	/// The node that owns the failing outgoing channel, i.e. the forwarder that
	/// failed the HTLC: for the first hop that is our own node, otherwise the
	/// previous hop's node. For a [`NetworkUpdate::NodeFailure`] it is the node LDK
	/// named. `None` when the blamed channel is not part of the reported path.
	pub failing_node_id: Option<PublicKey>,
	/// Zero-based index into the path's hops of the hop whose
	/// `short_channel_id` matches the blamed channel. `None` when the blamed
	/// channel is not part of the reported path (an alias, or no channel blamed).
	pub hop_index: Option<u32>,
	/// Coarse failure classification.
	pub failure_class: PathFailureClass,
	/// LDK's `payment_failed_permanently`: the recipient rejected the payment, so
	/// retrying over another route is pointless.
	pub payment_failed_permanently: bool,
	/// Whether the blamed channel was absent from our network graph when the
	/// failure was recorded.
	///
	/// LDK's background processor applies the event's `network_update` to the graph
	/// itself and the ordering of that application relative to our event handler is
	/// not guaranteed, so this is an *observation* taken at capture time, not proof
	/// that the capture caused or awaited the prune. Only computed when the blamed
	/// hop is part of the path and flagged as possibly announced; an unannounced or
	/// aliased channel is never in the graph and would read as a false positive.
	pub graph_pruned: bool,
	/// Unix timestamp (seconds) at which the failure was recorded.
	pub at_unix_secs: u64,
}

/// Bounded, most-recent-wins record of path failures keyed by [`PaymentId`].
pub(crate) struct PathFailureStore {
	entries: Mutex<VecDeque<(PaymentId, PathFailureInfo)>>,
}

impl PathFailureStore {
	pub(crate) fn new() -> Self {
		Self { entries: Mutex::new(VecDeque::with_capacity(PATH_FAILURE_STORE_CAPACITY)) }
	}

	/// Records `info` for `payment_id`, replacing any earlier record for the same
	/// payment and evicting the oldest record once the store is full.
	pub(crate) fn insert(&self, payment_id: PaymentId, info: PathFailureInfo) {
		let mut entries = self.entries.lock().unwrap();
		if let Some(pos) = entries.iter().position(|(id, _)| *id == payment_id) {
			entries.remove(pos);
		}
		entries.push_back((payment_id, info));
		while entries.len() > PATH_FAILURE_STORE_CAPACITY {
			entries.pop_front();
		}
	}

	#[cfg(any(feature = "cycles", test))]
	pub(crate) fn get(&self, payment_id: &PaymentId) -> Option<PathFailureInfo> {
		let entries = self.entries.lock().unwrap();
		entries.iter().find(|(id, _)| id == payment_id).map(|(_, info)| info.clone())
	}
}

/// The parts of a [`PathFailureInfo`] that follow purely from the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathFailureAttribution {
	pub(crate) short_channel_id: Option<u64>,
	pub(crate) failing_node_id: Option<PublicKey>,
	pub(crate) hop_index: Option<u32>,
	pub(crate) failure_class: PathFailureClass,
	/// Whether the blamed hop was found in the path *and* may be publicly
	/// announced, i.e. whether a graph lookup for it is meaningful.
	pub(crate) graph_lookup_meaningful: bool,
}

/// Classifies a path failure and attributes it to a hop and node.
///
/// Pure function over the event payload so it can be unit-tested without a node.
/// `short_channel_id` is the event's blamed channel; when it is `None` but the
/// failure carries a `ChannelFailure` update, that update's channel is used.
pub(crate) fn attribute_path_failure(
	path: &Path, short_channel_id: Option<u64>, failure: &PathFailure, our_node_id: &PublicKey,
) -> PathFailureAttribution {
	let (failure_class, update_scid, update_node) = match failure {
		PathFailure::InitialSend { .. } => (PathFailureClass::Local, None, None),
		PathFailure::OnPath { network_update } => match network_update {
			Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true }) => {
				(PathFailureClass::ChannelClosed, Some(*short_channel_id), None)
			},
			Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }) => {
				(PathFailureClass::Transient, Some(*short_channel_id), None)
			},
			Some(NetworkUpdate::NodeFailure { node_id, .. }) => {
				(PathFailureClass::NodeDown, None, Some(*node_id))
			},
			None => (PathFailureClass::Transient, None, None),
		},
	};

	let short_channel_id = short_channel_id.or(update_scid);

	let hop = short_channel_id.and_then(|scid| {
		path.hops.iter().position(|hop| hop.short_channel_id == scid).map(|i| (i, &path.hops[i]))
	});

	let hop_index = hop.map(|(i, _)| i as u32);

	let forwarder = hop.map(|(i, _)| if i == 0 { *our_node_id } else { path.hops[i - 1].pubkey });

	let failing_node_id = update_node.or(forwarder);

	let graph_lookup_meaningful = hop.map(|(_, h)| h.maybe_announced_channel).unwrap_or(false);

	PathFailureAttribution {
		short_channel_id,
		failing_node_id,
		hop_index,
		failure_class,
		graph_lookup_meaningful,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use lightning::routing::router::RouteHop;
	use lightning::types::features::{ChannelFeatures, NodeFeatures};
	use lightning::util::errors::APIError;

	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	fn pubkey(byte: u8) -> PublicKey {
		let secp = Secp256k1::new();
		PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
	}

	fn hop(pubkey: PublicKey, scid: u64) -> RouteHop {
		RouteHop {
			pubkey,
			node_features: NodeFeatures::empty(),
			short_channel_id: scid,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 0,
			cltv_expiry_delta: 40,
			maybe_announced_channel: true,
		}
	}

	/// us --100--> A --200--> B --300--> us (a three-hop cycle back to ourselves).
	fn cycle_path(us: PublicKey, a: PublicKey, b: PublicKey) -> Path {
		Path { hops: vec![hop(a, 100), hop(b, 200), hop(us, 300)], blinded_tail: None }
	}

	#[test]
	fn permanent_channel_failure_mid_path_is_channel_closed_blamed_on_forwarder() {
		let (us, a, b) = (pubkey(1), pubkey(2), pubkey(3));
		let path = cycle_path(us, a, b);
		let failure = PathFailure::OnPath {
			network_update: Some(NetworkUpdate::ChannelFailure {
				short_channel_id: 200,
				is_permanent: true,
			}),
		};

		let got = attribute_path_failure(&path, Some(200), &failure, &us);

		assert_eq!(got.failure_class, PathFailureClass::ChannelClosed);
		assert_eq!(got.short_channel_id, Some(200));
		assert_eq!(got.hop_index, Some(1));
		assert_eq!(got.failing_node_id, Some(a));
		assert!(got.graph_lookup_meaningful);
	}

	#[test]
	fn node_failure_is_node_down_blamed_on_the_named_node() {
		let (us, a, b) = (pubkey(1), pubkey(2), pubkey(3));
		let path = cycle_path(us, a, b);
		let failure = PathFailure::OnPath {
			network_update: Some(NetworkUpdate::NodeFailure { node_id: b, is_permanent: false }),
		};

		let got = attribute_path_failure(&path, Some(300), &failure, &us);

		assert_eq!(got.failure_class, PathFailureClass::NodeDown);
		assert_eq!(got.short_channel_id, Some(300));
		assert_eq!(got.hop_index, Some(2));
		assert_eq!(got.failing_node_id, Some(b));
	}

	#[test]
	fn temporary_channel_failure_and_bare_on_path_are_transient() {
		let (us, a, b) = (pubkey(1), pubkey(2), pubkey(3));
		let path = cycle_path(us, a, b);

		let temporary = PathFailure::OnPath {
			network_update: Some(NetworkUpdate::ChannelFailure {
				short_channel_id: 300,
				is_permanent: false,
			}),
		};
		let got = attribute_path_failure(&path, Some(300), &temporary, &us);
		assert_eq!(got.failure_class, PathFailureClass::Transient);
		assert_eq!(got.hop_index, Some(2));
		assert_eq!(got.failing_node_id, Some(b));

		let bare = PathFailure::OnPath { network_update: None };
		let got = attribute_path_failure(&path, Some(100), &bare, &us);
		assert_eq!(got.failure_class, PathFailureClass::Transient);
		assert_eq!(got.hop_index, Some(0));
		assert_eq!(got.failing_node_id, Some(us), "first hop is our own outgoing channel");
	}

	#[test]
	fn initial_send_is_local_and_blamed_on_us() {
		let (us, a, b) = (pubkey(1), pubkey(2), pubkey(3));
		let path = cycle_path(us, a, b);
		let failure = PathFailure::InitialSend {
			err: APIError::ChannelUnavailable { err: "peer disconnected".to_string() },
		};

		let got = attribute_path_failure(&path, Some(100), &failure, &us);

		assert_eq!(got.failure_class, PathFailureClass::Local);
		assert_eq!(got.short_channel_id, Some(100));
		assert_eq!(got.hop_index, Some(0));
		assert_eq!(got.failing_node_id, Some(us));
	}

	#[test]
	fn scid_not_in_path_yields_no_hop_attribution() {
		let (us, a, b) = (pubkey(1), pubkey(2), pubkey(3));
		let path = cycle_path(us, a, b);
		let failure = PathFailure::OnPath {
			network_update: Some(NetworkUpdate::ChannelFailure {
				short_channel_id: 999,
				is_permanent: true,
			}),
		};

		let got = attribute_path_failure(&path, Some(999), &failure, &us);

		assert_eq!(got.failure_class, PathFailureClass::ChannelClosed);
		assert_eq!(got.short_channel_id, Some(999));
		assert_eq!(got.hop_index, None);
		assert_eq!(got.failing_node_id, None);
		assert!(!got.graph_lookup_meaningful);

		// No blamed channel at all: nothing to attribute, class still follows the update.
		let got =
			attribute_path_failure(&path, None, &PathFailure::OnPath { network_update: None }, &us);
		assert_eq!(got.failure_class, PathFailureClass::Transient);
		assert_eq!(got.short_channel_id, None);
		assert_eq!(got.hop_index, None);
		assert_eq!(got.failing_node_id, None);
	}

	#[test]
	fn missing_event_scid_falls_back_to_the_update_scid() {
		let (us, a, b) = (pubkey(1), pubkey(2), pubkey(3));
		let path = cycle_path(us, a, b);
		let failure = PathFailure::OnPath {
			network_update: Some(NetworkUpdate::ChannelFailure {
				short_channel_id: 200,
				is_permanent: true,
			}),
		};

		let got = attribute_path_failure(&path, None, &failure, &us);

		assert_eq!(got.short_channel_id, Some(200));
		assert_eq!(got.hop_index, Some(1));
		assert_eq!(got.failing_node_id, Some(a));
	}

	#[test]
	fn unannounced_hop_makes_graph_lookup_meaningless() {
		let (us, a, b) = (pubkey(1), pubkey(2), pubkey(3));
		let mut path = cycle_path(us, a, b);
		path.hops[0].maybe_announced_channel = false;
		let failure = PathFailure::OnPath { network_update: None };

		let got = attribute_path_failure(&path, Some(100), &failure, &us);

		assert_eq!(got.hop_index, Some(0));
		assert!(!got.graph_lookup_meaningful);
	}

	#[test]
	fn class_names_are_snake_case() {
		assert_eq!(PathFailureClass::ChannelClosed.as_str(), "channel_closed");
		assert_eq!(PathFailureClass::NodeDown.as_str(), "node_down");
		assert_eq!(PathFailureClass::Transient.as_str(), "transient");
		assert_eq!(PathFailureClass::Local.as_str(), "local");
		assert_eq!(PathFailureClass::Unknown.as_str(), "unknown");
	}

	fn info(at: u64) -> PathFailureInfo {
		PathFailureInfo {
			short_channel_id: None,
			failing_node_id: None,
			hop_index: None,
			failure_class: PathFailureClass::Transient,
			payment_failed_permanently: false,
			graph_pruned: false,
			at_unix_secs: at,
		}
	}

	#[test]
	fn store_is_bounded_and_evicts_the_oldest() {
		let store = PathFailureStore::new();
		for i in 0..(PATH_FAILURE_STORE_CAPACITY as u64 + 8) {
			let mut id = [0u8; 32];
			id[..8].copy_from_slice(&i.to_be_bytes());
			store.insert(PaymentId(id), info(i));
		}

		let oldest = PaymentId([0u8; 32]);
		assert_eq!(store.get(&oldest), None, "oldest entry must have been evicted");

		let mut newest = [0u8; 32];
		newest[..8].copy_from_slice(&(PATH_FAILURE_STORE_CAPACITY as u64 + 7).to_be_bytes());
		assert_eq!(store.get(&PaymentId(newest)).map(|i| i.at_unix_secs), Some(263));

		let entries = store.entries.lock().unwrap();
		assert_eq!(entries.len(), PATH_FAILURE_STORE_CAPACITY);
	}

	#[test]
	fn store_replaces_an_earlier_record_for_the_same_payment() {
		let store = PathFailureStore::new();
		let id = PaymentId([7u8; 32]);
		store.insert(id, info(1));
		store.insert(id, info(2));

		assert_eq!(store.get(&id).map(|i| i.at_unix_secs), Some(2));
		assert_eq!(store.entries.lock().unwrap().len(), 1);
	}
}
