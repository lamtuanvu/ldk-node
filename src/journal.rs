// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Payment-journal observations delivered through a bounded, in-memory queue.
//!
//! These observations are deliberately NOT part of [`crate::Event`]: that queue is persisted
//! and must be acknowledged, so adding variants to it would break older readers of a queued
//! event and cost whole-queue rewrites per observation. [`JournalEvent`]s live only in memory,
//! are never persisted, and are lost on restart or when the queue overflows (oldest first).

use crate::path_failure::{PathFailureAttribution, PathFailureClass};

use lightning::events::HTLCDestination;
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::types::ChannelId;
use lightning::routing::router::Path;
use lightning_types::payment::PaymentHash;

use bitcoin::secp256k1::PublicKey;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of [`JournalEvent`]s retained; on overflow the oldest is dropped.
pub const JOURNAL_QUEUE_CAPACITY: usize = 4096;

/// One hop of a payment path, as recorded in the payment journal.
///
/// Built from a `lightning::routing::router::Path`. When the path ends in a blinded path, only
/// the unblinded hops are listed (up to and including the blinded path's introduction node);
/// the hops inside the blinded tail are hidden from the sender by design. The owning event's
/// `has_blinded_tail` flag tells whether such a tail existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHop {
	/// The node this hop forwards to.
	pub node_id: PublicKey,
	/// The short channel id of the channel used to reach `node_id`. For the first hop or for
	/// route hints this may be an SCID alias.
	pub short_channel_id: u64,
	/// The fee, in millisatoshis, paid to `node_id` for forwarding. For the last hop of a path
	/// WITHOUT a blinded tail this is the amount delivered to the recipient; with a blinded
	/// tail the last listed hop is the introduction node and its value is not the delivered
	/// amount.
	pub fee_msat: u64,
	/// The CLTV delta added for `node_id`. For the last hop of a path without a blinded tail
	/// this is the final CLTV delta.
	pub cltv_expiry_delta: u32,
}

impl PathHop {
	/// Converts the unblinded hops of `path` into journal hops, in path order, and reports
	/// whether the path had a blinded tail.
	pub(crate) fn from_path(path: &Path) -> (Vec<PathHop>, bool) {
		let hops = path
			.hops
			.iter()
			.map(|hop| PathHop {
				node_id: hop.pubkey,
				short_channel_id: hop.short_channel_id,
				fee_msat: hop.fee_msat,
				cltv_expiry_delta: hop.cltv_expiry_delta,
			})
			.collect();
		(hops, path.blinded_tail.is_some())
	}
}

/// Which kind of next destination an HTLC could not be handled for, as reported by
/// [`JournalEvent::HtlcHandlingFailed`]. A stable mirror of LDK's `HTLCDestination`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtlcDestinationKind {
	/// Forwarding over a known outgoing channel failed (e.g. not enough outbound liquidity).
	NextHopChannel,
	/// The requested outgoing short channel id is unknown to us.
	UnknownNextHop,
	/// The forward could not be performed, e.g. a duplicate intercepted HTLC.
	InvalidForward,
	/// The incoming onion could not be decoded.
	InvalidOnion,
	/// An HTLC intended for us was rejected (timeout, overpayment, modified in transit, ...).
	FailedPayment,
	/// A destination kind this version does not model.
	Other,
}

impl HtlcDestinationKind {
	/// Stable snake_case name for logs and wire payloads.
	pub fn as_str(&self) -> &'static str {
		match self {
			HtlcDestinationKind::NextHopChannel => "next_hop_channel",
			HtlcDestinationKind::UnknownNextHop => "unknown_next_hop",
			HtlcDestinationKind::InvalidForward => "invalid_forward",
			HtlcDestinationKind::InvalidOnion => "invalid_onion",
			HtlcDestinationKind::FailedPayment => "failed_payment",
			HtlcDestinationKind::Other => "other",
		}
	}
}

/// The journal-facing fields extracted from an LDK `HTLCDestination`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HtlcDestinationInfo {
	pub(crate) kind: HtlcDestinationKind,
	pub(crate) next_channel_id: Option<ChannelId>,
	pub(crate) next_node_id: Option<PublicKey>,
	pub(crate) failed_payment_hash: Option<PaymentHash>,
	pub(crate) requested_forward_scid: Option<u64>,
}

impl HtlcDestinationInfo {
	pub(crate) fn from_destination(destination: &HTLCDestination) -> Self {
		let bare = |kind| Self {
			kind,
			next_channel_id: None,
			next_node_id: None,
			failed_payment_hash: None,
			requested_forward_scid: None,
		};
		match destination {
			HTLCDestination::NextHopChannel { node_id, channel_id } => Self {
				next_channel_id: Some(*channel_id),
				next_node_id: *node_id,
				..bare(HtlcDestinationKind::NextHopChannel)
			},
			HTLCDestination::UnknownNextHop { requested_forward_scid } => Self {
				requested_forward_scid: Some(*requested_forward_scid),
				..bare(HtlcDestinationKind::UnknownNextHop)
			},
			HTLCDestination::InvalidForward { requested_forward_scid } => Self {
				requested_forward_scid: Some(*requested_forward_scid),
				..bare(HtlcDestinationKind::InvalidForward)
			},
			HTLCDestination::InvalidOnion => bare(HtlcDestinationKind::InvalidOnion),
			HTLCDestination::FailedPayment { payment_hash } => Self {
				failed_payment_hash: Some(*payment_hash),
				..bare(HtlcDestinationKind::FailedPayment)
			},
			#[allow(unreachable_patterns)]
			_ => bare(HtlcDestinationKind::Other),
		}
	}
}

/// A payment-journal observation. Delivered via [`crate::Node::drain_journal_events`], never
/// through the persisted [`crate::Event`] queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEvent {
	/// One payment path attempt failed. Emitted for every failed attempt (each retry), not only
	/// for the terminal failure that [`crate::Event::PaymentFailed`] reports.
	PaymentPathFailed {
		/// Unix time in milliseconds when the observation was captured.
		timestamp_ms: u64,
		/// A local identifier used to track the payment, if LDK provided one.
		payment_id: Option<PaymentId>,
		/// The hash of the payment.
		payment_hash: PaymentHash,
		/// Whether the recipient rejected the payment, making a retry over another route
		/// pointless.
		payment_failed_permanently: bool,
		/// Coarse classification of the failure; see [`PathFailureClass::as_str`].
		failure_class: PathFailureClass,
		/// Zero-based index into `hops` of the hop the HTLC could not be forwarded into, if the
		/// blamed channel is part of the path.
		blamed_hop_index: Option<u32>,
		/// The channel LDK blamed for the failure, if it named one.
		blamed_short_channel_id: Option<u64>,
		/// The unblinded hops of the failed path (see [`PathHop`]).
		hops: Vec<PathHop>,
		/// Whether the path ended in a blinded tail not represented in `hops`.
		has_blinded_tail: bool,
	},
	/// One payment path attempt succeeded. A multi-path payment emits one per path.
	PaymentPathSuccessful {
		/// Unix time in milliseconds when the observation was captured.
		timestamp_ms: u64,
		/// A local identifier used to track the payment.
		payment_id: PaymentId,
		/// The hash of the payment, if LDK provided it.
		payment_hash: Option<PaymentHash>,
		/// The unblinded hops of the successful path (see [`PathHop`]).
		hops: Vec<PathHop>,
		/// Whether the path ended in a blinded tail not represented in `hops`.
		has_blinded_tail: bool,
	},
	/// We failed to handle an HTLC, either one we were asked to forward or one meant for us.
	HtlcHandlingFailed {
		/// Unix time in milliseconds when the observation was captured.
		timestamp_ms: u64,
		/// The channel the HTLC arrived on.
		prev_channel_id: ChannelId,
		/// Which kind of destination could not be handled.
		destination_kind: HtlcDestinationKind,
		/// The outgoing channel we failed to forward over; only for
		/// [`HtlcDestinationKind::NextHopChannel`].
		next_channel_id: Option<ChannelId>,
		/// The node on the outgoing channel, if known; only for
		/// [`HtlcDestinationKind::NextHopChannel`].
		next_node_id: Option<PublicKey>,
		/// The hash of the rejected payment; only for [`HtlcDestinationKind::FailedPayment`].
		failed_payment_hash: Option<PaymentHash>,
		/// The outgoing short channel id the sender asked for; only for
		/// [`HtlcDestinationKind::UnknownNextHop`] and [`HtlcDestinationKind::InvalidForward`].
		requested_forward_scid: Option<u64>,
	},
}

/// Current unix time in milliseconds (0 if the clock is before the epoch).
pub(crate) fn now_ms() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Bounded, non-persisted queue of [`JournalEvent`]s. Drop-oldest on overflow.
pub(crate) struct JournalQueue {
	inner: Mutex<VecDeque<JournalEvent>>,
	capacity: usize,
	dropped: AtomicU64,
}

impl JournalQueue {
	pub(crate) fn new() -> Self {
		Self::with_capacity(JOURNAL_QUEUE_CAPACITY)
	}

	pub(crate) fn with_capacity(capacity: usize) -> Self {
		Self {
			inner: Mutex::new(VecDeque::new()),
			capacity: capacity.max(1),
			dropped: AtomicU64::new(0),
		}
	}

	/// Appends an event, evicting the oldest one when full. Never fails.
	pub(crate) fn push(&self, event: JournalEvent) {
		let mut queue = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		while queue.len() >= self.capacity {
			queue.pop_front();
			self.dropped.fetch_add(1, Ordering::Relaxed);
		}
		queue.push_back(event);
	}

	/// Removes and returns up to `max` of the oldest events, oldest first.
	pub(crate) fn drain(&self, max: usize) -> Vec<JournalEvent> {
		let mut queue = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		let n = max.min(queue.len());
		queue.drain(..n).collect()
	}

	pub(crate) fn dropped(&self) -> u64 {
		self.dropped.load(Ordering::Relaxed)
	}

	pub(crate) fn path_failed(
		&self, payment_id: Option<PaymentId>, payment_hash: PaymentHash,
		payment_failed_permanently: bool, attribution: &PathFailureAttribution, path: &Path,
	) {
		let (hops, has_blinded_tail) = PathHop::from_path(path);
		self.push(JournalEvent::PaymentPathFailed {
			timestamp_ms: now_ms(),
			payment_id,
			payment_hash,
			payment_failed_permanently,
			failure_class: attribution.failure_class,
			blamed_hop_index: attribution.hop_index,
			blamed_short_channel_id: attribution.short_channel_id,
			hops,
			has_blinded_tail,
		});
	}

	pub(crate) fn path_successful(
		&self, payment_id: PaymentId, payment_hash: Option<PaymentHash>, path: &Path,
	) {
		let (hops, has_blinded_tail) = PathHop::from_path(path);
		self.push(JournalEvent::PaymentPathSuccessful {
			timestamp_ms: now_ms(),
			payment_id,
			payment_hash,
			hops,
			has_blinded_tail,
		});
	}

	pub(crate) fn htlc_handling_failed(
		&self, prev_channel_id: ChannelId, destination: &HTLCDestination,
	) {
		let info = HtlcDestinationInfo::from_destination(destination);
		self.push(JournalEvent::HtlcHandlingFailed {
			timestamp_ms: now_ms(),
			prev_channel_id,
			destination_kind: info.kind,
			next_channel_id: info.next_channel_id,
			next_node_id: info.next_node_id,
			failed_payment_hash: info.failed_payment_hash,
			requested_forward_scid: info.requested_forward_scid,
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_pubkey(byte: u8) -> PublicKey {
		let secp = bitcoin::secp256k1::Secp256k1::new();
		PublicKey::from_secret_key(
			&secp,
			&bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap(),
		)
	}

	fn route_hop(
		byte: u8, scid: u64, fee_msat: u64, cltv: u32,
	) -> lightning::routing::router::RouteHop {
		lightning::routing::router::RouteHop {
			pubkey: test_pubkey(byte),
			node_features: lightning::types::features::NodeFeatures::empty(),
			short_channel_id: scid,
			channel_features: lightning::types::features::ChannelFeatures::empty(),
			fee_msat,
			cltv_expiry_delta: cltv,
			maybe_announced_channel: true,
		}
	}

	fn sample_path() -> Path {
		Path {
			hops: vec![route_hop(2, 100, 5, 40), route_hop(3, 200, 1000, 144)],
			blinded_tail: None,
		}
	}

	fn sample_hops() -> Vec<PathHop> {
		vec![
			PathHop {
				node_id: test_pubkey(2),
				short_channel_id: 100,
				fee_msat: 5,
				cltv_expiry_delta: 40,
			},
			PathHop {
				node_id: test_pubkey(3),
				short_channel_id: 200,
				fee_msat: 1000,
				cltv_expiry_delta: 144,
			},
		]
	}

	fn marker(i: u64) -> JournalEvent {
		JournalEvent::HtlcHandlingFailed {
			timestamp_ms: i,
			prev_channel_id: ChannelId([1u8; 32]),
			destination_kind: HtlcDestinationKind::InvalidOnion,
			next_channel_id: None,
			next_node_id: None,
			failed_payment_hash: None,
			requested_forward_scid: None,
		}
	}

	fn ts(e: &JournalEvent) -> u64 {
		match e {
			JournalEvent::HtlcHandlingFailed { timestamp_ms, .. }
			| JournalEvent::PaymentPathFailed { timestamp_ms, .. }
			| JournalEvent::PaymentPathSuccessful { timestamp_ms, .. } => *timestamp_ms,
		}
	}

	#[test]
	fn queue_is_bounded_and_drops_oldest() {
		let q = JournalQueue::with_capacity(3);
		for i in 0..5 {
			q.push(marker(i));
		}
		assert_eq!(q.dropped(), 2);
		let got: Vec<u64> = q.drain(10).iter().map(ts).collect();
		assert_eq!(got, vec![2, 3, 4]);
		assert_eq!(q.dropped(), 2);
	}

	#[test]
	fn default_capacity_is_the_constant() {
		let q = JournalQueue::new();
		for i in 0..(JOURNAL_QUEUE_CAPACITY as u64 + 1) {
			q.push(marker(i));
		}
		assert_eq!(q.dropped(), 1);
		assert_eq!(q.drain(usize::MAX).len(), JOURNAL_QUEUE_CAPACITY);
	}

	#[test]
	fn drain_respects_max_and_order() {
		let q = JournalQueue::with_capacity(10);
		for i in 0..5 {
			q.push(marker(i));
		}
		assert_eq!(q.drain(2).iter().map(ts).collect::<Vec<_>>(), vec![0, 1]);
		assert!(q.drain(0).is_empty());
		assert_eq!(q.drain(10).iter().map(ts).collect::<Vec<_>>(), vec![2, 3, 4]);
		assert!(q.drain(10).is_empty());
		assert_eq!(q.dropped(), 0);
	}

	#[test]
	fn path_hops_without_blinded_tail() {
		let (hops, blinded) = PathHop::from_path(&sample_path());
		assert_eq!(hops, sample_hops());
		assert!(!blinded);
	}

	#[test]
	fn path_hops_with_blinded_tail() {
		use lightning::blinded_path::BlindedHop;
		use lightning::routing::router::BlindedTail;
		let tail = BlindedTail {
			hops: vec![BlindedHop {
				blinded_node_id: test_pubkey(9),
				encrypted_payload: vec![1, 2, 3],
			}],
			blinding_point: test_pubkey(8),
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: 1000,
		};
		let path = Path { hops: vec![route_hop(2, 100, 5, 40)], blinded_tail: Some(tail) };
		let (hops, blinded) = PathHop::from_path(&path);
		assert_eq!(hops.len(), 1);
		assert_eq!(hops[0].node_id, test_pubkey(2));
		assert!(blinded);
	}

	#[test]
	fn htlc_destination_mapping() {
		let chan = ChannelId([7u8; 32]);
		let node = test_pubkey(4);
		let hash = PaymentHash([9u8; 32]);

		let got = HtlcDestinationInfo::from_destination(&HTLCDestination::NextHopChannel {
			node_id: Some(node),
			channel_id: chan,
		});
		assert_eq!(got.kind, HtlcDestinationKind::NextHopChannel);
		assert_eq!(got.next_channel_id, Some(chan));
		assert_eq!(got.next_node_id, Some(node));
		assert_eq!(got.failed_payment_hash, None);
		assert_eq!(got.requested_forward_scid, None);

		let got = HtlcDestinationInfo::from_destination(&HTLCDestination::FailedPayment {
			payment_hash: hash,
		});
		assert_eq!(got.kind, HtlcDestinationKind::FailedPayment);
		assert_eq!(got.failed_payment_hash, Some(hash));
		assert_eq!(got.next_channel_id, None);

		for (dest, kind) in [
			(
				HTLCDestination::UnknownNextHop { requested_forward_scid: 42 },
				HtlcDestinationKind::UnknownNextHop,
			),
			(
				HTLCDestination::InvalidForward { requested_forward_scid: 42 },
				HtlcDestinationKind::InvalidForward,
			),
		] {
			let got = HtlcDestinationInfo::from_destination(&dest);
			assert_eq!(got.kind, kind);
			assert_eq!(got.requested_forward_scid, Some(42));
			assert_eq!(got.next_channel_id, None);
			assert_eq!(got.failed_payment_hash, None);
		}

		let got = HtlcDestinationInfo::from_destination(&HTLCDestination::InvalidOnion);
		assert_eq!(got.kind, HtlcDestinationKind::InvalidOnion);
		assert_eq!(got.requested_forward_scid, None);
	}

	#[test]
	fn destination_kind_names_are_stable() {
		assert_eq!(HtlcDestinationKind::NextHopChannel.as_str(), "next_hop_channel");
		assert_eq!(HtlcDestinationKind::UnknownNextHop.as_str(), "unknown_next_hop");
		assert_eq!(HtlcDestinationKind::InvalidForward.as_str(), "invalid_forward");
		assert_eq!(HtlcDestinationKind::InvalidOnion.as_str(), "invalid_onion");
		assert_eq!(HtlcDestinationKind::FailedPayment.as_str(), "failed_payment");
		assert_eq!(HtlcDestinationKind::Other.as_str(), "other");
	}

	#[test]
	fn recorders_push_the_right_events() {
		let q = JournalQueue::with_capacity(10);
		let before = now_ms();

		q.path_failed(
			Some(PaymentId([1u8; 32])),
			PaymentHash([2u8; 32]),
			true,
			&PathFailureAttribution {
				short_channel_id: Some(200),
				failing_node_id: Some(test_pubkey(3)),
				hop_index: Some(1),
				failure_class: PathFailureClass::Transient,
				graph_lookup_meaningful: true,
			},
			&sample_path(),
		);
		q.path_successful(PaymentId([3u8; 32]), None, &sample_path());
		q.htlc_handling_failed(
			ChannelId([5u8; 32]),
			&HTLCDestination::UnknownNextHop { requested_forward_scid: 77 },
		);

		let events = q.drain(10);
		assert_eq!(events.len(), 3);
		assert!(events.iter().all(|e| ts(e) >= before));

		match &events[0] {
			JournalEvent::PaymentPathFailed {
				payment_id,
				payment_hash,
				payment_failed_permanently,
				failure_class,
				blamed_hop_index,
				blamed_short_channel_id,
				hops,
				has_blinded_tail,
				..
			} => {
				assert_eq!(*payment_id, Some(PaymentId([1u8; 32])));
				assert_eq!(*payment_hash, PaymentHash([2u8; 32]));
				assert!(*payment_failed_permanently);
				assert_eq!(*failure_class, PathFailureClass::Transient);
				assert_eq!(*blamed_hop_index, Some(1));
				assert_eq!(*blamed_short_channel_id, Some(200));
				assert_eq!(*hops, sample_hops());
				assert!(!*has_blinded_tail);
			},
			other => panic!("unexpected {:?}", other),
		}
		match &events[1] {
			JournalEvent::PaymentPathSuccessful { payment_id, payment_hash, hops, .. } => {
				assert_eq!(*payment_id, PaymentId([3u8; 32]));
				assert_eq!(*payment_hash, None);
				assert_eq!(*hops, sample_hops());
			},
			other => panic!("unexpected {:?}", other),
		}
		match &events[2] {
			JournalEvent::HtlcHandlingFailed {
				prev_channel_id,
				destination_kind,
				requested_forward_scid,
				..
			} => {
				assert_eq!(*prev_channel_id, ChannelId([5u8; 32]));
				assert_eq!(*destination_kind, HtlcDestinationKind::UnknownNextHop);
				assert_eq!(*requested_forward_scid, Some(77));
			},
			other => panic!("unexpected {:?}", other),
		}
	}
}
