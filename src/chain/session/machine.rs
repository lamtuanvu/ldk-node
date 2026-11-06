// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The provider session's state machine: which Pro node this node follows, whether that Pro is
//! alive, and how its blocks arrive.
//!
//! Pure on purpose: no clock, no I/O, no async. Every input carries the time ([`Now`]); every
//! effect comes back out of [`ProviderSession::poll`] as an [`Action`] for the driver in
//! [`super`] to perform, whose result is fed back in. It knows nothing of gossip, prices or
//! transports: candidates go in, status comes out, so it ports to `node-chain` as it stands.
//!
//! ```text
//!               probe answered, or any call answered
//!        ┌────────────────────────────────────────────────┐
//!        ▼                                                │
//!     Active ── probe failed ──► Suspect ── 3 retries ──► Unreachable ──► another Pro answers:
//!        ▲                         30 s, 1 min, 2 min         │            Active on that Pro
//!        │                                                    ▼
//!        └───────── a candidate answers ◄─────────────── NoProvider (keeps probing)
//! ```
//!
//! # What decides
//!
//! Silence is not evidence: blocks can be an hour apart. Only the result of a direct call moves
//! the state. A card's age on gossip ([`ProviderSession::card_age_hint`]) and a failed ordinary
//! call only bring a probe forward; the probe's answer decides. A first `Unsupported` does not
//! count, because the host answers the same for a Pro too old to know the route and for a Pro
//! whose app is restarting.
//!
//! # Delivery
//!
//! A field of the session, not a state. A Pro refusing push moves the node to [`Delivery::Pull`],
//! never to another Pro. What each delivery uses to know the Pro is alive:
//!
//! * [`Delivery::Pull`]: the sync loop's own 30 s tip poll is the signal. Each answer is a
//!   [`ProviderSession::on_call_answered`], so a probe only runs after [`NO_SIGNAL_PROBE_AFTER`]
//!   without one.
//! * [`Delivery::Push`]: nothing is polled. [`NO_SIGNAL_PROBE_AFTER`] without a push is what
//!   brings on a probe, and an unrelated answered call does not push that back, since a Pro can
//!   answer fees and still have lost this node's lease.
//!
//! # No flapping
//!
//! Once on a Pro the node stays until that Pro fails. A candidate ranked higher, or a Pro
//! coming back, moves nothing. A new list moves the node only when the active Pro has left it,
//! and only once another candidate has answered.
//!
//! # A Pro proven lying
//!
//! [`Action::CrossCheck`] compares the active Pro's filter headers with a second Pro's at
//! [`CROSS_CHECK_INTERVAL`]; [`super::cross_check`] has the rules of proof. A Pro proven lying is
//! dropped for [`DROPPED_PRO_FOR`], across restarts. If it was the active one the node leaves it at
//! once and reads [`SessionState::NoProvider`] until another answers. An owner's pin stays, and
//! the status names what it did; pinning a dropped Pro forgives it.
//!
//! # A difference nobody can attribute
//!
//! When the block cannot show which Pro is right, **nobody is dropped**: a Pro goes only when it is
//! proven wrong. Otherwise one attacker tagging itself a Pro could cost a node its honest witnesses,
//! one per check, and be left the only source it asks. The node stays, the status names both and
//! where it stands ([`FilterConflict`]), and either remains a Pro the owner can choose.
//!
//! What protects the node meanwhile is not a verdict: it reads the block itself, whoever is right
//! ([`super::cross_check`]), and the witness keeps being asked, so a later proof or matching answers
//! end it. A third Pro is asked at once about the block they part at ([`Action::TieBreak`]), and
//! its answer is told to the owner. **It moves nobody.** Two to one proves nothing, keys being free:
//! the seat is worth having, as the Pro in it hears every broadcast first and answers the sync loop,
//! so two sybils must not be able to take it for free. Only proof moves a node: a Pro convicted, or
//! a witness showing more work.
//!
//! # Who chooses
//!
//! A node that verifies what it follows takes a source off the list by itself: proof of work and
//! the checks above stand between it and that source. A node with no such check, a Dependent one,
//! simply believes its source. So it does not take one by itself, and a list is only something for
//! its owner to choose from: it asks nobody on it, and the status says it needs the owner
//! ([`ProviderSession::needs_owner_choice`]). Its owner can pin any source, use any for now, or say
//! let it choose ([`ProviderSession::set_auto_source`]), which is then what it does. The rule is
//! about who decides, not what can be picked. A source it was given it keeps until it dies; it does
//! not fail over to a stranger then, and asks again only what it was given.
//!
//! The same switch turns this off on any node, for an owner who wants no discovery at all.
//!
//! # A Pro that does not show the chain
//!
//! Probes and calls can only say a Pro answers. A Pro can answer every question and leave out the
//! block that holds a revoked commitment, and a node that only asks it has no way to know. Time
//! alone cannot decide it: blocks can be an hour apart, and a gap of three hours comes about once
//! in decades, a gap of 30 minutes several times a day. So **silence is only a reason to ask, and
//! only proof of work moves the node.**
//!
//! [`Action::TipCheck`] asks a second Pro for its tip and for headers above this node's. A claim
//! is worth nothing until its headers pass every check this node's own chain has to pass, and
//! those carry the same work a real block does, so nobody can make one up to move a node. Asked at
//! each [`CROSS_CHECK_INTERVAL`], and sooner with no block for [`TIP_CHECK_QUIET_AFTER`], or when
//! the sync loop reports a stale tip or that it is stuck. About 3 calls a day at the usual pace.
//!
//! With headers proving more work than this node holds, the active Pro is behind that second Pro.
//! That may be a block just found, so it is asked again every [`BEHIND_RECHECK`], and:
//!
//! * Caught up: nothing happened.
//! * Not caught up after [`BEHIND_LEAVE_AFTER`]: the node moves to the Pro that showed the block.
//! * Moving, and saying it has the blocks: a node catching up, given [`BEHIND_CATCHING_UP_LIMIT`]
//!   so that a Pro cannot keep it hanging by feeding it slowly.
//!
//! **The bound, and what it rests on:** a block a witness can show is taken, or the node has left,
//! at most [`BEHIND_LEAVE_AFTER`] after that witness is asked, and for a Pro feeding slowly at most
//! [`BEHIND_CATCHING_UP_LIMIT`]. When an honest witness gets asked depends on its turn: witnesses
//! take turns, about three checks an hour, every other turn going to those known longest
//! ([`SessionMemory::longest_known`]). So with one honest among the four known longest it is about 3
//! hours at worst; with one honest on a list of 15 strangers, about 10. **With no honest witness
//! there is no bound of this kind:** a tip three hours old reads stale, and a Pro delaying every
//! block by less than that is not caught at all, about 18 blocks of time against a deadline. That
//! is the case for a pin.
//!
//! With a pin it stays, and [`Self::chain_stale`] says so. With nobody else to ask, it stays and
//! the status says there is no witness; what it can show then is only a tip that has gone stale.
//! Not left for silence: a tip three hours old with every witness at the same tip is the network,
//! and the status says stale without blaming anyone.
//!
//! # What a sync loop reports
//!
//! What a Pro served that fails verification, three times running, or one header that fails proof
//! of work, proves it wrong whatever else answers: it is dropped as [`Self::on_sync_event`] says.
//! The loop's words about tips and being stuck only bring the next [`Action::TipCheck`] forward.
//!
//! # A pinned source
//!
//! The owner's choice wins over the list: it never fails over. A dead pin reads
//! [`SessionState::Unreachable`], stays the target, and is probed until it answers.
//!
//! # A source used for now
//!
//! [`ProviderSession::use_now`]: the owner's choice without the pin. The node moves at once, and
//! from there it is a source like any other in one respect and not in another: a new list leaves
//! it alone even if it is not on the list, and its death fails over as ever, which ends the choice.

use std::collections::VecDeque;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Bound on a probe: above the app's 45 s serve timeout on a `since`. A dead Pro often costs all
/// of it, so the retries below allow for it.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(50);

/// How long a Pro stays Suspect before the node looks for another, whatever its probes cost: the
/// design's 30 s + 1 min + 2 min. Fleet nodes restart 4-9 times a day, and a Pro's restart must
/// not move its followers.
pub const SUSPECT_FOR: Duration = Duration::from_secs(30 + 60 + 2 * 60);

/// When each retry starts, counted from the failure that made the Pro suspect, not from the
/// failed retry before it. Each leaves the one before its full [`PROBE_TIMEOUT`], and the last
/// starts early enough to be back by [`SUSPECT_FOR`]. A Pro that fails faster than that gets no
/// less time: the node still waits out [`SUSPECT_FOR`].
pub const PROBE_RETRIES_AFTER: [Duration; 3] = [
	Duration::from_secs(30),
	Duration::from_secs(30 + 60),
	Duration::from_secs(SUSPECT_FOR.as_secs() - PROBE_TIMEOUT.as_secs()),
];

/// With no signal from the active Pro for this long, it is probed. The signal is a push on
/// [`Delivery::Push`], any answered call on [`Delivery::Pull`].
pub const NO_SIGNAL_PROBE_AFTER: Duration = Duration::from_secs(10 * 60);

/// A gossip card older than this brings a probe forward. Cards are republished every 60 s, so
/// three missed in a row. Never declares anything offline.
pub const CARD_AGE_PROBE_AFTER: Duration = Duration::from_secs(3 * 60);

/// Hints and failed ordinary calls bring a probe forward at most this often.
pub const EARLY_PROBE_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// With no provider, or on a dead pin, how often the candidates are asked again.
pub const NO_PROVIDER_PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// The lease asked for. Every acknowledged push renews it on the Pro.
pub const LEASE_SECS: u32 = 3600;

/// A lease is renewed when it has this long left, for the hour with no block.
pub const LEASE_RENEW_BEFORE: Duration = Duration::from_secs(30 * 60);

/// After a call this node's own host refused to send, it is asked again after this long. The host
/// lifts its refusal when its carrier returns the calls its callers gave up on.
pub const NOT_SENT_RETRY_AFTER: Duration = Duration::from_secs(15);

/// After a `subscribe` that failed outright, it is asked again after this long.
pub const SUBSCRIBE_RETRY_AFTER: Duration = Duration::from_secs(2 * 60);

/// After a `subscribe` refused, or unknown to the Pro, with no time named, it is asked again
/// after this long. Long, because each retry costs an older Pro a refused call.
pub const SUBSCRIBE_REFUSED_RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

/// How often the active Pro's filter headers are compared with a second Pro's. A filter header
/// commits to every filter below it, so one comparison answers for the whole chain, and a lie
/// cannot wait out the interval: it stays in every later header. An hour is the longest a lie
/// goes unseen with an honest witness in turn, against a force close's delay of a day and more. See
/// the module docs for what that turn takes. Three calls an hour per node to
/// the witness: its filter header, its tip and its fees; a fourth, headers, when it is ahead.
pub const CROSS_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The first comparison after a start or a move: long enough that a restart that is soon followed
/// by another costs nothing, short enough that a new Pro is not believed for the whole interval.
pub const CROSS_CHECK_FIRST_AFTER: Duration = Duration::from_secs(5 * 60);

/// Compared this far below the tip. Candidates stay within 2 blocks to be ranked at all, so a Pro
/// that is merely behind still has the block; a Pro that does not is asked again another time.
pub const CROSS_CHECK_BURY: u32 = 2;

/// After a difference that could not be judged because a Pro did not answer, asked again this
/// soon, up to [`CROSS_CHECK_MAX_RETRIES`] times, then back to the interval.
pub const CROSS_CHECK_RETRY_AFTER: Duration = Duration::from_secs(10 * 60);

/// See [`CROSS_CHECK_RETRY_AFTER`].
pub const CROSS_CHECK_MAX_RETRIES: u8 = 3;

/// See [`ProviderSession::note_reading_again`].
pub const CROSS_CHECK_AFTER_READING_AGAIN: Duration = Duration::from_secs(60);

/// With no new block for this long, a witness is asked whether there is one. Silence itself is no
/// evidence of anything; see the module docs. About 5% of gaps between blocks are this long.
pub const TIP_CHECK_QUIET_AFTER: Duration = Duration::from_secs(30 * 60);

/// While a witness shows more than this node holds, how often that is looked at again.
pub const BEHIND_RECHECK: Duration = Duration::from_secs(2 * 60);

/// How long the active Pro may stay behind what a witness shows before the node moves. Far above
/// what a block takes to reach an honest Pro, and short against any time lock.
pub const BEHIND_LEAVE_AFTER: Duration = Duration::from_secs(10 * 60);

/// The same, while the node keeps moving and the Pro says it has the blocks: a real catch-up after
/// time away. Past this it moves anyway, as that also describes a Pro feeding it slowly.
pub const BEHIND_CATCHING_UP_LIMIT: Duration = Duration::from_secs(2 * 60 * 60);

/// With this node's own host refusing to send to the active Pro for this long, chain data may be
/// old, and nobody is to blame for it.
pub const NOT_SENT_STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// The longest wait a Pro's own numbers can set here: its `retry_after`, its lease.
pub const MAX_WAIT_A_PRO_NAMES: Duration = Duration::from_secs(24 * 60 * 60);

/// A Pro proven lying is not picked again for this long, across restarts. It can re-tag itself
/// at no cost, so the list cannot be what keeps it out. A day: longer than any restart habit, and
/// short enough that an operator who repaired a broken index gets the node back without asking.
/// Back on the list it is checked like any other.
pub const DROPPED_PRO_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// Most dropped Pros remembered; the oldest goes first. Proof costs a Pro nothing but its own
/// standing, so this only bounds the file.
pub const MAX_DROPPED_PROS: usize = 64;

/// How many moves between sources are kept for a status surface.
pub const MAX_MOVES_KEPT: usize = 8;

/// The time, as the machine's inputs carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
	/// A monotonic clock, in milliseconds. Every timer runs on this: a device with no RTC jumps
	/// its wall clock after boot.
	pub mono_ms: u64,
	/// The wall clock, in seconds since the UNIX epoch. Reported, and compared with what a Pro
	/// names in its own wall clock; never timed against.
	pub unix_secs: u64,
}

/// Where the session stands with its Pro node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
	/// The active Pro answers.
	Active,
	/// The active Pro's probe failed; retrying before believing it.
	Suspect,
	/// The active Pro failed every retry. Only lasts while another Pro is sought, or for as long
	/// as a pinned source stays dead.
	Unreachable,
	/// No Pro at all. The cursor is kept and the candidates are asked again.
	NoProvider,
}

impl SessionState {
	/// The name in status surfaces.
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Active => "active",
			Self::Suspect => "suspect",
			Self::Unreachable => "unreachable",
			Self::NoProvider => "no_provider",
		}
	}
}

/// How blocks reach this node from its Pro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
	/// The Pro pushes each block under a lease. The tip is not polled.
	Push,
	/// The node polls the tip and pulls a bundle when it moves.
	Pull,
}

impl Delivery {
	/// The name in status surfaces.
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Push => "push",
			Self::Pull => "pull",
		}
	}
}

/// Whether the session asks its Pros to push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryPreference {
	/// Subscribe, and pull only when refused. For a node verifying block filters.
	Push,
	/// Never subscribe. For a Dependent node, whose sync does not read bundles.
	Pull,
}

/// Something the driver is to do. The result comes back through the matching `on_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// Make this the node every chain call goes to, `None` for none.
	Retarget(Option<String>),
	/// Ask `target` a `chain.since` from the cursor. [`ProviderSession::on_probe`].
	Probe(String),
	/// Ask `target` for a lease. [`ProviderSession::on_subscribe`].
	Subscribe(String),
	/// Give up the lease on `target`, best effort: a release that is lost is cleaned up by the
	/// `not_subscribed` ack to the next push.
	Release(String),
	/// Compare the filter headers `active` gave with what `witness` says.
	/// [`ProviderSession::on_cross_check`].
	CrossCheck {
		/// The Pro being followed.
		active: String,
		/// The second opinion.
		witness: String,
	},
	/// Two Pros differ at `height` and nothing shows which is right: ask `third`.
	/// [`ProviderSession::on_tie_break`].
	TieBreak {
		/// The Pro being followed.
		active: String,
		/// The one that differed with it.
		witness: String,
		/// Who is asked.
		third: String,
		/// The first height they differ.
		height: u32,
	},
	/// Ask `witness` what it can show above this node's tip. [`ProviderSession::on_tip_check`].
	TipCheck {
		/// The Pro being followed.
		active: String,
		/// The second opinion.
		witness: String,
	},
}

/// How an [`Action::TipCheck`] came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipCheckOutcome {
	/// The witness did not answer: nothing known.
	Unanswered,
	/// The witness shows nothing above what this node holds.
	NotAhead,
	/// The witness showed headers, every check passed, with more work than this node holds.
	Ahead {
		/// How high they reach.
		witness_height: u32,
		/// The tip the active Pro claims now, if it answered.
		active_tip: Option<u32>,
		/// Where this node stands.
		cursor: u32,
	},
	/// A header the witness served failed proof of work or difficulty.
	Forged {
		/// Where.
		height: u32,
	},
}

/// How an [`Action::TieBreak`] came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TieBreak {
	/// The third Pro says what the active one says.
	SidesWithActive,
	/// The third Pro says what the other one says.
	SidesWithWitness,
	/// It says something else, or did not answer.
	NoAnswer,
}

/// What a sync loop reported; see [`ProviderSession::on_sync_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncReport {
	/// Steps complete: what was said below no longer stands.
	Healthy,
	/// It is reading blocks again, as what it held differs from what the Pro it follows says.
	ReadingAgain,
	/// Caught up with the Pro on a tip too old to believe.
	StaleTip {
		/// The tip.
		height: u32,
		/// How old its time stamp is.
		age_secs: u64,
	},
	/// No step has completed for a long time.
	Stuck,
	/// What the active Pro served proves it wrong.
	Evidence {
		/// What it was caught at.
		kind: LieKind,
		/// Where.
		height: u32,
	},
	/// The loop ended, and the engine is to start it again.
	Ended {
		/// Why.
		reason: String,
	},
	/// The engine started it again.
	Restarted,
}

/// The active Pro is behind what a witness can show. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Behind {
	witness: String,
	since_ms: u64,
	since_unix: u64,
	witness_height: u32,
	cursor: u32,
}

/// See [`ProviderSession::behind_witness`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BehindWitness {
	/// The Pro that showed it.
	pub witness: String,
	/// How high it showed.
	pub witness_height: u32,
	/// Since when, in seconds since the UNIX epoch.
	pub since: u64,
	/// Whether the node moves when the time is up: not on a pin.
	pub will_move: bool,
}

/// See [`ProviderSession::tip_stale`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TipStale {
	/// The tip.
	pub height: u32,
	/// How old its time stamp was, in seconds, when last seen.
	pub age_secs: u64,
}

/// See [`ProviderSession::sync_loop`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SyncLoopStatus {
	/// Why it is not running, while it is not.
	pub ended: Option<String>,
	/// How often it was started again in this run.
	pub restarts: u32,
}

/// What a Pro was caught at. Only what its own answers prove, against a block the proof of work
/// vouches for: an honest Pro can never earn one, whatever anyone else says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LieKind {
	/// It served a filter that does not hash to the filter header it served for that block.
	FilterDoesNotHashToHeader,
	/// It served a filter without a script the block's own outputs pay to.
	FilterLacksBlockOutput,
	/// It served a filter that cannot be read.
	FilterDoesNotDecode,
	/// What it says now of a block is not the filter header it gave this node for that block. One
	/// block has one: it told the sync loop one thing and the check another.
	AnswerChanged,
	/// It served a span of filter headers that does not continue the span it served before.
	BrokenFilterHeaderChain,
	/// It served a header that fails proof of work or claims the wrong difficulty. No race or
	/// restart produces one: a chain of headers is what proof of work vouches for.
	BadHeader,
	/// Its filters or filter headers failed verification, three times running.
	InvalidFilterData,
	/// A block it served is not the one the proof of work committed to, three times running.
	InvalidBlock,
	/// Its replies could not be read as what was asked, three times running.
	InvalidReply,
	/// Its chain, with its proof of work, forks below every header held: not a chain this node
	/// can follow. It may not be lying, and it cannot be used.
	WrongChain,
}

impl LieKind {
	/// The name in status surfaces.
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::FilterDoesNotHashToHeader => "filter_does_not_hash_to_header",
			Self::FilterLacksBlockOutput => "filter_lacks_block_output",
			Self::FilterDoesNotDecode => "filter_does_not_decode",
			Self::AnswerChanged => "answer_changed",
			Self::BrokenFilterHeaderChain => "broken_filter_header_chain",
			Self::BadHeader => "bad_header",
			Self::InvalidFilterData => "invalid_filter_data",
			Self::InvalidBlock => "invalid_block",
			Self::InvalidReply => "invalid_reply",
			Self::WrongChain => "wrong_chain",
		}
	}
}

/// How a cross-check came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCheckOutcome {
	/// Nothing to compare yet. No call was made.
	NotYet,
	/// Same filter header at this height, which vouches for every one below it.
	Agreed {
		/// The height compared.
		height: u32,
	},
	/// The witness did not have the block, or did not answer. Behind, on another branch, or
	/// restarting: no evidence of anything.
	Inconclusive,
	/// A difference, and a Pro would not answer what judging it takes.
	Interrupted {
		/// The lowest height known to differ.
		height: u32,
	},
	/// Both Pros say the same, and what this node took from an earlier Pro is not that. Nobody here
	/// is to blame; the node scans those blocks again.
	HeldWasWrong {
		/// The lowest height this node holds wrong.
		height: u32,
	},
	/// A difference judged from the block at `height`. Neither convicted: the difference is in what
	/// a block alone does not show, and nobody is dropped.
	Judged {
		/// The first height the two Pros differ.
		height: u32,
		/// What the active Pro was caught at.
		active_lied: Option<LieKind>,
		/// What the witness was caught at.
		witness_lied: Option<LieKind>,
	},
}

/// A Pro proven lying, not picked again until `until`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedPro {
	/// Its node id.
	pub node_id: String,
	/// What it was caught at; see [`LieKind::as_str`].
	pub reason: String,
	/// The block it was caught at.
	pub height: u32,
	/// When it may be picked again, in seconds since the UNIX epoch.
	pub until: u64,
	/// When it was dropped, in seconds since the UNIX epoch. 0 in a file from before this was kept.
	#[serde(default)]
	pub at: u64,
}

/// Who moved the node to another source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveBy {
	/// The owner's choice, pinned or for now.
	Owner,
	/// The node, because its source stopped answering, or it had none.
	Auto,
	/// The node, because its source left the list while still answering.
	List,
	/// The node, on evidence against its source: proof of lying, or a witness's proof of work.
	Evidence,
}

/// One move between sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceMove {
	/// What the node left. `None` when it had nothing to leave.
	pub from: Option<String>,
	/// Where it went.
	pub to: String,
	/// When, in milliseconds since the UNIX epoch, to the second.
	pub at_ms: u64,
	/// Who decided.
	pub by: MoveBy,
}

/// What the session is waiting to ask next, while something is wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeStatus {
	/// The check it is on. 0 with no provider: there is no series of checks then.
	pub attempt: u32,
	/// How many checks before it gives up on the source. 0 with no provider.
	pub of: u32,
	/// Seconds until the next. 0 when one is due or out.
	pub next_in_s: u64,
	/// The time between the start of one retry and the next, in seconds.
	pub waits_s: Vec<u64>,
}

/// A Pro said no to a lease: why the node pulls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryRefusal {
	/// The refusal code on the wire.
	pub code: String,
	/// When, in milliseconds since the UNIX epoch, to the second.
	pub at_ms: u64,
}

/// Two Pros differ and nothing shows which is right. Nobody is dropped for this; see the module
/// docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilterConflict {
	/// The Pro being followed.
	pub active: String,
	/// The Pro that said otherwise.
	pub witness: String,
	/// The first height they differ.
	pub height: u32,
	/// When it was seen, in seconds since the UNIX epoch.
	pub at: u64,
	/// Where it stands.
	pub state: ConflictState,
	/// The third Pro asked, if one was.
	pub third: Option<String>,
}

/// See [`FilterConflict::state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictState {
	/// A third Pro is to be asked, or a Pro did not answer what judging it takes.
	Open,
	/// There is nobody else to ask.
	NoThirdPro,
	/// A third Pro says what the active one says. The node stays.
	SidesWithActive,
	/// A third Pro says what the other one says. Worth telling the owner, and it moves nobody: two
	/// to one proves nothing.
	SidesWithWitness,
	/// A third Pro said something else, or did not answer.
	ThirdDidNotSettleIt,
}

/// What the filter cross-check has seen, for a status surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CrossCheckStatus {
	/// Whether this node can check: it verifies filters. A Dependent one cannot.
	pub supported: bool,
	/// When a comparison last came back, in seconds since the UNIX epoch.
	pub last_at: Option<u64>,
	/// The Pro asked.
	pub last_witness: Option<String>,
	/// `agreed`, `inconclusive`, `interrupted`, `held_was_wrong`, `conflict` or `dropped`.
	pub last_result: Option<String>,
	/// The height it was about.
	pub last_height: Option<u32>,
	/// An open difference nothing could decide.
	pub conflict: Option<FilterConflict>,
	/// Blocks in doubt this node has yet to read: see [`Unread`]. While this stands, nobody may say
	/// they were read.
	pub unread: Option<Unread>,
	/// What this node held differed from two Pros that agree, and since then no comparison has come
	/// back the same. A Pro in the seat answering differently here and to the sync loop would look
	/// like an earlier Pro's fault: worth saying.
	pub held_differed: Option<HeldDiffered>,
}

/// See [`CrossCheckStatus::unread`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unread {
	/// Whose filters say which blocks to read.
	pub witness: String,
	/// The lowest block in doubt.
	pub from: u32,
	/// The last check read nothing more: this is not being read now.
	pub stuck: bool,
}

/// See [`CrossCheckStatus::held_differed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeldDiffered {
	/// The lowest block, last time.
	pub height: u32,
	/// Last time, in seconds since the UNIX epoch.
	pub at: u64,
	/// How many times since the last comparison that came back the same.
	pub times: u32,
}

/// How a probe came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
	/// The Pro answered. `missed_blocks` when its tip is past this node's cursor: a push went
	/// missing, so the lease may have.
	Answered {
		/// See above.
		missed_blocks: bool,
	},
	/// The Pro refused as `unsupported`. Could be its app restarting.
	Unsupported,
	/// This node's host refused to send it. Nobody was asked, so it counts for nothing.
	NotSent,
	/// Anything else.
	Failed,
}

/// How a `subscribe` came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeOutcome {
	/// A lease until this time, on the Pro's wall clock.
	Granted {
		/// Seconds since the UNIX epoch.
		lease_until_unix: u64,
	},
	/// The Pro does not want to push to this node. It stays the Pro; the node pulls.
	Refused {
		/// When to ask again, if the Pro said.
		retry_after: Option<Duration>,
	},
	/// The Pro does not know the route, or its app is restarting.
	Unsupported,
	/// This node's host refused to send it. A lease held is still held.
	NotSent,
	/// No answer.
	Failed,
}

/// Whether a block update is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushVerdict {
	/// From the active Pro.
	Accept,
	/// From anyone else, or to a node that wants no pushes. The ack says `not_subscribed`, and
	/// the Pro drops the lease at once.
	NotSubscribed,
}

/// A search for another Pro: candidates asked one at a time, moved to on the first answer.
#[derive(Debug, Default)]
struct Walk {
	queue: VecDeque<String>,
	/// The active Pro still answers and stays if nobody else does.
	keep_current: bool,
}

/// What is kept across a restart, so one works with no app calling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionMemory {
	/// Whether the node may take a source from the list by itself. `None`: whether it can check
	/// what a source tells it. See the module docs, "Who chooses".
	pub auto_source: Option<bool>,
	/// The list the Selector walks.
	pub candidates: Vec<String>,
	/// Those on it known longest, by whoever does the matching: harder to fill with fresh keys, so
	/// they get every other turn as a witness. Empty says nothing.
	pub longest_known: Vec<String>,
	/// The owner's pinned source.
	pub pinned: Option<String>,
	/// The last Pro that answered.
	pub last_good: Option<String>,
	/// The Pros proven wrong.
	pub dropped: Vec<DroppedPro>,
	/// The owner's choice for now: the node is on it and not pinned to it, so a new list does not
	/// take it off, and its death does. Gone as soon as the node moves away.
	pub used_for_now: Option<String>,
}

/// See the module docs.
#[derive(Debug)]
pub struct ProviderSession {
	preference: DeliveryPreference,
	memory: SessionMemory,
	dirty: bool,
	active: Option<String>,
	state: SessionState,
	delivery: Delivery,
	pending: VecDeque<Action>,

	last_ok_at_unix: Option<u64>,
	/// Any answered call: the signal on [`Delivery::Pull`].
	last_answer_ms: u64,
	/// A push or a probe's answer: the signal on [`Delivery::Push`].
	last_heard_ms: u64,

	probe_due_ms: Option<u64>,
	probe_in_flight: Option<String>,
	/// No probe starts before this: this node's host refused the last one.
	probes_held_until_ms: u64,
	last_probe_ms: Option<u64>,
	/// When the failure that made the active Pro suspect came back.
	suspect_since_ms: u64,
	failed_retries: usize,
	unsupported_seen: bool,

	subscribe_due_ms: Option<u64>,
	subscribe_in_flight: bool,
	lease_held: bool,

	walk: Option<Walk>,
	next_walk_ms: Option<u64>,

	cross_check: CrossCheckStatus,
	cross_check_due_ms: Option<u64>,
	cross_check_in_flight: bool,
	/// Which witness is next, over the candidates at the time.
	witness_turn: usize,
	/// The witness a difference is still open with, and how often it has been asked again.
	retry_witness: Option<(String, u8)>,

	moves: VecDeque<SourceMove>,
	refused: Option<DeliveryRefusal>,
	/// What the node had before it had nothing, for the next move to name.
	left: Option<String>,
	/// It left on evidence, so the next move is named so.
	left_on_evidence: bool,

	tip_check_due_ms: Option<u64>,
	tip_check_in_flight: bool,
	last_tip_check_ms: Option<u64>,
	/// Which witness is next for a tip check, apart from the cross-check's turns.
	tip_witness_turn: usize,
	/// Who is next to be handed a transaction or asked about one.
	send_turn: usize,
	/// Those dropped since the last look, for whoever tells of it.
	newly_dropped: Vec<DroppedPro>,
	behind: Option<Behind>,
	tip_stale: Option<TipStale>,
	sync_stuck: bool,
	sync_loop: SyncLoopStatus,
	/// Since when this node's own host has refused to send to the active Pro.
	not_sent_since_ms: Option<u64>,
	not_sent_stale: bool,
}

/// Node ids are hex; compare them as such.
pub fn normalise_node_id(node_id: &str) -> String {
	node_id.trim().to_ascii_lowercase()
}

fn ms(duration: Duration) -> u64 {
	duration.as_millis() as u64
}

impl ProviderSession {
	/// A session resuming from `memory`: on the pin, else on the last good Pro, and if neither,
	/// with no provider and a search for one starting at once. Any provider it starts on is
	/// taken as active and probed at the first poll. The driver makes the first
	/// [`Action::Retarget`] from [`Self::active`], so a restart needs no app.
	pub fn new(preference: DeliveryPreference, mut memory: SessionMemory, now: Now) -> Self {
		memory.dropped.retain(|dropped| dropped.until > now.unix_secs);
		let is_dropped = |id: &String| memory.dropped.iter().any(|d| d.node_id == *id);
		let active = memory
			.pinned
			.clone()
			.or_else(|| memory.used_for_now.clone().filter(|id| !is_dropped(id)))
			.or_else(|| memory.last_good.clone().filter(|id| !is_dropped(id)));
		if memory.used_for_now != active {
			memory.used_for_now = None;
		}
		let state = if active.is_some() { SessionState::Active } else { SessionState::NoProvider };
		let mut session = Self {
			preference,
			memory,
			dirty: false,
			active,
			state,
			delivery: Delivery::Pull,
			pending: VecDeque::new(),
			last_ok_at_unix: None,
			last_answer_ms: now.mono_ms,
			last_heard_ms: now.mono_ms,
			probe_due_ms: None,
			probe_in_flight: None,
			probes_held_until_ms: 0,
			last_probe_ms: None,
			suspect_since_ms: 0,
			failed_retries: 0,
			unsupported_seen: false,
			subscribe_due_ms: None,
			subscribe_in_flight: false,
			lease_held: false,
			walk: None,
			next_walk_ms: None,
			cross_check: CrossCheckStatus::default(),
			cross_check_due_ms: None,
			cross_check_in_flight: false,
			witness_turn: 0,
			retry_witness: None,
			moves: VecDeque::new(),
			refused: None,
			left: None,
			left_on_evidence: false,
			tip_check_due_ms: None,
			tip_check_in_flight: false,
			last_tip_check_ms: None,
			tip_witness_turn: 0,
			send_turn: 0,
			newly_dropped: Vec::new(),
			behind: None,
			tip_stale: None,
			sync_stuck: false,
			sync_loop: SyncLoopStatus::default(),
			not_sent_since_ms: None,
			not_sent_stale: false,
		};
		if session.active.is_some() {
			session.probe_due_ms = Some(now.mono_ms);
			session.subscribe_due_ms = session.wants_push().then_some(now.mono_ms);
		} else {
			session.next_walk_ms = Some(now.mono_ms);
		}
		session
	}

	fn wants_push(&self) -> bool {
		self.preference == DeliveryPreference::Push
	}

	/// The Pro every chain call goes to.
	pub fn active(&self) -> Option<&str> {
		self.active.as_deref()
	}

	/// Where the session stands.
	pub fn state(&self) -> SessionState {
		self.state
	}

	/// How blocks arrive.
	pub fn delivery(&self) -> Delivery {
		self.delivery
	}

	/// The list, the pin and the last good Pro.
	pub fn memory(&self) -> &SessionMemory {
		&self.memory
	}

	/// When a call to a Pro was last answered, in seconds since the UNIX epoch.
	pub fn last_ok_at(&self) -> Option<u64> {
		self.last_ok_at_unix
	}

	/// What is known of the chain may be old: nothing answers, or what answers is not showing the
	/// chain, or what would take it in is not running.
	pub fn chain_stale(&self) -> bool {
		matches!(self.state, SessionState::Unreachable | SessionState::NoProvider)
			|| self.tip_stale.is_some()
			|| self.behind.is_some()
			|| self.sync_stuck
			|| self.sync_loop.ended.is_some()
			|| self.not_sent_stale
			|| self.on_proven_liar()
	}

	/// Whether the Pro's pushes are the live truth about its tip, so the tip need not be asked.
	pub fn push_is_trusted(&self) -> bool {
		self.state == SessionState::Active
			&& self.delivery == Delivery::Push
			&& self.behind.is_none()
			&& self.tip_stale.is_none()
	}

	/// What a witness has shown beyond what this node holds, while that stands.
	pub fn behind_witness(&self) -> Option<BehindWitness> {
		let pinned = self.memory.pinned.is_some();
		self.behind.as_ref().map(|behind| BehindWitness {
			witness: behind.witness.clone(),
			witness_height: behind.witness_height,
			since: behind.since_unix,
			will_move: !pinned,
		})
	}

	/// The tip this node is caught up on is too old to believe, while it is.
	pub fn tip_stale(&self) -> Option<TipStale> {
		self.tip_stale
	}

	/// No step of the sync loop has completed for a long time, while that lasts.
	pub fn sync_stuck(&self) -> bool {
		self.sync_stuck
	}

	/// Whether the sync loop runs, and how often it has been started again.
	pub fn sync_loop(&self) -> &SyncLoopStatus {
		&self.sync_loop
	}

	/// The active Pro is one proven lying, which only a pin keeps it on.
	pub fn on_proven_liar(&self) -> bool {
		self.active.as_deref().map_or(false, |active| {
			self.memory.dropped.iter().any(|dropped| dropped.node_id == active)
		})
	}

	/// This node's own host has been refusing to send to the active Pro for a long time.
	pub fn host_not_sending(&self) -> bool {
		self.not_sent_stale
	}

	/// This node can check its Pro against another, and nobody else is there to ask.
	pub fn no_witness(&self, now: Now) -> bool {
		let active = self.active.as_deref();
		self.cross_check.supported
			&& active.is_some()
			&& !self.witness_list(now).iter().any(|id| Some(id.as_str()) != active)
	}

	/// What the cross-check has seen.
	pub fn cross_check(&self) -> &CrossCheckStatus {
		&self.cross_check
	}

	/// The latest moves between sources, oldest first.
	pub fn moves(&self) -> &VecDeque<SourceMove> {
		&self.moves
	}

	/// The last refusal of a lease by the Pro being followed, while it stands.
	pub fn refused(&self) -> Option<&DeliveryRefusal> {
		self.refused.as_ref()
	}

	/// A Pro's refusal, by its code on the wire. Comes before [`Self::on_subscribe`] tells of it.
	pub fn note_refused(&mut self, code: &str, now: Now) {
		self.refused =
			Some(DeliveryRefusal { code: code.to_string(), at_ms: now.unix_secs.saturating_mul(1000) });
	}

	/// What it is waiting to ask next, while something is wrong.
	pub fn probe_status(&self, now: Now) -> Option<ProbeStatus> {
		let next_in = |due: Option<u64>| due.map_or(0, |at| at.saturating_sub(now.mono_ms) / 1000);
		match self.state {
			SessionState::Suspect => {
				let mut waits_s = Vec::with_capacity(PROBE_RETRIES_AFTER.len());
				let mut before = 0;
				for after in PROBE_RETRIES_AFTER {
					waits_s.push(after.as_secs() - before);
					before = after.as_secs();
				}
				Some(ProbeStatus {
					attempt: self.failed_retries as u32 + 1,
					of: PROBE_RETRIES_AFTER.len() as u32 + 1,
					next_in_s: next_in(self.probe_due_ms),
					waits_s,
				})
			},
			SessionState::NoProvider => Some(ProbeStatus {
				attempt: 0,
				of: 0,
				next_in_s: next_in(self.next_walk_ms),
				waits_s: Vec::new(),
			}),
			SessionState::Active | SessionState::Unreachable => None,
		}
	}

	/// The owner's choice of `target` for now: see [`SessionMemory::used_for_now`]. `false`, and
	/// nothing changes, for a dropped Pro: unlike a pin this is not a choice to overrule that.
	pub fn use_now(&mut self, target: String, now: Now) -> bool {
		let target = normalise_node_id(&target);
		if target.is_empty() || self.is_dropped(&target, now) {
			return false;
		}
		if self.memory.pinned.take().is_some() {
			self.dirty = true;
		}
		if self.active.as_deref() == Some(target.as_str()) {
			self.walk = None;
			if self.state != SessionState::Active {
				self.probe_due_ms = Some(now.mono_ms);
			}
		} else {
			self.switch_to(target.clone(), now, None, MoveBy::Owner);
		}
		self.memory.used_for_now = Some(target);
		self.dirty = true;
		true
	}

	/// The node left this Pro for nothing, or moved: the owner's choice for now is over.
	fn end_use_for_now(&mut self) {
		if self.memory.used_for_now.take().is_some() {
			self.dirty = true;
		}
	}

	/// See [`SessionMemory::auto_source`]: the owner's word, or `None` for the default. Turned off,
	/// what the node found by itself goes with it, and what the owner chose stays.
	pub fn set_auto_source(&mut self, allowed: Option<bool>, now: Now) {
		if self.memory.auto_source != allowed {
			self.memory.auto_source = allowed;
			self.dirty = true;
		}
		if self.picks_by_itself() {
			if self.active.is_none() {
				self.begin_walk(false, now);
			}
			return;
		}
		let chosen = self.memory.pinned.is_some() || self.memory.used_for_now.is_some();
		if !chosen && self.active.is_some() {
			self.memory.last_good = None;
			self.dirty = true;
			self.leave_active(now);
			self.left_on_evidence = false;
		}
	}

	/// Whether this node takes a source from the list by itself. See the module docs.
	pub fn picks_by_itself(&self) -> bool {
		self.memory.auto_source.unwrap_or(self.wants_push() || self.cross_check.supported)
	}

	/// This node has no source and will not take one until its owner says.
	pub fn needs_owner_choice(&self) -> bool {
		self.active.is_none() && !self.picks_by_itself()
	}

	/// A cross-check at the next poll.
	#[cfg(test)]
	pub(crate) fn check_soon(&mut self, now: Now) {
		self.cross_check_due_ms = Some(now.mono_ms);
	}

	/// This node verifies filters, so has something to compare.
	pub fn enable_cross_check(&mut self, now: Now) {
		self.cross_check.supported = true;
		self.cross_check_due_ms = Some(now.mono_ms + ms(CROSS_CHECK_FIRST_AFTER));
		self.tip_check_due_ms = Some(now.mono_ms + ms(TIP_CHECK_QUIET_AFTER));
		// What was refused before this was known is asked now.
		if self.active.is_none() && self.next_walk_ms.is_some() {
			self.next_walk_ms = Some(now.mono_ms);
		}
	}

	/// A new block reached this node: there is no silence to ask about for a while.
	pub fn note_block(&mut self, now: Now) {
		if self.cross_check.supported && self.behind.is_none() {
			self.tip_check_due_ms = Some(now.mono_ms + ms(TIP_CHECK_QUIET_AFTER));
		}
	}

	/// A tip check at the next poll, at most every [`BEHIND_RECHECK`].
	fn tip_check_soon(&mut self, now: Now) {
		if !self.cross_check.supported {
			return;
		}
		let earliest = self.last_tip_check_ms.map_or(now.mono_ms, |at| at + ms(BEHIND_RECHECK));
		let at = earliest.max(now.mono_ms);
		self.tip_check_due_ms = Some(self.tip_check_due_ms.map_or(at, |due| due.min(at)));
	}

	/// What the sync loop reported of the Pro being followed. See the module docs.
	pub fn on_sync_event(&mut self, report: SyncReport, now: Now) {
		match report {
			SyncReport::Healthy => {
				self.tip_stale = None;
				self.sync_stuck = false;
			},
			SyncReport::ReadingAgain => self.note_reading_again(now),
			SyncReport::StaleTip { height, age_secs } => {
				self.tip_stale = Some(TipStale { height, age_secs });
				self.tip_check_soon(now);
			},
			SyncReport::Stuck => {
				self.sync_stuck = true;
				self.tip_check_soon(now);
			},
			SyncReport::Evidence { kind, height } => {
				let Some(active) = self.active.clone() else { return };
				self.left_on_evidence = true;
				self.drop_pro(&active, kind, height, now);
			},
			SyncReport::Ended { reason } => self.sync_loop.ended = Some(reason),
			SyncReport::Restarted => {
				self.sync_loop.ended = None;
				self.sync_loop.restarts = self.sync_loop.restarts.saturating_add(1);
			},
		}
	}

	/// An [`Action::TipCheck`] came back. See the module docs.
	pub fn on_tip_check(
		&mut self, active: &str, witness: &str, outcome: TipCheckOutcome, now: Now,
	) {
		self.tip_check_in_flight = false;
		self.last_tip_check_ms = Some(now.mono_ms);
		if self.active.as_deref() != Some(active) {
			return;
		}
		let next = match outcome {
			TipCheckOutcome::Unanswered => {
				if self.behind.is_some() {
					BEHIND_RECHECK
				} else {
					TIP_CHECK_QUIET_AFTER
				}
			},
			TipCheckOutcome::NotAhead => {
				self.behind = None;
				TIP_CHECK_QUIET_AFTER
			},
			TipCheckOutcome::Forged { height } => {
				self.drop_pro(witness, LieKind::BadHeader, height, now);
				self.behind = self.behind.take().filter(|behind| behind.witness != witness);
				BEHIND_RECHECK
			},
			TipCheckOutcome::Ahead { witness_height, active_tip, cursor } => {
				if self.judge_behind(witness, witness_height, active_tip, cursor, now) {
					return;
				}
				if self.memory.pinned.is_some() {
					TIP_CHECK_QUIET_AFTER
				} else {
					BEHIND_RECHECK
				}
			},
		};
		if self.cross_check.supported {
			self.tip_check_due_ms = Some(now.mono_ms + ms(next));
		}
	}

	/// Whether the node has moved. See the module docs.
	fn judge_behind(
		&mut self, witness: &str, witness_height: u32, active_tip: Option<u32>,
		cursor: u32, now: Now,
	) -> bool {
		let seen = self.behind.get_or_insert_with(|| Behind {
			witness: witness.to_string(),
			since_ms: now.mono_ms,
			since_unix: now.unix_secs,
			witness_height,
			cursor,
		});
		let moving = cursor > seen.cursor;
		let has_them = active_tip.map_or(false, |tip| tip >= witness_height);
		seen.witness = witness.to_string();
		seen.witness_height = witness_height;
		seen.cursor = cursor;
		let limit = if moving && has_them { BEHIND_CATCHING_UP_LIMIT } else { BEHIND_LEAVE_AFTER };
		let time_up = now.mono_ms.saturating_sub(seen.since_ms) >= ms(limit);
		if !time_up || self.memory.pinned.is_some() {
			return false;
		}
		self.switch_to(witness.to_string(), now, Some(now), MoveBy::Evidence);
		true
	}

	/// A cross-check came back. Whether the node should take back what it holds from `active`:
	/// not when the owner's pin keeps it on that Pro.
	pub fn on_cross_check(
		&mut self, active: &str, witness: &str, outcome: CrossCheckOutcome, now: Now,
	) -> bool {
		self.cross_check_in_flight = false;
		let retry = self.retry_witness.take();
		self.cross_check_due_ms = Some(now.mono_ms + ms(CROSS_CHECK_INTERVAL));
		let (result, height) = match outcome {
			CrossCheckOutcome::NotYet => {
				self.retry_witness = retry;
				self.cross_check_due_ms = Some(now.mono_ms + ms(CROSS_CHECK_FIRST_AFTER));
				return false;
			},
			CrossCheckOutcome::Agreed { height } => {
				self.answers_match(witness);
				self.cross_check.held_differed = None;
				if self.cross_check.unread.as_ref().map_or(false, |u| u.witness == witness) {
					self.cross_check.unread = None;
				}
				("agreed", Some(height))
			},
			CrossCheckOutcome::Inconclusive => ("inconclusive", None),
			CrossCheckOutcome::Interrupted { height } => {
				self.note_conflict(witness, height, now);
				let asked = retry.filter(|(id, _)| id == witness).map_or(0, |(_, asked)| asked);
				if asked < CROSS_CHECK_MAX_RETRIES {
					self.retry_witness = Some((witness.to_string(), asked + 1));
					self.cross_check_due_ms = Some(now.mono_ms + ms(CROSS_CHECK_RETRY_AFTER));
				}
				("interrupted", Some(height))
			},
			CrossCheckOutcome::HeldWasWrong { height } => {
				// The two say the same. What differs is what an earlier Pro gave this node, or one
				// from before this run, and it is read again.
				self.answers_match(witness);
				let times = self.cross_check.held_differed.as_ref().map_or(0, |seen| seen.times);
				self.cross_check.held_differed = Some(HeldDiffered {
					height,
					at: now.unix_secs,
					times: times.saturating_add(1),
				});
				("held_was_wrong", Some(height))
			},
			CrossCheckOutcome::Judged { height, active_lied: None, witness_lied: None } => {
				self.note_conflict(witness, height, now);
				self.ask_a_third(active, witness, height, now);
				("conflict", Some(height))
			},
			CrossCheckOutcome::Judged { height, active_lied, witness_lied } => {
				if let Some(lie) = witness_lied {
					self.drop_pro(witness, lie, height, now);
				}
				if let Some(lie) = active_lied {
					self.drop_pro(active, lie, height, now);
				}
				("dropped", Some(height))
			},
		};
		self.cross_check.last_at = Some(now.unix_secs);
		self.cross_check.last_witness = Some(witness.to_string());
		self.cross_check.last_result = Some(result.to_string());
		self.cross_check.last_height = height;
		match outcome {
			CrossCheckOutcome::HeldWasWrong { .. } => true,
			CrossCheckOutcome::Judged { active_lied: Some(_), .. } => !self.owner_keeps(active),
			_ => false,
		}
	}

	/// How far a check that found a difference got with reading what is in doubt. With more to read
	/// and getting somewhere it goes on soon, with the same witness.
	pub fn note_reading(&mut self, witness: &str, unread_from: Option<u32>, progressed: bool, now: Now) {
		let same = self.cross_check.unread.as_ref().map_or(false, |u| u.witness == witness);
		match unread_from {
			Some(from) => {
				let stuck = !progressed;
				self.cross_check.unread = Some(Unread { witness: witness.to_string(), from, stuck });
				if progressed && self.active.is_some() {
					self.retry_witness = Some((witness.to_string(), 0));
					self.cross_check_due_ms = Some(now.mono_ms + ms(CROSS_CHECK_RETRY_AFTER));
				}
			},
			None if same => self.cross_check.unread = None,
			None => {},
		}
	}

	/// The sync loop is reading blocks again on the word of the Pro it follows: a witness is asked
	/// soon, as that word should not stand alone.
	pub fn note_reading_again(&mut self, now: Now) {
		if self.cross_check.supported {
			let soon = now.mono_ms + ms(CROSS_CHECK_AFTER_READING_AGAIN);
			self.cross_check_due_ms =
				Some(self.cross_check_due_ms.map_or(soon, |due| due.min(soon)));
		}
	}

	fn note_conflict(&mut self, witness: &str, height: u32, now: Now) {
		self.cross_check.conflict = Some(FilterConflict {
			active: self.active.clone().unwrap_or_default(),
			witness: witness.to_string(),
			height,
			at: now.unix_secs,
			state: ConflictState::Open,
			third: None,
		});
	}

	/// Whatever this witness differed over, it no longer does.
	fn answers_match(&mut self, witness: &str) {
		if self.cross_check.conflict.as_ref().map_or(false, |c| c.witness == witness) {
			self.cross_check.conflict = None;
		}
	}

	/// See the module docs. Someone other than the two who differ, when there is anyone.
	fn ask_a_third(&mut self, active: &str, witness: &str, height: u32, now: Now) {
		let third = self.witness_list(now).into_iter().find(|id| id != witness);
		if let Some(conflict) = self.cross_check.conflict.as_mut() {
			conflict.third.clone_from(&third);
			conflict.state =
				if third.is_some() { ConflictState::Open } else { ConflictState::NoThirdPro };
		}
		if let Some(third) = third {
			self.pending.push_back(Action::TieBreak {
				active: active.to_string(),
				witness: witness.to_string(),
				third,
				height,
			});
		}
	}

	/// An [`Action::TieBreak`] came back. See the module docs.
	pub fn on_tie_break(&mut self, active: &str, witness: &str, answer: TieBreak) {
		let current = self.active.as_deref() == Some(active);
		let Some(conflict) =
			self.cross_check.conflict.as_mut().filter(|c| current && c.witness == witness)
		else {
			return;
		};
		conflict.state = match answer {
			TieBreak::SidesWithActive => ConflictState::SidesWithActive,
			TieBreak::SidesWithWitness => ConflictState::SidesWithWitness,
			TieBreak::NoAnswer => ConflictState::ThirdDidNotSettleIt,
		};
	}

	/// Whether this node stays on `id` whatever `id` is caught at: the owner's pin, or the source of a
	/// node that does not pick by itself, which leaving would leave with none, and blind to a close of
	/// its channels, until the owner comes by. A liar's blocks are still blocks. The status says
	/// what it did, and new channels wait.
	fn owner_keeps(&self, id: &str) -> bool {
		self.memory.pinned.as_deref() == Some(id)
			|| (self.active.as_deref() == Some(id) && !self.picks_by_itself())
	}

	/// Who this node follows is the owner's choice, not the list's: nothing a stranger on the list
	/// says of fees or of the mempool outweighs that source.
	pub fn owner_chose_source(&self) -> bool {
		self.memory.pinned.is_some() || !self.picks_by_itself()
	}

	/// Remembers what `id` was caught at, and leaves it if it is the Pro being followed, unless
	/// the owner keeps it: see [`Self::owner_keeps`].
	fn drop_pro(&mut self, id: &str, lie: LieKind, height: u32, now: Now) {
		self.memory.dropped.retain(|dropped| dropped.node_id != id);
		if self.memory.dropped.len() >= MAX_DROPPED_PROS {
			self.memory.dropped.remove(0);
		}
		let dropped = DroppedPro {
			node_id: id.to_string(),
			reason: lie.as_str().to_string(),
			height,
			until: now.unix_secs + DROPPED_PRO_FOR.as_secs(),
			at: now.unix_secs,
		};
		self.newly_dropped.push(dropped.clone());
		self.memory.dropped.push(dropped);
		if self.memory.last_good.as_deref() == Some(id) {
			self.memory.last_good = None;
		}
		self.dirty = true;
		if self.active.as_deref() == Some(id) && !self.owner_keeps(id) {
			self.leave_active(now);
		}
	}

	/// Off the active Pro at once, taking nothing more from it, and on to whoever answers.
	fn leave_active(&mut self, now: Now) {
		if let Some(old) = self.active.take() {
			self.release_if_held(&old);
			self.pending.push_back(Action::Retarget(None));
			self.left = Some(old);
		}
		self.left_on_evidence = true;
		self.clear_judgements();
		self.end_use_for_now();
		self.state = SessionState::NoProvider;
		self.delivery = Delivery::Pull;
		self.probe_due_ms = None;
		self.subscribe_due_ms = None;
		self.begin_walk(false, now);
	}

	pub(crate) fn is_dropped(&self, id: &str, now: Now) -> bool {
		self.memory
			.dropped
			.iter()
			.any(|dropped| dropped.node_id == id && dropped.until > now.unix_secs)
	}

	fn forget_expired_drops(&mut self, now: Now) {
		let before = self.memory.dropped.len();
		self.memory.dropped.retain(|dropped| dropped.until > now.unix_secs);
		if self.memory.dropped.len() != before {
			self.dirty = true;
		}
	}

	/// Everything judged about the Pro being followed, on leaving it.
	fn clear_judgements(&mut self) {
		self.behind = None;
		self.tip_stale = None;
		self.sync_stuck = false;
		self.not_sent_since_ms = None;
		self.not_sent_stale = false;
		self.tip_check_in_flight = false;
	}

	/// Who can be asked: the candidates. Never the active Pro, never one proven wrong.
	fn witness_list(&self, now: Now) -> Vec<String> {
		let active = self.active.as_deref();
		self.memory
			.candidates
			.iter()
			.filter(|id| active != Some(id.as_str()) && !self.is_dropped(id, now))
			.cloned()
			.collect()
	}

	/// Whose turn it is, on a list that is not empty: see [`SessionMemory::longest_known`].
	fn in_turn(&self, list: &[String], turn: usize) -> String {
		let known: Vec<&String> =
			list.iter().filter(|id| self.memory.longest_known.contains(id)).collect();
		if known.is_empty() {
			return list[turn % list.len()].clone();
		}
		if turn % 2 == 0 {
			known[(turn / 2) % known.len()].clone()
		} else {
			list[(turn / 2) % list.len()].clone()
		}
	}

	/// See [`SessionMemory::longest_known`].
	pub fn set_longest_known(&mut self, known: Vec<String>) {
		let known: Vec<String> = known.iter().map(|id| normalise_node_id(id)).collect();
		if known != self.memory.longest_known {
			self.memory.longest_known = known;
			self.dirty = true;
		}
	}

	/// The Pro to compare with: the one a difference is still open with, or the next one's turn.
	fn next_witness(&mut self, now: Now) -> Option<String> {
		if let Some((id, _)) = &self.retry_witness {
			if self.active.as_deref() != Some(id.as_str()) && !self.is_dropped(id, now) {
				return Some(id.clone());
			}
		}
		let list = self.witness_list(now);
		if list.is_empty() {
			return None;
		}
		let witness = self.in_turn(&list, self.witness_turn);
		self.witness_turn = self.witness_turn.wrapping_add(1);
		Some(witness)
	}

	/// The Pro to ask about the tip: the one already showing more, or the next one's turn.
	fn next_tip_witness(&mut self, now: Now) -> Option<String> {
		let list = self.witness_list(now);
		if let Some(behind) = &self.behind {
			if list.contains(&behind.witness) {
				return Some(behind.witness.clone());
			}
		}
		if list.is_empty() {
			return None;
		}
		let witness = self.in_turn(&list, self.tip_witness_turn);
		self.tip_witness_turn = self.tip_witness_turn.wrapping_add(1);
		Some(witness)
	}

	/// The next `count` to hand a transaction to or ask about one: anyone on the list but the active
	/// Pro and those proven wrong, in turn, so a transaction sent again reaches the next ones. Not
	/// `skip`, those that just failed, unless nobody else is left.
	pub fn next_to_tell(&mut self, count: usize, skip: &[String], now: Now) -> Vec<String> {
		let list = self.witness_list(now);
		let usable: Vec<&String> = list.iter().filter(|id| !skip.contains(id)).collect();
		let from: Vec<String> =
			if usable.is_empty() { list.clone() } else { usable.into_iter().cloned().collect() };
		let mut picked: Vec<String> = Vec::with_capacity(count);
		for _ in 0..(count * 2).max(from.len() * 2) {
			if picked.len() >= count.min(from.len()) {
				break;
			}
			let next = self.in_turn(&from, self.send_turn);
			self.send_turn = self.send_turn.wrapping_add(1);
			if !picked.contains(&next) {
				picked.push(next);
			}
		}
		picked
	}

	/// Those dropped since the last call.
	pub fn take_newly_dropped(&mut self) -> Vec<DroppedPro> {
		std::mem::take(&mut self.newly_dropped)
	}

	/// Whether [`Self::memory`] changed since the last call.
	pub fn take_dirty(&mut self) -> bool {
		std::mem::take(&mut self.dirty)
	}

	/// The ordered list the Selector walks, from whoever does the matching.
	///
	/// With a Pro in hand this moves nothing, unless that Pro has left a non-empty list: then
	/// the node moves once another answers. An empty list says nothing about the current Pro:
	/// the matching app may simply know nobody yet.
	pub fn set_candidates(&mut self, candidates: Vec<String>, now: Now) {
		let mut list: Vec<String> = Vec::with_capacity(candidates.len());
		for candidate in candidates {
			let id = normalise_node_id(&candidate);
			if !id.is_empty() && !list.contains(&id) {
				list.push(id);
			}
		}
		if list != self.memory.candidates {
			self.memory.candidates = list;
			self.dirty = true;
		}
		self.reselect(now);
	}

	/// The owner's choice of one source, or `None` to clear it. A new pin takes effect at once,
	/// without waiting for it to answer: the old Pro's lease is released, and if the pin is dead
	/// the status says so.
	pub fn set_pin(&mut self, pin: Option<String>, now: Now) {
		let pin = pin.map(|p| normalise_node_id(&p)).filter(|p| !p.is_empty());
		if pin != self.memory.pinned {
			self.memory.pinned = pin.clone();
			self.dirty = true;
		}
		self.end_use_for_now();
		// Choosing a Pro proven lying is the owner's call to make.
		if let Some(pin) = &pin {
			let before = self.memory.dropped.len();
			self.memory.dropped.retain(|dropped| dropped.node_id != *pin);
			self.dirty |= self.memory.dropped.len() != before;
		}
		match pin {
			Some(pin) if self.active.as_deref() == Some(pin.as_str()) => {
				self.walk = None;
				if self.state != SessionState::Active {
					self.probe_due_ms = Some(now.mono_ms);
				}
			},
			Some(pin) => self.switch_to(pin, now, None, MoveBy::Owner),
			None => self.reselect(now),
		}
	}

	/// Starts or refreshes a search if the list or the state calls for one.
	fn reselect(&mut self, now: Now) {
		if self.memory.pinned.is_some() {
			return;
		}
		// A pin kept the node on a Pro proven lying, and the pin is gone.
		if self.picks_by_itself()
			&& self.active.as_deref().map_or(false, |active| self.is_dropped(active, now))
		{
			self.leave_active(now);
			return;
		}
		match (&self.active, self.state) {
			(None, _) => self.begin_walk(false, now),
			(Some(_), SessionState::Unreachable) => self.begin_walk(false, now),
			(Some(active), _) => {
				let list = &self.memory.candidates;
				let chosen =
					self.memory.used_for_now.as_ref() == Some(active) || !self.picks_by_itself();
				if !chosen && !list.is_empty() && !list.contains(active) {
					self.begin_walk(true, now);
				}
			},
		}
	}

	fn begin_walk(&mut self, keep_current: bool, now: Now) {
		let mut queue: VecDeque<String> = VecDeque::new();
		let last_good = self.memory.last_good.iter();
		// Off the list only by itself; see the module docs.
		let listed = if self.picks_by_itself() { &self.memory.candidates[..] } else { &[] };
		for id in listed.iter().chain(last_good) {
			if self.active.as_deref() != Some(id.as_str())
				&& !queue.contains(id)
				&& !self.is_dropped(id, now)
			{
				queue.push_back(id.clone());
			}
		}
		self.next_walk_ms = None;
		self.walk = Some(Walk { queue, keep_current });
		self.advance_walk(now);
	}

	/// The search ran out of candidates, or has none left to ask.
	fn advance_walk(&mut self, now: Now) {
		let Some(walk) = &self.walk else { return };
		if !walk.queue.is_empty() || self.probe_in_flight.is_some() {
			return;
		}
		let keep_current = walk.keep_current;
		self.walk = None;
		if keep_current {
			return;
		}
		if let Some(old) = self.active.take() {
			self.release_if_held(&old);
			self.pending.push_back(Action::Retarget(None));
			self.left = Some(old);
		}
		self.clear_judgements();
		self.end_use_for_now();
		self.state = SessionState::NoProvider;
		self.delivery = Delivery::Pull;
		self.probe_due_ms = None;
		self.subscribe_due_ms = None;
		self.next_walk_ms = Some(now.mono_ms + ms(NO_PROVIDER_PROBE_INTERVAL));
	}

	fn release_if_held(&mut self, target: &str) {
		if self.lease_held {
			self.lease_held = false;
			self.pending.push_back(Action::Release(target.to_string()));
		}
	}

	/// Moves to `target`. `answered` when it has just answered a probe, so needs no other.
	fn switch_to(&mut self, target: String, now: Now, answered: Option<Now>, by: MoveBy) {
		let from = self.active.take();
		if let Some(old) = &from {
			self.release_if_held(old);
		}
		let left = self.left.take();
		self.note_move(from.or(left), &target, by, now);
		self.end_use_for_now();
		self.refused = None;
		self.pending.push_back(Action::Retarget(Some(target.clone())));
		self.active = Some(target);
		self.state = SessionState::Active;
		self.delivery = Delivery::Pull;
		self.walk = None;
		self.next_walk_ms = None;
		self.failed_retries = 0;
		self.unsupported_seen = false;
		self.probe_in_flight = None;
		self.subscribe_in_flight = false;
		self.subscribe_due_ms = self.wants_push().then_some(now.mono_ms);
		self.last_answer_ms = now.mono_ms;
		self.last_heard_ms = now.mono_ms;
		self.retry_witness = None;
		self.cross_check.conflict = None;
		self.clear_judgements();
		self.left_on_evidence = false;
		if self.cross_check.supported {
			self.cross_check_due_ms = Some(now.mono_ms + ms(CROSS_CHECK_FIRST_AFTER));
			self.tip_check_due_ms = Some(now.mono_ms + ms(TIP_CHECK_QUIET_AFTER));
		}
		match answered {
			Some(at) => {
				self.probe_due_ms = None;
				self.note_good(at);
			},
			None => self.probe_due_ms = Some(now.mono_ms),
		}
	}

	fn note_move(&mut self, from: Option<String>, to: &str, by: MoveBy, now: Now) {
		if self.moves.len() >= MAX_MOVES_KEPT {
			self.moves.pop_front();
		}
		self.moves.push_back(SourceMove {
			from,
			to: to.to_string(),
			at_ms: now.unix_secs.saturating_mul(1000),
			by,
		});
	}

	fn note_good(&mut self, now: Now) {
		self.last_ok_at_unix = Some(now.unix_secs);
		self.last_answer_ms = now.mono_ms;
		self.not_sent_since_ms = None;
		self.not_sent_stale = false;
		let proven = self.active.as_deref().map_or(false, |active| self.is_dropped(active, now));
		if self.memory.last_good != self.active && !proven {
			self.memory.last_good.clone_from(&self.active);
			self.dirty = true;
		}
	}

	/// What is due now. Effects queued by the inputs since the last poll come first, in order.
	pub fn poll(&mut self, now: Now) -> Vec<Action> {
		self.forget_expired_drops(now);
		if let Some(at) = self.next_walk_ms {
			if now.mono_ms >= at && self.walk.is_none() {
				self.reselect_after_wait(now);
			}
		}
		self.conclude_suspect(now);
		self.not_sent_stale = self
			.not_sent_since_ms
			.map_or(false, |since| now.mono_ms.saturating_sub(since) >= ms(NOT_SENT_STALE_AFTER));

		if self.probe_in_flight.is_none() && now.mono_ms >= self.probes_held_until_ms {
			if let Some(next) = self.walk.as_mut().and_then(|walk| walk.queue.pop_front()) {
				self.probe_in_flight = Some(next.clone());
				self.last_probe_ms = Some(now.mono_ms);
				self.pending.push_back(Action::Probe(next));
			} else if self.active_probe_is_due(now) {
				if let Some(active) = self.active.clone() {
					self.probe_due_ms = None;
					self.probe_in_flight = Some(active.clone());
					self.last_probe_ms = Some(now.mono_ms);
					self.pending.push_back(Action::Probe(active));
				}
			}
		}

		if self.wants_push()
			&& self.state == SessionState::Active
			&& !self.subscribe_in_flight
			&& self.subscribe_due_ms.map_or(false, |at| now.mono_ms >= at)
		{
			if let Some(active) = self.active.clone() {
				self.subscribe_due_ms = None;
				self.subscribe_in_flight = true;
				self.pending.push_back(Action::Subscribe(active));
			}
		}

		if self.state == SessionState::Active
			&& self.walk.is_none()
			&& !self.cross_check_in_flight
			&& self.cross_check_due_ms.map_or(false, |at| now.mono_ms >= at)
		{
			if let (Some(active), Some(witness)) = (self.active.clone(), self.next_witness(now)) {
				self.cross_check_due_ms = None;
				self.cross_check_in_flight = true;
				self.pending.push_back(Action::CrossCheck { active, witness });
			}
		}

		if self.state == SessionState::Active
			&& self.walk.is_none()
			&& !self.tip_check_in_flight
			&& self.tip_check_due_ms.map_or(false, |at| now.mono_ms >= at)
		{
			self.tip_check_due_ms = None;
			match (self.active.clone(), self.next_tip_witness(now)) {
				(Some(active), Some(witness)) => {
					self.tip_check_in_flight = true;
					self.pending.push_back(Action::TipCheck { active, witness });
				},
				// Nobody to ask. A witness appearing counts from here.
				_ => self.tip_check_due_ms = Some(now.mono_ms + ms(TIP_CHECK_QUIET_AFTER)),
			}
		}

		self.pending.drain(..).collect()
	}

	fn reselect_after_wait(&mut self, now: Now) {
		self.next_walk_ms = None;
		if self.active.is_none() {
			self.begin_walk(false, now);
		}
	}

	fn active_probe_is_due(&self, now: Now) -> bool {
		if self.active.is_none() || self.walk.as_ref().map_or(false, |w| !w.keep_current) {
			return false;
		}
		if self.probe_due_ms.map_or(false, |at| now.mono_ms >= at) {
			return true;
		}
		let signal = match self.delivery {
			Delivery::Push => self.last_heard_ms,
			Delivery::Pull => self.last_answer_ms,
		};
		self.state == SessionState::Active
			&& now.mono_ms.saturating_sub(signal) >= ms(NO_SIGNAL_PROBE_AFTER)
	}

	/// A probe to `target` came back.
	pub fn on_probe(&mut self, target: &str, outcome: ProbeOutcome, now: Now) {
		let awaited = self.probe_in_flight.as_deref() == Some(target);
		if awaited {
			self.probe_in_flight = None;
		}
		if outcome == ProbeOutcome::NotSent {
			self.on_probe_not_sent(target, now);
			return;
		}
		if self.active.as_deref() == Some(target) {
			self.on_active_probe(outcome, now);
		} else if let ProbeOutcome::Answered { .. } = outcome {
			// A candidate answered the search. One from before a move answers nothing.
			if let Some(walk) = self.walk.as_ref().filter(|_| awaited) {
				let by = match (walk.keep_current, self.left_on_evidence) {
					(true, _) => MoveBy::List,
					(false, true) => MoveBy::Evidence,
					(false, false) => MoveBy::Auto,
				};
				self.switch_to(target.to_string(), now, Some(now), by);
				return;
			}
		}
		self.advance_walk(now);
	}

	/// Nobody was asked: no state moves and no retry is used up. The same one is asked again.
	fn on_probe_not_sent(&mut self, target: &str, now: Now) {
		self.probes_held_until_ms = now.mono_ms + ms(NOT_SENT_RETRY_AFTER);
		if self.active.as_deref() == Some(target) {
			self.not_sent_since_ms.get_or_insert(now.mono_ms);
			self.probe_due_ms = Some(self.probes_held_until_ms);
		} else if let Some(walk) = self.walk.as_mut() {
			walk.queue.push_front(target.to_string());
		}
	}

	fn on_active_probe(&mut self, outcome: ProbeOutcome, now: Now) {
		match outcome {
			ProbeOutcome::Answered { missed_blocks } => {
				let recovered = self.state != SessionState::Active;
				self.state = SessionState::Active;
				self.failed_retries = 0;
				self.unsupported_seen = false;
				self.probe_due_ms = None;
				self.last_heard_ms = now.mono_ms;
				self.note_good(now);
				self.drop_search_unless_moving();
				let lease_may_be_gone =
					recovered || (missed_blocks && self.delivery == Delivery::Push);
				if self.wants_push() && lease_may_be_gone && !self.subscribe_in_flight {
					self.subscribe_due_ms = Some(now.mono_ms);
				}
			},
			ProbeOutcome::Unsupported if !self.unsupported_seen => {
				self.unsupported_seen = true;
				self.probe_due_ms = Some(now.mono_ms + ms(PROBE_RETRIES_AFTER[0]));
			},
			ProbeOutcome::Unsupported | ProbeOutcome::Failed => self.on_active_failed(now),
			ProbeOutcome::NotSent => {},
		}
	}

	/// A search that was to replace a dead Pro is over once that Pro answers. One replacing a
	/// Pro that left the list carries on.
	fn drop_search_unless_moving(&mut self) {
		if self.walk.as_ref().map_or(false, |w| !w.keep_current) {
			self.walk = None;
		}
	}

	fn on_active_failed(&mut self, now: Now) {
		match self.state {
			SessionState::Active => {
				self.state = SessionState::Suspect;
				self.suspect_since_ms = now.mono_ms;
				self.failed_retries = 0;
				self.probe_due_ms = Some(now.mono_ms + ms(PROBE_RETRIES_AFTER[0]));
			},
			SessionState::Suspect => {
				self.failed_retries += 1;
				self.probe_due_ms = PROBE_RETRIES_AFTER
					.get(self.failed_retries)
					.map(|after| self.suspect_since_ms + ms(*after));
				self.conclude_suspect(now);
			},
			SessionState::Unreachable => {
				self.probe_due_ms = Some(now.mono_ms + ms(NO_PROVIDER_PROBE_INTERVAL));
			},
			SessionState::NoProvider => {},
		}
	}

	/// Every retry has come back failed, and the time is up. One still out has not failed.
	fn conclude_suspect(&mut self, now: Now) {
		if self.state == SessionState::Suspect
			&& self.failed_retries >= PROBE_RETRIES_AFTER.len()
			&& now.mono_ms >= self.suspect_since_ms + ms(SUSPECT_FOR)
		{
			self.enter_unreachable(now);
		}
	}

	fn enter_unreachable(&mut self, now: Now) {
		self.state = SessionState::Unreachable;
		self.subscribe_due_ms = None;
		if self.memory.pinned.is_some() {
			self.probe_due_ms = Some(now.mono_ms + ms(NO_PROVIDER_PROBE_INTERVAL));
			return;
		}
		self.probe_due_ms = None;
		self.begin_walk(false, now);
	}

	/// A `subscribe` to `target` came back.
	pub fn on_subscribe(&mut self, target: &str, outcome: SubscribeOutcome, now: Now) {
		let current = self.active.as_deref() == Some(target);
		if !current {
			// The node moved while asking. A lease it got meanwhile is one it does not want.
			if let SubscribeOutcome::Granted { .. } = outcome {
				self.pending.push_back(Action::Release(target.to_string()));
			}
			return;
		}
		self.subscribe_in_flight = false;
		match outcome {
			SubscribeOutcome::Granted { lease_until_unix } => {
				self.lease_held = true;
				self.delivery = Delivery::Push;
				self.last_heard_ms = now.mono_ms;
				self.refused = None;
				self.note_lease(lease_until_unix, now);
			},
			SubscribeOutcome::Refused { retry_after } => {
				self.lease_held = false;
				self.delivery = Delivery::Pull;
				let wait = retry_after.unwrap_or(SUBSCRIBE_REFUSED_RETRY_AFTER);
				self.subscribe_due_ms = Some(now.mono_ms + ms(wait.min(MAX_WAIT_A_PRO_NAMES)));
			},
			SubscribeOutcome::Unsupported => {
				self.lease_held = false;
				self.delivery = Delivery::Pull;
				self.subscribe_due_ms = Some(now.mono_ms + ms(SUBSCRIBE_REFUSED_RETRY_AFTER));
			},
			SubscribeOutcome::NotSent => {
				self.subscribe_due_ms = Some(now.mono_ms + ms(NOT_SENT_RETRY_AFTER));
			},
			SubscribeOutcome::Failed => {
				self.delivery = Delivery::Pull;
				self.subscribe_due_ms = Some(now.mono_ms + ms(SUBSCRIBE_RETRY_AFTER));
			},
		}
	}

	fn note_lease(&mut self, lease_until_unix: u64, now: Now) {
		let left = lease_until_unix.saturating_sub(now.unix_secs);
		let renew_in =
			left.saturating_sub(LEASE_RENEW_BEFORE.as_secs()).min(MAX_WAIT_A_PRO_NAMES.as_secs());
		self.subscribe_due_ms = Some(now.mono_ms + renew_in * 1000);
	}

	/// A block update arrived from `from`, naming the lease's new end if it did. A push is a
	/// direct answer: it brings a suspect Pro straight back.
	pub fn on_push(&mut self, from: &str, lease_until_unix: Option<u64>, now: Now) -> PushVerdict {
		let from = normalise_node_id(from);
		if !self.wants_push() || self.active.as_deref() != Some(from.as_str()) {
			return PushVerdict::NotSubscribed;
		}
		self.state = SessionState::Active;
		self.delivery = Delivery::Push;
		self.lease_held = true;
		self.failed_retries = 0;
		self.unsupported_seen = false;
		self.probe_due_ms = None;
		self.last_heard_ms = now.mono_ms;
		self.note_good(now);
		self.drop_search_unless_moving();
		if let Some(until) = lease_until_unix {
			self.note_lease(until, now);
		}
		PushVerdict::Accept
	}

	/// An ordinary call to `target` was answered: as good as a probe for whether it is alive, so
	/// it brings a suspect Pro back. Says nothing about a lease.
	pub fn on_call_answered(&mut self, target: &str, now: Now) {
		if self.active.as_deref() != Some(target) {
			return;
		}
		if self.state != SessionState::Active {
			self.state = SessionState::Active;
			self.failed_retries = 0;
			self.unsupported_seen = false;
			self.probe_due_ms = None;
			self.drop_search_unless_moving();
			if self.wants_push() {
				self.subscribe_due_ms = Some(now.mono_ms);
			}
		}
		self.note_good(now);
	}

	/// An ordinary call to `target` got no answer. Decides nothing, but an active Pro is probed
	/// now rather than at the next timer.
	pub fn on_call_unreachable(&mut self, target: &str, now: Now) {
		if self.state == SessionState::Active && self.active.as_deref() == Some(target) {
			self.bring_probe_forward(now);
		}
	}

	/// The gossip card of `node_id` was last seen `age` ago, from whoever reads gossip. Only an
	/// old card of the active Pro has any effect, and that is an early probe.
	pub fn card_age_hint(&mut self, node_id: &str, age: Duration, now: Now) {
		let id = normalise_node_id(node_id);
		if self.state == SessionState::Active
			&& self.active.as_deref() == Some(id.as_str())
			&& age >= CARD_AGE_PROBE_AFTER
		{
			self.bring_probe_forward(now);
		}
	}

	fn bring_probe_forward(&mut self, now: Now) {
		let recently = self
			.last_probe_ms
			.map_or(false, |at| now.mono_ms.saturating_sub(at) < ms(EARLY_PROBE_MIN_INTERVAL));
		if !recently && self.probe_due_ms.is_none() {
			self.probe_due_ms = Some(now.mono_ms);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const A: &str = "02aa";
	const B: &str = "02bb";
	const C: &str = "02cc";

	fn at(secs: u64) -> Now {
		Now { mono_ms: secs * 1000, unix_secs: 1_000_000 + secs }
	}

	fn answered() -> ProbeOutcome {
		ProbeOutcome::Answered { missed_blocks: false }
	}

	fn on(active: &str) -> ProviderSession {
		let memory = SessionMemory {
			longest_known: Vec::new(),
			candidates: vec![A.into(), B.into(), C.into()],
			pinned: None,
			last_good: Some(active.into()),
			dropped: Vec::new(),
			used_for_now: None,
			auto_source: None,
		};
		let mut session = ProviderSession::new(DeliveryPreference::Push, memory, at(0));
		let actions = session.poll(at(0));
		assert_eq!(
			actions,
			vec![Action::Probe(active.into()), Action::Subscribe(active.into())],
			"a resumed session asks its Pro at once"
		);
		session.on_probe(active, answered(), at(0));
		session.on_subscribe(
			active,
			SubscribeOutcome::Granted { lease_until_unix: at(0).unix_secs + 3600 },
			at(0),
		);
		assert_eq!(session.delivery(), Delivery::Push);
		session
	}

	/// Fails the active Pro's probes at `first`, +30, +90 and +160. Returns when the search for
	/// another falls due, +210, which the next poll starts.
	fn fail_until_unreachable(session: &mut ProviderSession, target: &str, first: u64) -> u64 {
		for when in [0u64, 30, 90, 160].map(|after| first + after) {
			let asked = session.poll(at(when));
			assert!(asked.contains(&Action::Probe(target.into())), "a probe at {}", when);
			session.on_probe(target, ProbeOutcome::Failed, at(when));
		}
		first + 210
	}

	/// A real clock: polled every second as the driver does, and a probe comes back only as long
	/// after it started as `reply` says. The machine's other tests answer in no time at all.
	struct Run {
		probes: Vec<(u64, String)>,
		/// When the state changed, with what it changed to.
		states: Vec<(u64, SessionState)>,
		/// When the active Pro changed, with what it changed to.
		moves: Vec<(u64, Option<String>)>,
	}

	impl Run {
		fn entered(&self, state: SessionState) -> Option<u64> {
			self.states.iter().find(|(_, s)| *s == state).map(|(t, _)| *t)
		}

		fn probes_of(&self, target: &str) -> Vec<u64> {
			self.probes.iter().filter(|(_, p)| p == target).map(|(t, _)| *t).collect()
		}
	}

	fn run_clock(
		session: &mut ProviderSession, from: u64, until: u64,
		reply: impl Fn(&str, u64) -> (u64, ProbeOutcome),
	) -> Run {
		let mut run = Run { probes: Vec::new(), states: Vec::new(), moves: Vec::new() };
		let mut in_flight: Vec<(u64, String, ProbeOutcome)> = Vec::new();
		let mut state = session.state();
		let mut active = session.active().map(str::to_string);
		for t in from..=until {
			let (back, later): (Vec<_>, Vec<_>) =
				in_flight.drain(..).partition(|(back_at, _, _)| *back_at <= t);
			in_flight = later;
			for (_, target, outcome) in back {
				session.on_probe(&target, outcome, at(t));
			}
			for action in session.poll(at(t)) {
				if let Action::Probe(target) = action {
					let (takes, outcome) = reply(&target, t);
					run.probes.push((t, target.clone()));
					in_flight.push((t + takes, target, outcome));
				}
			}
			if session.state() != state {
				state = session.state();
				run.states.push((t, state));
			}
			if session.active().map(str::to_string) != active {
				active = session.active().map(str::to_string);
				run.moves.push((t, active.clone()));
			}
		}
		run
	}

	const TIMEOUT: u64 = PROBE_TIMEOUT.as_secs();

	/// `dead` costs every probe the full timeout; anyone else answers in a second.
	fn dead(pro: &'static str) -> impl Fn(&str, u64) -> (u64, ProbeOutcome) {
		move |target, _| {
			if target == pro {
				(TIMEOUT, ProbeOutcome::Failed)
			} else {
				(1, answered())
			}
		}
	}

	#[test]
	fn on_a_real_clock_a_dead_pro_is_left_210_s_after_it_went_suspect() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		let run = run_clock(&mut s, 100, 700, dead(A));

		let suspect = run.entered(SessionState::Suspect).unwrap();
		assert_eq!(suspect, 100 + TIMEOUT, "the first probe spends its timeout");
		let unreachable = run.entered(SessionState::Unreachable).unwrap();
		assert_eq!(unreachable - suspect, 210, "the time the design gives, timeouts included");
		assert_eq!(run.moves, vec![(unreachable + 1, Some(B.to_string()))]);
		let starts = run.probes_of(A);
		for pair in starts.windows(2) {
			assert!(pair[1] - pair[0] >= TIMEOUT, "no probe runs past the next: {:?}", starts);
		}
		assert_eq!(starts.len(), 4, "the first and three retries: {:?}", starts);
	}

	#[test]
	fn on_push_the_designed_total_is_the_ten_minutes_a_timeout_and_210_s() {
		let mut s = on(A);
		let run = run_clock(&mut s, 0, 1000, dead(A));
		assert_eq!(run.entered(SessionState::Suspect), Some(600 + TIMEOUT));
		assert_eq!(run.entered(SessionState::Unreachable), Some(600 + TIMEOUT + 210));
		assert_eq!(run.moves, vec![(600 + TIMEOUT + 211, Some(B.to_string()))]);
	}

	#[test]
	fn a_probe_this_node_did_not_send_moves_nothing_and_comes_back() {
		let mut s = on(A);
		s.on_probe(A, answered(), at(0));
		assert_eq!(s.poll(at(700)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::NotSent, at(700));
		assert_eq!(s.state(), SessionState::Active, "nobody was asked");
		assert_eq!(s.poll(at(714)), vec![], "not at once: the refusal has to lift");
		assert_eq!(s.poll(at(715)), vec![Action::Probe(A.into())]);
		s.on_probe(A, answered(), at(715));
		assert_eq!(s.state(), SessionState::Active);
	}

	#[test]
	fn a_retry_this_node_did_not_send_is_not_a_failed_retry() {
		let mut s = on(A);
		s.on_probe(A, answered(), at(0));
		s.on_call_unreachable(A, at(100));
		assert_eq!(s.poll(at(100)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Failed, at(100));
		assert_eq!(s.state(), SessionState::Suspect);
		assert_eq!(s.poll(at(130)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::NotSent, at(130));
		assert_eq!(s.poll(at(145)), vec![Action::Probe(A.into())], "the same retry again");
		s.on_probe(A, ProbeOutcome::Failed, at(145));
		assert_eq!(s.poll(at(189)), vec![], "the next one is on the design's clock");
		assert_eq!(s.poll(at(190)), vec![Action::Probe(A.into())]);
	}

	#[test]
	fn a_search_this_node_could_not_send_does_not_give_up_on_a_source() {
		let mut s = on(A);
		s.on_probe(A, answered(), at(0));
		s.on_call_unreachable(A, at(100));
		for (at_s, outcome) in [
			(100, ProbeOutcome::Failed),
			(130, ProbeOutcome::Failed),
			(190, ProbeOutcome::Failed),
			(260, ProbeOutcome::Failed),
		] {
			let _ = s.poll(at(at_s));
			s.on_probe(A, outcome, at(at_s));
		}
		assert_eq!(s.poll(at(311)), vec![Action::Probe(B.into())]);
		s.on_probe(B, ProbeOutcome::NotSent, at(311));
		assert_eq!(s.poll(at(312)), vec![], "not C: B was not asked");
		assert_eq!(s.poll(at(326)), vec![Action::Probe(B.into())], "B again");
		s.on_probe(B, answered(), at(326));
		assert_eq!(s.active(), Some(B));
	}

	#[test]
	fn a_lease_ask_this_node_did_not_send_keeps_the_delivery_and_comes_back_soon() {
		let mut s = on(A);
		s.on_probe(A, answered(), at(0));
		let renew_at = 60;
		let until = 1_000_000 + LEASE_RENEW_BEFORE.as_secs() + renew_at;
		s.on_subscribe(A, SubscribeOutcome::Granted { lease_until_unix: until }, at(0));
		assert_eq!(s.delivery(), Delivery::Push);
		assert_eq!(s.poll(at(renew_at)), vec![Action::Subscribe(A.into())]);
		s.on_subscribe(A, SubscribeOutcome::NotSent, at(renew_at));
		assert_eq!(s.delivery(), Delivery::Push, "the lease is still held");
		assert_eq!(s.poll(at(renew_at + 14)), vec![]);
		assert_eq!(s.poll(at(renew_at + 15)), vec![Action::Subscribe(A.into())]);
	}

	#[test]
	fn a_pro_failing_at_once_still_gets_the_whole_210_s() {
		for takes in [0u64, 1, 20] {
			let mut s = on(A);
			s.on_call_unreachable(A, at(100));
			let run = run_clock(&mut s, 100, 700, |target, _| {
				if target == A {
					(takes, ProbeOutcome::Failed)
				} else {
					(1, answered())
				}
			});
			let suspect = run.entered(SessionState::Suspect).unwrap();
			let unreachable = run.entered(SessionState::Unreachable).unwrap();
			assert_eq!(unreachable - suspect, 210, "a probe taking {} s", takes);
		}
	}

	#[test]
	fn on_a_real_clock_a_restart_answering_the_last_retry_moves_nothing() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		// The Pro is back while the last retry is being answered, just before the time is up.
		let run = run_clock(&mut s, 100, 700, |target, started| match target {
			A if started >= 300 => (TIMEOUT - 1, answered()),
			_ => (TIMEOUT, ProbeOutcome::Failed),
		});
		assert_eq!(run.entered(SessionState::Unreachable), None);
		assert_eq!(run.moves, vec![]);
		assert_eq!(s.state(), SessionState::Active);
		assert_eq!(s.active(), Some(A));
	}

	#[test]
	fn a_verdict_waits_for_a_probe_that_is_still_out() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		// An unanswered ask is no evidence: the last retry comes back after the time is up, alive.
		let run = run_clock(&mut s, 100, 700, |target, started| match target {
			A if started >= 300 => (TIMEOUT + 5, answered()),
			_ => (TIMEOUT, ProbeOutcome::Failed),
		});
		assert_eq!(run.entered(SessionState::Unreachable), None);
		assert_eq!(s.active(), Some(A));
	}

	#[test]
	fn on_a_real_clock_a_first_unsupported_during_suspect_costs_no_retry() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		// Host back, app still starting: the last retry says Unsupported. It does not count, so
		// one more real failure is needed, however late.
		let run = run_clock(&mut s, 100, 700, |target, started| match target {
			A if (300..=310).contains(&started) => (0, ProbeOutcome::Unsupported),
			A => (TIMEOUT, ProbeOutcome::Failed),
			_ => (1, answered()),
		});
		let starts = run.probes_of(A);
		assert_eq!(starts.len(), 5, "the first, three retries and one for the first Unsupported");
		let suspect = run.entered(SessionState::Suspect).unwrap();
		let unreachable = run.entered(SessionState::Unreachable).unwrap();
		assert!(unreachable - suspect > 210, "{} after suspect", unreachable - suspect);
		assert_eq!(unreachable, starts[4] + TIMEOUT);
	}

	#[test]
	fn on_a_real_clock_a_returned_pro_never_takes_the_node_back() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		let run = run_clock(&mut s, 100, 7300, |target, started| match target {
			// Dead for the failover, back for good from then on.
			A if started < 400 => (TIMEOUT, ProbeOutcome::Failed),
			_ => (1, answered()),
		});
		assert_eq!(run.moves.len(), 1, "one move and no flap: {:?}", run.moves);
		assert_eq!(s.active(), Some(B));
		let after_move = run.moves[0].0;
		assert!(run.probes_of(A).iter().all(|t| *t < after_move), "the old Pro is left alone");
	}

	#[test]
	fn the_retries_leave_each_probe_its_timeout_and_3_5_min_pass_before_moving() {
		assert_eq!(
			SUSPECT_FOR.as_secs(),
			30 + 60 + 120,
			"named in the design, and what fleet restarts are measured against"
		);
		assert_eq!(PROBE_RETRIES_AFTER.map(|d| d.as_secs()), [30, 90, 160]);
		for pair in PROBE_RETRIES_AFTER.windows(2) {
			assert!(pair[1] - pair[0] >= PROBE_TIMEOUT, "no probe runs past the next");
		}
		assert_eq!(NO_SIGNAL_PROBE_AFTER.as_secs(), 600);
		assert_eq!(CARD_AGE_PROBE_AFTER.as_secs(), 180);

		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		assert_eq!(s.poll(at(100)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Failed, at(100));
		assert_eq!(s.state(), SessionState::Suspect);
		assert!(!s.push_is_trusted(), "pushes are no truth about a suspect Pro");
		assert_eq!(s.active(), Some(A), "still the target");

		assert_eq!(s.poll(at(129)), vec![], "not before 30 s");
		assert_eq!(s.poll(at(130)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Failed, at(130));
		assert_eq!(s.poll(at(189)), vec![], "not before 1 min more");
		assert_eq!(s.poll(at(190)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Failed, at(190));
		assert_eq!(s.state(), SessionState::Suspect);
		assert_eq!(s.poll(at(259)), vec![], "the last starts a timeout before the time is up");
		assert_eq!(s.poll(at(260)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Failed, at(260));
		assert_eq!(s.state(), SessionState::Suspect, "failing fast does not shorten the time");
		assert_eq!(s.poll(at(309)), vec![]);
		assert_eq!(s.state(), SessionState::Suspect);

		// The next candidate is probed before anything moves.
		assert_eq!(s.poll(at(310)), vec![Action::Probe(B.into())]);
		assert_eq!(s.state(), SessionState::Unreachable, "210 s after the first failure");
		assert_eq!(s.active(), Some(A));
		s.on_probe(B, answered(), at(311));
		assert_eq!(s.active(), Some(B));
		assert_eq!(s.state(), SessionState::Active);
		assert_eq!(s.memory().last_good.as_deref(), Some(B));
		assert_eq!(
			s.poll(at(311)),
			vec![
				Action::Release(A.into()),
				Action::Retarget(Some(B.into())),
				Action::Subscribe(B.into())
			],
			"the old lease goes, the new target comes in, and the new Pro is asked to push"
		);
	}

	#[test]
	fn an_answer_during_suspect_brings_it_back_with_a_new_subscribe_and_no_move() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		s.poll(at(100));
		s.on_probe(A, ProbeOutcome::Failed, at(100));
		assert_eq!(s.state(), SessionState::Suspect);

		s.poll(at(130));
		s.on_probe(A, answered(), at(130));
		assert_eq!(s.state(), SessionState::Active);
		assert_eq!(s.active(), Some(A));
		assert_eq!(
			s.poll(at(130)),
			vec![Action::Subscribe(A.into())],
			"the lease may be gone: a Pro's restart forgets every lease"
		);
	}

	#[test]
	fn a_first_unsupported_does_not_count_and_a_second_does() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		s.poll(at(100));
		s.on_probe(A, ProbeOutcome::Unsupported, at(100));
		assert_eq!(s.state(), SessionState::Active, "could be its app restarting");
		assert_eq!(s.poll(at(129)), vec![]);
		assert_eq!(s.poll(at(130)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Unsupported, at(130));
		assert_eq!(s.state(), SessionState::Suspect);
		// An answer forgets the first one.
		s.poll(at(160));
		s.on_probe(A, answered(), at(160));
		s.on_call_unreachable(A, at(200));
		s.poll(at(200));
		s.on_probe(A, ProbeOutcome::Unsupported, at(200));
		assert_eq!(s.state(), SessionState::Active);
	}

	#[test]
	fn an_old_pro_answering_the_raw_routes_stays_active_though_it_does_not_know_since() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		s.poll(at(100));
		s.on_probe(A, ProbeOutcome::Unsupported, at(100));
		s.poll(at(130));
		s.on_probe(A, ProbeOutcome::Unsupported, at(130));
		assert_eq!(s.state(), SessionState::Suspect);
		// The sync loop's next tip poll is answered over a route it does know.
		s.on_call_answered(A, at(131));
		assert_eq!(s.state(), SessionState::Active);
		assert_eq!(s.last_ok_at(), Some(at(131).unix_secs));
	}

	#[test]
	fn gossip_card_age_only_brings_a_probe_forward_and_never_declares_anything() {
		let mut s = on(A);
		s.card_age_hint(A, Duration::from_secs(179), at(100));
		assert_eq!(s.poll(at(100)), vec![], "a fresh card is nothing");
		s.card_age_hint(B, Duration::from_secs(9999), at(100));
		assert_eq!(s.poll(at(100)), vec![], "another node's card is nothing");

		s.card_age_hint(A, Duration::from_secs(9999), at(100));
		assert_eq!(s.state(), SessionState::Active, "the hint alone decides nothing");
		assert!(s.push_is_trusted());
		assert_eq!(s.poll(at(100)), vec![Action::Probe(A.into())]);
		s.on_probe(A, answered(), at(101));
		assert_eq!(s.state(), SessionState::Active, "and an answer settles it");

		// Hints do not become a poll.
		s.card_age_hint(A, Duration::from_secs(9999), at(120));
		assert_eq!(s.poll(at(120)), vec![], "within the minimum interval");
		s.card_age_hint(A, Duration::from_secs(9999), at(130));
		assert_eq!(s.poll(at(130)), vec![Action::Probe(A.into())]);
	}

	#[test]
	fn on_push_ten_minutes_with_no_push_brings_a_probe_and_nothing_sooner() {
		let mut s = on(A);
		// Ordinary answered calls do not stand in for a push: the lease can be gone.
		s.on_call_answered(A, at(300));
		assert_eq!(s.poll(at(599)), vec![]);
		assert_eq!(s.poll(at(600)), vec![Action::Probe(A.into())]);
		s.on_probe(A, answered(), at(601));

		// A push restarts the wait.
		assert_eq!(s.on_push(A, None, at(900)), PushVerdict::Accept);
		assert_eq!(s.poll(at(1499)), vec![]);
		assert_eq!(s.poll(at(1500)), vec![Action::Probe(A.into())]);
		s.on_probe(A, answered(), at(1500));
		assert_eq!(s.poll(at(1500)), vec![], "no block missed: no need to ask for the lease");
	}

	#[test]
	fn on_pull_answered_calls_are_the_signal_and_no_probe_runs_while_they_come() {
		let memory = SessionMemory { last_good: Some(A.into()), ..Default::default() };
		let mut s = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		assert_eq!(s.poll(at(0)), vec![Action::Probe(A.into())], "and never a subscribe");
		s.on_probe(A, answered(), at(0));
		for tick in 1..=100 {
			s.on_call_answered(A, at(tick * 30));
			assert_eq!(s.poll(at(tick * 30)), vec![]);
		}
		assert_eq!(s.delivery(), Delivery::Pull);
		assert!(!s.push_is_trusted());
		assert_eq!(s.poll(at(3000 + 599)), vec![]);
		assert_eq!(s.poll(at(3000 + 600)), vec![Action::Probe(A.into())]);
	}

	#[test]
	fn a_probe_showing_a_missed_block_asks_for_the_lease_again() {
		let mut s = on(A);
		assert_eq!(s.poll(at(600)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Answered { missed_blocks: true }, at(600));
		assert_eq!(s.poll(at(600)), vec![Action::Subscribe(A.into())]);
	}

	#[test]
	fn a_refusal_moves_delivery_to_pull_and_never_to_another_pro() {
		for outcome in [
			SubscribeOutcome::Refused { retry_after: Some(Duration::from_secs(45)) },
			SubscribeOutcome::Unsupported,
			SubscribeOutcome::Failed,
		] {
			let mut s = on(A);
			s.poll(at(1800));
			s.on_subscribe(A, outcome, at(1800));
			assert_eq!(s.active(), Some(A), "{:?}", outcome);
			assert_eq!(s.state(), SessionState::Active);
			assert_eq!(s.delivery(), Delivery::Pull);
			assert!(!s.push_is_trusted());
		}

		let mut s = on(A);
		s.poll(at(1800));
		s.on_subscribe(
			A,
			SubscribeOutcome::Refused { retry_after: Some(Duration::from_secs(45)) },
			at(1800),
		);
		assert_eq!(s.poll(at(1844)), vec![]);
		assert_eq!(s.poll(at(1845)), vec![Action::Subscribe(A.into())], "as long as the Pro said");

		let mut s = on(A);
		s.poll(at(1800));
		s.on_subscribe(A, SubscribeOutcome::Refused { retry_after: None }, at(1800));
		s.on_call_answered(A, at(3599));
		assert_eq!(s.poll(at(3599)), vec![]);
		assert_eq!(s.poll(at(3600)), vec![Action::Subscribe(A.into())], "half an hour");

		let mut s = on(A);
		s.poll(at(1800));
		s.on_subscribe(A, SubscribeOutcome::Failed, at(1800));
		assert_eq!(s.poll(at(1919)), vec![]);
		assert_eq!(s.poll(at(1920)), vec![Action::Subscribe(A.into())], "two minutes");
	}

	#[test]
	fn a_lease_is_renewed_with_half_an_hour_left_and_a_push_naming_a_new_end_moves_that() {
		let mut s = on(A);
		s.on_call_answered(A, at(599));
		// Granted at 0 until 3600: renew at 1800. Pushes keep the probes away meanwhile.
		for t in (500..1800).step_by(500) {
			s.on_push(A, None, at(t));
		}
		assert_eq!(s.poll(at(1799)), vec![]);
		assert_eq!(s.poll(at(1800)), vec![Action::Subscribe(A.into())]);
		s.on_subscribe(
			A,
			SubscribeOutcome::Granted { lease_until_unix: at(1800).unix_secs + 3600 },
			at(1800),
		);
		s.on_push(A, Some(at(2000).unix_secs + 3600), at(2000));
		assert_eq!(s.poll(at(2000 + 599)), vec![]);
		s.on_push(A, Some(at(2500).unix_secs + 3600), at(2500));
		assert_eq!(s.poll(at(2500 + 599)), vec![], "the renewal moved with the push");
		s.on_push(A, Some(at(3000).unix_secs + 3600), at(3000));
		s.on_push(A, Some(at(3500).unix_secs + 3600), at(3500));
		s.on_push(A, Some(at(4000).unix_secs + 3600), at(4000));
		assert_eq!(s.poll(at(4100)), vec![]);
	}

	#[test]
	fn a_push_is_taken_only_from_the_active_pro_and_any_other_says_not_subscribed() {
		let mut s = on(A);
		assert_eq!(s.on_push(B, None, at(10)), PushVerdict::NotSubscribed);
		assert_eq!(s.on_push(" 02AA ", None, at(10)), PushVerdict::Accept, "ids compare as hex");

		// It follows the active one: after a move, the old Pro's next push is refused.
		s.set_pin(Some(B.into()), at(20));
		assert_eq!(s.on_push(A, None, at(21)), PushVerdict::NotSubscribed);
		assert_eq!(s.on_push(B, None, at(21)), PushVerdict::Accept);

		// A pull-only node wants nobody's pushes.
		let memory = SessionMemory { last_good: Some(A.into()), ..Default::default() };
		let mut s = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		assert_eq!(s.on_push(A, None, at(1)), PushVerdict::NotSubscribed);
		// Neither does a node with no provider.
		let mut s = ProviderSession::new(DeliveryPreference::Push, SessionMemory::default(), at(0));
		assert_eq!(s.on_push(A, None, at(1)), PushVerdict::NotSubscribed);
	}

	#[test]
	fn a_push_brings_a_suspect_pro_straight_back() {
		let mut s = on(A);
		s.on_call_unreachable(A, at(100));
		s.poll(at(100));
		s.on_probe(A, ProbeOutcome::Failed, at(100));
		assert_eq!(s.on_push(A, None, at(110)), PushVerdict::Accept);
		assert_eq!(s.state(), SessionState::Active);
		assert!(s.push_is_trusted());
		assert_eq!(s.poll(at(130)), vec![], "the retry is off");
	}

	#[test]
	fn the_owner_pin_takes_effect_at_once_and_releases_the_old_lease() {
		let mut s = on(A);
		s.set_pin(Some(C.into()), at(100));
		assert!(s.take_dirty());
		assert_eq!(s.active(), Some(C));
		assert_eq!(s.delivery(), Delivery::Pull, "until the new Pro grants");
		assert_eq!(
			s.poll(at(100)),
			vec![
				Action::Release(A.into()),
				Action::Retarget(Some(C.into())),
				Action::Probe(C.into()),
				Action::Subscribe(C.into()),
			]
		);
		// The order the two come back in does not matter.
		s.on_subscribe(
			C,
			SubscribeOutcome::Granted { lease_until_unix: at(100).unix_secs + 3600 },
			at(101),
		);
		s.on_probe(C, answered(), at(102));
		assert_eq!(s.delivery(), Delivery::Push);
		assert_eq!(s.memory().last_good.as_deref(), Some(C));
	}

	#[test]
	fn a_dead_pin_never_fails_over_reads_unreachable_and_recovers() {
		let mut s = on(A);
		s.set_pin(Some(B.into()), at(0));
		s.poll(at(0));
		s.on_subscribe(B, SubscribeOutcome::Failed, at(0));
		let reached = {
			s.on_probe(B, ProbeOutcome::Failed, at(0));
			for when in [30, 90, 210] {
				assert_eq!(s.poll(at(when)).first(), Some(&Action::Probe(B.into())));
				s.on_probe(B, ProbeOutcome::Failed, at(when));
			}
			210
		};
		assert_eq!(s.state(), SessionState::Unreachable);
		assert!(s.chain_stale());
		assert_eq!(s.active(), Some(B), "the owner's choice stands");
		assert_eq!(s.poll(at(reached + 59)), vec![]);
		assert_eq!(s.poll(at(reached + 60)), vec![Action::Probe(B.into())], "and is asked again");
		s.on_probe(B, ProbeOutcome::Failed, at(reached + 60));
		assert_eq!(s.state(), SessionState::Unreachable);
		assert_eq!(s.poll(at(reached + 120)), vec![Action::Probe(B.into())]);
		s.on_probe(B, answered(), at(reached + 120));
		assert_eq!(s.state(), SessionState::Active);
		assert!(!s.chain_stale());
	}

	#[test]
	fn clearing_the_pin_leaves_the_node_where_it_is_while_that_works() {
		let mut s = on(A);
		s.set_pin(Some(B.into()), at(0));
		s.poll(at(0));
		s.on_probe(B, answered(), at(0));
		s.set_pin(None, at(10));
		assert!(s.memory().pinned.is_none());
		assert_eq!(s.active(), Some(B), "no flapping back to a higher candidate");
		assert_eq!(s.poll(at(10)).iter().filter(|a| matches!(a, Action::Retarget(_))).count(), 0);
	}

	#[test]
	fn no_flapping_a_pro_coming_back_or_ranking_higher_moves_nothing() {
		let mut s = on(A);
		fail_until_unreachable(&mut s, A, 600);
		assert_eq!(s.poll(at(810)), vec![Action::Probe(B.into())]);
		s.on_probe(B, answered(), at(811));
		assert_eq!(s.active(), Some(B));
		s.poll(at(811));

		// A is back and first in a fresh list.
		s.set_candidates(vec![A.into(), B.into(), C.into()], at(900));
		assert_eq!(s.active(), Some(B));
		assert_eq!(s.poll(at(900)), vec![]);
		// A stray answer from it changes nothing either.
		s.on_probe(A, answered(), at(901));
		s.on_call_answered(A, at(902));
		assert_eq!(s.active(), Some(B));
		assert_eq!(s.memory().last_good.as_deref(), Some(B));
	}

	#[test]
	fn with_nobody_left_it_is_no_provider_keeps_trying_and_recovers() {
		let mut s = on(A);
		s.set_candidates(vec![A.into(), B.into()], at(1));
		let t = fail_until_unreachable(&mut s, A, 600);
		assert_eq!(s.poll(at(t)), vec![Action::Probe(B.into())]);
		s.on_probe(B, ProbeOutcome::Failed, at(t));
		assert_eq!(s.state(), SessionState::NoProvider);
		assert_eq!(s.active(), None);
		assert!(s.chain_stale());
		assert_eq!(s.delivery(), Delivery::Pull);
		assert_eq!(
			s.poll(at(t)),
			vec![Action::Release(A.into()), Action::Retarget(None)],
			"its calls now fail as unreachable, and the Pro keeps no lease for this node"
		);

		assert_eq!(s.poll(at(t + 59)), vec![]);
		assert_eq!(s.poll(at(t + 60)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Failed, at(t + 60));
		assert_eq!(s.poll(at(t + 60)), vec![Action::Probe(B.into())]);
		s.on_probe(B, ProbeOutcome::Unsupported, at(t + 60));
		assert_eq!(s.state(), SessionState::NoProvider, "a candidate is not taken on that");
		assert_eq!(s.poll(at(t + 119)), vec![]);
		assert_eq!(s.poll(at(t + 120)), vec![Action::Probe(A.into())]);
		s.on_probe(A, answered(), at(t + 120));
		assert_eq!(s.active(), Some(A));
		assert_eq!(s.state(), SessionState::Active);
		assert!(!s.chain_stale());
		assert_eq!(
			s.poll(at(t + 120)),
			vec![Action::Retarget(Some(A.into())), Action::Subscribe(A.into())]
		);
	}

	#[test]
	fn a_fresh_boot_has_no_provider_and_takes_the_first_candidate_that_answers() {
		let mut s = ProviderSession::new(DeliveryPreference::Push, SessionMemory::default(), at(0));
		assert_eq!(s.state(), SessionState::NoProvider);
		assert_eq!(s.active(), None);
		assert!(s.chain_stale());
		assert_eq!(s.poll(at(0)), vec![], "nobody to ask");

		s.set_candidates(vec![" 02AA ".into(), B.into(), "".into(), "02aa".into()], at(5));
		assert!(s.take_dirty());
		assert_eq!(s.memory().candidates, vec![A.to_string(), B.to_string()], "clean, in order");
		assert_eq!(s.poll(at(5)), vec![Action::Probe(A.into())]);
		s.on_probe(A, ProbeOutcome::Failed, at(6));
		assert_eq!(s.poll(at(6)), vec![Action::Probe(B.into())]);
		s.on_probe(B, answered(), at(7));
		assert_eq!(s.active(), Some(B));
		assert!(s.take_dirty(), "last good changed");
		assert_eq!(s.memory().last_good.as_deref(), Some(B));
		assert_eq!(s.last_ok_at(), Some(at(7).unix_secs));
	}

	#[test]
	fn a_restart_comes_back_on_the_pin_or_else_the_last_good_with_no_app() {
		let memory = SessionMemory {
			longest_known: Vec::new(),
			candidates: vec![A.into(), B.into()],
			pinned: None,
			last_good: Some(B.into()),
			dropped: Vec::new(),
			used_for_now: None,
			auto_source: None,
		};
		let mut s = ProviderSession::new(DeliveryPreference::Push, memory.clone(), at(0));
		assert_eq!(s.active(), Some(B));
		assert_eq!(s.state(), SessionState::Active);
		assert!(!s.push_is_trusted(), "nothing pushed yet");
		assert!(!s.take_dirty());
		assert_eq!(s.poll(at(0)), vec![Action::Probe(B.into()), Action::Subscribe(B.into())]);

		let pinned = SessionMemory { pinned: Some(A.into()), ..memory.clone() };
		let s = ProviderSession::new(DeliveryPreference::Push, pinned, at(0));
		assert_eq!(s.active(), Some(A));

		// Candidates but no last good: searched.
		let list = SessionMemory { last_good: None, ..memory };
		let mut s = ProviderSession::new(DeliveryPreference::Push, list, at(0));
		assert_eq!(s.state(), SessionState::NoProvider);
		assert_eq!(s.poll(at(0)), vec![Action::Probe(A.into())]);
	}

	#[test]
	fn a_pro_leaving_the_list_is_replaced_only_once_another_answers() {
		let mut s = on(A);
		s.set_candidates(vec![B.into(), C.into()], at(100));
		assert_eq!(s.active(), Some(A), "not moved yet");
		assert_eq!(s.poll(at(100)), vec![Action::Probe(B.into())]);
		s.on_probe(B, ProbeOutcome::Failed, at(101));
		assert_eq!(s.poll(at(101)), vec![Action::Probe(C.into())]);
		s.on_probe(C, ProbeOutcome::Failed, at(102));
		assert_eq!(s.active(), Some(A), "nobody else answers: it stays");
		assert_eq!(s.state(), SessionState::Active);
		assert_eq!(s.poll(at(102)), vec![]);

		s.set_candidates(vec![C.into()], at(200));
		assert_eq!(s.poll(at(200)), vec![Action::Probe(C.into())]);
		s.on_probe(C, answered(), at(201));
		assert_eq!(s.active(), Some(C));

		// An empty list says nothing about the Pro in hand.
		s.poll(at(201));
		s.set_candidates(Vec::new(), at(300));
		assert_eq!(s.active(), Some(C));
		assert_eq!(s.poll(at(300)), vec![]);
	}

	#[test]
	fn a_lease_granted_after_the_node_moved_is_given_back() {
		let mut s = on(A);
		s.poll(at(1800));
		s.set_pin(Some(B.into()), at(1801));
		s.poll(at(1801));
		s.on_subscribe(
			A,
			SubscribeOutcome::Granted { lease_until_unix: at(1801).unix_secs + 3600 },
			at(1802),
		);
		assert_eq!(s.delivery(), Delivery::Pull, "it says nothing about the new Pro");
		assert_eq!(s.poll(at(1802)), vec![Action::Release(A.into())]);
	}

	#[test]
	fn only_memory_changes_mark_it_dirty() {
		let mut s = on(A);
		assert!(!s.take_dirty(), "the Pro it resumed on is already the last good");
		s.set_candidates(vec![A.into(), B.into(), C.into()], at(1));
		assert!(!s.take_dirty());
		s.set_candidates(vec![B.into(), A.into()], at(2));
		assert!(s.take_dirty());
		s.set_pin(None, at(3));
		assert!(!s.take_dirty());
		s.set_pin(Some(A.into()), at(4));
		assert!(s.take_dirty());
	}

	#[test]
	fn state_and_delivery_names_are_the_status_contract() {
		assert_eq!(
			[
				SessionState::Active,
				SessionState::Suspect,
				SessionState::Unreachable,
				SessionState::NoProvider
			]
			.map(|s| s.as_str()),
			["active", "suspect", "unreachable", "no_provider"]
		);
		assert_eq!(Delivery::Push.as_str(), "push");
		assert_eq!(Delivery::Pull.as_str(), "pull");
		assert_eq!(serde_json::to_value(SessionState::NoProvider).unwrap(), "no_provider");
		assert_eq!(serde_json::to_value(Delivery::Pull).unwrap(), "pull");
	}

	// ── filter cross-check ─────────────────────────────────────────────────

	const LYING: LieKind = LieKind::FilterLacksBlockOutput;

	fn checking(active: &str) -> ProviderSession {
		let mut session = on(active);
		session.enable_cross_check(at(0));
		session
	}

	fn cross_checks(actions: &[Action]) -> Vec<(String, String)> {
		actions
			.iter()
			.filter_map(|action| match action {
				Action::CrossCheck { active, witness } => Some((active.clone(), witness.clone())),
				_ => None,
			})
			.collect()
	}

	fn agreed() -> CrossCheckOutcome {
		CrossCheckOutcome::Agreed { height: 100 }
	}

	fn active_lied() -> CrossCheckOutcome {
		CrossCheckOutcome::Judged { height: 100, active_lied: Some(LYING), witness_lied: None }
	}

	fn witness_lied() -> CrossCheckOutcome {
		CrossCheckOutcome::Judged { height: 100, active_lied: None, witness_lied: Some(LYING) }
	}

	/// The session asks to check at `secs`, and is answered `outcome`.
	fn check_at(session: &mut ProviderSession, secs: u64, outcome: CrossCheckOutcome) -> String {
		let checks = cross_checks(&session.poll(at(secs)));
		assert_eq!(checks.len(), 1, "a check is due at {}", secs);
		let (active, witness) = checks[0].clone();
		session.on_cross_check(&active, &witness, outcome, at(secs));
		witness
	}

	#[test]
	fn the_call_budget_is_one_check_an_hour_after_the_first() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		assert!(cross_checks(&session.poll(at(first - 1))).is_empty());
		let mut checks = 0;
		let (mut asked_at, mut secs) = (first, first);
		// Three hours of a tick a second, with a Pro that always answers.
		while secs <= first + 3 * 3600 {
			let asked = cross_checks(&session.poll(at(secs)));
			if let Some((active, witness)) = asked.first() {
				checks += 1;
				asked_at = secs;
				session.on_cross_check(active, witness, agreed(), at(secs));
			}
			session.on_call_answered(A, at(secs));
			secs += 1;
		}
		assert_eq!(checks, 4, "at the start, and once for each hour after");
		assert_eq!(asked_at, first + 3 * CROSS_CHECK_INTERVAL.as_secs());
	}

	#[test]
	fn the_witness_is_never_the_active_pro_and_takes_turns() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let hour = CROSS_CHECK_INTERVAL.as_secs();
		let one = check_at(&mut session, first, agreed());
		let two = check_at(&mut session, first + hour, agreed());
		assert_ne!(one, A);
		assert_ne!(two, A);
		assert_ne!(one, two, "both others get asked");
	}

	#[test]
	fn with_one_pro_known_there_is_no_check_and_no_call() {
		let memory = SessionMemory { last_good: Some(A.into()), ..Default::default() };
		let mut session = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		session.enable_cross_check(at(0));
		session.on_probe(A, answered(), at(0));
		for secs in (0..7200).step_by(60) {
			session.on_call_answered(A, at(secs));
			assert!(cross_checks(&session.poll(at(secs))).is_empty());
		}
		// A second Pro appearing is all it takes.
		session.set_candidates(vec![A.into(), B.into()], at(7200));
		assert_eq!(cross_checks(&session.poll(at(7200))), vec![(A.to_string(), B.to_string())]);
	}

	#[test]
	fn a_node_that_cannot_check_never_asks() {
		// A Dependent node has no filters to compare: the session is never enabled.
		let mut session = on(A);
		for secs in (0..7200).step_by(60) {
			session.on_call_answered(A, at(secs));
			assert!(cross_checks(&session.poll(at(secs))).is_empty());
		}
		assert!(!session.cross_check().supported);
	}

	#[test]
	fn no_check_while_the_pro_is_in_doubt() {
		let mut session = checking(A);
		session.on_probe(A, ProbeOutcome::Failed, at(1));
		assert_eq!(session.state(), SessionState::Suspect);
		assert!(cross_checks(&session.poll(at(CROSS_CHECK_FIRST_AFTER.as_secs()))).is_empty());
	}

	#[test]
	fn agreeing_and_inconclusive_drop_nobody_and_keep_the_pro() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let hour = CROSS_CHECK_INTERVAL.as_secs();
		for (i, outcome) in [agreed(), CrossCheckOutcome::Inconclusive].into_iter().enumerate() {
			check_at(&mut session, first + i as u64 * hour, outcome);
			assert!(session.memory().dropped.is_empty());
			assert_eq!(session.active(), Some(A));
			assert_eq!(session.state(), SessionState::Active);
		}
		assert_eq!(session.cross_check().last_result.as_deref(), Some("inconclusive"));
		assert!(session.cross_check().supported);
	}

	#[test]
	fn a_proven_active_pro_is_left_at_once_named_and_not_picked_again_for_a_day() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let checks = cross_checks(&session.poll(at(first)));
		let (active, witness) = checks[0].clone();
		let may_rewind = session.on_cross_check(&active, &witness, active_lied(), at(first));
		assert!(may_rewind);

		let dropped = &session.memory().dropped;
		assert_eq!(dropped.len(), 1);
		assert_eq!(dropped[0].node_id, A);
		assert_eq!(dropped[0].reason, "filter_lacks_block_output");
		assert_eq!(dropped[0].height, 100);
		assert_eq!(dropped[0].until, at(first).unix_secs + DROPPED_PRO_FOR.as_secs());
		assert!(session.take_dirty());

		assert_eq!(session.active(), None, "nothing more is taken from it");
		assert_eq!(session.state(), SessionState::NoProvider);
		assert!(session.chain_stale());
		assert_eq!(session.memory().last_good, None, "a restart must not resume on it");
		let actions = session.poll(at(first));
		assert!(actions.contains(&Action::Retarget(None)));
		assert!(actions.contains(&Action::Release(A.to_string())), "{:?}", actions);
		let probed = actions.iter().find_map(|a| match a {
			Action::Probe(id) => Some(id.clone()),
			_ => None,
		});
		assert_ne!(probed.as_deref(), Some(A));
		let next = probed.expect("another candidate is asked");
		session.on_probe(&next, answered(), at(first));
		assert_eq!(session.active(), Some(next.as_str()));

		// It stays out however often it is listed, until the day is over.
		let day = DROPPED_PRO_FOR.as_secs();
		session.set_candidates(vec![A.into()], at(first + 1));
		let mut asked_of_a = false;
		for secs in (first + 2..first + day - 1).step_by(3600) {
			asked_of_a |= session.poll(at(secs)).contains(&Action::Probe(A.to_string()));
		}
		assert!(!asked_of_a, "dropped: not asked within {} s", day);
		assert!(session.memory().dropped.iter().any(|d| d.node_id == A));

		session.poll(at(first + day));
		assert!(session.memory().dropped.is_empty(), "the day is over");
	}

	#[test]
	fn a_proven_witness_is_dropped_and_the_active_pro_is_not_touched() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let witness = check_at(&mut session, first, witness_lied());
		assert_eq!(session.active(), Some(A));
		assert_eq!(session.state(), SessionState::Active);
		assert_eq!(session.memory().dropped.len(), 1);
		assert_eq!(session.memory().dropped[0].node_id, witness);
		// Never asked again, for the check or for the search.
		for hour in 1..6 {
			session.on_call_answered(A, at(first + hour * 3600));
			let other = check_at(&mut session, first + hour * 3600, agreed());
			assert_ne!(other, witness);
		}
	}

	#[test]
	fn both_proven_with_nobody_left_is_no_provider_and_stale() {
		let memory = SessionMemory {
			candidates: vec![A.into(), B.into()],
			last_good: Some(A.into()),
			..Default::default()
		};
		let mut session = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		session.enable_cross_check(at(0));
		session.on_probe(A, answered(), at(0));
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		session.on_call_answered(A, at(first));
		let both = CrossCheckOutcome::Judged {
			height: 100,
			active_lied: Some(LYING),
			witness_lied: Some(LYING),
		};
		check_at(&mut session, first, both);
		assert_eq!(session.memory().dropped.len(), 2);
		assert_eq!(session.state(), SessionState::NoProvider);
		assert_eq!(session.active(), None);
		let actions = session.poll(at(first + 120));
		assert!(!actions.iter().any(|a| matches!(a, Action::Probe(_))), "{:?}", actions);
	}

	#[test]
	fn a_dropped_pro_is_not_resumed_on_after_a_restart() {
		let memory = SessionMemory {
			candidates: vec![A.into(), B.into()],
			last_good: Some(A.into()),
			dropped: vec![DroppedPro {
				node_id: A.into(),
				reason: "filter_lacks_block_output".into(),
				height: 1,
				until: at(0).unix_secs + 100,
				at: 0,
			}],
			..Default::default()
		};
		let mut session = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		session.enable_cross_check(at(0));
		assert_eq!(session.active(), None);
		assert_eq!(session.poll(at(0)), vec![Action::Probe(B.to_string())]);
	}

	#[test]
	fn the_owners_pin_stays_on_a_proven_pro_and_the_status_says_so() {
		let mut session = checking(A);
		session.set_pin(Some(A.into()), at(1));
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let checks = cross_checks(&session.poll(at(first)));
		let (active, witness) = checks[0].clone();
		let may_rewind = session.on_cross_check(&active, &witness, active_lied(), at(first));
		assert!(!may_rewind, "still on it, so what it said stands");
		assert_eq!(session.active(), Some(A));
		assert_eq!(session.state(), SessionState::Active);
		assert_eq!(session.memory().dropped[0].node_id, A);
		assert_eq!(session.cross_check().last_result.as_deref(), Some("dropped"));
	}

	#[test]
	fn clearing_the_pin_leaves_a_proven_pro() {
		let mut session = checking(A);
		session.set_pin(Some(A.into()), at(1));
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let checks = cross_checks(&session.poll(at(first)));
		let (active, witness) = checks[0].clone();
		session.on_cross_check(&active, &witness, active_lied(), at(first));
		session.on_call_answered(A, at(first));
		assert_eq!(session.memory().last_good, None, "not while it is proven");
		session.set_pin(None, at(first + 1));
		assert_eq!(session.active(), None);
		let actions = session.poll(at(first + 1));
		assert!(actions.contains(&Action::Retarget(None)), "{:?}", actions);
		assert!(!actions.contains(&Action::Probe(A.to_string())), "{:?}", actions);
	}

	#[test]
	fn the_list_of_dropped_pros_is_bounded() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		for i in 0..MAX_DROPPED_PROS + 5 {
			session.drop_pro(&format!("03{:04x}", i), LYING, 1, at(first));
		}
		assert_eq!(session.memory().dropped.len(), MAX_DROPPED_PROS);
		assert_eq!(session.memory().dropped[0].node_id, format!("03{:04x}", 5));
	}

	#[test]
	fn pinning_a_dropped_pro_is_the_owners_call() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let witness = check_at(&mut session, first, witness_lied());
		session.set_pin(Some(witness.clone()), at(first + 1));
		assert!(session.memory().dropped.is_empty());
		assert_eq!(session.active(), Some(witness.as_str()));
	}

	#[test]
	fn a_difference_that_could_not_be_judged_is_asked_again_soon_then_at_the_interval() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		let retry = CROSS_CHECK_RETRY_AFTER.as_secs();
		let interrupted = CrossCheckOutcome::Interrupted { height: 100 };
		let witness = check_at(&mut session, first, interrupted);
		assert!(session.cross_check().conflict.is_some());
		let mut secs = first;
		for _ in 0..CROSS_CHECK_MAX_RETRIES {
			secs += retry;
			session.on_call_answered(A, at(secs));
			assert_eq!(check_at(&mut session, secs, interrupted), witness, "the same witness");
		}
		session.on_call_answered(A, at(secs + retry));
		assert!(cross_checks(&session.poll(at(secs + retry))).is_empty(), "the retries are spent");
		session.on_call_answered(A, at(secs + CROSS_CHECK_INTERVAL.as_secs()));
		check_at(&mut session, secs + CROSS_CHECK_INTERVAL.as_secs(), agreed());
	}

	#[test]
	fn not_yet_costs_nothing_and_comes_back_soon() {
		let mut session = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		check_at(&mut session, first, CrossCheckOutcome::NotYet);
		assert_eq!(session.cross_check().last_result, None);
		check_at(&mut session, first * 2, agreed());
	}

	#[test]
	fn moving_to_another_pro_brings_its_first_check_forward() {
		let mut session = checking(A);
		session.set_pin(Some(B.into()), at(10));
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		assert!(cross_checks(&session.poll(at(10 + first - 1))).is_empty());
		session.on_call_answered(B, at(10 + first));
		let checks = cross_checks(&session.poll(at(10 + first)));
		assert_eq!(checks.len(), 1);
		assert_eq!(checks[0].0, B);
	}

	// ── "use it for now": the owner moves the node without pinning it ───────

	fn list_of(ids: &[&str]) -> Vec<String> {
		ids.iter().map(|id| id.to_string()).collect()
	}

	#[test]
	fn use_for_now_moves_at_once_without_a_pin_and_releases_the_old_lease() {
		let mut s = on(A);
		assert!(s.use_now(C.into(), at(100)));
		assert_eq!(s.active(), Some(C));
		assert_eq!(s.memory().pinned, None, "not a pin");
		assert_eq!(s.memory().used_for_now.as_deref(), Some(C));
		assert!(s.take_dirty());
		assert_eq!(
			s.poll(at(100)),
			vec![
				Action::Release(A.into()),
				Action::Retarget(Some(C.into())),
				Action::Probe(C.into()),
				Action::Subscribe(C.into()),
			]
		);
	}

	#[test]
	fn the_next_list_does_not_undo_use_for_now_even_with_the_source_left_out() {
		let mut s = on(A);
		s.use_now(C.into(), at(100));
		s.poll(at(100));
		s.on_probe(C, answered(), at(101));
		// The sweep's list has a different head, then leaves the source out altogether.
		s.set_candidates(list_of(&[B, A, C]), at(102));
		assert_eq!(s.poll(at(102)), vec![], "a higher rank moves nothing");
		s.set_candidates(list_of(&[B, A]), at(103));
		let moved = s.poll(at(103));
		assert!(!moved.iter().any(|a| matches!(a, Action::Probe(_))), "no search began: {:?}", moved);
		assert_eq!(s.active(), Some(C));
	}

	#[test]
	fn a_source_used_for_now_fails_over_when_it_dies() {
		let mut s = on(A);
		s.use_now(C.into(), at(100));
		s.poll(at(100));
		s.on_probe(C, answered(), at(101));
		// Left out of the list as well: that must not make it stay.
		s.set_candidates(list_of(&[B, A]), at(102));
		s.on_probe(C, ProbeOutcome::Failed, at(110));
		assert_eq!(s.state(), SessionState::Suspect);
		for (i, after) in PROBE_RETRIES_AFTER.iter().enumerate() {
			let when = 110 + after.as_secs();
			assert_eq!(s.poll(at(when)), vec![Action::Probe(C.into())], "retry {}", i);
			s.on_probe(C, ProbeOutcome::Failed, at(when));
		}
		let end = 110 + SUSPECT_FOR.as_secs();
		assert_eq!(s.poll(at(end)), vec![Action::Probe(B.into())], "it looks for another");
		s.on_probe(B, answered(), at(end));
		assert_eq!(s.active(), Some(B));
		assert_eq!(s.memory().used_for_now, None, "that choice is over");
		assert_eq!(s.memory().pinned, None);
		// C coming back moves nothing: no flapping.
		s.set_candidates(list_of(&[C, B, A]), at(end + 1));
		assert_eq!(s.active(), Some(B));
	}

	#[test]
	fn use_for_now_replaces_a_pin_and_a_pin_replaces_use_for_now() {
		let mut s = on(A);
		s.set_pin(Some(B.into()), at(10));
		s.use_now(C.into(), at(11));
		assert_eq!(s.memory().pinned, None);
		assert_eq!(s.active(), Some(C));
		s.set_pin(Some(C.into()), at(12));
		assert_eq!(s.memory().pinned.as_deref(), Some(C));
		assert_eq!(s.memory().used_for_now, None);
		assert_eq!(s.active(), Some(C));
	}

	#[test]
	fn use_for_now_on_the_active_source_lifts_the_pin_and_keeps_it() {
		let mut s = on(A);
		s.set_pin(Some(A.into()), at(10));
		s.poll(at(10));
		assert!(s.use_now(A.into(), at(11)));
		assert_eq!(s.memory().pinned, None);
		assert_eq!(s.active(), Some(A));
		assert_eq!(s.memory().used_for_now.as_deref(), Some(A));
		assert!(!s.poll(at(11)).iter().any(|a| matches!(a, Action::Retarget(_))));
	}

	#[test]
	fn clearing_the_choice_ends_use_for_now_and_the_list_applies_again() {
		let mut s = on(A);
		s.use_now(C.into(), at(10));
		s.poll(at(10));
		s.on_probe(C, answered(), at(10));
		s.set_candidates(list_of(&[A, B]), at(11));
		assert_eq!(s.active(), Some(C));
		s.set_pin(None, at(12));
		assert_eq!(s.memory().used_for_now, None);
		assert_eq!(s.poll(at(12)), vec![Action::Probe(A.into())], "it left the list, so it moves");
	}

	#[test]
	fn a_restart_stays_on_the_source_used_for_now_and_keeps_it_unpinned() {
		let memory = SessionMemory {
			candidates: list_of(&[A, B]),
			last_good: Some(A.into()),
			used_for_now: Some(C.into()),
			..Default::default()
		};
		let mut s = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		assert_eq!(s.active(), Some(C));
		s.poll(at(0));
		s.on_probe(C, answered(), at(0));
		s.set_candidates(list_of(&[A, B]), at(1));
		assert_eq!(s.active(), Some(C));
		assert_eq!(s.memory().pinned, None);
	}

	#[test]
	fn a_dropped_source_cannot_be_used_for_now() {
		let mut s = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		s.on_call_answered(A, at(first));
		let witness = check_at(&mut s, first, witness_lied());
		assert!(!s.use_now(witness.clone(), at(first + 1)), "dropped");
		assert_eq!(s.active(), Some(A));
		assert_eq!(s.memory().used_for_now, None);
		assert_eq!(s.memory().dropped.len(), 1, "and it forgives nothing");
	}

	#[test]
	fn a_move_is_on_record_with_who_made_it() {
		let mut s = on(A);
		s.use_now(C.into(), at(100));
		s.poll(at(100));
		s.on_probe(C, answered(), at(100));
		let by_owner = s.moves().back().unwrap().clone();
		assert_eq!(by_owner.from.as_deref(), Some(A));
		assert_eq!(by_owner.to, C);
		assert_eq!(by_owner.by, MoveBy::Owner);
		assert_eq!(by_owner.at_ms, at(100).unix_secs * 1000);
		// Dies: the next one is the node's own move, naming what it left.
		s.on_probe(C, ProbeOutcome::Failed, at(110));
		for after in PROBE_RETRIES_AFTER {
			s.poll(at(110 + after.as_secs()));
			s.on_probe(C, ProbeOutcome::Failed, at(110 + after.as_secs()));
		}
		let end = 110 + SUSPECT_FOR.as_secs();
		let probe = s.poll(at(end));
		let Action::Probe(next) = &probe[0] else { panic!("{:?}", probe) };
		s.on_probe(next, answered(), at(end));
		let by_itself = s.moves().back().unwrap();
		assert_eq!(by_itself.from.as_deref(), Some(C));
		assert_eq!(by_itself.by, MoveBy::Auto);
	}

	#[test]
	fn a_move_because_the_list_changed_is_not_called_a_failure() {
		let mut s = on(A);
		s.set_candidates(list_of(&[B]), at(10));
		assert_eq!(s.poll(at(10)), vec![Action::Probe(B.into())]);
		s.on_probe(B, answered(), at(11));
		assert_eq!(s.moves().back().unwrap().by, MoveBy::List);
	}

	#[test]
	fn the_old_moves_are_forgotten_past_the_bound() {
		let mut s = on(A);
		for i in 0..(MAX_MOVES_KEPT as u64 + 3) {
			s.set_pin(Some(if i % 2 == 0 { B } else { C }.into()), at(i));
		}
		assert_eq!(s.moves().len(), MAX_MOVES_KEPT);
	}

	#[test]
	fn a_node_on_no_provider_names_the_dead_pro_when_it_finds_another() {
		let mut s = on(A);
		s.set_candidates(list_of(&[A]), at(1));
		s.on_probe(A, ProbeOutcome::Failed, at(10));
		for after in PROBE_RETRIES_AFTER {
			s.poll(at(10 + after.as_secs()));
			s.on_probe(A, ProbeOutcome::Failed, at(10 + after.as_secs()));
		}
		s.poll(at(10 + SUSPECT_FOR.as_secs()));
		assert_eq!(s.state(), SessionState::NoProvider);
		let later = 10 + SUSPECT_FOR.as_secs() + 1;
		s.set_candidates(list_of(&[B]), at(later));
		assert_eq!(s.poll(at(later)), vec![Action::Probe(B.into())]);
		s.on_probe(B, answered(), at(later));
		let moved = s.moves().back().unwrap();
		assert_eq!(moved.from.as_deref(), Some(A));
		assert_eq!(moved.by, MoveBy::Auto);
	}

	#[test]
	fn the_retries_are_told_while_suspect_and_the_next_search_with_no_provider() {
		let mut s = on(A);
		assert_eq!(s.probe_status(at(1)), None);
		s.on_probe(A, ProbeOutcome::Failed, at(10));
		let told = s.probe_status(at(15)).unwrap();
		assert_eq!(told.attempt, 1);
		assert_eq!(told.of, 1 + PROBE_RETRIES_AFTER.len() as u32);
		assert_eq!(told.next_in_s, PROBE_RETRIES_AFTER[0].as_secs() - 5);
		assert_eq!(told.waits_s, vec![30, 60, 70], "the time between one start and the next");

		let mut none = ProviderSession::new(DeliveryPreference::Pull, Default::default(), at(0));
		none.poll(at(0));
		let told = none.probe_status(at(20)).unwrap();
		assert_eq!((told.attempt, told.of), (0, 0));
		assert_eq!(told.next_in_s, NO_PROVIDER_PROBE_INTERVAL.as_secs() - 20);
		assert!(told.waits_s.is_empty());
	}

	#[test]
	fn a_refusal_is_told_until_a_lease_is_granted_or_the_node_moves() {
		let mut s = on(A);
		s.note_refused("policy", at(10));
		assert_eq!(s.refused().map(|r| r.code.as_str()), Some("policy"));
		assert_eq!(s.refused().map(|r| r.at_ms), Some(at(10).unix_secs * 1000));
		s.on_subscribe(A, SubscribeOutcome::Granted { lease_until_unix: at(20).unix_secs + 3600 }, at(20));
		assert_eq!(s.refused(), None);
		s.note_refused("policy", at(30));
		s.set_pin(Some(B.into()), at(31));
		assert_eq!(s.refused(), None);
	}

	// ── a Pro that does not show the chain ──────────────────────────────────

	fn tip_checks(actions: &[Action]) -> Vec<(String, String)> {
		actions
			.iter()
			.filter_map(|action| match action {
				Action::TipCheck { active, witness } => Some((active.clone(), witness.clone())),
				_ => None,
			})
			.collect()
	}

	/// Runs the session second by second, answering every tip check with `answer`, and says at
	/// which second it moved off `A`, if it did.
	fn until_moved(
		session: &mut ProviderSession, from: u64, to: u64,
		answer: impl Fn(u64) -> TipCheckOutcome,
	) -> Option<u64> {
		for secs in from..=to {
			let actions = session.poll(at(secs));
			if let Some((active, witness)) = tip_checks(&actions).first() {
				session.on_tip_check(active, witness, answer(secs), at(secs));
			}
			if session.active() != Some(A) {
				return Some(secs);
			}
		}
		None
	}

	const QUIET: u64 = TIP_CHECK_QUIET_AFTER.as_secs();

	#[test]
	fn silence_alone_asks_and_moves_nothing_however_long_it_lasts() {
		let mut s = checking(A);
		assert!(!s.chain_stale());
		// Six hours with no block, on a chain every witness also sees standing still.
		let moved = until_moved(&mut s, 1, 6 * 3600, |_| TipCheckOutcome::NotAhead);
		assert_eq!(moved, None);
		assert_eq!(s.state(), SessionState::Active);
		assert!(!s.chain_stale(), "silence is not evidence");
		assert!(s.behind_witness().is_none());
	}

	#[test]
	fn the_quiet_check_costs_one_call_per_silence_and_a_block_puts_it_off() {
		let mut s = checking(A);
		let (mut asked, mut secs) = (0, 1);
		while secs <= 3 * 3600 {
			// A block every 20 minutes: never quiet long enough.
			if secs % 1200 == 0 {
				s.note_block(at(secs));
			}
			asked += tip_checks(&s.poll(at(secs))).len();
			secs += 1;
		}
		assert_eq!(asked, 0, "blocks arrive, so nobody is asked");
		s.note_block(at(secs));
		let next = secs + QUIET;
		assert!(tip_checks(&s.poll(at(next - 1))).is_empty());
		assert_eq!(tip_checks(&s.poll(at(next))).len(), 1);
	}

	#[test]
	fn with_no_other_pro_nobody_is_asked_and_the_status_says_there_is_no_witness() {
		let memory = SessionMemory { last_good: Some(A.into()), ..Default::default() };
		let mut s = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		s.enable_cross_check(at(0));
		s.on_probe(A, answered(), at(0));
		assert!(s.no_witness(at(1)));
		assert!(tip_checks(&s.poll(at(QUIET))).is_empty());
		s.set_candidates(vec![A.into(), B.into()], at(QUIET + 1));
		assert!(!s.no_witness(at(QUIET + 1)));
	}

	/// B1: the requirement, on the clock.
	#[test]
	fn a_pro_behind_what_a_witness_shows_is_left_for_that_witness_within_the_bound() {
		let mut s = checking(A);
		let ahead = |_| TipCheckOutcome::Ahead {
			witness_height: 101,
			active_tip: Some(100),
			cursor: 100,
		};
		let moved = until_moved(&mut s, 1, 4 * 3600, ahead).expect("it leaves");
		// First asked at the quiet time, then given its time to catch up.
		let bound = QUIET + BEHIND_LEAVE_AFTER.as_secs() + BEHIND_RECHECK.as_secs();
		assert!(moved <= bound, "moved at {}, bound {}", moved, bound);
		assert!(moved >= QUIET + BEHIND_LEAVE_AFTER.as_secs(), "not before its time: {}", moved);
		assert_ne!(s.active(), Some(A));
		assert_eq!(s.state(), SessionState::Active);
		assert_eq!(s.moves().back().map(|m| m.by), Some(MoveBy::Evidence));
		assert!(s.behind_witness().is_none(), "the new one owes nothing for the old");
		assert!(!s.chain_stale());
	}

	#[test]
	fn while_it_is_behind_the_status_is_not_healthy_and_catching_up_clears_it() {
		let mut s = checking(A);
		let ahead = TipCheckOutcome::Ahead { witness_height: 101, active_tip: Some(100), cursor: 100 };
		let checks = tip_checks(&s.poll(at(QUIET)));
		let (active, witness) = checks[0].clone();
		s.on_tip_check(&active, &witness, ahead, at(QUIET));
		assert!(s.chain_stale(), "new channels wait");
		assert!(!s.push_is_trusted(), "and its silence is not taken for an empty chain");
		let seen = s.behind_witness().expect("named");
		assert_eq!((seen.witness.as_str(), seen.witness_height), (witness.as_str(), 101));
		assert!(seen.will_move);

		// Asked again soon, and the block has come.
		let next = QUIET + BEHIND_RECHECK.as_secs();
		assert!(tip_checks(&s.poll(at(next - 1))).is_empty());
		let checks = tip_checks(&s.poll(at(next)));
		assert_eq!(checks[0].1, witness, "the same one");
		s.on_tip_check(&active, &witness, TipCheckOutcome::NotAhead, at(next));
		assert!(!s.chain_stale());
		assert!(s.behind_witness().is_none());
		assert_eq!(s.active(), Some(A), "nothing happened");
	}

	#[test]
	fn a_node_catching_up_keeps_its_pro_and_a_pro_feeding_slowly_does_not_keep_it_for_ever() {
		let mut s = checking(A);
		// The Pro says it has the blocks and the node keeps moving, one block a look.
		let moving = |secs: u64| TipCheckOutcome::Ahead {
			witness_height: 2000,
			active_tip: Some(2000),
			cursor: 100 + (secs / 60) as u32,
		};
		let moved = until_moved(&mut s, 1, 6 * 3600, moving).expect("not for ever");
		let limit = QUIET + BEHIND_CATCHING_UP_LIMIT.as_secs();
		assert!(moved >= limit, "it had its time: {}", moved);
		assert!(moved <= limit + BEHIND_RECHECK.as_secs(), "and no more: {}", moved);
	}

	/// The Pro says it has the blocks and serves none: its word is not what counts.
	#[test]
	fn a_pro_claiming_the_tip_and_serving_nothing_is_left_on_the_short_bound() {
		let mut s = checking(A);
		let stuck = |_| TipCheckOutcome::Ahead {
			witness_height: 101,
			active_tip: Some(101),
			cursor: 100,
		};
		let moved = until_moved(&mut s, 1, 4 * 3600, stuck).expect("it leaves");
		assert!(moved <= QUIET + BEHIND_LEAVE_AFTER.as_secs() + BEHIND_RECHECK.as_secs());
	}

	#[test]
	fn a_pin_stays_behind_and_the_status_says_so() {
		let mut s = checking(A);
		s.set_pin(Some(A.into()), at(0));
		let ahead = |_| TipCheckOutcome::Ahead { witness_height: 101, active_tip: Some(100), cursor: 100 };
		assert_eq!(until_moved(&mut s, 1, 4 * 3600, ahead), None);
		assert!(s.chain_stale());
		assert_eq!(s.behind_witness().map(|b| b.will_move), Some(false));
	}

	#[test]
	fn a_witness_showing_a_header_that_fails_proof_of_work_is_convicted_and_moves_nobody() {
		let mut s = checking(A);
		let checks = tip_checks(&s.poll(at(QUIET)));
		let (active, witness) = checks[0].clone();
		s.on_tip_check(&active, &witness, TipCheckOutcome::Forged { height: 101 }, at(QUIET));
		assert_eq!(s.active(), Some(A));
		assert!(!s.chain_stale(), "its word is worth nothing");
		let dropped = &s.memory().dropped;
		assert_eq!(dropped.len(), 1);
		assert_eq!(dropped[0].node_id, witness);
		assert_eq!(dropped[0].reason, "bad_header");
	}

	#[test]
	fn a_stale_tip_or_a_stuck_loop_is_not_healthy_and_brings_the_question_forward() {
		let mut s = checking(A);
		s.on_sync_event(SyncReport::StaleTip { height: 100, age_secs: 11_000 }, at(5));
		assert!(s.chain_stale());
		assert_eq!(s.tip_stale().map(|t| t.height), Some(100));
		assert_eq!(tip_checks(&s.poll(at(5))).len(), 1, "asked now, not at the quiet time");
		let checks = tip_checks(&s.poll(at(6)));
		assert!(checks.is_empty(), "one at a time");
		s.on_tip_check(A, B, TipCheckOutcome::NotAhead, at(6));
		// It says the same every 30 s: at most one question per recheck.
		s.on_sync_event(SyncReport::StaleTip { height: 100, age_secs: 11_030 }, at(7));
		assert!(tip_checks(&s.poll(at(8))).is_empty());
		assert_eq!(tip_checks(&s.poll(at(6 + BEHIND_RECHECK.as_secs()))).len(), 1);
		s.on_sync_event(SyncReport::Healthy, at(200));
		assert!(!s.chain_stale());
		s.on_sync_event(SyncReport::Stuck, at(201));
		assert!(s.sync_stuck());
		assert!(s.chain_stale());
		assert_eq!(s.active(), Some(A), "words about the tip move nothing");
	}

	/// B2 and H2: what a Pro served that proves it wrong takes the node off it, on to whoever
	/// answers, the moves say why, and it is not gone back to.
	#[test]
	fn evidence_from_the_sync_loop_drops_the_pro_and_the_node_moves() {
		let mut s = checking(A);
		s.on_sync_event(SyncReport::Evidence { kind: LieKind::BadHeader, height: 700 }, at(10));
		assert_eq!(s.active(), None, "at once, taking nothing more from it");
		assert_eq!(s.state(), SessionState::NoProvider);
		assert_eq!(s.memory().dropped[0].node_id, A);
		assert_eq!(s.memory().dropped[0].reason, "bad_header");
		assert_eq!(s.memory().dropped[0].height, 700);
		let actions = s.poll(at(10));
		assert!(actions.contains(&Action::Retarget(None)));
		let probe = actions.iter().find_map(|a| match a {
			Action::Probe(id) => Some(id.clone()),
			_ => None,
		});
		let next = probe.expect("a search");
		assert_ne!(next, A);
		s.on_probe(&next, answered(), at(11));
		assert_eq!(s.active(), Some(next.as_str()));
		let moved = s.moves().back().expect("a move");
		assert_eq!(moved.by, MoveBy::Evidence);
		assert_eq!(moved.from.as_deref(), Some(A));
	}

	#[test]
	fn evidence_against_a_pin_keeps_it_and_says_so() {
		let mut s = checking(A);
		s.set_pin(Some(A.into()), at(0));
		s.on_sync_event(SyncReport::Evidence { kind: LieKind::InvalidFilterData, height: 9 }, at(10));
		assert_eq!(s.active(), Some(A), "the owner's choice stands");
		assert!(s.on_proven_liar());
		assert!(s.chain_stale());
		s.set_pin(None, at(20));
		assert_ne!(s.active(), Some(A), "and it was only the pin");
	}

	/// Review 3's F1, second half: a node that picks no source by itself has nowhere to go. Off its
	/// only source it would be blind, with channels, until the owner came by.
	#[test]
	fn evidence_against_the_source_of_a_node_that_does_not_pick_keeps_it_and_says_so() {
		let mut s = checking(A);
		s.use_now(A.into(), at(0));
		s.set_auto_source(Some(false), at(0));
		s.on_sync_event(SyncReport::Evidence { kind: LieKind::InvalidFilterData, height: 9 }, at(10));
		assert_eq!(s.active(), Some(A), "it stays on what the owner chose");
		assert!(s.on_proven_liar(), "and the status says so");
		assert!(s.chain_stale(), "and new channels wait");
		s.set_candidates(vec![A.into(), B.into()], at(20));
		assert_eq!(s.active(), Some(A), "the list moves nobody");
		let caught = CrossCheckOutcome::Judged {
			height: 9,
			active_lied: Some(LieKind::AnswerChanged),
			witness_lied: None,
		};
		assert!(!s.on_cross_check(A, B, caught, at(30)), "nothing is taken back from what it stays on");
		s.set_auto_source(Some(true), at(40));
		s.set_candidates(vec![A.into(), B.into()], at(41));
		assert_ne!(s.active(), Some(A), "picking again, it goes");
	}

	/// A limit reached is told as that, not as reading.
	#[test]
	fn a_reading_that_got_nowhere_is_told_apart_from_one_going_on() {
		let mut s = checking(A);
		s.note_reading(B, Some(20), true, at(1));
		assert_eq!(s.cross_check().unread.as_ref().map(|u| u.stuck), Some(false));
		s.note_reading(B, Some(20), false, at(2));
		assert_eq!(s.cross_check().unread.as_ref().map(|u| u.stuck), Some(true));
		s.note_reading(B, None, false, at(3));
		assert_eq!(s.cross_check().unread, None);
	}

	#[test]
	fn a_dead_sync_loop_is_said_and_coming_back_clears_it() {
		let mut s = checking(A);
		s.on_sync_event(SyncReport::Ended { reason: "applicator halted".into() }, at(1));
		assert!(s.chain_stale());
		assert_eq!(s.sync_loop().ended.as_deref(), Some("applicator halted"));
		s.on_sync_event(SyncReport::Restarted, at(30));
		assert!(!s.chain_stale());
		assert_eq!(s.sync_loop().ended, None);
		assert_eq!(s.sync_loop().restarts, 1);
	}

	/// M1: the host refusing to send moves nothing, and is not green for ever.
	#[test]
	fn a_host_refusing_to_send_is_stale_after_its_time_and_blames_nobody() {
		let mut s = on(A);
		let (mut secs, stale_at) = (1, NOT_SENT_STALE_AFTER.as_secs() + 1);
		s.on_probe(A, ProbeOutcome::NotSent, at(secs));
		while secs < stale_at {
			secs += 1;
			for action in s.poll(at(secs)) {
				if let Action::Probe(target) = action {
					s.on_probe(&target, ProbeOutcome::NotSent, at(secs));
				}
			}
			if secs < stale_at {
				assert!(!s.chain_stale(), "not yet at {}", secs);
			}
		}
		assert!(s.host_not_sending());
		assert!(s.chain_stale());
		assert_eq!(s.state(), SessionState::Active, "not the Pro's doing");
		assert_eq!(s.active(), Some(A));
		s.on_call_answered(A, at(secs + 1));
		s.poll(at(secs + 1));
		assert!(!s.chain_stale());
	}

	/// L4: a Pro's numbers go into this node's clock.
	#[test]
	fn a_pro_naming_absurd_waits_cannot_overflow_the_clock_or_park_the_lease() {
		let mut s = on(A);
		s.on_subscribe(A, SubscribeOutcome::Granted { lease_until_unix: u64::MAX }, at(1));
		s.on_subscribe(
			A,
			SubscribeOutcome::Refused { retry_after: Some(Duration::from_secs(u64::MAX / 2)) },
			at(2),
		);
		let day = MAX_WAIT_A_PRO_NAMES.as_secs();
		assert!(!s.poll(at(2 + day - 1)).contains(&Action::Subscribe(A.into())));
		assert!(s.poll(at(2 + day)).contains(&Action::Subscribe(A.into())));
	}

	// ── a conflict nobody can attribute: nobody is dropped ──────────────────

	fn undecided() -> CrossCheckOutcome {
		CrossCheckOutcome::Judged { height: 100, active_lied: None, witness_lied: None }
	}

	/// On A with B and C to ask. B differs with it, as the first check finds.
	fn in_conflict() -> (ProviderSession, u64) {
		let mut s = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		s.on_call_answered(A, at(first));
		assert_eq!(check_at(&mut s, first, undecided()), B);
		(s, first)
	}

	fn tie_breaks(actions: &[Action]) -> Vec<(String, String, String, u32)> {
		actions
			.iter()
			.filter_map(|action| match action {
				Action::TieBreak { active, witness, third, height } => {
					Some((active.clone(), witness.clone(), third.clone(), *height))
				},
				_ => None,
			})
			.collect()
	}

	/// The user's rule, 11-05: an unattributable conflict drops nobody. A Pro is dropped only when
	/// proven wrong.
	#[test]
	fn an_unattributable_conflict_drops_nobody_and_names_both_and_where_it_stands() {
		let (s, first) = in_conflict();
		assert!(s.memory().dropped.is_empty(), "nobody");
		assert_eq!(s.active(), Some(A));
		assert_eq!(s.state(), SessionState::Active);
		assert_eq!(s.cross_check().last_result.as_deref(), Some("conflict"));
		let conflict = s.cross_check().conflict.clone().expect("said");
		assert_eq!(conflict.active, A);
		assert_eq!(conflict.witness, B);
		assert_eq!(conflict.height, 100);
		assert_eq!(conflict.at, at(first).unix_secs);
		assert_eq!(conflict.state, ConflictState::Open);
		assert_eq!(conflict.third.as_deref(), Some(C), "about to be asked");
	}

	#[test]
	fn a_third_pro_is_asked_at_once_about_the_block_they_part_at() {
		let (mut s, first) = in_conflict();
		let asked = tie_breaks(&s.poll(at(first)));
		assert_eq!(asked, vec![(A.to_string(), B.to_string(), C.to_string(), 100)]);
		assert_eq!(s.cross_check().conflict.as_ref().unwrap().third.as_deref(), Some(C));
		assert!(tie_breaks(&s.poll(at(first + 1))).is_empty(), "once");
	}

	/// B1: sybils can fill a list, not its longest known. Those get every other turn, whatever else
	/// is on it, so an honest one among them is asked in a few turns and not a whole list's.
	#[test]
	fn those_known_longest_get_every_other_turn_as_a_witness() {
		let memory = SessionMemory {
			candidates: list_of(&[A, B, C, "02d0", "02d1", "02d2", "02d3"]),
			longest_known: list_of(&[C]),
			last_good: Some(A.into()),
			..Default::default()
		};
		let mut s = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		s.on_probe(A, answered(), at(0));
		let asked: Vec<String> = (0..4).map(|_| s.next_witness(at(1)).unwrap()).collect();
		assert!(asked.iter().filter(|id| *id == C).count() >= 2, "{:?}", asked);
		assert_eq!(asked[0], C);
		// Each send reaches it or follows it, and two different ones.
		let told = s.next_to_tell(2, &[], at(1));
		assert_eq!(told.len(), 2);
		assert_ne!(told[0], told[1]);
		assert!(told.contains(&C.to_string()), "{:?}", told);
	}

	#[test]
	fn with_no_third_pro_the_conflict_stands_and_says_so() {
		let memory = SessionMemory {
			candidates: list_of(&[A, B]),
			last_good: Some(A.into()),
			..Default::default()
		};
		let mut s = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		s.enable_cross_check(at(0));
		s.on_probe(A, answered(), at(0));
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		s.on_call_answered(A, at(first));
		check_at(&mut s, first, undecided());
		assert!(tie_breaks(&s.poll(at(first))).is_empty());
		assert_eq!(s.cross_check().conflict.as_ref().unwrap().state, ConflictState::NoThirdPro);
		assert!(s.memory().dropped.is_empty());
	}

	#[test]
	fn a_third_pro_on_the_side_of_the_active_keeps_the_node_and_drops_nobody() {
		let (mut s, first) = in_conflict();
		s.poll(at(first));
		s.on_tie_break(A, B, TieBreak::SidesWithActive);
		assert_eq!(s.active(), Some(A));
		assert!(s.memory().dropped.is_empty());
		let conflict = s.cross_check().conflict.as_ref().unwrap();
		assert_eq!(conflict.state, ConflictState::SidesWithActive);
		assert_eq!(conflict.third.as_deref(), Some(C));
	}

	/// Keys are free: two sybils siding with each other buy a warning and no more.
	#[test]
	fn a_third_pro_on_the_side_of_the_witness_moves_nobody_and_drops_nobody() {
		let (mut s, first) = in_conflict();
		s.poll(at(first));
		s.on_tie_break(A, B, TieBreak::SidesWithWitness);
		assert_eq!(s.active(), Some(A));
		assert!(s.memory().dropped.is_empty(), "two to one proves nothing");
		assert!(s.moves().iter().all(|m| m.to != B), "{:?}", s.moves());
		assert_ne!(s.memory().last_good.as_deref(), Some(B));
		let conflict = s.cross_check().conflict.as_ref().unwrap();
		assert_eq!(conflict.state, ConflictState::SidesWithWitness, "and the owner is told");
	}

	/// Nothing about a conflict stands between a Pro and being used.
	#[test]
	fn a_pro_with_an_open_conflict_can_be_chosen_and_walked_to() {
		let (mut s, first) = in_conflict();
		assert!(s.use_now(B.into(), at(first + 1)), "the owner's pick");
		assert_eq!(s.active(), Some(B));

		let (mut s, first) = in_conflict();
		let start = first + 1;
		s.on_probe(A, ProbeOutcome::Failed, at(start));
		for after in PROBE_RETRIES_AFTER {
			s.poll(at(start + after.as_secs()));
			s.on_probe(A, ProbeOutcome::Failed, at(start + after.as_secs()));
		}
		let actions = s.poll(at(start + SUSPECT_FOR.as_secs()));
		assert!(actions.contains(&Action::Probe(B.into())), "{:?}", actions);
	}

	#[test]
	fn taking_the_active_off_the_hook_needs_no_rewind() {
		// The active is believed, so nothing it gave is scanned again.
		let mut s = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		s.on_call_answered(A, at(first));
		let checks = cross_checks(&s.poll(at(first)));
		let (active, witness) = checks[0].clone();
		assert!(!s.on_cross_check(&active, &witness, undecided(), at(first)));
	}

	#[test]
	fn a_conflict_closes_when_the_answers_match() {
		let (mut s, first) = in_conflict();
		let hour = first + 2 * CROSS_CHECK_INTERVAL.as_secs();
		s.on_cross_check(A, B, agreed(), at(hour));
		assert_eq!(s.cross_check().conflict, None);

		let (mut s, first) = in_conflict();
		let hour = first + CROSS_CHECK_INTERVAL.as_secs();
		s.on_cross_check(A, B, CrossCheckOutcome::HeldWasWrong { height: 90 }, at(hour));
		assert_eq!(s.cross_check().conflict, None);
	}

	#[test]
	fn a_witness_in_conflict_later_proven_lying_is_dropped_for_that() {
		let (mut s, first) = in_conflict();
		let hour = first + CROSS_CHECK_INTERVAL.as_secs();
		s.on_cross_check(A, B, witness_lied(), at(hour));
		assert_eq!(s.memory().dropped.len(), 1);
		assert_eq!(s.memory().dropped[0].node_id, B);
		assert_eq!(s.memory().dropped[0].reason, LYING.as_str());
		assert_eq!(s.active(), Some(A));
	}

	#[test]
	fn an_active_in_conflict_later_proven_lying_is_left_for_who_differed_with_it() {
		let (mut s, first) = in_conflict();
		let hour = first + CROSS_CHECK_INTERVAL.as_secs();
		s.on_cross_check(A, B, active_lied(), at(hour));
		let dropped: Vec<&str> = s.memory().dropped.iter().map(|d| d.node_id.as_str()).collect();
		assert_eq!(dropped, vec![A]);
		let actions = s.poll(at(hour));
		assert!(actions.contains(&Action::Probe(B.into())), "{:?}", actions);
	}

	// ── who chooses: a node that cannot check what it is told ───────────────

	/// A Dependent node: pull, no sync loop to check against.
	fn dependent(memory: SessionMemory) -> ProviderSession {
		ProviderSession::new(DeliveryPreference::Pull, memory, at(0))
	}

	fn probes(actions: &[Action]) -> Vec<String> {
		actions
			.iter()
			.filter_map(|action| match action {
				Action::Probe(id) => Some(id.clone()),
				_ => None,
			})
			.collect()
	}

	/// H6: a stranger off gossip is not believed by a node that cannot check it. Nobody is asked.
	#[test]
	fn a_node_that_cannot_check_takes_no_source_off_the_list_by_itself() {
		let mut s = dependent(SessionMemory::default());
		s.set_candidates(list_of(&[A, B]), at(1));
		for secs in (1..600).step_by(10) {
			assert!(probes(&s.poll(at(secs))).is_empty(), "{}", secs);
		}
		assert_eq!(s.active(), None);
		assert_eq!(s.state(), SessionState::NoProvider);
		assert!(s.needs_owner_choice());
		assert!(!s.picks_by_itself());
		assert_eq!(s.memory().candidates, list_of(&[A, B]), "the list is there to choose from");
	}

	/// It is a choice the owner keeps, in every form it has.
	#[test]
	fn its_owner_can_choose_any_source_or_let_it_choose() {
		let mut s = dependent(SessionMemory::default());
		s.set_candidates(list_of(&[A, B]), at(1));
		s.set_pin(Some(B.into()), at(2));
		assert_eq!(s.active(), Some(B), "pin");
		assert!(!s.needs_owner_choice());

		let mut s = dependent(SessionMemory::default());
		s.set_candidates(list_of(&[A, B]), at(1));
		assert!(s.use_now(A.into(), at(2)), "for now");
		assert_eq!(s.active(), Some(A));

		let mut s = dependent(SessionMemory::default());
		s.set_candidates(list_of(&[A, B]), at(1));
		s.set_auto_source(Some(true), at(2));
		assert!(s.picks_by_itself());
		assert!(!s.needs_owner_choice());
		assert_eq!(probes(&s.poll(at(2))), vec![A.to_string()], "let it choose");
		assert!(s.take_dirty(), "saved");
	}

	#[test]
	fn a_source_it_was_given_is_kept_and_not_left_for_the_list() {
		let mut s = dependent(SessionMemory::default());
		s.set_candidates(list_of(&[A, B]), at(1));
		s.set_pin(Some(A.into()), at(2));
		s.on_probe(A, answered(), at(3));
		s.set_pin(None, at(4));
		assert_eq!(s.active(), Some(A), "it was chosen");
		s.set_candidates(list_of(&[B]), at(5));
		assert!(probes(&s.poll(at(6))).is_empty(), "off the list is no reason here");
		assert_eq!(s.active(), Some(A));
		assert_eq!(s.memory().last_good.as_deref(), Some(A));
	}

	/// When the chosen source dies, it does not fail over to a stranger: it asks that one again
	/// and says it needs the owner.
	#[test]
	fn a_chosen_source_dying_does_not_fail_over_to_a_stranger() {
		let mut s = dependent(SessionMemory::default());
		s.set_candidates(list_of(&[A, B]), at(1));
		assert!(s.use_now(A.into(), at(2)));
		s.poll(at(2));
		s.on_probe(A, answered(), at(3));
		let start = 4;
		s.on_probe(A, ProbeOutcome::Failed, at(start));
		for after in PROBE_RETRIES_AFTER {
			s.poll(at(start + after.as_secs()));
			s.on_probe(A, ProbeOutcome::Failed, at(start + after.as_secs()));
		}
		let gone = start + SUSPECT_FOR.as_secs();
		let actions = s.poll(at(gone));
		assert!(probes(&actions).is_empty(), "{:?}", actions);
		assert_eq!(s.active(), None);
		let again = gone + NO_PROVIDER_PROBE_INTERVAL.as_secs();
		assert_eq!(probes(&s.poll(at(again))), vec![A.to_string()], "the one it was given, alone");
		s.on_probe(A, ProbeOutcome::Failed, at(again));
		assert!(s.needs_owner_choice(), "the status says so");
	}

	/// A node that can check keeps choosing by itself; the owner can turn that off, for M3 too.
	#[test]
	fn a_node_that_can_check_picks_by_itself_until_told_not_to() {
		let memory = SessionMemory { candidates: list_of(&[A, B]), ..Default::default() };
		let mut s = ProviderSession::new(DeliveryPreference::Pull, memory, at(0));
		s.enable_cross_check(at(0));
		assert!(s.picks_by_itself());
		assert_eq!(probes(&s.poll(at(0))).len(), 1);
		s.on_probe(A, answered(), at(1));
		assert_eq!(s.active(), Some(A));

		s.set_auto_source(Some(false), at(2));
		assert!(!s.picks_by_itself());
		assert_eq!(s.active(), None, "what it found by itself it does not keep");
		assert_eq!(s.memory().last_good, None);
		assert!(s.needs_owner_choice());
		assert!(probes(&s.poll(at(3))).is_empty());
		s.set_auto_source(None, at(4));
		assert!(s.picks_by_itself(), "back to the default");
	}

	#[test]
	fn turning_it_off_leaves_what_the_owner_chose() {
		let memory = SessionMemory {
			candidates: list_of(&[A, B]),
			pinned: Some(B.into()),
			..Default::default()
		};
		let mut s = ProviderSession::new(DeliveryPreference::Push, memory, at(0));
		s.set_auto_source(Some(false), at(1));
		assert_eq!(s.active(), Some(B));
		assert!(!s.needs_owner_choice());
	}

	#[test]
	fn agreeing_does_not_clear_a_proof() {
		let mut s = checking(A);
		let first = CROSS_CHECK_FIRST_AFTER.as_secs();
		s.on_call_answered(A, at(first));
		let witness = check_at(&mut s, first, witness_lied());
		// An answer from a check already out when it was caught.
		s.on_cross_check(A, &witness, agreed(), at(first + 1));
		assert_eq!(s.memory().dropped.len(), 1);
		assert_eq!(s.memory().dropped[0].node_id, witness);
	}
}
