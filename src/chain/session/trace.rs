// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! What the provider session did, told as spans through one narrow seam.
//!
//! ```text
//!   ChainProviderSession ── SessionSpan ──► SessionObserver     (the embedding app's store)
//!            │
//!            └─ TraceScope, task-local ──► the provider's call   (the app stamps its route row)
//! ```
//!
//! The session knows nothing of where a span goes: no store, no gossip, no prices. Without an
//! observer it keeps nothing and [`current_scope`] answers `None`, so this ports to `node-chain`
//! as it stands.
//!
//! # One clock per trace
//!
//! The wall clock is read once, when a trace starts. Every bar in that trace is the monotonic time
//! since then, starts rounded down and ends rounded up to the millisecond: so no bar is negative,
//! a step of the wall clock during an outage moves nothing, and a span ended before its parent
//! stays inside it after rounding. [`TraceClock::continuing`] carries one trace's clock across a
//! boundary as "the trace started then, and this much has passed", which lags and never leads.
//!
//! # An activity with no natural end
//!
//! A span is told when it opens, with no duration, and again when it closes, so a reader during a
//! long Suspect sees it, and one left behind by a crash can be told from a finished one. A trace
//! still unsettled after [`TRACE_OPEN_MAX`] closes as `unsettled` and a new one continues it,
//! naming the old: an outage of days stays bounded per trace ([`MAX_SPANS_PER_TRACE`]).

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;

use super::machine::SessionState;
use super::Logged;

/// A trace still unsettled after this long is closed and continued by a new one.
pub const TRACE_OPEN_MAX: Duration = Duration::from_secs(60 * 60);

/// Spans one trace takes from the session, route calls included. The rest are counted, not kept.
/// An hour of outage with a probe a minute and ordinary calls fits.
pub const MAX_SPANS_PER_TRACE: u32 = 128;

/// How long a switch or a failover stays open once settled, so that the catch-up calls its move
/// sets off are in it. Shows as a gap at its end, and the root's detail says `settled_ms`.
pub const SETTLE_LINGER: Duration = Duration::from_secs(2);

/// A fee answer outside the bounds is told at most this often: one lying Pro answers many times.
pub const FEE_EVENT_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// An owner's or an app's move of the chain source.
pub const NAME_SWITCH: &str = "chain.session.switch";
/// From the failed probe that made a Pro suspect until the node is on a Pro again.
pub const NAME_FAILOVER: &str = "chain.session.failover";
/// A node with no source finding its first.
pub const NAME_FIND_SOURCE: &str = "chain.session.find_source";
/// A trace continuing one closed at [`TRACE_OPEN_MAX`].
pub const NAME_OUTAGE: &str = "chain.session.outage";
/// One `chain.since` asked to learn whether a Pro is alive.
pub const NAME_PROBE: &str = "chain.session.probe";
/// Asking for or renewing a lease.
pub const NAME_SUBSCRIBE: &str = "chain.session.subscribe";
/// Giving a lease up.
pub const NAME_RELEASE: &str = "chain.session.release";
/// The target every call goes to changed.
pub const NAME_RETARGET: &str = "chain.session.retarget";
/// Comparing filter headers with a second Pro.
pub const NAME_CROSS_CHECK: &str = "chain.session.cross_check";
/// A second Pro asked what it can show above this node's tip.
pub const NAME_TIP_CHECK: &str = "chain.session.tip_check";
/// A third Pro asked which of two it agrees with.
pub const NAME_TIE_BREAK: &str = "chain.session.tie_break";
/// A transaction handed to a Pro other than the active one.
pub const NAME_WITNESS_BROADCAST: &str = "chain.session.witness_broadcast";
/// A Pro other than the active one asked about this node's own transactions.
pub const NAME_OWN_TX_CHECK: &str = "chain.session.own_tx_check";
/// A block a Pro pushed, from taking it to every check on it passing: its filter hashes to the
/// filter header, its header carries its proof of work. A child of the inbound push.
pub const NAME_BLOCK_CHECK: &str = "chain.session.block_check";
/// The reply to a push being handed back. A child of the inbound push.
pub const NAME_BLOCK_ACK: &str = "chain.session.block_ack";
/// A Pro was dropped on evidence.
pub const NAME_SOURCE_DROPPED: &str = "chain.session.source_dropped";
/// A Pro's fee rates were outside the bounds.
pub const NAME_FEE_REJECTED: &str = "chain.session.fee_rejected";
/// The state span while a Pro is suspect.
pub const NAME_SUSPECT: &str = "chain.session.suspect";
/// The state span while a Pro counts as unreachable.
pub const NAME_UNREACHABLE: &str = "chain.session.unreachable";
/// The state span while nobody answers.
pub const NAME_NO_PROVIDER: &str = "chain.session.no_provider";

/// Which way a span faces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
	/// Another node, or a local caller, asked this one.
	Inbound,
	/// This node asked another.
	Outbound,
	/// Inside this node.
	Internal,
}

impl SpanKind {
	/// The stored name.
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Inbound => "inbound",
			Self::Outbound => "outbound",
			Self::Internal => "internal",
		}
	}
}

/// One span, as opened or as closed. The same `span_id` told again replaces what was told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSpan {
	/// The whole activity.
	pub trace_id: String,
	/// This span.
	pub span_id: String,
	/// The span it lies inside; `None` for a trace's root.
	pub parent_span_id: Option<String>,
	/// What happened.
	pub name: &'static str,
	/// Which way it faces.
	pub kind: SpanKind,
	/// The other node, if another node is involved.
	pub peer: Option<String>,
	/// When it started, in Unix milliseconds on its trace's clock.
	pub started_at_ms: i64,
	/// `None` while open.
	pub duration_ms: Option<i64>,
	/// Whether it did what it set out to do.
	pub ok: bool,
	/// Why not, as a short class.
	pub failure_class: Option<&'static str>,
	/// A little text for a human.
	pub detail: Option<String>,
}

/// Where the session's spans go. MUST NOT block and must not call back into the session: this
/// runs on the path of what it describes. A full queue drops and counts on the far side.
pub trait SessionObserver: Send + Sync {
	/// A span opened or closed.
	fn on_span(&self, span: SessionSpan);
}

/// A trace's one clock. See the module docs.
#[derive(Debug, Clone, Copy)]
pub struct TraceClock {
	anchor: Instant,
	anchor_wall_us: i64,
}

impl TraceClock {
	/// The clock of a trace starting now.
	pub fn starting_now() -> Self {
		let wall_ms =
			SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
		Self { anchor: Instant::now(), anchor_wall_us: wall_ms.saturating_mul(1000) }
	}

	/// The clock of a trace another part of this node started: at `started_at_ms`, with
	/// `elapsed_us` gone by when it was handed over. Lags the sender's by the handover.
	pub fn continuing(started_at_ms: i64, elapsed_us: u64) -> Self {
		let now = Instant::now();
		let anchor = now.checked_sub(Duration::from_micros(elapsed_us)).unwrap_or(now);
		Self { anchor, anchor_wall_us: started_at_ms.saturating_mul(1000) }
	}

	/// When this trace started, in Unix milliseconds.
	pub fn started_at_ms(&self) -> i64 {
		self.anchor_wall_us.div_euclid(1000)
	}

	/// How much of this trace has gone by.
	pub fn elapsed_us(&self) -> u64 {
		self.anchor.elapsed().as_micros() as u64
	}

	fn at_us(&self, at: Instant) -> i64 {
		self.anchor_wall_us
			.saturating_add(at.saturating_duration_since(self.anchor).as_micros() as i64)
	}

	/// `at`, for a span's start: rounded down.
	pub fn start_ms(&self, at: Instant) -> i64 {
		self.at_us(at).div_euclid(1000)
	}

	/// `at`, for a span's end: rounded up.
	pub fn end_ms(&self, at: Instant) -> i64 {
		(self.at_us(at) + 999).div_euclid(1000)
	}

	/// A bar: its start in Unix milliseconds and its duration. Never negative.
	pub fn bar(&self, started: Instant, ended: Instant) -> (i64, i64) {
		let start = self.start_ms(started);
		(start, (self.end_ms(ended) - start).max(0))
	}
}

/// A place in a trace: what a call made under it belongs to.
#[derive(Debug, Clone)]
pub struct TraceScope {
	/// The whole activity.
	pub trace_id: Arc<str>,
	/// The span the call lies inside.
	pub parent_span_id: Arc<str>,
	/// The trace's clock.
	pub clock: TraceClock,
}

tokio::task_local! {
	static SCOPE: TraceScope;
}

/// The place in a trace of the calling task, for a provider to stamp its call with. `None` when no
/// trace is under way.
pub fn current_scope() -> Option<TraceScope> {
	SCOPE.try_with(TraceScope::clone).ok()
}

/// Runs `call` at `scope`.
pub async fn scoped<F: Future>(scope: Option<TraceScope>, call: F) -> F::Output {
	match scope {
		Some(scope) => SCOPE.scope(scope, call).await,
		None => call.await,
	}
}

/// A new trace id: 32 hex.
pub fn new_trace_id() -> String {
	format!("{:032x}", rand::thread_rng().gen::<u128>())
}

/// A new span id: 16 hex.
pub fn new_span_id() -> String {
	format!("{:016x}", rand::thread_rng().gen::<u64>())
}

/// A trace another part of this node started, for the session to carry on. Its root span is the
/// session's to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceOrigin {
	/// The whole activity.
	pub trace_id: String,
	/// The id the root span is to have.
	pub root_span_id: String,
	/// When the trace started, in Unix milliseconds.
	pub started_at_ms: i64,
	/// How much of it had gone by when it was handed over.
	pub elapsed_us: u64,
}

/// A span under way, from [`Tracer::action`].
pub struct ActionSpan {
	trace_id: Arc<str>,
	span_id: Arc<str>,
	parent: Option<Arc<str>>,
	clock: TraceClock,
	name: &'static str,
	peer: Option<String>,
	started: Instant,
}

impl ActionSpan {
	/// What a call made as part of this span is to carry.
	pub fn scope(&self) -> TraceScope {
		TraceScope {
			trace_id: Arc::clone(&self.trace_id),
			parent_span_id: Arc::clone(&self.span_id),
			clock: self.clock,
		}
	}
}

/// The row of an inbound call another part of this node keeps, for what the session does about it to
/// lie under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSpan {
	/// Its trace.
	pub trace_id: String,
	/// Its span.
	pub span_id: String,
}

/// What a finished span says.
pub(crate) struct SpanEnd {
	pub(crate) ok: bool,
	pub(crate) failure_class: Option<&'static str>,
	pub(crate) detail: Option<String>,
}

impl SpanEnd {
	pub(crate) fn ok(detail: Option<String>) -> Self {
		Self { ok: true, failure_class: None, detail }
	}

	pub(crate) fn failed(failure_class: &'static str, detail: Option<String>) -> Self {
		Self { ok: false, failure_class: Some(failure_class), detail }
	}
}

/// What turns session changes into spans. See the module docs.
#[derive(Default)]
pub(crate) struct Tracer {
	observer: RwLock<Option<Arc<dyn SessionObserver>>>,
	state: Mutex<TracerState>,
}

#[derive(Default)]
struct TracerState {
	current: Option<Activity>,
	last_fee_event: Option<Instant>,
}

struct Activity {
	trace_id: Arc<str>,
	root: Arc<str>,
	clock: TraceClock,
	name: &'static str,
	peer: Option<String>,
	started: Instant,
	opened: Instant,
	state_span: Option<ActionSpan>,
	in_flight: u32,
	last_action: Instant,
	settled_at: Option<Instant>,
	spans: u32,
	spans_over: u32,
	linger: Duration,
	from: Option<String>,
	to: Option<String>,
	outcome: Option<&'static str>,
	continues: Option<String>,
	/// A trace of one action says at its root how that action went.
	lone_failure: Option<&'static str>,
}

impl Tracer {
	fn observer(&self) -> Option<Arc<dyn SessionObserver>> {
		self.observer.read().unwrap_or_else(|e| e.into_inner()).clone()
	}

	fn state(&self) -> MutexGuard<'_, TracerState> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// Where spans go from now on.
	pub(crate) fn set_observer(&self, observer: Arc<dyn SessionObserver>) {
		*self.observer.write().unwrap_or_else(|e| e.into_inner()) = Some(observer);
	}

	/// A move of the source was asked for. `true` when its root span is now the session's to
	/// write. An activity under way is closed: this one takes over.
	pub(crate) fn begin_switch(&self, origin: Option<TraceOrigin>, target: Option<&str>) -> bool {
		let Some(observer) = self.observer() else { return false };
		let now = Instant::now();
		let mut state = self.state();
		if let Some(old) = state.current.take() {
			close_activity(&*observer, old, now, Close::Superseded);
		}
		let activity = match origin {
			Some(origin) => {
				let clock = TraceClock::continuing(origin.started_at_ms, origin.elapsed_us);
				new_activity(
					Some((origin.trace_id.as_str().into(), origin.root_span_id.as_str().into())),
					clock,
					clock.anchor,
					NAME_SWITCH,
					target,
					SETTLE_LINGER,
					now,
				)
			},
			None => new_activity(
				None,
				TraceClock::starting_now(),
				now,
				NAME_SWITCH,
				target,
				SETTLE_LINGER,
				now,
			),
		};
		emit_root(&*observer, &activity);
		state.current = Some(activity);
		true
	}

	/// The session's state, delivery or target changed.
	pub(super) fn on_change(&self, prev: &Logged, next: &Logged) {
		let Some(observer) = self.observer() else { return };
		let active_changed = prev.active != next.active;
		let state_changed = prev.state != next.state;
		if !active_changed && !state_changed {
			return;
		}
		let now = Instant::now();
		let mut state = self.state();
		let long_lived = state.current.as_ref().map_or(false, |a| !a.linger.is_zero());
		let wanted = match next.state {
			SessionState::Suspect | SessionState::Unreachable => Some(NAME_FAILOVER),
			SessionState::NoProvider if prev.active.is_some() => Some(NAME_FAILOVER),
			SessionState::NoProvider => None,
			SessionState::Active if !active_changed => None,
			SessionState::Active if prev.active.is_none() && !long_lived => Some(NAME_FIND_SOURCE),
			SessionState::Active => Some(NAME_SWITCH),
		};
		if let Some(name) = wanted {
			let peer = next.active.as_deref().or(prev.active.as_deref());
			upgrade(&*observer, &mut state, name, peer, now);
		}
		let Some(activity) = state.current.as_mut() else { return };
		activity.last_action = now;
		if activity.from.is_none() {
			activity.from.clone_from(&prev.active);
		}
		activity.to.clone_from(&next.active);
		let recovered = !active_changed
			&& prev.state != SessionState::Active
			&& next.state == SessionState::Active;
		activity.outcome = Some(match next.state {
			SessionState::Active if recovered => "recovered",
			SessionState::Active => "moved",
			SessionState::Suspect => "suspect",
			SessionState::Unreachable => "unreachable",
			SessionState::NoProvider => "no_provider",
		});
		activity.settled_at =
			if next.state == SessionState::Active { Some(now) } else { None };
		if state_changed {
			if let Some(span) = activity.state_span.take() {
				let end = if recovered {
					SpanEnd::ok(Some("answered again".to_string()))
				} else {
					SpanEnd::failed(state_class(span.name), None)
				};
				emit_end(&*observer, &span, end, now);
			}
			let name = match next.state {
				SessionState::Suspect => Some(NAME_SUSPECT),
				SessionState::Unreachable => Some(NAME_UNREACHABLE),
				SessionState::NoProvider => Some(NAME_NO_PROVIDER),
				SessionState::Active => None,
			};
			if let Some(name) = name {
				let peer = next.active.clone().or_else(|| prev.active.clone());
				let span = ActionSpan {
					trace_id: Arc::clone(&activity.trace_id),
					span_id: new_span_id().into(),
					parent: Some(Arc::clone(&activity.root)),
					clock: activity.clock,
					name,
					peer,
					started: now,
				};
				emit_open(&*observer, &span);
				activity.state_span = Some(span);
			}
		}
	}

	/// An action starts: a span in the activity under way, or else a trace of its own. `None`
	/// with no observer, or over the cap.
	pub(crate) fn action(&self, name: &'static str, peer: &str) -> Option<ActionSpan> {
		let observer = self.observer()?;
		let now = Instant::now();
		let mut state = self.state();
		if state.current.is_none() {
			let activity = new_activity(
				None,
				TraceClock::starting_now(),
				now,
				name,
				Some(peer),
				Duration::ZERO,
				now,
			);
			emit_root(&*observer, &activity);
			state.current = Some(activity);
		}
		let activity = state.current.as_mut()?;
		if activity.spans >= MAX_SPANS_PER_TRACE {
			activity.spans_over = activity.spans_over.saturating_add(1);
			return None;
		}
		activity.spans += 1;
		activity.in_flight += 1;
		activity.last_action = now;
		let span = ActionSpan {
			trace_id: Arc::clone(&activity.trace_id),
			span_id: new_span_id().into(),
			parent: Some(
				activity
					.state_span
					.as_ref()
					.map_or_else(|| Arc::clone(&activity.root), |s| Arc::clone(&s.span_id)),
			),
			clock: activity.clock,
			name,
			peer: Some(peer.to_string()),
			started: now,
		};
		emit_open(&*observer, &span);
		Some(span)
	}

	/// A trace of its own beside whatever is under way: a cross-check.
	pub(crate) fn standalone(&self, name: &'static str, peer: &str) -> Option<ActionSpan> {
		let observer = self.observer()?;
		let clock = TraceClock::starting_now();
		let span = ActionSpan {
			trace_id: new_trace_id().into(),
			span_id: new_span_id().into(),
			parent: None,
			clock,
			name,
			peer: Some(peer.to_string()),
			started: clock.anchor,
		};
		emit_open(&*observer, &span);
		Some(span)
	}

	/// An action or a standalone trace ended.
	pub(crate) fn finish(&self, span: Option<ActionSpan>, end: SpanEnd) {
		let (Some(span), Some(observer)) = (span, self.observer()) else { return };
		let now = Instant::now();
		let failure = if end.ok { None } else { end.failure_class };
		emit_end(&*observer, &span, end, now);
		let mut state = self.state();
		let mine = state.current.as_ref().map_or(false, |a| a.trace_id == span.trace_id);
		if !mine || span.parent.is_none() {
			return;
		}
		let done = {
			let Some(activity) = state.current.as_mut() else { return };
			activity.in_flight = activity.in_flight.saturating_sub(1);
			activity.last_action = now;
			if activity.linger.is_zero() && failure.is_some() {
				activity.lone_failure = failure;
			}
			activity.linger.is_zero() && activity.in_flight == 0
		};
		if done {
			if let Some(activity) = state.current.take() {
				close_activity(&*observer, activity, now, Close::Settled);
			}
		}
	}

	/// Where an ordinary call belongs: the root of a switch or a failover under way, within the
	/// cap. A lone probe's trace takes only the probe.
	pub(crate) fn ordinary_scope(&self) -> Option<TraceScope> {
		self.observer.read().unwrap_or_else(|e| e.into_inner()).as_ref()?;
		let mut state = self.state();
		let activity = state.current.as_mut().filter(|a| !a.linger.is_zero())?;
		if activity.spans >= MAX_SPANS_PER_TRACE {
			activity.spans_over = activity.spans_over.saturating_add(1);
			return None;
		}
		activity.spans += 1;
		Some(TraceScope {
			trace_id: Arc::clone(&activity.trace_id),
			parent_span_id: Arc::clone(&activity.root),
			clock: activity.clock,
		})
	}

	/// A span under a row another part of this node keeps: an inbound call, whose trace it is.
	pub(crate) fn under_inbound(
		&self, name: &'static str, peer: &str, inbound: &InboundSpan,
	) -> Option<ActionSpan> {
		self.observer()?;
		let clock = TraceClock::starting_now();
		Some(ActionSpan {
			trace_id: inbound.trace_id.as_str().into(),
			span_id: new_span_id().into(),
			parent: Some(inbound.span_id.as_str().into()),
			clock,
			name,
			peer: Some(peer.to_string()),
			started: clock.anchor,
		})
	}

	/// A Pro was dropped on evidence: under the root of the move that follows, while one is under
	/// way, within its cap. A witness dropped moves nothing, and is a trace of its own.
	pub(crate) fn source_dropped(&self, peer: &str, detail: String) {
		let Some(observer) = self.observer() else { return };
		let now = Instant::now();
		let span = {
			let mut state = self.state();
			match state.current.as_mut().filter(|a| a.spans < MAX_SPANS_PER_TRACE) {
				Some(activity) => {
					activity.spans += 1;
					ActionSpan {
						trace_id: Arc::clone(&activity.trace_id),
						span_id: new_span_id().into(),
						parent: Some(Arc::clone(&activity.root)),
						clock: activity.clock,
						name: NAME_SOURCE_DROPPED,
						peer: Some(peer.to_string()),
						started: now,
					}
				},
				None => {
					let clock = TraceClock::starting_now();
					ActionSpan {
						trace_id: new_trace_id().into(),
						span_id: new_span_id().into(),
						parent: None,
						clock,
						name: NAME_SOURCE_DROPPED,
						peer: Some(peer.to_string()),
						started: clock.anchor,
					}
				},
			}
		};
		emit_end(&*observer, &span, SpanEnd::ok(Some(detail)), now);
	}

	/// Something happened at one moment, in the activity under way. Nothing with none.
	pub(crate) fn mark(&self, name: &'static str, peer: Option<&str>, detail: Option<String>) {
		let Some(observer) = self.observer() else { return };
		let now = Instant::now();
		let mut state = self.state();
		let Some(activity) = state.current.as_mut() else { return };
		activity.spans = activity.spans.saturating_add(1);
		let span = ActionSpan {
			trace_id: Arc::clone(&activity.trace_id),
			span_id: new_span_id().into(),
			parent: Some(
				activity
					.state_span
					.as_ref()
					.map_or_else(|| Arc::clone(&activity.root), |s| Arc::clone(&s.span_id)),
			),
			clock: activity.clock,
			name,
			peer: peer.map(str::to_string),
			started: now,
		};
		emit_end(&*observer, &span, SpanEnd::ok(detail), now);
	}

	/// A Pro's fee answer was outside the bounds: a trace of its own, at most once in
	/// [`FEE_EVENT_MIN_INTERVAL`].
	pub(crate) fn fee_rejected(&self, peer: &str, detail: String, now: Instant) {
		let Some(observer) = self.observer() else { return };
		{
			let mut state = self.state();
			let recent = state.last_fee_event.map_or(false, |at| {
				now.saturating_duration_since(at) < FEE_EVENT_MIN_INTERVAL
			});
			if recent {
				return;
			}
			state.last_fee_event = Some(now);
		}
		let clock = TraceClock::starting_now();
		let span = ActionSpan {
			trace_id: new_trace_id().into(),
			span_id: new_span_id().into(),
			parent: None,
			clock,
			name: NAME_FEE_REJECTED,
			peer: Some(peer.to_string()),
			started: clock.anchor,
		};
		emit_end(
			&*observer,
			&span,
			SpanEnd::failed("fee_out_of_bounds", Some(detail)),
			clock.anchor,
		);
	}

	/// The driver's look at what is due: an activity settled, or one open too long.
	pub(crate) fn tick(&self, state_now: SessionState, now: Instant) {
		let Some(observer) = self.observer() else { return };
		let mut state = self.state();
		let Some(activity) = state.current.as_ref() else { return };
		if state_now == SessionState::Active {
			if activity.in_flight == 0
				&& now.saturating_duration_since(activity.last_action) >= activity.linger
			{
				if let Some(activity) = state.current.take() {
					close_activity(&*observer, activity, now, Close::Settled);
				}
			}
			return;
		}
		if now.saturating_duration_since(activity.opened) < TRACE_OPEN_MAX {
			return;
		}
		let Some(old) = state.current.take() else { return };
		let continues = old.trace_id.to_string();
		let peer = old.peer.clone();
		let from = old.from.clone();
		let state_name = old.state_span.as_ref().map(|s| (s.name, s.peer.clone()));
		close_activity(&*observer, old, now, Close::Unsettled);
		let mut next = new_activity(
			None,
			TraceClock::starting_now(),
			now,
			NAME_OUTAGE,
			peer.as_deref(),
			SETTLE_LINGER,
			now,
		);
		next.continues = Some(continues);
		next.from = from;
		emit_root(&*observer, &next);
		if let Some((name, peer)) = state_name {
			let span = ActionSpan {
				trace_id: Arc::clone(&next.trace_id),
				span_id: new_span_id().into(),
				parent: Some(Arc::clone(&next.root)),
				clock: next.clock,
				name,
				peer,
				started: now,
			};
			emit_open(&*observer, &span);
			next.state_span = Some(span);
		}
		state.current = Some(next);
	}
}

fn state_class(name: &'static str) -> &'static str {
	match name {
		NAME_SUSPECT => "suspect",
		NAME_UNREACHABLE => "unreachable",
		_ => "no_provider",
	}
}

fn new_activity(
	ids: Option<(Arc<str>, Arc<str>)>, clock: TraceClock, started: Instant, name: &'static str,
	peer: Option<&str>, linger: Duration, now: Instant,
) -> Activity {
	let (trace_id, root) =
		ids.unwrap_or_else(|| (new_trace_id().into(), new_span_id().into()));
	Activity {
		trace_id,
		root,
		clock,
		name,
		peer: peer.map(str::to_string),
		started,
		opened: now,
		state_span: None,
		in_flight: 0,
		last_action: now,
		settled_at: None,
		spans: 0,
		spans_over: 0,
		linger,
		from: None,
		to: None,
		outcome: None,
		continues: None,
		lone_failure: None,
	}
}

/// The activity under way becomes `name`, unless it is already a long one: a lone probe that
/// failed is how a failover starts. With none, one starts.
fn upgrade(
	observer: &dyn SessionObserver, state: &mut TracerState, name: &'static str,
	peer: Option<&str>, now: Instant,
) {
	match state.current.as_mut() {
		Some(activity) if !activity.linger.is_zero() => {},
		Some(activity) => {
			activity.name = name;
			activity.linger = SETTLE_LINGER;
			emit_root(observer, activity);
		},
		None => {
			let activity = new_activity(
				None,
				TraceClock::starting_now(),
				now,
				name,
				peer,
				SETTLE_LINGER,
				now,
			);
			emit_root(observer, &activity);
			state.current = Some(activity);
		},
	}
}

enum Close {
	Settled,
	Superseded,
	Unsettled,
}

fn close_activity(observer: &dyn SessionObserver, mut activity: Activity, now: Instant, how: Close) {
	if let Some(span) = activity.state_span.take() {
		let class = state_class(span.name);
		emit_end(observer, &span, SpanEnd::failed(class, None), now);
	}
	let mut parts: Vec<String> = Vec::new();
	let outcome = match how {
		Close::Settled => activity.outcome.unwrap_or("done"),
		Close::Superseded => "superseded",
		Close::Unsettled => "unsettled",
	};
	parts.push(format!("outcome={}", outcome));
	if let Some(from) = &activity.from {
		parts.push(format!("from={}", from));
	}
	if let Some(to) = &activity.to {
		parts.push(format!("to={}", to));
	}
	if let Some(at) = activity.settled_at {
		let ms = at.saturating_duration_since(activity.started).as_millis();
		parts.push(format!("settled_ms={}", ms));
	}
	if let Some(old) = &activity.continues {
		parts.push(format!("continues={}", old));
	}
	if activity.spans_over > 0 {
		parts.push(format!("spans_over_cap={}", activity.spans_over));
	}
	let (start, duration) = activity.clock.bar(activity.started, now);
	let end = match how {
		Close::Unsettled => (false, Some("unsettled")),
		Close::Settled if activity.lone_failure.is_some() => (false, activity.lone_failure),
		Close::Settled | Close::Superseded => (true, None),
	};
	observer.on_span(SessionSpan {
		trace_id: activity.trace_id.to_string(),
		span_id: activity.root.to_string(),
		parent_span_id: None,
		name: activity.name,
		kind: SpanKind::Internal,
		peer: activity.peer.clone(),
		started_at_ms: start,
		duration_ms: Some(duration),
		ok: end.0,
		failure_class: end.1,
		detail: Some(parts.join(" ")),
	});
}

fn emit_root(observer: &dyn SessionObserver, activity: &Activity) {
	observer.on_span(SessionSpan {
		trace_id: activity.trace_id.to_string(),
		span_id: activity.root.to_string(),
		parent_span_id: None,
		name: activity.name,
		kind: SpanKind::Internal,
		peer: activity.peer.clone(),
		started_at_ms: activity.clock.start_ms(activity.started),
		duration_ms: None,
		ok: true,
		failure_class: None,
		detail: None,
	});
}

fn emit_open(observer: &dyn SessionObserver, span: &ActionSpan) {
	observer.on_span(SessionSpan {
		trace_id: span.trace_id.to_string(),
		span_id: span.span_id.to_string(),
		parent_span_id: span.parent.as_ref().map(|p| p.to_string()),
		name: span.name,
		kind: kind_of(span.name),
		peer: span.peer.clone(),
		started_at_ms: span.clock.start_ms(span.started),
		duration_ms: None,
		ok: true,
		failure_class: None,
		detail: None,
	});
}

fn emit_end(observer: &dyn SessionObserver, span: &ActionSpan, end: SpanEnd, now: Instant) {
	let (start, duration) = span.clock.bar(span.started, now);
	observer.on_span(SessionSpan {
		trace_id: span.trace_id.to_string(),
		span_id: span.span_id.to_string(),
		parent_span_id: span.parent.as_ref().map(|p| p.to_string()),
		name: span.name,
		kind: kind_of(span.name),
		peer: span.peer.clone(),
		started_at_ms: start,
		duration_ms: Some(duration),
		ok: end.ok,
		failure_class: end.failure_class,
		detail: end.detail,
	});
}

fn kind_of(name: &'static str) -> SpanKind {
	match name {
		NAME_PROBE | NAME_SUBSCRIBE | NAME_RELEASE | NAME_CROSS_CHECK | NAME_TIP_CHECK
		| NAME_TIE_BREAK | NAME_WITNESS_BROADCAST | NAME_OWN_TX_CHECK | NAME_BLOCK_ACK => {
			SpanKind::Outbound
		},
		_ => SpanKind::Internal,
	}
}

#[cfg(test)]
pub(crate) mod test_support {
	use super::*;

	/// An observer that keeps everything told, in order.
	#[derive(Default)]
	pub(crate) struct Kept(pub(crate) Mutex<Vec<SessionSpan>>);

	impl SessionObserver for Kept {
		fn on_span(&self, span: SessionSpan) {
			self.0.lock().unwrap().push(span);
		}
	}

	impl Kept {
		/// The last word on each span, in the order first told.
		pub(crate) fn spans(&self) -> Vec<SessionSpan> {
			let told = self.0.lock().unwrap();
			let mut spans: Vec<SessionSpan> = Vec::new();
			for span in told.iter() {
				match spans.iter_mut().find(|s| s.span_id == span.span_id) {
					Some(known) => *known = span.clone(),
					None => spans.push(span.clone()),
				}
			}
			spans
		}

		pub(crate) fn named(&self, name: &str) -> Vec<SessionSpan> {
			self.spans().into_iter().filter(|s| s.name == name).collect()
		}
	}

	/// The rule the waterfall rests on: one root, every other span's parent is here, and a closed
	/// child lies inside a closed parent.
	pub(crate) fn assert_nested(spans: &[SessionSpan]) {
		let roots: Vec<_> = spans.iter().filter(|s| s.parent_span_id.is_none()).collect();
		assert_eq!(roots.len(), 1, "one root: {:?}", spans);
		for span in spans {
			assert_eq!(span.trace_id, roots[0].trace_id, "one trace: {:?}", span);
			let Some(parent) = &span.parent_span_id else { continue };
			let parent = spans
				.iter()
				.find(|s| &s.span_id == parent)
				.unwrap_or_else(|| panic!("no parent for {:?}", span));
			assert!(span.started_at_ms >= parent.started_at_ms, "{:?} starts before {:?}", span, parent);
			if let (Some(child), Some(outer)) = (span.duration_ms, parent.duration_ms) {
				assert!(child >= 0);
				assert!(
					span.started_at_ms + child <= parent.started_at_ms + outer,
					"{:?} ends after {:?}",
					span,
					parent
				);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::test_support::*;
	use super::*;

	fn logged(state: SessionState, active: Option<&str>) -> Logged {
		Logged {
			state,
			delivery: super::super::Delivery::Pull,
			active: active.map(str::to_string),
		}
	}

	fn tracer() -> (Tracer, Arc<Kept>) {
		let tracer = Tracer::default();
		let kept = Arc::new(Kept::default());
		tracer.set_observer(Arc::clone(&kept) as Arc<dyn SessionObserver>);
		(tracer, kept)
	}

	const A: &str = "02aa";
	const B: &str = "02bb";

	#[test]
	fn a_bar_cannot_go_negative_and_rounding_keeps_a_child_inside_its_parent() {
		let clock = TraceClock::starting_now();
		let start = Instant::now();
		// A span "ended" before it started, as a confused caller could say.
		let (_, duration) = clock.bar(start + Duration::from_secs(1), start);
		assert_eq!(duration, 0);
		let parent_start = start;
		let child_start = start + Duration::from_micros(1_100);
		let child_end = start + Duration::from_micros(1_200);
		let parent_end = start + Duration::from_micros(1_250);
		let parent = clock.bar(parent_start, parent_end);
		let child = clock.bar(child_start, child_end);
		assert!(child.0 >= parent.0);
		assert!(child.0 + child.1 <= parent.0 + parent.1);
		assert!(child.1 >= 1, "work under a millisecond still shows: {:?}", child);
	}

	#[test]
	fn a_clock_handed_over_lags_and_never_leads() {
		let origin = TraceClock::starting_now();
		std::thread::sleep(Duration::from_millis(5));
		let handed = TraceClock::continuing(origin.started_at_ms(), origin.elapsed_us());
		let now = Instant::now();
		assert_eq!(handed.started_at_ms(), origin.started_at_ms());
		assert!(handed.end_ms(now) <= origin.end_ms(now));
		assert!(handed.start_ms(now) + 2 >= origin.start_ms(now), "it lags by the handover only");
	}

	#[test]
	fn the_wall_clock_is_read_once_so_a_step_of_it_moves_no_bar() {
		// Nothing about a span's place reads the wall clock after the trace started.
		let clock = TraceClock::continuing(1_000_000, 0);
		let at = clock.anchor + Duration::from_millis(250);
		assert_eq!(clock.start_ms(at), 1_000_250);
		assert_eq!(clock.end_ms(at), 1_000_250);
	}

	#[test]
	fn with_no_observer_nothing_is_started_and_no_call_carries_a_trace() {
		let tracer = Tracer::default();
		assert!(!tracer.begin_switch(None, Some(A)));
		assert!(tracer.action(NAME_PROBE, A).is_none());
		assert!(tracer.ordinary_scope().is_none());
	}

	#[test]
	fn a_lone_probe_that_answers_is_a_trace_of_its_own_and_takes_no_other_call() {
		let (tracer, kept) = tracer();
		let probe = tracer.action(NAME_PROBE, A);
		assert!(tracer.ordinary_scope().is_none());
		tracer.finish(probe, SpanEnd::ok(None));
		let spans = kept.spans();
		assert_eq!(spans.len(), 2, "{:?}", spans);
		assert_nested(&spans);
		assert!(spans.iter().all(|s| s.duration_ms.is_some()));
		assert!(tracer.ordinary_scope().is_none(), "it is over");
	}

	#[test]
	fn a_lone_action_that_fails_says_so_at_its_root() {
		let (tracer, kept) = tracer();
		let probe = tracer.action(NAME_PROBE, A);
		tracer.finish(probe, SpanEnd::failed("probe_unsupported", None));
		let root = kept.spans().into_iter().find(|s| s.parent_span_id.is_none()).unwrap();
		assert!(!root.ok);
		assert_eq!(root.failure_class, Some("probe_unsupported"));
	}

	#[test]
	fn a_failed_probe_becomes_the_failover_and_all_of_it_is_one_trace() {
		let (tracer, kept) = tracer();
		let first = tracer.action(NAME_PROBE, A);
		let trace_id = first.as_ref().unwrap().scope().trace_id.to_string();
		tracer.on_change(&logged(SessionState::Active, Some(A)), &logged(SessionState::Suspect, Some(A)));
		tracer.finish(first, SpanEnd::failed("probe_failed", Some("nobody".into())));

		let retry = tracer.action(NAME_PROBE, A).unwrap();
		assert_eq!(retry.scope().trace_id.as_ref(), trace_id);
		let suspect = kept.named(NAME_SUSPECT);
		assert_eq!(suspect.len(), 1);
		assert_eq!(suspect[0].duration_ms, None, "stored open while it lasts");
		assert_eq!(retry.parent.as_deref(), Some(suspect[0].span_id.as_str()), "under the state");
		let tip_poll = tracer.ordinary_scope().unwrap();
		assert_eq!(tip_poll.trace_id.as_ref(), trace_id, "an ordinary call in the outage is in it");
		tracer.finish(Some(retry), SpanEnd::failed("probe_failed", None));

		tracer.on_change(&logged(SessionState::Suspect, Some(A)), &logged(SessionState::Unreachable, Some(A)));
		let walk = tracer.action(NAME_PROBE, B);
		tracer.on_change(&logged(SessionState::Unreachable, Some(A)), &logged(SessionState::Active, Some(B)));
		tracer.finish(walk, SpanEnd::ok(None));
		tracer.mark(NAME_RETARGET, Some(B), None);
		let lease = tracer.action(NAME_SUBSCRIBE, B);
		tracer.finish(lease, SpanEnd::ok(None));
		tracer.tick(SessionState::Active, Instant::now() + SETTLE_LINGER + Duration::from_millis(1));

		let spans = kept.spans();
		assert_nested(&spans);
		let root = spans.iter().find(|s| s.parent_span_id.is_none()).unwrap();
		assert_eq!(root.name, NAME_FAILOVER, "the probe's trace became the failover");
		assert!(root.ok);
		let detail = root.detail.clone().unwrap();
		assert!(detail.contains("outcome=moved"), "{}", detail);
		assert!(detail.contains(&format!("from={} to={}", A, B)), "{}", detail);
		assert!(detail.contains("settled_ms="), "{}", detail);
		assert_eq!(kept.named(NAME_PROBE).len(), 3);
		assert!(spans.iter().all(|s| s.duration_ms.is_some()), "nothing left open: {:?}", spans);
		assert_eq!(kept.named(NAME_SUSPECT)[0].failure_class, Some("suspect"));
	}

	#[test]
	fn a_suspect_that_answers_again_closes_as_recovered() {
		let (tracer, kept) = tracer();
		let probe = tracer.action(NAME_PROBE, A);
		tracer.on_change(&logged(SessionState::Active, Some(A)), &logged(SessionState::Suspect, Some(A)));
		tracer.finish(probe, SpanEnd::failed("probe_failed", None));
		tracer.on_change(&logged(SessionState::Suspect, Some(A)), &logged(SessionState::Active, Some(A)));
		tracer.tick(SessionState::Active, Instant::now() + SETTLE_LINGER + Duration::from_millis(1));
		let spans = kept.spans();
		assert_nested(&spans);
		let root = spans.iter().find(|s| s.parent_span_id.is_none()).unwrap();
		assert!(root.detail.clone().unwrap().contains("outcome=recovered"));
		assert!(kept.named(NAME_SUSPECT)[0].ok);
	}

	#[test]
	fn an_activity_with_no_end_is_closed_as_unsettled_and_continued_by_a_new_trace_naming_it() {
		let (tracer, kept) = tracer();
		let probe = tracer.action(NAME_PROBE, A);
		let first_trace = probe.as_ref().unwrap().scope().trace_id.to_string();
		tracer.on_change(&logged(SessionState::Active, Some(A)), &logged(SessionState::Suspect, Some(A)));
		tracer.finish(probe, SpanEnd::failed("probe_failed", None));
		tracer.on_change(&logged(SessionState::Suspect, Some(A)), &logged(SessionState::Unreachable, Some(A)));

		tracer.tick(SessionState::Unreachable, Instant::now() + TRACE_OPEN_MAX / 2);
		assert!(kept.spans().iter().any(|s| s.parent_span_id.is_none() && s.duration_ms.is_none()));

		tracer.tick(SessionState::Unreachable, Instant::now() + TRACE_OPEN_MAX);
		let spans = kept.spans();
		let closed = spans.iter().find(|s| s.trace_id == first_trace && s.parent_span_id.is_none()).unwrap();
		assert_eq!(closed.failure_class, Some("unsettled"));
		assert!(closed.duration_ms.is_some());
		let next = spans.iter().find(|s| s.name == NAME_OUTAGE).unwrap();
		assert_ne!(next.trace_id, first_trace);
		assert_eq!(next.duration_ms, None);
		assert!(spans.iter().filter(|s| s.trace_id == next.trace_id).any(|s| s.name == NAME_UNREACHABLE && s.duration_ms.is_none()));

		tracer.on_change(&logged(SessionState::Unreachable, Some(A)), &logged(SessionState::Active, Some(B)));
		tracer.tick(SessionState::Active, Instant::now() + TRACE_OPEN_MAX * 2);
		let spans = kept.spans();
		let done = spans.iter().find(|s| s.name == NAME_OUTAGE).unwrap();
		assert!(done.detail.clone().unwrap().contains(&format!("continues={}", first_trace)));
		assert!(done.duration_ms.is_some());
	}

	#[test]
	fn a_trace_stops_taking_spans_at_the_cap_and_says_how_many_it_left_out() {
		let (tracer, kept) = tracer();
		assert!(tracer.begin_switch(None, Some(A)));
		for _ in 0..MAX_SPANS_PER_TRACE {
			assert!(tracer.ordinary_scope().is_some());
		}
		assert!(tracer.ordinary_scope().is_none());
		assert!(tracer.action(NAME_PROBE, A).is_none());
		tracer.tick(SessionState::Active, Instant::now() + SETTLE_LINGER + Duration::from_millis(1));
		let root = kept.spans().into_iter().find(|s| s.name == NAME_SWITCH).unwrap();
		assert!(root.detail.unwrap().contains("spans_over_cap=2"));
	}

	#[test]
	fn an_owners_switch_supersedes_what_is_under_way_and_continues_the_trace_it_was_given() {
		let (tracer, kept) = tracer();
		let probe = tracer.action(NAME_PROBE, A);
		let old = probe.as_ref().unwrap().scope().trace_id.to_string();
		let origin = TraceClock::starting_now();
		std::thread::sleep(Duration::from_millis(3));
		let given = TraceOrigin {
			trace_id: "ab".repeat(16),
			root_span_id: "cd".repeat(8),
			started_at_ms: origin.started_at_ms(),
			elapsed_us: origin.elapsed_us(),
		};
		assert!(tracer.begin_switch(Some(given.clone()), Some(B)));
		tracer.finish(probe, SpanEnd::ok(None));
		let lease = tracer.action(NAME_SUBSCRIBE, B).unwrap();
		assert_eq!(lease.scope().trace_id.as_ref(), given.trace_id);
		assert_eq!(lease.parent.as_deref(), Some(given.root_span_id.as_str()));
		tracer.finish(Some(lease), SpanEnd::ok(None));
		tracer.tick(SessionState::Active, Instant::now() + SETTLE_LINGER + Duration::from_millis(1));
		let spans = kept.spans();
		let superseded = spans.iter().find(|s| s.trace_id == old && s.parent_span_id.is_none()).unwrap();
		assert!(superseded.detail.clone().unwrap().contains("outcome=superseded"));
		let root = spans.iter().find(|s| s.span_id == given.root_span_id).unwrap();
		assert_eq!(root.started_at_ms, given.started_at_ms, "offset 0 is when the owner asked");
		assert_eq!(root.name, NAME_SWITCH);
		let this: Vec<_> = spans.into_iter().filter(|s| s.trace_id == given.trace_id).collect();
		assert_nested(&this);
	}

	#[test]
	fn a_fee_answer_out_of_bounds_is_told_once_a_minute() {
		let (tracer, kept) = tracer();
		let now = Instant::now();
		tracer.fee_rejected(A, "onchain 9".into(), now);
		tracer.fee_rejected(A, "onchain 9".into(), now + Duration::from_secs(59));
		assert_eq!(kept.named(NAME_FEE_REJECTED).len(), 1);
		tracer.fee_rejected(A, "onchain 9".into(), now + FEE_EVENT_MIN_INTERVAL);
		let told = kept.named(NAME_FEE_REJECTED);
		assert_eq!(told.len(), 2);
		assert_eq!(told[0].failure_class, Some("fee_out_of_bounds"));
		assert!(!told[0].ok);
	}

	#[test]
	fn ids_have_the_shape_the_store_admits() {
		assert_eq!(new_trace_id().len(), 32);
		assert_eq!(new_span_id().len(), 16);
		assert!(new_trace_id().bytes().all(|b| b.is_ascii_hexdigit()));
		assert_ne!(new_trace_id(), new_trace_id());
	}

	#[tokio::test]
	async fn a_scope_reaches_the_call_under_it_and_ends_with_it() {
		assert!(current_scope().is_none());
		let (tracer, _kept) = tracer();
		let probe = tracer.action(NAME_PROBE, A).unwrap();
		let want = probe.scope();
		let seen = scoped(Some(want.clone()), async { current_scope() }).await.unwrap();
		assert_eq!(seen.trace_id, want.trace_id);
		assert_eq!(seen.parent_span_id, want.parent_span_id);
		assert!(current_scope().is_none());
	}
}
