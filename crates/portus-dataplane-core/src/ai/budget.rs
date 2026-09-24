//! Token budgets on the request path: a shared counter, synced.
//!
//! Every pod keeps, per (policy, subject), the window's global spend as of
//! its last sync plus what it has spent and reserved locally since. A
//! request reserves an estimate (the body's `max_tokens` plus a quarter of
//! its bytes) with one atomic add, is refused when the estimate does not
//! fit, and settles to the provider's real count when the response ends.
//! A background task ships each subject's unsynced spend to the ledger
//! about once a second, sooner when it grows, and takes back the global
//! total. Overrun is therefore bounded by one sync interval of spend across
//! pods, plus the gap between an estimate and reality; nothing is granted,
//! so nothing is lost at the window end.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::{mpsc, Notify};

use super::usage::{Dialect, Tokens};
use crate::plan::Reply;
use portus_types::proto::portus::ledger::v1::budget_client::BudgetClient;
use portus_types::proto::portus::ledger::v1::SyncRequest;

/// Fixed, UTC-aligned budget windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    Hourly,
    Daily,
    Monthly,
}

impl Window {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "HOURLY" => Some(Self::Hourly),
            "DAILY" => Some(Self::Daily),
            "MONTHLY" => Some(Self::Monthly),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hourly => "HOURLY",
            Self::Daily => "DAILY",
            Self::Monthly => "MONTHLY",
        }
    }

    /// End of the window containing `now_micros`, in unix microseconds.
    pub fn end_of(self, now_micros: u64) -> u64 {
        const MICROS: u64 = 1_000_000;
        let secs = now_micros / MICROS;
        match self {
            Self::Hourly => (secs / 3600 + 1) * 3600 * MICROS,
            Self::Daily => (secs / 86_400 + 1) * 86_400 * MICROS,
            Self::Monthly => {
                let days = secs / 86_400;
                let (y, m, _) = civil_from_days(days as i64);
                let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                (days_from_civil(ny, nm, 1) as u64) * 86_400 * MICROS
            }
        }
    }
}

/// Whose counter a request spends from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Key,
    Tenant,
    Route,
    /// The user behind the call: the `auth.onBehalfOf` name when a trusted
    /// caller gave one, else the key (or OAuth subject) itself.
    Subject,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "KEY" => Some(Self::Key),
            "TENANT" => Some(Self::Tenant),
            "ROUTE" => Some(Self::Route),
            "SUBJECT" => Some(Self::Subject),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Key => "KEY",
            Self::Tenant => "TENANT",
            Self::Route => "ROUTE",
            Self::Subject => "SUBJECT",
        }
    }
}

/// What a budget counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Input + output + cache tokens the provider reports (LLM routes).
    Tokens,
    /// Requests that reached the server (MCP routes: JSON-RPC calls).
    Calls,
}

impl Unit {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "TOKENS" | "" => Some(Self::Tokens),
            "CALLS" => Some(Self::Calls),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tokens => "TOKENS",
            Self::Calls => "CALLS",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Tokens => "token",
            Self::Calls => "call",
        }
    }
}

/// An AIUsagePolicy as compiled onto a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetPolicy {
    /// namespace/name of the AIUsagePolicy.
    pub id: Arc<str>,
    /// Units per window the subject is held to: the route's, or a key's own
    /// `budget_limit` (see [`BudgetPolicy::for_key`]).
    pub limit: u64,
    /// The route policy's limit, before any key override.
    pub route_limit: u64,
    pub unit: Unit,
    pub window: Window,
    pub per: Scope,
    /// With no sync yet and the ledger unreachable: allow or refuse.
    pub fail_open: bool,
}

impl BudgetPolicy {
    /// The policy as it applies to a key with its own `budget_limit`: the
    /// key's limit replaces the route's for `per: Key` and `per: Subject`
    /// counters (a tenant or route counter is shared, so a key cannot resize
    /// it). `0`: no override.
    pub fn for_key(&self, key_budget_limit: u64) -> Option<Self> {
        (key_budget_limit > 0 && matches!(self.per, Scope::Key | Scope::Subject)).then(|| Self { limit: key_budget_limit, ..self.clone() })
    }
}

/// How often a subject's unsynced spend is shipped to the ledger.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(1);
/// Unsynced spend above budget / this share triggers a sync at once.
const URGENT_SYNC_SHARE: u64 = 100;

/// One subject's view of its window on this pod.
pub struct Counter {
    /// End of the window the figures below belong to; 0 before the first sync.
    window_end: AtomicU64,
    /// Global spend in the window as of the last sync.
    global_spent: AtomicU64,
    /// Actual tokens spent here since the last sync.
    unsynced_spent: AtomicU64,
    /// Estimates of requests in flight here.
    reserved: AtomicU64,
    /// The ledger has answered at least once for this window.
    synced: AtomicBool,
    /// A sync is in flight; no second one is queued.
    syncing: AtomicBool,
    /// Woken when a sync lands or fails, for the one bounded wait a cold
    /// subject makes before its first decision.
    settled: Notify,
    budget: AtomicU64,
    /// The route policy's limit, told to the ledger for /v1/limits.
    route_limit: AtomicU64,
    unit: Unit,
    per: Scope,
    fail_open: bool,
    window: std::sync::Mutex<Window>,
}

impl Counter {
    fn new(policy: &BudgetPolicy) -> Self {
        Self {
            window_end: AtomicU64::new(0),
            global_spent: AtomicU64::new(0),
            unsynced_spent: AtomicU64::new(0),
            reserved: AtomicU64::new(0),
            synced: AtomicBool::new(false),
            syncing: AtomicBool::new(false),
            settled: Notify::new(),
            budget: AtomicU64::new(policy.limit),
            route_limit: AtomicU64::new(policy.route_limit),
            unit: policy.unit,
            per: policy.per,
            fail_open: policy.fail_open,
            window: std::sync::Mutex::new(policy.window),
        }
    }

    /// Tokens left in the window as this pod sees it right now; negative
    /// after an overrun.
    pub fn remaining(&self) -> i64 {
        self.budget.load(Ordering::Relaxed) as i64
            - self.global_spent.load(Ordering::Relaxed) as i64
            - self.unsynced_spent.load(Ordering::Relaxed) as i64
            - self.reserved.load(Ordering::Relaxed) as i64
    }

    /// Wait up to `timeout` for the in-flight sync. Only for a subject with
    /// no sync yet in this window: every later decision is local.
    pub async fn wait_for_sync(&self, timeout: Duration) {
        if !self.syncing.load(Ordering::Relaxed) {
            return;
        }
        let _ = tokio::time::timeout(timeout, self.settled.notified()).await;
    }

    fn apply_sync(&self, spent_total: u64, window_end: u64, reported: u64) {
        let previous = self.window_end.swap(window_end, Ordering::Relaxed);
        if previous == window_end {
            // The delta we shipped is now inside the global total.
            let _ = self.unsynced_spent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(reported)));
        } else {
            // The ledger is in a newer window than this pod's figures; the
            // reported delta belonged to the old one and is gone with it.
            self.unsynced_spent.store(0, Ordering::Relaxed);
        }
        self.global_spent.store(spent_total, Ordering::Relaxed);
        self.synced.store(true, Ordering::Relaxed);
        self.syncing.store(false, Ordering::Relaxed);
        self.settled.notify_waiters();
    }

    fn sync_failed(&self, reported: u64) {
        // Put the delta back; it goes with the next attempt.
        self.unsynced_spent.fetch_add(reported, Ordering::Relaxed);
        self.syncing.store(false, Ordering::Relaxed);
        self.settled.notify_waiters();
    }

    /// Forget the window's figures: it ended.
    fn roll_over(&self) {
        self.window_end.store(0, Ordering::Relaxed);
        self.global_spent.store(0, Ordering::Relaxed);
        self.unsynced_spent.store(0, Ordering::Relaxed);
        self.synced.store(false, Ordering::Relaxed);
    }

    fn window(&self) -> Window {
        self.window.lock().map(|w| *w).unwrap_or(Window::Hourly)
    }
}

/// A request's hold on its subject's counter: the estimate reserved before
/// forwarding, replaced by the real count when the response ends.
pub struct Reservation {
    counter: Arc<Counter>,
    estimate: u64,
    settled: AtomicBool,
}

impl Reservation {
    /// Replace the estimate with what the provider reported. A call budget
    /// spends one unit per settled response whatever it carried.
    pub fn settle(&self, tokens: Option<&Tokens>) {
        if self.settled.swap(true, Ordering::Relaxed) {
            return;
        }
        let actual = match self.counter.unit {
            Unit::Tokens => tokens.map_or(0, |t| u64::from(t.input) + u64::from(t.output) + u64::from(t.cache_read) + u64::from(t.cache_creation)),
            Unit::Calls => 1,
        };
        let _ = self.counter.reserved.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(self.estimate)));
        self.counter.unsynced_spent.fetch_add(actual, Ordering::Relaxed);
    }

    pub fn remaining(&self) -> i64 {
        self.counter.remaining()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // A request that never produced a response cost no tokens; a call
        // budget still counts it (the server was reached).
        self.settle(None);
    }
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reservation({} tokens)", self.estimate)
    }
}

impl PartialEq for Reservation {
    fn eq(&self, other: &Self) -> bool {
        self.estimate == other.estimate && Arc::ptr_eq(&self.counter, &other.counter)
    }
}

impl Eq for Reservation {}

/// What the budget says about a request before it is forwarded.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward it; settle the reservation when the response ends.
    Allow(Reservation),
    /// The estimate does not fit in what is left; `retry_after_secs` is
    /// until the window resets, `needed` the request's estimate.
    Exhausted { retry_after_secs: u64, remaining: i64, needed: u64 },
    /// No sync for this window yet and none in hand.
    Unknown,
}

/// Tokens a request will cost, before the provider says: `max_tokens` for
/// the output plus roughly one token per four request bytes for the prompt.
pub fn estimate(max_tokens: Option<u64>, request_bytes: u64) -> u64 {
    max_tokens.unwrap_or(0) + request_bytes / 4
}

/// What to reserve for a request under `unit`.
pub fn cost(unit: Unit, max_tokens: Option<u64>, request_bytes: u64) -> u64 {
    match unit {
        Unit::Tokens => estimate(max_tokens, request_bytes),
        Unit::Calls => 1,
    }
}

pub(crate) struct SyncAsk {
    policy_id: Arc<str>,
    subject: Arc<str>,
    counter: Arc<Counter>,
}

/// Every counter on this pod and the channel to the sync task.
pub struct Budgets {
    counters: DashMap<(Arc<str>, Arc<str>), Arc<Counter>>,
    asks: mpsc::Sender<SyncAsk>,
}

impl Budgets {
    /// Start the sync task against the ledger at `addr`.
    pub fn start(addr: String, node: String) -> Arc<Self> {
        let (asks, rx) = mpsc::channel(4096);
        let budgets = Arc::new(Self { counters: DashMap::new(), asks });
        tokio::spawn(sync_loop(addr, node, rx));
        tokio::spawn(tick_loop(Arc::clone(&budgets)));
        budgets
    }

    /// A `Budgets` whose asks are handed back for the test to answer.
    #[cfg(test)]
    pub(crate) fn detached() -> (Arc<Self>, mpsc::Receiver<SyncAsk>) {
        let (asks, rx) = mpsc::channel(64);
        (Arc::new(Self { counters: DashMap::new(), asks }), rx)
    }

    pub fn counter(&self, policy: &BudgetPolicy, subject: &Arc<str>) -> Arc<Counter> {
        let c = self
            .counters
            .entry((Arc::clone(&policy.id), Arc::clone(subject)))
            .or_insert_with(|| Arc::new(Counter::new(policy)))
            .clone();
        c.budget.store(policy.limit, Ordering::Relaxed);
        c.route_limit.store(policy.route_limit, Ordering::Relaxed);
        c
    }

    /// Decide for one request that will cost about `estimate` tokens.
    pub fn check(&self, policy: &BudgetPolicy, subject: &Arc<str>, estimate: u64, now_micros: u64) -> Verdict {
        let counter = self.counter(policy, subject);
        let window_end = counter.window_end.load(Ordering::Relaxed);
        if window_end != 0 && window_end <= now_micros {
            counter.roll_over();
        }
        if !counter.synced.load(Ordering::Relaxed) {
            self.ask(&policy.id, subject, &counter);
            return Verdict::Unknown;
        }
        let remaining = counter.remaining();
        if remaining <= 0 || remaining < estimate as i64 {
            let end = counter.window_end.load(Ordering::Relaxed);
            return Verdict::Exhausted { retry_after_secs: end.saturating_sub(now_micros).div_ceil(1_000_000).max(1), remaining, needed: estimate };
        }
        counter.reserved.fetch_add(estimate, Ordering::Relaxed);
        // Sync at once when a lot has piled up since the last one.
        if counter.unsynced_spent.load(Ordering::Relaxed) * URGENT_SYNC_SHARE > policy.limit {
            self.ask(&policy.id, subject, &counter);
        }
        Verdict::Allow(Reservation { counter, estimate, settled: AtomicBool::new(false) })
    }

    fn ask(&self, policy_id: &Arc<str>, subject: &Arc<str>, counter: &Arc<Counter>) {
        if counter.syncing.swap(true, Ordering::Relaxed) {
            return;
        }
        let ask = SyncAsk { policy_id: Arc::clone(policy_id), subject: Arc::clone(subject), counter: Arc::clone(counter) };
        if self.asks.try_send(ask).is_err() {
            counter.syncing.store(false, Ordering::Relaxed);
        }
    }

    /// Queue a sync for every counter with unsynced spend, in-flight
    /// reservations or a window that ended.
    fn sync_all(&self, now_micros: u64) {
        for entry in self.counters.iter() {
            let counter = entry.value();
            let end = counter.window_end.load(Ordering::Relaxed);
            let stale = end != 0 && end <= now_micros;
            if stale || counter.unsynced_spent.load(Ordering::Relaxed) > 0 || counter.reserved.load(Ordering::Relaxed) > 0 {
                let (policy_id, subject) = entry.key();
                self.ask(policy_id, subject, counter);
            }
        }
    }
}

/// The reply a spent budget answers with, in the client's dialect: 429 for
/// LLM clients; for MCP a JSON-RPC error on 200 echoing the request's `id`
/// (`request_id`, JSON text), because a non-2xx inside a session makes
/// clients drop the session. Both carry `Retry-After` and the remaining
/// header for the unit.
pub fn exhausted_reply(dialect: Dialect, unit: Unit, retry_after_secs: u64, remaining: i64, needed: u64, request_id: Option<&str>) -> Reply {
    let noun = unit.noun();
    let message = if remaining <= 0 {
        format!("{noun} budget for this window is exhausted")
    } else {
        format!("{noun} budget cannot cover this request: about {needed} {noun}s needed, {remaining} remaining in this window")
    };
    let (status, body) = match dialect {
        Dialect::Anthropic => (429, format!(r#"{{"type":"error","error":{{"type":"rate_limit_error","message":"{message}"}}}}"#)),
        Dialect::OpenAi => (429, format!(r#"{{"error":{{"message":"{message}","type":"insufficient_quota","code":"insufficient_quota"}}}}"#)),
        Dialect::Mcp => (200, super::mcp::error_body(request_id, super::mcp::CODE_BUDGET_EXHAUSTED, &message)),
    };
    Reply::json(status, body)
        .with_header(http::header::RETRY_AFTER, http::HeaderValue::from(retry_after_secs))
        .with_header(remaining_header(unit).clone(), http::HeaderValue::from(remaining.max(0)))
}

/// Response header carrying the subject's remaining tokens in the window.
pub static TOKENS_REMAINING_HEADER: http::HeaderName = http::HeaderName::from_static("x-portus-tokens-remaining");
/// Response header carrying the subject's remaining calls in the window.
pub static CALLS_REMAINING_HEADER: http::HeaderName = http::HeaderName::from_static("x-portus-calls-remaining");

pub fn remaining_header(unit: Unit) -> &'static http::HeaderName {
    match unit {
        Unit::Tokens => &TOKENS_REMAINING_HEADER,
        Unit::Calls => &CALLS_REMAINING_HEADER,
    }
}

pub fn now_micros() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

async fn tick_loop(budgets: Arc<Budgets>) {
    let mut tick = tokio::time::interval(SYNC_INTERVAL);
    loop {
        tick.tick().await;
        budgets.sync_all(now_micros());
    }
}

async fn sync_loop(addr: String, node: String, mut asks: mpsc::Receiver<SyncAsk>) {
    let mut client: Option<BudgetClient<tonic::transport::Channel>> = None;
    while let Some(ask) = asks.recv().await {
        if client.is_none() {
            match crate::config_receiver::grpc_client_endpoint(&addr) {
                Ok(endpoint) => match endpoint.connect().await {
                    Ok(channel) => client = Some(BudgetClient::new(channel)),
                    Err(e) => log::warn!("ledger at {addr} unreachable for budget sync: {e}"),
                },
                Err(e) => log::error!("ledger endpoint {addr} is invalid: {e}; budgets cannot sync"),
            }
        }
        let Some(c) = client.as_mut() else {
            ask.counter.sync_failed(0);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        let delta = ask.counter.unsynced_spent.swap(0, Ordering::Relaxed);
        let request = SyncRequest {
            node: node.clone(),
            policy: ask.policy_id.to_string(),
            subject: ask.subject.to_string(),
            window: ask.counter.window().as_str().to_string(),
            spent_delta: delta,
            limit: ask.counter.route_limit.load(Ordering::Relaxed),
            unit: ask.counter.unit.as_str().to_string(),
            per: ask.counter.per.as_str().to_string(),
            fail_open: ask.counter.fail_open,
            subject_limit: ask.counter.budget.load(Ordering::Relaxed),
        };
        match c.sync(request).await {
            Ok(resp) => {
                let s = resp.into_inner();
                ask.counter.apply_sync(s.spent_total, s.window_end_unix_micros, delta);
            }
            Err(e) => {
                log::warn!("budget sync for {}/{} failed: {e}", ask.policy_id, ask.subject);
                client = None;
                ask.counter.sync_failed(delta);
            }
        }
    }
}

// Howard Hinnant's civil date algorithms, days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_789_673_548_000_000; // 2026-09-17T19:32:28Z

    fn policy(tokens: u64) -> BudgetPolicy {
        BudgetPolicy { id: Arc::from("llm/hourly"), limit: tokens, route_limit: tokens, unit: Unit::Tokens, window: Window::Hourly, per: Scope::Key, fail_open: true }
    }

    fn calls(limit: u64) -> BudgetPolicy {
        BudgetPolicy { id: Arc::from("mcp/hourly"), limit, route_limit: limit, unit: Unit::Calls, window: Window::Hourly, per: Scope::Key, fail_open: true }
    }

    #[test]
    fn a_key_budget_replaces_the_route_limit_for_its_own_counters_only() {
        let route = policy(1_000);
        let mine = route.for_key(5_000).expect("per Key takes the override");
        assert_eq!((mine.limit, mine.route_limit, mine.id.as_ref()), (5_000, 1_000, "llm/hourly"));
        assert!(route.for_key(0).is_none(), "0 is no override");
        let per_user = BudgetPolicy { per: Scope::Subject, ..policy(1_000) };
        assert_eq!(per_user.for_key(20).map(|p| p.limit), Some(20));
        let shared = BudgetPolicy { per: Scope::Tenant, ..policy(1_000) };
        assert!(shared.for_key(5_000).is_none(), "a shared tenant counter is not resized by one key");
        assert!(BudgetPolicy { per: Scope::Route, ..policy(1_000) }.for_key(5_000).is_none());
        // The counter follows the effective policy and remembers the route's.
        let (budgets, _asks) = Budgets::detached();
        let subject: Arc<str> = Arc::from("k1");
        let c = budgets.counter(&mine, &subject);
        c.apply_sync(4_500, Window::Hourly.end_of(NOW), 0);
        assert_eq!(c.remaining(), 500);
        assert_eq!(c.route_limit.load(Ordering::Relaxed), 1_000);
    }

    #[test]
    fn a_call_budget_spends_one_per_request_whatever_the_response_carried() {
        let (budgets, _asks) = Budgets::detached();
        let p = calls(3);
        let subject: Arc<str> = Arc::from("k1");
        let c = budgets.counter(&p, &subject);
        c.apply_sync(0, Window::Hourly.end_of(NOW), 0);
        assert_eq!(cost(Unit::Calls, Some(4096), 100_000), 1);
        assert_eq!(cost(Unit::Tokens, Some(4096), 100_000), 29_096);
        let Verdict::Allow(r1) = budgets.check(&p, &subject, 1, NOW) else { panic!("first call allowed") };
        r1.settle(Some(&tokens(1_000_000)));
        let Verdict::Allow(r2) = budgets.check(&p, &subject, 1, NOW) else { panic!("second call allowed") };
        drop(r2); // no response at all: still one call
        let Verdict::Allow(r3) = budgets.check(&p, &subject, 1, NOW) else { panic!("third call allowed") };
        r3.settle(None);
        match budgets.check(&p, &subject, 1, NOW) {
            Verdict::Exhausted { remaining, needed, .. } => assert_eq!((remaining, needed), (0, 1)),
            other => panic!("fourth call must be refused: {other:?}"),
        }
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn an_mcp_budget_refusal_is_a_json_rpc_error_on_200_with_the_request_id() {
        let r = exhausted_reply(Dialect::Mcp, Unit::Calls, 30, 0, 1, Some("\"req-7\""));
        assert_eq!(r.status, 200);
        assert_eq!(std::str::from_utf8(&r.body).unwrap(), r#"{"jsonrpc":"2.0","id":"req-7","error":{"code":-32003,"message":"call budget for this window is exhausted"}}"#);
        assert!(r.headers.iter().any(|(n, v)| n == http::header::RETRY_AFTER && v == "30"));
        assert!(r.headers.iter().any(|(n, v)| *n == CALLS_REMAINING_HEADER && v == "0"));
        assert_eq!(remaining_header(Unit::Tokens).as_str(), "x-portus-tokens-remaining");
        assert_eq!(Unit::parse("CALLS"), Some(Unit::Calls));
        assert_eq!(Unit::parse(""), Some(Unit::Tokens), "routes compiled before units existed are token budgets");
    }

    fn tokens(n: u32) -> Tokens {
        Tokens { input: n, output: 0, cache_read: 0, cache_creation: 0 }
    }

    #[test]
    fn windows_end_on_utc_boundaries() {
        assert_eq!(Window::Hourly.end_of(NOW), 1_789_675_200_000_000, "20:00Z");
        assert_eq!(Window::Daily.end_of(NOW), 1_789_689_600_000_000, "2026-09-18T00:00Z");
        assert_eq!(Window::Monthly.end_of(NOW), 1_790_812_800_000_000, "2026-10-01T00:00Z");
        let dec = 1_797_000_000_000_000u64; // 2026-12-11
        assert_eq!(Window::Monthly.end_of(dec), (days_from_civil(2027, 1, 1) as u64) * 86_400_000_000);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn estimates_use_max_tokens_and_a_quarter_of_the_bytes() {
        assert_eq!(estimate(Some(1024), 4000), 2024);
        assert_eq!(estimate(None, 4000), 1000);
        assert_eq!(estimate(None, 3), 0);
    }

    #[tokio::test]
    async fn a_cold_subject_is_unknown_until_the_first_sync_then_spends_locally() {
        let (budgets, mut asks) = Budgets::detached();
        let p = policy(10_000);
        let subject: Arc<str> = Arc::from("key-1");
        assert_eq!(budgets.check(&p, &subject, 100, NOW), Verdict::Unknown);
        assert_eq!(budgets.check(&p, &subject, 100, NOW), Verdict::Unknown, "still cold");
        let ask = asks.try_recv().unwrap();
        assert!(asks.try_recv().is_err(), "one sync in flight at a time");
        // The ledger says 9 000 already spent globally this window.
        ask.counter.apply_sync(9_000, Window::Hourly.end_of(NOW), 0);

        let Verdict::Allow(r1) = budgets.check(&p, &subject, 600, NOW) else { panic!("fits: 1 000 left") };
        assert_eq!(r1.remaining(), 400, "the estimate is reserved");
        assert!(matches!(budgets.check(&p, &subject, 500, NOW), Verdict::Exhausted { remaining: 400, needed: 500, .. }), "500 does not fit in 400");
        let Verdict::Allow(r2) = budgets.check(&p, &subject, 300, NOW) else { panic!("300 fits") };
        assert_eq!(r2.remaining(), 100);
        // Real usage replaces the estimates: r1 cost 250, r2 cost 700 (over its estimate).
        r1.settle(Some(&tokens(250)));
        assert_eq!(r2.remaining(), 10_000 - 9_000 - 250 - 300);
        r2.settle(Some(&tokens(700)));
        let counter = budgets.counter(&p, &subject);
        assert_eq!(counter.remaining(), 50);
        assert_eq!(counter.unsynced_spent.load(Ordering::Relaxed), 950);
        assert_eq!(counter.reserved.load(Ordering::Relaxed), 0);
        // Dropping an unsettled reservation costs nothing.
        let Verdict::Allow(r3) = budgets.check(&p, &subject, 40, NOW) else { panic!() };
        drop(r3);
        assert_eq!(counter.remaining(), 50);
    }

    #[tokio::test]
    async fn syncs_ship_the_delta_and_take_back_the_global_total() {
        let (budgets, mut asks) = Budgets::detached();
        let p = policy(1_000_000);
        let subject: Arc<str> = Arc::from("key-2");
        budgets.check(&p, &subject, 10, NOW);
        asks.try_recv().unwrap().counter.apply_sync(0, Window::Hourly.end_of(NOW), 0);
        let Verdict::Allow(r) = budgets.check(&p, &subject, 10, NOW) else { panic!() };
        r.settle(Some(&tokens(5_000)));
        let counter = budgets.counter(&p, &subject);
        assert_eq!(counter.remaining(), 995_000);

        // The tick finds unsynced spend and queues a sync.
        budgets.sync_all(NOW);
        let ask = asks.try_recv().unwrap();
        let delta = ask.counter.unsynced_spent.swap(0, Ordering::Relaxed);
        assert_eq!(delta, 5_000);
        // Meanwhile another pod spent 20 000; the ledger's total includes our delta.
        ask.counter.apply_sync(25_000, Window::Hourly.end_of(NOW), delta);
        assert_eq!(counter.remaining(), 975_000, "global view replaces the local delta, nothing counted twice");
        assert!(asks.try_recv().is_err());

        // A failed sync puts the delta back for the next attempt.
        let Verdict::Allow(r) = budgets.check(&p, &subject, 10, NOW) else { panic!() };
        r.settle(Some(&tokens(100)));
        budgets.sync_all(NOW);
        let ask = asks.try_recv().unwrap();
        let delta = ask.counter.unsynced_spent.swap(0, Ordering::Relaxed);
        ask.counter.sync_failed(delta);
        assert_eq!(counter.unsynced_spent.load(Ordering::Relaxed), 100);
        assert_eq!(counter.remaining(), 974_900);
    }

    #[tokio::test]
    async fn heavy_local_spend_syncs_at_once_and_windows_roll_over_clean() {
        let (budgets, mut asks) = Budgets::detached();
        let p = policy(10_000);
        let subject: Arc<str> = Arc::from("key-3");
        budgets.check(&p, &subject, 10, NOW);
        asks.try_recv().unwrap().counter.apply_sync(0, Window::Hourly.end_of(NOW), 0);
        let Verdict::Allow(r) = budgets.check(&p, &subject, 10, NOW) else { panic!() };
        r.settle(Some(&tokens(500))); // 5 % of the budget unsynced: over the 1 % urgency line
        let Verdict::Allow(_r) = budgets.check(&p, &subject, 10, NOW) else { panic!() };
        assert!(asks.try_recv().is_ok(), "an urgent sync was queued by the next check");

        // The window ends: figures reset, the subject is cold again.
        let later = Window::Hourly.end_of(NOW) + 1;
        assert_eq!(budgets.check(&p, &subject, 10, later), Verdict::Unknown);
        let counter = budgets.counter(&p, &subject);
        assert_eq!((counter.global_spent.load(Ordering::Relaxed), counter.unsynced_spent.load(Ordering::Relaxed)), (0, 0));
    }

    #[tokio::test]
    async fn a_cold_subject_can_wait_briefly_for_its_first_sync() {
        let (budgets, mut asks) = Budgets::detached();
        let p = policy(10_000);
        let subject: Arc<str> = Arc::from("key-4");
        assert_eq!(budgets.check(&p, &subject, 10, NOW), Verdict::Unknown);
        let ask = asks.try_recv().unwrap();
        let counter = budgets.counter(&p, &subject);
        let waiter = Arc::clone(&counter);
        let waited = tokio::spawn(async move {
            let t = std::time::Instant::now();
            waiter.wait_for_sync(Duration::from_secs(5)).await;
            t.elapsed()
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        ask.counter.apply_sync(0, Window::Hourly.end_of(NOW), 0);
        assert!(waited.await.unwrap() < Duration::from_secs(1), "woken by the sync, not the timeout");
        assert!(matches!(budgets.check(&p, &subject, 10, NOW), Verdict::Allow(_)));
    }

    #[test]
    fn the_429_names_the_reset_and_the_remaining_tokens() {
        let r = exhausted_reply(Dialect::Anthropic, Unit::Tokens, 90, 12, 500, None);
        assert_eq!(r.status, 429);
        assert!(r.headers.iter().any(|(n, v)| n == http::header::RETRY_AFTER && v == "90"));
        assert!(r.headers.iter().any(|(n, v)| *n == TOKENS_REMAINING_HEADER && v == "12"));
        assert!(std::str::from_utf8(&r.body).unwrap().contains("rate_limit_error"));
        assert!(std::str::from_utf8(&r.body).unwrap().contains("about 500 tokens needed, 12 remaining"));
        assert!(r.headers.iter().any(|(n, v)| n == http::header::CONTENT_LENGTH && v == r.body.len().to_string().as_str()));
        assert!(std::str::from_utf8(&exhausted_reply(Dialect::OpenAi, Unit::Tokens, 1, -5, 10, None).body).unwrap().contains("is exhausted"));
    }
}
