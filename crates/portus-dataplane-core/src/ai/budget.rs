//! Token budgets on the request path. Each (policy, subject) holds an
//! allowance the ledger granted; a request spends from it with two atomics
//! (one to check, one to debit when the response ends). When the allowance
//! runs low a background task asks the ledger for the next grant, so the
//! request path never waits on the network. Overrun is bounded by one grant
//! per pod per subject, by design.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::{mpsc, Notify};

use super::usage::{Dialect, Tokens};
use crate::plan::Reply;
use portus_types::proto::portus::ledger::v1::budget_client::BudgetClient;
use portus_types::proto::portus::ledger::v1::GrantRequest;

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
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "KEY" => Some(Self::Key),
            "TENANT" => Some(Self::Tenant),
            "ROUTE" => Some(Self::Route),
            _ => None,
        }
    }
}

/// An AIUsagePolicy as compiled onto a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetPolicy {
    /// namespace/name of the AIUsagePolicy.
    pub id: Arc<str>,
    pub tokens: u64,
    pub window: Window,
    pub per: Scope,
    /// With no allowance held and the ledger unreachable: allow or refuse.
    pub fail_open: bool,
}

/// One subject's grant on this pod.
pub struct Allowance {
    /// Tokens left from the current grant; negative after an overrun.
    remaining: AtomicI64,
    /// End of the window the grant belongs to; 0 before the first grant.
    window_end: AtomicU64,
    /// The ledger has said the window is exhausted.
    exhausted: AtomicBool,
    /// A grant request is in flight; no second one is queued.
    requesting: AtomicBool,
    /// Tokens debited since the last grant, reported with the next request.
    spent: AtomicU64,
    /// At least one answer from the ledger ever arrived for this subject.
    ever_granted: AtomicBool,
    /// Woken when a grant lands or an ask fails, for the one bounded wait a
    /// cold subject makes before its first decision.
    settled: Notify,
}

impl Allowance {
    fn new() -> Self {
        Self {
            remaining: AtomicI64::new(0),
            window_end: AtomicU64::new(0),
            exhausted: AtomicBool::new(false),
            requesting: AtomicBool::new(false),
            spent: AtomicU64::new(0),
            ever_granted: AtomicBool::new(false),
            settled: Notify::new(),
        }
    }

    /// Wait up to `timeout` for the in-flight ask to be answered. Only for a
    /// subject with no allowance yet: every later decision is local.
    pub async fn wait_for_grant(&self, timeout: Duration) {
        if !self.requesting.load(Ordering::Relaxed) {
            return;
        }
        let _ = tokio::time::timeout(timeout, self.settled.notified()).await;
    }

    fn ask_failed(&self) {
        self.requesting.store(false, Ordering::Relaxed);
        self.settled.notify_waiters();
    }

    /// Charge the tokens a response reported.
    pub fn debit(&self, tokens: &Tokens) {
        let total = i64::from(tokens.input) + i64::from(tokens.output) + i64::from(tokens.cache_read) + i64::from(tokens.cache_creation);
        self.remaining.fetch_sub(total, Ordering::Relaxed);
        self.spent.fetch_add(total as u64, Ordering::Relaxed);
    }

    pub fn remaining(&self) -> i64 {
        self.remaining.load(Ordering::Relaxed)
    }

    fn apply_grant(&self, tokens: u64, window_end: u64, exhausted: bool) {
        let previous_end = self.window_end.swap(window_end, Ordering::Relaxed);
        if previous_end != window_end {
            // A new window: whatever was left of the old grant is gone.
            self.remaining.store(0, Ordering::Relaxed);
        }
        self.remaining.fetch_add(tokens as i64, Ordering::Relaxed);
        self.exhausted.store(exhausted, Ordering::Relaxed);
        self.ever_granted.store(true, Ordering::Relaxed);
        self.requesting.store(false, Ordering::Relaxed);
        self.settled.notify_waiters();
    }
}

/// What the budget says about a request before it is forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// The window's budget is spent; `retry_after_secs` is until it resets.
    Exhausted { retry_after_secs: u64 },
    /// No allowance and no word from the ledger yet.
    Unknown,
}

pub(crate) struct Ask {
    policy: BudgetPolicy,
    subject: Arc<str>,
    allowance: Arc<Allowance>,
}

/// Every allowance on this pod and the channel to the grant task.
pub struct Budgets {
    allowances: DashMap<(Arc<str>, Arc<str>), Arc<Allowance>>,
    asks: mpsc::Sender<Ask>,
}

/// Tokens the ledger is asked for at once: 5 % of the budget, at least a
/// quarter of it (or 1 000, whichever is smaller) so several pods can share
/// a small budget, at most 200 000.
pub fn grant_chunk(budget_tokens: u64) -> u64 {
    let floor = 1_000.min(budget_tokens.div_ceil(4)).max(1);
    (budget_tokens / 20).clamp(floor, 200_000.max(floor)).min(budget_tokens.max(1))
}

impl Budgets {
    /// Start the grant task against the ledger at `addr`.
    pub fn start(addr: String, node: String) -> Arc<Self> {
        let (asks, rx) = mpsc::channel(4096);
        let budgets = Arc::new(Self { allowances: DashMap::new(), asks });
        tokio::spawn(grant_loop(addr, node, rx));
        budgets
    }

    /// A `Budgets` that never reaches a ledger: allowances stay empty.
    #[cfg(test)]
    pub(crate) fn detached() -> (Arc<Self>, mpsc::Receiver<Ask>) {
        let (asks, rx) = mpsc::channel(64);
        (Arc::new(Self { allowances: DashMap::new(), asks }), rx)
    }

    pub fn allowance(&self, policy: &BudgetPolicy, subject: &Arc<str>) -> Arc<Allowance> {
        self.allowances
            .entry((Arc::clone(&policy.id), Arc::clone(subject)))
            .or_insert_with(|| Arc::new(Allowance::new()))
            .clone()
    }

    /// Decide for one request and, when the allowance is low, ask for more.
    pub fn check(&self, policy: &BudgetPolicy, subject: &Arc<str>, now_micros: u64) -> (Verdict, Arc<Allowance>) {
        let allowance = self.allowance(policy, subject);
        let window_end = allowance.window_end.load(Ordering::Relaxed);
        let in_window = window_end > now_micros;
        let remaining = if in_window { allowance.remaining.load(Ordering::Relaxed) } else { 0 };
        let low_water = (grant_chunk(policy.tokens) / 4) as i64;
        if !in_window || remaining < low_water {
            self.ask(policy, subject, &allowance);
        }
        let verdict = if remaining > 0 {
            Verdict::Allow
        } else if in_window && allowance.exhausted.load(Ordering::Relaxed) {
            Verdict::Exhausted { retry_after_secs: window_end.saturating_sub(now_micros).div_ceil(1_000_000).max(1) }
        } else if in_window && allowance.ever_granted.load(Ordering::Relaxed) {
            // Granted before, spent it all, next grant not here yet: treat as
            // exhausted until the ledger says otherwise.
            Verdict::Exhausted { retry_after_secs: 1 }
        } else {
            Verdict::Unknown
        };
        (verdict, allowance)
    }

    fn ask(&self, policy: &BudgetPolicy, subject: &Arc<str>, allowance: &Arc<Allowance>) {
        if allowance.requesting.swap(true, Ordering::Relaxed) {
            return;
        }
        let ask = Ask { policy: policy.clone(), subject: Arc::clone(subject), allowance: Arc::clone(allowance) };
        if self.asks.try_send(ask).is_err() {
            allowance.requesting.store(false, Ordering::Relaxed);
        }
    }
}

/// The 429 a spent budget answers with, in the client's dialect.
pub fn exhausted_reply(dialect: Dialect, retry_after_secs: u64) -> Reply {
    let message = "token budget for this window is exhausted";
    let body = match dialect {
        Dialect::Anthropic => format!(r#"{{"type":"error","error":{{"type":"rate_limit_error","message":"{message}"}}}}"#),
        Dialect::OpenAi => format!(r#"{{"error":{{"message":"{message}","type":"insufficient_quota","code":"insufficient_quota"}}}}"#),
    };
    let mut reply = Reply::empty(429)
        .with_header(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"))
        .with_header(http::header::RETRY_AFTER, http::HeaderValue::from(retry_after_secs));
    reply.body = body.into();
    reply
}

pub fn now_micros() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

async fn grant_loop(addr: String, node: String, mut asks: mpsc::Receiver<Ask>) {
    let mut client: Option<BudgetClient<tonic::transport::Channel>> = None;
    while let Some(ask) = asks.recv().await {
        if client.is_none() {
            match crate::config_receiver::grpc_client_endpoint(&addr) {
                Ok(endpoint) => match endpoint.connect().await {
                    Ok(channel) => client = Some(BudgetClient::new(channel)),
                    Err(e) => log::warn!("ledger at {addr} unreachable for grants: {e}"),
                },
                Err(e) => log::error!("ledger endpoint {addr} is invalid: {e}; budgets cannot be granted"),
            }
        }
        let Some(c) = client.as_mut() else {
            ask.allowance.ask_failed();
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        let request = GrantRequest {
            node: node.clone(),
            policy: ask.policy.id.to_string(),
            subject: ask.subject.to_string(),
            budget_tokens: ask.policy.tokens,
            window: ask.policy.window.as_str().to_string(),
            spent: ask.allowance.spent.swap(0, Ordering::Relaxed),
        };
        match c.grant(request).await {
            Ok(resp) => {
                let g = resp.into_inner();
                ask.allowance.apply_grant(g.tokens, g.window_end_unix_micros, g.exhausted);
            }
            Err(e) => {
                log::warn!("grant for {}/{} failed: {e}", ask.policy.id, ask.subject);
                client = None;
                ask.allowance.ask_failed();
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

    fn policy(tokens: u64) -> BudgetPolicy {
        BudgetPolicy { id: Arc::from("llm/hourly"), tokens, window: Window::Hourly, per: Scope::Key, fail_open: true }
    }

    #[test]
    fn windows_end_on_utc_boundaries() {
        // 2026-09-17T19:32:28Z
        let now = 1_789_673_548_000_000u64;
        assert_eq!(Window::Hourly.end_of(now), 1_789_675_200_000_000, "20:00Z");
        assert_eq!(Window::Daily.end_of(now), 1_789_689_600_000_000, "2026-09-18T00:00Z");
        assert_eq!(Window::Monthly.end_of(now), 1_790_812_800_000_000, "2026-10-01T00:00Z");
        // December rolls into the next year.
        let dec = 1_797_000_000_000_000u64; // 2026-12-11
        assert_eq!(civil_from_days((dec / 1_000_000 / 86_400) as i64).1, 12);
        assert_eq!(Window::Monthly.end_of(dec), (days_from_civil(2027, 1, 1) as u64) * 86_400_000_000);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn grant_chunks_are_a_bounded_share_of_the_budget() {
        assert_eq!(grant_chunk(100), 25, "a quarter of a tiny budget, so pods can share it");
        assert_eq!(grant_chunk(400), 100);
        assert_eq!(grant_chunk(3), 1);
        assert_eq!(grant_chunk(10_000), 1_000, "floor");
        assert_eq!(grant_chunk(1_000_000), 50_000, "5 %");
        assert_eq!(grant_chunk(100_000_000), 200_000, "ceiling");
    }

    #[tokio::test]
    async fn a_fresh_subject_is_unknown_asks_once_then_spends_its_grant() {
        let (budgets, mut asks) = Budgets::detached();
        let p = policy(10_000);
        let subject: Arc<str> = Arc::from("key-1");
        let now = 1_789_673_548_000_000u64;
        let (verdict, allowance) = budgets.check(&p, &subject, now);
        assert_eq!(verdict, Verdict::Unknown);
        let (verdict, _) = budgets.check(&p, &subject, now);
        assert_eq!(verdict, Verdict::Unknown);
        assert!(asks.try_recv().is_ok(), "one ask was queued");
        assert!(asks.try_recv().is_err(), "not a second while the first is in flight");

        allowance.apply_grant(1_000, Window::Hourly.end_of(now), false);
        let (verdict, _) = budgets.check(&p, &subject, now);
        assert_eq!(verdict, Verdict::Allow);
        allowance.debit(&Tokens { input: 600, output: 100, cache_read: 0, cache_creation: 0 });
        assert_eq!(allowance.remaining(), 300);
        // 300 is above the low-water mark of 250: no new ask yet.
        assert!(asks.try_recv().is_err());
        allowance.debit(&Tokens { input: 100, output: 0, cache_read: 0, cache_creation: 0 });
        let (verdict, _) = budgets.check(&p, &subject, now);
        assert_eq!(verdict, Verdict::Allow, "200 left still allows");
        assert!(asks.try_recv().is_ok(), "below low water: asked ahead");
        allowance.debit(&Tokens { input: 250, output: 0, cache_read: 0, cache_creation: 0 });
        assert_eq!(allowance.remaining(), -50, "overrun is bounded by the grant, not refused mid-flight");
        let (verdict, _) = budgets.check(&p, &subject, now);
        assert_eq!(verdict, Verdict::Exhausted { retry_after_secs: 1 }, "spent, next grant pending");
    }

    #[tokio::test]
    async fn an_exhausted_window_says_when_to_retry_and_resets_on_the_next_window() {
        let (budgets, _asks) = Budgets::detached();
        let p = policy(10_000);
        let subject: Arc<str> = Arc::from("key-2");
        let now = 1_789_673_548_000_000u64;
        let end = Window::Hourly.end_of(now);
        let (_, allowance) = budgets.check(&p, &subject, now);
        allowance.apply_grant(0, end, true);
        let (verdict, _) = budgets.check(&p, &subject, now);
        assert_eq!(verdict, Verdict::Exhausted { retry_after_secs: 1652 });
        // Next window: nothing held, the ledger is asked again, verdict is
        // Unknown until it answers (the policy's fail_open decides).
        let (verdict, _) = budgets.check(&p, &subject, end + 1);
        assert_eq!(verdict, Verdict::Unknown);
        allowance.apply_grant(500, Window::Hourly.end_of(end + 1), false);
        assert_eq!(allowance.remaining(), 500, "leftover from the old window did not carry over");
    }

    #[tokio::test]
    async fn a_cold_subject_can_wait_briefly_for_its_first_grant() {
        let (budgets, mut asks) = Budgets::detached();
        let p = policy(10_000);
        let subject: Arc<str> = Arc::from("key-3");
        let now = 1_789_673_548_000_000u64;
        let (verdict, allowance) = budgets.check(&p, &subject, now);
        assert_eq!(verdict, Verdict::Unknown);
        let ask = asks.try_recv().unwrap();
        let waiter = Arc::clone(&allowance);
        let waited = tokio::spawn(async move {
            let t = std::time::Instant::now();
            waiter.wait_for_grant(Duration::from_secs(5)).await;
            t.elapsed()
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        ask.allowance.apply_grant(1_000, Window::Hourly.end_of(now), false);
        assert!(waited.await.unwrap() < Duration::from_secs(1), "woken by the grant, not the timeout");
        assert_eq!(budgets.check(&p, &subject, now).0, Verdict::Allow);
        // A failed ask wakes the waiter too, and the timeout bounds the wait.
        let (budgets, mut asks) = Budgets::detached();
        let (_, allowance) = budgets.check(&p, &subject, now);
        let ask = asks.try_recv().unwrap();
        ask.allowance.ask_failed();
        allowance.wait_for_grant(Duration::from_millis(50)).await;
        let t = std::time::Instant::now();
        let (_, a2) = budgets.check(&p, &subject, now);
        a2.wait_for_grant(Duration::from_millis(50)).await;
        assert!(t.elapsed() >= Duration::from_millis(50), "nobody answered: the timeout bounded the wait");
    }

    #[test]
    fn the_429_names_the_window_reset_in_the_client_dialect() {
        let r = exhausted_reply(Dialect::Anthropic, 90);
        assert_eq!(r.status, 429);
        assert!(r.headers.iter().any(|(n, v)| n == http::header::RETRY_AFTER && v == "90"));
        assert!(std::str::from_utf8(&r.body).unwrap().contains("rate_limit_error"));
        assert!(std::str::from_utf8(&exhausted_reply(Dialect::OpenAi, 1).body).unwrap().contains("insufficient_quota"));
    }
}
