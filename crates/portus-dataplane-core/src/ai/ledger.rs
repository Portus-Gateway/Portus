//! Shipping usage records to the ledger: one drain task per data plane pod
//! pops the ring in batches and sends them over gRPC. The request path only
//! ever touches the ring.
//!
//! The ledger is optional. Without `PORTUS_LEDGER_ADDR` nothing is
//! recorded; with it, records survive a ledger outage for as long as the
//! ring and a few retained batches hold, then the oldest are dropped and
//! counted.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use portus_types::proto::portus::ledger::v1::key_distribution_client::KeyDistributionClient;
use portus_types::proto::portus::ledger::v1::ledger_ingest_client::LedgerIngestClient;
use portus_types::proto::portus::ledger::v1::{KeyWatchRequest, UsageBatch, UsageRecord as WireRecord};

use super::budget::Budgets;
use super::keys::KeySet;
use super::usage::{UsageRecord, UsageRing};

/// Records held per pod between drains.
pub const RING_CAPACITY: usize = 65_536;
/// Records per batch, and the ring depth that triggers an early drain.
pub const BATCH_SIZE: usize = 512;
/// How often the drain runs when the ring stays below `BATCH_SIZE`.
pub const DRAIN_INTERVAL: Duration = Duration::from_secs(1);
/// Batches kept while the ledger is unreachable; older ones are dropped.
pub const RETAINED_BATCHES: usize = 8;
const RETRY_MAX: Duration = Duration::from_secs(30);

/// Where the drain task stands, for :9090.
#[derive(Default)]
pub struct LedgerStats {
    pub batches_sent: AtomicU64,
    pub records_sent: AtomicU64,
    pub send_failures: AtomicU64,
    /// Records discarded because retained batches overflowed during an outage.
    pub records_discarded: AtomicU64,
}

/// The pod's ring and the drain task feeding the ledger, plus the API key
/// snapshot the ledger pushes back.
pub struct LedgerReporter {
    pub ring: Arc<UsageRing>,
    pub stats: Arc<LedgerStats>,
    /// Replaced whole on every snapshot; empty until the first arrives, so
    /// key-requiring routes fail closed while the ledger is unreachable.
    pub keys: Arc<ArcSwap<KeySet>>,
    /// Token allowances per policy and subject, refilled by ledger grants.
    pub budgets: Arc<Budgets>,
}

impl LedgerReporter {
    /// Start reporting to `PORTUS_LEDGER_ADDR` if it is set. Must be called
    /// on a tokio runtime.
    pub fn from_env() -> Option<Arc<Self>> {
        let addr = std::env::var("PORTUS_LEDGER_ADDR").ok().filter(|a| !a.trim().is_empty())?;
        Some(Self::start(addr.trim().to_string()))
    }

    pub fn start(addr: String) -> Arc<Self> {
        let node = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        let reporter = Arc::new(Self {
            ring: Arc::new(UsageRing::new(RING_CAPACITY)),
            stats: Arc::new(LedgerStats::default()),
            keys: Arc::new(ArcSwap::from_pointee(KeySet::default())),
            budgets: Budgets::start(addr.clone(), node.clone()),
        });
        tokio::spawn(drain_loop(addr.clone(), node.clone(), Arc::clone(&reporter.ring), Arc::clone(&reporter.stats)));
        tokio::spawn(watch_keys_loop(addr, node, Arc::clone(&reporter.keys)));
        log::info!("usage records are reported to the ledger at {}", reporter_addr_for_log());
        reporter
    }
}

fn reporter_addr_for_log() -> String {
    std::env::var("PORTUS_LEDGER_ADDR").unwrap_or_default()
}

pub fn to_wire(r: &UsageRecord) -> WireRecord {
    let t = r.tokens.unwrap_or_default();
    WireRecord {
        ts_unix_micros: r.ts_unix_micros,
        duration_micros: r.duration_micros,
        status: u32::from(r.status),
        dialect: r.dialect.as_str().to_string(),
        stream: r.stream,
        provider: r.provider.to_string(),
        route_host: r.route_host.to_string(),
        requested_model: r.requested_model.to_string(),
        served_model: r.served_model.to_string(),
        has_usage: r.tokens.is_some(),
        input_tokens: t.input,
        output_tokens: t.output,
        cache_read_tokens: t.cache_read,
        cache_creation_tokens: t.cache_creation,
        request_bytes: r.request_bytes,
        response_bytes: r.response_bytes,
        key_id: r.key_id,
        request_id: r.request_id,
        refusal: r.refusal.map_or("", |k| k.as_str()).to_string(),
    }
}

async fn drain_loop(addr: String, node: String, ring: Arc<UsageRing>, stats: Arc<LedgerStats>) {
    let mut client: Option<LedgerIngestClient<tonic::transport::Channel>> = None;
    let mut pending: std::collections::VecDeque<Vec<WireRecord>> = std::collections::VecDeque::new();
    let mut backoff = Duration::from_secs(1);
    let mut scratch: Vec<UsageRecord> = Vec::with_capacity(BATCH_SIZE);
    loop {
        // Wait for a full batch or the interval, whichever comes first.
        let deadline = tokio::time::Instant::now() + DRAIN_INTERVAL;
        while ring.len() < BATCH_SIZE && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        scratch.clear();
        if ring.drain_into(&mut scratch, BATCH_SIZE) > 0 {
            pending.push_back(scratch.iter().map(to_wire).collect());
        }
        while pending.len() > RETAINED_BATCHES {
            if let Some(dropped) = pending.pop_front() {
                stats.records_discarded.fetch_add(dropped.len() as u64, Ordering::Relaxed);
            }
        }
        let Some(batch) = pending.front() else { continue };

        if client.is_none() {
            match crate::config_receiver::grpc_client_endpoint(&addr) {
                Ok(endpoint) => match endpoint.connect().await {
                    Ok(channel) => client = Some(LedgerIngestClient::new(channel)),
                    Err(e) => {
                        log::warn!("ledger at {addr} unreachable: {e}; retrying in {backoff:?}");
                    }
                },
                Err(e) => {
                    log::error!("ledger endpoint {addr} is invalid: {e}; usage records will be discarded");
                    tokio::time::sleep(RETRY_MAX).await;
                    continue;
                }
            }
        }
        let Some(c) = client.as_mut() else {
            stats.send_failures.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RETRY_MAX);
            continue;
        };
        let request = UsageBatch { node: node.clone(), records: batch.clone(), dropped_total: ring.dropped() };
        match c.report(request).await {
            Ok(_) => {
                let sent = batch.len() as u64;
                pending.pop_front();
                stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                stats.records_sent.fetch_add(sent, Ordering::Relaxed);
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                log::warn!("ledger report failed: {e}; {} batches retained", pending.len());
                stats.send_failures.fetch_add(1, Ordering::Relaxed);
                client = None;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_MAX);
            }
        }
    }
}

/// Hold a key-snapshot stream open to the ledger, applying each newer
/// snapshot; reconnect with backoff when it drops.
async fn watch_keys_loop(addr: String, node: String, keys: Arc<ArcSwap<KeySet>>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let endpoint = match crate::config_receiver::grpc_client_endpoint(&addr) {
            Ok(e) => e,
            Err(e) => {
                log::error!("ledger endpoint {addr} is invalid: {e}; API keys cannot be validated");
                tokio::time::sleep(RETRY_MAX).await;
                continue;
            }
        };
        let stream = match endpoint.connect().await {
            Ok(channel) => KeyDistributionClient::new(channel).watch_keys(KeyWatchRequest { node: node.clone() }).await,
            Err(e) => Err(tonic::Status::unavailable(e.to_string())),
        };
        match stream {
            Ok(response) => {
                backoff = Duration::from_secs(1);
                let mut inbound = response.into_inner();
                // The first message of a stream is the ledger's current truth,
                // whatever version number it carries (the ledger may have
                // restarted); later messages must move forward.
                let mut first = true;
                loop {
                    match inbound.message().await {
                        Ok(Some(snapshot)) => {
                            let current = keys.load();
                            if first || snapshot.version > current.version || current.is_empty() {
                                first = false;
                                let set = KeySet::from_snapshot(&snapshot);
                                log::info!("API key snapshot v{} applied: {} keys", set.version, set.len());
                                keys.store(Arc::new(set));
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            log::warn!("key snapshot stream from the ledger ended: {e}");
                            break;
                        }
                    }
                }
            }
            Err(e) => log::warn!("cannot watch API keys at {addr}: {e}; retrying in {backoff:?}"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RETRY_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::usage::{Dialect, Tokens};
    use arrayvec::ArrayString;

    #[test]
    fn wire_records_carry_every_field_and_flag_missing_usage() {
        let mut r = UsageRecord {
            ts_unix_micros: 1,
            duration_micros: 2,
            status: 200,
            dialect: Dialect::OpenAi,
            stream: true,
            provider: UsageRecord::name("echo"),
            route_host: UsageRecord::name("llm.bench"),
            requested_model: UsageRecord::name("gpt-5"),
            served_model: ArrayString::new(),
            tokens: Some(Tokens { input: 9, output: 12, cache_read: 3, cache_creation: 0 }),
            request_bytes: 100,
            response_bytes: 200,
            key_id: 7,
            request_id: 42,
            refusal: None,
        };
        let w = to_wire(&r);
        assert_eq!(w.refusal, "");
        assert_eq!((w.status, w.dialect.as_str(), w.stream, w.has_usage), (200, "openai", true, true));
        assert_eq!((w.input_tokens, w.output_tokens, w.cache_read_tokens), (9, 12, 3));
        assert_eq!((w.provider.as_str(), w.route_host.as_str(), w.requested_model.as_str(), w.served_model.as_str()), ("echo", "llm.bench", "gpt-5", ""));
        assert_eq!((w.request_bytes, w.response_bytes, w.key_id, w.request_id), (100, 200, 7, 42));
        r.tokens = None;
        r.refusal = Some(crate::ai::usage::RefusalKind::BudgetExhausted);
        let w = to_wire(&r);
        assert!(!w.has_usage);
        assert_eq!(w.refusal, "budget_exhausted");
        assert_eq!((w.input_tokens, w.output_tokens), (0, 0));
    }
}
