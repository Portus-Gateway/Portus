//! Portus AI gateway ledger: the companion service that keeps everything
//! with state so the data plane can stay pure. It receives usage records
//! over gRPC and stores them, issues and revokes API keys, and pushes key
//! snapshots to every data plane.
//!
//! Configuration (environment):
//! - `LEDGER_GRPC_ADDR` (default `0.0.0.0:9444`): ingest + key distribution.
//! - `LEDGER_HTTP_ADDR` (default `0.0.0.0:8083`): `/healthz`, `/readyz` and
//!   `/metrics` open; `/export.jsonl?since_us=<µs>&limit=<n>`,
//!   `/v1/summary?hours=&by=key|subject|model|tool|tenant|route`,
//!   `/v1/series?hours=&bucket_secs=&by=`, `/v1/limits` and the key API `/v1/keys`
//!   (`/export.jsonl?after_id=<row id>` pages by row id; the response names
//!   the next cursor in `x-portus-next-after-id`)
//!   (GET, POST, PATCH `/v1/keys/{id}`, DELETE) behind bearer
//!   `LEDGER_ADMIN_TOKEN` (the admin API is disabled when it is unset).
//! - `LEDGER_OPEN_READS=true`: serve `/export.jsonl` and `/v1/summary`
//!   without the token (usage rows name keys, tenants and subjects; only for
//!   a ledger nothing but operators can reach).
//! - `LEDGER_DB_PATH` (default `/data/ledger.db`).
//! - `GRPC_TLS_CERT`, `GRPC_TLS_KEY`: serve TLS; with `GRPC_TLS_CA` require
//!   client certificates (the data planes present the config-stream cert).

mod budget;
mod events;
mod jwks;
mod keys;
mod store;

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use portus_types::proto::portus::ledger::v1::budget_server::{Budget, BudgetServer};
use portus_types::proto::portus::ledger::v1::key_distribution_server::{KeyDistribution, KeyDistributionServer};
use portus_types::proto::portus::ledger::v1::ledger_ingest_server::{LedgerIngest, LedgerIngestServer};
use portus_types::proto::portus::ledger::v1::{
    DeclareAck, KeySnapshot, KeyWatchRequest, PolicyDeclaration, ReportAck, SyncRequest, SyncResponse, UsageBatch,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Status};

use keys::{KeyPatch, KeyRow, NewKey};
use store::{GroupBy, Store};

#[derive(Default)]
struct Stats {
    batches: AtomicU64,
    records: AtomicU64,
    write_errors: AtomicU64,
    syncs: AtomicU64,
    synced_tokens: AtomicU64,
    events_delivered: AtomicU64,
    events_failed: AtomicU64,
    events_dropped: AtomicU64,
    /// Sum of the data planes' own drop counters, as last reported per node.
    dataplane_dropped: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

type Done<T> = oneshot::Sender<rusqlite::Result<T>>;

/// Every storage operation queues to the one SQLite thread.
enum Op {
    Write { node: String, records: Vec<portus_types::proto::portus::ledger::v1::UsageRecord>, done: Done<usize> },
    Export { since: u64, after_id: Option<i64>, limit: usize, done: Done<Vec<store::Row>> },
    Summary { since: u64, by: GroupBy, done: Done<Vec<store::Summary>> },
    Series { since: u64, bucket_micros: u64, by: GroupBy, done: Done<Vec<store::Summary>> },
    Count(Done<u64>),
    IssueKey { new: NewKey, done: Done<(KeyRow, String)> },
    Declare { policies: Vec<budget::Declared>, now_micros: u64, done: Done<usize> },
    DueEvents { now_micros: u64, limit: usize, done: Done<Vec<events::Pending>> },
    EventDelivered { id: i64, done: Done<()> },
    EventFailed { id: i64, attempts: u32, now_micros: u64, done: Done<bool> },
    EventsPending(Done<u64>),
    Limits { now_micros: u64, done: Done<Vec<budget::PolicyLimits>> },
    UpdateKey { id: u64, patch: KeyPatch, done: Done<Option<KeyRow>> },
    RevokeKey { id: u64, done: Done<bool> },
    /// Revoke keys whose expiry has passed; how many.
    ExpireKeys { now_secs: u64, done: Done<usize> },
    ListKeys(Done<Vec<KeyRow>>),
    /// Advance the persisted version and build the snapshot at it.
    NextKeySnapshot(Done<KeySnapshot>),
    SyncSpend { req: SyncRequest, now_micros: u64, done: Done<Option<budget::Synced>> },
    PruneSpend { now_micros: u64, done: Done<usize> },
}

fn storage_thread(mut store: Store, mut ops: mpsc::Receiver<Op>) {
    while let Some(op) = ops.blocking_recv() {
        match op {
            Op::Write { node, records, done } => {
                let _ = done.send(store.insert_batch(&node, &records));
            }
            Op::Export { since, after_id, limit, done } => {
                let _ = done.send(store.export(since, after_id, limit));
            }
            Op::Summary { since, by, done } => {
                let _ = done.send(store.summary(since, by));
            }
            Op::Series { since, bucket_micros, by, done } => {
                let _ = done.send(store.series(since, bucket_micros, by));
            }
            Op::Count(done) => {
                let _ = done.send(store.count());
            }
            Op::IssueKey { new, done } => {
                let _ = done.send(store.issue_key(&new));
            }
            Op::Declare { policies, now_micros, done } => {
                let _ = done.send(store.declare(&policies, now_micros));
            }
            Op::DueEvents { now_micros, limit, done } => {
                let _ = done.send(store.due_events(now_micros, limit));
            }
            Op::EventDelivered { id, done } => {
                let _ = done.send(store.event_delivered(id));
            }
            Op::EventFailed { id, attempts, now_micros, done } => {
                let _ = done.send(store.event_failed(id, attempts, now_micros));
            }
            Op::EventsPending(done) => {
                let _ = done.send(store.events_pending());
            }
            Op::Limits { now_micros, done } => {
                let _ = done.send(store.limits(now_micros));
            }
            Op::UpdateKey { id, patch, done } => {
                let _ = done.send(store.update_key(id, &patch));
            }
            Op::RevokeKey { id, done } => {
                let _ = done.send(store.revoke_key(id));
            }
            Op::ExpireKeys { now_secs, done } => {
                let _ = done.send(store.expire_keys(now_secs));
            }
            Op::ListKeys(done) => {
                let _ = done.send(store.list_keys());
            }
            Op::NextKeySnapshot(done) => {
                let _ = done.send(store.bump_key_version().and_then(|v| store.key_snapshot(v)));
            }
            Op::SyncSpend { req, now_micros, done } => {
                // Data planes before 0.2.9 send no shape; the spend still counts.
                let shape = (req.limit > 0).then(|| budget::Shape { limit: req.limit, unit: req.unit.clone(), per: req.per.clone(), fail_open: req.fail_open, subject_limit: req.subject_limit });
                let _ = done.send(store.sync_spend(&req.policy, &req.subject, &req.window, req.spent_delta, now_micros, shape.as_ref()));
            }
            Op::PruneSpend { now_micros, done } => {
                let _ = done.send(store.prune_spend(now_micros));
            }
        }
    }
}

/// Shared by the gRPC services and the HTTP API.
struct Shared {
    ops: mpsc::Sender<Op>,
    stats: Stats,
    /// Latest key snapshot; every data plane holds the receiver.
    keys: watch::Sender<Arc<KeySnapshot>>,
    key_version: AtomicU64,
    admin_token: Option<String>,
    /// Serve the usage reads without the admin token.
    open_reads: bool,
    /// OAuth issuers' JWKS as last fetched, attached to every key snapshot.
    jwks: std::sync::Mutex<Vec<portus_types::proto::portus::ledger::v1::JwksEntry>>,
}

impl Shared {
    async fn run<T: Send + 'static>(&self, make: impl FnOnce(Done<T>) -> Op) -> Result<T, String> {
        let (tx, rx) = oneshot::channel();
        self.ops.send(make(tx)).await.map_err(|_| "storage thread is gone".to_string())?;
        match rx.await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("storage thread dropped the request".to_string()),
        }
    }

    /// Rebuild and publish the key snapshot after a change. The version is
    /// persisted by the store, so a restarted ledger never republishes a
    /// number a data plane has already seen.
    async fn publish_keys(&self) -> Result<(), String> {
        let mut snapshot = self.run(Op::NextKeySnapshot).await?;
        snapshot.issuers = self.jwks.lock().map(|j| j.clone()).unwrap_or_default();
        self.key_version.store(snapshot.version, Ordering::Relaxed);
        log::info!("key snapshot v{}: {} live keys, {} OAuth issuers", snapshot.version, snapshot.keys.len(), snapshot.issuers.len());
        // send_replace, not send: `send` leaves the value untouched when no
        // data plane is connected, and the next one to connect would get a
        // stale snapshot.
        self.keys.send_replace(Arc::new(snapshot));
        Ok(())
    }
}

// ---- gRPC ----

struct Ingest(Arc<Shared>);

#[tonic::async_trait]
impl LedgerIngest for Ingest {
    async fn report(&self, request: Request<UsageBatch>) -> Result<tonic::Response<ReportAck>, Status> {
        let batch = request.into_inner();
        let n = batch.records.len();
        if let Ok(mut m) = self.0.stats.dataplane_dropped.lock() {
            m.insert(batch.node.clone(), batch.dropped_total);
        }
        match self.0.run(|done| Op::Write { node: batch.node, records: batch.records, done }).await {
            Ok(written) => {
                self.0.stats.batches.fetch_add(1, Ordering::Relaxed);
                self.0.stats.records.fetch_add(written as u64, Ordering::Relaxed);
                Ok(tonic::Response::new(ReportAck { accepted: written as u64 }))
            }
            Err(e) => {
                self.0.stats.write_errors.fetch_add(1, Ordering::Relaxed);
                log::error!("storing a batch of {n} records failed: {e}");
                Err(Status::internal("write failed"))
            }
        }
    }
}

struct Spend(Arc<Shared>);

#[tonic::async_trait]
impl Budget for Spend {
    async fn sync(&self, request: Request<SyncRequest>) -> Result<tonic::Response<SyncResponse>, Status> {
        let req = request.into_inner();
        if req.policy.is_empty() || req.subject.is_empty() {
            return Err(Status::invalid_argument("policy and subject are required"));
        }
        let now = now_micros();
        let delta = req.spent_delta;
        match self.0.run(|done| Op::SyncSpend { req, now_micros: now, done }).await {
            Ok(Some(s)) => {
                self.0.stats.syncs.fetch_add(1, Ordering::Relaxed);
                self.0.stats.synced_tokens.fetch_add(delta, Ordering::Relaxed);
                Ok(tonic::Response::new(SyncResponse { spent_total: s.spent_total, window_end_unix_micros: s.window_end_unix_micros }))
            }
            Ok(None) => Err(Status::invalid_argument("unknown budget window")),
            Err(e) => {
                log::error!("budget sync failed: {e}");
                Err(Status::internal("sync failed"))
            }
        }
    }

    async fn declare(&self, request: Request<PolicyDeclaration>) -> Result<tonic::Response<DeclareAck>, Status> {
        let req = request.into_inner();
        let policies: Vec<budget::Declared> = req
            .policies
            .into_iter()
            .filter(|p| !p.policy.is_empty())
            .map(|p| budget::Declared {
                policy: p.policy,
                window: p.window,
                shape: budget::Shape { limit: p.limit, unit: p.unit, per: p.per, fail_open: p.fail_open, subject_limit: 0 },
            })
            .collect();
        match self.0.run(|done| Op::Declare { policies, now_micros: now_micros(), done }).await {
            Ok(n) => Ok(tonic::Response::new(DeclareAck { accepted: n as u64 })),
            Err(e) => {
                log::error!("policy declaration from {} failed: {e}", req.node);
                Err(Status::internal("declare failed"))
            }
        }
    }
}

fn now_micros() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

struct Keys(Arc<Shared>);

#[tonic::async_trait]
impl KeyDistribution for Keys {
    type WatchKeysStream = Pin<Box<dyn Stream<Item = Result<KeySnapshot, Status>> + Send>>;

    async fn watch_keys(&self, request: Request<KeyWatchRequest>) -> Result<tonic::Response<Self::WatchKeysStream>, Status> {
        let node = request.into_inner().node;
        log::info!("data plane {node} watching API keys");
        // WatchStream yields the current value first, then every change.
        let stream = tokio_stream::wrappers::WatchStream::new(self.0.keys.subscribe()).map(|s| Ok(s.as_ref().clone()));
        Ok(tonic::Response::new(Box::pin(stream)))
    }
}

// ---- HTTP ----

#[derive(Deserialize, Default)]
struct ExportParams {
    #[serde(default)]
    since_us: u64,
    /// Row-id cursor: the rows stored after this one, in id order.
    after_id: Option<i64>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct IssuedKey {
    #[serde(flatten)]
    row: KeyRow,
    /// Shown once.
    key: String,
}

fn admin_ok(shared: &Shared, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let Some(expected) = shared.admin_token.as_deref() else {
        return Err(Box::new((StatusCode::FORBIDDEN, "admin API disabled: set LEDGER_ADMIN_TOKEN").into_response()));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let same: bool = Sha256::digest(presented.as_bytes()).ct_eq(&Sha256::digest(expected.as_bytes())).into();
    if same { Ok(()) } else { Err(Box::new((StatusCode::UNAUTHORIZED, "invalid admin token").into_response())) }
}

fn storage_error(e: String) -> Response {
    log::error!("storage: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
}

async fn health() -> &'static str {
    "ok"
}

async fn metrics(State(shared): State<Arc<Shared>>) -> Response {
    let stored = shared.run(Op::Count).await.unwrap_or(0);
    let dropped: u64 = shared.stats.dataplane_dropped.lock().map(|m| m.values().sum()).unwrap_or(0);
    let live_keys = shared.keys.borrow().keys.len();
    let body = format!(
        "# TYPE ledger_batches_total counter\nledger_batches_total {}\n\
         # TYPE ledger_records_total counter\nledger_records_total {}\n\
         # TYPE ledger_write_errors_total counter\nledger_write_errors_total {}\n\
         # TYPE ledger_records_stored gauge\nledger_records_stored {}\n\
         # TYPE ledger_dataplane_dropped_total gauge\nledger_dataplane_dropped_total {}\n\
         # TYPE ledger_api_keys_live gauge\nledger_api_keys_live {}\n\
         # TYPE ledger_key_snapshot_version gauge\nledger_key_snapshot_version {}\n\
         # TYPE ledger_budget_syncs_total counter\nledger_budget_syncs_total {}\n\
         # TYPE ledger_budget_tokens_total counter\nledger_budget_tokens_total {}\n\
         # TYPE ledger_events_pending gauge\nledger_events_pending {}\n\
         # TYPE ledger_events_delivered_total counter\nledger_events_delivered_total {}\n\
         # TYPE ledger_events_failed_total counter\nledger_events_failed_total {}\n\
         # TYPE ledger_events_dropped_total counter\nledger_events_dropped_total {}\n",
        shared.stats.batches.load(Ordering::Relaxed),
        shared.stats.records.load(Ordering::Relaxed),
        shared.stats.write_errors.load(Ordering::Relaxed),
        stored,
        dropped,
        live_keys,
        shared.key_version.load(Ordering::Relaxed),
        shared.stats.syncs.load(Ordering::Relaxed),
        shared.stats.synced_tokens.load(Ordering::Relaxed),
        shared.run(Op::EventsPending).await.unwrap_or(0),
        shared.stats.events_delivered.load(Ordering::Relaxed),
        shared.stats.events_failed.load(Ordering::Relaxed),
        shared.stats.events_dropped.load(Ordering::Relaxed),
    );
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

/// Usage rows name keys, tenants and subjects, so they are behind the admin
/// token unless the operator opened them on purpose.
fn reads_ok(shared: &Shared, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if shared.open_reads { Ok(()) } else { admin_ok(shared, headers) }
}

async fn export(State(shared): State<Arc<Shared>>, headers: HeaderMap, Query(p): Query<ExportParams>) -> Response {
    if let Err(r) = reads_ok(&shared, &headers) {
        return *r;
    }
    let limit = p.limit.unwrap_or(10_000).clamp(1, 100_000);
    let after_id = p.after_id.map(|a| a.max(0));
    match shared.run(|done| Op::Export { since: p.since_us, after_id, limit, done }).await {
        Ok(rows) => {
            // The cursor for the next page: the last row's id, or the one
            // asked for when there were no newer rows.
            let next = rows.last().map(|r| r.id).or(after_id).unwrap_or(0);
            let mut out = String::new();
            for row in rows {
                if let Ok(line) = serde_json::to_string(&row) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            (
                [(axum::http::header::CONTENT_TYPE, "application/x-ndjson".to_string()), (axum::http::HeaderName::from_static("x-portus-next-after-id"), next.to_string())],
                out,
            )
                .into_response()
        }
        Err(e) => storage_error(e),
    }
}

/// Totals over the last `hours` (default 24), grouped by `by` (default
/// key), biggest spenders first.
async fn summary(State(shared): State<Arc<Shared>>, headers: HeaderMap, Query(p): Query<SummaryParams>) -> Response {
    if let Err(r) = reads_ok(&shared, &headers) {
        return *r;
    }
    let Some(by) = GroupBy::parse(p.by.as_deref().unwrap_or("")) else {
        return (StatusCode::BAD_REQUEST, "by must be key, subject, model, tool, tenant or route").into_response();
    };
    let since = now_micros().saturating_sub(p.hours.unwrap_or(24).clamp(1, 24 * 366) * 3_600_000_000);
    match shared.run(|done| Op::Summary { since, by, done }).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => storage_error(e),
    }
}

/// Totals per time bucket over the last `hours` (default 24), `bucket_secs`
/// wide (default 3600, 60 s to 7 d), grouped by `by` inside each bucket.
async fn series(State(shared): State<Arc<Shared>>, headers: HeaderMap, Query(p): Query<SummaryParams>) -> Response {
    if let Err(r) = reads_ok(&shared, &headers) {
        return *r;
    }
    let Some(by) = GroupBy::parse(p.by.as_deref().unwrap_or("")) else {
        return (StatusCode::BAD_REQUEST, "by must be key, subject, model, tool, tenant or route").into_response();
    };
    let hours = p.hours.unwrap_or(24).clamp(1, 24 * 366);
    let bucket_secs = p.bucket_secs.unwrap_or(3600).clamp(60, 7 * 86_400);
    let since = now_micros().saturating_sub(hours * 3_600_000_000);
    match shared.run(|done| Op::Series { since, bucket_micros: bucket_secs * 1_000_000, by, done }).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => storage_error(e),
    }
}

/// Every budget policy the data planes have synced, with the current
/// window's spend and remaining per subject, and the key overrides in
/// force. What a hub reads instead of the AIUsagePolicy objects.
async fn limits(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    if let Err(r) = reads_ok(&shared, &headers) {
        return *r;
    }
    let now = now_micros();
    let policies = match shared.run(|done| Op::Limits { now_micros: now, done }).await {
        Ok(p) => p,
        Err(e) => return storage_error(e),
    };
    let keys = match shared.run(Op::ListKeys).await {
        Ok(k) => k,
        Err(e) => return storage_error(e),
    };
    let overrides: Vec<KeyBudget> = keys
        .into_iter()
        .filter(|k| k.revoked_unix_micros.is_none() && (k.token_limit.is_some() || k.call_limit.is_some()))
        .map(|k| KeyBudget { key_id: k.id, tenant: k.tenant, name: k.name, token_limit: k.token_limit, call_limit: k.call_limit, labels: k.labels })
        .collect();
    Json(Limits { now_unix_micros: now, policies, key_budgets: overrides }).into_response()
}

#[derive(Serialize)]
struct Limits {
    now_unix_micros: u64,
    policies: Vec<budget::PolicyLimits>,
    /// Live keys with a budget of their own.
    key_budgets: Vec<KeyBudget>,
}

#[derive(Serialize)]
struct KeyBudget {
    key_id: u64,
    tenant: String,
    name: String,
    token_limit: Option<u64>,
    call_limit: Option<u64>,
    #[serde(skip_serializing_if = "keys::Labels::is_empty")]
    labels: keys::Labels,
}

#[derive(Deserialize, Default)]
struct SummaryParams {
    hours: Option<u64>,
    by: Option<String>,
    bucket_secs: Option<u64>,
}

async fn issue_key(State(shared): State<Arc<Shared>>, headers: HeaderMap, Json(mut new): Json<NewKey>) -> Response {
    if let Err(r) = admin_ok(&shared, &headers) {
        return *r;
    }
    new.tenant = new.tenant.trim().to_string();
    new.name = new.name.trim().to_string();
    new.plaintext = new.plaintext.as_deref().map(str::trim).map(str::to_string);
    if new.name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    if new.plaintext.as_deref().is_some_and(|k| k.len() < 16) {
        return (StatusCode::BAD_REQUEST, "an imported key must be at least 16 characters").into_response();
    }
    if let Err(e) = keys::validate_labels(&new.labels) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    let issued = shared.run(|done| Op::IssueKey { new, done }).await;
    match issued {
        Ok((row, key)) => {
            if let Err(e) = shared.publish_keys().await {
                return storage_error(e);
            }
            (StatusCode::CREATED, Json(IssuedKey { row, key })).into_response()
        }
        Err(e) if e.contains("UNIQUE") => (StatusCode::CONFLICT, "a key with this value already exists").into_response(),
        Err(e) => storage_error(e),
    }
}

async fn list_keys(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    if let Err(r) = admin_ok(&shared, &headers) {
        return *r;
    }
    match shared.run(Op::ListKeys).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => storage_error(e),
    }
}

/// Change a live key's tenant, name, allow lists or expiry in place; the
/// plaintext stays valid and the data planes pick the change up with the
/// next snapshot, so nothing restarts.
async fn update_key(State(shared): State<Arc<Shared>>, headers: HeaderMap, Path(id): Path<u64>, Json(patch): Json<KeyPatch>) -> Response {
    if let Err(r) = admin_ok(&shared, &headers) {
        return *r;
    }
    if patch.name.as_deref().is_some_and(|n| n.trim().is_empty()) {
        return (StatusCode::BAD_REQUEST, "name cannot be empty").into_response();
    }
    if let Some(Err(e)) = patch.labels.as_ref().map(keys::validate_labels) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    match shared.run(|done| Op::UpdateKey { id, patch, done }).await {
        Ok(Some(row)) => match shared.publish_keys().await {
            Ok(()) => Json(row).into_response(),
            Err(e) => storage_error(e),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "no live key with that id").into_response(),
        Err(e) => storage_error(e),
    }
}

async fn revoke_key(State(shared): State<Arc<Shared>>, headers: HeaderMap, Path(id): Path<u64>) -> Response {
    if let Err(r) = admin_ok(&shared, &headers) {
        return *r;
    }
    match shared.run(|done| Op::RevokeKey { id, done }).await {
        Ok(true) => match shared.publish_keys().await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => storage_error(e),
        },
        Ok(false) => (StatusCode::NOT_FOUND, "no live key with that id").into_response(),
        Err(e) => storage_error(e),
    }
}

fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/metrics", get(metrics))
        .route("/export.jsonl", get(export))
        .route("/v1/summary", get(summary))
        .route("/v1/series", get(series))
        .route("/v1/limits", get(limits))
        .route("/v1/keys", get(list_keys).post(issue_key))
        .route("/v1/keys/{id}", axum::routing::delete(revoke_key).patch(update_key))
        .with_state(shared)
}

/// Deliver outbox events in id order: POST each one, delete it on a 2xx,
/// back off on anything else, drop it after `events::MAX_ATTEMPTS`.
async fn deliver_events(shared: Arc<Shared>, url: String, secret: Option<String>) {
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(e) => {
            log::error!("webhook client: {e}; no events will be delivered");
            return;
        }
    };
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tick.tick().await;
        let due = match shared.run(|done| Op::DueEvents { now_micros: now_micros(), limit: 100, done }).await {
            Ok(d) => d,
            Err(e) => {
                log::warn!("reading the event outbox: {e}");
                continue;
            }
        };
        for event in due {
            let mut req = client
                .post(&url)
                .header("content-type", "application/json")
                .header("x-portus-event-id", event.id.to_string())
                .body(event.body.clone());
            if let Some(s) = &secret {
                req = req.header("x-portus-signature", events::signature(s, &event.body));
            }
            let outcome = match req.send().await {
                Ok(resp) if resp.status().is_success() => Ok(()),
                Ok(resp) => Err(format!("answered {}", resp.status())),
                Err(e) => Err(e.to_string()),
            };
            let (id, attempts) = (event.id, event.attempts);
            match outcome {
                Ok(()) => {
                    shared.stats.events_delivered.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = shared.run(|done| Op::EventDelivered { id, done }).await {
                        log::warn!("event {id} delivered but not cleared: {e}; it will be sent again");
                    }
                }
                Err(why) => {
                    shared.stats.events_failed.fetch_add(1, Ordering::Relaxed);
                    match shared.run(|done| Op::EventFailed { id, attempts, now_micros: now_micros(), done }).await {
                        Ok(true) => {
                            shared.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                            log::error!("event {id} dropped after {} attempts to {url}: {why}", events::MAX_ATTEMPTS);
                        }
                        Ok(false) => log::warn!("event {id} to {url} failed (attempt {}): {why}", attempts + 1),
                        Err(e) => log::warn!("event {id}: {e}"),
                    }
                    // The receiver is down: stop this round, keep the order.
                    break;
                }
            }
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| default.to_string())
}

fn server_tls() -> Option<tonic::transport::ServerTlsConfig> {
    let (cert_path, key_path) = (std::env::var("GRPC_TLS_CERT").ok()?, std::env::var("GRPC_TLS_KEY").ok()?);
    let cert = std::fs::read_to_string(&cert_path).unwrap_or_else(|e| panic!("failed to read GRPC_TLS_CERT at {cert_path}: {e}"));
    let key = std::fs::read_to_string(&key_path).unwrap_or_else(|e| panic!("failed to read GRPC_TLS_KEY at {key_path}: {e}"));
    let mut tls = tonic::transport::ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(cert, key));
    if let Ok(ca_path) = std::env::var("GRPC_TLS_CA") {
        let ca = std::fs::read_to_string(&ca_path).unwrap_or_else(|e| panic!("failed to read GRPC_TLS_CA at {ca_path}: {e}"));
        tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(ca));
        log::info!("ledger gRPC mTLS enabled (client certs required)");
    }
    Some(tls)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // tonic and reqwest both use rustls; one process-wide provider, chosen here.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let db_path = PathBuf::from(env_or("LEDGER_DB_PATH", "/data/ledger.db"));
    let grpc_addr: std::net::SocketAddr = env_or("LEDGER_GRPC_ADDR", "0.0.0.0:9444").parse()?;
    let http_addr = env_or("LEDGER_HTTP_ADDR", "0.0.0.0:8083");
    let admin_token = std::env::var("LEDGER_ADMIN_TOKEN").ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    let open_reads = std::env::var("LEDGER_OPEN_READS").ok().is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    if open_reads {
        log::warn!("LEDGER_OPEN_READS is set: /export.jsonl and /v1/summary answer without the admin token");
    }

    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Budget and refusal events for a webhook, when one is configured.
    let webhook_url = std::env::var("LEDGER_WEBHOOK_URL").ok().map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    let webhook_secret = std::env::var("LEDGER_WEBHOOK_SECRET").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let mut store = Store::open(&db_path)?;
    if let Some(url) = &webhook_url {
        let config = events::EventConfig::parse(
            &env_or("LEDGER_WEBHOOK_THRESHOLDS", "80,100"),
            &env_or("LEDGER_WEBHOOK_REFUSALS", "model_not_allowed,tool_not_allowed,budget_exhausted"),
        )?;
        log::info!("budget events to {url}: thresholds {:?}%, refusals {:?}{}", config.thresholds, config.refusals, if webhook_secret.is_some() { ", signed" } else { ", UNSIGNED (set LEDGER_WEBHOOK_SECRET)" });
        store = store.with_events(config);
    }
    let initial = store.key_snapshot(store.key_version()?)?;
    log::info!("ledger store at {} ({} live API keys, key snapshot v{})", db_path.display(), initial.keys.len(), initial.version);

    let (ops_tx, ops_rx) = mpsc::channel::<Op>(1024);
    std::thread::Builder::new().name("ledger-storage".into()).spawn(move || storage_thread(store, ops_rx))?;
    let (keys_tx, _keys_rx) = watch::channel(Arc::new(initial));
    let initial_version = keys_tx.borrow().version;
    let shared = Arc::new(Shared { ops: ops_tx, stats: Stats::default(), keys: keys_tx, key_version: AtomicU64::new(initial_version), admin_token, open_reads, jwks: std::sync::Mutex::new(Vec::new()) });
    if shared.admin_token.is_none() {
        log::warn!("LEDGER_ADMIN_TOKEN is not set; the key admin API is disabled");
    }
    // OAuth issuers: fetch their JWKS now and every few minutes; a change
    // goes out in a new key snapshot.
    let issuers = jwks::issuers_from_env(&std::env::var("LEDGER_JWT_ISSUERS").unwrap_or_default());
    if !issuers.is_empty() {
        log::info!("OAuth issuers: {}", issuers.join(", "));
        let refresher = Arc::clone(&shared);
        tokio::spawn(async move {
            let client = jwks::client();
            let mut tick = tokio::time::interval(jwks::REFRESH_INTERVAL);
            loop {
                tick.tick().await;
                let current = refresher.jwks.lock().map(|j| j.clone()).unwrap_or_default();
                let fresh = jwks::refresh(&client, &issuers, &current).await;
                if fresh != current {
                    if let Ok(mut j) = refresher.jwks.lock() {
                        *j = fresh;
                    }
                    if let Err(e) = refresher.publish_keys().await {
                        log::warn!("publishing JWKS: {e}");
                    }
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&http_addr).await?;
    log::info!("ledger HTTP endpoint listening on {http_addr}");
    tokio::spawn(axum::serve(listener, router(Arc::clone(&shared))).into_future());
    // Keys expire on their own: every minute, revoke the ones whose time has
    // passed and push a snapshot without them.
    let expirer = Arc::clone(&shared);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            match expirer.run(|done| Op::ExpireKeys { now_secs: now_micros() / 1_000_000, done }).await {
                Ok(n) if n > 0 => {
                    log::info!("{n} API key(s) expired");
                    if let Err(e) = expirer.publish_keys().await {
                        log::warn!("publishing keys after expiry: {e}");
                    }
                }
                Ok(_) => {}
                Err(e) => log::warn!("expiring keys: {e}"),
            }
        }
    });
    if let Some(url) = webhook_url {
        tokio::spawn(deliver_events(Arc::clone(&shared), url, webhook_secret));
    }
    // Closed budget windows are dead weight; sweep them hourly.
    let sweeper = Arc::clone(&shared);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            if let Ok(n) = sweeper.run(|done| Op::PruneSpend { now_micros: now_micros(), done }).await
                && n > 0
            {
                log::info!("pruned {n} closed budget windows");
            }
        }
    });

    let mut builder = tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(15)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(60)));
    match server_tls() {
        Some(tls) => {
            builder = builder.tls_config(tls)?;
            log::info!("ledger gRPC TLS enabled");
        }
        None => log::warn!("ledger gRPC ingest running WITHOUT TLS; set GRPC_TLS_CERT and GRPC_TLS_KEY"),
    }
    log::info!("ledger gRPC listening on {grpc_addr}");
    builder
        .add_service(LedgerIngestServer::new(Ingest(Arc::clone(&shared))).max_decoding_message_size(16 * 1024 * 1024))
        .add_service(KeyDistributionServer::new(Keys(Arc::clone(&shared))))
        .add_service(BudgetServer::new(Spend(shared)))
        .serve(grpc_addr)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    async fn app() -> (Router, Arc<Shared>) {
        let store = Store::in_memory().unwrap();
        let initial = store.key_snapshot(store.key_version().unwrap()).unwrap();
        let (ops_tx, ops_rx) = mpsc::channel::<Op>(64);
        std::thread::spawn(move || storage_thread(store, ops_rx));
        let (keys_tx, _rx) = watch::channel(Arc::new(initial));
        let shared = Arc::new(Shared {
            ops: ops_tx,
            stats: Stats::default(),
            keys: keys_tx,
            key_version: AtomicU64::new(1),
            admin_token: Some("secret-admin".into()),
            open_reads: false,
            jwks: std::sync::Mutex::new(Vec::new()),
        });
        (router(Arc::clone(&shared)), shared)
    }

    #[tokio::test]
    async fn export_pages_by_row_id_and_names_the_next_cursor() {
        let (app, shared) = app().await;
        let rows: Vec<portus_types::proto::portus::ledger::v1::UsageRecord> =
            (0..3).map(|i| portus_types::proto::portus::ledger::v1::UsageRecord { ts_unix_micros: 5, dialect: "anthropic".into(), request_id: i, ..Default::default() }).collect();
        shared.run(|done| Op::Write { node: "pod".into(), records: rows, done }).await.unwrap();
        let page = |after: i64| {
            let app = app.clone();
            async move {
                let req = HttpRequest::builder().uri(format!("/export.jsonl?after_id={after}&limit=2")).header("authorization", "Bearer secret-admin").body(Body::empty()).unwrap();
                let resp = app.oneshot(req).await.unwrap();
                let next: i64 = resp.headers().get("x-portus-next-after-id").unwrap().to_str().unwrap().parse().unwrap();
                let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
                (String::from_utf8_lossy(&body).lines().count(), next)
            }
        };
        let (n1, c1) = page(0).await;
        let (n2, c2) = page(c1).await;
        let (n3, c3) = page(c2).await;
        assert_eq!((n1, n2, n3), (2, 1, 0), "three rows with one timestamp, each once");
        assert_eq!(c3, c2, "an empty page keeps the cursor");
    }

    #[tokio::test]
    async fn usage_reads_need_the_admin_token_unless_opened_on_purpose() {
        let (app, shared) = app().await;
        for uri in ["/export.jsonl?limit=10", "/v1/summary?hours=1"] {
            assert_eq!(call(&app, "GET", uri, None, None).await.0, StatusCode::UNAUTHORIZED, "{uri} without a token");
            assert_eq!(call(&app, "GET", uri, Some("Bearer wrong"), None).await.0, StatusCode::UNAUTHORIZED, "{uri} with a wrong token");
            assert_eq!(call(&app, "GET", uri, Some("Bearer secret-admin"), None).await.0, StatusCode::OK, "{uri} with the token");
        }
        assert_eq!(call(&app, "GET", "/metrics", None, None).await.0, StatusCode::OK, "metrics stay open");
        assert_eq!(call(&app, "GET", "/healthz", None, None).await.0, StatusCode::OK);
        // No admin token configured: the reads are closed, not open.
        let closed = Arc::new(Shared { ops: shared.ops.clone(), stats: Stats::default(), keys: watch::channel(Arc::new(KeySnapshot::default())).0, key_version: AtomicU64::new(1), admin_token: None, open_reads: false, jwks: std::sync::Mutex::new(Vec::new()) });
        assert_eq!(call(&router(closed), "GET", "/v1/summary", None, None).await.0, StatusCode::FORBIDDEN);
        // The explicit opt-out serves them to anyone.
        let open = Arc::new(Shared { ops: shared.ops.clone(), stats: Stats::default(), keys: watch::channel(Arc::new(KeySnapshot::default())).0, key_version: AtomicU64::new(1), admin_token: None, open_reads: true, jwks: std::sync::Mutex::new(Vec::new()) });
        assert_eq!(call(&router(open), "GET", "/export.jsonl", None, None).await.0, StatusCode::OK);
    }

    async fn call(app: &Router, method: &str, uri: &str, auth: Option<&str>, body: Option<&str>) -> (StatusCode, String) {
        let mut req = HttpRequest::builder().method(method).uri(uri);
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        let resp = app.clone().oneshot(req.body(Body::from(body.unwrap_or("").to_string())).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn keys_are_issued_listed_revoked_and_pushed_as_snapshots() {
        let (app, shared) = app().await;
        let mut rx = shared.keys.subscribe();
        assert_eq!(rx.borrow_and_update().keys.len(), 0);

        let (status, body) = call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"tenant":"team-a","name":"ci","allowed_models":["claude-haiku-4-5"],"allowed_tools":["github.*"]}"#)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let issued: serde_json::Value = serde_json::from_str(&body).unwrap();
        let key = issued["key"].as_str().unwrap().to_string();
        assert!(key.starts_with(keys::KEY_PREFIX));
        let id = issued["id"].as_u64().unwrap();

        rx.changed().await.unwrap();
        let snap = rx.borrow_and_update().clone();
        assert_eq!((snap.version, snap.keys.len()), (2, 1));
        assert_eq!(snap.keys[0].hash_sha256, keys::hash_key(&key).to_vec());
        assert_eq!(snap.keys[0].allowed_models, vec!["claude-haiku-4-5".to_string()]);
        assert_eq!(snap.keys[0].allowed_tools, vec!["github.*".to_string()]);

        let (status, body) = call(&app, "GET", "/v1/keys", Some("Bearer secret-admin"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"name\":\"ci\"") && !body.contains(&key), "listing never shows the plaintext: {body}");

        // PATCH changes the lists in place: same key, new snapshot.
        let (status, body) = call(&app, "PATCH", &format!("/v1/keys/{id}"), Some("Bearer secret-admin"), Some(r#"{"allowed_models":["claude-opus-5"],"expires_in_secs":3600}"#)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let patched: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(patched["allowed_models"], serde_json::json!(["claude-opus-5"]));
        assert_eq!(patched["allowed_tools"], serde_json::json!(["github.*"]), "untouched fields stay");
        assert!(patched["expires_unix_secs"].as_u64().is_some());
        assert!(!body.contains(&key), "a patch never shows the plaintext");
        rx.changed().await.unwrap();
        let snap = rx.borrow_and_update().clone();
        assert_eq!((snap.version, snap.keys.len()), (3, 1));
        assert_eq!(snap.keys[0].hash_sha256, keys::hash_key(&key).to_vec(), "the same key keeps working");
        assert_eq!(snap.keys[0].allowed_models, vec!["claude-opus-5".to_string()]);
        assert!(snap.keys[0].expires_unix_secs > 0);
        assert_eq!(call(&app, "PATCH", "/v1/keys/12345", Some("Bearer secret-admin"), Some("{}")).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&app, "PATCH", &format!("/v1/keys/{id}"), Some("Bearer secret-admin"), Some(r#"{"name":" "}"#)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, "PATCH", &format!("/v1/keys/{id}"), None, Some("{}")).await.0, StatusCode::UNAUTHORIZED);

        let (status, _) = call(&app, "DELETE", &format!("/v1/keys/{id}"), Some("Bearer secret-admin"), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().keys.len(), 0);
        let (status, _) = call(&app, "DELETE", &format!("/v1/keys/{id}"), Some("Bearer secret-admin"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_admin_api_needs_the_token_and_validates_input() {
        let (app, _) = app().await;
        assert_eq!(call(&app, "GET", "/v1/keys", None, None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, "GET", "/v1/keys", Some("Bearer wrong"), None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"name":"  "}"#)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"name":"x","key":"short"}"#)).await.0, StatusCode::BAD_REQUEST);
        let (status, body) = call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"name":"ext","key":"sk-external-0123456789"}"#)).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(body.contains("\"external\":true") && body.contains("sk-external-0123456789"));
        assert_eq!(call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"name":"again","key":"sk-external-0123456789"}"#)).await.0, StatusCode::CONFLICT);
        assert_eq!(call(&app, "GET", "/healthz", None, None).await, (StatusCode::OK, "ok".to_string()));
        let (status, body) = call(&app, "GET", "/metrics", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("ledger_api_keys_live 1"), "{body}");
        let (status, body) = call(&app, "GET", "/v1/summary?hours=1", Some("Bearer secret-admin"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "[]", "no usage yet");
        assert_eq!(call(&app, "GET", "/v1/summary?by=subject", Some("Bearer secret-admin"), None).await.0, StatusCode::OK);
        assert_eq!(call(&app, "GET", "/v1/summary?by=bogus", Some("Bearer secret-admin"), None).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, "GET", "/v1/series?bucket_secs=300&by=model", Some("Bearer secret-admin"), None).await, (StatusCode::OK, "[]".to_string()));
        assert_eq!(call(&app, "GET", "/v1/series", None, None).await.0, StatusCode::UNAUTHORIZED, "the series is a usage read");
        assert_eq!(call(&app, "GET", "/v1/limits", None, None).await.0, StatusCode::UNAUTHORIZED, "limits name keys");
    }

    #[tokio::test]
    async fn limits_list_synced_policies_and_key_budgets() {
        let (app, shared) = app().await;
        let (status, body) = call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"tenant":"team-a","name":"big","token_limit":200000000,"call_limit":50,"labels":{"expert":"ns"}}"#)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_u64().unwrap();
        let (status, body) = call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"tenant":"team-a","name":"plain"}"#)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        // A data plane syncs the big key's spend under a daily policy.
        let spend = Spend(Arc::clone(&shared));
        let req = SyncRequest { node: "pod".into(), policy: "llm/daily".into(), subject: id.to_string(), window: "DAILY".into(), spent_delta: 1_500, limit: 1_000_000, unit: "TOKENS".into(), per: "KEY".into(), fail_open: true, subject_limit: 200_000_000 };
        assert_eq!(spend.sync(Request::new(req)).await.unwrap().into_inner().spent_total, 1_500);
        let (status, body) = call(&app, "GET", "/v1/limits", Some("Bearer secret-admin"), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["policies"][0]["policy"], "llm/daily");
        assert_eq!((v["policies"][0]["limit"].as_u64(), v["policies"][0]["unit"].as_str(), v["policies"][0]["per"].as_str()), (Some(1_000_000), Some("TOKENS"), Some("KEY")));
        let s = &v["policies"][0]["subjects"][0];
        assert_eq!((s["subject"].as_str(), s["limit"].as_u64(), s["spent"].as_u64(), s["remaining"].as_i64()), (Some(id.to_string().as_str()), Some(200_000_000), Some(1_500), Some(199_998_500)));
        assert_eq!(v["key_budgets"].as_array().unwrap().len(), 1, "only keys with their own budget: {body}");
        assert_eq!((v["key_budgets"][0]["name"].as_str(), v["key_budgets"][0]["token_limit"].as_u64(), v["key_budgets"][0]["call_limit"].as_u64()), (Some("big"), Some(200_000_000), Some(50)));
        assert_eq!(v["key_budgets"][0]["labels"]["expert"], "ns");
        // The snapshot carries both limits and the labels to the data planes.
        let entry = shared.keys.borrow().keys.iter().find(|k| k.id == id).unwrap().clone();
        assert_eq!((entry.token_limit, entry.call_limit, entry.labels.get("expert").map(String::as_str)), (200_000_000, 50, Some("ns")));
        // A declared policy shows before any spend.
        let ack = spend.declare(Request::new(PolicyDeclaration { node: "pod".into(), policies: vec![portus_types::proto::portus::ledger::v1::DeclaredPolicy { policy: "mcp/calls".into(), limit: 100, unit: "CALLS".into(), window: "DAILY".into(), per: "SUBJECT".into(), fail_open: false }] })).await.unwrap().into_inner();
        assert_eq!(ack.accepted, 1);
        let (_, body) = call(&app, "GET", "/v1/limits", Some("Bearer secret-admin"), None).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let calls = v["policies"].as_array().unwrap().iter().find(|p| p["policy"] == "mcp/calls").expect("declared policy listed").clone();
        assert_eq!((calls["limit"].as_u64(), calls["subjects"].as_array().map(Vec::len)), (Some(100), Some(0)));
        // Bad labels are refused on POST and PATCH.
        assert_eq!(call(&app, "POST", "/v1/keys", Some("Bearer secret-admin"), Some(r#"{"name":"x","labels":{"bad key":"v"}}"#)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, "PATCH", &format!("/v1/keys/{id}"), Some("Bearer secret-admin"), Some(r#"{"labels":{"":"v"}}"#)).await.0, StatusCode::BAD_REQUEST);
    }
}
