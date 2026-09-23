//! Portus AI gateway ledger: the companion service that keeps everything
//! with state so the data plane can stay pure. It receives usage records
//! over gRPC and stores them, issues and revokes API keys, and pushes key
//! snapshots to every data plane.
//!
//! Configuration (environment):
//! - `LEDGER_GRPC_ADDR` (default `0.0.0.0:9444`): ingest + key distribution.
//! - `LEDGER_HTTP_ADDR` (default `0.0.0.0:8083`): `/healthz`, `/readyz`,
//!   `/metrics`, `/export.jsonl?since_us=<µs>&limit=<n>`, and the admin API
//!   `/v1/keys` (bearer `LEDGER_ADMIN_TOKEN`; disabled when unset).
//! - `LEDGER_DB_PATH` (default `/data/ledger.db`).
//! - `GRPC_TLS_CERT`, `GRPC_TLS_KEY`: serve TLS; with `GRPC_TLS_CA` require
//!   client certificates (the data planes present the config-stream cert).

mod budget;
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
use portus_types::proto::portus::ledger::v1::{KeySnapshot, KeyWatchRequest, ReportAck, SyncRequest, SyncResponse, UsageBatch};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Status};

use keys::KeyRow;
use store::Store;

#[derive(Default)]
struct Stats {
    batches: AtomicU64,
    records: AtomicU64,
    write_errors: AtomicU64,
    syncs: AtomicU64,
    synced_tokens: AtomicU64,
    /// Sum of the data planes' own drop counters, as last reported per node.
    dataplane_dropped: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

type Done<T> = oneshot::Sender<rusqlite::Result<T>>;

/// Every storage operation queues to the one SQLite thread.
enum Op {
    Write { node: String, records: Vec<portus_types::proto::portus::ledger::v1::UsageRecord>, done: Done<usize> },
    Export { since: u64, limit: usize, done: Done<Vec<store::Row>> },
    Summary { since: u64, done: Done<Vec<store::KeySummary>> },
    Count(Done<u64>),
    IssueKey { tenant: String, name: String, models: Vec<String>, tools: Vec<String>, plaintext: Option<String>, done: Done<(KeyRow, String)> },
    RevokeKey { id: u64, done: Done<bool> },
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
            Op::Export { since, limit, done } => {
                let _ = done.send(store.export(since, limit));
            }
            Op::Summary { since, done } => {
                let _ = done.send(store.summary(since));
            }
            Op::Count(done) => {
                let _ = done.send(store.count());
            }
            Op::IssueKey { tenant, name, models, tools, plaintext, done } => {
                let _ = done.send(store.issue_key(&tenant, &name, &models, &tools, plaintext.as_deref()));
            }
            Op::RevokeKey { id, done } => {
                let _ = done.send(store.revoke_key(id));
            }
            Op::ListKeys(done) => {
                let _ = done.send(store.list_keys());
            }
            Op::NextKeySnapshot(done) => {
                let _ = done.send(store.bump_key_version().and_then(|v| store.key_snapshot(v)));
            }
            Op::SyncSpend { req, now_micros, done } => {
                let _ = done.send(store.sync_spend(&req.policy, &req.subject, &req.window, req.spent_delta, now_micros));
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
        let snapshot = self.run(Op::NextKeySnapshot).await?;
        self.key_version.store(snapshot.version, Ordering::Relaxed);
        log::info!("key snapshot v{}: {} live keys", snapshot.version, snapshot.keys.len());
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
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct IssueKeyRequest {
    #[serde(default)]
    tenant: String,
    name: String,
    #[serde(default)]
    allowed_models: Vec<String>,
    /// MCP tools the key may call (`tools/call` names, exact or `prefix.*`).
    #[serde(default)]
    allowed_tools: Vec<String>,
    /// An externally issued key to accept as-is; omitted to generate one.
    #[serde(default)]
    key: Option<String>,
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
         # TYPE ledger_budget_tokens_total counter\nledger_budget_tokens_total {}\n",
        shared.stats.batches.load(Ordering::Relaxed),
        shared.stats.records.load(Ordering::Relaxed),
        shared.stats.write_errors.load(Ordering::Relaxed),
        stored,
        dropped,
        live_keys,
        shared.key_version.load(Ordering::Relaxed),
        shared.stats.syncs.load(Ordering::Relaxed),
        shared.stats.synced_tokens.load(Ordering::Relaxed),
    );
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

async fn export(State(shared): State<Arc<Shared>>, Query(p): Query<ExportParams>) -> Response {
    let limit = p.limit.unwrap_or(10_000).clamp(1, 100_000);
    match shared.run(|done| Op::Export { since: p.since_us, limit, done }).await {
        Ok(rows) => {
            let mut out = String::new();
            for row in rows {
                if let Ok(line) = serde_json::to_string(&row) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            ([(axum::http::header::CONTENT_TYPE, "application/x-ndjson")], out).into_response()
        }
        Err(e) => storage_error(e),
    }
}

/// Per-key totals over the last `hours` (default 24), newest spenders first.
/// Read-only, so no admin token: it names keys and tenants, never plaintext.
async fn summary(State(shared): State<Arc<Shared>>, Query(p): Query<SummaryParams>) -> Response {
    let hours = p.hours.unwrap_or(24).clamp(1, 24 * 366);
    let since = now_micros().saturating_sub(hours * 3_600_000_000);
    match shared.run(|done| Op::Summary { since, done }).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => storage_error(e),
    }
}

#[derive(Deserialize, Default)]
struct SummaryParams {
    hours: Option<u64>,
}

async fn issue_key(State(shared): State<Arc<Shared>>, headers: HeaderMap, Json(req): Json<IssueKeyRequest>) -> Response {
    if let Err(r) = admin_ok(&shared, &headers) {
        return *r;
    }
    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    if req.key.as_deref().is_some_and(|k| k.trim().len() < 16) {
        return (StatusCode::BAD_REQUEST, "an imported key must be at least 16 characters").into_response();
    }
    let issued = shared
        .run(|done| Op::IssueKey {
            tenant: req.tenant.trim().to_string(),
            name: req.name.trim().to_string(),
            models: req.allowed_models.clone(),
            tools: req.allowed_tools.clone(),
            plaintext: req.key.as_deref().map(str::trim).map(str::to_string),
            done,
        })
        .await;
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
        .route("/v1/keys", get(list_keys).post(issue_key))
        .route("/v1/keys/{id}", axum::routing::delete(revoke_key))
        .with_state(shared)
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

    let db_path = PathBuf::from(env_or("LEDGER_DB_PATH", "/data/ledger.db"));
    let grpc_addr: std::net::SocketAddr = env_or("LEDGER_GRPC_ADDR", "0.0.0.0:9444").parse()?;
    let http_addr = env_or("LEDGER_HTTP_ADDR", "0.0.0.0:8083");
    let admin_token = std::env::var("LEDGER_ADMIN_TOKEN").ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());

    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let store = Store::open(&db_path)?;
    let initial = store.key_snapshot(store.key_version()?)?;
    log::info!("ledger store at {} ({} live API keys, key snapshot v{})", db_path.display(), initial.keys.len(), initial.version);

    let (ops_tx, ops_rx) = mpsc::channel::<Op>(1024);
    std::thread::Builder::new().name("ledger-storage".into()).spawn(move || storage_thread(store, ops_rx))?;
    let (keys_tx, _keys_rx) = watch::channel(Arc::new(initial));
    let initial_version = keys_tx.borrow().version;
    let shared = Arc::new(Shared { ops: ops_tx, stats: Stats::default(), keys: keys_tx, key_version: AtomicU64::new(initial_version), admin_token });
    if shared.admin_token.is_none() {
        log::warn!("LEDGER_ADMIN_TOKEN is not set; the key admin API is disabled");
    }

    let listener = tokio::net::TcpListener::bind(&http_addr).await?;
    log::info!("ledger HTTP endpoint listening on {http_addr}");
    tokio::spawn(axum::serve(listener, router(Arc::clone(&shared))).into_future());
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
        });
        (router(Arc::clone(&shared)), shared)
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
        let (status, body) = call(&app, "GET", "/v1/summary?hours=1", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "[]", "no usage yet");
    }
}
