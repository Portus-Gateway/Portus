//! Portus AI gateway ledger: the companion service that keeps everything
//! with state so the data plane can stay pure. This slice receives usage
//! records over gRPC and stores them; keys and budgets come later.
//!
//! Configuration (environment):
//! - `LEDGER_GRPC_ADDR` (default `0.0.0.0:9444`): ingest listener.
//! - `LEDGER_HTTP_ADDR` (default `0.0.0.0:8083`): `/healthz`, `/readyz`,
//!   `/metrics`, `/export.jsonl?since_us=<µs>&limit=<n>`.
//! - `LEDGER_DB_PATH` (default `/data/ledger.db`).
//! - `GRPC_TLS_CERT`, `GRPC_TLS_KEY`: serve TLS; with `GRPC_TLS_CA` require
//!   client certificates (the data planes present the config-stream cert).

mod store;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use portus_types::proto::portus::ledger::v1::ledger_ingest_server::{LedgerIngest, LedgerIngestServer};
use portus_types::proto::portus::ledger::v1::{ReportAck, UsageBatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use store::Store;

#[derive(Default)]
struct Stats {
    batches: AtomicU64,
    records: AtomicU64,
    write_errors: AtomicU64,
    /// Sum of the data planes' own drop counters, as last reported per node.
    dataplane_dropped: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

/// One write request to the storage thread.
struct Write {
    node: String,
    records: Vec<portus_types::proto::portus::ledger::v1::UsageRecord>,
    done: oneshot::Sender<rusqlite::Result<usize>>,
}

/// One read request to the storage thread.
struct Read {
    since: u64,
    limit: usize,
    done: oneshot::Sender<rusqlite::Result<Vec<store::Row>>>,
}

enum Op {
    Write(Write),
    Read(Read),
    Count(oneshot::Sender<rusqlite::Result<u64>>),
}

/// SQLite wants one connection on one thread; every operation queues here.
fn storage_thread(mut store: Store, mut ops: mpsc::Receiver<Op>) {
    while let Some(op) = ops.blocking_recv() {
        match op {
            Op::Write(w) => {
                let _ = w.done.send(store.insert_batch(&w.node, &w.records));
            }
            Op::Read(r) => {
                let _ = r.done.send(store.export(r.since, r.limit));
            }
            Op::Count(done) => {
                let _ = done.send(store.count());
            }
        }
    }
}

struct Ingest {
    ops: mpsc::Sender<Op>,
    stats: Arc<Stats>,
}

#[tonic::async_trait]
impl LedgerIngest for Ingest {
    async fn report(&self, request: Request<UsageBatch>) -> Result<Response<ReportAck>, Status> {
        let batch = request.into_inner();
        let n = batch.records.len();
        if let Ok(mut m) = self.stats.dataplane_dropped.lock() {
            m.insert(batch.node.clone(), batch.dropped_total);
        }
        let (tx, rx) = oneshot::channel();
        self.ops
            .send(Op::Write(Write { node: batch.node, records: batch.records, done: tx }))
            .await
            .map_err(|_| Status::unavailable("storage thread is gone"))?;
        match rx.await {
            Ok(Ok(written)) => {
                self.stats.batches.fetch_add(1, Ordering::Relaxed);
                self.stats.records.fetch_add(written as u64, Ordering::Relaxed);
                Ok(Response::new(ReportAck { accepted: written as u64 }))
            }
            Ok(Err(e)) => {
                self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
                log::error!("storing a batch of {n} records failed: {e}");
                Err(Status::internal("write failed"))
            }
            Err(_) => Err(Status::unavailable("storage thread dropped the request")),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| default.to_string())
}

/// Parse `?since_us=..&limit=..` from a request target.
fn export_params(target: &str) -> (u64, usize) {
    let mut since = 0u64;
    let mut limit = 10_000usize;
    if let Some((_, query)) = target.split_once('?') {
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("since_us", v)) => since = v.parse().unwrap_or(0),
                Some(("limit", v)) => limit = v.parse::<usize>().unwrap_or(10_000).clamp(1, 100_000),
                _ => {}
            }
        }
    }
    (since, limit)
}

async fn http_server(addr: String, ops: mpsc::Sender<Op>, stats: Arc<Stats>) {
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("failed to bind HTTP endpoint on {addr}: {e}");
            return;
        }
    };
    log::info!("ledger HTTP endpoint listening on {addr}");
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        let ops = ops.clone();
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
            let target = req.split_whitespace().nth(1).unwrap_or("/");
            let path = target.split('?').next().unwrap_or("/");
            let (status, content_type, body) = match path {
                "/healthz" | "/readyz" => ("200 OK", "text/plain", "ok".to_string()),
                "/metrics" => ("200 OK", "text/plain; version=0.0.4", metrics_text(&ops, &stats).await),
                "/export.jsonl" => {
                    let (since, limit) = export_params(target);
                    let (tx, rx) = oneshot::channel();
                    let _ = ops.send(Op::Read(Read { since, limit, done: tx })).await;
                    match rx.await {
                        Ok(Ok(rows)) => {
                            let mut out = String::new();
                            for row in rows {
                                if let Ok(line) = serde_json::to_string(&row) {
                                    out.push_str(&line);
                                    out.push('\n');
                                }
                            }
                            ("200 OK", "application/x-ndjson", out)
                        }
                        _ => ("500 Internal Server Error", "text/plain", "export failed".to_string()),
                    }
                }
                _ => ("404 Not Found", "text/plain", "not found".to_string()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

async fn metrics_text(ops: &mpsc::Sender<Op>, stats: &Stats) -> String {
    let (tx, rx) = oneshot::channel();
    let _ = ops.send(Op::Count(tx)).await;
    let stored = match rx.await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let dropped: u64 = stats.dataplane_dropped.lock().map(|m| m.values().sum()).unwrap_or(0);
    format!(
        "# TYPE ledger_batches_total counter\nledger_batches_total {}\n\
         # TYPE ledger_records_total counter\nledger_records_total {}\n\
         # TYPE ledger_write_errors_total counter\nledger_write_errors_total {}\n\
         # TYPE ledger_records_stored gauge\nledger_records_stored {}\n\
         # TYPE ledger_dataplane_dropped_total gauge\nledger_dataplane_dropped_total {}\n",
        stats.batches.load(Ordering::Relaxed),
        stats.records.load(Ordering::Relaxed),
        stats.write_errors.load(Ordering::Relaxed),
        stored,
        dropped,
    )
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

    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let store = Store::open(&db_path)?;
    log::info!("ledger store at {}", db_path.display());

    let (ops_tx, ops_rx) = mpsc::channel::<Op>(1024);
    std::thread::Builder::new().name("ledger-storage".into()).spawn(move || storage_thread(store, ops_rx))?;
    let stats = Arc::new(Stats::default());

    tokio::spawn(http_server(http_addr, ops_tx.clone(), Arc::clone(&stats)));

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
    log::info!("ledger gRPC ingest listening on {grpc_addr}");
    builder
        .add_service(LedgerIngestServer::new(Ingest { ops: ops_tx, stats }).max_decoding_message_size(16 * 1024 * 1024))
        .serve(grpc_addr)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_params_parse_and_clamp() {
        assert_eq!(export_params("/export.jsonl"), (0, 10_000));
        assert_eq!(export_params("/export.jsonl?since_us=1700000000000000&limit=5"), (1_700_000_000_000_000, 5));
        assert_eq!(export_params("/export.jsonl?limit=0"), (0, 1));
        assert_eq!(export_params("/export.jsonl?limit=9999999&since_us=x"), (0, 100_000));
    }
}
