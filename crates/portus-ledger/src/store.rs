//! The usage ledger on disk: one SQLite file, one writer, append-only rows.
//!
//! Every batch a data plane reports lands in one transaction. Reads are for
//! export (JSONL by time range) and for the counters on `/metrics`.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use portus_types::proto::portus::ledger::v1::UsageRecord;

pub struct Store {
    conn: Connection,
}

/// One stored record, as exported.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Row {
    pub id: i64,
    pub node: String,
    pub ts_unix_micros: u64,
    pub duration_micros: u64,
    pub status: u32,
    pub dialect: String,
    pub stream: bool,
    pub provider: String,
    pub route_host: String,
    pub requested_model: String,
    pub served_model: String,
    pub has_usage: bool,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_read_tokens: u32,
    pub cache_creation_tokens: u32,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub key_id: u64,
    pub request_id: u64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY,
    node TEXT NOT NULL,
    ts_unix_micros INTEGER NOT NULL,
    duration_micros INTEGER NOT NULL,
    status INTEGER NOT NULL,
    dialect TEXT NOT NULL,
    stream INTEGER NOT NULL,
    provider TEXT NOT NULL,
    route_host TEXT NOT NULL,
    requested_model TEXT NOT NULL,
    served_model TEXT NOT NULL,
    has_usage INTEGER NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cache_read_tokens INTEGER NOT NULL,
    cache_creation_tokens INTEGER NOT NULL,
    request_bytes INTEGER NOT NULL,
    response_bytes INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    request_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_ts ON usage (ts_unix_micros);
CREATE INDEX IF NOT EXISTS usage_key_ts ON usage (key_id, ts_unix_micros);
";

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        // WAL: readers (export) never block the single writer, and a crash
        // mid-batch loses at most that batch, which the data plane resends.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Append a batch atomically. Returns how many rows were written.
    pub fn insert_batch(&mut self, node: &str, records: &[UsageRecord]) -> rusqlite::Result<usize> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO usage (node, ts_unix_micros, duration_micros, status, dialect, stream, provider, route_host,
                 requested_model, served_model, has_usage, input_tokens, output_tokens, cache_read_tokens,
                 cache_creation_tokens, request_bytes, response_bytes, key_id, request_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            )?;
            for r in records {
                stmt.execute(params![
                    node,
                    r.ts_unix_micros as i64,
                    r.duration_micros as i64,
                    r.status,
                    r.dialect,
                    r.stream,
                    r.provider,
                    r.route_host,
                    r.requested_model,
                    r.served_model,
                    r.has_usage,
                    r.input_tokens,
                    r.output_tokens,
                    r.cache_read_tokens,
                    r.cache_creation_tokens,
                    r.request_bytes as i64,
                    r.response_bytes as i64,
                    r.key_id as i64,
                    r.request_id as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(records.len())
    }

    /// Rows with `ts_unix_micros >= since`, oldest first, at most `limit`.
    pub fn export(&self, since: u64, limit: usize) -> rusqlite::Result<Vec<Row>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, node, ts_unix_micros, duration_micros, status, dialect, stream, provider, route_host,
             requested_model, served_model, has_usage, input_tokens, output_tokens, cache_read_tokens,
             cache_creation_tokens, request_bytes, response_bytes, key_id, request_id
             FROM usage WHERE ts_unix_micros >= ?1 ORDER BY ts_unix_micros, id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since as i64, limit as i64], |r| {
            Ok(Row {
                id: r.get(0)?,
                node: r.get(1)?,
                ts_unix_micros: r.get::<_, i64>(2)? as u64,
                duration_micros: r.get::<_, i64>(3)? as u64,
                status: r.get(4)?,
                dialect: r.get(5)?,
                stream: r.get(6)?,
                provider: r.get(7)?,
                route_host: r.get(8)?,
                requested_model: r.get(9)?,
                served_model: r.get(10)?,
                has_usage: r.get(11)?,
                input_tokens: r.get(12)?,
                output_tokens: r.get(13)?,
                cache_read_tokens: r.get(14)?,
                cache_creation_tokens: r.get(15)?,
                request_bytes: r.get::<_, i64>(16)? as u64,
                response_bytes: r.get::<_, i64>(17)? as u64,
                key_id: r.get::<_, i64>(18)? as u64,
                request_id: r.get::<_, i64>(19)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Rows stored, for `/metrics`.
    pub fn count(&self) -> rusqlite::Result<u64> {
        let n: Option<i64> = self.conn.query_row("SELECT COUNT(*) FROM usage", [], |r| r.get(0)).optional()?;
        Ok(n.unwrap_or(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ts: u64, model: &str, tokens: Option<(u32, u32)>) -> UsageRecord {
        UsageRecord {
            ts_unix_micros: ts,
            duration_micros: 1500,
            status: 200,
            dialect: "anthropic".into(),
            stream: false,
            provider: "anthropic".into(),
            route_host: "llm.example.com".into(),
            requested_model: model.into(),
            served_model: model.into(),
            has_usage: tokens.is_some(),
            input_tokens: tokens.map_or(0, |t| t.0),
            output_tokens: tokens.map_or(0, |t| t.1),
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            request_bytes: 10,
            response_bytes: 20,
            key_id: 0,
            request_id: ts,
        }
    }

    #[test]
    fn batches_round_trip_through_export_in_time_order() {
        let mut store = Store::in_memory().unwrap();
        assert_eq!(store.insert_batch("pod-a", &[record(30, "claude-opus-5", Some((10, 4))), record(10, "claude-haiku-4-5", None)]).unwrap(), 2);
        assert_eq!(store.insert_batch("pod-b", &[record(20, "claude-opus-5", Some((7, 1)))]).unwrap(), 1);
        assert_eq!(store.count().unwrap(), 3);

        let all = store.export(0, 100).unwrap();
        assert_eq!(all.iter().map(|r| r.ts_unix_micros).collect::<Vec<_>>(), vec![10, 20, 30]);
        assert_eq!(all[0].node, "pod-a");
        assert!(!all[0].has_usage);
        assert_eq!((all[2].input_tokens, all[2].output_tokens, all[2].served_model.as_str()), (10, 4, "claude-opus-5"));

        let since = store.export(20, 100).unwrap();
        assert_eq!(since.len(), 2);
        assert_eq!(store.export(0, 1).unwrap().len(), 1);
        let line = serde_json::to_string(&all[2]).unwrap();
        assert!(line.contains("\"requested_model\":\"claude-opus-5\""), "{line}");
    }

    #[test]
    fn an_empty_batch_is_a_no_op() {
        let mut store = Store::in_memory().unwrap();
        assert_eq!(store.insert_batch("pod", &[]).unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
    }
}
