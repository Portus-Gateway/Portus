//! The usage ledger on disk: one SQLite file, one writer, append-only rows.
//!
//! Every batch a data plane reports lands in one transaction. Reads are for
//! export (JSONL by time range) and for the counters on `/metrics`.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use portus_types::proto::portus::ledger::v1::{KeySnapshot, UsageRecord};

use crate::budget::{self, Synced};
use crate::keys::{self, KeyRow};

pub struct Store {
    conn: Connection,
}

/// Totals for one API key over a period; key 0 is unauthenticated traffic.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KeySummary {
    pub key_id: u64,
    pub tenant: String,
    pub name: String,
    /// Requests forwarded to a provider.
    pub requests: u64,
    /// Requests the gateway refused (401, 403, 429).
    pub refusals: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_tokens: u64,
    pub last_seen_unix_micros: u64,
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
    /// Empty when the request was forwarded.
    pub refusal: String,
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
    request_id INTEGER NOT NULL,
    refusal TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS usage_ts ON usage (ts_unix_micros);
CREATE INDEX IF NOT EXISTS usage_key_ts ON usage (key_id, ts_unix_micros);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
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
        // Ledgers created before refusals were recorded lack the column.
        let has_refusal: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('usage') WHERE name = 'refusal'")?
            .exists([])?;
        if !has_refusal {
            conn.execute_batch("ALTER TABLE usage ADD COLUMN refusal TEXT NOT NULL DEFAULT ''")?;
        }
        conn.execute_batch(keys::SCHEMA)?;
        conn.execute_batch(budget::SCHEMA)?;
        Ok(Self { conn })
    }

    /// Add a pod's spend delta and return the window's total; `None` for
    /// an unknown window.
    pub fn sync_spend(&self, policy: &str, subject: &str, window: &str, delta: u64, now_micros: u64) -> rusqlite::Result<Option<Synced>> {
        budget::sync(&self.conn, policy, subject, window, delta, now_micros)
    }

    pub fn prune_spend(&self, now_micros: u64) -> rusqlite::Result<usize> {
        budget::prune(&self.conn, now_micros)
    }

    /// The key snapshot version last published; survives restarts so data
    /// planes never see the counter go backwards.
    pub fn key_version(&self) -> rusqlite::Result<u64> {
        let v: Option<i64> = self.conn.query_row("SELECT value FROM meta WHERE key = 'key_version'", [], |r| r.get(0)).optional()?;
        Ok(v.unwrap_or(1) as u64)
    }

    /// Advance and persist the key snapshot version.
    pub fn bump_key_version(&self) -> rusqlite::Result<u64> {
        let next = self.key_version()? + 1;
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('key_version', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1",
            params![next as i64],
        )?;
        Ok(next)
    }

    pub fn issue_key(&self, tenant: &str, name: &str, models: &[String], plaintext: Option<&str>) -> rusqlite::Result<(KeyRow, String)> {
        keys::issue(&self.conn, tenant, name, models, plaintext)
    }

    pub fn revoke_key(&self, id: u64) -> rusqlite::Result<bool> {
        keys::revoke(&self.conn, id)
    }

    pub fn list_keys(&self) -> rusqlite::Result<Vec<KeyRow>> {
        keys::list(&self.conn)
    }

    pub fn key_snapshot(&self, version: u64) -> rusqlite::Result<KeySnapshot> {
        keys::snapshot(&self.conn, version)
    }

    /// Append a batch atomically. Returns how many rows were written.
    pub fn insert_batch(&mut self, node: &str, records: &[UsageRecord]) -> rusqlite::Result<usize> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO usage (node, ts_unix_micros, duration_micros, status, dialect, stream, provider, route_host,
                 requested_model, served_model, has_usage, input_tokens, output_tokens, cache_read_tokens,
                 cache_creation_tokens, request_bytes, response_bytes, key_id, request_id, refusal)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
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
                    r.refusal,
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
             cache_creation_tokens, request_bytes, response_bytes, key_id, request_id, refusal
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
                refusal: r.get(20)?,
            })
        })?;
        rows.collect()
    }

    /// Per-key totals since `since` (unix µs): what an operator asks first.
    pub fn summary(&self, since: u64) -> rusqlite::Result<Vec<KeySummary>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT u.key_id, COALESCE(k.tenant, ''), COALESCE(k.name, ''),
                    SUM(CASE WHEN u.refusal = '' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN u.refusal <> '' THEN 1 ELSE 0 END),
                    SUM(u.input_tokens), SUM(u.output_tokens), SUM(u.cache_read_tokens), SUM(u.cache_creation_tokens),
                    MAX(u.ts_unix_micros)
             FROM usage u LEFT JOIN api_keys k ON k.id = u.key_id
             WHERE u.ts_unix_micros >= ?1
             GROUP BY u.key_id ORDER BY SUM(u.input_tokens) + SUM(u.output_tokens) DESC",
        )?;
        let rows = stmt.query_map(params![since as i64], |r| {
            Ok(KeySummary {
                key_id: r.get::<_, i64>(0)? as u64,
                tenant: r.get(1)?,
                name: r.get(2)?,
                requests: r.get::<_, i64>(3)? as u64,
                refusals: r.get::<_, i64>(4)? as u64,
                input_tokens: r.get::<_, i64>(5)? as u64,
                output_tokens: r.get::<_, i64>(6)? as u64,
                cache_read_tokens: r.get::<_, i64>(7)? as u64,
                cache_creation_tokens: r.get::<_, i64>(8)? as u64,
                last_seen_unix_micros: r.get::<_, i64>(9)? as u64,
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
            refusal: String::new(),
        }
    }

    #[test]
    fn refusals_are_stored_and_exported_with_their_reason() {
        let mut store = Store::in_memory().unwrap();
        let mut r = record(5, "claude-opus-5", None);
        r.status = 429;
        r.key_id = 77;
        r.refusal = "budget_exhausted".into();
        store.insert_batch("pod", &[r]).unwrap();
        let rows = store.export(0, 10).unwrap();
        assert_eq!((rows[0].status, rows[0].key_id, rows[0].refusal.as_str(), rows[0].has_usage), (429, 77, "budget_exhausted", false));
    }

    #[test]
    fn the_summary_totals_per_key_and_counts_refusals_separately() {
        let mut store = Store::in_memory().unwrap();
        let (row, _) = store.issue_key("team-a", "ci", &[], None).unwrap();
        let mut ok1 = record(10, "claude-opus-5", Some((100, 20)));
        ok1.key_id = row.id;
        let mut ok2 = record(20, "claude-opus-5", Some((50, 5)));
        ok2.key_id = row.id;
        ok2.cache_read_tokens = 300;
        let mut refused = record(30, "claude-opus-5", None);
        refused.key_id = row.id;
        refused.status = 429;
        refused.refusal = "budget_exhausted".into();
        let anon = record(40, "gpt-5", None);
        store.insert_batch("pod", &[ok1, ok2, refused, anon]).unwrap();

        let s = store.summary(0).unwrap();
        assert_eq!(s.len(), 2);
        let mine = s.iter().find(|k| k.key_id == row.id).unwrap();
        assert_eq!((mine.tenant.as_str(), mine.name.as_str()), ("team-a", "ci"));
        assert_eq!((mine.requests, mine.refusals), (2, 1));
        assert_eq!((mine.input_tokens, mine.output_tokens, mine.cache_read_tokens), (150, 25, 300));
        assert_eq!(mine.last_seen_unix_micros, 30);
        let anon = s.iter().find(|k| k.key_id == 0).unwrap();
        assert_eq!((anon.name.as_str(), anon.requests), ("", 1));
        assert_eq!(store.summary(25).unwrap().iter().find(|k| k.key_id == row.id).unwrap().requests, 0, "since filters");
    }

    #[test]
    fn an_old_ledger_file_gains_the_refusal_column() {
        let dir = std::env::temp_dir().join(format!("portus-ledger-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(&SCHEMA.replace(",
    refusal TEXT NOT NULL DEFAULT ''", "")).unwrap();
            c.execute("INSERT INTO usage (node, ts_unix_micros, duration_micros, status, dialect, stream, provider, route_host, requested_model, served_model, has_usage, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, request_bytes, response_bytes, key_id, request_id) VALUES ('p',1,1,200,'anthropic',0,'a','h','m','m',1,1,1,0,0,0,0,0,1)", []).unwrap();
        }
        let store = Store::open(&path).unwrap();
        let rows = store.export(0, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].refusal, "", "pre-existing rows read as forwarded");
        let _ = std::fs::remove_dir_all(&dir);
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
    fn the_key_version_survives_reopening_the_store() {
        let dir = std::env::temp_dir().join(format!("portus-ledger-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.db");
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.key_version().unwrap(), 1);
            assert_eq!(store.bump_key_version().unwrap(), 2);
            assert_eq!(store.bump_key_version().unwrap(), 3);
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.key_version().unwrap(), 3, "a restart continues the count");
        assert_eq!(store.bump_key_version().unwrap(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_batch_is_a_no_op() {
        let mut store = Store::in_memory().unwrap();
        assert_eq!(store.insert_batch("pod", &[]).unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
    }
}
