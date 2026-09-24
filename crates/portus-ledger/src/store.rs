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

/// How `/v1/summary` and `/v1/series` group rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    /// Per API key (or OAuth subject id); key 0 is unauthenticated traffic.
    Key,
    /// Per key and the user behind it (`subject`: the on-behalf-of user, the
    /// key's name, or the OAuth subject).
    Subject,
    /// Per key and requested model (MCP: the JSON-RPC method).
    Model,
    /// Per key, method and tool (MCP).
    Tool,
    /// Per tenant.
    Tenant,
    /// Per route host and provider.
    Route,
}

impl GroupBy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "" | "key" => Some(Self::Key),
            "subject" | "user" => Some(Self::Subject),
            "model" => Some(Self::Model),
            "tool" => Some(Self::Tool),
            "tenant" => Some(Self::Tenant),
            "route" | "provider" => Some(Self::Route),
            _ => None,
        }
    }

    /// (extra grouped columns, whether key_id is a grouping column).
    fn columns(self) -> (&'static [&'static str], bool) {
        match self {
            Self::Key => (&[], true),
            Self::Subject => (&["subject"], true),
            Self::Model => (&["requested_model"], true),
            Self::Tool => (&["requested_model", "served_model"], true),
            Self::Tenant => (&["tenant"], false),
            Self::Route => (&["route_host", "provider"], false),
        }
    }
}

/// Totals for one group over a period. `key_id`, `tenant` and `name` name
/// the key; `subject`, `model`, `tool`, `route_host` and `provider` are set
/// when grouped by them; `bucket_start_unix_micros` only in a series.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub bucket_start_unix_micros: u64,
    pub key_id: u64,
    pub tenant: String,
    pub name: String,
    pub subject: String,
    pub model: String,
    pub tool: String,
    pub route_host: String,
    pub provider: String,
    /// Requests forwarded to a provider.
    pub requests: u64,
    /// Requests the gateway refused (401, 403, 429), by reason below.
    pub refusals: u64,
    pub refused_unauthenticated: u64,
    pub refused_model_not_allowed: u64,
    pub refused_tool_not_allowed: u64,
    pub refused_budget_exhausted: u64,
    /// Forwarded requests the provider answered with a 5xx.
    pub upstream_errors: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_tokens: u64,
    /// Wall time of forwarded requests, summed; divide by `requests`.
    pub duration_micros_total: u64,
    /// Time to first response byte, summed over `first_byte_samples` rows.
    pub first_byte_micros_total: u64,
    pub first_byte_samples: u64,
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
    /// The subject as the data plane knew it; names OAuth subjects, which
    /// have no key row.
    pub tenant: String,
    pub subject: String,
    /// What refused the request (policy id, `key`, `jwt`); empty when forwarded.
    pub rule: String,
    /// The client's own x-portus-request-id, when it sent one.
    pub client_request_id: String,
    /// Time to the first response body byte; 0 when there was none.
    pub first_byte_micros: u64,
    /// The user a trusted caller acted for; empty otherwise.
    pub on_behalf_of: String,
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
    refusal TEXT NOT NULL DEFAULT '',
    tenant TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    rule TEXT NOT NULL DEFAULT '',
    client_request_id TEXT NOT NULL DEFAULT '',
    first_byte_micros INTEGER NOT NULL DEFAULT 0,
    on_behalf_of TEXT NOT NULL DEFAULT ''
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
        // Ledgers created before OAuth subjects lack the subject columns.
        let has_subject: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('usage') WHERE name = 'subject'")?
            .exists([])?;
        if !has_subject {
            conn.execute_batch("ALTER TABLE usage ADD COLUMN tenant TEXT NOT NULL DEFAULT ''; ALTER TABLE usage ADD COLUMN subject TEXT NOT NULL DEFAULT ''")?;
        }
        // Ledgers created before 0.2.8 lack the rule, correlation and latency columns.
        let has_rule: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('usage') WHERE name = 'rule'")?
            .exists([])?;
        if !has_rule {
            conn.execute_batch(
                "ALTER TABLE usage ADD COLUMN rule TEXT NOT NULL DEFAULT '';
                 ALTER TABLE usage ADD COLUMN client_request_id TEXT NOT NULL DEFAULT '';
                 ALTER TABLE usage ADD COLUMN first_byte_micros INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE usage ADD COLUMN on_behalf_of TEXT NOT NULL DEFAULT ''",
            )?;
        }
        conn.execute_batch(keys::SCHEMA)?;
        // Ledgers created before MCP lack the tool list on keys.
        let has_tools: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('api_keys') WHERE name = 'allowed_tools'")?
            .exists([])?;
        if !has_tools {
            conn.execute_batch("ALTER TABLE api_keys ADD COLUMN allowed_tools TEXT NOT NULL DEFAULT ''")?;
        }
        // Ledgers created before 0.2.8 lack key expiry.
        let has_expiry: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('api_keys') WHERE name = 'expires_unix_secs'")?
            .exists([])?;
        if !has_expiry {
            conn.execute_batch("ALTER TABLE api_keys ADD COLUMN expires_unix_secs INTEGER")?;
        }
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

    pub fn issue_key(&self, tenant: &str, name: &str, models: &[String], tools: &[String], plaintext: Option<&str>, expires_in_secs: Option<u64>) -> rusqlite::Result<(KeyRow, String)> {
        keys::issue(&self.conn, tenant, name, models, tools, plaintext, expires_in_secs)
    }

    pub fn update_key(&self, id: u64, patch: &keys::KeyPatch) -> rusqlite::Result<Option<KeyRow>> {
        keys::update(&self.conn, id, patch)
    }

    /// Revoke every key whose expiry has passed; how many.
    pub fn expire_keys(&self, now_unix_secs: u64) -> rusqlite::Result<usize> {
        keys::expire(&self.conn, now_unix_secs)
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
                 cache_creation_tokens, request_bytes, response_bytes, key_id, request_id, refusal, tenant, subject,
                 rule, client_request_id, first_byte_micros, on_behalf_of)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
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
                    r.tenant,
                    r.subject,
                    r.rule,
                    r.client_request_id,
                    r.first_byte_micros as i64,
                    r.on_behalf_of,
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
             cache_creation_tokens, request_bytes, response_bytes, key_id, request_id, refusal, tenant, subject,
             rule, client_request_id, first_byte_micros, on_behalf_of
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
                tenant: r.get(21)?,
                subject: r.get(22)?,
                rule: r.get(23)?,
                client_request_id: r.get(24)?,
                first_byte_micros: r.get::<_, i64>(25)? as u64,
                on_behalf_of: r.get(26)?,
            })
        })?;
        rows.collect()
    }

    /// Totals since `since` (unix µs), grouped by `by`: what an operator
    /// asks first.
    pub fn summary(&self, since: u64, by: GroupBy) -> rusqlite::Result<Vec<Summary>> {
        self.aggregate(since, 0, by)
    }

    /// Totals per `bucket_micros`-wide time bucket since `since`, grouped by
    /// `by` within each bucket. Buckets are aligned to the epoch.
    pub fn series(&self, since: u64, bucket_micros: u64, by: GroupBy) -> rusqlite::Result<Vec<Summary>> {
        self.aggregate(since, bucket_micros.max(1), by)
    }

    fn aggregate(&self, since: u64, bucket_micros: u64, by: GroupBy) -> rusqlite::Result<Vec<Summary>> {
        let (extra, by_key) = by.columns();
        // Grouping columns are chosen from a fixed list; nothing from the
        // request reaches the SQL text.
        let bucket_expr = if bucket_micros > 0 { format!("(u.ts_unix_micros / {bucket_micros}) * {bucket_micros}") } else { "0".to_string() };
        let key_expr = if by_key { "u.key_id" } else { "0" };
        let tenant_expr = if by_key { "COALESCE(NULLIF(k.tenant, ''), MAX(u.tenant), '')" } else if extra.contains(&"tenant") { "u.tenant" } else { "''" };
        let name_expr = if by_key { "COALESCE(NULLIF(k.name, ''), MAX(u.subject), '')" } else { "''" };
        let col = |c: &str| if extra.contains(&c) { format!("u.{c}") } else { "''".to_string() };
        let mut group: Vec<String> = Vec::new();
        if bucket_micros > 0 {
            group.push(bucket_expr.clone());
        }
        if by_key {
            group.push("u.key_id".to_string());
        }
        group.extend(extra.iter().map(|c| format!("u.{c}")));
        let group_by = if group.is_empty() { String::new() } else { format!("GROUP BY {}", group.join(", ")) };
        let sql = format!(
            "SELECT {bucket_expr}, {key_expr}, {tenant_expr}, {name_expr}, {subject}, {model}, {tool}, {route_host}, {provider},
                    SUM(CASE WHEN u.refusal = '' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN u.refusal <> '' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN u.refusal = 'unauthenticated' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN u.refusal = 'model_not_allowed' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN u.refusal = 'tool_not_allowed' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN u.refusal = 'budget_exhausted' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN u.refusal = '' AND u.status >= 500 THEN 1 ELSE 0 END),
                    SUM(u.input_tokens), SUM(u.output_tokens), SUM(u.cache_read_tokens), SUM(u.cache_creation_tokens),
                    SUM(CASE WHEN u.refusal = '' THEN u.duration_micros ELSE 0 END),
                    SUM(u.first_byte_micros), SUM(CASE WHEN u.first_byte_micros > 0 THEN 1 ELSE 0 END),
                    MAX(u.ts_unix_micros)
             FROM usage u LEFT JOIN api_keys k ON k.id = u.key_id
             WHERE u.ts_unix_micros >= ?1
             {group_by}
             ORDER BY 1, SUM(u.input_tokens) + SUM(u.output_tokens) DESC, SUM(CASE WHEN u.refusal = '' THEN 1 ELSE 0 END) DESC",
            subject = col("subject"),
            model = col("requested_model"),
            tool = col("served_model"),
            route_host = col("route_host"),
            provider = col("provider"),
        );
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params![since as i64], |r| {
            let n = |i: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, Option<i64>>(i)?.unwrap_or(0).max(0) as u64) };
            Ok(Summary {
                bucket_start_unix_micros: n(0)?,
                key_id: n(1)?,
                tenant: r.get(2)?,
                name: r.get(3)?,
                subject: r.get(4)?,
                model: r.get(5)?,
                tool: r.get(6)?,
                route_host: r.get(7)?,
                provider: r.get(8)?,
                requests: n(9)?,
                refusals: n(10)?,
                refused_unauthenticated: n(11)?,
                refused_model_not_allowed: n(12)?,
                refused_tool_not_allowed: n(13)?,
                refused_budget_exhausted: n(14)?,
                upstream_errors: n(15)?,
                input_tokens: n(16)?,
                output_tokens: n(17)?,
                cache_read_tokens: n(18)?,
                cache_creation_tokens: n(19)?,
                duration_micros_total: n(20)?,
                first_byte_micros_total: n(21)?,
                first_byte_samples: n(22)?,
                last_seen_unix_micros: n(23)?,
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
            tenant: String::new(),
            subject: String::new(),
            rule: String::new(),
            client_request_id: String::new(),
            first_byte_micros: 0,
            on_behalf_of: String::new(),
        }
    }

    #[test]
    fn the_summary_groups_by_subject_model_tool_tenant_or_route_and_breaks_refusals_down() {
        let mut store = Store::in_memory().unwrap();
        let (hub, _) = store.issue_key("team-a", "hub", &[], &[], None, None).unwrap();
        let mut rows = Vec::new();
        for (ts, user, model, tokens, refusal, rule, status) in [
            (10, "alice", "claude-opus-5", Some((100, 10)), "", "", 200),
            (20, "alice", "claude-haiku-4-5", Some((50, 5)), "", "", 200),
            (30, "bob", "claude-opus-5", Some((10, 1)), "", "", 200),
            (40, "bob", "claude-opus-5", None, "budget_exhausted", "team-a/daily", 429),
            (50, "bob", "gpt-5", None, "model_not_allowed", "key", 403),
            (60, "carol", "claude-opus-5", None, "", "", 502),
        ] {
            let mut r = record(ts, model, tokens);
            r.key_id = hub.id;
            r.tenant = "team-a".into();
            r.subject = user.into();
            r.on_behalf_of = user.into();
            r.refusal = refusal.into();
            r.rule = rule.into();
            r.status = status;
            r.first_byte_micros = if refusal.is_empty() { 700 } else { 0 };
            rows.push(r);
        }
        store.insert_batch("pod", &rows).unwrap();

        let by_key = store.summary(0, GroupBy::Key).unwrap();
        assert_eq!(by_key.len(), 1);
        let k = &by_key[0];
        assert_eq!((k.key_id, k.tenant.as_str(), k.name.as_str(), k.subject.as_str()), (hub.id, "team-a", "hub", ""));
        assert_eq!((k.requests, k.refusals, k.upstream_errors), (4, 2, 1));
        assert_eq!((k.refused_unauthenticated, k.refused_model_not_allowed, k.refused_tool_not_allowed, k.refused_budget_exhausted), (0, 1, 0, 1));
        assert_eq!((k.input_tokens, k.output_tokens), (160, 16));
        assert_eq!((k.duration_micros_total, k.first_byte_micros_total, k.first_byte_samples), (4 * 1500, 4 * 700, 4), "latency sums cover forwarded rows only");
        assert_eq!(k.bucket_start_unix_micros, 0);

        let by_user = store.summary(0, GroupBy::Subject).unwrap();
        assert_eq!(by_user.iter().map(|s| (s.subject.as_str(), s.requests, s.refusals)).collect::<Vec<_>>(), vec![("alice", 2, 0), ("bob", 1, 2), ("carol", 1, 0)]);
        assert!(by_user.iter().all(|s| s.key_id == hub.id && s.name == "hub"), "the vouching key stays on every row");

        let by_model = store.summary(0, GroupBy::Model).unwrap();
        assert_eq!(by_model.iter().map(|s| (s.model.as_str(), s.requests, s.input_tokens)).collect::<Vec<_>>(), vec![("claude-opus-5", 3, 110), ("claude-haiku-4-5", 1, 50), ("gpt-5", 0, 0)]);

        let by_tenant = store.summary(0, GroupBy::Tenant).unwrap();
        assert_eq!(by_tenant.iter().map(|s| (s.tenant.as_str(), s.key_id, s.requests)).collect::<Vec<_>>(), vec![("team-a", 0, 4)]);

        let by_route = store.summary(0, GroupBy::Route).unwrap();
        assert_eq!(by_route.iter().map(|s| (s.route_host.as_str(), s.provider.as_str(), s.requests)).collect::<Vec<_>>(), vec![("llm.example.com", "anthropic", 4)]);

        let by_tool = store.summary(0, GroupBy::Tool).unwrap();
        assert_eq!(by_tool.len(), 3, "method + tool pairs: {by_tool:?}");
        assert_eq!(GroupBy::parse("user"), Some(GroupBy::Subject));
        assert_eq!(GroupBy::parse("nope"), None);
    }

    #[test]
    fn the_series_buckets_by_time_and_keeps_the_grouping_inside_each_bucket() {
        let mut store = Store::in_memory().unwrap();
        let mut rows = Vec::new();
        for (ts, model, tokens) in [(1_000, "a", Some((1, 1))), (1_500, "b", Some((2, 2))), (2_100, "a", Some((4, 4))), (3_999, "a", None)] {
            let mut r = record(ts, model, tokens);
            r.key_id = 9;
            rows.push(r);
        }
        store.insert_batch("pod", &rows).unwrap();
        let s = store.series(0, 1_000, GroupBy::Key).unwrap();
        assert_eq!(s.iter().map(|b| (b.bucket_start_unix_micros, b.requests, b.input_tokens)).collect::<Vec<_>>(), vec![(1_000, 2, 3), (2_000, 1, 4), (3_000, 1, 0)]);
        let s = store.series(0, 1_000, GroupBy::Model).unwrap();
        assert_eq!(s.iter().map(|b| (b.bucket_start_unix_micros, b.model.as_str(), b.requests)).collect::<Vec<_>>(), vec![(1_000, "b", 1), (1_000, "a", 1), (2_000, "a", 1), (3_000, "a", 1)]);
        assert_eq!(store.series(2_000, 1_000, GroupBy::Key).unwrap().len(), 2, "since applies");
    }

    #[test]
    fn the_new_row_fields_round_trip_through_export() {
        let mut store = Store::in_memory().unwrap();
        let mut r = record(5, "claude-opus-5", None);
        r.rule = "llm/daily".into();
        r.client_request_id = "turn-12".into();
        r.first_byte_micros = 321;
        r.on_behalf_of = "alice@example.com".into();
        store.insert_batch("pod", &[r]).unwrap();
        let rows = store.export(0, 10).unwrap();
        assert_eq!((rows[0].rule.as_str(), rows[0].client_request_id.as_str(), rows[0].first_byte_micros, rows[0].on_behalf_of.as_str()), ("llm/daily", "turn-12", 321, "alice@example.com"));
        let line = serde_json::to_string(&rows[0]).unwrap();
        assert!(line.contains("\"on_behalf_of\":\"alice@example.com\"") && line.contains("\"first_byte_micros\":321"), "{line}");
    }

    #[test]
    fn oauth_subjects_are_named_in_the_summary_from_their_rows() {
        let mut store = Store::in_memory().unwrap();
        let mut a = record(10, "tools/list", None);
        a.key_id = 4242;
        a.tenant = "team-oauth".into();
        a.subject = "alice@example.com".into();
        let mut b = record(20, "tools/call", None);
        b.key_id = 4242;
        b.tenant = "team-oauth".into();
        b.subject = "alice@example.com".into();
        store.insert_batch("pod", &[a, b]).unwrap();
        let rows = store.export(0, 10).unwrap();
        assert_eq!((rows[0].tenant.as_str(), rows[0].subject.as_str()), ("team-oauth", "alice@example.com"));
        let s = store.summary(0, GroupBy::Key).unwrap();
        let alice = s.iter().find(|k| k.key_id == 4242).unwrap();
        assert_eq!((alice.tenant.as_str(), alice.name.as_str(), alice.requests), ("team-oauth", "alice@example.com", 2));
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
        let (row, _) = store.issue_key("team-a", "ci", &[], &[], None, None).unwrap();
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

        let s = store.summary(0, GroupBy::Key).unwrap();
        assert_eq!(s.len(), 2);
        let mine = s.iter().find(|k| k.key_id == row.id).unwrap();
        assert_eq!((mine.tenant.as_str(), mine.name.as_str()), ("team-a", "ci"));
        assert_eq!((mine.requests, mine.refusals), (2, 1));
        assert_eq!((mine.input_tokens, mine.output_tokens, mine.cache_read_tokens), (150, 25, 300));
        assert_eq!(mine.last_seen_unix_micros, 30);
        let anon = s.iter().find(|k| k.key_id == 0).unwrap();
        assert_eq!((anon.name.as_str(), anon.requests), ("", 1));
        assert_eq!(store.summary(25, GroupBy::Key).unwrap().iter().find(|k| k.key_id == row.id).unwrap().requests, 0, "since filters");
    }

    #[test]
    fn an_old_ledger_file_gains_the_refusal_column() {
        let dir = std::env::temp_dir().join(format!("portus-ledger-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.db");
        {
            let c = Connection::open(&path).unwrap();
            let old = SCHEMA
                .replace(",
    refusal TEXT NOT NULL DEFAULT ''", "")
                .replace(",
    rule TEXT NOT NULL DEFAULT '',
    client_request_id TEXT NOT NULL DEFAULT '',
    first_byte_micros INTEGER NOT NULL DEFAULT 0,
    on_behalf_of TEXT NOT NULL DEFAULT ''", "");
            assert!(!old.contains("on_behalf_of") && !old.contains("refusal"), "{old}");
            c.execute_batch(&old).unwrap();
            c.execute_batch(&keys::SCHEMA.replace(",
    expires_unix_secs INTEGER", "")).unwrap();
            c.execute("INSERT INTO usage (node, ts_unix_micros, duration_micros, status, dialect, stream, provider, route_host, requested_model, served_model, has_usage, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, request_bytes, response_bytes, key_id, request_id) VALUES ('p',1,1,200,'anthropic',0,'a','h','m','m',1,1,1,0,0,0,0,0,1)", []).unwrap();
        }
        let store = Store::open(&path).unwrap();
        let rows = store.export(0, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].refusal, "", "pre-existing rows read as forwarded");
        assert_eq!((rows[0].rule.as_str(), rows[0].first_byte_micros, rows[0].on_behalf_of.as_str()), ("", 0, ""));
        let (row, _) = store.issue_key("t", "k", &[], &[], None, Some(60)).unwrap();
        assert!(row.expires_unix_secs.is_some(), "the key table gained its expiry column");
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
