//! The usage ledger on disk: one SQLite file, one writer, append-only rows.
//!
//! Every batch a data plane reports lands in one transaction. Reads are for
//! export (JSONL by time range) and for the counters on `/metrics`.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use portus_types::proto::portus::ledger::v1::{KeySnapshot, UsageRecord};

use crate::budget::{self, Declared, PolicyLimits, Shape, Synced};
use crate::events::{self, EventConfig, Pending};
use crate::keys::{self, KeyRow, Labels, NewKey};

pub struct Store {
    conn: Connection,
    /// Set when a webhook is configured: which crossings and refusals
    /// become outbox events.
    events: Option<EventConfig>,
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
    /// The key's labels, when grouped by key and the key has any.
    #[serde(skip_serializing_if = "Labels::is_empty")]
    pub key_labels: Labels,
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
    /// The key's labels, when it has any.
    #[serde(skip_serializing_if = "Labels::is_empty")]
    pub key_labels: Labels,
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
        // Ledgers created before 0.2.11 lack the per-unit key budgets and labels.
        let has_column = |table: &str, column: &str| -> rusqlite::Result<bool> {
            conn.prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"))?.exists(params![column])
        };
        if !has_column("api_keys", "token_limit")? {
            conn.execute_batch("ALTER TABLE api_keys ADD COLUMN token_limit INTEGER; ALTER TABLE api_keys ADD COLUMN call_limit INTEGER")?;
        }
        if !has_column("api_keys", "labels")? {
            conn.execute_batch("ALTER TABLE api_keys ADD COLUMN labels TEXT NOT NULL DEFAULT '{}'")?;
        }
        // 0.2.9's budget_limit applied one number to token and call policies
        // alike; its unit cannot be recovered, so it is cleared and named.
        if has_column("api_keys", "budget_limit")? {
            let mut stmt = conn.prepare("SELECT id, tenant, name, budget_limit FROM api_keys WHERE budget_limit IS NOT NULL AND revoked_unix_micros IS NULL")?;
            let old: Vec<(i64, String, String, i64)> = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<rusqlite::Result<_>>()?;
            drop(stmt);
            for (id, tenant, name, limit) in &old {
                log::warn!("key {tenant}/{name} ({id}) had budget_limit {limit}; it is no longer applied: set token_limit or call_limit instead");
            }
            conn.execute_batch("UPDATE api_keys SET budget_limit = NULL")?;
        }
        conn.execute_batch(budget::SCHEMA)?;
        if !has_column("spend", "subject_limit")? {
            conn.execute_batch("ALTER TABLE spend ADD COLUMN subject_limit INTEGER NOT NULL DEFAULT 0")?;
        }
        if !has_column("spend", "alerted")? {
            conn.execute_batch("ALTER TABLE spend ADD COLUMN alerted INTEGER NOT NULL DEFAULT 0")?;
        }
        conn.execute_batch(events::SCHEMA)?;
        Ok(Self { conn, events: None })
    }

    /// Write budget and refusal events to the outbox from now on.
    pub fn with_events(mut self, config: EventConfig) -> Self {
        self.events = Some(config);
        self
    }

    /// Add a pod's spend delta and return the window's total; `None` for
    /// an unknown window.
    /// With events on, a threshold the new total crossed is queued in the
    /// same transaction, so the crossing and its event land together.
    pub fn sync_spend(&self, policy: &str, subject: &str, window: &str, delta: u64, now_micros: u64, shape: Option<&Shape>) -> rusqlite::Result<Option<Synced>> {
        let thresholds = self.events.as_ref().map(|e| e.thresholds.as_slice()).unwrap_or(&[]);
        let tx = self.conn.unchecked_transaction()?;
        let synced = budget::sync_alerting(&tx, policy, subject, window, delta, now_micros, shape, thresholds)?;
        if let Some(s) = synced.as_ref().filter(|s| !s.crossed.is_empty()) {
            let who = events::subject_key(subject);
            let key = match &who {
                Some(w) => keys::list(&tx)?.into_iter().find(|k| k.id == w.key_id),
                None => None,
            };
            let unit = shape.map(|s| s.unit.as_str()).unwrap_or("");
            for c in &s.crossed {
                let event = events::threshold_event(policy, subject, window, s.window_end_unix_micros, unit, c, key.as_ref().map(|k| (k, who.as_ref().and_then(|w| w.user.as_deref()))), now_micros);
                events::enqueue(&tx, &event, now_micros)?;
            }
        }
        tx.commit()?;
        Ok(synced)
    }

    /// Policies a data plane holds, before any spend.
    pub fn declare(&self, policies: &[Declared], now_micros: u64) -> rusqlite::Result<usize> {
        budget::declare(&self.conn, policies, now_micros)
    }

    pub fn due_events(&self, now_micros: u64, limit: usize) -> rusqlite::Result<Vec<Pending>> {
        events::due(&self.conn, now_micros, limit)
    }

    pub fn event_delivered(&self, id: i64) -> rusqlite::Result<()> {
        events::delivered(&self.conn, id)
    }

    pub fn event_failed(&self, id: i64, attempts: u32, now_micros: u64) -> rusqlite::Result<bool> {
        events::failed(&self.conn, id, attempts, now_micros)
    }

    pub fn events_pending(&self) -> rusqlite::Result<u64> {
        events::pending(&self.conn)
    }

    /// Every synced policy with the current window's spend per subject.
    pub fn limits(&self, now_micros: u64) -> rusqlite::Result<Vec<PolicyLimits>> {
        budget::limits(&self.conn, now_micros)
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

    pub fn issue_key(&self, new: &NewKey) -> rusqlite::Result<(KeyRow, String)> {
        keys::issue(&self.conn, new)
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
            // Refusals of the configured kinds become events in the same
            // transaction as their rows.
            if let Some(cfg) = self.events.as_ref().filter(|c| !c.refusals.is_empty()) {
                let refused: Vec<&UsageRecord> = records.iter().filter(|r| !r.refusal.is_empty() && cfg.refusals.contains(&r.refusal)).collect();
                if !refused.is_empty() {
                    let labels = keys::labels_by_id(&tx)?;
                    let now = refused.iter().map(|r| r.ts_unix_micros).max().unwrap_or(0);
                    for r in refused {
                        events::enqueue(&tx, &events::refusal_event(r, labels.get(&r.key_id)), now)?;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(records.len())
    }

    /// Rows oldest first, at most `limit`: with `after_id`, the rows stored
    /// after that row id (a cursor that never repeats or skips a row);
    /// otherwise rows with `ts_unix_micros >= since`.
    pub fn export(&self, since: u64, after_id: Option<i64>, limit: usize) -> rusqlite::Result<Vec<Row>> {
        const COLUMNS: &str = "SELECT id, node, ts_unix_micros, duration_micros, status, dialect, stream, provider, route_host,
             requested_model, served_model, has_usage, input_tokens, output_tokens, cache_read_tokens,
             cache_creation_tokens, request_bytes, response_bytes, key_id, request_id, refusal, tenant, subject,
             rule, client_request_id, first_byte_micros, on_behalf_of FROM usage";
        let (sql, from) = match after_id {
            Some(id) => (format!("{COLUMNS} WHERE id > ?1 ORDER BY id LIMIT ?2"), id),
            None => (format!("{COLUMNS} WHERE ts_unix_micros >= ?1 ORDER BY ts_unix_micros, id LIMIT ?2"), since as i64),
        };
        let labels = keys::labels_by_id(&self.conn)?;
        let mut stmt = self.conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params![from, limit as i64], |r| {
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
                key_labels: Labels::new(),
            })
        })?;
        let mut out = rows.collect::<rusqlite::Result<Vec<Row>>>()?;
        for row in &mut out {
            if let Some(l) = labels.get(&row.key_id) {
                row.key_labels = l.clone();
            }
        }
        Ok(out)
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
                key_labels: Labels::new(),
            })
        })?;
        let mut out = rows.collect::<rusqlite::Result<Vec<Summary>>>()?;
        if by_key {
            let labels = keys::labels_by_id(&self.conn)?;
            for s in &mut out {
                if let Some(l) = labels.get(&s.key_id) {
                    s.key_labels = l.clone();
                }
            }
        }
        Ok(out)
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
        let (hub, _) = store.issue_key(&keys::new_key("team-a", "hub")).unwrap();
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
        let rows = store.export(0, None, 10).unwrap();
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
        let rows = store.export(0, None, 10).unwrap();
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
        let rows = store.export(0, None, 10).unwrap();
        assert_eq!((rows[0].status, rows[0].key_id, rows[0].refusal.as_str(), rows[0].has_usage), (429, 77, "budget_exhausted", false));
    }

    #[test]
    fn the_summary_totals_per_key_and_counts_refusals_separately() {
        let mut store = Store::in_memory().unwrap();
        let (row, _) = store.issue_key(&keys::new_key("team-a", "ci")).unwrap();
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
        let rows = store.export(0, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].refusal, "", "pre-existing rows read as forwarded");
        assert_eq!((rows[0].rule.as_str(), rows[0].first_byte_micros, rows[0].on_behalf_of.as_str()), ("", 0, ""));
        let (row, _) = store.issue_key(&keys::NewKey { expires_in_secs: Some(60), ..keys::new_key("t", "k") }).unwrap();
        assert!(row.expires_unix_secs.is_some(), "the key table gained its expiry column");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batches_round_trip_through_export_in_time_order() {
        let mut store = Store::in_memory().unwrap();
        assert_eq!(store.insert_batch("pod-a", &[record(30, "claude-opus-5", Some((10, 4))), record(10, "claude-haiku-4-5", None)]).unwrap(), 2);
        assert_eq!(store.insert_batch("pod-b", &[record(20, "claude-opus-5", Some((7, 1)))]).unwrap(), 1);
        assert_eq!(store.count().unwrap(), 3);

        let all = store.export(0, None, 100).unwrap();
        assert_eq!(all.iter().map(|r| r.ts_unix_micros).collect::<Vec<_>>(), vec![10, 20, 30]);
        assert_eq!(all[0].node, "pod-a");
        assert!(!all[0].has_usage);
        assert_eq!((all[2].input_tokens, all[2].output_tokens, all[2].served_model.as_str()), (10, 4, "claude-opus-5"));

        let since = store.export(20, None, 100).unwrap();
        assert_eq!(since.len(), 2);
        assert_eq!(store.export(0, None, 1).unwrap().len(), 1);
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
    fn the_after_id_cursor_pages_without_repeats_even_when_timestamps_tie() {
        let mut store = Store::in_memory().unwrap();
        // Five rows, three sharing one timestamp: a since_us page boundary repeats them.
        let rows: Vec<UsageRecord> = [10, 20, 20, 20, 30].iter().map(|ts| record(*ts, "m", None)).collect();
        store.insert_batch("pod", &rows).unwrap();
        let mut seen = Vec::new();
        let mut cursor = Some(0);
        loop {
            let page = store.export(0, cursor, 2).unwrap();
            if page.is_empty() {
                break;
            }
            cursor = page.last().map(|r| r.id);
            seen.extend(page.iter().map(|r| r.id));
        }
        let mut unique = seen.clone();
        unique.dedup();
        assert_eq!((seen.len(), unique.len()), (5, 5), "every row once: {seen:?}");
        assert!(seen.windows(2).all(|w| w[0] < w[1]), "in id order");
    }

    #[test]
    fn events_are_written_with_the_crossing_and_the_refusal_rows_that_caused_them() {
        let mut store = Store::in_memory().unwrap().with_events(EventConfig::parse("80,100", "budget_exhausted,tool_not_allowed").unwrap());
        let (key, _) = store.issue_key(&NewKey { labels: [("expert".to_string(), "ns".to_string())].into_iter().collect(), ..keys::new_key("team-a", "ns") }).unwrap();
        let shape = Shape { limit: 100, unit: "CALLS".into(), per: "SUBJECT".into(), fail_open: false, subject_limit: 0 };
        let subject = format!("{}:alice@example.com", key.id);
        store.sync_spend("mcp/calls", &subject, "DAILY", 79, 1_000, Some(&shape)).unwrap();
        assert_eq!(store.events_pending().unwrap(), 0);
        store.sync_spend("mcp/calls", &subject, "DAILY", 30, 1_000, Some(&shape)).unwrap();
        let due = store.due_events(1_000, 10).unwrap();
        let kinds: Vec<serde_json::Value> = due.iter().map(|p| serde_json::from_str(&p.body).unwrap()).collect();
        assert_eq!(kinds.iter().map(|e| e["threshold_pct"].as_u64().unwrap()).collect::<Vec<_>>(), vec![80, 100], "109 of 100 crosses both");
        assert_eq!((kinds[0]["key_name"].as_str(), kinds[0]["user"].as_str(), kinds[0]["key_labels"]["expert"].as_str()), (Some("ns"), Some("alice@example.com"), Some("ns")));
        for p in &due {
            store.event_delivered(p.id).unwrap();
        }
        store.sync_spend("mcp/calls", &subject, "DAILY", 5, 1_000, Some(&shape)).unwrap();
        assert_eq!(store.events_pending().unwrap(), 0, "each threshold once");
        let mut refused = record(2_000, "tools/call", None);
        refused.dialect = "mcp".into();
        refused.served_model = "qompass.fleet_report".into();
        refused.refusal = "tool_not_allowed".into();
        refused.key_id = key.id;
        let mut unauth = record(2_001, "tools/call", None);
        unauth.refusal = "unauthenticated".into();
        store.insert_batch("pod", &[refused, unauth, record(2_002, "m", Some((1, 1)))]).unwrap();
        let due = store.due_events(3_000, 10).unwrap();
        assert_eq!(due.len(), 1, "only configured refusal kinds");
        let e: serde_json::Value = serde_json::from_str(&due[0].body).unwrap();
        assert_eq!((e["type"].as_str(), e["tool"].as_str(), e["key_labels"]["expert"].as_str()), (Some("refusal"), Some("qompass.fleet_report"), Some("ns")));
        // No webhook configured: no outbox writes.
        let mut quiet = Store::in_memory().unwrap();
        quiet.sync_spend("mcp/calls", "7", "DAILY", 500, 1_000, Some(&shape)).unwrap();
        let mut r = record(1, "m", None);
        r.refusal = "budget_exhausted".into();
        quiet.insert_batch("pod", &[r]).unwrap();
        assert_eq!(quiet.events_pending().unwrap(), 0);
    }

    #[test]
    fn labels_ride_on_export_and_by_key_summary_rows() {
        let mut store = Store::in_memory().unwrap();
        let (key, _) = store.issue_key(&NewKey { labels: [("owner".to_string(), "alice".to_string())].into_iter().collect(), ..keys::new_key("t", "k") }).unwrap();
        let mut r = record(5, "m", Some((1, 1)));
        r.key_id = key.id;
        store.insert_batch("pod", &[r, record(6, "m", None)]).unwrap();
        let rows = store.export(0, None, 10).unwrap();
        assert_eq!(rows[0].key_labels.get("owner").map(String::as_str), Some("alice"));
        assert!(rows[1].key_labels.is_empty());
        assert!(!serde_json::to_string(&rows[1]).unwrap().contains("key_labels"), "omitted when empty");
        let s = store.summary(0, GroupBy::Key).unwrap();
        assert_eq!(s.iter().find(|x| x.key_id == key.id).unwrap().key_labels.len(), 1);
        assert!(store.summary(0, GroupBy::Tenant).unwrap()[0].key_labels.is_empty(), "no key, no labels");
    }

    #[test]
    fn a_0_2_9_budget_limit_is_cleared_on_open() {
        let dir = std::env::temp_dir().join(format!("portus-ledger-budget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE api_keys (id INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE, tenant TEXT NOT NULL, name TEXT NOT NULL,
                 allowed_models TEXT NOT NULL, allowed_tools TEXT NOT NULL DEFAULT '', external INTEGER NOT NULL, created_unix_micros INTEGER NOT NULL,
                 revoked_unix_micros INTEGER, expires_unix_secs INTEGER, budget_limit INTEGER);
                 INSERT INTO api_keys VALUES (7, x'00', 't', 'expert', '', '', 0, 1, NULL, NULL, 5000000);",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let k = store.list_keys().unwrap().into_iter().find(|k| k.id == 7).unwrap();
        assert_eq!((k.token_limit, k.call_limit), (None, None), "an ambiguous unit is not guessed");
        assert!(k.labels.is_empty());
        let still: Option<i64> = store.conn.query_row("SELECT budget_limit FROM api_keys WHERE id = 7", [], |r| r.get(0)).unwrap();
        assert_eq!(still, None, "cleared, so the warning is logged once");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_batch_is_a_no_op() {
        let mut store = Store::in_memory().unwrap();
        assert_eq!(store.insert_batch("pod", &[]).unwrap(), 0);
        assert_eq!(store.count().unwrap(), 0);
    }
}
