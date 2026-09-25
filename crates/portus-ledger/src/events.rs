//! Budget and refusal events for a webhook: written to an outbox in the
//! same transaction as the spend or usage row that caused them, delivered
//! by a background task that deletes a row only after a 2xx. A ledger
//! restart can deliver an event twice, never lose one; every event carries
//! a stable `id` the receiver deduplicates on. Bodies are signed with
//! HMAC-SHA256 over the exact bytes sent (`x-portus-signature: sha256=…`).

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use portus_types::proto::portus::ledger::v1::UsageRecord;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_unix_micros INTEGER NOT NULL,
    body TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_unix_micros INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (next_attempt_unix_micros);
";

/// Delivery attempts before an event is dropped (with an error log).
pub const MAX_ATTEMPTS: u32 = 20;

/// What becomes an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventConfig {
    /// Percent of a subject's limit, ascending; each fires once per window.
    pub thresholds: Vec<u32>,
    /// Refusal kinds that become events (`unauthenticated`, `model_not_allowed`,
    /// `tool_not_allowed`, `budget_exhausted`).
    pub refusals: Vec<String>,
}

impl EventConfig {
    /// From `LEDGER_WEBHOOK_THRESHOLDS` (`80,100`) and
    /// `LEDGER_WEBHOOK_REFUSALS` (comma list; `none` for no refusal events).
    pub fn parse(thresholds: &str, refusals: &str) -> Result<Self, String> {
        let mut t: Vec<u32> = Vec::new();
        for part in thresholds.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let n: u32 = part.parse().map_err(|_| format!("threshold {part:?} is not a whole percent"))?;
            if n == 0 || n > 1000 {
                return Err(format!("threshold {n} must be 1-1000"));
            }
            t.push(n);
        }
        t.sort_unstable();
        t.dedup();
        let known = ["unauthenticated", "model_not_allowed", "tool_not_allowed", "budget_exhausted"];
        let mut r: Vec<String> = Vec::new();
        for part in refusals.split(',').map(str::trim).filter(|p| !p.is_empty() && *p != "none") {
            if !known.contains(&part) {
                return Err(format!("refusal kind {part:?} is not one of {}", known.join(", ")));
            }
            r.push(part.to_string());
        }
        Ok(Self { thresholds: t, refusals: r })
    }
}

/// Queue `event` for delivery; returns its id.
pub fn enqueue(conn: &Connection, event: &Value, now_micros: u64) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO outbox (created_unix_micros, body, attempts, next_attempt_unix_micros) VALUES (?1, ?2, 0, ?1)",
        params![now_micros as i64, event.to_string()],
    )?;
    Ok(conn.last_insert_rowid())
}

/// An event waiting for delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: i64,
    /// The JSON sent, with `id` set.
    pub body: String,
    pub attempts: u32,
}

/// Events due now, oldest first.
pub fn due(conn: &Connection, now_micros: u64, limit: usize) -> rusqlite::Result<Vec<Pending>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, body, attempts FROM outbox WHERE next_attempt_unix_micros <= ?1 ORDER BY id LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![now_micros as i64, limit as i64], |r| {
        let id: i64 = r.get(0)?;
        let body: String = r.get(1)?;
        Ok(Pending { id, body: with_id(&body, id), attempts: r.get::<_, i64>(2)? as u32 })
    })?;
    rows.collect()
}

fn with_id(body: &str, id: i64) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(mut m)) => {
            m.insert("id".to_string(), json!(id));
            Value::Object(m).to_string()
        }
        _ => body.to_string(),
    }
}

pub fn delivered(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM outbox WHERE id = ?1", params![id]).map(|_| ())
}

/// Try again later, or drop the event after [`MAX_ATTEMPTS`]. Returns
/// whether it was dropped.
pub fn failed(conn: &Connection, id: i64, attempts: u32, now_micros: u64) -> rusqlite::Result<bool> {
    let attempts = attempts + 1;
    if attempts >= MAX_ATTEMPTS {
        conn.execute("DELETE FROM outbox WHERE id = ?1", params![id])?;
        return Ok(true);
    }
    let next = now_micros + backoff_secs(attempts) * 1_000_000;
    conn.execute("UPDATE outbox SET attempts = ?2, next_attempt_unix_micros = ?3 WHERE id = ?1", params![id, attempts, next as i64])?;
    Ok(false)
}

/// Seconds before attempt `n + 1`: 2, 4, 8 … capped at five minutes.
pub fn backoff_secs(attempts: u32) -> u64 {
    (1u64 << attempts.min(9)).min(300)
}

pub fn pending(conn: &Connection) -> rusqlite::Result<u64> {
    let n: Option<i64> = conn.query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0)).optional()?;
    Ok(n.unwrap_or(0) as u64)
}

/// Who a budget subject is: the key behind `7`, `7:alice@example.com`
/// (`per: Subject`), or nothing for a tenant or route counter.
pub struct SubjectKey {
    pub key_id: u64,
    pub user: Option<String>,
}

pub fn subject_key(subject: &str) -> Option<SubjectKey> {
    let (id, user) = match subject.split_once(':') {
        Some((id, user)) => (id, Some(user.to_string())),
        None => (subject, None),
    };
    id.parse::<u64>().ok().map(|key_id| SubjectKey { key_id, user })
}

/// A subject crossed `threshold_pct` of its limit.
#[allow(clippy::too_many_arguments)]
pub fn threshold_event(
    policy: &str,
    subject: &str,
    window: &str,
    window_end_unix_micros: u64,
    unit: &str,
    crossing: &crate::budget::Crossing,
    key: Option<(&crate::keys::KeyRow, Option<&str>)>,
    now_micros: u64,
) -> Value {
    let mut v = json!({
        "type": "budget.threshold",
        "ts_unix_micros": now_micros,
        "policy": policy,
        "subject": subject,
        "window": window.to_ascii_uppercase(),
        "window_end_unix_micros": window_end_unix_micros,
        "unit": unit,
        "threshold_pct": crossing.threshold_pct,
        "spent": crossing.spent,
        "limit": crossing.limit,
    });
    if let Some((k, user)) = key {
        v["key_id"] = json!(k.id);
        v["tenant"] = json!(k.tenant);
        v["key_name"] = json!(k.name);
        v["key_labels"] = json!(k.labels);
        if let Some(u) = user {
            v["user"] = json!(u);
        }
    }
    v
}

/// The gateway refused a request.
pub fn refusal_event(r: &UsageRecord, labels: Option<&crate::keys::Labels>) -> Value {
    let mcp = r.dialect == "mcp";
    let mut v = json!({
        "type": "refusal",
        "ts_unix_micros": r.ts_unix_micros,
        "refusal": r.refusal,
        "rule": r.rule,
        "status": r.status,
        "key_id": r.key_id,
        "tenant": r.tenant,
        "subject": r.subject,
        "on_behalf_of": r.on_behalf_of,
        "route_host": r.route_host,
        "provider": r.provider,
        "dialect": r.dialect,
        "request_id": format!("{:016x}", r.request_id),
        "client_request_id": r.client_request_id,
    });
    if mcp {
        v["method"] = json!(r.requested_model);
        v["tool"] = json!(r.served_model);
    } else {
        v["model"] = json!(r.requested_model);
    }
    if let Some(l) = labels.filter(|l| !l.is_empty()) {
        v["key_labels"] = json!(l);
    }
    v
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// The `x-portus-signature` value for `body`.
pub fn signature(secret: &str, body: &str) -> String {
    let mac = hmac_sha256(secret.as_bytes(), body.as_bytes());
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256=");
    for b in mac {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        // Test case 2.
        assert_eq!(signature("Jefe", "what do ya want for nothing?"), "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // Test case 6: a key longer than the block is hashed first.
        let key = [0xaau8; 131];
        let mac = hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(mac[..4], [0x60, 0xe4, 0x31, 0x59]);
    }

    #[test]
    fn events_are_delivered_in_order_retried_with_backoff_and_dropped_at_the_cap() {
        let c = conn();
        let a = enqueue(&c, &json!({"type":"refusal","n":1}), 100).unwrap();
        let b = enqueue(&c, &json!({"type":"refusal","n":2}), 100).unwrap();
        assert!(b > a);
        let d = due(&c, 100, 10).unwrap();
        assert_eq!(d.iter().map(|p| p.id).collect::<Vec<_>>(), vec![a, b]);
        let first: Value = serde_json::from_str(&d[0].body).unwrap();
        assert_eq!((first["id"].as_i64(), first["n"].as_i64()), (Some(a), Some(1)), "the id is in the body");
        delivered(&c, a).unwrap();
        assert!(!failed(&c, b, 0, 100).unwrap());
        assert!(due(&c, 100, 10).unwrap().is_empty(), "not due until the backoff passes");
        assert_eq!(due(&c, 100 + 2_000_000, 10).unwrap()[0].attempts, 1);
        assert_eq!(pending(&c).unwrap(), 1);
        assert!(failed(&c, b, MAX_ATTEMPTS - 1, 100).unwrap(), "dropped at the cap");
        assert_eq!(pending(&c).unwrap(), 0);
        assert_eq!((backoff_secs(1), backoff_secs(3), backoff_secs(30)), (2, 8, 300));
    }

    #[test]
    fn config_parses_thresholds_and_refusal_kinds() {
        let c = EventConfig::parse("100, 80,80", "budget_exhausted,tool_not_allowed").unwrap();
        assert_eq!(c.thresholds, vec![80, 100]);
        assert_eq!(c.refusals, vec!["budget_exhausted".to_string(), "tool_not_allowed".to_string()]);
        assert!(EventConfig::parse("", "none").unwrap().refusals.is_empty());
        assert!(EventConfig::parse("eighty", "").is_err());
        assert!(EventConfig::parse("0", "").is_err());
        assert!(EventConfig::parse("80", "teapot").is_err());
    }

    #[test]
    fn payloads_name_the_key_the_user_and_what_was_refused() {
        assert!(matches!(subject_key("7:alice@example.com"), Some(SubjectKey { key_id: 7, user: Some(ref u) }) if u == "alice@example.com"));
        assert!(matches!(subject_key("42"), Some(SubjectKey { key_id: 42, user: None })));
        assert!(subject_key("team-a").is_none() && subject_key("route").is_none());
        let key = crate::keys::KeyRow {
            id: 7,
            tenant: "team-a".into(),
            name: "neuralsight".into(),
            allowed_models: vec![],
            allowed_tools: vec![],
            external: false,
            created_unix_micros: 0,
            revoked_unix_micros: None,
            expires_unix_secs: None,
            token_limit: Some(1_000),
            call_limit: None,
            labels: [("owner".to_string(), "alice".to_string())].into_iter().collect(),
        };
        let crossing = crate::budget::Crossing { threshold_pct: 80, spent: 800, limit: 1_000 };
        let e = threshold_event("llm/daily", "7:alice@example.com", "daily", 99, "TOKENS", &crossing, Some((&key, Some("alice@example.com"))), 5);
        assert_eq!((e["type"].as_str(), e["threshold_pct"].as_u64(), e["key_name"].as_str(), e["user"].as_str()), (Some("budget.threshold"), Some(80), Some("neuralsight"), Some("alice@example.com")));
        assert_eq!(e["key_labels"]["owner"], "alice");
        assert_eq!(e["window"], "DAILY");
        let r = UsageRecord { dialect: "mcp".into(), refusal: "tool_not_allowed".into(), rule: "key".into(), requested_model: "tools/call".into(), served_model: "qompass.fleet_report".into(), key_id: 7, request_id: 255, ..Default::default() };
        let e = refusal_event(&r, None);
        assert_eq!((e["refusal"].as_str(), e["method"].as_str(), e["tool"].as_str(), e["request_id"].as_str()), (Some("tool_not_allowed"), Some("tools/call"), Some("qompass.fleet_report"), Some("00000000000000ff")));
        assert!(e.get("model").is_none() && e.get("key_labels").is_none());
    }
}
