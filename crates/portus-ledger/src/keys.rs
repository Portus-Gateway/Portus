//! API keys the ledger issues: stored as SHA-256 hashes with their tenant,
//! name, allow lists, budgets and labels. The plaintext exists once, in the
//! response that issued it. Externally issued keys go through the same
//! table: the caller supplies the plaintext, the ledger keeps only its hash.

use std::collections::BTreeMap;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use portus_types::proto::portus::ledger::v1::{KeyEntry, KeySnapshot};

/// Prefix of every key the ledger generates.
pub const KEY_PREFIX: &str = "portus_sk_";

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    hash BLOB NOT NULL UNIQUE,
    tenant TEXT NOT NULL,
    name TEXT NOT NULL,
    allowed_models TEXT NOT NULL,
    allowed_tools TEXT NOT NULL DEFAULT '',
    external INTEGER NOT NULL,
    created_unix_micros INTEGER NOT NULL,
    revoked_unix_micros INTEGER,
    expires_unix_secs INTEGER,
    token_limit INTEGER,
    call_limit INTEGER,
    labels TEXT NOT NULL DEFAULT '{}'
);
";

/// Labels per key, and the size of each part.
const MAX_LABELS: usize = 32;
const MAX_LABEL_KEY: usize = 63;
const MAX_LABEL_VALUE: usize = 253;

pub type Labels = BTreeMap<String, String>;

/// A key as listed: never the plaintext, never the hash.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KeyRow {
    pub id: u64,
    pub tenant: String,
    pub name: String,
    pub allowed_models: Vec<String>,
    /// MCP tools a `tools/call` may name, exact or `prefix.*`; empty: any.
    pub allowed_tools: Vec<String>,
    pub external: bool,
    pub created_unix_micros: u64,
    pub revoked_unix_micros: Option<u64>,
    /// Unix seconds the key stops working at; None: never. An expired key
    /// is revoked (with `revoked_unix_micros` set) by the ledger's sweep.
    pub expires_unix_secs: Option<u64>,
    /// The key's own budget per window on token policies; None: the policy's.
    pub token_limit: Option<u64>,
    /// The key's own budget per window on call policies; None: the policy's.
    pub call_limit: Option<u64>,
    pub labels: Labels,
}

/// What `POST /v1/keys` creates.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct NewKey {
    #[serde(default)]
    pub tenant: String,
    pub name: String,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// MCP tools the key may call (`tools/call` names, exact or `prefix.*`).
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// An externally issued key to accept as-is; omitted to generate one.
    #[serde(default, rename = "key")]
    pub plaintext: Option<String>,
    /// Seconds until the key expires; omitted or 0: never.
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
    /// Omitted or 0: the policy's limit.
    #[serde(default)]
    pub token_limit: Option<u64>,
    #[serde(default)]
    pub call_limit: Option<u64>,
    #[serde(default)]
    pub labels: Labels,
}

/// What a PATCH may change on a live key; every field optional. `labels`
/// replaces the whole map (send `{}` to clear it).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct KeyPatch {
    pub tenant: Option<String>,
    pub name: Option<String>,
    pub allowed_models: Option<Vec<String>>,
    pub allowed_tools: Option<Vec<String>>,
    /// Seconds from now until the key expires; 0 clears an expiry.
    pub expires_in_secs: Option<u64>,
    /// 0 clears it.
    pub token_limit: Option<u64>,
    pub call_limit: Option<u64>,
    pub labels: Option<Labels>,
}

/// Why labels were refused, for a 400.
pub fn validate_labels(labels: &Labels) -> Result<(), String> {
    if labels.len() > MAX_LABELS {
        return Err(format!("at most {MAX_LABELS} labels"));
    }
    for (k, v) in labels {
        let key_ok = !k.is_empty()
            && k.len() <= MAX_LABEL_KEY
            && k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'));
        if !key_ok {
            return Err(format!("label key {k:?} must be 1-{MAX_LABEL_KEY} of letters, digits, - _ . /"));
        }
        if v.len() > MAX_LABEL_VALUE || v.chars().any(char::is_control) {
            return Err(format!("label {k} value must be at most {MAX_LABEL_VALUE} printable characters"));
        }
    }
    Ok(())
}

fn now_secs() -> u64 {
    now_micros() / 1_000_000
}

fn expiry(expires_in_secs: Option<u64>) -> Option<u64> {
    expires_in_secs.filter(|s| *s > 0).map(|s| now_secs() + s)
}

fn limit(v: Option<u64>) -> Option<u64> {
    v.filter(|b| *b > 0)
}

pub fn hash_key(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// A fresh key: prefix plus 40 hex characters of randomness (160 bits).
pub fn generate_key() -> String {
    let bytes: [u8; 20] = rand::random();
    let mut s = String::with_capacity(KEY_PREFIX.len() + 40);
    s.push_str(KEY_PREFIX);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn now_micros() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

fn labels_json(labels: &Labels) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}

fn labels_from(text: &str) -> Labels {
    serde_json::from_str(text).unwrap_or_default()
}

/// Store a key (generated when `plaintext` is None). Returns the row and the
/// plaintext, the only time it is available.
pub fn issue(conn: &Connection, new: &NewKey) -> rusqlite::Result<(KeyRow, String)> {
    let external = new.plaintext.is_some();
    let key = new.plaintext.clone().unwrap_or_else(generate_key);
    let id: u64 = rand::random::<u64>() >> 1; // fits SQLite's signed INTEGER
    let created = now_micros();
    let expires = expiry(new.expires_in_secs);
    let (token_limit, call_limit) = (limit(new.token_limit), limit(new.call_limit));
    conn.execute(
        "INSERT INTO api_keys (id, hash, tenant, name, allowed_models, allowed_tools, external, created_unix_micros, revoked_unix_micros,
                               expires_unix_secs, token_limit, call_limit, labels)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11, ?12)",
        params![
            id as i64,
            hash_key(&key).to_vec(),
            new.tenant,
            new.name,
            new.allowed_models.join(","),
            new.allowed_tools.join(","),
            external,
            created as i64,
            expires.map(|e| e as i64),
            token_limit.map(|b| b as i64),
            call_limit.map(|b| b as i64),
            labels_json(&new.labels),
        ],
    )?;
    let row = KeyRow {
        id,
        tenant: new.tenant.clone(),
        name: new.name.clone(),
        allowed_models: new.allowed_models.clone(),
        allowed_tools: new.allowed_tools.clone(),
        external,
        created_unix_micros: created,
        revoked_unix_micros: None,
        expires_unix_secs: expires,
        token_limit,
        call_limit,
        labels: new.labels.clone(),
    };
    Ok((row, key))
}

/// Change a live key in place. The plaintext and hash never change, so
/// clients keep working; the data planes get the change in the next
/// snapshot. `None` when there is no live key with that id.
pub fn update(conn: &Connection, id: u64, patch: &KeyPatch) -> rusqlite::Result<Option<KeyRow>> {
    let Some(current) = list(conn)?.into_iter().find(|k| k.id == id && k.revoked_unix_micros.is_none()) else { return Ok(None) };
    let next = KeyRow {
        tenant: patch.tenant.as_deref().map(str::trim).map(str::to_string).unwrap_or_else(|| current.tenant.clone()),
        name: patch.name.as_deref().map(str::trim).map(str::to_string).unwrap_or_else(|| current.name.clone()),
        allowed_models: patch.allowed_models.clone().unwrap_or_else(|| current.allowed_models.clone()),
        allowed_tools: patch.allowed_tools.clone().unwrap_or_else(|| current.allowed_tools.clone()),
        expires_unix_secs: match patch.expires_in_secs {
            Some(secs) => expiry(Some(secs)),
            None => current.expires_unix_secs,
        },
        token_limit: match patch.token_limit {
            Some(b) => limit(Some(b)),
            None => current.token_limit,
        },
        call_limit: match patch.call_limit {
            Some(b) => limit(Some(b)),
            None => current.call_limit,
        },
        labels: patch.labels.clone().unwrap_or_else(|| current.labels.clone()),
        ..current
    };
    conn.execute(
        "UPDATE api_keys SET tenant = ?2, name = ?3, allowed_models = ?4, allowed_tools = ?5, expires_unix_secs = ?6,
                             token_limit = ?7, call_limit = ?8, labels = ?9
         WHERE id = ?1 AND revoked_unix_micros IS NULL",
        params![
            id as i64,
            next.tenant,
            next.name,
            next.allowed_models.join(","),
            next.allowed_tools.join(","),
            next.expires_unix_secs.map(|e| e as i64),
            next.token_limit.map(|b| b as i64),
            next.call_limit.map(|b| b as i64),
            labels_json(&next.labels),
        ],
    )?;
    Ok(Some(next))
}

/// Revoke every live key whose expiry has passed. Returns how many.
pub fn expire(conn: &Connection, now_unix_secs: u64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE api_keys SET revoked_unix_micros = ?1 WHERE revoked_unix_micros IS NULL AND expires_unix_secs IS NOT NULL AND expires_unix_secs <= ?2",
        params![(now_unix_secs * 1_000_000) as i64, now_unix_secs as i64],
    )
}

/// Mark a key revoked. Returns whether a live key was found.
pub fn revoke(conn: &Connection, id: u64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE api_keys SET revoked_unix_micros = ?1 WHERE id = ?2 AND revoked_unix_micros IS NULL",
        params![now_micros() as i64, id as i64],
    )?;
    Ok(n > 0)
}

fn split_models(s: &str) -> Vec<String> {
    s.split(',').filter(|m| !m.is_empty()).map(str::to_string).collect()
}

/// Every key, revoked ones included, newest first.
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<KeyRow>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, tenant, name, allowed_models, external, created_unix_micros, revoked_unix_micros, allowed_tools, expires_unix_secs,
                token_limit, call_limit, labels
         FROM api_keys ORDER BY created_unix_micros DESC, id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(KeyRow {
            id: r.get::<_, i64>(0)? as u64,
            tenant: r.get(1)?,
            name: r.get(2)?,
            allowed_models: split_models(&r.get::<_, String>(3)?),
            allowed_tools: split_models(&r.get::<_, String>(7)?),
            external: r.get(4)?,
            created_unix_micros: r.get::<_, i64>(5)? as u64,
            revoked_unix_micros: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
            expires_unix_secs: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
            token_limit: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
            call_limit: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
            labels: labels_from(&r.get::<_, String>(11)?),
        })
    })?;
    rows.collect()
}

/// Labels of every key, for joining onto usage rows.
pub fn labels_by_id(conn: &Connection) -> rusqlite::Result<std::collections::HashMap<u64, Labels>> {
    let mut stmt = conn.prepare_cached("SELECT id, labels FROM api_keys WHERE labels <> '{}'")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)? as u64, labels_from(&r.get::<_, String>(1)?))))?;
    rows.collect()
}

/// The live keys as the data planes receive them.
pub fn snapshot(conn: &Connection, version: u64) -> rusqlite::Result<KeySnapshot> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, hash, tenant, name, allowed_models, allowed_tools, expires_unix_secs, token_limit, call_limit, labels FROM api_keys
         WHERE revoked_unix_micros IS NULL AND (expires_unix_secs IS NULL OR expires_unix_secs > ?1) ORDER BY id",
    )?;
    let keys = stmt
        .query_map(params![now_secs() as i64], |r| {
            Ok(KeyEntry {
                id: r.get::<_, i64>(0)? as u64,
                hash_sha256: r.get(1)?,
                tenant: r.get(2)?,
                name: r.get(3)?,
                allowed_models: split_models(&r.get::<_, String>(4)?),
                allowed_tools: split_models(&r.get::<_, String>(5)?),
                expires_unix_secs: r.get::<_, Option<i64>>(6)?.map(|v| v as u64).unwrap_or(0),
                token_limit: r.get::<_, Option<i64>>(7)?.map(|v| v as u64).unwrap_or(0),
                call_limit: r.get::<_, Option<i64>>(8)?.map(|v| v as u64).unwrap_or(0),
                labels: labels_from(&r.get::<_, String>(9)?).into_iter().collect(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(KeySnapshot { version, keys, issuers: Vec::new() })
}

#[cfg(test)]
pub(crate) fn new_key(tenant: &str, name: &str) -> NewKey {
    NewKey { tenant: tenant.into(), name: name.into(), ..Default::default() }
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
    fn generated_keys_have_the_prefix_and_enough_entropy() {
        let a = generate_key();
        let b = generate_key();
        assert!(a.starts_with(KEY_PREFIX) && a.len() == KEY_PREFIX.len() + 40, "{a}");
        assert_ne!(a, b);
    }

    #[test]
    fn issued_keys_appear_in_the_snapshot_by_hash_until_revoked() {
        let c = conn();
        let (row, key) = issue(&c, &NewKey { allowed_models: vec!["claude-haiku-4-5".into()], allowed_tools: vec!["echo".into(), "github.*".into()], ..new_key("team-a", "ci") }).unwrap();
        let (ext_row, ext_key) = issue(&c, &NewKey { plaintext: Some("sk-external-123".into()), ..new_key("team-b", "legacy") }).unwrap();
        assert_eq!(ext_key, "sk-external-123");
        assert!(ext_row.external && !row.external);

        let snap = snapshot(&c, 7).unwrap();
        assert_eq!(snap.version, 7);
        assert_eq!(snap.keys.len(), 2);
        let mine = snap.keys.iter().find(|k| k.id == row.id).unwrap();
        assert_eq!(mine.hash_sha256, hash_key(&key).to_vec());
        assert_eq!((mine.tenant.as_str(), mine.name.as_str()), ("team-a", "ci"));
        assert_eq!(mine.allowed_models, vec!["claude-haiku-4-5".to_string()]);
        assert_eq!(mine.allowed_tools, vec!["echo".to_string(), "github.*".to_string()]);
        assert!(snap.keys.iter().all(|k| k.hash_sha256.len() == 32));
        assert_eq!(list(&c).unwrap().iter().find(|k| k.id == row.id).unwrap().allowed_tools.len(), 2);

        assert!(revoke(&c, row.id).unwrap());
        assert!(!revoke(&c, row.id).unwrap(), "already revoked");
        assert!(!revoke(&c, 12345).unwrap(), "unknown");
        let snap = snapshot(&c, 8).unwrap();
        assert_eq!(snap.keys.iter().map(|k| k.id).collect::<Vec<_>>(), vec![ext_row.id]);

        let listed = list(&c).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().find(|k| k.id == row.id).unwrap().revoked_unix_micros.is_some());
    }

    #[test]
    fn the_same_plaintext_cannot_be_stored_twice() {
        let c = conn();
        issue(&c, &NewKey { plaintext: Some("dup".into()), ..new_key("a", "one") }).unwrap();
        assert!(issue(&c, &NewKey { plaintext: Some("dup".into()), ..new_key("a", "two") }).is_err());
    }

    #[test]
    fn token_and_call_limits_are_separate_stored_patched_and_pushed() {
        let c = conn();
        let (expert, _) = issue(&c, &NewKey { token_limit: Some(5_000_000), call_limit: Some(200), ..new_key("team-a", "expert") }).unwrap();
        let (plain, _) = issue(&c, &NewKey { token_limit: Some(0), ..new_key("team-a", "plain") }).unwrap();
        assert_eq!((expert.token_limit, expert.call_limit), (Some(5_000_000), Some(200)));
        assert_eq!((plain.token_limit, plain.call_limit), (None, None), "0 means none");
        let snap = snapshot(&c, 1).unwrap();
        let e = snap.keys.iter().find(|k| k.id == expert.id).unwrap();
        assert_eq!((e.token_limit, e.call_limit), (5_000_000, 200));
        let p = snap.keys.iter().find(|k| k.id == plain.id).unwrap();
        assert_eq!((p.token_limit, p.call_limit), (0, 0));
        let patched = update(&c, plain.id, &KeyPatch { call_limit: Some(50), ..Default::default() }).unwrap().unwrap();
        assert_eq!((patched.token_limit, patched.call_limit), (None, Some(50)), "one unit changes, the other stays");
        let cleared = update(&c, expert.id, &KeyPatch { token_limit: Some(0), ..Default::default() }).unwrap().unwrap();
        assert_eq!((cleared.token_limit, cleared.call_limit), (None, Some(200)));
    }

    #[test]
    fn labels_are_stored_replaced_and_pushed_and_bad_ones_refused() {
        let c = conn();
        let labels: Labels = [("owner".to_string(), "alice".to_string()), ("expert".to_string(), "neuralsight".to_string())].into_iter().collect();
        let (row, _) = issue(&c, &NewKey { labels: labels.clone(), ..new_key("team-a", "ns") }).unwrap();
        assert_eq!(list(&c).unwrap()[0].labels, labels);
        let snap = snapshot(&c, 1).unwrap();
        assert_eq!(snap.keys[0].labels.get("expert").map(String::as_str), Some("neuralsight"));
        assert_eq!(labels_by_id(&c).unwrap().get(&row.id), Some(&labels));
        let replaced = update(&c, row.id, &KeyPatch { labels: Some([("owner".to_string(), "bob".to_string())].into_iter().collect()), ..Default::default() }).unwrap().unwrap();
        assert_eq!(replaced.labels.len(), 1, "the map is replaced whole");
        let untouched = update(&c, row.id, &KeyPatch { name: Some("ns-2".into()), ..Default::default() }).unwrap().unwrap();
        assert_eq!(untouched.labels.get("owner").map(String::as_str), Some("bob"));
        assert!(update(&c, row.id, &KeyPatch { labels: Some(Labels::new()), ..Default::default() }).unwrap().unwrap().labels.is_empty());
        assert!(labels_by_id(&c).unwrap().is_empty(), "keys without labels are not listed");

        assert!(validate_labels(&labels).is_ok());
        let bad = |k: &str, v: &str| validate_labels(&[(k.to_string(), v.to_string())].into_iter().collect());
        assert!(bad("", "x").is_err());
        assert!(bad("has space", "x").is_err());
        assert!(bad("ok", "line\nbreak").is_err());
        assert!(bad(&"k".repeat(64), "x").is_err());
        assert!(bad("app.kubernetes.io/name", "").is_ok(), "an empty value is allowed");
        let many: Labels = (0..33).map(|i| (format!("k{i}"), String::new())).collect();
        assert!(validate_labels(&many).is_err());
    }

    #[test]
    fn a_key_is_changed_in_place_and_keeps_its_plaintext() {
        let c = conn();
        let (row, key) = issue(&c, &NewKey { allowed_models: vec!["claude-haiku-4-5".into()], ..new_key("team-a", "hub") }).unwrap();
        let patched = update(&c, row.id, &KeyPatch { allowed_models: Some(vec!["claude-opus-5".to_string()]), allowed_tools: Some(vec!["github.*".to_string()]), name: Some("hub-2".into()), ..Default::default() }).unwrap().unwrap();
        assert_eq!((patched.id, patched.tenant.as_str(), patched.name.as_str()), (row.id, "team-a", "hub-2"));
        assert_eq!((patched.allowed_models, patched.allowed_tools), (vec!["claude-opus-5".to_string()], vec!["github.*".to_string()]));
        let snap = snapshot(&c, 2).unwrap();
        assert_eq!(snap.keys[0].hash_sha256, hash_key(&key).to_vec(), "same key, new lists");
        assert_eq!(snap.keys[0].allowed_models, vec!["claude-opus-5".to_string()]);
        assert_eq!(update(&c, 12345, &KeyPatch::default()).unwrap(), None, "unknown id");
        assert!(revoke(&c, row.id).unwrap());
        assert_eq!(update(&c, row.id, &KeyPatch::default()).unwrap(), None, "a revoked key cannot be edited");
    }

    #[test]
    fn expiring_keys_leave_the_snapshot_and_are_revoked_by_the_sweep() {
        let c = conn();
        let (forever, _) = issue(&c, &new_key("t", "forever")).unwrap();
        let (soon, _) = issue(&c, &NewKey { expires_in_secs: Some(3600), ..new_key("t", "soon") }).unwrap();
        let now = now_secs();
        let exp = soon.expires_unix_secs.unwrap();
        assert!(exp >= now + 3599 && exp <= now + 3601, "{exp} vs {now}");
        assert_eq!(forever.expires_unix_secs, None);
        let snap = snapshot(&c, 1).unwrap();
        assert_eq!(snap.keys.len(), 2);
        assert_eq!(snap.keys.iter().find(|k| k.id == soon.id).unwrap().expires_unix_secs, exp, "the data plane learns the expiry");
        assert_eq!(snap.keys.iter().find(|k| k.id == forever.id).unwrap().expires_unix_secs, 0);
        // Rotation grace: an existing key gets an expiry; 0 clears it again.
        let graced = update(&c, forever.id, &KeyPatch { expires_in_secs: Some(60), ..Default::default() }).unwrap().unwrap();
        assert!(graced.expires_unix_secs.is_some());
        let cleared = update(&c, forever.id, &KeyPatch { expires_in_secs: Some(0), ..Default::default() }).unwrap().unwrap();
        assert_eq!(cleared.expires_unix_secs, None);
        assert_eq!(expire(&c, now).unwrap(), 0, "nothing has expired yet");
        assert_eq!(expire(&c, exp).unwrap(), 1);
        assert_eq!(snapshot(&c, 2).unwrap().keys.iter().map(|k| k.id).collect::<Vec<_>>(), vec![forever.id]);
        let soon_row = list(&c).unwrap().into_iter().find(|k| k.id == soon.id).unwrap();
        assert_eq!(soon_row.revoked_unix_micros, Some(exp * 1_000_000), "revoked at its expiry");
        assert_eq!(expire(&c, exp + 1).unwrap(), 0, "once");
    }
}
