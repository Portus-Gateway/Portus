//! API keys the ledger issues: stored as SHA-256 hashes with their tenant,
//! name, model list and tool list. The plaintext exists once, in the response that
//! issued it. Externally issued keys go through the same table: the caller
//! supplies the plaintext, the ledger keeps only its hash.

use rusqlite::{params, Connection};
use serde::Serialize;
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
    expires_unix_secs INTEGER
);
";

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
}

/// What a PATCH may change on a live key; every field optional.
#[derive(Debug, Clone, Default, serde::Deserialize, PartialEq, Eq)]
pub struct KeyPatch {
    pub tenant: Option<String>,
    pub name: Option<String>,
    pub allowed_models: Option<Vec<String>>,
    pub allowed_tools: Option<Vec<String>>,
    /// Seconds from now until the key expires; 0 clears an expiry.
    pub expires_in_secs: Option<u64>,
}

fn now_secs() -> u64 {
    now_micros() / 1_000_000
}

fn expiry(expires_in_secs: Option<u64>) -> Option<u64> {
    expires_in_secs.filter(|s| *s > 0).map(|s| now_secs() + s)
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

/// Store a key (generated when `plaintext` is None). Returns the row and the
/// plaintext, the only time it is available.
pub fn issue(
    conn: &Connection,
    tenant: &str,
    name: &str,
    allowed_models: &[String],
    allowed_tools: &[String],
    plaintext: Option<&str>,
    expires_in_secs: Option<u64>,
) -> rusqlite::Result<(KeyRow, String)> {
    let external = plaintext.is_some();
    let key = plaintext.map(str::to_string).unwrap_or_else(generate_key);
    let id: u64 = rand::random::<u64>() >> 1; // fits SQLite's signed INTEGER
    let created = now_micros();
    let expires = expiry(expires_in_secs);
    conn.execute(
        "INSERT INTO api_keys (id, hash, tenant, name, allowed_models, allowed_tools, external, created_unix_micros, revoked_unix_micros, expires_unix_secs)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)",
        params![id as i64, hash_key(&key).to_vec(), tenant, name, allowed_models.join(","), allowed_tools.join(","), external, created as i64, expires.map(|e| e as i64)],
    )?;
    let row = KeyRow {
        id,
        tenant: tenant.to_string(),
        name: name.to_string(),
        allowed_models: allowed_models.to_vec(),
        allowed_tools: allowed_tools.to_vec(),
        external,
        created_unix_micros: created,
        revoked_unix_micros: None,
        expires_unix_secs: expires,
    };
    Ok((row, key))
}

/// Change a live key in place. The plaintext and hash never change, so
/// clients keep working; the data planes get the new lists in the next
/// snapshot. `None` when there is no live key with that id.
pub fn update(conn: &Connection, id: u64, patch: &KeyPatch) -> rusqlite::Result<Option<KeyRow>> {
    let Some(current) = list(conn)?.into_iter().find(|k| k.id == id && k.revoked_unix_micros.is_none()) else { return Ok(None) };
    let tenant = patch.tenant.as_deref().map(str::trim).unwrap_or(&current.tenant);
    let name = patch.name.as_deref().map(str::trim).unwrap_or(&current.name);
    let models = patch.allowed_models.as_ref().unwrap_or(&current.allowed_models);
    let tools = patch.allowed_tools.as_ref().unwrap_or(&current.allowed_tools);
    let expires = match patch.expires_in_secs {
        Some(secs) => expiry(Some(secs)),
        None => current.expires_unix_secs,
    };
    conn.execute(
        "UPDATE api_keys SET tenant = ?2, name = ?3, allowed_models = ?4, allowed_tools = ?5, expires_unix_secs = ?6 WHERE id = ?1 AND revoked_unix_micros IS NULL",
        params![id as i64, tenant, name, models.join(","), tools.join(","), expires.map(|e| e as i64)],
    )?;
    Ok(Some(KeyRow { tenant: tenant.to_string(), name: name.to_string(), allowed_models: models.clone(), allowed_tools: tools.clone(), expires_unix_secs: expires, ..current }))
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
        "SELECT id, tenant, name, allowed_models, external, created_unix_micros, revoked_unix_micros, allowed_tools, expires_unix_secs
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
        })
    })?;
    rows.collect()
}

/// The live keys as the data planes receive them.
pub fn snapshot(conn: &Connection, version: u64) -> rusqlite::Result<KeySnapshot> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, hash, tenant, name, allowed_models, allowed_tools, expires_unix_secs FROM api_keys
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
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(KeySnapshot { version, keys, issuers: Vec::new() })
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
        let (row, key) = issue(&c, "team-a", "ci", &["claude-haiku-4-5".to_string()], &["echo".to_string(), "github.*".to_string()], None, None).unwrap();
        let (ext_row, ext_key) = issue(&c, "team-b", "legacy", &[], &[], Some("sk-external-123"), None).unwrap();
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
        issue(&c, "a", "one", &[], &[], Some("dup"), None).unwrap();
        assert!(issue(&c, "a", "two", &[], &[], Some("dup"), None).is_err());
    }

    #[test]
    fn a_key_is_changed_in_place_and_keeps_its_plaintext() {
        let c = conn();
        let (row, key) = issue(&c, "team-a", "hub", &["claude-haiku-4-5".to_string()], &[], None, None).unwrap();
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
        let (forever, _) = issue(&c, "t", "forever", &[], &[], None, None).unwrap();
        let (soon, _) = issue(&c, "t", "soon", &[], &[], None, Some(3600)).unwrap();
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
