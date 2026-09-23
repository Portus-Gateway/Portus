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
    revoked_unix_micros INTEGER
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
) -> rusqlite::Result<(KeyRow, String)> {
    let external = plaintext.is_some();
    let key = plaintext.map(str::to_string).unwrap_or_else(generate_key);
    let id: u64 = rand::random::<u64>() >> 1; // fits SQLite's signed INTEGER
    let created = now_micros();
    conn.execute(
        "INSERT INTO api_keys (id, hash, tenant, name, allowed_models, allowed_tools, external, created_unix_micros, revoked_unix_micros)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
        params![id as i64, hash_key(&key).to_vec(), tenant, name, allowed_models.join(","), allowed_tools.join(","), external, created as i64],
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
    };
    Ok((row, key))
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
        "SELECT id, tenant, name, allowed_models, external, created_unix_micros, revoked_unix_micros, allowed_tools
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
        })
    })?;
    rows.collect()
}

/// The live keys as the data planes receive them.
pub fn snapshot(conn: &Connection, version: u64) -> rusqlite::Result<KeySnapshot> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, hash, tenant, name, allowed_models, allowed_tools FROM api_keys WHERE revoked_unix_micros IS NULL ORDER BY id",
    )?;
    let keys = stmt
        .query_map([], |r| {
            Ok(KeyEntry {
                id: r.get::<_, i64>(0)? as u64,
                hash_sha256: r.get(1)?,
                tenant: r.get(2)?,
                name: r.get(3)?,
                allowed_models: split_models(&r.get::<_, String>(4)?),
                allowed_tools: split_models(&r.get::<_, String>(5)?),
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
        let (row, key) = issue(&c, "team-a", "ci", &["claude-haiku-4-5".to_string()], &["echo".to_string(), "github.*".to_string()], None).unwrap();
        let (ext_row, ext_key) = issue(&c, "team-b", "legacy", &[], &[], Some("sk-external-123")).unwrap();
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
        issue(&c, "a", "one", &[], &[], Some("dup")).unwrap();
        assert!(issue(&c, "a", "two", &[], &[], Some("dup")).is_err());
    }
}
