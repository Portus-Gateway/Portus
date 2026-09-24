//! The budget authority: one spend counter per (policy, subject, window).
//! Data planes add their deltas and read back the total; nothing is
//! granted, so nothing is lost when a window closes.

use rusqlite::{params, Connection};
use serde::Serialize;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS spend (
    policy TEXT NOT NULL,
    subject TEXT NOT NULL,
    window_end_unix_micros INTEGER NOT NULL,
    spent INTEGER NOT NULL,
    subject_limit INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (policy, subject, window_end_unix_micros)
);
CREATE TABLE IF NOT EXISTS policies (
    policy TEXT PRIMARY KEY,
    limit_units INTEGER NOT NULL,
    unit TEXT NOT NULL,
    window TEXT NOT NULL,
    per TEXT NOT NULL,
    fail_open INTEGER NOT NULL,
    updated_unix_micros INTEGER NOT NULL
);
";

/// The policy as a data plane applies it, learned from its syncs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shape {
    pub limit: u64,
    pub unit: String,
    pub per: String,
    pub fail_open: bool,
    /// The limit this subject is held to (a key override, or `limit`).
    pub subject_limit: u64,
}

/// One policy with every subject the ledger has seen spend under it in the
/// current window: what `/v1/limits` answers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PolicyLimits {
    pub policy: String,
    pub limit: u64,
    pub unit: String,
    pub window: String,
    pub per: String,
    pub fail_open: bool,
    pub window_end_unix_micros: u64,
    pub updated_unix_micros: u64,
    pub subjects: Vec<SubjectSpend>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SubjectSpend {
    pub subject: String,
    /// The limit this subject is held to: the policy's, or its key's own.
    pub limit: u64,
    pub spent: u64,
    pub remaining: i64,
}

/// Fixed, UTC-aligned windows (mirrors the data plane's).
pub fn window_end(window: &str, now_micros: u64) -> Option<u64> {
    const MICROS: u64 = 1_000_000;
    let secs = now_micros / MICROS;
    Some(match window.to_ascii_uppercase().as_str() {
        "HOURLY" => (secs / 3600 + 1) * 3600 * MICROS,
        "DAILY" => (secs / 86_400 + 1) * 86_400 * MICROS,
        "MONTHLY" => {
            let days = (secs / 86_400) as i64;
            let (y, m, _) = civil_from_days(days);
            let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            (days_from_civil(ny, nm, 1) as u64) * 86_400 * MICROS
        }
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Synced {
    pub spent_total: u64,
    pub window_end_unix_micros: u64,
}

/// Add a pod's delta to the window's counter and return the new total.
/// `shape` (when the data plane sent one) keeps the policy table and the
/// subject's limit current for `/v1/limits`.
pub fn sync(conn: &Connection, policy: &str, subject: &str, window: &str, delta: u64, now_micros: u64, shape: Option<&Shape>) -> rusqlite::Result<Option<Synced>> {
    let Some(end) = window_end(window, now_micros) else { return Ok(None) };
    let subject_limit = shape.map_or(0, |s| if s.subject_limit > 0 { s.subject_limit } else { s.limit });
    conn.execute(
        "INSERT INTO spend (policy, subject, window_end_unix_micros, spent, subject_limit) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(policy, subject, window_end_unix_micros) DO UPDATE SET spent = spend.spent + ?4, subject_limit = CASE WHEN ?5 > 0 THEN ?5 ELSE spend.subject_limit END",
        params![policy, subject, end as i64, delta as i64, subject_limit as i64],
    )?;
    if let Some(s) = shape.filter(|s| s.limit > 0 && !s.unit.is_empty()) {
        conn.execute(
            "INSERT INTO policies (policy, limit_units, unit, window, per, fail_open, updated_unix_micros) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(policy) DO UPDATE SET limit_units = ?2, unit = ?3, window = ?4, per = ?5, fail_open = ?6, updated_unix_micros = ?7",
            params![policy, s.limit as i64, s.unit, window.to_ascii_uppercase(), s.per, s.fail_open, now_micros as i64],
        )?;
    }
    let total: i64 = conn.query_row(
        "SELECT spent FROM spend WHERE policy = ?1 AND subject = ?2 AND window_end_unix_micros = ?3",
        params![policy, subject, end as i64],
        |r| r.get(0),
    )?;
    Ok(Some(Synced { spent_total: total as u64, window_end_unix_micros: end }))
}

/// Drop windows that ended before `now_micros`.
pub fn prune(conn: &Connection, now_micros: u64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM spend WHERE window_end_unix_micros < ?1", params![now_micros as i64])
}

/// Every policy a data plane has synced, with the current window's spend
/// per subject. A policy appears after its first budgeted request; a
/// subject after its first sync in the window.
pub fn limits(conn: &Connection, now_micros: u64) -> rusqlite::Result<Vec<PolicyLimits>> {
    let mut stmt = conn.prepare_cached("SELECT policy, limit_units, unit, window, per, fail_open, updated_unix_micros FROM policies ORDER BY policy")?;
    let policies = stmt
        .query_map([], |r| {
            Ok(PolicyLimits {
                policy: r.get(0)?,
                limit: r.get::<_, i64>(1)? as u64,
                unit: r.get(2)?,
                window: r.get(3)?,
                per: r.get(4)?,
                fail_open: r.get(5)?,
                window_end_unix_micros: 0,
                updated_unix_micros: r.get::<_, i64>(6)? as u64,
                subjects: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut subjects_stmt = conn.prepare_cached(
        "SELECT subject, spent, subject_limit FROM spend WHERE policy = ?1 AND window_end_unix_micros = ?2 ORDER BY spent DESC, subject",
    )?;
    let mut out = Vec::with_capacity(policies.len());
    for mut p in policies {
        let Some(end) = window_end(&p.window, now_micros) else { continue };
        p.window_end_unix_micros = end;
        p.subjects = subjects_stmt
            .query_map(params![p.policy, end as i64], |r| {
                let spent = r.get::<_, i64>(1)? as u64;
                let stored = r.get::<_, i64>(2)? as u64;
                let limit = if stored > 0 { stored } else { p.limit };
                Ok(SubjectSpend { subject: r.get(0)?, limit, spent, remaining: limit as i64 - spent as i64 })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        out.push(p);
    }
    Ok(out)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c
    }

    const NOW: u64 = 1_789_673_548_000_000; // 2026-09-17T19:32:28Z

    #[test]
    fn deltas_from_every_pod_add_up_per_subject_and_window() {
        let c = conn();
        let s = sync(&c, "llm/p", "key-1", "HOURLY", 0, NOW, None).unwrap().unwrap();
        assert_eq!((s.spent_total, s.window_end_unix_micros), (0, window_end("HOURLY", NOW).unwrap()), "a cold pod learns the total");
        assert_eq!(sync(&c, "llm/p", "key-1", "HOURLY", 339, NOW, None).unwrap().unwrap().spent_total, 339);
        assert_eq!(sync(&c, "llm/p", "key-1", "HOURLY", 61, NOW + 1_000_000, None).unwrap().unwrap().spent_total, 400, "another pod's delta");
        assert_eq!(sync(&c, "llm/p", "key-2", "HOURLY", 5, NOW, None).unwrap().unwrap().spent_total, 5, "subjects are separate");
        assert_eq!(sync(&c, "llm/q", "key-1", "DAILY", 7, NOW, None).unwrap().unwrap().spent_total, 7, "policies are separate");
        // The next window starts from zero; the old rows can be pruned.
        let next = window_end("HOURLY", NOW).unwrap() + 1;
        assert_eq!(sync(&c, "llm/p", "key-1", "HOURLY", 10, next, None).unwrap().unwrap().spent_total, 10);
        assert_eq!(prune(&c, next).unwrap(), 2, "the two closed hourly rows go; the daily one stays");
        assert!(sync(&c, "x", "y", "WEEKLY", 1, NOW, None).unwrap().is_none(), "unknown window");
    }

    #[test]
    fn limits_describe_every_synced_policy_with_its_subjects_and_their_own_limits() {
        let c = conn();
        let shape = |limit: u64, subject_limit: u64| Shape { limit, unit: "TOKENS".into(), per: "KEY".into(), fail_open: true, subject_limit };
        assert!(limits(&c, NOW).unwrap().is_empty(), "nothing synced yet");
        sync(&c, "llm/daily", "101", "DAILY", 400, NOW, Some(&shape(1_000, 0))).unwrap();
        sync(&c, "llm/daily", "202", "DAILY", 4_500, NOW, Some(&shape(1_000, 5_000))).unwrap();
        sync(&c, "mcp/calls", "7:alice", "HOURLY", 3, NOW, Some(&Shape { limit: 3, unit: "CALLS".into(), per: "SUBJECT".into(), fail_open: false, subject_limit: 0 })).unwrap();
        // A sync without a shape (an older data plane) still counts spend.
        sync(&c, "llm/daily", "101", "DAILY", 100, NOW, None).unwrap();
        let l = limits(&c, NOW).unwrap();
        assert_eq!(l.iter().map(|p| p.policy.as_str()).collect::<Vec<_>>(), vec!["llm/daily", "mcp/calls"]);
        let daily = &l[0];
        assert_eq!((daily.limit, daily.unit.as_str(), daily.window.as_str(), daily.per.as_str(), daily.fail_open), (1_000, "TOKENS", "DAILY", "KEY", true));
        assert_eq!(daily.window_end_unix_micros, window_end("DAILY", NOW).unwrap());
        assert_eq!(
            daily.subjects.iter().map(|s| (s.subject.as_str(), s.limit, s.spent, s.remaining)).collect::<Vec<_>>(),
            vec![("202", 5_000, 4_500, 500), ("101", 1_000, 500, 500)],
            "a key override shows as that subject's limit"
        );
        let calls = &l[1];
        assert_eq!((calls.unit.as_str(), calls.per.as_str(), calls.fail_open), ("CALLS", "SUBJECT", false));
        assert_eq!(calls.subjects[0].remaining, 0);
        // A raised policy limit is reflected on the next sync.
        sync(&c, "llm/daily", "101", "DAILY", 0, NOW, Some(&shape(2_000, 0))).unwrap();
        let l = limits(&c, NOW).unwrap();
        assert_eq!((l[0].limit, l[0].subjects.iter().find(|s| s.subject == "101").unwrap().limit), (2_000, 2_000));
        assert!(limits(&c, window_end("DAILY", NOW).unwrap() + 1).unwrap()[0].subjects.is_empty(), "a new window starts empty");
    }

    #[test]
    fn window_ends_match_the_data_plane() {
        assert_eq!(window_end("hourly", NOW), Some(1_789_675_200_000_000));
        assert_eq!(window_end("DAILY", NOW), Some(1_789_689_600_000_000));
        assert_eq!(window_end("MONTHLY", NOW), Some(1_790_812_800_000_000));
    }
}
