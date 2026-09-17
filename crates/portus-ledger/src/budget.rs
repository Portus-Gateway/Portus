//! The budget authority. For each (policy, subject, window) the ledger
//! remembers how many tokens it has granted to data planes; a grant is a
//! slice of what is left. Granted tokens count as spent whether or not the
//! data plane used them, so a window can never be overspent by more than the
//! grants outstanding when it closed.

use rusqlite::{params, Connection, OptionalExtension};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS grants (
    policy TEXT NOT NULL,
    subject TEXT NOT NULL,
    window_end_unix_micros INTEGER NOT NULL,
    granted INTEGER NOT NULL,
    spent INTEGER NOT NULL,
    PRIMARY KEY (policy, subject, window_end_unix_micros)
);
";

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

/// Tokens handed out at once: 5 % of the budget, 1k..200k, never more
/// than the budget (mirrors the data plane's low-water logic).
pub fn grant_chunk(budget_tokens: u64) -> u64 {
    let floor = 1_000.min(budget_tokens.div_ceil(4)).max(1);
    (budget_tokens / 20).clamp(floor, 200_000.max(floor)).min(budget_tokens.max(1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Granted {
    pub tokens: u64,
    pub window_end_unix_micros: u64,
    pub exhausted: bool,
}

/// Hand out the next slice for `(policy, subject)` in the window that
/// contains `now_micros`, recording `spent` from the previous grant.
pub fn grant(
    conn: &Connection,
    policy: &str,
    subject: &str,
    budget_tokens: u64,
    window: &str,
    spent: u64,
    now_micros: u64,
) -> rusqlite::Result<Option<Granted>> {
    let Some(end) = window_end(window, now_micros) else { return Ok(None) };
    let already: Option<u64> = conn
        .query_row(
            "SELECT granted FROM grants WHERE policy = ?1 AND subject = ?2 AND window_end_unix_micros = ?3",
            params![policy, subject, end as i64],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )
        .optional()?;
    let already = already.unwrap_or(0);
    let left = budget_tokens.saturating_sub(already);
    let tokens = grant_chunk(budget_tokens).min(left);
    conn.execute(
        "INSERT INTO grants (policy, subject, window_end_unix_micros, granted, spent) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(policy, subject, window_end_unix_micros) DO UPDATE SET granted = granted + ?4, spent = spent + ?5",
        params![policy, subject, end as i64, tokens as i64, spent as i64],
    )?;
    Ok(Some(Granted { tokens, window_end_unix_micros: end, exhausted: tokens == 0 || already + tokens >= budget_tokens }))
}

/// Drop windows that ended before `now_micros`.
pub fn prune(conn: &Connection, now_micros: u64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM grants WHERE window_end_unix_micros < ?1", params![now_micros as i64])
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
    fn grants_slice_the_budget_until_it_is_gone_then_say_exhausted() {
        let c = conn();
        // Budget 100 → chunk 25: four grants share the window between pods.
        for expected in [(25, false), (25, false), (25, false), (25, true)] {
            let g = grant(&c, "llm/p", "key-1", 100, "HOURLY", 0, NOW).unwrap().unwrap();
            assert_eq!((g.tokens, g.exhausted), expected);
        }
        let g = grant(&c, "llm/p", "key-1", 100, "HOURLY", 339, NOW + 5).unwrap().unwrap();
        assert_eq!((g.tokens, g.exhausted), (0, true), "nothing left in the window");
        // Another subject has its own counter.
        let g = grant(&c, "llm/p", "key-2", 100, "HOURLY", 0, NOW).unwrap().unwrap();
        assert_eq!(g.tokens, 25);
        // Budget 5000 → chunk 1000 → five grants, the fifth marks exhaustion.
        let mut got = Vec::new();
        for _ in 0..6 {
            let g = grant(&c, "llm/big", "k", 5_000, "DAILY", 0, NOW).unwrap().unwrap();
            got.push((g.tokens, g.exhausted));
        }
        assert_eq!(got, vec![(1000, false), (1000, false), (1000, false), (1000, false), (1000, true), (0, true)]);
        // Next window starts fresh.
        let next = window_end("HOURLY", NOW).unwrap() + 1;
        let g = grant(&c, "llm/p", "key-1", 100, "HOURLY", 0, next).unwrap().unwrap();
        assert_eq!((g.tokens, g.exhausted), (25, false));
        assert_eq!(prune(&c, next).unwrap(), 2, "the two closed hourly windows go; the daily one is still open");
        assert!(grant(&c, "x", "y", 1, "WEEKLY", 0, NOW).unwrap().is_none(), "unknown window");
    }

    #[test]
    fn spent_is_accumulated_per_window() {
        let c = conn();
        grant(&c, "p", "s", 10_000, "HOURLY", 0, NOW).unwrap();
        grant(&c, "p", "s", 10_000, "HOURLY", 700, NOW).unwrap();
        grant(&c, "p", "s", 10_000, "HOURLY", 250, NOW).unwrap();
        let spent: i64 = c.query_row("SELECT spent FROM grants WHERE policy = 'p'", [], |r| r.get(0)).unwrap();
        assert_eq!(spent, 950);
    }

    #[test]
    fn window_ends_match_the_data_plane() {
        assert_eq!(window_end("hourly", NOW), Some(1_789_675_200_000_000));
        assert_eq!(window_end("DAILY", NOW), Some(1_789_689_600_000_000));
        assert_eq!(window_end("MONTHLY", NOW), Some(1_790_812_800_000_000));
    }
}
