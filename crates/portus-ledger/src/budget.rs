//! The budget authority: one spend counter per (policy, subject, window).
//! Data planes add their deltas and read back the total; nothing is
//! granted, so nothing is lost when a window closes.

use rusqlite::{params, Connection};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS spend (
    policy TEXT NOT NULL,
    subject TEXT NOT NULL,
    window_end_unix_micros INTEGER NOT NULL,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Synced {
    pub spent_total: u64,
    pub window_end_unix_micros: u64,
}

/// Add a pod's delta to the window's counter and return the new total.
pub fn sync(conn: &Connection, policy: &str, subject: &str, window: &str, delta: u64, now_micros: u64) -> rusqlite::Result<Option<Synced>> {
    let Some(end) = window_end(window, now_micros) else { return Ok(None) };
    conn.execute(
        "INSERT INTO spend (policy, subject, window_end_unix_micros, spent) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(policy, subject, window_end_unix_micros) DO UPDATE SET spent = spent + ?4",
        params![policy, subject, end as i64, delta as i64],
    )?;
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
        let s = sync(&c, "llm/p", "key-1", "HOURLY", 0, NOW).unwrap().unwrap();
        assert_eq!((s.spent_total, s.window_end_unix_micros), (0, window_end("HOURLY", NOW).unwrap()), "a cold pod learns the total");
        assert_eq!(sync(&c, "llm/p", "key-1", "HOURLY", 339, NOW).unwrap().unwrap().spent_total, 339);
        assert_eq!(sync(&c, "llm/p", "key-1", "HOURLY", 61, NOW + 1_000_000).unwrap().unwrap().spent_total, 400, "another pod's delta");
        assert_eq!(sync(&c, "llm/p", "key-2", "HOURLY", 5, NOW).unwrap().unwrap().spent_total, 5, "subjects are separate");
        assert_eq!(sync(&c, "llm/q", "key-1", "DAILY", 7, NOW).unwrap().unwrap().spent_total, 7, "policies are separate");
        // The next window starts from zero; the old rows can be pruned.
        let next = window_end("HOURLY", NOW).unwrap() + 1;
        assert_eq!(sync(&c, "llm/p", "key-1", "HOURLY", 10, next).unwrap().unwrap().spent_total, 10);
        assert_eq!(prune(&c, next).unwrap(), 2, "the two closed hourly rows go; the daily one stays");
        assert!(sync(&c, "x", "y", "WEEKLY", 1, NOW).unwrap().is_none(), "unknown window");
    }

    #[test]
    fn window_ends_match_the_data_plane() {
        assert_eq!(window_end("hourly", NOW), Some(1_789_675_200_000_000));
        assert_eq!(window_end("DAILY", NOW), Some(1_789_689_600_000_000));
        assert_eq!(window_end("MONTHLY", NOW), Some(1_790_812_800_000_000));
    }
}
