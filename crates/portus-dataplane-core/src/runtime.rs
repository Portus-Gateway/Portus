//! Worker-thread sizing shared by every network stack.

/// Number of proxy worker threads.
///
/// `available_parallelism()` reports the *node's* CPUs, which is wrong for a
/// container with a CPU limit: several dataplanes on one node would each spawn
/// node-many threads and oversubscribe it (twelve per-Gateway dataplanes on a
/// 10-CPU node asked for 120 worker threads, and the resulting scheduling
/// delays showed up as multi-second stalls). `DATAPLANE_THREADS` (the chart's
/// `dataplane.threads`, passed through by the provisioner) wins; otherwise the
/// cgroup v2 CPU quota (a CPU limit), then the node's CPU count. Pods have no
/// CPU limit by default, so they size like any uncapped proxy on the node.
pub fn worker_threads() -> usize {
    let host = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if let Ok(v) = std::env::var("DATAPLANE_THREADS")
        && let Ok(n) = v.trim().parse::<usize>()
        && n > 0
    {
        return n.min(host);
    }
    if let Some(n) = cgroup_cpu_quota() {
        return n.clamp(1, host);
    }
    host
}

/// CPU count implied by the cgroup v2 quota (`/sys/fs/cgroup/cpu.max`), rounded
/// up. Returns None when unlimited or unreadable (non-Linux, cgroup v1).
fn cgroup_cpu_quota() -> Option<usize> {
    let raw = std::fs::read_to_string("/sys/fs/cgroup/cpu.max").ok()?;
    parse_cpu_max(&raw)
}

fn parse_cpu_max(raw: &str) -> Option<usize> {
    let mut parts = raw.split_whitespace();
    let quota = parts.next()?;
    if quota == "max" {
        return None;
    }
    let quota: u64 = quota.parse().ok()?;
    let period: u64 = parts.next()?.parse().ok()?;
    if period == 0 {
        return None;
    }
    Some(quota.div_ceil(period).max(1) as usize)
}

#[cfg(test)]
mod tests {
    use super::parse_cpu_max;

    #[test]
    fn cpu_max_rounds_the_quota_up_and_treats_max_as_unlimited() {
        assert_eq!(parse_cpu_max("max 100000\n"), None);
        assert_eq!(parse_cpu_max("200000 100000\n"), Some(2));
        assert_eq!(parse_cpu_max("250000 100000\n"), Some(3), "2.5 CPUs round up");
        assert_eq!(parse_cpu_max("50000 100000\n"), Some(1), "never below one");
        assert_eq!(parse_cpu_max("100000 0\n"), None);
        assert_eq!(parse_cpu_max("garbage"), None);
    }
}
