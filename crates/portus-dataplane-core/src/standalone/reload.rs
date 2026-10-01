//! Standalone hot reload.
//!
//! One thread owns the last good config and reapplies it when:
//! - the YAML or a certificate/key file it names changes (watched by file and
//!   by directory, so in-place writes, atomic renames and symlink swaps such as
//!   certbot's `live/` or a ConfigMap's `..data` are all seen);
//! - a backend hostname resolves to a different address set
//!   (`dns_refresh_secs`);
//! - the ACME client caches a newly issued certificate.
//!
//! File events are debounced on the trailing edge: a reload runs once the
//! files have been quiet for [`QUIET`] (or [`MAX_SETTLE`] after the first
//! event), so the last write of a burst is always the one applied.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{info, warn};
use notify::{RecursiveMode, Watcher};

use super::{
    acme, content_hash, resolve_backend_hosts, system_lookup, to_compiled_config, DnsTable, Lookup, StandaloneConfig,
};
use crate::config_receiver::{apply_config, validate_config, ProxyState};

/// Quiet time after the last file event before reloading.
const QUIET: Duration = Duration::from_millis(200);
/// Reload at the latest this long after the first event of a burst, even if
/// events keep coming (a log file written next to the config).
const MAX_SETTLE: Duration = Duration::from_secs(2);

enum Trigger {
    FileChanged,
    CertIssued,
}

/// Load `path`, apply it, and keep it applied as files, DNS and ACME change.
/// Fails only if the first load fails; later errors keep the previous config.
pub fn start(path: &str, state: Arc<ProxyState>) -> Result<(), String> {
    start_with_lookup(path, state, system_lookup)
}

pub(super) fn start_with_lookup(path: &str, state: Arc<ProxyState>, lookup: Lookup) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let mut reloader = Reloader {
        path: PathBuf::from(path),
        state,
        lookup,
        last: None,
        dns: DnsTable::new(),
        seen: BTreeMap::new(),
        acme: None,
        trigger: tx.clone(),
    };
    reloader.reload_from_disk()?;

    let watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| match res {
        Ok(event) if matches!(
            event.kind,
            notify::EventKind::Create(_) | notify::EventKind::Modify(_) | notify::EventKind::Remove(_)
        ) =>
        {
            let _ = tx.send(Trigger::FileChanged);
        }
        Ok(_) => {}
        Err(e) => warn!("standalone config watcher error: {e}"),
    });
    let watcher = match watcher {
        Ok(w) => Some(w),
        Err(e) => {
            warn!("failed to create the config file watcher: {e}; edits need a restart");
            None
        }
    };
    std::thread::Builder::new()
        .name("standalone-reload".to_string())
        .spawn(move || reloader.run(rx, watcher))
        .map_err(|e| format!("failed to start the standalone reload thread: {e}"))?;
    Ok(())
}

struct Reloader {
    path: PathBuf,
    state: Arc<ProxyState>,
    lookup: Lookup,
    /// The last config that compiled and applied.
    last: Option<StandaloneConfig>,
    dns: DnsTable,
    /// The YAML plus every certificate/key file the last config read, with
    /// the hash of the contents last read: these are the files watched, and
    /// an event that leaves them all unchanged is ignored.
    seen: BTreeMap<PathBuf, u64>,
    /// Started with the first config that has an ACME listener.
    acme: Option<acme::Manager>,
    trigger: Sender<Trigger>,
}

impl Reloader {
    fn run(mut self, rx: Receiver<Trigger>, mut watcher: Option<impl Watcher>) {
        let mut watches = Watches::default();
        if let Some(w) = watcher.as_mut() {
            self.sync_watches(w, &mut watches);
        }
        let mut next_dns = self.next_dns_refresh();
        loop {
            let wait = next_dns.saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait) {
                Ok(Trigger::FileChanged) => {
                    let burst = settle(&rx);
                    if burst.closed {
                        return;
                    }
                    // Directory watches also fire for unrelated files (a log
                    // next to the YAML, the ACME cache): reload only on a
                    // real change.
                    if !self.inputs_unchanged() {
                        info!("standalone config change detected, reloading '{}'", self.path.display());
                        if let Err(e) = self.reload_from_disk() {
                            warn!("standalone config reload failed: {e}; keeping the previous config");
                        }
                    } else if burst.cert_issued {
                        self.reapply("new ACME certificate");
                    }
                }
                Ok(Trigger::CertIssued) => self.reapply("new ACME certificate"),
                Err(RecvTimeoutError::Timeout) => {
                    self.refresh_dns();
                    next_dns = self.next_dns_refresh();
                }
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if let Some(w) = watcher.as_mut() {
                self.sync_watches(w, &mut watches);
            }
        }
    }

    fn next_dns_refresh(&self) -> Instant {
        let secs = self.last.as_ref().map_or(0, |c| c.dns_refresh_secs);
        // 0 disables; a far-off deadline keeps the loop uniform.
        let every = if secs == 0 { Duration::from_secs(86_400 * 365) } else { Duration::from_secs(secs) };
        Instant::now() + every
    }

    /// Whether the YAML and every file the last config read hold the bytes
    /// last read from them.
    fn inputs_unchanged(&self) -> bool {
        !self.seen.is_empty()
            && self.seen.iter().all(|(file, hash)| std::fs::read(file).ok().map(|b| content_hash(&b)) == Some(*hash))
    }

    fn reload_from_disk(&mut self) -> Result<(), String> {
        let path = self.path.display().to_string();
        let yaml = std::fs::read_to_string(&self.path).map_err(|e| format!("failed to read config file '{path}': {e}"))?;
        // Recorded whatever happens next, so the same broken bytes are not
        // retried (and re-logged) on every unrelated event.
        self.seen.insert(self.path.clone(), content_hash(yaml.as_bytes()));
        let config: StandaloneConfig =
            serde_yaml_ng::from_str(&yaml).map_err(|e| format!("failed to parse YAML config '{path}': {e}"))?;
        let dns = resolve_backend_hosts(&config, &self.dns, self.lookup);
        self.apply(config, dns)
    }

    /// Re-resolve backend hostnames; reapply only if an address set changed.
    fn refresh_dns(&mut self) {
        let Some(config) = &self.last else { return };
        let dns = resolve_backend_hosts(config, &self.dns, self.lookup);
        if dns != self.dns {
            info!("backend DNS changed; reapplying the standalone config");
            if let Some(config) = self.last.take()
                && let Err(e) = self.apply(config, dns)
            {
                warn!("standalone config reapply failed: {e}; keeping the previous config");
            }
        }
    }

    /// Recompile the last good config (it reads the ACME cache afresh).
    fn reapply(&mut self, why: &str) {
        let Some(config) = self.last.take() else { return };
        let dns = self.dns.clone();
        info!("{why}; reapplying the standalone config");
        if let Err(e) = self.apply(config, dns) {
            warn!("standalone config reapply failed: {e}; keeping the previous config");
        }
    }

    /// Compile, validate and apply. On error `last` keeps (or gets back) the
    /// previous good config.
    fn apply(&mut self, config: StandaloneConfig, dns: DnsTable) -> Result<(), String> {
        let checked = to_compiled_config(&config, &dns)
            .and_then(|compiled| validate_config(&compiled.config).map(|warnings| (compiled, warnings)));
        let (compiled, warnings) = match checked {
            Ok(v) => v,
            Err(e) => {
                // `reapply` and `refresh_dns` took `last` out; hand it back.
                self.last.get_or_insert(config);
                return Err(e);
            }
        };
        for w in &warnings {
            warn!("config validation warning: {w}");
        }
        let (listeners, routes) = (compiled.config.listeners.len(), compiled.config.routes.len());
        apply_config(compiled.config, &self.state);
        info!("standalone config applied from '{}': {listeners} listeners, {routes} routes", self.path.display());

        if compiled.acme.is_some() && self.acme.is_none() {
            let trigger = self.trigger.clone();
            match acme::Manager::start(move || {
                let _ = trigger.send(Trigger::CertIssued);
            }) {
                Ok(manager) => self.acme = Some(manager),
                Err(e) => warn!("{e}; ACME listeners keep their placeholder certificates"),
            }
        }
        if let Some(manager) = &self.acme {
            manager.update(compiled.acme);
        }
        let yaml = self.path.clone();
        self.seen.retain(|file, _| *file == yaml);
        self.seen.extend(compiled.read_files);
        self.dns = dns;
        self.last = Some(config);
        Ok(())
    }

    /// Watch every file (in-place writes; kqueue reports nothing on the
    /// directory for those) and its directory (renames and symlink swaps
    /// replace the file a file watch was holding). A file is re-watched only
    /// when it became a different file: adding a watch can itself raise an
    /// event, so re-watching unconditionally would reload in a loop.
    fn sync_watches(&self, watcher: &mut impl Watcher, watches: &mut Watches) {
        let dirs: BTreeSet<PathBuf> = self
            .seen
            .keys()
            .map(|f| f.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf())
            .collect();
        for gone in watches.dirs.difference(&dirs) {
            let _ = watcher.unwatch(gone);
        }
        for dir in dirs.difference(&watches.dirs) {
            if let Err(e) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                warn!("failed to watch '{}': {e}; changes there need a restart", dir.display());
            }
        }
        watches.dirs = dirs;

        watches.files.retain(|file, _| {
            let keep = self.seen.contains_key(file);
            if !keep {
                let _ = watcher.unwatch(file);
            }
            keep
        });
        for file in self.seen.keys() {
            let identity = file_identity(file);
            if watches.files.get(file) == Some(&identity) {
                continue;
            }
            let _ = watcher.unwatch(file);
            if let Err(e) = watcher.watch(file, RecursiveMode::NonRecursive) {
                warn!("failed to watch '{}': {e}", file.display());
            }
            watches.files.insert(file.clone(), identity);
        }
    }
}

/// What the watcher currently holds: directories, and files with the
/// identity they had when their watch was added.
#[derive(Default)]
struct Watches {
    dirs: BTreeSet<PathBuf>,
    files: std::collections::BTreeMap<PathBuf, Option<(u64, u64)>>,
}

/// `(device, inode)` of the file `path` resolves to (through symlinks).
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let modified = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some((meta.len(), modified.as_nanos() as u64))
    }
}

/// What arrived while a burst of file events settled.
#[derive(Debug, Default, PartialEq, Eq)]
struct Burst {
    /// The ACME client cached a certificate meanwhile.
    cert_issued: bool,
    /// The channel closed: the reloader is done.
    closed: bool,
}

/// Wait out a burst of file events, remembering any issuance in between.
fn settle(rx: &Receiver<Trigger>) -> Burst {
    let deadline = Instant::now() + MAX_SETTLE;
    let mut burst = Burst::default();
    loop {
        let wait = QUIET.min(deadline.saturating_duration_since(Instant::now()));
        match rx.recv_timeout(wait) {
            Ok(trigger) => {
                burst.cert_issued |= matches!(trigger, Trigger::CertIssued);
                if Instant::now() >= deadline {
                    return burst;
                }
            }
            Err(RecvTimeoutError::Timeout) => return burst,
            Err(RecvTimeoutError::Disconnected) => {
                burst.closed = true;
                return burst;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Mutex;

    #[test]
    fn settle_waits_for_quiet() {
        let (tx, rx) = mpsc::channel();
        let sender = std::thread::spawn(move || {
            for _ in 0..4 {
                tx.send(Trigger::FileChanged).unwrap();
                std::thread::sleep(Duration::from_millis(100));
            }
            tx
        });
        let started = Instant::now();
        assert_eq!(settle(&rx), Burst::default());
        // Four events 100 ms apart, then QUIET: never before the last event.
        assert!(started.elapsed() >= Duration::from_millis(300 + 200));
        drop(sender.join().unwrap());
    }

    #[test]
    fn settle_gives_up_waiting_after_max_settle() {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let sender = std::thread::spawn(move || {
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = tx.send(Trigger::FileChanged);
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let started = Instant::now();
        assert!(!settle(&rx).closed);
        assert!(started.elapsed() < MAX_SETTLE + Duration::from_millis(500));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.join().unwrap();
    }

    #[test]
    fn settle_reports_a_closed_channel() {
        let (tx, rx) = mpsc::channel::<Trigger>();
        drop(tx);
        assert!(settle(&rx).closed);
    }

    /// Found by the Pebble e2e run: the ACME cache under the YAML's directory
    /// raised a file event, the issuance landed during the settle, and the
    /// unchanged-inputs check then skipped the reload: the issued certificate
    /// was never served.
    #[test]
    fn settle_remembers_an_issuance_inside_the_burst() {
        let (tx, rx) = mpsc::channel();
        tx.send(Trigger::FileChanged).unwrap();
        tx.send(Trigger::CertIssued).unwrap();
        tx.send(Trigger::FileChanged).unwrap();
        assert_eq!(settle(&rx), Burst { cert_issued: true, closed: false });
        drop(tx);
    }

    static ADDRS: Mutex<Vec<IpAddr>> = Mutex::new(Vec::new());

    fn table_lookup(host: &str) -> std::io::Result<Vec<IpAddr>> {
        if host == "app.internal" {
            Ok(ADDRS.lock().unwrap().clone())
        } else {
            Err(std::io::Error::other("unknown host"))
        }
    }

    /// The DNS refresh: a changed address set is applied, a failed lookup
    /// keeps the last addresses.
    #[test]
    fn dns_refresh_follows_address_changes_and_survives_failures() {
        let dir = std::env::temp_dir().join(format!("portus-reload-dns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("portus.yaml");
        std::fs::write(
            &path,
            "listeners:\n  - port: 80\n    routes:\n      - backends:\n          - address: \"app.internal:8080\"\n",
        )
        .unwrap();
        *ADDRS.lock().unwrap() = vec!["10.1.0.1".parse().unwrap()];
        let state = super::super::test_support::proxy_state();
        let (tx, _rx) = mpsc::channel();
        let mut r = Reloader {
            path: path.clone(),
            state: state.clone(),
            lookup: table_lookup,
            last: None,
            dns: DnsTable::new(),
            seen: BTreeMap::new(),
            acme: None,
            trigger: tx,
        };
        r.reload_from_disk().unwrap();
        let endpoints = |state: &ProxyState| -> Vec<String> {
            let snap = state.snapshot.load();
            let mut eps: Vec<String> =
                snap.lbs.values().flat_map(|p| p.endpoints().iter().map(|e| e.addr.to_string())).collect();
            eps.sort();
            eps
        };
        assert_eq!(endpoints(&state), vec!["10.1.0.1:8080"]);

        *ADDRS.lock().unwrap() = vec!["10.1.0.2".parse().unwrap(), "10.1.0.3".parse().unwrap()];
        r.refresh_dns();
        assert_eq!(endpoints(&state), vec!["10.1.0.2:8080", "10.1.0.3:8080"]);

        ADDRS.lock().unwrap().clear();
        r.refresh_dns();
        assert_eq!(endpoints(&state), vec!["10.1.0.2:8080", "10.1.0.3:8080"], "a failed lookup emptied the pool");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A broken edit keeps the previous config, and a later reapply (ACME,
    /// DNS) still has it.
    #[test]
    fn broken_edit_keeps_the_last_good_config() {
        let dir = std::env::temp_dir().join(format!("portus-reload-broken-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("portus.yaml");
        std::fs::write(&path, "listeners:\n  - port: 80\n    routes:\n      - hosts: [good.example.com]\n        backends: [{address: \"10.0.0.1:80\"}]\n").unwrap();
        let state = super::super::test_support::proxy_state();
        let (tx, _rx) = mpsc::channel();
        let mut r = Reloader {
            path: path.clone(),
            state: state.clone(),
            lookup: table_lookup,
            last: None,
            dns: DnsTable::new(),
            seen: BTreeMap::new(),
            acme: None,
            trigger: tx,
        };
        r.reload_from_disk().unwrap();
        std::fs::write(&path, "listeners:\n  - port: 80\n    routes:\n      - backends: [{address: \"no-port\"}]\n").unwrap();
        assert!(r.reload_from_disk().is_err());
        r.reapply("test");
        assert!(r.last.is_some());
        let snap = state.snapshot.load();
        assert!(snap.listeners_by_port[&80].iter().any(|b| b.exact.contains_key("good.example.com")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
