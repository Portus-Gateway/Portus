use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use kube::api::{Api, Patch, PatchParams, PostParams};

use crate::status::with_write_timeout;

const DEFAULT_LEASE_NAME: &str = "portus-gateway-controller";
const LEASE_DURATION_SECONDS: i32 = 15;
const RENEWAL_INTERVAL_SECS: u64 = 5; // leaseDuration / 3
const MAX_RENEWAL_FAILURES: u32 = 3;

/// Configuration for leader election.
pub struct LeaderElectionConfig {
    pub lease_name: String,
    pub namespace: String,
    pub identity: String,
}

impl LeaderElectionConfig {
    /// Build config from environment variables with sensible defaults.
    ///
    /// - `LEASE_NAME` overrides the lease resource name (default: `portus-gateway-controller`)
    /// - `LEASE_NAMESPACE` overrides the namespace (default: read from service account token)
    /// - `HOSTNAME` provides the holder identity (default: `unknown`)
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let lease_name = std::env::var("LEASE_NAME").unwrap_or_else(|_| DEFAULT_LEASE_NAME.to_string());

        let namespace = std::env::var("LEASE_NAMESPACE").or_else(|_| {
            std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
                .map(|s| s.trim().to_string())
        }).unwrap_or_else(|_| "default".to_string());

        let identity = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());

        Ok(Self {
            lease_name,
            namespace,
            identity,
        })
    }
}

fn now_micro_time() -> MicroTime {
    MicroTime(k8s_openapi::jiff::Timestamp::now())
}

/// Attempt to acquire or renew the lease.
///
/// Returns:
/// - `Ok(true)` if we are the leader (acquired or renewed)
/// - `Ok(false)` if another instance holds a valid (non-expired) lease
/// - `Err(...)` on API errors
async fn try_acquire_or_renew(
    leases: &Api<Lease>,
    lease_name: &str,
    identity: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    match with_write_timeout("lease get", leases.get(lease_name)).await {
        Ok(existing) => {
            let spec = existing.spec.as_ref();
            let holder = spec.and_then(|s| s.holder_identity.as_deref()).unwrap_or("");

            if holder == identity {
                // We already hold it -- renew.
                let patch = serde_json::json!({
                    "spec": {
                        "renewTime": now_micro_time(),
                        "leaseDurationSeconds": LEASE_DURATION_SECONDS,
                    }
                });
                with_write_timeout(
                    "lease renew",
                    leases.patch(
                        lease_name,
                        &PatchParams::apply("portus-leader-election").force(),
                        &Patch::Apply(lease_from_json(&patch, lease_name)),
                    ),
                )
                .await?;
                return Ok(true);
            }

            // Someone else holds it (or it was released). Check whether it is free.
            let renew_time = spec.and_then(|s| s.renew_time.as_ref()).map(|t| t.0);
            let duration = spec.and_then(|s| s.lease_duration_seconds).unwrap_or(LEASE_DURATION_SECONDS);
            let now = k8s_openapi::jiff::Timestamp::now();
            if !lease_is_free(holder, renew_time, duration, now) {
                return Ok(false);
            }

            // Lease released, expired, or never renewed -- take it over.
            let transitions = spec.and_then(|s| s.lease_transitions).unwrap_or(0);
            let patch = serde_json::json!({
                "spec": {
                    "holderIdentity": identity,
                    "acquireTime": now_micro_time(),
                    "renewTime": now_micro_time(),
                    "leaseDurationSeconds": LEASE_DURATION_SECONDS,
                    "leaseTransitions": transitions + 1,
                }
            });
            with_write_timeout(
                "lease takeover",
                leases.patch(
                    lease_name,
                    &PatchParams::apply("portus-leader-election").force(),
                    &Patch::Apply(lease_from_json(&patch, lease_name)),
                ),
            )
            .await?;
            Ok(true)
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            // Lease does not exist yet -- create it.
            let lease = Lease {
                metadata: ObjectMeta {
                    name: Some(lease_name.to_string()),
                    ..Default::default()
                },
                spec: Some(k8s_openapi::api::coordination::v1::LeaseSpec {
                    holder_identity: Some(identity.to_string()),
                    acquire_time: Some(now_micro_time()),
                    renew_time: Some(now_micro_time()),
                    lease_duration_seconds: Some(LEASE_DURATION_SECONDS),
                    lease_transitions: Some(0),
                    ..Default::default()
                }),
            };
            with_write_timeout("lease create", leases.create(&PostParams::default(), &lease)).await?;
            Ok(true)
        }
        Err(e) => Err(Box::new(e)),
    }
}

/// Whether a lease held by someone else can be taken over: released (empty
/// holder), never renewed, or renewed longer ago than its duration.
fn lease_is_free(
    holder: &str,
    renew_time: Option<k8s_openapi::jiff::Timestamp>,
    duration_secs: i32,
    now: k8s_openapi::jiff::Timestamp,
) -> bool {
    if holder.is_empty() {
        return true;
    }
    match renew_time {
        None => true,
        Some(renewed_at) => {
            let expires_at =
                renewed_at + std::time::Duration::from_secs(duration_secs.max(0) as u64);
            now >= expires_at
        }
    }
}

/// Release the lease on graceful shutdown so the successor can acquire it
/// immediately instead of waiting up to `LEASE_DURATION_SECONDS` for expiry.
/// Mirrors client-go: clear the holder and shorten the duration to 1s. Only
/// touches the lease if we still hold it.
pub async fn release_lease(client: kube::Client, config: &LeaderElectionConfig) {
    let leases: Api<Lease> = Api::namespaced(client, &config.namespace);
    let existing = match with_write_timeout("lease get", leases.get(&config.lease_name)).await {
        Ok(existing) => existing,
        Err(e) => {
            log::warn!("leader election: could not read lease before release: {e}");
            return;
        }
    };
    let spec = existing.spec.as_ref();
    let held_by_us = spec
        .and_then(|s| s.holder_identity.as_deref())
        .is_some_and(|h| h == config.identity);
    if !held_by_us {
        return;
    }
    // Server-side apply with our field manager owns the whole spec, so carry
    // the bookkeeping fields forward or the apply would drop them.
    let patch = serde_json::json!({
        "spec": {
            "holderIdentity": "",
            "acquireTime": spec.and_then(|s| s.acquire_time.clone()),
            "leaseTransitions": spec.and_then(|s| s.lease_transitions).unwrap_or(0),
            "renewTime": now_micro_time(),
            "leaseDurationSeconds": 1,
        }
    });
    match with_write_timeout(
        "lease release",
        leases.patch(
            &config.lease_name,
            &PatchParams::apply("portus-leader-election").force(),
            &Patch::Apply(lease_from_json(&patch, &config.lease_name)),
        ),
    )
    .await
    {
        Ok(_) => log::info!(
            "leader election: released lease {}/{}",
            config.namespace,
            config.lease_name
        ),
        Err(e) => log::warn!("leader election: failed to release lease: {e}"),
    }
}

/// Build a partial Lease object for server-side apply patches.
fn lease_from_json(value: &serde_json::Value, name: &str) -> Lease {
    let mut lease: Lease = serde_json::from_value(value.clone()).unwrap_or_default();
    lease.metadata.name = Some(name.to_string());
    // Server-side apply requires apiVersion and kind; kube-rs fills them from
    // the Resource trait, but we still need the metadata.
    lease
}

/// Block until this instance becomes the leader by acquiring the Lease.
pub async fn acquire_lease(
    client: kube::Client,
    config: &LeaderElectionConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let leases: Api<Lease> = Api::namespaced(client, &config.namespace);

    loop {
        match try_acquire_or_renew(&leases, &config.lease_name, &config.identity).await {
            Ok(true) => {
                log::info!(
                    "leader election: acquired lease {}/{} (identity={})",
                    config.namespace,
                    config.lease_name,
                    config.identity
                );
                return Ok(());
            }
            Ok(false) => {
                log::info!(
                    "leader election: another instance holds lease {}/{}, waiting...",
                    config.namespace,
                    config.lease_name
                );
                tokio::time::sleep(std::time::Duration::from_secs(RENEWAL_INTERVAL_SECS)).await;
            }
            Err(e) => {
                log::warn!("leader election: lease acquisition error: {}, retrying...", e);
                tokio::time::sleep(std::time::Duration::from_secs(RENEWAL_INTERVAL_SECS)).await;
            }
        }
    }
}

/// Spawn a background task that renews the lease periodically.
///
/// Returns a `tokio::sync::watch::Receiver<bool>` that flips to `false` when
/// leadership is lost (after `MAX_RENEWAL_FAILURES` consecutive failures).
/// The caller should select on this receiver and initiate shutdown.
pub fn spawn_renewal_task(
    client: kube::Client,
    config: &LeaderElectionConfig,
) -> tokio::sync::watch::Receiver<bool> {
    let (leader_tx, leader_rx) = tokio::sync::watch::channel(true);
    let namespace = config.namespace.clone();
    let lease_name = config.lease_name.clone();
    let identity = config.identity.clone();

    tokio::spawn(async move {
        let leases: Api<Lease> = Api::namespaced(client, &namespace);
        let mut consecutive_failures: u32 = 0;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(RENEWAL_INTERVAL_SECS)).await;

            // Convert Result to a Send-safe enum before any .await points
            let outcome = match try_acquire_or_renew(&leases, &lease_name, &identity).await {
                Ok(true) => 0u8,  // renewed
                Ok(false) => 1u8, // someone else holds it
                Err(e) => {
                    // Handle error immediately (before await) so Box<dyn Error> doesn't cross await
                    consecutive_failures += 1;
                    log::warn!(
                        "leader election: renewal failed ({}/{}): {}",
                        consecutive_failures,
                        MAX_RENEWAL_FAILURES,
                        e
                    );
                    if consecutive_failures >= MAX_RENEWAL_FAILURES {
                        log::error!(
                            "leader election: {} consecutive renewal failures, shutting down",
                            MAX_RENEWAL_FAILURES
                        );
                        let _ = leader_tx.send(false);
                        return;
                    }
                    2u8 // error (already handled)
                }
            };
            match outcome {
                0 => {
                    consecutive_failures = 0;
                    log::debug!("leader election: renewed lease {}/{}", namespace, lease_name);
                }
                1 => {
                    // Someone else holds the lease. During upgrades, the old pod
                    // may briefly re-acquire the lease before terminating. Instead of
                    // immediately shutting down, wait for the lease to expire and
                    // re-acquire it — there's only one desired replica.
                    consecutive_failures += 1;
                    log::warn!(
                        "leader election: lease {}/{} held by another instance ({}/{}), waiting for expiry...",
                        namespace,
                        lease_name,
                        consecutive_failures,
                        MAX_RENEWAL_FAILURES
                    );
                    if consecutive_failures >= MAX_RENEWAL_FAILURES {
                        log::error!(
                            "leader election: lost lease {}/{} after {} attempts, shutting down",
                            namespace,
                            lease_name,
                            MAX_RENEWAL_FAILURES
                        );
                        let _ = leader_tx.send(false);
                        return;
                    }
                    // Wait for lease duration to expire before retrying
                    tokio::time::sleep(std::time::Duration::from_secs(
                        LEASE_DURATION_SECONDS as u64,
                    ))
                    .await;
                }
                _ => { /* error already handled above */ }
            }
        }
    });

    leader_rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        // Don't mutate env in tests (unsafe in edition 2024 and racy).
        // Instead, test the direct construction path.
        let config = LeaderElectionConfig {
            lease_name: DEFAULT_LEASE_NAME.to_string(),
            namespace: "default".to_string(),
            identity: "unknown".to_string(),
        };
        assert_eq!(config.lease_name, "portus-gateway-controller");
        assert_eq!(config.namespace, "default");
        assert_eq!(config.identity, "unknown");
    }

    #[test]
    fn test_config_custom_values() {
        let config = LeaderElectionConfig {
            lease_name: "my-lease".to_string(),
            namespace: "kube-system".to_string(),
            identity: "controller-pod-abc123".to_string(),
        };
        assert_eq!(config.lease_name, "my-lease");
        assert_eq!(config.namespace, "kube-system");
        assert_eq!(config.identity, "controller-pod-abc123");
    }

    #[test]
    fn test_now_micro_time_is_recent() {
        let mt = now_micro_time();
        let now = k8s_openapi::jiff::Timestamp::now();
        // Should be within 1 second. jiff Span needs get_seconds() for the total.
        let diff = now.since(mt.0).expect("timestamp subtraction");
        assert!(
            diff.get_seconds() < 1,
            "MicroTime should be very recent, got {} seconds",
            diff.get_seconds()
        );
    }

    #[test]
    fn test_lease_from_json_sets_name() {
        let value = serde_json::json!({
            "spec": {
                "holderIdentity": "test-pod",
                "leaseDurationSeconds": 15,
            }
        });
        let lease = lease_from_json(&value, "test-lease");
        assert_eq!(lease.metadata.name.as_deref(), Some("test-lease"));
        assert_eq!(
            lease.spec.as_ref().unwrap().holder_identity.as_deref(),
            Some("test-pod")
        );
        assert_eq!(
            lease.spec.as_ref().unwrap().lease_duration_seconds,
            Some(15)
        );
    }

    #[test]
    fn test_lease_is_free_when_released_or_expired() {
        let now = k8s_openapi::jiff::Timestamp::now();
        let fresh = Some(now - std::time::Duration::from_secs(2));
        let stale = Some(now - std::time::Duration::from_secs(LEASE_DURATION_SECONDS as u64 + 1));
        // Released by the previous holder (client-go style): free at once.
        assert!(lease_is_free("", fresh, LEASE_DURATION_SECONDS, now));
        // Held and recently renewed: not free.
        assert!(!lease_is_free("other-pod", fresh, LEASE_DURATION_SECONDS, now));
        // Held but renewal older than the duration: free.
        assert!(lease_is_free("other-pod", stale, LEASE_DURATION_SECONDS, now));
        // Never renewed: free.
        assert!(lease_is_free("other-pod", None, LEASE_DURATION_SECONDS, now));
        // A released lease with duration shortened to 1s expires immediately too.
        assert!(lease_is_free("other-pod", Some(now - std::time::Duration::from_secs(1)), 1, now));
    }

    #[test]
    fn test_lease_constants() {
        assert_eq!(LEASE_DURATION_SECONDS, 15);
        assert_eq!(RENEWAL_INTERVAL_SECS, 5);
        assert_eq!(MAX_RENEWAL_FAILURES, 3);
        assert_eq!(DEFAULT_LEASE_NAME, "portus-gateway-controller");
    }
}
