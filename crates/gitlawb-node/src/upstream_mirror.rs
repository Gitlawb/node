//! Scheduled external-forge fetches for canonical INBOUND mirrors.
//!
//! This worker is deliberately separate from `sync`, which mirrors repositories
//! between Gitlawb peers. External upstream URLs are owner-controlled data that
//! eventually reach `git fetch`, so each cycle resolves DNS itself, validates
//! every address, and pins the approved answers into Git/libcurl with
//! `http.curloptResolve`. Redirects, proxies, credential helpers, submodule
//! recursion, and non-HTTPS protocols are disabled at the command boundary.

use anyhow::{Context, Result};
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::config::Config;
use crate::db::{Db, InboundMirrorTarget, MirrorStatus};
use crate::git::repo_store::RepoStore;
use crate::state::{repo_identity_key, RepoWriteLeases};

const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_CURL_OPT_RESOLVE_GIT: (u64, u64) = (2, 37);

#[derive(Debug, Clone)]
struct EgressPolicy {
    allowed_private_hosts: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedUpstream {
    url: String,
    curlopt_resolve: Option<String>,
}

impl EgressPolicy {
    fn new(allowed_private_hosts: &[String]) -> Result<Self> {
        let allowed_private_hosts = allowed_private_hosts
            .iter()
            .map(|host| normalize_allowlisted_host(host))
            .collect::<Result<HashSet<_>>>()?;
        Ok(Self {
            allowed_private_hosts,
        })
    }

    async fn resolve(&self, url: reqwest::Url) -> Result<PinnedUpstream> {
        let raw_host = url.host_str().context("mirror upstream URL has no host")?;
        let connect_host = raw_host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let policy_host = normalize_policy_host(&connect_host);
        reject_always_local_hostname(&policy_host)?;
        let allow_private = self.allowed_private_hosts.contains(&policy_host);
        let port = url
            .port_or_known_default()
            .context("mirror upstream URL has no known port")?;

        if let Ok(ip) = connect_host.parse::<IpAddr>() {
            self.validate_addresses(&policy_host, &[ip], allow_private)?;
            return Ok(PinnedUpstream {
                url: url.to_string(),
                // An IP literal performs no DNS lookup, so there is no rebinding
                // window to pin. TLS still verifies the literal from the URL.
                curlopt_resolve: None,
            });
        }

        let resolved = tokio::time::timeout(
            DNS_TIMEOUT,
            tokio::net::lookup_host((connect_host.as_str(), port)),
        )
        .await
        .context("mirror upstream DNS lookup timed out")?
        .context("resolving mirror upstream host")?;
        let addresses: BTreeSet<IpAddr> = resolved.map(|addr| addr.ip()).collect();
        if addresses.is_empty() {
            anyhow::bail!("mirror upstream host resolved to no addresses");
        }
        let addresses: Vec<IpAddr> = addresses.into_iter().collect();
        self.validate_addresses(&policy_host, &addresses, allow_private)?;

        let pinned = addresses
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{v6}]"),
            })
            .collect::<Vec<_>>()
            .join(",");
        Ok(PinnedUpstream {
            url: url.to_string(),
            curlopt_resolve: Some(format!("+{connect_host}:{port}:{pinned}")),
        })
    }

    fn validate_addresses(
        &self,
        host: &str,
        addresses: &[IpAddr],
        allow_private: bool,
    ) -> Result<()> {
        for &ip in addresses {
            if !address_is_permitted(ip, allow_private) {
                anyhow::bail!("mirror upstream host {host:?} resolved to disallowed address {ip}");
            }
        }
        Ok(())
    }
}

fn normalize_policy_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn reject_always_local_hostname(host: &str) -> Result<()> {
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
    {
        anyhow::bail!("mirror upstream host is local-only and cannot be fetched");
    }
    Ok(())
}

fn normalize_allowlisted_host(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains(|c: char| c.is_whitespace() || c.is_control())
        || trimmed.contains(['/', '?', '#', '@', '*'])
    {
        anyhow::bail!("invalid private mirror host allowlist entry {raw:?}");
    }
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed);
    let normalized = normalize_policy_host(unbracketed);
    reject_always_local_hostname(&normalized)?;

    if normalized.parse::<IpAddr>().is_err()
        && !normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        anyhow::bail!("invalid private mirror host allowlist entry {raw:?}");
    }
    Ok(normalized)
}

fn address_is_permitted(ip: IpAddr, allow_private: bool) -> bool {
    // Broadcast/multicast/reserved destinations are never forge endpoints.
    match ip {
        IpAddr::V4(v4) if v4.octets()[0] >= 224 => return false,
        IpAddr::V6(v6) if v6.is_multicast() => return false,
        _ => {}
    }
    if crate::api::peers::is_public_ip(ip) {
        return true;
    }
    if !allow_private {
        return false;
    }
    // An exact operator allowlist may admit only normal private address space
    // used by an on-prem forge. Loopback, link-local, CGNAT, unspecified, and
    // transition encodings remain denied because neither arm includes them.
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn parse_git_version(output: &str) -> Option<(u64, u64)> {
    let version = output.split_whitespace().find(|part| {
        part.as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
    })?;
    let mut parts = version.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn ensure_safe_git_runtime(git_bin: &str) -> Result<()> {
    let output = std::process::Command::new(git_bin)
        .arg("--version")
        .output()
        .with_context(|| format!("running {git_bin} --version for upstream mirror safety check"))?;
    if !output.status.success() {
        anyhow::bail!("{git_bin} --version failed");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = parse_git_version(&stdout).context("parsing git version")?;
    if version < MIN_CURL_OPT_RESOLVE_GIT {
        anyhow::bail!(
            "upstream mirroring requires Git 2.37+ for DNS pinning; found {}.{}",
            version.0,
            version.1
        );
    }
    Ok(())
}

fn fetch_args(upstream: &PinnedUpstream) -> Vec<String> {
    let mut args = vec![
        "-c".to_string(),
        "http.proxy=".to_string(),
        "-c".to_string(),
        "http.followRedirects=false".to_string(),
        // Reset any inherited multi-valued resolver entries before adding the
        // address set validated for this exact fetch.
        "-c".to_string(),
        "http.curloptResolve=".to_string(),
        // Never forward operator or repository-scoped HTTP credentials to an
        // owner-selected forge. Empty values reset Git's multi-valued headers
        // and disable cookie state for this invocation.
        "-c".to_string(),
        "http.extraHeader=".to_string(),
        "-c".to_string(),
        "http.cookieFile=".to_string(),
        "-c".to_string(),
        "http.saveCookies=false".to_string(),
        "-c".to_string(),
        "http.sslVerify=true".to_string(),
    ];
    if let Some(resolve) = &upstream.curlopt_resolve {
        args.extend(["-c".to_string(), format!("http.curloptResolve={resolve}")]);
    }
    args.extend([
        "-c".to_string(),
        "credential.helper=".to_string(),
        "-c".to_string(),
        "core.askPass=false".to_string(),
        "-c".to_string(),
        "fetch.recurseSubmodules=false".to_string(),
        "-c".to_string(),
        "protocol.allow=never".to_string(),
        "-c".to_string(),
        "protocol.https.allow=always".to_string(),
        "fetch".to_string(),
        "--atomic".to_string(),
        "--force".to_string(),
        "--prune".to_string(),
        "--prune-tags".to_string(),
        "--no-auto-maintenance".to_string(),
        "--no-recurse-submodules".to_string(),
        "--no-write-fetch-head".to_string(),
        upstream.url.clone(),
        "+refs/heads/*:refs/heads/*".to_string(),
        "+refs/tags/*:refs/tags/*".to_string(),
    ]);
    args
}

fn run_fetch(
    git_bin: &str,
    repo_path: &Path,
    upstream: &PinnedUpstream,
    timeout: Duration,
) -> Result<()> {
    let args = fetch_args(upstream);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("upstream mirror fetch timeout is not representable")?;
    let (status, _stdout, stderr) = crate::git::visibility_pack::run_bounded_git_raw(
        git_bin, &borrowed, repo_path, b"", deadline,
    )?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let stderr = stderr.chars().take(4_096).collect::<String>();
        anyhow::bail!("git upstream fetch failed: {stderr}");
    }
    Ok(())
}

#[derive(Clone)]
struct Worker {
    db: Arc<Db>,
    config: Arc<Config>,
    repo_store: RepoStore,
    repo_write_leases: RepoWriteLeases,
    git_write_semaphore: Arc<tokio::sync::Semaphore>,
    policy: EgressPolicy,
    git_bin: String,
}

impl Worker {
    async fn fetch_target(&self, target: InboundMirrorTarget) -> Result<()> {
        let url = crate::db::validate_mirror_upstream_url(&target.upstream_url)?;
        let upstream = self.policy.resolve(url).await?;

        let repo_identity = repo_identity_key(&target.owner_did, &target.name);
        let steal_after = Duration::from_secs(
            self.config
                .upstream_mirror_fetch_timeout_secs
                .saturating_mul(2)
                .saturating_add(60),
        );
        let _lease = self
            .repo_write_leases
            .acquire(&repo_identity, steal_after)
            .await
            .context("upstream mirror write-lease waiter cap reached")?;

        let _write_permit = Arc::clone(&self.git_write_semaphore)
            .acquire_owned()
            .await
            .context("upstream mirror write semaphore closed")?;
        let acquire_timeout = Duration::from_secs(self.config.git_acquire_timeout_secs);
        let guard = tokio::time::timeout(
            acquire_timeout,
            self.repo_store
                .acquire_write(&target.owner_did, &target.name),
        )
        .await
        .context("upstream mirror write-lock acquisition timed out")??;
        let repo_path = guard.path().to_path_buf();

        // A row can leave INBOUND state after selection. Recheck only after
        // both the process-local lease and the cluster-wide advisory write lock
        // are held. Every future transition path must take these same locks
        // before changing authority, so no other node can commit a transition
        // between this check and the fetch.
        let current = match self.db.get_repo_mirror_state(&target.repo_id).await {
            Ok(Some(current)) => current,
            Ok(None) => {
                guard.release(false).await;
                anyhow::bail!("inbound mirror state disappeared before fetch");
            }
            Err(error) => {
                guard.release(false).await;
                return Err(error);
            }
        };
        if current.status != MirrorStatus::Inbound
            || current.transition_id.is_some()
            || current.transition_phase.is_some()
            || current.upstream_url != target.upstream_url
        {
            guard.release(false).await;
            info!(repo_id = %target.repo_id, "upstream mirror state changed before fetch; skipping stale target");
            return Ok(());
        }

        let git_bin = self.git_bin.clone();
        let fetch_timeout = Duration::from_secs(self.config.upstream_mirror_fetch_timeout_secs);
        let fetch = tokio::task::spawn_blocking(move || {
            run_fetch(&git_bin, &repo_path, &upstream, fetch_timeout)
        })
        .await
        .context("upstream mirror fetch task panicked")?;
        let success = fetch.is_ok();
        guard.release(success).await;
        fetch
    }

    async fn scan_once(&self) {
        let mut cursor: Option<String> = None;
        loop {
            let targets = match self
                .db
                .list_inbound_mirror_targets(
                    cursor.as_deref(),
                    self.config.upstream_mirror_page_size as i64,
                )
                .await
            {
                Ok(targets) => targets,
                Err(error) => {
                    warn!(err = %error, "failed to list inbound mirror targets");
                    return;
                }
            };
            if targets.is_empty() {
                return;
            }
            let page_len = targets.len();
            cursor = targets.last().map(|target| target.repo_id.clone());
            for target in targets {
                let repo_id = target.repo_id.clone();
                let upstream_url = target.upstream_url.clone();
                match self.fetch_target(target).await {
                    Ok(()) => {
                        info!(repo_id, upstream = %upstream_url, "upstream mirror fetch completed")
                    }
                    Err(error) => {
                        warn!(repo_id, upstream = %upstream_url, err = %error, "upstream mirror fetch failed")
                    }
                }
            }
            if page_len < self.config.upstream_mirror_page_size {
                return;
            }
        }
    }
}

/// Validate the opt-in runtime and spawn the scheduled worker. The worker runs
/// one scan immediately, sleeps only after a complete scan, and exits between
/// scans when graceful shutdown is signalled. An in-flight Git child is bounded
/// and reaped before the worker observes shutdown.
pub fn start(
    db: Arc<Db>,
    config: Arc<Config>,
    repo_store: RepoStore,
    repo_write_leases: RepoWriteLeases,
    git_write_semaphore: Arc<tokio::sync::Semaphore>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    ensure_safe_git_runtime("git")?;
    let policy = EgressPolicy::new(&config.upstream_mirror_allowed_private_hosts)?;
    let worker = Worker {
        db,
        config: Arc::clone(&config),
        repo_store,
        repo_write_leases,
        git_write_semaphore,
        policy,
        git_bin: "git".to_string(),
    };
    tokio::spawn(async move {
        info!(
            interval_secs = config.upstream_mirror_interval_secs,
            "upstream mirror worker started"
        );
        loop {
            worker.scan_once().await;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(config.upstream_mirror_interval_secs)) => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        info!("upstream mirror worker stopped");
                        return;
                    }
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_version_gate_requires_curlopt_resolve_support() {
        assert_eq!(parse_git_version("git version 2.37.0"), Some((2, 37)));
        assert_eq!(
            parse_git_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        assert_eq!(parse_git_version("not git"), None);
        assert!((2, 36) < MIN_CURL_OPT_RESOLVE_GIT);
    }

    #[test]
    fn private_targets_require_an_exact_operator_allowlist() {
        let policy = EgressPolicy::new(&["ghe.internal".to_string()]).unwrap();
        let public_v4: IpAddr = "8.8.8.8".parse().unwrap();
        let private_v4: IpAddr = "10.2.3.4".parse().unwrap();
        let private_v6: IpAddr = "fd00::20".parse().unwrap();
        assert!(policy
            .validate_addresses("ghe.internal", &[private_v4, private_v6], true)
            .is_ok());
        assert!(policy
            .validate_addresses("other.internal", &[private_v4], false)
            .is_err());
        assert!(policy
            .validate_addresses("public.example", &[public_v4, private_v4], false)
            .is_err());

        for never in ["127.0.0.1", "169.254.169.254", "::1", "fe80::1"] {
            let ip = never.parse().unwrap();
            assert!(!address_is_permitted(ip, true), "{never} must stay denied");
        }
    }

    #[test]
    fn private_host_allowlist_rejects_wildcards_and_localhost() {
        for invalid in ["", "*.internal", "localhost", "forge.local", "host/path"] {
            assert!(normalize_allowlisted_host(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(
            normalize_allowlisted_host("GHE.INTERNAL.").unwrap(),
            "ghe.internal"
        );
    }

    #[test]
    fn fetch_command_pins_dns_and_only_updates_branches_and_tags() {
        let upstream = PinnedUpstream {
            url: "https://github.example/org/repo.git".to_string(),
            curlopt_resolve: Some("+github.example:443:203.0.113.10,[2001:db8::10]".to_string()),
        };
        let args = fetch_args(&upstream);
        assert!(args.contains(&"http.followRedirects=false".to_string()));
        assert!(args.contains(&"http.proxy=".to_string()));
        assert!(args.contains(&"http.extraHeader=".to_string()));
        assert!(args.contains(&"http.cookieFile=".to_string()));
        assert!(args.contains(&"http.saveCookies=false".to_string()));
        assert!(args.contains(&"http.sslVerify=true".to_string()));
        assert!(args.contains(
            &"http.curloptResolve=+github.example:443:203.0.113.10,[2001:db8::10]".to_string()
        ));
        assert!(args.contains(&"protocol.allow=never".to_string()));
        assert!(args.contains(&"protocol.https.allow=always".to_string()));
        assert!(args.contains(&"--atomic".to_string()));
        assert!(args.contains(&"+refs/heads/*:refs/heads/*".to_string()));
        assert!(args.contains(&"+refs/tags/*:refs/tags/*".to_string()));
        assert!(!args.iter().any(|arg| arg == "+refs/*:refs/*"));
    }

    #[tokio::test]
    async fn literal_addresses_are_checked_without_dns() {
        let policy = EgressPolicy::new(&["10.2.3.4".to_string()]).unwrap();
        let allowed = policy
            .resolve(reqwest::Url::parse("https://10.2.3.4/org/repo.git").unwrap())
            .await
            .unwrap();
        assert_eq!(allowed.curlopt_resolve, None);

        assert!(policy
            .resolve(reqwest::Url::parse("https://127.0.0.1/org/repo.git").unwrap())
            .await
            .is_err());
    }
}
