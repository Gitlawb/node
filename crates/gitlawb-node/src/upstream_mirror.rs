//! Scheduled external-forge fetches for canonical INBOUND mirrors.
//!
//! This worker is deliberately separate from `sync`, which mirrors repositories
//! between Gitlawb peers. External upstream URLs are owner-controlled data that
//! eventually reach `git fetch`, so each cycle resolves DNS itself, validates
//! every address, and pins the approved answers into Git/libcurl with
//! `http.curloptResolve`. Redirects, proxies, credential helpers, submodule
//! recursion, and non-HTTPS protocols are disabled at the command boundary.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
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
const MAX_PINNED_ADDRESSES: usize = 32;
const MIN_CURL_OPT_RESOLVE_GIT: (u64, u64) = (2, 37);

#[derive(Debug, Clone, Copy)]
struct EgressPolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedUpstream {
    url: String,
    curlopt_resolve: Option<String>,
}

impl EgressPolicy {
    async fn resolve(&self, url: reqwest::Url) -> Result<PinnedUpstream> {
        let raw_host = url.host_str().context("mirror upstream URL has no host")?;
        let connect_host = raw_host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let policy_host = normalize_policy_host(&connect_host);
        reject_always_local_hostname(&policy_host)?;
        let port = url
            .port_or_known_default()
            .context("mirror upstream URL has no known port")?;

        if let Ok(ip) = connect_host.parse::<IpAddr>() {
            self.validate_addresses(&policy_host, &[ip])?;
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
        self.validate_addresses(&policy_host, &addresses)?;

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

    fn validate_addresses(&self, host: &str, addresses: &[IpAddr]) -> Result<()> {
        if addresses.is_empty() || addresses.len() > MAX_PINNED_ADDRESSES {
            anyhow::bail!(
                "mirror upstream host must resolve to 1..={MAX_PINNED_ADDRESSES} addresses"
            );
        }
        for &ip in addresses {
            if !address_is_permitted(ip) {
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
        || host.ends_with(".internal")
    {
        anyhow::bail!("mirror upstream host is local-only and cannot be fetched");
    }
    Ok(())
}

fn address_is_permitted(ip: IpAddr) -> bool {
    if !crate::api::peers::is_public_ip(ip) {
        return false;
    }
    let classified = match ip {
        IpAddr::V6(v6) => crate::api::peers::embedded_ipv4(v6)
            .map(IpAddr::V4)
            .unwrap_or(ip),
        _ => ip,
    };
    match classified {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            // IANA special-purpose ranges that are not globally reachable but
            // may be routed inside labs, clouds, or operator networks. They are
            // unsuitable for an owner-controlled outbound fetch even though
            // `Ipv4Addr::is_private` does not classify them as RFC1918.
            !(a >= 224
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && matches!(b, 18 | 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // IANA special-purpose ranges that are non-global, locally
            // meaningful, or unsafe to treat as ordinary forge endpoints.
            // Reject the complete IETF protocol-assignment /23 rather than
            // trying to maintain its narrow globally reachable exceptions;
            // a public forge has no reason to depend on those anycast ranges.
            !(v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 1)
                || (s[0] == 0x2001 && (s[1] & 0xfe00) == 0)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x3fff && (s[1] & 0xf000) == 0)
                || s[0] == 0x5f00)
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct FetchCommand {
    config: Vec<(String, String)>,
    args: Vec<String>,
}

fn fetch_command(upstream: &PinnedUpstream) -> FetchCommand {
    let http_scope = |name: &str| format!("http.{}.{name}", upstream.url);
    let credential_scope = |name: &str| format!("credential.{}.{name}", upstream.url);
    let mut config = vec![
        ("http.proxy".to_string(), "".to_string()),
        ("http.followRedirects".to_string(), "false".to_string()),
        // Reset any inherited multi-valued resolver entries before adding the
        // address set validated for this exact fetch.
        ("http.curloptResolve".to_string(), "".to_string()),
        // Never forward operator or repository-scoped HTTP credentials to an
        // owner-selected forge. Empty values reset Git's multi-valued headers
        // and disable cookie state for this invocation.
        ("http.extraHeader".to_string(), "".to_string()),
        ("http.cookieFile".to_string(), "".to_string()),
        ("http.saveCookies".to_string(), "false".to_string()),
        ("http.sslVerify".to_string(), "true".to_string()),
        // URL-specific configuration outranks generic `http.*` values even
        // when the generic value is command-scoped. Repeat every security
        // control at the exact validated URL so a repository-local scoped
        // setting cannot re-enable redirects/proxies/headers/cookies or disable
        // TLS. Key/value environment entries avoid `git -c` splitting a valid
        // URL path that contains `=`.
        (http_scope("proxy"), "".to_string()),
        (http_scope("followRedirects"), "false".to_string()),
        (http_scope("curloptResolve"), "".to_string()),
        (http_scope("extraHeader"), "".to_string()),
        (http_scope("cookieFile"), "".to_string()),
        (http_scope("saveCookies"), "false".to_string()),
        (http_scope("sslVerify"), "true".to_string()),
    ];
    if let Some(resolve) = &upstream.curlopt_resolve {
        config.extend([
            ("http.curloptResolve".to_string(), resolve.clone()),
            (http_scope("curloptResolve"), resolve.clone()),
        ]);
    }
    config.extend([
        ("credential.helper".to_string(), "".to_string()),
        (credential_scope("helper"), "".to_string()),
        ("credential.interactive".to_string(), "false".to_string()),
        ("core.askPass".to_string(), "false".to_string()),
        ("fetch.recurseSubmodules".to_string(), "false".to_string()),
        // Do not let a smart server or repository-local config introduce a
        // second, unvalidated pack/bundle URL outside the pinned upstream.
        ("fetch.uriprotocols".to_string(), "".to_string()),
        ("fetch.bundleURI".to_string(), "".to_string()),
        ("protocol.allow".to_string(), "never".to_string()),
        ("protocol.https.allow".to_string(), "always".to_string()),
    ]);
    let args = vec![
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
    ];
    FetchCommand { config, args }
}

fn reject_local_url_rewrite(
    git_bin: &str,
    repo_path: &Path,
    upstream_url: &str,
    deadline: Instant,
) -> Result<()> {
    let args = ["ls-remote", "--get-url", upstream_url];
    let (status, stdout, stderr) = crate::git::visibility_pack::run_bounded_git_raw_isolated_https(
        git_bin, &args, repo_path, b"", deadline,
    )?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        anyhow::bail!(
            "checking mirror upstream URL rewrite failed: {}",
            stderr.chars().take(4_096).collect::<String>()
        );
    }
    let expanded = std::str::from_utf8(&stdout)
        .context("Git returned a non-UTF-8 expanded mirror upstream URL")?
        .trim_end_matches(['\r', '\n']);
    if expanded != upstream_url {
        anyhow::bail!("repository-local Git config attempted to rewrite the mirror upstream URL");
    }
    Ok(())
}

fn reject_sensitive_local_config(git_bin: &str, repo_path: &Path, deadline: Instant) -> Result<()> {
    let args = [
        "config",
        "--local",
        "--includes",
        "--get-regexp",
        r"^(http|credential|url)\.",
    ];
    let (status, stdout, stderr) = crate::git::visibility_pack::run_bounded_git_raw_isolated_https(
        git_bin, &args, repo_path, b"", deadline,
    )?;
    match status.code() {
        Some(1) if stdout.is_empty() => Ok(()),
        Some(0) => anyhow::bail!(
            "repository-local network or credential Git config is not allowed for upstream mirrors"
        ),
        _ => {
            let stderr = String::from_utf8_lossy(&stderr);
            anyhow::bail!(
                "checking repository-local Git config failed: {}",
                stderr.chars().take(4_096).collect::<String>()
            )
        }
    }
}

fn run_fetch(
    git_bin: &str,
    repo_path: &Path,
    upstream: &PinnedUpstream,
    timeout: Duration,
) -> Result<()> {
    let command = fetch_command(upstream);
    let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
    let config: Vec<(&str, &str)> = command
        .config
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("upstream mirror fetch timeout is not representable")?;
    reject_local_url_rewrite(git_bin, repo_path, &upstream.url, deadline)?;
    reject_sensitive_local_config(git_bin, repo_path, deadline)?;
    let (status, _stdout, stderr) =
        crate::git::visibility_pack::run_bounded_git_raw_isolated_https_with_config(
            git_bin, &args, repo_path, b"", deadline, &config,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchOutcome {
    Updated,
    SkippedStale,
}

impl Worker {
    async fn fetch_target(&self, target: InboundMirrorTarget) -> Result<FetchOutcome> {
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
            return Ok(FetchOutcome::SkippedStale);
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
        fetch.map(|()| FetchOutcome::Updated)
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
                    Ok(FetchOutcome::Updated) => {
                        info!(repo_id, upstream = %upstream_url, "upstream mirror fetch completed")
                    }
                    Ok(FetchOutcome::SkippedStale) => {}
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
    let policy = EgressPolicy;
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
    use clap::Parser;
    use std::path::PathBuf;

    async fn test_worker(
        pool: sqlx::PgPool,
        git_bin: PathBuf,
        page_size: usize,
    ) -> (Worker, Arc<Db>, tempfile::TempDir) {
        let db = Arc::new(Db::for_testing(pool.clone()));
        db.run_migrations().await.unwrap();
        let repos = tempfile::tempdir().unwrap();
        let config = Arc::new(Config::parse_from([
            "gitlawb-node".to_string(),
            "--upstream-mirror-enabled".to_string(),
            "--enforce-owner-push".to_string(),
            "--upstream-mirror-fetch-timeout-secs".to_string(),
            "5".to_string(),
            "--upstream-mirror-page-size".to_string(),
            page_size.to_string(),
        ]));
        config.validate().unwrap();
        let worker = Worker {
            db: Arc::clone(&db),
            config,
            repo_store: RepoStore::for_testing(repos.path().to_path_buf(), pool),
            repo_write_leases: RepoWriteLeases::new(8),
            git_write_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            policy: EgressPolicy,
            git_bin: git_bin.to_string_lossy().into_owned(),
        };
        (worker, db, repos)
    }

    async fn add_inbound_mirror(
        worker: &Worker,
        db: &Db,
        id: &str,
        name: &str,
        upstream_url: &str,
    ) -> InboundMirrorTarget {
        let now = chrono::Utc::now();
        let record = crate::db::RepoRecord {
            id: id.to_string(),
            name: name.to_string(),
            owner_did: "did:key:z6MkMirrorWorker".to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/test/{id}.git"),
            forked_from: None,
            machine_id: None,
        };
        db.create_repo(&record).await.unwrap();
        worker
            .repo_store
            .init(&record.owner_did, &record.name)
            .await
            .unwrap();
        let state = db
            .configure_inbound_mirror(&record.id, upstream_url)
            .await
            .unwrap();
        InboundMirrorTarget {
            repo_id: record.id,
            owner_did: record.owner_did,
            name: record.name,
            upstream_url: state.upstream_url,
        }
    }

    #[cfg(unix)]
    fn fake_git(repos: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let git = repos.path().join("fake-git");
        let calls = repos.path().join("fetch-calls");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "ls-remote" ]; then
  printf '%s\n' "$3"
  exit 0
fi
if [ "$1" = "config" ]; then
  # Match real Git when no sensitive repository-local keys are configured.
  exit 1
fi
case "$*" in
  *fail.git*) printf '%s\n' fail >> '{}'; exit 7 ;;
  *) printf '%s\n' ok >> '{}'; exit 0 ;;
esac
"#,
            calls.display(),
            calls.display()
        );
        std::fs::write(&git, script).unwrap();
        let mut permissions = std::fs::metadata(&git).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&git, permissions).unwrap();
        (git, calls)
    }

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
    fn every_resolved_address_must_be_public() {
        let policy = EgressPolicy;
        let public_v4: IpAddr = "8.8.8.8".parse().unwrap();
        let private_v4: IpAddr = "10.2.3.4".parse().unwrap();
        let private_v6: IpAddr = "fd00::20".parse().unwrap();
        assert!(policy
            .validate_addresses("public.example", &[public_v4])
            .is_ok());
        assert!(policy
            .validate_addresses("private.example", &[private_v4, private_v6])
            .is_err());
        assert!(policy
            .validate_addresses("mixed.example", &[public_v4, private_v4])
            .is_err());
        let too_many = (1..=MAX_PINNED_ADDRESSES + 1)
            .map(|last| IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 0, last as u8)))
            .collect::<Vec<_>>();
        assert!(policy
            .validate_addresses("oversized.example", &too_many)
            .is_err());

        for never in [
            "127.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.10",
            "::1",
            "::ffff:198.18.0.1",
            "2002:c612:1::",
            "64:ff9b::c612:1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "fec0::1",
            "fe80::1",
            "3fff::1",
            "5f00::1",
        ] {
            let ip = never.parse().unwrap();
            assert!(!address_is_permitted(ip), "{never} must stay denied");
        }
    }

    #[test]
    fn local_only_hostnames_are_always_rejected() {
        for invalid in [
            "",
            "localhost",
            "forge.localhost",
            "forge.local",
            "ghe.internal",
        ] {
            assert!(
                reject_always_local_hostname(invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(reject_always_local_hostname("github.example").is_ok());
    }

    #[test]
    fn fetch_command_pins_dns_and_only_updates_branches_and_tags() {
        let upstream = PinnedUpstream {
            url: "https://github.example/org/repo.git".to_string(),
            curlopt_resolve: Some("+github.example:443:8.8.8.8,[2606:4700:4700::1111]".to_string()),
        };
        let command = fetch_command(&upstream);
        let has_config = |key: &str, value: &str| {
            command
                .config
                .contains(&(key.to_string(), value.to_string()))
        };
        assert!(has_config("http.followRedirects", "false"));
        assert!(has_config("http.proxy", ""));
        assert!(has_config("http.extraHeader", ""));
        assert!(has_config("http.cookieFile", ""));
        assert!(has_config("http.saveCookies", "false"));
        assert!(has_config("http.sslVerify", "true"));
        assert!(has_config(
            "http.curloptResolve",
            "+github.example:443:8.8.8.8,[2606:4700:4700::1111]"
        ));
        assert!(has_config(
            "http.https://github.example/org/repo.git.followRedirects",
            "false"
        ));
        assert!(has_config(
            "http.https://github.example/org/repo.git.proxy",
            ""
        ));
        assert!(has_config(
            "http.https://github.example/org/repo.git.extraHeader",
            ""
        ));
        assert!(has_config(
            "http.https://github.example/org/repo.git.curloptResolve",
            "+github.example:443:8.8.8.8,[2606:4700:4700::1111]"
        ));
        assert!(has_config(
            "credential.https://github.example/org/repo.git.helper",
            ""
        ));
        assert!(has_config("protocol.allow", "never"));
        assert!(has_config("protocol.https.allow", "always"));
        assert!(has_config("fetch.uriprotocols", ""));
        assert!(has_config("fetch.bundleURI", ""));
        assert!(!command
            .config
            .iter()
            .any(|(key, _)| key.ends_with("sslCert") || key.ends_with("sslKey")));
        assert!(command.args.contains(&"--atomic".to_string()));
        assert!(command
            .args
            .contains(&"+refs/heads/*:refs/heads/*".to_string()));
        assert!(command
            .args
            .contains(&"+refs/tags/*:refs/tags/*".to_string()));
        assert!(!command.args.iter().any(|arg| arg == "+refs/*:refs/*"));
    }

    #[test]
    fn repository_local_instead_of_rewrite_is_rejected() {
        let repo = tempfile::tempdir().unwrap();
        let init = std::process::Command::new("git")
            .args(["init", "--bare"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(init.status.success());
        let config = std::process::Command::new("git")
            .args([
                "config",
                "url.https://evil.example/.insteadOf",
                "https://github.example/",
            ])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(config.status.success());

        let error = reject_local_url_rewrite(
            "git",
            repo.path(),
            "https://github.example/org/repo.git",
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(error.to_string().contains("attempted to rewrite"));
    }

    #[test]
    fn repository_local_network_and_credential_config_is_rejected() {
        let repo = tempfile::tempdir().unwrap();
        let init = std::process::Command::new("git")
            .args(["init", "--bare"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(init.status.success());

        reject_sensitive_local_config("git", repo.path(), Instant::now() + Duration::from_secs(5))
            .unwrap();

        let config = std::process::Command::new("git")
            .args(["config", "http.sslCert", "/tmp/untrusted-client.pem"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(config.status.success());

        let error = reject_sensitive_local_config(
            "git",
            repo.path(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(error.to_string().contains("network or credential"));
    }

    #[cfg(unix)]
    #[test]
    fn hardened_real_git_reaches_https_transport_for_equals_path() {
        let repo = tempfile::tempdir().unwrap();
        let init = std::process::Command::new("git")
            .args(["init", "--bare"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(init.status.success());

        // This is intentionally a loopback test seam around `run_fetch`, below
        // the egress-policy layer. Reaching the listener proves the generated
        // Git config neither dies on an empty client certificate nor splits the
        // valid `=` path at the command-config boundary. The listener closes
        // immediately, so the expected final result is a TLS transport error.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let accepted = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((_stream, _address)) => return true,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accepting real-Git transport probe: {error}"),
                }
            }
            false
        });
        let upstream = PinnedUpstream {
            url: format!("https://127.0.0.1:{port}/org/repo=mirror.git"),
            curlopt_resolve: None,
        };
        let error = run_fetch("git", repo.path(), &upstream, Duration::from_secs(5)).unwrap_err();
        assert!(
            accepted.join().unwrap(),
            "real Git must reach the HTTPS transport; got {error:#}"
        );
        let error = error.to_string();
        assert!(!error.contains("credential missing host field"));
        assert!(!error.contains("invalid key"));
    }

    #[tokio::test]
    async fn literal_addresses_are_checked_without_dns() {
        let policy = EgressPolicy;
        let allowed = policy
            .resolve(reqwest::Url::parse("https://8.8.8.8/org/repo.git").unwrap())
            .await
            .unwrap();
        assert_eq!(allowed.curlopt_resolve, None);

        for denied in [
            "127.0.0.1",
            "10.2.3.4",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.10",
            "[::1]",
            "[100::1]",
            "[100:0:0:1::1]",
            "[2001::1]",
            "[2001:db8::1]",
            "[fec0::1]",
            "[fd00::20]",
            "[3fff::1]",
            "[5f00::1]",
        ] {
            let url = reqwest::Url::parse(&format!("https://{denied}/org/repo.git")).unwrap();
            assert!(
                policy.resolve(url).await.is_err(),
                "{denied} must stay denied"
            );
        }
    }

    #[sqlx::test]
    async fn stale_target_is_rechecked_under_the_write_locks(pool: sqlx::PgPool) {
        let missing_git = PathBuf::from("/definitely/missing/git");
        let (worker, db, _repos) = test_worker(pool, missing_git, 1).await;
        let target = add_inbound_mirror(
            &worker,
            &db,
            "00000000-0000-0000-0000-000000000001",
            "stale",
            "https://8.8.8.8/org/stale.git",
        )
        .await;
        sqlx::query(
            "UPDATE repos
             SET mirror_status = 'outbound'
             WHERE id = $1",
        )
        .bind(&target.repo_id)
        .execute(db.pool())
        .await
        .unwrap();

        let outcome = worker.fetch_target(target).await.unwrap();
        assert_eq!(outcome, FetchOutcome::SkippedStale);
        assert!(worker.repo_write_leases.is_empty());
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn scan_pages_past_one_failure_and_fetches_the_next_repo(pool: sqlx::PgPool) {
        let bootstrap = tempfile::tempdir().unwrap();
        let (git, calls) = fake_git(&bootstrap);
        let (worker, db, _repos) = test_worker(pool, git, 1).await;
        add_inbound_mirror(
            &worker,
            &db,
            "00000000-0000-0000-0000-000000000001",
            "fails",
            "https://8.8.8.8/org/fail.git",
        )
        .await;
        add_inbound_mirror(
            &worker,
            &db,
            "00000000-0000-0000-0000-000000000002",
            "succeeds",
            "https://8.8.8.8/org/ok.git",
        )
        .await;

        worker.scan_once().await;

        let calls = std::fs::read_to_string(calls).unwrap();
        assert_eq!(calls.lines().collect::<Vec<_>>(), ["fail", "ok"]);
        assert!(worker.repo_write_leases.is_empty());
    }
}
