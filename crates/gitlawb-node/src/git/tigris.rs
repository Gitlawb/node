//! Tigris (S3-compatible) storage client for git bare repos.
//!
//! Repos are stored as `repos/v1/{owner_slug}/{repo_name}.tar.zst` — a
//! zstd-compressed tar archive of the bare repo directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::Client as S3Client;
use tracing::{debug, info};

/// The precondition an upload is fenced on.
///
/// Object storage is the only place a fence can hold. Dropping the future of an
/// in-flight PUT does not cancel the request the server is already processing,
/// so no amount of local locking stops an abandoned writer's bytes from landing
/// after a successor has published. A conditional PUT the store itself refuses
/// is what actually stops it.
#[derive(Clone, Debug)]
pub enum UploadPrecondition {
    /// Publish only if the stored object is still the generation we observed.
    IfMatch(String),
    /// Publish only if nothing is stored under the key yet.
    IfAbsent,
    /// No fence. Last writer wins.
    Unconditional,
}

/// Why an upload failed, split so a caller can tell "someone else already
/// published this key" (expected, and dropping our bytes is the correct
/// outcome) from a real storage failure.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("upload precondition lost (HTTP {status})")]
    PreconditionLost { status: u16 },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Wrapper around the S3 client with the configured bucket.
#[derive(Clone)]
pub struct TigrisClient {
    s3: S3Client,
    bucket: String,
}

impl TigrisClient {
    /// Create a new client. Uses AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and
    /// AWS_ENDPOINT_URL_S3 env vars — all set automatically by Fly for Tigris buckets.
    pub async fn new(bucket: &str) -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3 = S3Client::new(&config);
        info!(bucket = %bucket, "tigris storage client initialized");
        Ok(Self {
            s3,
            bucket: bucket.to_string(),
        })
    }

    /// Build a client pointed at an arbitrary endpoint, for tests.
    ///
    /// The production constructor reads the endpoint and credentials from the
    /// environment, which a test cannot steer without mutating process-global
    /// state. This takes both explicitly so a test can aim the client at a
    /// closed port and get a prompt transport error out of `exists()`.
    ///
    /// `RetryConfig::disabled()` is load-bearing, not tidiness: the SDK's default
    /// policy retries a connection refusal with backoff, which turns each failing
    /// call into seconds of waiting.
    #[cfg(test)]
    pub fn for_testing_with_endpoint(bucket: &str, endpoint: &str) -> Self {
        use aws_sdk_s3::config::{retry::RetryConfig, Credentials, Region};

        let config = aws_sdk_s3::config::Config::builder()
            .endpoint_url(endpoint)
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .region(Region::new("auto"))
            .retry_config(RetryConfig::disabled())
            .behavior_version_latest()
            .build();
        Self {
            s3: S3Client::from_conf(config),
            bucket: bucket.to_string(),
        }
    }

    /// S3 key for a given repo: `repos/v1/{owner_slug}/{repo_name}.tar.zst`
    fn repo_key(owner_slug: &str, repo_name: &str) -> String {
        format!("repos/v1/{owner_slug}/{repo_name}.tar.zst")
    }

    /// Check if a repo archive exists in Tigris.
    pub async fn exists(&self, owner_slug: &str, repo_name: &str) -> Result<bool> {
        let key = Self::repo_key(owner_slug, repo_name);
        match self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.as_service_error().is_some_and(|e| e.is_not_found()) {
                    Ok(false)
                } else {
                    Err(anyhow::anyhow!("tigris HEAD {key}: {e}"))
                }
            }
        }
    }

    /// Read the ETag of a repo archive, or `None` when nothing is stored under
    /// the key. The ETag identifies the generation a later conditional upload
    /// can fence itself on.
    ///
    /// Separate from `exists` rather than folded into it: `exists` has callers
    /// that only want the boolean, and widening its return type would churn
    /// every one of them for no benefit.
    pub async fn head_etag(&self, owner_slug: &str, repo_name: &str) -> Result<Option<String>> {
        let key = Self::repo_key(owner_slug, repo_name);
        match self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(out) => Ok(Some(
                out.e_tag()
                    .context(format!("tigris HEAD {key}: hit carried no ETag"))?
                    .to_string(),
            )),
            Err(e) => {
                if e.as_service_error().is_some_and(|e| e.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("tigris HEAD {key}: {e}"))
                }
            }
        }
    }

    /// Upload a local bare repo directory to Tigris as a tar.zst archive,
    /// fenced by `precondition`.
    pub async fn upload(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
        precondition: UploadPrecondition,
    ) -> std::result::Result<(), UploadError> {
        let key = Self::repo_key(owner_slug, repo_name);
        debug!(key = %key, path = %local_path.display(), "uploading repo to tigris");

        // Create tar.zst in memory
        let archive_bytes = tokio::task::spawn_blocking({
            let local_path = local_path.to_path_buf();
            move || compress_repo(&local_path)
        })
        .await
        .context("tar task panicked")?
        .context("compressing repo")?;

        let body = aws_sdk_s3::primitives::ByteStream::from(archive_bytes);

        let mut req = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .content_type("application/zstd");
        match &precondition {
            UploadPrecondition::IfMatch(etag) => req = req.if_match(etag),
            UploadPrecondition::IfAbsent => req = req.if_none_match("*"),
            UploadPrecondition::Unconditional => {}
        }

        if let Err(e) = req.send().await {
            // `PutObjectError` models no PreconditionFailed variant (its arms are
            // EncryptionTypeMismatch, InvalidRequest, InvalidWriteOffset,
            // TooManyParts, Unhandled), so a refused precondition arrives as
            // `Unhandled` and matching the enum would classify it as a generic
            // failure. The raw HTTP status off the service-error response is the
            // only place the answer actually lives.
            let status = match &e {
                SdkError::ServiceError(ctx) => Some(ctx.raw().status().as_u16()),
                _ => None,
            };
            // 412 is always a lost precondition. 409 is one only when we asked
            // for create-only, which is how S3-compatible stores report "the key
            // already exists". Everything else, 404 included, is a real failure:
            // archive keys are never deleted (`delete` has no callers), so a 404
            // here means something permanent like a missing bucket or a
            // misrouted endpoint, and reporting that as a lost precondition
            // would tell a caller to expect a successor that does not exist.
            let lost = match status {
                Some(412) => true,
                Some(409) => matches!(precondition, UploadPrecondition::IfAbsent),
                _ => false,
            };
            if lost {
                return Err(UploadError::PreconditionLost {
                    status: status.expect("a lost precondition came from a status"),
                });
            }
            return Err(UploadError::Other(
                anyhow::Error::new(e).context(format!("tigris PUT {key}")),
            ));
        }

        info!(key = %key, "uploaded repo to tigris");
        Ok(())
    }

    /// Download a repo archive from Tigris and extract to local disk.
    pub async fn download(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
    ) -> Result<()> {
        self.download_to(owner_slug, repo_name, local_path, true)
            .await
            .map(|_| ())
    }

    /// Download a repo archive from Tigris and extract it, returning the
    /// directory that was populated.
    ///
    /// `publish` controls whether the extract is swapped into `target` in place
    /// (the live-path mutation used by writes; returns `target`) or unpacked
    /// into a fresh temp directory under `target`'s parent (a non-mutating
    /// snapshot read; returns the temp dir, which the caller owns and cleans
    /// up). The snapshot form never touches the live repo path.
    pub async fn download_to(
        &self,
        owner_slug: &str,
        repo_name: &str,
        target: &Path,
        publish: bool,
    ) -> Result<PathBuf> {
        let key = Self::repo_key(owner_slug, repo_name);
        debug!(key = %key, path = %target.display(), "downloading repo from tigris");

        let resp = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .context(format!("tigris GET {key}"))?;

        let data = resp
            .body
            .collect()
            .await
            .context("reading tigris response body")?
            .into_bytes();

        // Extract tar.zst to a directory.
        let extracted = tokio::task::spawn_blocking({
            let target = target.to_path_buf();
            move || -> Result<PathBuf> {
                if publish {
                    decompress_repo(&data, &target)?;
                    return Ok(target);
                }
                // Non-mutating snapshot: unpack into a fresh temp dir under the
                // target's parent. The live repo path is never touched.
                let parent = target.parent().context("snapshot path has no parent")?;
                std::fs::create_dir_all(parent).context("creating parent dir")?;
                let file_name = target
                    .file_name()
                    .context("snapshot path has no file name")?
                    .to_string_lossy();
                let tmp_dir = parent.join(format!(
                    ".{file_name}.tmp-snapshot.{}",
                    uuid::Uuid::new_v4()
                ));
                std::fs::create_dir_all(&tmp_dir).context("creating temp extract dir")?;
                let unpack = (|| -> Result<()> {
                    let decoder = zstd::stream::Decoder::new(&data[..])?;
                    let mut archive = tar::Archive::new(decoder);
                    archive.unpack(&tmp_dir).context("unpacking tar.zst")?;
                    Ok(())
                })();
                if let Err(e) = unpack {
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(e);
                }
                Ok(tmp_dir)
            }
        })
        .await
        .context("extract task panicked")?
        .context("extracting repo")?;

        info!(key = %key, path = %target.display(), "downloaded repo from tigris");
        Ok(extracted)
    }

    /// Delete a repo archive from Tigris.
    #[allow(dead_code)]
    pub async fn delete(&self, owner_slug: &str, repo_name: &str) -> Result<()> {
        let key = Self::repo_key(owner_slug, repo_name);
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .context(format!("tigris DELETE {key}"))?;
        Ok(())
    }
}

/// Compress a bare repo directory into a tar.zst byte vector.
fn compress_repo(repo_path: &Path) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let encoder = zstd::stream::Encoder::new(buf, 3)?; // level 3 = fast + decent ratio
    let mut tar = tar::Builder::new(encoder);

    // Append the bare repo directory contents (not the directory itself)
    tar.append_dir_all(".", repo_path)
        .context("building tar archive")?;

    let encoder = tar.into_inner().context("finishing tar")?;
    let compressed = encoder.finish().context("finishing zstd")?;
    Ok(compressed)
}

/// Per-repo-path lock serializing the publish (swap-into-place) step of
/// `decompress_repo`. Concurrent extractions unpack into isolated temp dirs in
/// parallel, but the final `remove_dir_all` + `rename` must not interleave for
/// the same `local_path`, or they race to a nondeterministic overwrite/failure.
fn publish_lock(local_path: &Path) -> Arc<Mutex<()>> {
    // KNOWN LIMITATION: this map is never evicted — one (PathBuf, Arc<Mutex>)
    // entry accrues per distinct repo path for the process lifetime. Bounded by
    // the number of repos a node hosts, so it's negligible for normal use, but
    // high-volume/churning deployments may want LRU or weak-ref eviction here.
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = locks.lock().expect("publish lock map poisoned");
    map.entry(local_path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Decompress a tar.zst byte vector into a local directory.
///
/// Extraction is atomic with respect to `local_path`: the archive is unpacked
/// into a sibling temp directory first, and only swapped into place once it
/// fully succeeds. A corrupt or truncated archive therefore can never clobber a
/// good existing copy at `local_path` — on failure we discard the temp dir and
/// leave `local_path` exactly as it was.
fn decompress_repo(data: &[u8], local_path: &Path) -> Result<()> {
    let parent = local_path.parent().context("repo path has no parent")?;
    std::fs::create_dir_all(parent).context("creating parent dir")?;

    let file_name = local_path
        .file_name()
        .context("repo path has no file name")?
        .to_string_lossy();
    // Unique per-extraction temp dir: a fixed name would let two concurrent
    // extractions of the same repo share one dir and clobber each other's
    // in-progress unpack. A fresh UUID also means it can't collide with a
    // leftover dir from a previously-interrupted run.
    let tmp_dir = parent.join(format!(".{file_name}.tmp-extract.{}", uuid::Uuid::new_v4()));

    std::fs::create_dir_all(&tmp_dir).context("creating temp extract dir")?;

    // Unpack into the temp dir; on any failure, clean up and bail without
    // touching local_path.
    let unpack = (|| -> Result<()> {
        let decoder = zstd::stream::Decoder::new(data)?;
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(&tmp_dir).context("unpacking tar.zst")?;
        Ok(())
    })();
    if let Err(e) = unpack {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(e);
    }

    // Swap the freshly-extracted repo into place. rename within the same parent
    // is effectively atomic, but most platforms refuse to rename onto a
    // non-empty dir, so remove the old copy first. Serialize this per repo path:
    // concurrent extractions unpack into isolated temp dirs, but their swaps
    // must not interleave or they race to a nondeterministic overwrite/failure.
    let lock = publish_lock(local_path);
    let _publish = lock.lock().expect("publish lock poisoned");
    if local_path.exists() {
        std::fs::remove_dir_all(local_path).context("removing stale repo dir")?;
    }
    std::fs::rename(&tmp_dir, local_path).context("swapping extracted repo into place")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::primitives::ByteStream;
    use futures::FutureExt;

    /// The envs the probe needs, all of them, or it does not run.
    ///
    /// `AWS_ENDPOINT_URL_S3` is included on purpose: without it the SDK resolves
    /// to real AWS S3, and a probe that passed there would say nothing about
    /// Tigris.
    fn probe_env() -> Option<String> {
        if std::env::var("GITLAWB_TIGRIS_PROBE").ok().as_deref() != Some("1") {
            return None;
        }
        for name in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ENDPOINT_URL_S3",
        ] {
            if std::env::var(name).is_err() {
                eprintln!("tigris conditional-write probe: {name} is unset, skipping");
                return None;
            }
        }
        match std::env::var("GITLAWB_TIGRIS_BUCKET") {
            Ok(b) if !b.is_empty() => Some(b),
            _ => {
                eprintln!(
                    "tigris conditional-write probe: GITLAWB_TIGRIS_BUCKET is unset, skipping"
                );
                None
            }
        }
    }

    /// One conditional PUT, reported as the status that REFUSED it, or `None`
    /// when the store accepted the write.
    ///
    /// Accepted is the interesting answer here, not an error: it means the
    /// endpoint ignored the header we fenced on.
    async fn conditional_put(
        s3: &S3Client,
        bucket: &str,
        key: &str,
        body: &'static [u8],
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Option<u16>, String> {
        let mut req = s3
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(body));
        if let Some(v) = if_match {
            req = req.if_match(v);
        }
        if let Some(v) = if_none_match {
            req = req.if_none_match(v);
        }
        match req.send().await {
            Ok(_) => Ok(None),
            Err(e) => match &e {
                SdkError::ServiceError(ctx) => Ok(Some(ctx.raw().status().as_u16())),
                _ => Err(format!("conditional PUT {key}: no HTTP response: {e}")),
            },
        }
    }

    /// The probe body, written to RETURN its failures rather than panic on
    /// them, so the caller's cleanup is reached on every arm.
    async fn conditional_write_probe(s3: &S3Client, bucket: &str, key: &str) -> Result<(), String> {
        // 1. A plain PUT under a throwaway key.
        let seeded = s3
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from_static(b"probe-one"))
            .send()
            .await
            .map_err(|e| format!("seeding PUT {key}: {e}"))?;

        // 2. Its ETag, which is the generation the next arm fences against.
        let etag = seeded
            .e_tag()
            .ok_or_else(|| format!("seeding PUT {key} returned no ETag"))?
            .to_string();

        // 3. A deliberately wrong If-Match. A store honoring it answers 412.
        let wrong = format!("\"{}\"", "0".repeat(32));
        if etag.trim_matches('"') == wrong.trim_matches('"') {
            return Err(format!(
                "the seeded ETag {etag} collides with the deliberately wrong one, \
                 so this arm would prove nothing"
            ));
        }
        match conditional_put(s3, bucket, key, b"probe-two", Some(&wrong), None).await? {
            Some(412) => {}
            Some(status) => {
                return Err(format!(
                    "a stale If-Match must be refused with 412, the endpoint answered {status}"
                ))
            }
            None => {
                return Err(
                    "a stale If-Match was ACCEPTED: this endpoint does not honor If-Match, so \
                     the release fence cannot hold here"
                        .to_string(),
                )
            }
        }

        // 4. If-None-Match `*` over the object that now exists. This arm matters
        // MORE than the one above. An ignored If-Match eventually surfaces as
        // odd behavior, because a stale writer overwrites and someone notices
        // the lost tree. An ignored If-None-Match just returns 200, so a publish
        // that should have been fenced lands with no error anywhere: the silent
        // no-op the bucket-type caveat on this test describes.
        match conditional_put(s3, bucket, key, b"probe-three", None, Some("*")).await? {
            // Either status is a pass, and the asymmetry with the If-Match arm
            // above mirrors `upload`'s classifier exactly: 412 is always a lost
            // precondition, and 409 is one too when we asked for create-only.
            // AWS documents 409 for a create-only conflict racing a delete, so a
            // store answering it is enforcing the precondition and we already
            // handle it. Pinning 412 alone here would fail the probe against a
            // backend that is behaving correctly, which sends whoever runs it
            // chasing a fault that is not there.
            Some(412) | Some(409) => {}
            Some(status) => {
                return Err(format!(
                    "create-only over an existing object must be refused with 412 or 409, \
                     the endpoint answered {status}"
                ))
            }
            None => {
                return Err(
                    "If-None-Match * was ACCEPTED over an existing object: this endpoint does \
                     not honor create-only, so a fenced publish lands silently"
                        .to_string(),
                )
            }
        }

        Ok(())
    }

    /// Probe the REAL Tigris endpoint for the conditional-write semantics the
    /// release fence depends on.
    ///
    /// UNTIL THIS IS RUN AGAINST REAL CREDENTIALS, the fence is verified against
    /// vendor documentation and an in-process mock, not against the backend it
    /// runs on. The mock implements the semantics we believe Tigris has; it
    /// cannot tell us whether Tigris actually has them.
    ///
    /// The bucket matters, not just the endpoint. Tigris documents conditional
    /// operations as supported on Single-region and Multi-region buckets only.
    /// Global and Dual-region buckets are eventually consistent, and a
    /// conditional PUT evaluated against a stale replica would make the fence a
    /// silent no-op rather than an error. So point `GITLAWB_TIGRIS_BUCKET` at a
    /// throwaway bucket of the SAME type production uses.
    ///
    /// Ignored by default and additionally gated on `GITLAWB_TIGRIS_PROBE=1`,
    /// because it writes to a real bucket and costs real requests. Run with:
    /// `GITLAWB_TIGRIS_PROBE=1 cargo test -p gitlawb-node --bin gitlawb-node
    /// tigris_honors_conditional_writes -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "writes to a real Tigris bucket; needs GITLAWB_TIGRIS_PROBE=1 plus credentials"]
    async fn tigris_honors_conditional_writes() {
        let Some(bucket) = probe_env() else {
            eprintln!(
                "tigris conditional-write probe: skipped. Set GITLAWB_TIGRIS_PROBE=1, \
                 GITLAWB_TIGRIS_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and \
                 AWS_ENDPOINT_URL_S3 to run it."
            );
            return;
        };

        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3 = S3Client::new(&config);
        // A fresh key per run, so a probe that somehow orphaned an object on an
        // earlier run cannot change what this one observes.
        let key = format!("probe/conditional-write-{}.bin", uuid::Uuid::new_v4());

        // CLEANUP MUST RUN ON EVERY ARM, and a failing assertion is precisely
        // the case this probe exists to catch, so the delete cannot sit after
        // the checks. The body returns its failures rather than panicking, and
        // `catch_unwind` covers the panic an SDK call could still raise; either
        // way the delete below is reached before the verdict is re-raised.
        let outcome = std::panic::AssertUnwindSafe(conditional_write_probe(&s3, &bucket, &key))
            .catch_unwind()
            .await;

        if let Err(e) = s3.delete_object().bucket(&bucket).key(&key).send().await {
            eprintln!("tigris conditional-write probe: cleanup of {key} failed: {e}");
        }

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(msg)) => panic!("tigris conditional-write probe: {msg}"),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}
