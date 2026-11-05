//! Tigris (S3-compatible) storage client for git bare repos.
//!
//! Repos are stored as `repos/v1/{owner_slug}/{repo_name}.tar.zst` — a
//! zstd-compressed tar archive of the bare repo directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use aws_sdk_s3::Client as S3Client;
use tracing::{debug, info, warn};

// The publication vocabulary lives in `git::publish`, which carries no
// object-storage types, and is re-exported here so existing `git::tigris::…`
// imports keep resolving. #79 deletes this file; `git::publish` is what survives
// the swap, and the only backend-aware code below is `classify_dispatch`.
pub use super::publish::{
    DispatchKnowledge, PublishAttemptId, PublishStage, PublishStageCell, StoredGeneration,
    UploadError, UploadPrecondition, UploadReceipt, ATTEMPT_METADATA_KEY,
};

/// What happened to a conditional, attempt-guarded delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptDelete {
    /// The object was this attempt's and is gone.
    Deleted,
    /// Nothing is stored under the key.
    Absent,
    /// Something is stored, and it is NOT this attempt's work. Left alone.
    NotOurs,
}

/// THE ONLY BACKEND-AWARE CLASSIFIER in the publish path.
///
/// It answers one question: does this failure PROVE the request never committed?
/// Anything short of proof is [`DispatchKnowledge::MaybeSent`], because the
/// caller's next move on a definite failure is destructive (delete the object,
/// drop the only local clone, invalidate the cache) and being wrong there
/// destroys published state.
///
/// - An HTTP status means the server answered. A 4xx is a refusal it took
///   BEFORE storing anything, so it proves non-publication. A 5xx does not: the
///   store can commit and then fail to report it.
/// - No status at all means no response was read. Only a construction failure
///   proves the request never left; Smithy's timeout, dispatch and response
///   errors all allow that the bytes arrived and committed while the answer was
///   lost, corrupted, or never parsed.
/// - `SdkError` is `#[non_exhaustive]`, so the fallback arm must be the CAUTIOUS
///   one. A future variant defaulting to "definitely failed" would silently
///   re-open exactly the class this closes.
///
/// #79 replaces `tigris.rs` with a `BlobStore` layer; this function is the piece
/// each backend reimplements, and nothing above it changes.
fn classify_put_failure<E, R>(
    err: &aws_sdk_s3::error::SdkError<E, R>,
    status: Option<u16>,
) -> DispatchKnowledge {
    if let Some(status) = status {
        return if (400..500).contains(&status) {
            DispatchKnowledge::NeverSent
        } else {
            DispatchKnowledge::MaybeSent
        };
    }
    match err {
        aws_sdk_s3::error::SdkError::ConstructionFailure(_) => DispatchKnowledge::NeverSent,
        _ => DispatchKnowledge::MaybeSent,
    }
}

/// Wrapper around the S3 client with the configured bucket.
#[derive(Clone)]
pub struct TigrisClient {
    s3: S3Client,
    bucket: String,
    /// Test-only seam: when set, the blocking compression inside `upload_tracked`
    /// parks on this barrier. That is the ONLY window in which a publish attempt
    /// can be cancelled with `PublishStage::PreparingArchive` still holding, and
    /// it is unreachable from outside without a seam because compression of a
    /// test-sized repo finishes in microseconds.
    #[cfg(test)]
    compress_gate: Option<Arc<BlockingGate>>,
}

/// A gate a BLOCKING thread parks on until a test opens it.
///
/// A condvar rather than a held `MutexGuard`: the test's assertions run while the
/// gate is shut, and holding a `std::sync::MutexGuard` across those awaits is
/// both a lint violation and a real hazard. Here the test owns no guard at all —
/// it flips a flag and notifies.
#[cfg(test)]
#[derive(Default)]
pub struct BlockingGate {
    open: Mutex<bool>,
    opened: std::sync::Condvar,
}

#[cfg(test)]
impl BlockingGate {
    /// A gate that starts SHUT.
    pub fn shut() -> Self {
        Self::default()
    }

    fn wait(&self) {
        let mut open = self.open.lock().expect("compression gate poisoned");
        while !*open {
            open = self
                .opened
                .wait(open)
                .expect("compression gate poisoned while waiting");
        }
    }

    /// Let every parked compression through. Call this at teardown so the
    /// blocking thread is not stranded for the life of the process.
    pub fn open(&self) {
        *self.open.lock().expect("compression gate poisoned") = true;
        self.opened.notify_all();
    }
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
            #[cfg(test)]
            compress_gate: None,
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
            compress_gate: None,
        }
    }

    /// Test-only: park this client's blocking compression on `gate` until the
    /// holder releases it, so a cancellation can be aimed at
    /// [`PublishStage::PreparingArchive`] rather than at the PUT.
    #[cfg(test)]
    pub fn with_compress_gate(mut self, gate: Arc<BlockingGate>) -> Self {
        self.compress_gate = Some(gate);
        self
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
        Ok(self
            .head_generation(owner_slug, repo_name)
            .await?
            .map(|g| g.etag)
            .unwrap_or(None))
    }

    /// The full stored generation: the ETag AND the attempt that published it.
    ///
    /// The attempt half is what makes a lost response recoverable. An ETag alone
    /// answers "has the generation moved", which every writer sees the same way;
    /// the attempt id answers "are the published bytes MINE", which is the
    /// question a client whose PUT response vanished actually needs answered.
    pub async fn head_generation(
        &self,
        owner_slug: &str,
        repo_name: &str,
    ) -> Result<Option<StoredGeneration>> {
        let key = Self::repo_key(owner_slug, repo_name);
        match self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(out) => {
                let etag = out
                    .e_tag()
                    .context(format!("tigris HEAD {key}: hit carried no ETag"))?
                    .to_string();
                let attempt = out
                    .metadata()
                    .and_then(|m| m.get(ATTEMPT_METADATA_KEY))
                    .cloned();
                Ok(Some(StoredGeneration {
                    etag: Some(etag),
                    attempt,
                }))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|e| e.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("tigris HEAD {key}: {e}"))
                }
            }
        }
    }

    /// Did `attempt`'s bytes land? The reconciliation an ambiguous dispatch owes
    /// before anything downstream may treat it as confirmation.
    ///
    /// `Ok(false)` is deliberately NOT "the PUT failed": an abandoned request may
    /// still be in flight, so a negative answer licenses refusing and retrying,
    /// never deleting. Only `Ok(true)` upgrades an unresolved attempt to
    /// published.
    pub async fn attempt_landed(
        &self,
        owner_slug: &str,
        repo_name: &str,
        attempt: &PublishAttemptId,
    ) -> Result<bool> {
        Ok(self
            .head_generation(owner_slug, repo_name)
            .await?
            .is_some_and(|g| g.belongs_to(attempt)))
    }

    /// Upload a local bare repo directory to Tigris as a tar.zst archive,
    /// fenced by `precondition`, under a freshly minted attempt identity.
    pub async fn upload(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
        precondition: UploadPrecondition,
    ) -> std::result::Result<UploadReceipt, UploadError> {
        self.upload_tracked(
            owner_slug,
            repo_name,
            local_path,
            precondition,
            PublishAttemptId::new(),
            None,
        )
        .await
    }

    /// The full form: a caller-chosen attempt identity, and a stage cell the
    /// upload reports its progress into.
    ///
    /// The stage cell is the answer to "a dropped future never returns an
    /// outcome". Compression runs inside `spawn_blocking` and the conditional PUT
    /// is not even constructed until it finishes, so a handler cancelled during
    /// compression definitely never attempted publication — but nothing could
    /// observe that, because the only report was the return value of a future
    /// that no longer exists. Marking [`PublishStage::PreparingArchive`] before
    /// the blocking call and [`PublishStage::PutDispatched`] immediately before
    /// `send()` makes that boundary readable from outside.
    pub async fn upload_tracked(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
        precondition: UploadPrecondition,
        attempt: PublishAttemptId,
        stage: Option<&PublishStageCell>,
    ) -> std::result::Result<UploadReceipt, UploadError> {
        let key = Self::repo_key(owner_slug, repo_name);
        debug!(key = %key, path = %local_path.display(), attempt = %attempt, "uploading repo to tigris");

        if let Some(stage) = stage {
            stage.set(PublishStage::PreparingArchive);
        }

        // Create tar.zst in memory. Nothing has been sent at this point and
        // nothing can be: the request below is not constructed until this
        // returns. A failure or a cancellation here is a definite
        // non-publication.
        let compressed = {
            let local_path = local_path.to_path_buf();
            #[cfg(test)]
            let gate = self.compress_gate.clone();
            tokio::task::spawn_blocking(move || {
                // Test-only seam: park INSIDE the blocking compression, which is
                // the window a handler can be cancelled in while
                // `PublishStage::PreparingArchive` still holds.
                #[cfg(test)]
                if let Some(gate) = gate {
                    // Blocks until the test opens the gate.
                    gate.wait();
                }
                compress_repo(&local_path)
            })
            .await
        };
        let archive_bytes = match compressed {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                if let Some(stage) = stage {
                    stage.set(PublishStage::Refused);
                }
                return Err(UploadError::NotPublished(e.context("compressing repo")));
            }
            Err(e) => {
                if let Some(stage) = stage {
                    stage.set(PublishStage::Refused);
                }
                return Err(UploadError::NotPublished(
                    anyhow::Error::new(e).context("tar task panicked"),
                ));
            }
        };

        let body = aws_sdk_s3::primitives::ByteStream::from(archive_bytes);

        let mut req = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            // The attempt identity travels WITH the bytes. That is what makes a
            // lost response recoverable: the client can HEAD the key afterwards
            // and ask whether the published object is its own work, which is
            // decidable, instead of asking whether its request succeeded, which
            // is not.
            .metadata(ATTEMPT_METADATA_KEY, attempt.as_str())
            .body(body)
            .content_type("application/zstd");
        match &precondition {
            UploadPrecondition::IfMatch(etag) => req = req.if_match(etag),
            UploadPrecondition::IfAbsent => req = req.if_none_match("*"),
            UploadPrecondition::Unconditional => {}
        }

        // From HERE the bytes may reach the store. Everything downstream that
        // could destroy state has to treat this stage as "maybe published".
        if let Some(stage) = stage {
            stage.set(PublishStage::PutDispatched {
                attempt: attempt.clone(),
            });
        }

        let sent = req.send().await;
        let out = match sent {
            Ok(out) => out,
            Err(e) => {
                // `PutObjectError` models no PreconditionFailed variant (its arms are
                // EncryptionTypeMismatch, InvalidRequest, InvalidWriteOffset,
                // TooManyParts, Unhandled), so a refused precondition arrives as
                // `Unhandled` and matching the enum would classify it as a generic
                // failure. The raw HTTP status off the response is the only place the
                // answer actually lives.
                //
                // Read it via `raw_response()`, not a `ServiceError`-only match: the
                // SDK exposes the raw response for BOTH `ServiceError` and
                // `ResponseError`, and a refused conditional PUT whose error body the
                // SDK cannot parse (malformed XML, premature close) surfaces as
                // `ResponseError`. Matching only `ServiceError` would classify that
                // unparsable 409/412 as a generic failure, and `RepoWriteGuard::release`
                // would log-and-succeed instead of taking the supersede retry,
                // acknowledging a write that was definitively not published.
                let status = e.raw_response().map(|raw| raw.status().as_u16());
                // 412 is always a lost precondition. 409 is one only when we asked
                // for create-only, which is how S3-compatible stores report "the key
                // already exists". Everything else, 404 included, is a real failure:
                // archive keys are never deleted by the write path, so a 404 here
                // means something permanent like a missing bucket or a misrouted
                // endpoint, and reporting that as a lost precondition would tell a
                // caller to expect a successor that does not exist.
                let lost = match status {
                    Some(412) => true,
                    Some(409) => matches!(precondition, UploadPrecondition::IfAbsent),
                    _ => false,
                };
                if lost {
                    if let Some(stage) = stage {
                        stage.set(PublishStage::Refused);
                    }
                    return Err(UploadError::PreconditionLost {
                        status: status.expect("a lost precondition came from a status"),
                    });
                }
                let knowledge = classify_put_failure(&e, status);
                let ctx = anyhow::Error::new(e).context(format!("tigris PUT {key}"));
                return Err(match knowledge {
                    DispatchKnowledge::NeverSent => {
                        if let Some(stage) = stage {
                            stage.set(PublishStage::Refused);
                        }
                        UploadError::NotPublished(ctx)
                    }
                    DispatchKnowledge::MaybeSent => {
                        warn!(
                            key = %key,
                            attempt = %attempt,
                            status = ?status,
                            "tigris PUT failed WITHOUT proving it did not commit — the outcome \
                             is ambiguous and must be reconciled, not compensated"
                        );
                        if let Some(stage) = stage {
                            stage.set(PublishStage::Ambiguous {
                                attempt: attempt.clone(),
                            });
                        }
                        UploadError::Ambiguous {
                            attempt: attempt.clone(),
                            source: ctx,
                        }
                    }
                });
            }
        };

        let etag = out.e_tag().map(str::to_string);
        if let Some(stage) = stage {
            stage.set(PublishStage::Published {
                attempt: attempt.clone(),
                etag: etag.clone(),
            });
        }
        info!(key = %key, attempt = %attempt, "uploaded repo to tigris");
        Ok(UploadReceipt { attempt, etag })
    }

    /// Delete a repo archive ONLY while it is still `attempt`'s work.
    ///
    /// The unconditional delete this replaces used the logical owner/name as its
    /// cleanup authority, so a failed attempt compensating late could erase the
    /// object a SUCCESSOR had already published under the same name and already
    /// returned 201 for. A second name lookup before the delete only narrows that
    /// window; reading the attempt id off the object and fencing the delete on
    /// the generation it came from closes it.
    pub async fn delete_if_attempt_matches(
        &self,
        owner_slug: &str,
        repo_name: &str,
        attempt: &PublishAttemptId,
    ) -> Result<AttemptDelete> {
        let Some(generation) = self.head_generation(owner_slug, repo_name).await? else {
            return Ok(AttemptDelete::Absent);
        };
        if !generation.belongs_to(attempt) {
            return Ok(AttemptDelete::NotOurs);
        }
        let key = Self::repo_key(owner_slug, repo_name);
        let mut req = self.s3.delete_object().bucket(&self.bucket).key(&key);
        // The If-Match guard is what makes this atomic rather than merely
        // narrowed: between the HEAD above and this call a successor can publish,
        // and the store refusing on the moved generation is the only thing that
        // stops the delete landing on their object.
        if let Some(etag) = generation.etag.as_deref() {
            req = req.if_match(etag);
        }
        match req.send().await {
            Ok(_) => Ok(AttemptDelete::Deleted),
            Err(e) => {
                // A refused conditional delete means the generation moved: the
                // object is no longer ours, which is a successful outcome for a
                // guard whose whole job is not to touch somebody else's bytes.
                if e.raw_response()
                    .map(|raw| raw.status().as_u16())
                    .is_some_and(|s| s == 412 || s == 409)
                {
                    return Ok(AttemptDelete::NotOurs);
                }
                Err(anyhow::anyhow!("tigris conditional DELETE {key}: {e}"))
            }
        }
    }

    /// Download a repo archive from Tigris and extract to local disk.
    pub async fn download(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &super::repo_store::ValidatedRepoDiskPath,
        swap_authority: Option<Arc<AtomicBool>>,
    ) -> Result<()> {
        self.download_to(owner_slug, repo_name, local_path, true, swap_authority)
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
        target: &super::repo_store::ValidatedRepoDiskPath,
        publish: bool,
        swap_authority: Option<Arc<AtomicBool>>,
    ) -> Result<DownloadExtract> {
        let key = Self::repo_key(owner_slug, repo_name);
        debug!(key = %key, path = %target.as_path().display(), "downloading repo from tigris");

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

        // The snapshot temp dir is decided HERE, in the async layer, before the
        // extraction runs. Cleanup ownership moves into the blocking task so a
        // cancelled async future cannot drop it while extraction is still running.
        let snapshot_tmp = if publish {
            None
        } else {
            let parent = target.parent().context("snapshot path has no parent")?;
            std::fs::create_dir_all(parent).context("creating parent dir")?;
            let file_name = target
                .file_name()
                .context("snapshot path has no file name")?
                .to_string_lossy();
            Some(parent.join(format!(
                ".{file_name}.tmp-snapshot.{}",
                uuid::Uuid::new_v4()
            )))
        };

        // Extract tar.zst to a directory.
        let extracted = tokio::task::spawn_blocking({
            let target = target.clone();
            let snapshot_tmp = snapshot_tmp.clone();
            move || -> Result<DownloadExtract> {
                let result = (|| -> Result<DownloadExtract> {
                    if publish {
                        decompress_repo(&data, &target, swap_authority.as_ref())?;
                        return Ok(DownloadExtract::Published(()));
                    }
                    // Non-mutating snapshot: unpack into the temp dir decided above.
                    // The live repo path is never touched.
                    let tmp_dir = snapshot_tmp.expect("snapshot path was decided above");
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
                    Ok(DownloadExtract::Snapshot(TempSnapshotDir { path: tmp_dir }))
                })();
                result
            }
        })
        .await
        .context("extract task panicked")?
        .context("extracting repo")?;

        info!(key = %key, path = %target.as_path().display(), "downloaded repo from tigris");
        Ok(extracted)
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
pub(crate) fn publish_lock(local_path: &Path) -> Arc<Mutex<()>> {
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

/// Owns a snapshot temp dir from extraction through handoff to [`RepoSnapshot`].
/// Dropped when the `spawn_blocking` join result is abandoned, so cancellation
/// before the outer future resumes still removes the directory.
pub(crate) struct TempSnapshotDir {
    path: PathBuf,
}

impl TempSnapshotDir {
    pub(crate) fn into_repo_snapshot(self) -> super::repo_store::RepoSnapshot {
        let path = self.path.clone();
        std::mem::forget(self);
        super::repo_store::RepoSnapshot::from_owned_path(path)
    }
}

impl Drop for TempSnapshotDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// What [`TigrisClient::download_to`] produced.
pub enum DownloadExtract {
    /// Published into the validated live repo path.
    Published(()),
    /// Unpacked into a throwaway temp dir that cleans up on drop until adopted.
    Snapshot(TempSnapshotDir),
}

/// Decompress a tar.zst byte vector into a local directory.
///
/// Extraction is atomic with respect to `local_path`: the archive is unpacked
/// into a sibling temp directory first, and only swapped into place once it
/// fully succeeds. A corrupt or truncated archive therefore can never clobber a
/// good existing copy at `local_path` — on failure we discard the temp dir and
/// leave `local_path` exactly as it was.
fn decompress_repo(
    data: &[u8],
    local_path: &super::repo_store::ValidatedRepoDiskPath,
    swap_authority: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    let live = local_path.as_path();
    let parent = live.parent().context("repo path has no parent")?;
    std::fs::create_dir_all(parent).context("creating parent dir")?;

    let file_name = live
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

    // Swap through the validated-path helper so CodeQL sees the barrier before the
    // remove/rename sink (`rust/path-injection`).
    super::repo_store::swap_extracted_into_validated_repo(local_path, &tmp_dir, swap_authority)?;

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
            Err(e) => match e.raw_response() {
                // Same raw-response rule as `upload`: a refused conditional PUT
                // whose body the SDK cannot parse surfaces as `ResponseError`, and
                // the status has to come off the raw response for both variants.
                // Without it, an unparsable 409/412 would report "no HTTP
                // response" here and skip the supersede retry.
                Some(raw) => Ok(Some(raw.status().as_u16())),
                None => Err(format!("conditional PUT {key}: no HTTP response: {e}")),
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
