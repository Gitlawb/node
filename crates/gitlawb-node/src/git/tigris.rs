//! Tigris (S3-compatible) storage client for git bare repos.
//!
//! Repos are stored as `repos/v1/{owner_slug}/{repo_name}.tar.zst` — a
//! zstd-compressed tar archive of the bare repo directory.

use std::path::Path;

use anyhow::{Context, Result};
use aws_sdk_s3::Client as S3Client;
use tracing::{debug, info};

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

    /// Upload a local bare repo directory to Tigris as a tar.zst archive.
    pub async fn upload(&self, owner_slug: &str, repo_name: &str, local_path: &Path) -> Result<()> {
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

        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .content_type("application/zstd")
            .send()
            .await
            .context(format!("tigris PUT {key}"))?;

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
        let key = Self::repo_key(owner_slug, repo_name);
        debug!(key = %key, path = %local_path.display(), "downloading repo from tigris");

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
            .into_bytes()
            .to_vec();

        // Extract tar.zst to local path
        tokio::task::spawn_blocking({
            let local_path = local_path.to_path_buf();
            move || decompress_repo(&data, &local_path)
        })
        .await
        .context("extract task panicked")?
        .context("extracting repo")?;

        info!(key = %key, path = %local_path.display(), "downloaded repo from tigris");
        Ok(())
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

/// Decompress a tar.zst byte vector into a local directory.
fn decompress_repo(data: &[u8], local_path: &Path) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent).context("creating parent dir")?;
    }
    std::fs::create_dir_all(local_path).context("creating repo dir")?;

    let decoder = zstd::stream::Decoder::new(data)?;
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(local_path).context("unpacking tar.zst")?;

    Ok(())
}
