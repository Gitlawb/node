//! S3-compatible blob backend.
//!
//! Works with any S3 API implementation: Tigris, Cloudflare R2, AWS S3, MinIO,
//! Backblaze B2. Credentials and (for Tigris on Fly) the endpoint are read from
//! the standard AWS env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//! `AWS_ENDPOINT_URL_S3`, `AWS_REGION`). `endpoint`/`force_path_style` override
//! those for self-hosted services like MinIO.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;
use bytes::Bytes;
use tracing::debug;

use super::{validate_key, BlobStore, ObjectMeta};

#[derive(Clone)]
pub struct S3BlobStore {
    s3: S3Client,
    bucket: String,
}

impl S3BlobStore {
    /// Build a client. `endpoint` overrides `AWS_ENDPOINT_URL_S3` (for R2/MinIO);
    /// `force_path_style` is required by MinIO and some S3-compatibles.
    pub async fn new(
        bucket: &str,
        endpoint: Option<String>,
        force_path_style: bool,
    ) -> Result<Self> {
        let shared = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let Some(ep) = endpoint {
            builder = builder.endpoint_url(ep);
        }
        if force_path_style {
            builder = builder.force_path_style(true);
        }
        // Bound requests so a hung endpoint can't block the calling task forever
        // (under async_upload it would hold the advisory lock and stall every
        // later push). attempt_timeout bounds a single try; operation_timeout
        // bounds the whole call incl. retries — generous enough for large
        // archive transfers.
        let timeouts = aws_sdk_s3::config::timeout::TimeoutConfig::builder()
            .operation_attempt_timeout(std::time::Duration::from_secs(60))
            .operation_timeout(std::time::Duration::from_secs(300))
            .build();
        builder = builder.timeout_config(timeouts);
        let s3 = S3Client::from_conf(builder.build());
        Ok(Self {
            s3,
            bucket: bucket.to_string(),
        })
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    fn backend_name(&self) -> &'static str {
        "s3"
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        validate_key(key)?;
        match self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => {
                let data = resp
                    .body
                    .collect()
                    .await
                    .context("reading S3 response body")?
                    .into_bytes();
                Ok(Some(data))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|e| e.is_no_such_key()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("S3 GET {key}: {e}"))
                }
            }
        }
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<ObjectMeta> {
        validate_key(key)?;
        let size = body.len() as u64;
        let resp = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(body))
            .send()
            .await
            .context(format!("S3 PUT {key}"))?;
        debug!(key = %key, size, "s3 put");
        Ok(ObjectMeta {
            size,
            etag: resp.e_tag().map(|s| s.to_string()),
        })
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        validate_key(key)?;
        match self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => Ok(Some(ObjectMeta {
                size: resp.content_length().unwrap_or(0).max(0) as u64,
                etag: resp.e_tag().map(|s| s.to_string()),
            })),
            Err(e) => {
                if e.as_service_error().is_some_and(|e| e.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("S3 HEAD {key}: {e}"))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .context(format!("S3 DELETE {key}"))?;
        Ok(())
    }
}
