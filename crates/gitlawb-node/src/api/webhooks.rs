//! Webhook CRUD API.
//!
//! POST   /api/v1/repos/:owner/:repo/hooks        — create (owner only)
//! GET    /api/v1/repos/:owner/:repo/hooks        — list (owner only; auth required)
//! DELETE /api/v1/repos/:owner/:repo/hooks/:id   — delete (owner only)

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::Webhook;
use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub secret: Option<String>,
    /// Event patterns to subscribe to. Use ["*"] for all events.
    /// Valid values: "pull_request.opened", "pull_request.reviewed",
    ///               "pull_request.merged", "pull_request.closed", "push", "*"
    pub events: Option<Vec<String>>,
}

/// POST /api/v1/repos/:owner/:repo/hooks
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<Webhook>)> {
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;
    crate::api::require_repo_owner(&record, &auth.0)?;

    // Gate the target through the same hardened public-host validator the peer
    // announce path uses, so an authenticated owner cannot register a webhook
    // that makes the node POST to loopback/private/link-local/metadata
    // endpoints (SSRF). Delivery runs on the shared no-redirect client
    // (main.rs), which closes the 3xx-to-internal bounce.
    if !crate::api::peers::is_public_http_url(&req.url) {
        return Err(AppError::BadRequest(format!(
            "webhook URL {}",
            crate::api::peers::PUBLIC_HTTP_URL_REQUIREMENT
        )));
    }

    let events = req.events.unwrap_or_else(|| vec!["*".into()]);
    let created_by_did = auth.0;

    let hook = Webhook {
        id: Uuid::new_v4().to_string(),
        repo_id: record.id,
        url: req.url,
        // Seal the secret before it touches the database (#506): the column and
        // any dump/backup of it hold ciphertext, never the caller's signing key.
        secret: req.secret.map(|plain| {
            crate::webhook_secret::WebhookSecret::new(crate::webhook_secret::seal(
                state.webhook_secret_key.as_ref(),
                &plain,
            ))
        }),
        events,
        created_by_did,
        created_at: Utc::now().to_rfc3339(),
        active: true,
    };

    state.db.create_webhook(&hook).await?;
    Ok((StatusCode::CREATED, Json(hook)))
}

/// GET /api/v1/repos/:owner/:repo/hooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    // This route sits on `optional_signature`, so the DID is optional. Webhook
    // callback URLs are owner-secret config and there is no anonymous form, so a
    // headerless caller is rejected before any lookup (401, which fires for an
    // existing-private and an absent repo alike, so it leaks no existence).
    let Some(Extension(AuthenticatedDid(caller))) = auth else {
        return Err(AppError::Unauthorized(
            "listing webhooks requires authentication".into(),
        ));
    };

    // Read-visibility first, then owner. authorize_repo_read returns 404 on a
    // visibility deny, so a non-reader of a private repo cannot tell it exists
    // (uniform with the sibling read surfaces); require_repo_owner then yields
    // 403 only for a non-owner of a public/readable repo, where existence is not
    // secret.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(&caller), "/").await?;
    crate::api::require_repo_owner(&record, &caller)?;

    let hooks = state.db.list_webhooks(&record.id).await?;
    // `WebhookSecret` redacts itself on serialize, so a set secret is emitted as
    // "***" and the signing material never appears in the body (see webhook_secret).
    let count = hooks.len();
    Ok(Json(
        serde_json::json!({ "webhooks": hooks, "count": count }),
    ))
}

/// DELETE /api/v1/repos/:owner/:repo/hooks/:id
pub async fn delete_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;
    crate::api::require_repo_owner(&record, &auth.0)?;

    // Verify the webhook belongs to this repo
    let hook = state
        .db
        .get_webhook(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webhook {id} not found")))?;

    if hook.repo_id != record.id {
        return Err(AppError::NotFound(format!("webhook {id} not found")));
    }

    state.db.delete_webhook(&id).await?;
    Ok(Json(serde_json::json!({ "deleted": true, "id": id })))
}

#[cfg(test)]
mod tests {
    use axum::extract::{Extension, Path, State};
    use axum::Json;
    use chrono::Utc;
    use gitlawb_core::identity::Keypair;
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::{create_webhook, CreateWebhookRequest};
    use crate::api::peers::{is_public_http_url, PUBLIC_HTTP_URL_REQUIREMENT};
    use crate::auth::AuthenticatedDid;
    use crate::db::RepoRecord;
    use crate::error::AppError;
    use crate::test_support::test_state;
    use rand::Rng;

    // create_webhook gates req.url through is_public_http_url. Pin the exact
    // SSRF targets from issue #81 so the webhook path can never regress to the
    // old scheme-only check, independent of the validator's own peer tests.
    #[test]
    fn webhook_url_gate_rejects_ssrf_targets() {
        for bad in [
            "http://127.0.0.1:5432/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/",
            "http://node.localhost/",
            "http://10.0.0.5/",
            "http://[::1]/",
            // IPv6 transition encodings smuggling loopback v4 (6to4 / NAT64).
            "http://[2002:7f00:1::]/",
            "http://[64:ff9b::7f00:1]/",
            "ftp://example.com/",
            "not-a-url",
        ] {
            assert!(!is_public_http_url(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn webhook_url_gate_allows_public_targets() {
        assert!(is_public_http_url("https://hooks.example.com/gitlawb"));
        assert!(is_public_http_url("http://203.0.113.10:7545/"));
    }

    #[sqlx::test]
    async fn webhook_localhost_rejection_uses_shared_public_url_contract(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = Keypair::generate().did().to_string();
        let repo_id = Uuid::new_v4().to_string();
        state
            .db
            .create_repo(&RepoRecord {
                id: repo_id.clone(),
                name: "webhook-contract".to_string(),
                owner_did: owner.clone(),
                description: None,
                is_public: true,
                default_branch: "main".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                disk_path: "/tmp/webhook-contract.git".to_string(),
                forked_from: None,
                machine_id: None,
            })
            .await
            .unwrap();

        let result = create_webhook(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.clone())),
            Path((owner, "webhook-contract".to_string())),
            Json(CreateWebhookRequest {
                url: "https://node.localhost/hook".to_string(),
                secret: None,
                events: None,
            }),
        )
        .await;

        match result {
            Err(AppError::BadRequest(message)) => assert_eq!(
                message,
                format!("webhook URL {PUBLIC_HTTP_URL_REQUIREMENT}")
            ),
            Err(error) => panic!("unexpected webhook rejection: {error}"),
            Ok(_) => panic!("a .localhost webhook must be rejected"),
        }
        assert!(
            state.db.list_webhooks(&repo_id).await.unwrap().is_empty(),
            "a rejected .localhost webhook must leave no row behind"
        );
    }

    /// The startup re-encryption pass must seal any webhook secret still resting
    /// as plaintext (a row written before at-rest encryption shipped), and leave
    /// a second pass with nothing to do.
    #[sqlx::test]
    async fn reencrypt_legacy_secrets_encrypts_existing_cleartext(pool: PgPool) {
        let state = test_state(pool).await;

        // Seed a webhook the way a pre-encryption node would have: plaintext
        // secret written straight into the row, bypassing the handler's seal.
        let hook = crate::db::Webhook {
            id: Uuid::new_v4().to_string(),
            repo_id: "owner/legacy-repo".to_string(),
            url: "https://hooks.example.com/legacy".to_string(),
            secret: Some(crate::webhook_secret::WebhookSecret::new(
                "legacy-plaintext".to_string(),
            )),
            events: vec!["*".to_string()],
            created_by_did: "did:key:zLEGACYOWNER".to_string(),
            created_at: Utc::now().to_rfc3339(),
            active: true,
        };
        state.db.create_webhook(&hook).await.unwrap();

        let rewritten = state
            .db
            .reencrypt_legacy_webhook_secrets(state.webhook_secret_key.as_ref())
            .await
            .unwrap();
        assert_eq!(rewritten, 1, "exactly the one plaintext row is rewritten");

        let stored = state.db.get_webhook(&hook.id).await.unwrap().unwrap();
        let secret = stored.secret.expect("secret retained after re-encryption");
        assert!(secret.is_sealed(), "re-encrypted secret must be sealed");
        assert_eq!(
            crate::webhook_secret::open(state.webhook_secret_key.as_ref(), secret.as_str())
                .as_deref(),
            Some("legacy-plaintext"),
            "the node-held key must recover the original secret"
        );

        // Idempotent: a second pass finds nothing left to rewrite.
        let again = state
            .db
            .reencrypt_legacy_webhook_secrets(state.webhook_secret_key.as_ref())
            .await
            .unwrap();
        assert_eq!(again, 0);
    }

    /// A legacy plaintext secret that literally begins with the seal prefix is
    /// not ciphertext: prefix-matching alone would skip it forever while
    /// `reveal` fails to open it, wedging the hook. Classification is by
    /// `open`, so the pass seals it and the literal secret survives.
    #[sqlx::test]
    async fn reencrypt_seals_a_prefixed_plaintext_secret(pool: PgPool) {
        let state = test_state(pool).await;
        let literal = format!(
            "{}not-a-real-ciphertext",
            crate::webhook_secret::SEAL_PREFIX
        );
        let hook = crate::db::Webhook {
            id: Uuid::new_v4().to_string(),
            repo_id: "owner/prefixed-repo".to_string(),
            url: "https://hooks.example.com/prefixed".to_string(),
            secret: Some(crate::webhook_secret::WebhookSecret::new(literal.clone())),
            events: vec!["*".to_string()],
            created_by_did: "did:key:zLEGACYOWNER".to_string(),
            created_at: Utc::now().to_rfc3339(),
            active: true,
        };
        state.db.create_webhook(&hook).await.unwrap();

        let rewritten = state
            .db
            .reencrypt_legacy_webhook_secrets(state.webhook_secret_key.as_ref())
            .await
            .unwrap();
        assert_eq!(rewritten, 1, "the prefixed plaintext row is rewritten");

        let stored = state.db.get_webhook(&hook.id).await.unwrap().unwrap();
        let secret = stored.secret.unwrap();
        assert!(secret.is_sealed());
        assert_eq!(
            crate::webhook_secret::reveal(state.webhook_secret_key.as_ref(), &secret).as_deref(),
            Some(literal.as_str()),
            "the literal plaintext, prefix included, is the recovered secret"
        );
    }

    /// A well-formed sealed payload that does not open under this node's key
    /// (foreign or rotated ciphertext) must survive the re-encrypt pass
    /// untouched: re-wrapping it would make `reveal` return the outer blob as
    /// a signing secret and flip a broken hook from withheld into garbage
    /// signatures.
    #[sqlx::test]
    async fn reencrypt_leaves_foreign_ciphertext_untouched(pool: PgPool) {
        let state = test_state(pool).await;
        let foreign_key: [u8; 32] = chacha20poly1305::aead::OsRng.gen();
        let foreign_ciphertext = crate::webhook_secret::seal(&foreign_key, "owner-real-secret");
        let hook = crate::db::Webhook {
            id: Uuid::new_v4().to_string(),
            repo_id: "owner/foreign-repo".to_string(),
            url: "https://hooks.example.com/foreign".to_string(),
            secret: Some(crate::webhook_secret::WebhookSecret::new(
                foreign_ciphertext.clone(),
            )),
            events: vec!["*".to_string()],
            created_by_did: "did:key:zLEGACYOWNER".to_string(),
            created_at: Utc::now().to_rfc3339(),
            active: true,
        };
        state.db.create_webhook(&hook).await.unwrap();

        let rewritten = state
            .db
            .reencrypt_legacy_webhook_secrets(state.webhook_secret_key.as_ref())
            .await
            .unwrap();
        assert_eq!(rewritten, 0, "foreign ciphertext is left unchanged");

        let stored = state.db.get_webhook(&hook.id).await.unwrap().unwrap();
        let secret = stored.secret.unwrap();
        assert_eq!(
            secret.as_str(),
            foreign_ciphertext,
            "the stored value is still the unopenable ciphertext, not a re-wrap"
        );
        assert!(
            crate::webhook_secret::reveal(state.webhook_secret_key.as_ref(), &secret).is_none(),
            "delivery still withholds: reveal cannot open the foreign blob"
        );
    }
}
