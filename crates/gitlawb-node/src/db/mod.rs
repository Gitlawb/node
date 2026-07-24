use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::time::Duration;
use tracing::info;
use uuid::Uuid;

// ── Public data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRecord {
    pub id: String,
    pub name: String,
    pub owner_did: String,
    pub description: Option<String>,
    pub is_public: bool,
    pub default_branch: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disk_path: String,
    pub forked_from: Option<String>,
    pub machine_id: Option<String>,
}

/// Per-rule replication mode for a visibility rule.
/// `A` hides existence entirely (only valid at whole-repo scope `/`).
/// `B` keeps object SHAs and the path visible but withholds content
/// (the only mode allowed for subtrees; enforced on clones in Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VisibilityMode {
    A,
    B,
}

impl VisibilityMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            VisibilityMode::A => "a",
            VisibilityMode::B => "b",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "a" => VisibilityMode::A,
            "b" => VisibilityMode::B,
            other => {
                tracing::warn!("unknown visibility mode in DB: {other:?}, defaulting to B");
                VisibilityMode::B
            }
        }
    }
}

/// A path-scoped visibility rule. `path_glob` is "/" for whole-repo, or a
/// subtree pattern such as "/secret-pkg/**". The repo owner is always an
/// implicit reader regardless of `reader_dids`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityRule {
    pub id: String,
    pub repo_id: String,
    pub path_glob: String,
    pub mode: VisibilityMode,
    pub reader_dids: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub id: String,
    pub repo_id: String,
    pub number: i64,
    pub title: String,
    pub body: Option<String>,
    pub author_did: String,
    pub source_branch: String,
    pub target_branch: String,
    pub status: String, // "open" | "merged" | "closed"
    pub merged_by_did: Option<String>,
    pub merged_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrReview {
    pub id: String,
    pub pr_id: String,
    pub reviewer_did: String,
    pub body: Option<String>,
    pub status: String, // "approved" | "changes_requested" | "comment"
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrComment {
    pub id: String,
    pub pr_id: String,
    pub author_did: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueComment {
    pub id: String,
    pub issue_id: String,
    pub author_did: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub repo_id: String,
    pub url: String,
    pub secret: Option<String>,
    pub events: Vec<String>,
    pub created_by_did: String,
    pub created_at: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefCertificate {
    pub id: String,
    pub repo_id: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub pusher_did: String,
    pub node_did: String,
    pub signature: String,
    pub issued_at: String,
    /// Monotonic sequence number for chain continuity
    pub seq: i64,
    /// Hash of the previous certificate in the chain (first cert uses zeros)
    pub prev: String,
    /// RFC 9421 HTTP Signature from the pusher, proving they authorized this push
    pub pusher_sig: Option<String>,
    /// RFC 9421 Signature-Input header value, needed to reconstruct the signing
    /// string for pusher authorization verification.
    pub signature_input: Option<String>,
    /// Content-Digest header value covering the request body (RFC 9421).
    pub content_digest: Option<String>,
    /// The HTTP request path (e.g. /owner/repo.git/git-receive-pack) for RFC 9421
    /// signing-string reconstruction.
    pub request_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub did: String,
    pub http_url: String,
    pub last_seen: Option<String>,
    pub last_ping_ok: bool,
    pub announced_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReplica {
    pub replica_did: String,
    pub replica_url: String,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedCidRecord {
    pub sha256_hex: String,
    pub cid: String,
    pub pinned_at: String,
    pub pinata_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRefUpdate {
    pub id: String,
    pub node_did: String,
    pub pusher_did: String,
    pub repo: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub timestamp: String,
    pub cert_id: Option<String>,
    pub received_at: String,
    pub from_peer: String,
    /// Full owner DID — populated by new peers; None for events from older
    /// peers that predate the wire-format change (#144).
    pub owner_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyRecord {
    pub id: String,
    pub repo_owner: String,
    pub repo_name: String,
    pub issue_id: Option<String>,
    pub title: String,
    pub amount: i64,
    pub creator_did: String,
    pub claimant_did: Option<String>,
    pub claimant_wallet: Option<String>,
    pub pr_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub claimed_at: Option<String>,
    pub submitted_at: Option<String>,
    pub completed_at: Option<String>,
    pub deadline_secs: i64,
    pub tx_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String,
    pub repo_id: Option<String>,
    pub kind: String,
    pub status: String,
    pub delegator_did: String,
    pub assignee_did: Option<String>,
    pub capability: String,
    pub ucan_token: Option<String>,
    pub payload: Option<String>,
    pub result: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deadline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRow {
    pub did: String,
    pub trust_score: f64,
    pub capabilities: Vec<String>,
    pub registered_at: String,
    pub last_seen: Option<String>,
    /// Lifecycle status: `active` (default) or `revoked` (self-deregistered).
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRecord {
    pub did: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub website: Option<String>,
    pub socials: Option<String>,
    pub profile_cid: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ── Db ────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Db {
    pub(crate) pool: PgPool,
}

impl Db {
    /// Access the underlying Postgres connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[cfg(test)]
    pub fn for_testing(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Test-only: apply the full schema to a fresh pool. `#[sqlx::test]`
    /// provisions an empty per-test database, so DB-backed tests must run this
    /// before seeding. Reuses the production `migrate()` path (the advisory lock
    /// is harmless on an isolated test DB and migrations are idempotent).
    #[cfg(test)]
    pub(crate) async fn run_migrations(&self) -> Result<()> {
        self.migrate().await
    }

    /// Connect the pool and run migrations. The initial connection is bounded
    /// by `acquire_timeout` (sqlx routes pool connects through the acquire
    /// path); migrations are unbounded here — the caller wraps the whole call
    /// in its own attempt timeout, since the migration advisory lock can
    /// legitimately block while another instance migrates.
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self> {
        info!(
            max_connections,
            acquire_timeout_secs = acquire_timeout.as_secs(),
            "connecting to postgres"
        );
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect(database_url)
            .await
            .context("connecting to postgres")?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Cheap liveness probe against the pool, for readiness checks: one
    /// `SELECT 1` that fails fast when the database is unreachable.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("db ping")?;
        Ok(())
    }

    /// Run all pending versioned migrations in order, inside a single
    /// transaction per migration. Idempotent — migrations whose version is
    /// already recorded in `schema_migrations` are skipped.
    ///
    /// Concurrency: the whole routine is guarded by a Postgres advisory lock so
    /// two node instances pointed at the same database (e.g. during a
    /// blue/green or rolling deploy) cannot race to apply the same migration
    /// and trip the `schema_migrations` primary key.
    ///
    /// Legacy installs: v1 bundles the entire pre-versioning schema, and every
    /// statement in it is idempotent (`CREATE TABLE IF NOT EXISTS`,
    /// `CREATE INDEX IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). So an existing
    /// node that predates this system just runs v1 once: existing objects are
    /// no-ops, and any objects it was missing are created. We deliberately do
    /// *not* short-circuit on the presence of a single canonical table — a node
    /// that was behind on schema would then be marked complete while still
    /// missing newer objects.
    async fn migrate(&self) -> Result<()> {
        // Bootstrap: ensure the `schema_migrations` table itself exists.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS schema_migrations (
                version    BIGINT  NOT NULL PRIMARY KEY,
                name       TEXT    NOT NULL,
                applied_at TEXT    NOT NULL
            )"#,
        )
        .execute(&self.pool)
        .await
        .context("creating schema_migrations table")?;

        // Serialize migrations across processes: hold a session-level advisory
        // lock on a dedicated connection for the whole run. Another instance
        // starting up blocks here until we finish. The lock is released when we
        // explicitly unlock below, or automatically if the connection is
        // dropped (e.g. on panic), so a crash can't wedge future restarts.
        let mut lock_conn = self
            .pool
            .acquire()
            .await
            .context("acquiring connection for migration advisory lock")?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(MIGRATION_ADVISORY_LOCK)
            .execute(&mut *lock_conn)
            .await
            .context("acquiring migration advisory lock")?;

        let result = self.run_pending_migrations().await;

        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(MIGRATION_ADVISORY_LOCK)
            .execute(&mut *lock_conn)
            .await;

        result
    }

    /// Apply every migration whose version isn't yet recorded, in order.
    /// Must be called while holding the migration advisory lock.
    async fn run_pending_migrations(&self) -> Result<()> {
        for m in MIGRATIONS {
            let already: bool = sqlx::query(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1) AS applied",
            )
            .bind(m.version)
            .fetch_one(&self.pool)
            .await?
            .get::<bool, _>("applied");

            if already {
                continue;
            }

            let started = std::time::Instant::now();
            info!(
                version = m.version,
                name = m.name,
                statements = m.stmts.len(),
                "applying migration"
            );

            // Run the migration body in a single transaction so a failure
            // mid-way leaves the database in its prior state rather than
            // partially mutated.
            let mut tx = self.pool.begin().await?;
            for stmt in m.stmts {
                sqlx::query(stmt).execute(&mut *tx).await.with_context(|| {
                    format!(
                        "migration v{} ({}) failed on statement: {}",
                        m.version, m.name, stmt
                    )
                })?;
            }
            sqlx::query(
                "INSERT INTO schema_migrations (version, name, applied_at)
                 VALUES ($1, $2, $3)",
            )
            .bind(m.version)
            .bind(m.name)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await
            .context("recording migration as applied")?;
            tx.commit()
                .await
                .with_context(|| format!("committing migration v{}", m.version))?;

            info!(
                version = m.version,
                name = m.name,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "migration applied"
            );
        }

        Ok(())
    }

    /// Returns `(version, name, applied_at)` for every applied migration,
    /// oldest first. Useful for ops/observability — surface via `gl status`
    /// or `/api/v1/stats` in a follow-up.
    #[allow(dead_code)]
    pub async fn migration_status(&self) -> Result<Vec<(i64, String, String)>> {
        let rows = sqlx::query(
            "SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("version"),
                    r.get("name"),
                    r.get("applied_at"),
                )
            })
            .collect())
    }
}

// ── Migration catalogue ──────────────────────────────────────────────────────
//
// All schema statements are bundled into a single v1 migration so we can ship
// versioned migrations on a live network without breaking the existing
// install base. Future schema changes MUST be added as v2, v3, … — never
// appended to v1. Operators can read `schema_migrations` to confirm a node
// is at the expected version.
//
// NOTE: the v1 migration in this branch already includes columns (seq, prev,
// pusher_sig on ref_certificates; status, deadline_height, receipt_sig, cert_id
// on arweave_anchors) that were historically added by migrations v12/v13. These
// were bundled into v1 for development convenience and kept there to avoid a
// schema reset. The v12/v13 migrations remain as no-ops for existing installs
// that upgrade from an older branch. See v12/v13 for the actual DDL that newer
// installs skip via IF NOT EXISTS.
//
// Each migration runs in a single transaction, so statements that Postgres
// forbids inside a transaction (notably `CREATE INDEX CONCURRENTLY`) cannot be
// used here. Build such indexes the ordinary, transaction-safe way, or stage
// them as a dedicated out-of-band operational step.

// Arbitrary but stable key for the migration advisory lock ("gitlawb_" bytes).
const MIGRATION_ADVISORY_LOCK: i64 = 0x6769_746C_6177_625F;

const MIGRATION_V1_NAME: &str = "initial_schema";

struct Migration {
    version: i64,
    name: &'static str,
    stmts: &'static [&'static str],
}

const MIGRATIONS: &[Migration] = &[
    Migration {
    version: 1,
    name: MIGRATION_V1_NAME,
    stmts: &[
            r#"CREATE TABLE IF NOT EXISTS repos (
                id             TEXT NOT NULL PRIMARY KEY,
                name           TEXT NOT NULL,
                owner_did      TEXT NOT NULL,
                description    TEXT,
                is_public      BOOLEAN NOT NULL DEFAULT TRUE,
                default_branch TEXT NOT NULL DEFAULT 'main',
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL,
                disk_path      TEXT NOT NULL UNIQUE,
                forked_from    TEXT
            )"#,
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS forked_from TEXT",
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS machine_id TEXT",
            "CREATE INDEX IF NOT EXISTS idx_repos_owner ON repos(owner_did)",
            "CREATE INDEX IF NOT EXISTS idx_repos_name  ON repos(name)",
            "CREATE INDEX IF NOT EXISTS idx_repos_owner_short_name ON repos ((split_part(owner_did, ':', -1)), name)",
            "CREATE INDEX IF NOT EXISTS idx_repos_updated_at ON repos (updated_at DESC)",
            r#"CREATE TABLE IF NOT EXISTS agents (
                did           TEXT NOT NULL PRIMARY KEY,
                trust_score   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                capabilities  TEXT NOT NULL DEFAULT '[]',
                registered_at TEXT NOT NULL,
                last_seen     TEXT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS push_events (
                id           TEXT NOT NULL PRIMARY KEY,
                agent_did    TEXT NOT NULL,
                repo_id      TEXT NOT NULL,
                commit_hash  TEXT NOT NULL,
                object_count INTEGER NOT NULL DEFAULT 0,
                pushed_at    TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_push_events_agent ON push_events(agent_did)",
            r#"CREATE TABLE IF NOT EXISTS ref_certificates (
                id          TEXT NOT NULL PRIMARY KEY,
                repo_id     TEXT NOT NULL,
                ref_name    TEXT NOT NULL,
                old_sha     TEXT NOT NULL,
                new_sha     TEXT NOT NULL,
                pusher_did  TEXT NOT NULL,
                node_did    TEXT NOT NULL,
                signature   TEXT NOT NULL,
                issued_at   TEXT NOT NULL,
                seq         BIGINT NOT NULL DEFAULT 1,
                prev        TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
                pusher_sig  TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_ref_certs_repo ON ref_certificates(repo_id)",
            r#"CREATE TABLE IF NOT EXISTS peers (
                did          TEXT NOT NULL PRIMARY KEY,
                http_url     TEXT NOT NULL,
                last_seen    TEXT,
                last_ping_ok BOOLEAN NOT NULL DEFAULT FALSE,
                announced_at TEXT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS pinned_cids (
                sha256_hex TEXT NOT NULL PRIMARY KEY,
                cid        TEXT NOT NULL,
                pinned_at  TEXT NOT NULL,
                pinata_cid TEXT
            )"#,
            // Migrate existing installs that lack the pinata_cid column
            "ALTER TABLE pinned_cids ADD COLUMN IF NOT EXISTS pinata_cid TEXT",
            r#"CREATE TABLE IF NOT EXISTS branch_cids (
                repo       TEXT NOT NULL,
                ref_name   TEXT NOT NULL,
                sha        TEXT NOT NULL,
                cid        TEXT NOT NULL,
                node_did   TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (repo, ref_name)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS sync_queue (
                id           TEXT NOT NULL PRIMARY KEY,
                repo         TEXT NOT NULL,
                node_did     TEXT NOT NULL,
                ref_name     TEXT NOT NULL,
                new_sha      TEXT NOT NULL,
                cid          TEXT,
                status       TEXT NOT NULL DEFAULT 'pending',
                enqueued_at  TEXT NOT NULL,
                processed_at TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_sync_queue_status ON sync_queue(status)",
            r#"CREATE TABLE IF NOT EXISTS received_ref_updates (
                id          TEXT NOT NULL PRIMARY KEY,
                node_did    TEXT NOT NULL,
                pusher_did  TEXT NOT NULL,
                repo        TEXT NOT NULL,
                ref_name    TEXT NOT NULL,
                old_sha     TEXT NOT NULL,
                new_sha     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                cert_id     TEXT,
                received_at TEXT NOT NULL,
                from_peer   TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_ref_updates_repo ON received_ref_updates(repo)",
            "CREATE INDEX IF NOT EXISTS idx_ref_updates_ts  ON received_ref_updates(timestamp DESC)",
            r#"CREATE TABLE IF NOT EXISTS pull_requests (
                id            TEXT NOT NULL PRIMARY KEY,
                repo_id       TEXT NOT NULL,
                number        BIGINT NOT NULL,
                title         TEXT NOT NULL,
                body          TEXT,
                author_did    TEXT NOT NULL,
                source_branch TEXT NOT NULL,
                target_branch TEXT NOT NULL DEFAULT 'main',
                status        TEXT NOT NULL DEFAULT 'open',
                merged_by_did TEXT,
                merged_at     TEXT,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                UNIQUE(repo_id, number)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_prs_repo ON pull_requests(repo_id)",
            r#"CREATE TABLE IF NOT EXISTS pr_reviews (
                id           TEXT NOT NULL PRIMARY KEY,
                pr_id        TEXT NOT NULL,
                reviewer_did TEXT NOT NULL,
                body         TEXT,
                status       TEXT NOT NULL,
                created_at   TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_pr_reviews_pr ON pr_reviews(pr_id)",
            r#"CREATE TABLE IF NOT EXISTS webhooks (
                id             TEXT NOT NULL PRIMARY KEY,
                repo_id        TEXT NOT NULL,
                url            TEXT NOT NULL,
                secret         TEXT,
                events         TEXT NOT NULL DEFAULT '["*"]',
                created_by_did TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                active         BOOLEAN NOT NULL DEFAULT TRUE
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_webhooks_repo ON webhooks(repo_id)",
            r#"CREATE TABLE IF NOT EXISTS agent_tasks (
                id            TEXT NOT NULL PRIMARY KEY,
                repo_id       TEXT,
                kind          TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                delegator_did TEXT NOT NULL,
                assignee_did  TEXT,
                capability    TEXT NOT NULL,
                ucan_token    TEXT,
                payload       TEXT,
                result        TEXT,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                deadline      TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_status    ON agent_tasks(status)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_delegator ON agent_tasks(delegator_did)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_assignee  ON agent_tasks(assignee_did)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_repo      ON agent_tasks(repo_id)",
            // ── Arweave permanent anchors ────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS arweave_anchors (
                id              TEXT NOT NULL PRIMARY KEY,
                repo            TEXT NOT NULL,
                owner_did       TEXT NOT NULL,
                ref_name        TEXT NOT NULL,
                old_sha         TEXT NOT NULL,
                new_sha         TEXT NOT NULL,
                cid             TEXT,
                arweave_tx_id   TEXT NOT NULL,
                node_did        TEXT NOT NULL,
                anchored_at     TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'pending',
                deadline_height BIGINT,
                receipt_sig     TEXT,
                cert_id         TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_arweave_anchors_repo    ON arweave_anchors(repo)",
            "CREATE INDEX IF NOT EXISTS idx_arweave_anchors_new_sha ON arweave_anchors(new_sha)",
            // ── Branch protection ────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS protected_branches (
                id         TEXT NOT NULL PRIMARY KEY,
                repo_id    TEXT NOT NULL,
                branch     TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(repo_id, branch)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_protected_branches_repo ON protected_branches(repo_id)",
            // ── Repo stars ──────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS repo_stars (
                id         TEXT NOT NULL PRIMARY KEY,
                repo_id    TEXT NOT NULL,
                agent_did  TEXT NOT NULL,
                starred_at TEXT NOT NULL,
                UNIQUE(repo_id, agent_did)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_repo_stars_repo  ON repo_stars(repo_id)",
            "CREATE INDEX IF NOT EXISTS idx_repo_stars_agent ON repo_stars(agent_did)",
            // ── Repo replicas (network resilience) ──────────────────────────
            // Tracks which nodes are hosting a replica of a repo. Populated
            // when a replica node calls PUT /api/v1/repos/{owner}/{repo}/replicas
            // on the origin. Public via GET on the same path — anyone can see
            // how many nodes are mirroring a given repo.
            r#"CREATE TABLE IF NOT EXISTS repo_replicas (
                id            TEXT NOT NULL PRIMARY KEY,
                repo_id       TEXT NOT NULL,
                replica_did   TEXT NOT NULL,
                replica_url   TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                UNIQUE(repo_id, replica_did)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_repo_replicas_repo ON repo_replicas(repo_id)",
            "CREATE INDEX IF NOT EXISTS idx_repo_replicas_did  ON repo_replicas(replica_did)",
            // ── PR comments ─────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS pr_comments (
                id         TEXT NOT NULL PRIMARY KEY,
                pr_id      TEXT NOT NULL,
                author_did TEXT NOT NULL,
                body       TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_pr_comments_pr ON pr_comments(pr_id)",
            // ── Issue comments ──────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS issue_comments (
                id         TEXT NOT NULL PRIMARY KEY,
                issue_id   TEXT NOT NULL,
                author_did TEXT NOT NULL,
                body       TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_issue_comments_issue ON issue_comments(issue_id)",
            // ── Repo labels ─────────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS repo_labels (
                id         TEXT NOT NULL PRIMARY KEY,
                repo_id    TEXT NOT NULL,
                label      TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(repo_id, label)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_repo_labels_repo ON repo_labels(repo_id)",
            // ── Bounties ──────────────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS bounties (
                id              TEXT NOT NULL PRIMARY KEY,
                repo_owner      TEXT NOT NULL,
                repo_name       TEXT NOT NULL,
                issue_id        TEXT,
                title           TEXT NOT NULL,
                amount          BIGINT NOT NULL,
                creator_did     TEXT NOT NULL,
                claimant_did    TEXT,
                claimant_wallet TEXT,
                pr_id           TEXT,
                status          TEXT NOT NULL DEFAULT 'open',
                created_at      TEXT NOT NULL,
                claimed_at      TEXT,
                submitted_at    TEXT,
                completed_at    TEXT,
                deadline_secs   BIGINT NOT NULL DEFAULT 604800,
                tx_hash         TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_bounties_status ON bounties(status)",
            "CREATE INDEX IF NOT EXISTS idx_bounties_repo ON bounties(repo_owner, repo_name)",
            "CREATE INDEX IF NOT EXISTS idx_bounties_claimant ON bounties(claimant_did)",
        ],
    },
    Migration {
        version: 2,
        name: "agent_profiles",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS agent_profiles (
                did          TEXT NOT NULL PRIMARY KEY,
                display_name TEXT,
                bio          TEXT,
                avatar_url   TEXT,
                website      TEXT,
                socials      TEXT,
                profile_cid  TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )"#,
        ],
    },
    Migration {
        version: 3,
        name: "visibility_rules",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS visibility_rules (
                id          TEXT NOT NULL PRIMARY KEY,
                repo_id     TEXT NOT NULL,
                path_glob   TEXT NOT NULL,
                mode        TEXT NOT NULL,
                reader_dids TEXT NOT NULL,
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                UNIQUE(repo_id, path_glob)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_visibility_rules_repo ON visibility_rules(repo_id)",
        ],
    },
    Migration {
        version: 4,
        name: "encrypted_blobs",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS encrypted_blobs (
                repo_id    TEXT NOT NULL,
                oid        TEXT NOT NULL,
                cid        TEXT NOT NULL,
                recipients TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (repo_id, oid)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_encrypted_blobs_repo ON encrypted_blobs(repo_id)",
        ],
    },
    Migration {
        version: 5,
        name: "encrypted_blobs_blind_recipients",
        stmts: &[
            // Replace the cleartext recipient DID list with an opaque, node-keyed
            // tag used only to detect a recipient-set change. Existing rows get an
            // empty tag and are re-sealed on the next push.
            "ALTER TABLE encrypted_blobs DROP COLUMN IF EXISTS recipients",
            "ALTER TABLE encrypted_blobs ADD COLUMN IF NOT EXISTS recipients_tag TEXT NOT NULL DEFAULT ''",
        ],
    },
    Migration {
        version: 6,
        name: "agent_retirement",
        stmts: &[
            // Agent lifecycle status for issue #29. `active` is the default;
            // the key holder can self-deregister to `revoked` (terminal).
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS deactivated_at TEXT",
        ],
    },
    Migration {
        version: 7,
        name: "repo_owner_dedup_key_didkey_aware",
        stmts: &[
            // The dedup grouping key moved from the last `:` segment to a
            // did:key-aware key (strip `did:key:`, leave any other DID method
            // whole) so `did:key:X` and `did:gitlawb:X` no longer collapse. Swap
            // the index that backs it: drop the last-segment one from v1 and build
            // the matching expression index. The CASE must stay byte-for-byte in
            // sync with DEDUP_CTE / count_repos_deduped or Postgres won't use it.
            "DROP INDEX IF EXISTS idx_repos_owner_short_name",
            // Keep byte-identical to OWNER_KEY_CASE_SQL so Postgres uses the index.
            "CREATE INDEX IF NOT EXISTS idx_repos_owner_key_name ON repos ((CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END), name)",
        ],
    },
    Migration {
        version: 8,
        name: "icaptcha_consumed_proofs",
        stmts: &[
            // Single-use ledger for iCaptcha proof ids (jti). A proof may be
            // spent once per gated action; replays are rejected until the row
            // is swept after the proof's own expiry. `expires_at` is the
            // proof's unix-seconds exp, used for cleanup.
            r#"CREATE TABLE IF NOT EXISTS icaptcha_consumed_proofs (
                jti        TEXT   NOT NULL PRIMARY KEY,
                expires_at BIGINT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_icaptcha_consumed_expires ON icaptcha_consumed_proofs(expires_at)",
        ],
    },
    Migration {
        version: 9,
        name: "icaptcha_propagation",
        stmts: &[
            // The iCaptcha proof presented at repo creation, kept so it can travel
            // with the repo when it propagates to peers. A mirroring node that
            // enforces iCaptcha re-verifies this token offline before admitting the
            // mirror (see `icaptcha::admit_mirror`). One row per repo (its creation
            // proof); rows are best-effort and absent for repos created with the
            // gate off/in shadow or before this migration.
            r#"CREATE TABLE IF NOT EXISTS repo_icaptcha_proofs (
                repo_id     TEXT   NOT NULL PRIMARY KEY,
                proof_token TEXT   NOT NULL,
                sub_did     TEXT   NOT NULL,
                level       INTEGER NOT NULL,
                jti         TEXT   NOT NULL,
                exp         BIGINT NOT NULL,
                created_at  TEXT   NOT NULL
            )"#,
            // A mirror admitted by a node that could not validate its proof is
            // quarantined: kept on disk but hidden from serve/clone and listings
            // until an operator releases it. Default false; only the mirror
            // admission path sets it true.
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS quarantined BOOLEAN NOT NULL DEFAULT FALSE",
        ],
    },
    Migration {
        version: 10,
        name: "ref_cert_unique_per_ref",
        stmts: &[
            // Dedup before the unique index: keep only the most recent row per
            // (repo_id, ref_name) so the CREATE UNIQUE INDEX below does not fail
            // on existing databases that accumulated duplicates.
            r#"DELETE FROM ref_certificates
               WHERE id IN (
                   SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (
                            PARTITION BY repo_id, ref_name ORDER BY issued_at DESC, id DESC
                        ) AS rn
                       FROM ref_certificates
                   ) dups WHERE dups.rn > 1
               )"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ref_certs_repo_ref ON ref_certificates(repo_id, ref_name)",
        ],
    },
    Migration {
        version: 11,
        name: "ref_update_owner_did",
        stmts: &[
            // Index deferred — the feed gate (#144) does not read owner_did yet.
            "ALTER TABLE received_ref_updates ADD COLUMN IF NOT EXISTS owner_did TEXT",
        ],
    },
    Migration {
        version: 12,
        name: "arweave_anchor_v2_and_cert_chain",
        stmts: &[
            "ALTER TABLE ref_certificates ADD COLUMN IF NOT EXISTS seq BIGINT NOT NULL DEFAULT 1",
            "ALTER TABLE ref_certificates ADD COLUMN IF NOT EXISTS prev TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'",
            "ALTER TABLE ref_certificates ADD COLUMN IF NOT EXISTS pusher_sig TEXT",
            "ALTER TABLE arweave_anchors ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'",
            "ALTER TABLE arweave_anchors ADD COLUMN IF NOT EXISTS deadline_height BIGINT",
            "ALTER TABLE arweave_anchors ADD COLUMN IF NOT EXISTS receipt_sig TEXT",
            "ALTER TABLE arweave_anchors ADD COLUMN IF NOT EXISTS cert_id TEXT",
            // Rename irys_tx_id → arweave_tx_id only if the old column still exists
            // (fresh databases created by v1 already use arweave_tx_id).
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='arweave_anchors' AND column_name='irys_tx_id') THEN ALTER TABLE arweave_anchors RENAME COLUMN irys_tx_id TO arweave_tx_id; END IF; END $$",
            "ALTER TABLE arweave_anchors DROP COLUMN IF EXISTS arweave_url",
        ],
    },
    Migration {
        version: 13,
        name: "append_only_certs_and_pusher_proof",
        stmts: &[
            // Backfill: assign sequential seq values to existing certificates
            // before creating the unique index. Migrations v10/v11 may have left
            // multiple rows per repo (from different refs) all at seq = 1.
            // The prev column is intentionally NOT backfilled here: chain
            // verification in verify_anchor computes expected_prev dynamically
            // from the predecessor's 7 canonical fields (repo_id, ref, old,
            // new, pusher, node, ts), never reading the DB's prev column.
            // Existing prev values already match what was computed at issuance.
            r#"UPDATE ref_certificates
               SET seq = subq.new_seq
               FROM (
                   SELECT id, ROW_NUMBER() OVER (
                       PARTITION BY repo_id ORDER BY issued_at ASC, id ASC
                   ) AS new_seq
                   FROM ref_certificates
               ) subq
               WHERE ref_certificates.id = subq.id"#,
            // Make cert chain append-only: drop the (repo_id, ref_name) unique index
            // and add a unique constraint on (repo_id, seq) so concurrent pushes
            // cannot collide on the same sequence number.
            "DROP INDEX IF EXISTS idx_ref_certs_repo_ref",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ref_certs_repo_seq ON ref_certificates(repo_id, seq)",
            // Store the full HTTP Signature context so a third party can verify
            // the pusher authorization proof (RFC 9421).
            "ALTER TABLE ref_certificates ADD COLUMN IF NOT EXISTS signature_input TEXT",
            "ALTER TABLE ref_certificates ADD COLUMN IF NOT EXISTS content_digest TEXT",
            "ALTER TABLE ref_certificates ADD COLUMN IF NOT EXISTS request_path TEXT",
        ],
    },
];

// ── Repos ─────────────────────────────────────────────────────────────────────

pub(crate) fn normalize_owner_key(did: &str) -> &str {
    match did.strip_prefix("did:key:") {
        Some(rest) if !rest.contains(':') => rest,
        _ => did,
    }
}

/// SQL CASE expression byte-identical to `normalize_owner_key`. All queries that
/// filter or group by owner key use this const so the Rust and SQL sides cannot
/// drift apart. If you change `normalize_owner_key`, update this const too.
const OWNER_KEY_CASE_SQL: &str = "CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END";

#[cfg(test)]
mod normalize_owner_key_tests {
    use super::normalize_owner_key;

    // Boundary set matching the SQL CASE: did:key short/full, empty residual,
    // did:key:z:extra, non-key, bare, empty, uppercase.
    #[test]
    fn strips_did_key_prefix() {
        assert_eq!(normalize_owner_key("did:key:z6Mkfoo"), "z6Mkfoo");
    }

    #[test]
    fn keeps_full_did_key_unchanged_when_not_a_prefix() {
        assert_eq!(normalize_owner_key("z6Mkfoo"), "z6Mkfoo");
    }

    #[test]
    fn leaves_non_key_did_intact() {
        assert_eq!(
            normalize_owner_key("did:gitlawb:z6Mkfoo"),
            "did:gitlawb:z6Mkfoo"
        );
    }

    #[test]
    fn leaves_web_did_intact() {
        assert_eq!(
            normalize_owner_key("did:web:example.com:alice"),
            "did:web:example.com:alice"
        );
    }

    #[test]
    fn does_not_strip_did_key_with_extra_colon() {
        // did:key:did:gitlawb:z6... — the remainder contains ':', so it's left whole.
        assert_eq!(
            normalize_owner_key("did:key:did:gitlawb:z6Mkfoo"),
            "did:key:did:gitlawb:z6Mkfoo"
        );
    }

    #[test]
    fn empty_string_returns_empty() {
        assert_eq!(normalize_owner_key(""), "");
    }

    #[test]
    fn bare_did_key_colon_becomes_empty() {
        // did:key: with nothing after still has the prefix stripped.
        assert_eq!(normalize_owner_key("did:key:"), "");
    }

    #[test]
    fn uppercase_prefix_is_untouched() {
        assert_eq!(normalize_owner_key("DID:KEY:z6Mkfoo"), "DID:KEY:z6Mkfoo");
    }

    #[test]
    fn strips_did_key_even_with_trailing_slash() {
        // did:key:z6Mkfoo/extra has no ':' in the remainder, so it strips.
        assert_eq!(
            normalize_owner_key("did:key:z6Mkfoo/extra"),
            "z6Mkfoo/extra"
        );
    }
}

impl Db {
    pub async fn create_repo(&self, repo: &RepoRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch,
                                created_at, updated_at, disk_path, forked_from, machine_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&repo.id)
        .bind(&repo.name)
        .bind(&repo.owner_did)
        .bind(&repo.description)
        .bind(repo.is_public)
        .bind(&repo.default_branch)
        .bind(repo.created_at.to_rfc3339())
        .bind(repo.updated_at.to_rfc3339())
        .bind(&repo.disk_path)
        .bind(&repo.forked_from)
        .bind(&repo.machine_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Register a mirrored repo from a peer in the local DB so git smart HTTP can serve it.
    /// Uses INSERT OR IGNORE (SQLite) / ON CONFLICT DO NOTHING (Postgres) so it's idempotent.
    pub async fn upsert_mirror_repo(
        &self,
        owner_short: &str,
        name: &str,
        disk_path: &str,
        machine_id: Option<&str>,
        quarantined: bool,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{owner_short}/{name}");
        // `quarantined` is set only on first insert (the admission decision).
        // A re-sync (ON CONFLICT) preserves the existing flag — admission runs
        // once, and an operator's later release must not be silently reverted.
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch,
                                created_at, updated_at, disk_path, machine_id, quarantined)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (id) DO UPDATE SET updated_at = $8, disk_path = $9, machine_id = $10",
        )
        .bind(&id)
        .bind(name)
        .bind(owner_short)
        .bind("mirrored from peer")
        .bind(true)
        .bind("main")
        .bind(&now)
        .bind(&now)
        .bind(disk_path)
        .bind(machine_id)
        .bind(quarantined)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_repo(&self, owner_did: &str, name: &str) -> Result<Option<RepoRecord>> {
        // Normalize owner_did to its did:key short form, mirroring did_matches and
        // the DEDUP_CTE's owner-key CASE: strip `did:key:` only when the remainder
        // is a bare key id (no further `:`). This keeps `did:key:z...` and bare
        // `z...` interchangeable while `did:gitlawb:z...` / `did:web:z...` stay
        // distinct — the old LIKE '%:' || $1 || '%' was too broad (issue #124 P2).
        let owner_key = normalize_owner_key(owner_did);
        let sql = format!(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos
              WHERE ({key}) = $1
                AND name = $2
             -- Prefer canonical rows (UUID id, no slash) over mirror rows (slash id).
             -- Mirror rows are inserted by upsert_mirror_repo with is_public=true and
             -- no visibility rules; using them for visibility checks would bypass the
             -- canonical row's gate (issue #124).
             ORDER BY CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END,
                      created_at ASC, id ASC
             LIMIT 1",
            key = OWNER_KEY_CASE_SQL
        );
        let row = sqlx::query(&sql)
            .bind(owner_key)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(row_to_repo))
    }

    #[allow(dead_code)]
    pub async fn list_repos(&self, owner_did: &str) -> Result<Vec<RepoRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos WHERE owner_did = $1 ORDER BY updated_at DESC",
        )
        .bind(owner_did)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// Raw list of every repo row — NOT deduped (a mirror row and its canonical
    /// row both appear) and without stars. For enumeration callers that must see
    /// every physical row (e.g. the IPFS object scan in `api::ipfs`), not for
    /// listing surfaces. Listing surfaces dedupe via `list_all_repos_deduped` or
    /// `list_all_repos_with_stars` + `dedupe_canonical_repos`.
    pub async fn list_all_repos(&self) -> Result<Vec<RepoRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos ORDER BY updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    pub async fn list_all_repos_with_stars(&self) -> Result<Vec<(RepoRecord, i64)>> {
        let rows = sqlx::query(
            "SELECT r.id, r.name, r.owner_did, r.description, r.is_public, r.default_branch,
                    r.created_at, r.updated_at, r.disk_path, r.forked_from, r.machine_id,
                    COALESCE(s.cnt, 0) AS star_count
             FROM repos r
             LEFT JOIN (SELECT repo_id, COUNT(*) AS cnt FROM repo_stars GROUP BY repo_id) s
               ON s.repo_id = r.id
             WHERE r.quarantined = FALSE
             ORDER BY r.updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let stars: i64 = r.get("star_count");
                (row_to_repo(r), stars)
            })
            .collect())
    }

    /// Shared dedup CTE: collapses the mirror row and the canonical row of one
    /// logical repo into a single survivor. `$1` is an optional owner filter
    /// (NULL = all rows). Grouping collapses on a did:key-aware owner key: strip a
    /// `did:key:` prefix (8 chars, so `substr(owner_did, 9)`) only when the
    /// remainder is a bare id with no `:`, otherwise keep the full DID. That is the
    /// exact normalization in `crate::api::did_matches`, so `did:key:X` and a bare
    /// `X` collapse while distinct DID methods (`did:gitlawb:X`) never merge. The
    /// CASE is repeated verbatim in `count_repos_deduped` and the v7 index and must
    /// stay byte-identical or Postgres stops using the index.
    /// The canonical row wins (mirror rows carry a slash-form `id` written only by
    /// `upsert_mirror_repo`), ties broken by earliest `created_at` then `id` so a
    /// full tie still picks a deterministic survivor. `list_all_repos_deduped_with_stars`,
    /// `list_all_repos_deduped`, and the marker logic in
    /// `crate::api::repos::dedupe_canonical_repos` must stay in sync.
    fn dedup_cte() -> String {
        format!(
            "WITH deduped AS (
                 SELECT DISTINCT ON ({key}, name)
                     id, name, owner_did, description, is_public, default_branch,
                     created_at,
                     -- group MAX, not the canonical row's own value: pushes that
                     -- arrive via gossip touch only the mirror row, so the
                     -- canonical updated_at goes stale
                     MAX(updated_at) OVER (
                         PARTITION BY {key}, name
                     ) AS updated_at,
                     disk_path, forked_from, machine_id
                 FROM repos
                 -- Match the owner filter on the same did:key-aware owner key the
                 -- dedup groups on, so a full did:key: form matches a bare-owner
                 -- mirror row (and vice versa) exactly as crate::api::did_matches
                 -- does. Callers bind the already-normalized key ($1).
                 -- Quarantined mirrors (admitted but unvalidated by the iCaptcha
                 -- propagation gate) are withheld from every listing surface.
                 WHERE quarantined = FALSE AND ($1::text IS NULL OR ({key}) = $1)
                 ORDER BY {key}, name,
                     -- mirror rows carry a slash-form id (\"{{owner_short}}/{{name}}\"),
                     -- written only by upsert_mirror_repo; canonical ids are UUIDs.
                     -- Rank canonical (no slash) ahead of the mirror in each group,
                     -- keyed on the structural id, not the user-settable description.
                     CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END,
                     created_at ASC, id ASC
             )",
            key = OWNER_KEY_CASE_SQL
        )
    }

    /// All repos with star counts, mirror-deduplicated via `DEDUP_CTE` and
    /// ordered newest-first, optionally filtered to one owner. Returns the full
    /// set (no SQL pagination): the listing surface filters by per-caller `"/"`
    /// visibility in Rust and paginates after, so neither the page nor the count
    /// leaks a repo the caller may not read (#97).
    ///
    /// The owner filter is normalized to its did:key short form before binding so
    /// the SQL predicate matches `crate::api::did_matches`: a full `did:key:z...`
    /// query and a bare-owner mirror row (`z...`) match each other, and vice
    /// versa. A non-key DID (still has a `:` after the prefix) is left intact and
    /// only matches exactly.
    pub async fn list_all_repos_deduped_with_stars(
        &self,
        owner_filter: Option<&str>,
    ) -> Result<Vec<(RepoRecord, i64)>> {
        // Mirror did_matches: strip `did:key:` only when the remainder is a bare
        // key id (no further `:`). The DEDUP_CTE applies the identical CASE to
        // owner_did, so the two compare on the same normalized key.
        let owner_key = owner_filter.map(normalize_owner_key);
        let sql = format!(
            "{}
             SELECT
                 d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id,
                 COALESCE(s.cnt, 0) AS star_count
             FROM deduped d
             LEFT JOIN (
                 SELECT repo_id, COUNT(*) AS cnt FROM repo_stars GROUP BY repo_id
             ) s ON s.repo_id = d.id
             ORDER BY d.updated_at DESC",
            Self::dedup_cte()
        );
        let rows = sqlx::query(&sql)
            .bind(owner_key)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let stars: i64 = r.get("star_count");
                (row_to_repo(r), stars)
            })
            .collect())
    }

    /// Deduped repo list (no stars, no paging) for the unfiltered read surfaces
    /// (GraphQL `repos`). One logical repo per mirror+canonical group, ordered by
    /// the group's most recent activity. Shares `dedup_cte()` with the paged path so
    /// the dedup rule cannot drift; binds a NULL owner filter (all rows).
    pub async fn list_all_repos_deduped(&self) -> Result<Vec<RepoRecord>> {
        let sql = format!(
            "{}
             SELECT d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id
             FROM deduped d
             ORDER BY d.updated_at DESC",
            Self::dedup_cte()
        );
        let rows = sqlx::query(&sql)
            .bind(None::<&str>)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// Repos currently quarantined (admitted as mirrors but withheld from every
    /// listing surface). `list_all_repos_deduped` excludes these (its `DEDUP_CTE`
    /// filters `quarantined = FALSE`), so a gate that resolves a slug against the
    /// deduped set must also match against these and fail closed, or a quarantined
    /// repo's row is misclassified as remote/gossip-only and served.
    pub async fn list_quarantined_repos(&self) -> Result<Vec<RepoRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos WHERE quarantined = TRUE",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// Count of distinct logical repos (mirror + canonical collapsed). Uses the
    /// same did:key-aware owner-key grouping as `DEDUP_CTE` (the CASE must stay
    /// byte-identical); the marker/tiebreak only decide which row would survive,
    /// not the group count, so they are not needed here.
    ///
    /// `/api/v1/stats` no longer calls this — it counts only anonymously-listable
    /// repos to avoid a count oracle (#104). Retained as the tested reference
    /// implementation of the unfiltered dedup count: its tests pin the `DEDUP_CTE`
    /// CASE that the live list paths depend on. Allowed dead outside tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn count_repos_deduped(&self) -> Result<i64> {
        let sql = format!(
            "SELECT COUNT(DISTINCT ({key}, name)) AS cnt FROM repos",
            key = OWNER_KEY_CASE_SQL
        );
        let row = sqlx::query(&sql).fetch_one(&self.pool).await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    pub async fn touch_repo(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE repos SET updated_at = $1 WHERE id = $2")
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Agents / Trust ────────────────────────────────────────────────────────────

/// Map an `agents` row (selected with the status columns) into an `AgentRow`.
fn row_to_agent(r: &sqlx::postgres::PgRow) -> AgentRow {
    AgentRow {
        did: r.get("did"),
        trust_score: r.get("trust_score"),
        capabilities: serde_json::from_str(r.get::<&str, _>("capabilities")).unwrap_or_default(),
        registered_at: r.get("registered_at"),
        last_seen: r.get("last_seen"),
        status: r.get("status"),
    }
}

/// Reduce a trust-ranked agent list to what discovery should surface: only
/// `active` agents, optionally narrowed to those advertising `capability`.
/// Revoked agents are dropped so an orphaned DID can never win capability
/// routing. Input order is preserved, so an already trust-sorted list stays
/// active-first.
fn filter_discoverable(agents: Vec<AgentRow>, capability: Option<&str>) -> Vec<AgentRow> {
    agents
        .into_iter()
        .filter(|a| a.status == "active")
        .filter(|a| match capability {
            Some(cap) => a.capabilities.iter().any(|c| c == cap),
            None => true,
        })
        .collect()
}

impl Db {
    pub async fn register_agent(&self, did: &str, capabilities: &[String]) -> Result<()> {
        let caps = serde_json::to_string(capabilities)?;
        let now = Utc::now().to_rfc3339();
        // The ON CONFLICT clause deliberately updates only `last_seen` and
        // never touches `status`. That makes revocation terminal: re-registering
        // a `revoked` DID does not bring it back to `active` (issue #29).
        sqlx::query(
            "INSERT INTO agents (did, trust_score, capabilities, registered_at)
             VALUES ($1, 0.0, $2, $3)
             ON CONFLICT(did) DO UPDATE SET last_seen = $3",
        )
        .bind(did)
        .bind(&caps)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically consume an iCaptcha proof id (`jti`). Returns `Ok(true)` if it
    /// was newly recorded (the proof may be used), `Ok(false)` if it was already
    /// spent (a replay). `expires_at` is the proof's unix-seconds `exp`, kept so
    /// the ledger row can be swept once the proof can no longer be valid.
    pub async fn consume_proof_jti(&self, jti: &str, expires_at: i64) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO icaptcha_consumed_proofs (jti, expires_at)
             VALUES ($1, $2)
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete consumed-proof rows whose proof has expired. Returns rows removed.
    pub async fn sweep_expired_proofs(&self, now: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM icaptcha_consumed_proofs WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Persist the iCaptcha proof a repo was created with so it can travel with
    /// the repo when it propagates (see `icaptcha::admit_mirror`). Idempotent:
    /// re-recording the same repo's proof overwrites it.
    pub async fn record_repo_proof(
        &self,
        repo_id: &str,
        proof_token: &str,
        sub_did: &str,
        level: i32,
        jti: &str,
        exp: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO repo_icaptcha_proofs (repo_id, proof_token, sub_did, level, jti, exp, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (repo_id) DO UPDATE SET
                 proof_token = $2, sub_did = $3, level = $4, jti = $5, exp = $6, created_at = $7",
        )
        .bind(repo_id)
        .bind(proof_token)
        .bind(sub_did)
        .bind(level)
        .bind(jti)
        .bind(exp)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The raw proof token recorded for a repo, if any.
    pub async fn get_repo_proof_token(&self, repo_id: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT proof_token FROM repo_icaptcha_proofs WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("proof_token")))
    }

    /// Whether a repo row is quarantined (admitted as a mirror but withheld from
    /// serve/clone and listings pending operator review).
    pub async fn is_repo_quarantined(&self, repo_id: &str) -> Result<bool> {
        let row = sqlx::query("SELECT quarantined FROM repos WHERE id = $1")
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row
            .map(|r| r.get::<bool, _>("quarantined"))
            .unwrap_or(false))
    }

    /// Set or clear a repo's quarantine flag. Returns the number of rows touched
    /// (0 if no such repo). Backs the (deferred) operator release surface; the
    /// admission path writes the flag via `upsert_mirror_repo`. Allowed dead
    /// outside tests until the operator endpoint lands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn set_repo_quarantine(&self, repo_id: &str, quarantined: bool) -> Result<u64> {
        let result = sqlx::query("UPDATE repos SET quarantined = $1 WHERE id = $2")
            .bind(quarantined)
            .bind(repo_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Repo ids currently quarantined, for operator review. Allowed dead outside
    /// tests until the operator endpoint lands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn list_quarantined_repo_ids(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT id FROM repos WHERE quarantined = TRUE ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("id")).collect())
    }

    pub async fn get_trust_score(&self, agent_did: &str) -> Result<f64> {
        let row = sqlx::query("SELECT trust_score FROM agents WHERE did = $1")
            .bind(agent_did)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get::<f64, _>("trust_score")).unwrap_or(0.0))
    }

    /// Update an EXISTING agent's trust score; a no-op for unregistered DIDs.
    /// Deliberately never inserts: the only path into the agents table is
    /// `register_agent`, which sits behind the iCaptcha gate on /api/register.
    /// This used to be an upsert, which let any authenticated push/issue/PR
    /// re-create a deregistered DID's row with a fresh `registered_at`,
    /// bypassing the registration gate entirely.
    pub async fn update_trust_score(&self, agent_did: &str, score: f64) -> Result<()> {
        sqlx::query("UPDATE agents SET trust_score = $2 WHERE did = $1")
            .bind(agent_did)
            .bind(score)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_push(
        &self,
        agent_did: &str,
        repo_id: &str,
        commit_hash: &str,
        object_count: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO push_events (id, agent_did, repo_id, commit_hash, object_count, pushed_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(agent_did)
        .bind(repo_id)
        .bind(commit_hash)
        .bind(object_count)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_push_count(&self, agent_did: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM push_events WHERE agent_did = $1")
            .bind(agent_did)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    pub async fn count_agents(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM agents")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    pub async fn list_agents(&self, capability: Option<&str>) -> Result<Vec<AgentRow>> {
        let rows = sqlx::query(
            "SELECT did, trust_score, capabilities, registered_at, last_seen, status \
             FROM agents ORDER BY trust_score DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let agents: Vec<AgentRow> = rows.iter().map(row_to_agent).collect();

        Ok(filter_discoverable(agents, capability))
    }

    pub async fn get_agent(&self, did: &str) -> Result<Option<AgentRow>> {
        let row = sqlx::query(
            "SELECT did, trust_score, capabilities, registered_at, last_seen, status \
             FROM agents WHERE did = $1",
        )
        .bind(did)
        .fetch_optional(&self.pool)
        .await?;

        // Unfiltered by design: a revoked DID must still resolve so callers
        // can read its `status` and see it is retired.
        Ok(row.as_ref().map(row_to_agent))
    }

    /// Mark an agent `revoked` (terminal self-deregistration, issue #29).
    /// Returns `false` when no such agent exists so the caller can surface a
    /// 404. Revoking an already-revoked agent is idempotent, and a retry keeps
    /// the original `deactivated_at` (COALESCE) rather than overwriting it.
    pub async fn revoke_agent(&self, did: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE agents SET status = 'revoked', \
             deactivated_at = COALESCE(deactivated_at, $2) WHERE did = $1",
        )
        .bind(did)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count_pushes(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM push_events")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }
}

// ── Branch CIDs ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchCid {
    pub repo: String,
    pub ref_name: String,
    pub sha: String,
    pub cid: String,
    pub node_did: String,
    pub updated_at: String,
}

impl Db {
    pub async fn upsert_branch_cid(
        &self,
        repo: &str,
        ref_name: &str,
        sha: &str,
        cid: &str,
        node_did: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO branch_cids (repo, ref_name, sha, cid, node_did, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (repo, ref_name) DO UPDATE
               SET sha = EXCLUDED.sha, cid = EXCLUDED.cid,
                   node_did = EXCLUDED.node_did, updated_at = EXCLUDED.updated_at",
        )
        .bind(repo)
        .bind(ref_name)
        .bind(sha)
        .bind(cid)
        .bind(node_did)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_branch_cids(&self, repo: &str) -> Result<Vec<BranchCid>> {
        let rows = sqlx::query(
            "SELECT repo, ref_name, sha, cid, node_did, updated_at
             FROM branch_cids WHERE repo = $1 ORDER BY ref_name",
        )
        .bind(repo)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| BranchCid {
                repo: r.get("repo"),
                ref_name: r.get("ref_name"),
                sha: r.get("sha"),
                cid: r.get("cid"),
                node_did: r.get("node_did"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }
}

// ── Sync Queue ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncQueueItem {
    pub id: String,
    pub repo: String,
    pub node_did: String,
    pub ref_name: String,
    pub new_sha: String,
    pub cid: Option<String>,
    pub status: String,
    pub enqueued_at: String,
}

impl Db {
    pub async fn enqueue_sync(
        &self,
        repo: &str,
        node_did: &str,
        ref_name: &str,
        new_sha: &str,
        cid: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_queue (id, repo, node_did, ref_name, new_sha, cid, status, enqueued_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
             ON CONFLICT DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(repo)
        .bind(node_did)
        .bind(ref_name)
        .bind(new_sha)
        .bind(cid)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn dequeue_pending_syncs(&self, limit: i64) -> Result<Vec<SyncQueueItem>> {
        let rows = sqlx::query(
            "SELECT id, repo, node_did, ref_name, new_sha, cid, status, enqueued_at
             FROM sync_queue WHERE status = 'pending'
             ORDER BY enqueued_at ASC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SyncQueueItem {
                id: r.get("id"),
                repo: r.get("repo"),
                node_did: r.get("node_did"),
                ref_name: r.get("ref_name"),
                new_sha: r.get("new_sha"),
                cid: r.get("cid"),
                status: r.get("status"),
                enqueued_at: r.get("enqueued_at"),
            })
            .collect())
    }

    pub async fn mark_sync_done(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE sync_queue SET status = 'done', processed_at = $1 WHERE id = $2")
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_sync_failed(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE sync_queue SET status = 'failed', processed_at = $1 WHERE id = $2")
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Pull Requests ─────────────────────────────────────────────────────────────

impl Db {
    pub async fn create_pr(&self, pr: &PullRequest) -> Result<()> {
        sqlx::query(
            "INSERT INTO pull_requests
             (id, repo_id, number, title, body, author_did, source_branch, target_branch,
              status, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,$10)",
        )
        .bind(&pr.id)
        .bind(&pr.repo_id)
        .bind(pr.number)
        .bind(&pr.title)
        .bind(&pr.body)
        .bind(&pr.author_did)
        .bind(&pr.source_branch)
        .bind(&pr.target_branch)
        .bind(&pr.created_at)
        .bind(&pr.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn next_pr_number(&self, repo_id: &str) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(number), 0) + 1 AS next FROM pull_requests WHERE repo_id = $1",
        )
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("next"))
    }

    pub async fn list_prs(&self, repo_id: &str) -> Result<Vec<PullRequest>> {
        let rows = sqlx::query(
            "SELECT id,repo_id,number,title,body,author_did,source_branch,target_branch,
                    status,merged_by_did,merged_at,created_at,updated_at
             FROM pull_requests WHERE repo_id=$1 ORDER BY number DESC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_pr).collect())
    }

    pub async fn get_pr(&self, repo_id: &str, number: i64) -> Result<Option<PullRequest>> {
        let row = sqlx::query(
            "SELECT id,repo_id,number,title,body,author_did,source_branch,target_branch,
                    status,merged_by_did,merged_at,created_at,updated_at
             FROM pull_requests WHERE repo_id=$1 AND number=$2",
        )
        .bind(repo_id)
        .bind(number)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_pr))
    }

    pub async fn merge_pr(&self, pr_id: &str, merged_by_did: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE pull_requests
             SET status='merged', merged_by_did=$1, merged_at=$2, updated_at=$2
             WHERE id=$3",
        )
        .bind(merged_by_did)
        .bind(&now)
        .bind(pr_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn close_pr(&self, pr_id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE pull_requests SET status='closed', updated_at=$1 WHERE id=$2")
            .bind(&now)
            .bind(pr_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_pr_review(&self, review: &PrReview) -> Result<()> {
        sqlx::query(
            "INSERT INTO pr_reviews (id,pr_id,reviewer_did,body,status,created_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(&review.id)
        .bind(&review.pr_id)
        .bind(&review.reviewer_did)
        .bind(&review.body)
        .bind(&review.status)
        .bind(&review.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_pr_comment(&self, comment: &PrComment) -> Result<()> {
        sqlx::query(
            "INSERT INTO pr_comments (id,pr_id,author_did,body,created_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&comment.id)
        .bind(&comment.pr_id)
        .bind(&comment.author_did)
        .bind(&comment.body)
        .bind(&comment.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_pr_comments(&self, pr_id: &str) -> Result<Vec<PrComment>> {
        let rows = sqlx::query(
            "SELECT id,pr_id,author_did,body,created_at
             FROM pr_comments WHERE pr_id=$1 ORDER BY created_at ASC",
        )
        .bind(pr_id)
        .fetch_all(&self.pool)
        .await?;
        let mut comments = Vec::new();
        for row in rows {
            comments.push(PrComment {
                id: row.try_get("id")?,
                pr_id: row.try_get("pr_id")?,
                author_did: row.try_get("author_did")?,
                body: row.try_get("body")?,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(comments)
    }

    pub async fn create_issue_comment(&self, comment: &IssueComment) -> Result<()> {
        sqlx::query(
            "INSERT INTO issue_comments (id,issue_id,author_did,body,created_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&comment.id)
        .bind(&comment.issue_id)
        .bind(&comment.author_did)
        .bind(&comment.body)
        .bind(&comment.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_issue_comments(&self, issue_id: &str) -> Result<Vec<IssueComment>> {
        let rows = sqlx::query(
            "SELECT id,issue_id,author_did,body,created_at
             FROM issue_comments WHERE issue_id=$1 ORDER BY created_at ASC",
        )
        .bind(issue_id)
        .fetch_all(&self.pool)
        .await?;
        let mut comments = Vec::new();
        for row in rows {
            comments.push(IssueComment {
                id: row.try_get("id")?,
                issue_id: row.try_get("issue_id")?,
                author_did: row.try_get("author_did")?,
                body: row.try_get("body")?,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(comments)
    }

    pub async fn add_label(&self, repo_id: &str, label: &str) -> Result<bool> {
        let id = format!("{repo_id}:{label}");
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            "INSERT INTO repo_labels (id, repo_id, label, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (repo_id, label) DO NOTHING",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(label)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn remove_label(&self, repo_id: &str, label: &str) -> Result<()> {
        sqlx::query("DELETE FROM repo_labels WHERE repo_id = $1 AND label = $2")
            .bind(repo_id)
            .bind(label)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_labels(&self, repo_id: &str) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT label FROM repo_labels WHERE repo_id = $1 ORDER BY label ASC")
                .bind(repo_id)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .iter()
            .map(|r| r.try_get::<String, _>("label").unwrap_or_default())
            .collect())
    }

    pub async fn list_pr_reviews(&self, pr_id: &str) -> Result<Vec<PrReview>> {
        let rows = sqlx::query(
            "SELECT id,pr_id,reviewer_did,body,status,created_at
             FROM pr_reviews WHERE pr_id=$1 ORDER BY created_at ASC",
        )
        .bind(pr_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PrReview {
                id: r.get("id"),
                pr_id: r.get("pr_id"),
                reviewer_did: r.get("reviewer_did"),
                body: r.get("body"),
                status: r.get("status"),
                created_at: r.get("created_at"),
            })
            .collect())
    }
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

impl Db {
    pub async fn create_webhook(&self, hook: &Webhook) -> Result<()> {
        let events_json = serde_json::to_string(&hook.events)?;
        sqlx::query(
            "INSERT INTO webhooks (id, repo_id, url, secret, events, created_by_did, created_at, active)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&hook.id)
        .bind(&hook.repo_id)
        .bind(&hook.url)
        .bind(&hook.secret)
        .bind(&events_json)
        .bind(&hook.created_by_did)
        .bind(&hook.created_at)
        .bind(hook.active)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_webhooks(&self, repo_id: &str) -> Result<Vec<Webhook>> {
        let rows = sqlx::query(
            "SELECT id, repo_id, url, secret, events, created_by_did, created_at, active
             FROM webhooks WHERE repo_id = $1 ORDER BY created_at ASC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_webhook).collect())
    }

    pub async fn get_webhook(&self, id: &str) -> Result<Option<Webhook>> {
        let row = sqlx::query(
            "SELECT id, repo_id, url, secret, events, created_by_did, created_at, active
             FROM webhooks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_webhook))
    }

    pub async fn delete_webhook(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_webhooks_for_event(
        &self,
        repo_id: &str,
        event: &str,
    ) -> Result<Vec<Webhook>> {
        let all = self.list_webhooks(repo_id).await?;
        Ok(all
            .into_iter()
            .filter(|h| h.active && h.events.iter().any(|e| e == "*" || e == event))
            .collect())
    }
}

// ── Ref Certificates ──────────────────────────────────────────────────────────

impl Db {
    /// Insert a ref certificate (append-only). The unique constraint on
    /// `(repo_id, seq)` prevents duplicate sequence numbers; callers must
    /// handle retry on collision.
    #[allow(dead_code)]
    pub async fn insert_ref_certificate(&self, cert: &RefCertificate) -> Result<RefCertificate> {
        let row = sqlx::query(
            "INSERT INTO ref_certificates
              (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
              RETURNING id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path",
        )
        .bind(&cert.id)
        .bind(&cert.repo_id)
        .bind(&cert.ref_name)
        .bind(&cert.old_sha)
        .bind(&cert.new_sha)
        .bind(&cert.pusher_did)
        .bind(&cert.node_did)
        .bind(&cert.signature)
        .bind(&cert.issued_at)
        .bind(cert.seq)
        .bind(&cert.prev)
        .bind(&cert.pusher_sig)
        .bind(&cert.signature_input)
        .bind(&cert.content_digest)
        .bind(&cert.request_path)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_to_cert(row))
    }

    /// Transaction-scoped variant of [`insert_ref_certificate`].
    /// Uses the same advisory-lock hash for the repo_id so the lock key
    /// stays consistent with [`lock_repo_cert_issuance`].
    pub async fn insert_ref_certificate_tx(
        &self,
        cert: &RefCertificate,
        conn: &mut sqlx::postgres::PgConnection,
    ) -> Result<RefCertificate> {
        let row = sqlx::query(
            "INSERT INTO ref_certificates
              (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
              RETURNING id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path",
        )
        .bind(&cert.id)
        .bind(&cert.repo_id)
        .bind(&cert.ref_name)
        .bind(&cert.old_sha)
        .bind(&cert.new_sha)
        .bind(&cert.pusher_did)
        .bind(&cert.node_did)
        .bind(&cert.signature)
        .bind(&cert.issued_at)
        .bind(cert.seq)
        .bind(&cert.prev)
        .bind(&cert.pusher_sig)
        .bind(&cert.signature_input)
        .bind(&cert.content_digest)
        .bind(&cert.request_path)
        .fetch_one(&mut *conn)
        .await?;
        Ok(row_to_cert(row))
    }

    pub async fn list_ref_certificates(
        &self,
        repo_id: &str,
        limit: i64,
    ) -> Result<Vec<RefCertificate>> {
        // Clamp at the DB boundary so every caller (present and future) stays
        // bounded even if a raw/negative value slips through the handler layer.
        let limit = limit.max(1);
        let rows = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path
              FROM ref_certificates WHERE repo_id = $1 ORDER BY seq DESC, issued_at DESC LIMIT $2",
        )
        .bind(repo_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_cert).collect())
    }

    /// Look up ref certificates whose id starts with the given prefix.
    /// Used by the CLI for short-ID resolution where the caller does not know
    /// the full UUID.  Bounded by `limit` for safety — the caller should pass a
    /// generous cap (e.g. 200) since prefix-matching narrows the result set.
    pub async fn list_ref_certificates_by_prefix(
        &self,
        repo_id: &str,
        prefix: &str,
        limit: i64,
    ) -> Result<Vec<RefCertificate>> {
        let limit = limit.max(1);
        let pattern = format!("{}%", prefix);
        let rows = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path
              FROM ref_certificates WHERE repo_id = $1 AND id LIKE $2 ORDER BY seq DESC, issued_at DESC LIMIT $3",
        )
        .bind(repo_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_cert).collect())
    }

    pub async fn get_ref_certificate(&self, id: &str) -> Result<Option<RefCertificate>> {
        let row = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path
             FROM ref_certificates WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_cert))
    }

    /// Retrieve the most recent certificate for a repo (highest seq).
    pub async fn get_cert_by_seq(&self, repo_id: &str, seq: i64) -> Result<Option<RefCertificate>> {
        let row = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path
             FROM ref_certificates WHERE repo_id = $1 AND seq = $2",
        )
        .bind(repo_id)
        .bind(seq)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_cert))
    }

    #[allow(dead_code)]
    pub async fn get_most_recent_cert(&self, repo_id: &str) -> Result<Option<RefCertificate>> {
        let row = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path
             FROM ref_certificates WHERE repo_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_cert))
    }

    /// Transaction-scoped variant of [`get_most_recent_cert`].
    pub async fn get_most_recent_cert_tx(
        &self,
        repo_id: &str,
        conn: &mut sqlx::postgres::PgConnection,
    ) -> Result<Option<RefCertificate>> {
        let row = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, seq, prev, pusher_sig, signature_input, content_digest, request_path
             FROM ref_certificates WHERE repo_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(repo_id)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row.map(row_to_cert))
    }

    /// Acquire a per-repo advisory lock to serialize certificate issuance.
    /// This prevents two concurrent pushes to the same repo from racing on
    /// the sequence number allocation.
    /// Uses a transaction-scoped lock (`pg_advisory_xact_lock`) so it MUST
    /// be called within an active transaction to be effective.
    #[allow(dead_code)]
    pub async fn lock_repo_cert_issuance(&self, repo_id: &str) -> Result<()> {
        let hash = repo_lock_hash(repo_id);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Transaction-scoped variant of [`lock_repo_cert_issuance`].
    /// The lock is held until the enclosing transaction commits or rolls back.
    pub async fn lock_repo_cert_issuance_tx(
        &self,
        repo_id: &str,
        conn: &mut sqlx::postgres::PgConnection,
    ) -> Result<()> {
        let hash = repo_lock_hash(repo_id);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(hash)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}

/// Deterministic 64-bit hash of a repo_id for advisory lock keys.
/// Uses the first 8 bytes of SHA-256 rather than DefaultHasher (which the
/// std docs do not guarantee stable across Rust versions or platforms).
fn repo_lock_hash(repo_id: &str) -> i64 {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(repo_id.as_bytes());
    i64::from_ne_bytes(hash[..8].try_into().expect("sha256 output >= 8 bytes"))
}

// ── Peers ─────────────────────────────────────────────────────────────────────

impl Db {
    pub async fn upsert_peer(&self, did: &str, http_url: &str) -> Result<()> {
        // Defense-in-depth at the DB boundary: both writers funnel through here
        // — the announce handler and the bootstrap announce-back in main.rs.
        // The latter has no announce-time check, so validating here is what
        // stops a malicious bootstrap response from re-poisoning the table
        // right after prune_non_public_peers cleaned it.
        if !crate::api::peers::is_public_http_url(http_url) {
            anyhow::bail!("refusing to register non-public peer http_url: {http_url}");
        }
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO peers (did, http_url, last_seen, last_ping_ok, announced_at)
             VALUES ($1, $2, $3, FALSE, $3)
             ON CONFLICT(did) DO UPDATE SET http_url = $2, last_seen = $3",
        )
        .bind(did)
        .bind(http_url)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_peer_ping(&self, did: &str, ok: bool) -> Result<()> {
        sqlx::query("UPDATE peers SET last_seen = $1, last_ping_ok = $2 WHERE did = $3")
            .bind(Utc::now().to_rfc3339())
            .bind(ok)
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_peers(&self) -> Result<Vec<PeerRecord>> {
        let rows = sqlx::query(
            "SELECT did, http_url, last_seen, last_ping_ok, announced_at
             FROM peers ORDER BY last_seen DESC NULLS LAST",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PeerRecord {
                did: r.get("did"),
                http_url: r.get("http_url"),
                last_seen: r.get("last_seen"),
                last_ping_ok: r.get::<bool, _>("last_ping_ok"),
                announced_at: r.get("announced_at"),
            })
            .collect())
    }

    pub async fn prune_self_peers(&self, public_url: &str) -> Result<u64> {
        let trimmed = public_url.trim_end_matches('/');
        let with_slash = format!("{trimmed}/");
        let result = sqlx::query("DELETE FROM peers WHERE http_url = $1 OR http_url = $2")
            .bind(trimmed)
            .bind(&with_slash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Remove peer rows whose `http_url` is not a public http(s) endpoint
    /// (loopback/private/internal hosts injected via the open announce route).
    /// Runs at boot to clean tables poisoned before announce-time validation
    /// existed. Filtering is done in Rust to share one definition of "public"
    /// with the announce handler, then deleted in a single statement so one
    /// transient error can't abandon the remaining poisoned rows mid-loop.
    pub async fn prune_non_public_peers(&self) -> Result<u64> {
        let peers = self.list_peers().await?;
        let bad_dids: Vec<String> = peers
            .into_iter()
            .filter(|p| !crate::api::peers::is_public_http_url(&p.http_url))
            .map(|p| p.did)
            .collect();
        if bad_dids.is_empty() {
            return Ok(0);
        }
        let result = sqlx::query("DELETE FROM peers WHERE did = ANY($1)")
            .bind(&bad_dids)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// ── Pinned CIDs ───────────────────────────────────────────────────────────────

impl Db {
    pub async fn is_pinned(&self, sha256_hex: &str) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM pinned_cids WHERE sha256_hex = $1")
            .bind(sha256_hex)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt") > 0)
    }

    pub async fn record_pinned_cid(&self, sha256_hex: &str, cid: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at)
             VALUES ($1, $2, $3)
             ON CONFLICT(sha256_hex) DO NOTHING",
        )
        .bind(sha256_hex)
        .bind(cid)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_encrypted_blob(
        &self,
        repo_id: &str,
        oid: &str,
        cid: &str,
        recipients_tag: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO encrypted_blobs (repo_id, oid, cid, recipients_tag, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (repo_id, oid) DO UPDATE SET cid = EXCLUDED.cid, recipients_tag = EXCLUDED.recipients_tag",
        )
        .bind(repo_id)
        .bind(oid)
        .bind(cid)
        .bind(recipients_tag)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// (oid, cid) for every encrypted blob in the repo, unscoped by caller. Used
    /// by both the B2 replication view and B1 discovery. Recipient identities are
    /// not stored, so authorization is the caller's repo readability, not a per
    /// recipient check. Ciphertext metadata only.
    pub async fn list_all_encrypted_blobs(&self, repo_id: &str) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT oid, cid FROM encrypted_blobs WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for row in rows {
            let oid: String = row.get("oid");
            let cid: String = row.get("cid");
            out.push((oid, cid));
        }
        Ok(out)
    }

    /// The CID of one encrypted blob, or None if there is no such row. Recipient
    /// authorization is not enforced here: the handler checks repo readability and
    /// the envelope crypto gates decryption.
    pub async fn encrypted_blob_cid(&self, repo_id: &str, oid: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT cid FROM encrypted_blobs WHERE repo_id = $1 AND oid = $2")
            .bind(repo_id)
            .bind(oid)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("cid")))
    }

    /// The opaque recipients tag stored for an encrypted blob, or None if there is
    /// no row. Used only to decide whether a re-seal is needed (the recipient set
    /// changed); the tag is a node-keyed fingerprint, not the DID list.
    pub async fn encrypted_blob_recipients_tag(
        &self,
        repo_id: &str,
        oid: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT recipients_tag FROM encrypted_blobs WHERE repo_id = $1 AND oid = $2",
        )
        .bind(repo_id)
        .bind(oid)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("recipients_tag")))
    }

    pub async fn list_pinned_cids(&self) -> Result<Vec<PinnedCidRecord>> {
        let rows = sqlx::query(
            "SELECT sha256_hex, cid, pinned_at, pinata_cid FROM pinned_cids ORDER BY pinned_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PinnedCidRecord {
                sha256_hex: r.get("sha256_hex"),
                cid: r.get("cid"),
                pinned_at: r.get("pinned_at"),
                pinata_cid: r.get("pinata_cid"),
            })
            .collect())
    }

    /// Returns true if this object already has a Pinata CID recorded.
    pub async fn has_pinata_cid(&self, sha256_hex: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM pinned_cids WHERE sha256_hex = $1 AND pinata_cid IS NOT NULL",
        )
        .bind(sha256_hex)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("cnt") > 0)
    }

    /// Record the Pinata CID for a git object.
    /// Inserts the row if it doesn't exist (objects pinned directly to Pinata
    /// without a prior local IPFS pin get cid = pinata_cid).
    pub async fn record_pinata_cid(&self, sha256_hex: &str, pinata_cid: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(sha256_hex) DO UPDATE SET pinata_cid = EXCLUDED.pinata_cid",
        )
        .bind(sha256_hex)
        .bind(pinata_cid) // fallback local cid if row is new
        .bind(Utc::now().to_rfc3339())
        .bind(pinata_cid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ── Received Ref Updates ──────────────────────────────────────────────────────

impl Db {
    pub async fn insert_ref_update(&self, update: &ReceivedRefUpdate) -> Result<()> {
        sqlx::query(
            "INSERT INTO received_ref_updates
             (id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, timestamp,
              cert_id, received_at, from_peer, owner_did)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&update.id)
        .bind(&update.node_did)
        .bind(&update.pusher_did)
        .bind(&update.repo)
        .bind(&update.ref_name)
        .bind(&update.old_sha)
        .bind(&update.new_sha)
        .bind(&update.timestamp)
        .bind(&update.cert_id)
        .bind(&update.received_at)
        .bind(&update.from_peer)
        .bind(&update.owner_did)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Resolve the trusted display `owner_did` for every ref-update row in a page,
    /// issuing at most one query per *unique* local repo so the cost scales with
    /// the number of distinct repos in the page rather than the page size.
    ///
    /// The stored `owner_did` (and the `repo` slug) arrive over gossipsub or the
    /// unsigned peer-notify HTTP path, so neither is trusted. This method binds
    /// the wire `owner_did` to the local repo the slug names before it is ever
    /// surfaced:
    ///
    /// * **P1 (untrusted wire value):** a peer-supplied `owner_did` is only
    ///   echoed when it normalizes equal to the canonical owner of the *actual
    ///   local repo* at that slug. A caller asserting `did:key:zVictim` on a
    ///   `zAlice/widget` row is dropped, because `zVictim` does not own the
    ///   local `zAlice/widget` repo. The canonical DID is returned (not the raw
    ///   wire bytes), so the projection is always the local source of truth.
    /// * **P3 (legacy fallback):** a row stored with `owner_did = None` is
    ///   attributed only via an *exact, normalized, unique* local match —
    ///   `get_repo` matches the slug's owner key and name exactly (`LIMIT 1`,
    ///   preferring canonical rows). The loose prefix-tolerant drop gate
    ///   (`ref_update_row_names_repo`) is never used for attribution, so a
    ///   cross-method slug collision cannot synthesize the wrong owner. When no
    ///   unique local repo proves the owner, `None` is returned.
    ///
    /// # P2 mirror-only fallback
    ///
    /// Mirror-only repos store their owner as the bare normalized key (no DID
    /// method prefix).  When a validated wire DID carries a full prefix (e.g.
    /// `did:key:z…`) and the matching repo is a mirror, the full wire value is
    /// returned so the API contract preserves the DID method for these rows.
    ///
    /// The slug must be `"{owner}/{name}"`; a slug without a `/` cannot be
    /// attributed and yields `None`.
    pub async fn resolve_ref_update_owner_dids(
        &self,
        rows: &[(&str, Option<&str>)],
    ) -> Result<Vec<Option<String>>> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // ── 1.  Collect unique lookup keys ────────────────────────────────
        let mut slug_parts: Vec<Option<String>> = Vec::with_capacity(rows.len());
        // Keys are stored as `format!("{normalized_key}\0{name}")` for cheap
        // HashMap lookup.
        let mut unique_keys: Vec<String> = Vec::new();

        for (slug, _wire) in rows {
            if let Some((owner_part, name)) = slug.rsplit_once('/') {
                let normalized = normalize_owner_key(owner_part);
                let key = format!("{normalized}\0{name}");
                if !unique_keys.contains(&key) {
                    unique_keys.push(key.clone());
                }
                slug_parts.push(Some(key));
            } else {
                slug_parts.push(None);
            }
        }

        // ── 2.  Fetch all matching repos in one set-based query ──────────
        // Build a single SQL with one OR condition per unique key so every
        // distinct slug is resolved in one round-trip regardless of how many
        // unique repos the page names.
        let mut repo_map: std::collections::HashMap<String, RepoRecord> =
            std::collections::HashMap::new();

        if !unique_keys.is_empty() {
            let mut sql = String::from(
                "SELECT id, name, owner_did, description, is_public, default_branch,
                        created_at, updated_at, disk_path, forked_from, machine_id
                 FROM repos WHERE (",
            );
            let mut conds: Vec<String> = Vec::with_capacity(unique_keys.len());
            for i in 0..unique_keys.len() {
                let p = (2 * i + 1) as i64;
                let q = (2 * i + 2) as i64;
                conds.push(format!("({}) = ${p} AND name = ${q}", OWNER_KEY_CASE_SQL));
            }
            sql.push_str(&conds.join(" OR "));
            sql.push_str(
                ") ORDER BY CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END, \
                 created_at ASC, id ASC",
            );

            let mut q = sqlx::query(&sql);
            for key in &unique_keys {
                if let Some((owner_part, name)) = key.split_once('\0') {
                    q = q.bind(owner_part).bind(name);
                }
            }

            for row in q.fetch_all(&self.pool).await? {
                let repo = row_to_repo(row);
                let key = format!("{}\0{}", normalize_owner_key(&repo.owner_did), repo.name);
                repo_map.entry(key).or_insert(repo);
            }
        }

        // ── 3.  Resolve every input row ──────────────────────────────────
        let mut results = Vec::with_capacity(rows.len());
        for (i, (_slug, wire_owner_did)) in rows.iter().enumerate() {
            let Some(repo) = slug_parts[i].as_ref().and_then(|k| repo_map.get(k)) else {
                results.push(None);
                continue;
            };

            match (wire_owner_did, repo) {
                (Some(wire), repo)
                    if normalize_owner_key(wire) == normalize_owner_key(&repo.owner_did) =>
                {
                    if repo.id.contains('/') && *wire != repo.owner_did {
                        results.push(Some((*wire).to_string()));
                    } else {
                        results.push(Some(repo.owner_did.clone()));
                    }
                }
                (None, _) => {
                    results.push(Some(repo.owner_did.clone()));
                }
                _ => results.push(None),
            }
        }

        Ok(results)
    }

    /// One page of ref updates (newest first), optionally scoped to one repo.
    /// The `(timestamp DESC, id DESC)` order gives a stable tiebreak so offset
    /// paging does not skip or duplicate rows when timestamps collide. Used by
    /// the visibility-gated feed collector, which pages past dropped private rows
    /// so a small limit still returns the latest visible events (#114).
    /// One page of ref updates for the visibility collector, ordered
    /// `timestamp DESC, id DESC`, using a **keyset** cursor rather than
    /// `LIMIT/OFFSET`.
    ///
    /// `after` is the `(timestamp, id)` of the last row of the previous page;
    /// the next page reads rows strictly older than it via the row-value
    /// predicate `(timestamp, id) < (after_ts, after_id)`, which matches the
    /// `ORDER BY` exactly (same id tie-break). Because a concurrently inserted
    /// row is newer (larger `timestamp`) and so sorts to the front, it lands
    /// *above* the window we are paging through and cannot shift it. That keeps
    /// a single multi-page scan free of the duplicate/skip that OFFSET paging
    /// suffers when `received_ref_updates` is written between page reads.
    pub async fn list_ref_updates_keyset(
        &self,
        repo: Option<&str>,
        limit: i64,
        after: Option<(&str, &str)>,
    ) -> Result<Vec<ReceivedRefUpdate>> {
        const COLS: &str = "id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, \
                            timestamp, cert_id, received_at, from_peer, owner_did";

        // Positional params in bind order: repo?, after_ts?, after_id?, limit.
        let mut conds: Vec<String> = Vec::new();
        let mut n = 0;
        if repo.is_some() {
            n += 1;
            conds.push(format!("repo = ${n}"));
        }
        if after.is_some() {
            let (a, b) = (n + 1, n + 2);
            n += 2;
            conds.push(format!("(timestamp, id) < (${a}, ${b})"));
        }
        let where_clause = if conds.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conds.join(" AND "))
        };
        let sql = format!(
            "SELECT {COLS} FROM received_ref_updates{where_clause} \
             ORDER BY timestamp DESC, id DESC LIMIT ${}",
            n + 1
        );

        let mut q = sqlx::query(&sql);
        if let Some(r) = repo {
            q = q.bind(r.to_string());
        }
        if let Some((ts, id)) = after {
            q = q.bind(ts.to_string()).bind(id.to_string());
        }
        let rows = q.bind(limit).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(row_to_ref_update).collect())
    }
}

// ── Agent Tasks ───────────────────────────────────────────────────────────────

impl Db {
    pub async fn create_task(&self, task: &AgentTask) -> Result<()> {
        sqlx::query(
            "INSERT INTO agent_tasks (id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(&task.id)
        .bind(&task.repo_id)
        .bind(&task.kind)
        .bind(&task.status)
        .bind(&task.delegator_did)
        .bind(&task.assignee_did)
        .bind(&task.capability)
        .bind(&task.ucan_token)
        .bind(&task.payload)
        .bind(&task.result)
        .bind(&task.created_at)
        .bind(&task.updated_at)
        .bind(&task.deadline)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_task(&self, id: &str) -> Result<Option<AgentTask>> {
        let row = sqlx::query(
            "SELECT id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline
             FROM agent_tasks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_task))
    }

    pub async fn list_tasks(
        &self,
        status: Option<&str>,
        assignee_did: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AgentTask>> {
        let rows = match (status, assignee_did) {
            (Some(s), Some(a)) => sqlx::query(
                "SELECT id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline
                 FROM agent_tasks WHERE status=$1 AND assignee_did=$2 ORDER BY created_at DESC LIMIT $3",
            )
            .bind(s)
            .bind(a)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?,
            (Some(s), None) => sqlx::query(
                "SELECT id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline
                 FROM agent_tasks WHERE status=$1 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(s)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?,
            (None, Some(a)) => sqlx::query(
                "SELECT id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline
                 FROM agent_tasks WHERE assignee_did=$1 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(a)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?,
            (None, None) => sqlx::query(
                "SELECT id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline
                 FROM agent_tasks ORDER BY created_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?,
        };
        Ok(rows.into_iter().map(row_to_task).collect())
    }

    pub async fn claim_task(&self, id: &str, assignee_did: &str) -> Result<AgentTask> {
        let now = Utc::now().to_rfc3339();
        let row = sqlx::query(
            "UPDATE agent_tasks SET status='claimed', assignee_did=$2, updated_at=$3
             WHERE id=$1 AND status='pending'
             RETURNING id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline",
        )
        .bind(id)
        .bind(assignee_did)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_task)
            .ok_or_else(|| anyhow::anyhow!("task not claimable: not found or already claimed"))
    }

    pub async fn finish_task(
        &self,
        id: &str,
        new_status: &str,
        result: Option<&str>,
    ) -> Result<AgentTask> {
        let now = Utc::now().to_rfc3339();
        let row = sqlx::query(
            "UPDATE agent_tasks SET status=$2, result=$3, updated_at=$4
             WHERE id=$1 AND status='claimed'
             RETURNING id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline",
        )
        .bind(id)
        .bind(new_status)
        .bind(result)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_task)
            .ok_or_else(|| anyhow::anyhow!("task not found or not in claimed state"))
    }
}

// ── Arweave anchors ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArweaveAnchor {
    pub id: String,
    pub repo: String,
    pub owner_did: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub cid: Option<String>,
    pub arweave_tx_id: String,
    pub node_did: String,
    pub anchored_at: String,
    pub status: String,
    pub deadline_height: Option<i64>,
    pub receipt_sig: Option<String>,
    pub cert_id: Option<String>,
}

/// Input parameters for recording an Arweave anchor.
pub struct RecordAnchorInputV2<'a> {
    pub repo: &'a str,
    pub owner_did: &'a str,
    pub ref_name: &'a str,
    pub old_sha: &'a str,
    pub new_sha: &'a str,
    pub cid: Option<&'a str>,
    pub arweave_tx_id: &'a str,
    pub node_did: &'a str,
    /// ID of the [`RefCertificate`] embedded in this anchor, if any.
    pub cert_id: Option<String>,
}

impl Db {
    pub async fn record_arweave_anchor(&self, input: &RecordAnchorInputV2<'_>) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO arweave_anchors (id, repo, owner_did, ref_name, old_sha, new_sha, cid, arweave_tx_id, node_did, anchored_at, status, cert_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(&id)
        .bind(input.repo)
        .bind(input.owner_did)
        .bind(input.ref_name)
        .bind(input.old_sha)
        .bind(input.new_sha)
        .bind(input.cid)
        .bind(input.arweave_tx_id)
        .bind(input.node_did)
        .bind(&now)
        .bind("pending")
        .bind(input.cert_id.clone())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_arweave_anchors(
        &self,
        repo: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ArweaveAnchor>> {
        let rows = if let Some(repo) = repo {
            sqlx::query(
                "SELECT id, repo, owner_did, ref_name, old_sha, new_sha, cid, arweave_tx_id, node_did, anchored_at, status, deadline_height, receipt_sig, cert_id
                 FROM arweave_anchors WHERE repo=$1 ORDER BY anchored_at DESC LIMIT $2",
            )
            .bind(repo)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, repo, owner_did, ref_name, old_sha, new_sha, cid, arweave_tx_id, node_did, anchored_at, status, deadline_height, receipt_sig, cert_id
                 FROM arweave_anchors ORDER BY anchored_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| ArweaveAnchor {
                id: r.get("id"),
                repo: r.get("repo"),
                owner_did: r.get("owner_did"),
                ref_name: r.get("ref_name"),
                old_sha: r.get("old_sha"),
                new_sha: r.get("new_sha"),
                cid: r.get("cid"),
                arweave_tx_id: r.get("arweave_tx_id"),
                node_did: r.get("node_did"),
                anchored_at: r.get("anchored_at"),
                status: r.get("status"),
                deadline_height: r.try_get("deadline_height").unwrap_or(None),
                receipt_sig: r.try_get("receipt_sig").unwrap_or(None),
                cert_id: r.try_get("cert_id").unwrap_or(None),
            })
            .collect())
    }
}

// ── Row helpers ───────────────────────────────────────────────────────────────

fn row_to_repo(r: sqlx::postgres::PgRow) -> RepoRecord {
    let created_str: String = r.get("created_at");
    let updated_str: String = r.get("updated_at");
    RepoRecord {
        id: r.get("id"),
        name: r.get("name"),
        owner_did: r.get("owner_did"),
        description: r.get("description"),
        is_public: r.get::<bool, _>("is_public"),
        default_branch: r.get("default_branch"),
        created_at: created_str
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now()),
        updated_at: updated_str
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now()),
        disk_path: r.get("disk_path"),
        forked_from: r.try_get("forked_from").unwrap_or(None),
        machine_id: r.try_get("machine_id").unwrap_or(None),
    }
}

fn row_to_pr(r: sqlx::postgres::PgRow) -> PullRequest {
    PullRequest {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        number: r.get("number"),
        title: r.get("title"),
        body: r.get("body"),
        author_did: r.get("author_did"),
        source_branch: r.get("source_branch"),
        target_branch: r.get("target_branch"),
        status: r.get("status"),
        merged_by_did: r.get("merged_by_did"),
        merged_at: r.get("merged_at"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

fn row_to_webhook(r: sqlx::postgres::PgRow) -> Webhook {
    let events_str: String = r.get("events");
    let events: Vec<String> =
        serde_json::from_str(&events_str).unwrap_or_else(|_| vec!["*".into()]);
    Webhook {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        url: r.get("url"),
        secret: r.get("secret"),
        events,
        created_by_did: r.get("created_by_did"),
        created_at: r.get("created_at"),
        active: r.get::<bool, _>("active"),
    }
}

fn row_to_cert(r: sqlx::postgres::PgRow) -> RefCertificate {
    RefCertificate {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        ref_name: r.get("ref_name"),
        old_sha: r.get("old_sha"),
        new_sha: r.get("new_sha"),
        pusher_did: r.get("pusher_did"),
        node_did: r.get("node_did"),
        signature: r.get("signature"),
        issued_at: r.get("issued_at"),
        seq: r.try_get("seq").unwrap_or(0),
        prev: r.try_get("prev").unwrap_or_default(),
        pusher_sig: r.try_get("pusher_sig").unwrap_or(None),
        signature_input: r.try_get("signature_input").unwrap_or(None),
        content_digest: r.try_get("content_digest").unwrap_or(None),
        request_path: r.try_get("request_path").unwrap_or(None),
    }
}

fn row_to_ref_update(r: sqlx::postgres::PgRow) -> ReceivedRefUpdate {
    ReceivedRefUpdate {
        id: r.get("id"),
        node_did: r.get("node_did"),
        pusher_did: r.get("pusher_did"),
        repo: r.get("repo"),
        ref_name: r.get("ref_name"),
        old_sha: r.get("old_sha"),
        new_sha: r.get("new_sha"),
        timestamp: r.get("timestamp"),
        cert_id: r.get("cert_id"),
        received_at: r.get("received_at"),
        from_peer: r.get("from_peer"),
        owner_did: r.get("owner_did"),
    }
}

fn row_to_task(r: sqlx::postgres::PgRow) -> AgentTask {
    AgentTask {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        kind: r.get("kind"),
        status: r.get("status"),
        delegator_did: r.get("delegator_did"),
        assignee_did: r.get("assignee_did"),
        capability: r.get("capability"),
        ucan_token: r.get("ucan_token"),
        payload: r.get("payload"),
        result: r.get("result"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        deadline: r.get("deadline"),
    }
}

// ── Protected Branches ────────────────────────────────────────────────────────

impl Db {
    pub async fn protect_branch(
        &self,
        repo_id: &str,
        branch: &str,
        created_by: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{repo_id}:{branch}");
        sqlx::query(
            "INSERT INTO protected_branches (id, repo_id, branch, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (repo_id, branch) DO NOTHING",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(branch)
        .bind(created_by)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn unprotect_branch(&self, repo_id: &str, branch: &str) -> Result<()> {
        sqlx::query("DELETE FROM protected_branches WHERE repo_id = $1 AND branch = $2")
            .bind(repo_id)
            .bind(branch)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_protected_branches(&self, repo_id: &str) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT branch FROM protected_branches WHERE repo_id = $1 ORDER BY branch")
                .bind(repo_id)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("branch"))
            .collect())
    }

    pub async fn is_branch_protected(&self, repo_id: &str, branch: &str) -> Result<bool> {
        let row =
            sqlx::query("SELECT 1 FROM protected_branches WHERE repo_id = $1 AND branch = $2")
                .bind(repo_id)
                .bind(branch)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }
}

// ── Path-scoped Visibility ────────────────────────────────────────────────────

impl Db {
    pub async fn set_visibility_rule(
        &self,
        repo_id: &str,
        path_glob: &str,
        mode: VisibilityMode,
        reader_dids: &[String],
        created_by: &str,
    ) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let readers = serde_json::to_string(reader_dids).unwrap_or_else(|_| "[]".to_string());
        sqlx::query(
            "INSERT INTO visibility_rules
                 (id, repo_id, path_glob, mode, reader_dids, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (repo_id, path_glob) DO UPDATE
             SET mode = EXCLUDED.mode,
                 reader_dids = EXCLUDED.reader_dids,
                 created_by = EXCLUDED.created_by,
                 created_at = EXCLUDED.created_at",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(path_glob)
        .bind(mode.as_str())
        .bind(&readers)
        .bind(created_by)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn remove_visibility_rule(&self, repo_id: &str, path_glob: &str) -> Result<()> {
        sqlx::query("DELETE FROM visibility_rules WHERE repo_id = $1 AND path_glob = $2")
            .bind(repo_id)
            .bind(path_glob)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_visibility_rules(&self, repo_id: &str) -> Result<Vec<VisibilityRule>> {
        let rows = sqlx::query(
            "SELECT id, repo_id, path_glob, mode, reader_dids, created_by, created_at
             FROM visibility_rules WHERE repo_id = $1 ORDER BY path_glob",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let readers: String = r.get("reader_dids");
                let created_at: String = r.get("created_at");
                VisibilityRule {
                    id: r.get("id"),
                    repo_id: r.get("repo_id"),
                    path_glob: r.get("path_glob"),
                    mode: VisibilityMode::from_db(&r.get::<String, _>("mode")),
                    reader_dids: serde_json::from_str(&readers).unwrap_or_default(),
                    created_by: r.get("created_by"),
                    created_at: created_at
                        .parse::<DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                }
            })
            .collect())
    }

    /// All visibility rules for a set of repos, grouped by `repo_id`, in one
    /// query. The listing surfaces use this to apply the same `"/"` visibility
    /// decision the per-repo endpoints make without an N+1 per-repo rule fetch
    /// (#97). Repos with no rules are simply absent from the map.
    pub async fn list_visibility_rules_for_repos(
        &self,
        repo_ids: &[String],
    ) -> Result<std::collections::HashMap<String, Vec<VisibilityRule>>> {
        use std::collections::HashMap;
        if repo_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows = sqlx::query(
            "SELECT id, repo_id, path_glob, mode, reader_dids, created_by, created_at
             FROM visibility_rules WHERE repo_id = ANY($1) ORDER BY path_glob",
        )
        .bind(repo_ids)
        .fetch_all(&self.pool)
        .await?;
        let mut out: HashMap<String, Vec<VisibilityRule>> = HashMap::new();
        for r in rows {
            let readers: String = r.get("reader_dids");
            let created_at: String = r.get("created_at");
            let rule = VisibilityRule {
                id: r.get("id"),
                repo_id: r.get("repo_id"),
                path_glob: r.get("path_glob"),
                mode: VisibilityMode::from_db(&r.get::<String, _>("mode")),
                reader_dids: serde_json::from_str(&readers).unwrap_or_default(),
                created_by: r.get("created_by"),
                created_at: created_at
                    .parse::<DateTime<Utc>>()
                    .unwrap_or_else(|_| Utc::now()),
            };
            out.entry(rule.repo_id.clone()).or_default().push(rule);
        }
        Ok(out)
    }
}

// ── Repo Stars ────────────────────────────────────────────────────────────────

impl Db {
    /// Star a repo. Returns true if inserted (new star), false if already starred.
    pub async fn star_repo(&self, repo_id: &str, agent_did: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{repo_id}:{agent_did}");
        let result = sqlx::query(
            "INSERT INTO repo_stars (id, repo_id, agent_did, starred_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (repo_id, agent_did) DO NOTHING",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(agent_did)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Unstar a repo. Idempotent — no error if not starred.
    pub async fn unstar_repo(&self, repo_id: &str, agent_did: &str) -> Result<()> {
        sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1 AND agent_did = $2")
            .bind(repo_id)
            .bind(agent_did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Count total stars for a repo.
    pub async fn count_stars(&self, repo_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM repo_stars WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    // ── Repo replicas ──────────────────────────────────────────────────

    /// Register a replica for a repo. Returns true if inserted, false if the
    /// replica was already registered (URL updated either way).
    pub async fn register_replica(
        &self,
        repo_id: &str,
        replica_did: &str,
        replica_url: &str,
    ) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{repo_id}:{replica_did}");
        let result = sqlx::query(
            "INSERT INTO repo_replicas (id, repo_id, replica_did, replica_url, registered_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (repo_id, replica_did) DO UPDATE
               SET replica_url = EXCLUDED.replica_url",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(replica_did)
        .bind(replica_url)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Unregister a replica. Idempotent.
    pub async fn unregister_replica(&self, repo_id: &str, replica_did: &str) -> Result<()> {
        sqlx::query("DELETE FROM repo_replicas WHERE repo_id = $1 AND replica_did = $2")
            .bind(repo_id)
            .bind(replica_did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List all replicas for a repo, oldest registration first.
    pub async fn list_replicas(&self, repo_id: &str) -> Result<Vec<RepoReplica>> {
        let rows = sqlx::query(
            "SELECT replica_did, replica_url, registered_at
             FROM repo_replicas
             WHERE repo_id = $1
             ORDER BY registered_at ASC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RepoReplica {
                replica_did: r.get("replica_did"),
                replica_url: r.get("replica_url"),
                registered_at: r.get("registered_at"),
            })
            .collect())
    }

    /// Count replicas registered for a repo.
    pub async fn count_replicas(&self, repo_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM repo_replicas WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    /// Check whether a specific agent has starred a repo.
    #[allow(dead_code)]
    pub async fn is_starred(&self, repo_id: &str, agent_did: &str) -> Result<bool> {
        let row = sqlx::query("SELECT 1 FROM repo_stars WHERE repo_id = $1 AND agent_did = $2")
            .bind(repo_id)
            .bind(agent_did)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }
}

// ── Bounties ─────────────────────────────────────────────────────────────────

impl Db {
    pub async fn create_bounty(&self, b: &BountyRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO bounties
                (id, repo_owner, repo_name, issue_id, title, amount, creator_did, status, created_at, deadline_secs)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
        )
        .bind(&b.id)
        .bind(&b.repo_owner)
        .bind(&b.repo_name)
        .bind(&b.issue_id)
        .bind(&b.title)
        .bind(b.amount)
        .bind(&b.creator_did)
        .bind(&b.status)
        .bind(&b.created_at)
        .bind(b.deadline_secs)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_bounty(&self, id: &str) -> Result<Option<BountyRecord>> {
        let row = sqlx::query("SELECT * FROM bounties WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| self.bounty_from_row(&r)))
    }

    pub async fn list_bounties(
        &self,
        repo_owner: Option<&str>,
        repo_name: Option<&str>,
        status: Option<&str>,
        limit: i64,
        after_created_at: Option<&str>,
        after_id: Option<&str>,
    ) -> Result<Vec<BountyRecord>> {
        let mut sql = String::from("SELECT * FROM bounties WHERE 1=1");
        let mut binds: Vec<String> = Vec::new();
        let mut idx = 1;

        if let Some(o) = repo_owner {
            sql.push_str(&format!(" AND repo_owner = ${idx}"));
            binds.push(o.to_string());
            idx += 1;
        }
        if let Some(n) = repo_name {
            sql.push_str(&format!(" AND repo_name = ${idx}"));
            binds.push(n.to_string());
            idx += 1;
        }
        if let Some(s) = status {
            sql.push_str(&format!(" AND status = ${idx}"));
            binds.push(s.to_string());
            idx += 1;
        }
        if let Some(ts) = after_created_at {
            let id = after_id.unwrap_or("");
            sql.push_str(&format!(" AND (created_at, id) < (${idx}, ${})", idx + 1));
            binds.push(ts.to_string());
            idx += 1;
            binds.push(id.to_string());
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY created_at DESC, id DESC LIMIT ${idx}"));

        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        q = q.bind(limit);

        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| self.bounty_from_row(r)).collect())
    }

    pub async fn claim_bounty(
        &self,
        id: &str,
        claimant_did: &str,
        claimant_wallet: Option<&str>,
        claimed_at: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET claimant_did=$1, claimant_wallet=$2, claimed_at=$3, status='claimed' WHERE id=$4 AND status='open'",
        )
        .bind(claimant_did)
        .bind(claimant_wallet)
        .bind(claimed_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn submit_bounty(&self, id: &str, pr_id: &str, submitted_at: &str) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET pr_id=$1, submitted_at=$2, status='submitted' WHERE id=$3 AND status='claimed'",
        )
        .bind(pr_id)
        .bind(submitted_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn approve_bounty(
        &self,
        id: &str,
        completed_at: &str,
        tx_hash: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET completed_at=$1, tx_hash=$2, status='completed' WHERE id=$3 AND status='submitted'",
        )
        .bind(completed_at)
        .bind(tx_hash)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn cancel_bounty(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE bounties SET status='cancelled' WHERE id=$1 AND status='open'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn dispute_bounty(&self, id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET status='open', claimant_did=NULL, claimant_wallet=NULL, pr_id=NULL, claimed_at=NULL, submitted_at=NULL WHERE id=$1 AND status IN ('claimed','submitted')",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn count_bounties_by_status(&self, status: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as c FROM bounties WHERE status = $1")
            .bind(status)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("c"))
    }

    pub async fn agent_bounty_stats(&self, agent_did: &str) -> Result<(i64, i64)> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(amount),0) as total FROM bounties WHERE claimant_did = $1 AND status = 'completed'",
        )
        .bind(agent_did)
        .fetch_one(&self.pool)
        .await?;
        Ok((row.get::<i64, _>("cnt"), row.get::<i64, _>("total")))
    }

    pub async fn bounty_leaderboard(&self, limit: i64) -> Result<Vec<(String, i64, i64)>> {
        let rows = sqlx::query(
            "SELECT claimant_did, COUNT(*) as cnt, COALESCE(SUM(amount),0) as total FROM bounties WHERE status='completed' AND claimant_did IS NOT NULL GROUP BY claimant_did ORDER BY total DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("claimant_did"),
                    r.get::<i64, _>("cnt"),
                    r.get::<i64, _>("total"),
                )
            })
            .collect())
    }

    fn bounty_from_row(&self, r: &sqlx::postgres::PgRow) -> BountyRecord {
        BountyRecord {
            id: r.get("id"),
            repo_owner: r.get("repo_owner"),
            repo_name: r.get("repo_name"),
            issue_id: r.get("issue_id"),
            title: r.get("title"),
            amount: r.get("amount"),
            creator_did: r.get("creator_did"),
            claimant_did: r.get("claimant_did"),
            claimant_wallet: r.get("claimant_wallet"),
            pr_id: r.get("pr_id"),
            status: r.get("status"),
            created_at: r.get("created_at"),
            claimed_at: r.get("claimed_at"),
            submitted_at: r.get("submitted_at"),
            completed_at: r.get("completed_at"),
            deadline_secs: r.get("deadline_secs"),
            tx_hash: r.get("tx_hash"),
        }
    }
}

// ── Agent Profiles ───────────────────────────────────────────────────────────

impl Db {
    pub async fn upsert_profile(
        &self,
        did: &str,
        display_name: Option<&str>,
        bio: Option<&str>,
        avatar_url: Option<&str>,
        website: Option<&str>,
        socials: Option<&str>,
    ) -> Result<ProfileRecord> {
        let now = Utc::now().to_rfc3339();

        // Try update first for existing profiles (merge fields)
        let existing = self.get_profile(did).await?;

        if let Some(existing) = existing {
            let new_name = display_name.or(existing.display_name.as_deref());
            let new_bio = bio.or(existing.bio.as_deref());
            let new_avatar = avatar_url.or(existing.avatar_url.as_deref());
            let new_website = website.or(existing.website.as_deref());
            let new_socials = socials.or(existing.socials.as_deref());

            sqlx::query(
                "UPDATE agent_profiles
                 SET display_name=$1, bio=$2, avatar_url=$3, website=$4, socials=$5, updated_at=$6
                 WHERE did=$7",
            )
            .bind(new_name)
            .bind(new_bio)
            .bind(new_avatar)
            .bind(new_website)
            .bind(new_socials)
            .bind(&now)
            .bind(did)
            .execute(&self.pool)
            .await?;

            Ok(ProfileRecord {
                did: did.to_string(),
                display_name: new_name.map(String::from),
                bio: new_bio.map(String::from),
                avatar_url: new_avatar.map(String::from),
                website: new_website.map(String::from),
                socials: new_socials.map(String::from),
                profile_cid: existing.profile_cid,
                created_at: existing.created_at,
                updated_at: now,
            })
        } else {
            sqlx::query(
                "INSERT INTO agent_profiles (did, display_name, bio, avatar_url, website, socials, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(did)
            .bind(display_name)
            .bind(bio)
            .bind(avatar_url)
            .bind(website)
            .bind(socials)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            Ok(ProfileRecord {
                did: did.to_string(),
                display_name: display_name.map(String::from),
                bio: bio.map(String::from),
                avatar_url: avatar_url.map(String::from),
                website: website.map(String::from),
                socials: socials.map(String::from),
                profile_cid: None,
                created_at: now.clone(),
                updated_at: now,
            })
        }
    }

    pub async fn get_profile(&self, did: &str) -> Result<Option<ProfileRecord>> {
        let row = sqlx::query(
            "SELECT did, display_name, bio, avatar_url, website, socials, profile_cid, created_at, updated_at
             FROM agent_profiles
             WHERE did = $1 OR did LIKE '%:' || $1",
        )
        .bind(did)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| ProfileRecord {
            did: r.get("did"),
            display_name: r.get("display_name"),
            bio: r.get("bio"),
            avatar_url: r.get("avatar_url"),
            website: r.get("website"),
            socials: r.get("socials"),
            profile_cid: r.get("profile_cid"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn set_profile_cid(&self, did: &str, cid: &str) -> Result<()> {
        sqlx::query("UPDATE agent_profiles SET profile_cid = $1, updated_at = $2 WHERE did = $3")
            .bind(cid)
            .bind(Utc::now().to_rfc3339())
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// These tests don't require a live Postgres connection. They validate the
// static migration catalogue is well-formed so a future maintainer can't
// ship a regression like duplicate versions, negative versions, or empty
// migration bodies. The actual SQL execution is exercised by integration
// tests / first-run on a real node.

#[cfg(test)]
mod migration_tests {
    use super::{MIGRATIONS, MIGRATION_V1_NAME};

    #[test]
    fn migrations_are_non_empty() {
        assert!(
            !MIGRATIONS.is_empty(),
            "MIGRATIONS must contain at least the initial v1 schema"
        );
    }

    #[test]
    fn migration_versions_are_strictly_increasing() {
        let mut last = i64::MIN;
        for m in MIGRATIONS {
            assert!(
                m.version > last,
                "migration versions must be strictly increasing; \
                 found {} after {}",
                m.version,
                last
            );
            last = m.version;
        }
    }

    #[test]
    fn migration_versions_start_at_one() {
        // A version of 0 (or negative) would be a footgun: any future
        // `WHERE version > current_max` style query would skip it.
        assert_eq!(
            MIGRATIONS.first().map(|m| m.version),
            Some(1),
            "the first migration must have version 1"
        );
    }

    #[test]
    fn migration_names_are_non_empty_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for m in MIGRATIONS {
            assert!(
                !m.name.is_empty(),
                "migration v{} has empty name",
                m.version
            );
            assert!(
                !m.name.contains(char::is_whitespace),
                "migration v{} name {:?} contains whitespace",
                m.version,
                m.name
            );
            assert!(
                seen.insert(m.name),
                "duplicate migration name: {:?}",
                m.name
            );
        }
    }

    #[test]
    fn migration_bodies_are_non_empty() {
        for m in MIGRATIONS {
            assert!(
                !m.stmts.is_empty(),
                "migration v{} ({}) has no SQL statements",
                m.version,
                m.name
            );
        }
    }

    #[test]
    fn v1_name_is_the_initial_schema() {
        // This is what the legacy-install backfill writes to
        // `schema_migrations` when an existing node upgrades. If you rename
        // it, you must also update the backfill.
        assert_eq!(MIGRATIONS[0].name, MIGRATION_V1_NAME);
    }

    /// Simulate an existing node at v9 with populated received_ref_updates,
    /// then apply the v11 migration and verify (a) owner_did IS NULL on
    /// existing rows, (b) the column exists and is nullable TEXT, and
    /// (c) idempotent re-run does not error.
    #[sqlx::test]
    async fn migration_v11_creates_owner_did_column(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);

        // Create all tables by running the full migration chain from scratch,
        // then drop the owner_did column to simulate a pre-v10 schema.
        db.migrate().await.unwrap();
        sqlx::query("ALTER TABLE received_ref_updates DROP COLUMN owner_did")
            .execute(&db.pool)
            .await
            .unwrap();

        // Truncate schema_migrations and re-seed at v9 — simulate an existing
        // node that has run v1..v9 but not yet v10.
        sqlx::query("DELETE FROM schema_migrations")
            .execute(&db.pool)
            .await
            .unwrap();
        for m in MIGRATIONS.iter().take_while(|m| m.version < 10) {
            sqlx::query(
                "INSERT INTO schema_migrations (version, name, applied_at)
                 VALUES ($1, $2, $3)",
            )
            .bind(m.version)
            .bind(m.name)
            .bind("2026-07-01T00:00:00Z")
            .execute(&db.pool)
            .await
            .unwrap();
        }

        // ── Simulate an existing node with rows recorded before v11 ────────
        // The owner_did column does not exist yet, so we INSERT without it.
        let row_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO received_ref_updates
             (id, node_did, pusher_did, repo, ref_name, old_sha, new_sha,
              timestamp, cert_id, received_at, from_peer)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(&row_id)
        .bind("did:key:zNode")
        .bind("did:key:zPusher")
        .bind("z6MkOwner/myrepo")
        .bind("refs/heads/main")
        .bind("0000000000000000000000000000000000000000")
        .bind("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind("2026-07-01T12:00:00Z")
        .bind::<Option<String>>(None)
        .bind("2026-07-01T12:00:01Z")
        .bind("12D3KooWPeer")
        .execute(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM received_ref_updates")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            1,
            "pre-migration row must exist"
        );

        // ── Apply pending migrations (v10 ref_cert_unique_per_ref, v11 owner_did, v12 arweave) ──
        db.migrate().await.unwrap();

        // ── Assertions ────────────────────────────────────────────────────

        // (a) Existing row has owner_did IS NULL (not overwritten).
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_did FROM received_ref_updates WHERE id = $1")
                .bind(&row_id)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(owner, None, "existing row's owner_did must be NULL");

        // (b) Column exists and is nullable TEXT.
        let col: (String, String, String) = sqlx::query_as(
            "SELECT column_name, data_type, is_nullable
             FROM information_schema.columns
             WHERE table_name = 'received_ref_updates' AND column_name = 'owner_did'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(col.0, "owner_did");
        assert_eq!(col.1, "text");
        assert_eq!(col.2, "YES", "owner_did must be nullable");

        // (c) Version 11 is recorded as applied.
        let v11_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations WHERE version = 11")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(
            v11_count.0, 1,
            "migration v11 must be recorded in schema_migrations"
        );

        // (d) Re-run: idempotent — ADD COLUMN IF NOT EXISTS must not error.
        db.migrate().await.unwrap();
    }
}

#[cfg(test)]
mod agent_discovery_tests {
    use super::{filter_discoverable, AgentRow};

    fn agent(did: &str, trust: f64, status: &str, caps: &[&str]) -> AgentRow {
        AgentRow {
            did: did.to_string(),
            trust_score: trust,
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            registered_at: "2026-06-19T00:00:00Z".to_string(),
            last_seen: None,
            status: status.to_string(),
        }
    }

    fn dids(rows: &[AgentRow]) -> Vec<&str> {
        rows.iter().map(|a| a.did.as_str()).collect()
    }

    #[test]
    fn only_active_agents_are_returned() {
        let rows = vec![
            agent("did:key:active1", 0.5, "active", &["reputation:score"]),
            agent("did:key:revoked1", 0.4, "revoked", &["reputation:score"]),
            agent("did:key:revoked2", 0.3, "revoked", &["reputation:score"]),
        ];

        let out = filter_discoverable(rows, None);

        assert_eq!(dids(&out), vec!["did:key:active1"]);
    }

    #[test]
    fn revoked_orphan_never_wins_capability_routing() {
        // Reproduces issue #29: a self-deregistered orphan sharing the
        // canonical agent's capability and equal trust must be excluded so the
        // active replacement is the only capability match.
        let rows = vec![
            agent("did:key:orphan", 0.1, "revoked", &["reputation:score"]),
            agent("did:key:canonical", 0.1, "active", &["reputation:score"]),
        ];

        let out = filter_discoverable(rows, Some("reputation:score"));

        assert_eq!(dids(&out), vec!["did:key:canonical"]);
    }

    #[test]
    fn capability_and_status_filters_compose() {
        let rows = vec![
            // matches capability but retired -> excluded
            agent("did:key:revoked", 0.9, "revoked", &["attestation:verify"]),
            // active but wrong capability -> excluded
            agent("did:key:other", 0.8, "active", &["oracle:agent-trust"]),
            // active and matches -> kept
            agent("did:key:match", 0.7, "active", &["attestation:verify"]),
        ];

        let out = filter_discoverable(rows, Some("attestation:verify"));

        assert_eq!(dids(&out), vec!["did:key:match"]);
    }

    #[test]
    fn input_order_is_preserved_so_active_stays_trust_ranked() {
        // Input arrives pre-sorted by trust desc; filtering must not reorder.
        let rows = vec![
            agent("did:key:high", 0.9, "active", &[]),
            agent("did:key:retired", 0.8, "revoked", &[]),
            agent("did:key:mid", 0.5, "active", &[]),
            agent("did:key:low", 0.2, "active", &[]),
        ];

        let out = filter_discoverable(rows, None);

        assert_eq!(
            dids(&out),
            vec!["did:key:high", "did:key:mid", "did:key:low"]
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(filter_discoverable(vec![], None).is_empty());
        assert!(filter_discoverable(vec![], Some("reputation:score")).is_empty());
    }
}

#[cfg(test)]
mod dedup_db_tests {
    use super::{Db, RepoRecord};
    use chrono::{DateTime, Utc};
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// Build a repo row with explicit timestamps. A slash in `id` marks a mirror
    /// row (the format `upsert_mirror_repo` writes); a UUID-shaped `id` is canonical.
    fn rec(
        id: &str,
        owner_did: &str,
        name: &str,
        desc: &str,
        created: &str,
        updated: &str,
    ) -> RepoRecord {
        RepoRecord {
            id: id.to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: Some(desc.to_string()),
            is_public: true,
            default_branch: "main".to_string(),
            created_at: ts(created),
            updated_at: ts(updated),
            disk_path: format!("/srv/{id}"),
            forked_from: None,
            machine_id: None,
        }
    }

    /// The canonical `did:key:` row and the short-owner mirror row of one logical
    /// repo collapse to a single deduped entry: the canonical row wins and inherits
    /// the group's most recent `updated_at`.
    #[sqlx::test]
    async fn deduped_collapses_mirror_and_canonical(pool: PgPool) {
        let db = db(pool).await;
        let canonical = rec(
            "9d92186a-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "Decentralized npm for agents",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        // Mirror row in the shape upsert_mirror_repo writes: slash id, bare owner.
        let mirror = rec(
            "z6Mkwbud/nipmod",
            "z6Mkwbud",
            "nipmod",
            "mirrored from peer",
            "2026-02-01T00:00:00Z",
            "2026-03-01T00:00:00Z",
        );
        db.create_repo(&canonical).await.unwrap();
        db.create_repo(&mirror).await.unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1, "the pair collapses to one logical repo");
        assert_eq!(out[0].owner_did, "did:key:z6Mkwbud", "canonical row wins");
        assert_eq!(
            out[0].updated_at,
            ts("2026-03-01T00:00:00Z"),
            "survivor inherits the group's MAX(updated_at)"
        );
    }

    /// A PRIVATE canonical repo and a PUBLIC mirror row for the same
    /// (owner, name) collapse to a single survivor whose `is_public` is the
    /// canonical `false`, not the mirror's `true`. `upsert_mirror_repo` always
    /// writes `is_public=true`, so without this the deduped set could carry a
    /// public flag for a locally-private repo and the ref-updates feed gate
    /// would over-serve. Pins the DEDUP_CTE tiebreak so a future regression
    /// that flips the survivor can't leak silently.
    #[sqlx::test]
    async fn deduped_private_canonical_beats_public_mirror(pool: PgPool) {
        let db = db(pool).await;
        // Private canonical row (rec() forces is_public=true, so build inline).
        let mut canonical = rec(
            "uuid-private-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "private canonical",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        canonical.is_public = false;
        db.create_repo(&canonical).await.unwrap();
        // Public mirror row for the same (owner, name): id = "z6Mkwbud/nipmod",
        // is_public = true.
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/mirror", None, false)
            .await
            .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1, "the pair collapses to one logical repo");
        assert_eq!(out[0].owner_did, "did:key:z6Mkwbud", "canonical row wins");
        assert!(
            !out[0].is_public,
            "survivor keeps the canonical private is_public=false, not the mirror's true"
        );
    }

    /// upsert_mirror_repo's own rows dedupe against a canonical twin (proves the
    /// real mirror writer's row shape is classified correctly).
    #[sqlx::test]
    async fn deduped_collapses_real_upsert_mirror_row(pool: PgPool) {
        let db = db(pool).await;
        let canonical = rec(
            "uuid-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "real",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        db.create_repo(&canonical).await.unwrap();
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/mirror", None, false)
            .await
            .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            1,
            "real mirror row collapses with its canonical twin"
        );
        assert_eq!(out[0].owner_did, "did:key:z6Mkwbud", "canonical row wins");
    }

    /// Same name and base58 id but different DID methods (`did:key` vs
    /// `did:gitlawb`) must NOT collapse: the grouping key strips only `did:key:`
    /// and leaves other methods whole, matching crate::api::did_matches. Both the
    /// list (DEDUP_CTE) and count (count_repos_deduped) paths must agree.
    #[sqlx::test]
    async fn deduped_keeps_distinct_did_methods_apart(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-keyed",
            "did:key:z6Mkwbud",
            "nipmod",
            "via did:key",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-gitlawb",
            "did:gitlawb:z6Mkwbud",
            "nipmod",
            "via did:gitlawb",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 2, "distinct DID methods are distinct owners");
        assert_eq!(
            db.count_repos_deduped().await.unwrap(),
            2,
            "count path agrees with the list path",
        );
    }

    /// SQL residual-colon guard: a malformed `did:key:did:gitlawb:X` strips to a
    /// value that still holds a `:`, so the CASE keeps it whole and it does NOT
    /// collapse with a real `did:gitlawb:X`. Proves the SQL key matches the Rust
    /// `strip_prefix(...).filter(|r| !r.contains(':'))` and did_matches.
    #[sqlx::test]
    async fn deduped_did_key_wrapping_a_full_did_stays_distinct(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-wrapped",
            "did:key:did:gitlawb:z6Mkwbud",
            "nipmod",
            "malformed nested DID",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-method",
            "did:gitlawb:z6Mkwbud",
            "nipmod",
            "real method DID",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            2,
            "wrapped full DID stays distinct from the method DID"
        );
        assert_eq!(
            db.count_repos_deduped().await.unwrap(),
            2,
            "count path agrees with the list path",
        );
    }

    /// Empty-residual boundary: `did:key:` matches `LIKE 'did:key:%'`,
    /// `substr(owner_did, 9)` is '', and `position(':' in '')` is 0, so the CASE
    /// keys it to '' just like a bare empty owner, while a real `did:key:z…` keys
    /// separately. Pins that the SQL empty-residual handling matches the Rust
    /// `strip_prefix(...).filter(...)` path (mirrored in the api-level test).
    #[sqlx::test]
    async fn deduped_empty_did_key_residual_keys_to_empty_string(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-empty-didkey",
            "did:key:",
            "nipmod",
            "empty residual",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-empty-bare",
            "",
            "nipmod",
            "empty owner",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-real",
            "did:key:z6Mkwbud",
            "nipmod",
            "real id",
            "2026-01-03T00:00:00Z",
            "2026-01-03T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            2,
            "`did:key:` and the empty owner collapse on the empty key; the real id is separate"
        );
        assert_eq!(
            db.count_repos_deduped().await.unwrap(),
            2,
            "count path agrees with the list path",
        );
    }

    /// Distinct repos are preserved and ordered by most recent activity.
    #[sqlx::test]
    async fn deduped_preserves_distinct_repos_ordered_by_updated(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-a",
            "did:key:z6Aaa",
            "alpha",
            "first",
            "2026-03-01T00:00:00Z",
            "2026-03-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-b",
            "did:key:z6Bbb",
            "beta",
            "second",
            "2026-03-02T00:00:00Z",
            "2026-03-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "beta", "most recently updated first");
        assert_eq!(out[1].name, "alpha");
    }

    /// count_repos_deduped counts logical repos, not raw rows.
    #[sqlx::test]
    async fn count_repos_deduped_counts_logical_repos(pool: PgPool) {
        let db = db(pool).await;
        // One logical repo (canonical + mirror) plus one standalone.
        db.create_repo(&rec(
            "uuid-c",
            "did:key:z6Mkwbud",
            "nipmod",
            "real",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        ))
        .await
        .unwrap();
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/m", None, false)
            .await
            .unwrap();
        db.create_repo(&rec(
            "uuid-d",
            "did:key:z6Other",
            "solo",
            "real",
            "2026-01-16T00:00:00Z",
            "2026-01-16T00:00:00Z",
        ))
        .await
        .unwrap();

        assert_eq!(db.count_repos_deduped().await.unwrap(), 2);
    }

    /// Full tie (same mirror-status and created_at within a group) resolves to a
    /// deterministic survivor by `id ASC`, matching the Rust helper's tiebreak.
    #[sqlx::test]
    async fn deduped_full_tie_resolves_by_id_asc(pool: PgPool) {
        let db = db(pool).await;
        // Two canonical rows in the same (normalized owner, name) group, identical
        // created_at; only the id differs. Different owner_did strings avoid any
        // (owner, name) collision while still normalizing to the same group key.
        db.create_repo(&rec(
            "bbb",
            "did:key:z6Same",
            "repo",
            "real",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "aaa",
            "z6Same",
            "repo",
            "real",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1, "same group collapses");
        assert_eq!(
            out[0].id, "aaa",
            "id ASC breaks a full tie deterministically"
        );
    }

    /// Marker robustness: a canonical row whose `description` is literally
    /// "mirrored from peer" but whose `id` is a UUID is still ranked canonical and
    /// wins over a true slash-id mirror in its group — even though the mirror was
    /// created earlier. Proves dedup keys on the structural id, not the description.
    #[sqlx::test]
    async fn deduped_marker_uses_id_not_description(pool: PgPool) {
        let db = db(pool).await;
        let canonical = rec(
            "uuid-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "mirrored from peer", // user-settable description = the old marker string
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        let mirror = rec(
            "z6Mkwbud/nipmod", // slash id = the real structural marker
            "z6Mkwbud",
            "nipmod",
            "a normal description, not the marker",
            "2026-01-01T00:00:00Z", // earlier: would win on created_at if marker ignored
            "2026-01-01T00:00:00Z",
        );
        db.create_repo(&canonical).await.unwrap();
        db.create_repo(&mirror).await.unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].id, "uuid-canonical",
            "canonical wins by structural id marker despite carrying the mirror description"
        );
    }

    /// A mirror row with no canonical twin survives dedup as the sole entry for its
    /// group (it is not dropped just because it is the mirror).
    #[sqlx::test]
    async fn deduped_mirror_only_group_survives(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6Lonely", "orphan", "/srv/m", None, false)
            .await
            .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            1,
            "a mirror-only group still yields one logical repo"
        );
        assert_eq!(out[0].id, "z6Lonely/orphan");
        assert_eq!(db.count_repos_deduped().await.unwrap(), 1);
    }

    /// Degenerate empty table: deduped list is empty and the count is 0, no error.
    #[sqlx::test]
    async fn deduped_empty_table(pool: PgPool) {
        let db = db(pool).await;
        assert!(db.list_all_repos_deduped().await.unwrap().is_empty());
        assert_eq!(db.count_repos_deduped().await.unwrap(), 0);
    }

    /// count_repos_deduped and list_all_repos_deduped must agree: the count is the
    /// number of logical repos the list returns. Guards the two independent SQL
    /// queries against drifting on the grouping key.
    #[sqlx::test]
    async fn deduped_count_matches_list_len(pool: PgPool) {
        let db = db(pool).await;
        // Two logical repos: one canonical+mirror pair, one standalone canonical.
        db.create_repo(&rec(
            "uuid-1",
            "did:key:z6Pair",
            "shared",
            "real",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.upsert_mirror_repo("z6Pair", "shared", "/srv/m", None, false)
            .await
            .unwrap();
        db.create_repo(&rec(
            "uuid-2",
            "did:key:z6Solo",
            "solo",
            "real",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let list_len = db.list_all_repos_deduped().await.unwrap().len() as i64;
        let count = db.count_repos_deduped().await.unwrap();
        assert_eq!(list_len, 2);
        assert_eq!(count, list_len, "count must equal the deduped list length");
    }

    /// get_repo must prefer the canonical row over the mirror row when both match,
    /// so the visibility gate keys off the canonical row's rules and is_public flag
    /// rather than the mirror's hardcoded public-with-no-rules (issue #124).
    #[sqlx::test]
    async fn get_repo_prefers_canonical_over_mirror(pool: PgPool) {
        let db = db(pool).await;
        let short = "z6Mkwbud";
        let owner_did = "did:key:z6Mkwbud";

        // Mirror row seeded FIRST — hardcoded is_public=true, no visibility rules.
        // Without the ORDER BY fix, fetch_optional returns this row by insertion order,
        // so the test fails (proving it locks in the fix).
        db.upsert_mirror_repo(short, "secret-repo", "/srv/mirror", None, false)
            .await
            .unwrap();

        // Canonical row with is_public=false.
        let canonical = RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "secret-repo".into(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: false,
            default_branch: "main".into(),
            // Date after the mirror (Utc::now()) so that created_at ASC alone
            // would pick the mirror; the CASE WHEN position('/' in id) > 0 term
            // is what makes the canonical row win.
            created_at: ts("2126-01-01T00:00:00Z"),
            updated_at: ts("2126-01-01T00:00:00Z"),
            disk_path: "/srv/secret".into(),
            forked_from: None,
            machine_id: None,
        };
        db.create_repo(&canonical).await.unwrap();

        // Querying with bare short DID should return the canonical row.
        let got = db
            .get_repo(short, "secret-repo")
            .await
            .unwrap()
            .expect("get_repo should find the repo");

        assert_eq!(
            got.owner_did, owner_did,
            "canonical row (did:key: form) must win over mirror row (bare short DID)"
        );
        assert!(
            !got.id.contains('/'),
            "canonical row id must not contain a slash"
        );
        assert!(
            !got.is_public,
            "canonical row's is_public must be preserved"
        );

        // Querying with full did:key: form should also return the canonical row.
        let got_full = db
            .get_repo(owner_did, "secret-repo")
            .await
            .unwrap()
            .expect("get_repo should find the repo with full did:key");

        assert_eq!(
            got_full.owner_did, owner_did,
            "canonical row must be found using full did:key: form"
        );
        assert!(
            !got_full.id.contains('/'),
            "canonical row id must not contain a slash"
        );
        assert!(
            !got_full.is_public,
            "canonical row's is_public must be preserved"
        );
    }

    /// Seed a private canonical plus a public mirror twin for the same owner+name
    /// (mirror inserted first), call authorize_repo_read with caller=None, and
    /// assert Err(RepoNotFound). That locks the property at the gate.
    #[sqlx::test]
    async fn authorize_repo_read_denies_private_canonical_even_with_public_mirror(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let short = "z6Mkwbud";
        let owner_did = "did:key:z6Mkwbud";

        // Mirror row seeded FIRST — hardcoded is_public=true, no visibility rules.
        state
            .db
            .upsert_mirror_repo(short, "secret-repo", "/srv/mirror", None, false)
            .await
            .unwrap();

        // Canonical row with is_public=false.
        let canonical = RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "secret-repo".into(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: false,
            default_branch: "main".into(),
            created_at: ts("2126-01-01T00:00:00Z"),
            updated_at: ts("2126-01-01T00:00:00Z"),
            disk_path: "/srv/secret".into(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&canonical).await.unwrap();

        // call authorize_repo_read with caller=None, and assert Err(RepoNotFound)
        let res = crate::api::authorize_repo_read(&state, short, "secret-repo", None, "/").await;
        assert!(
            matches!(res, Err(crate::error::AppError::RepoNotFound(_))),
            "expected Err(RepoNotFound), got {res:?}"
        );
    }

    /// get_repo still returns the mirror row when no canonical row exists
    /// (mirror-only group), so sync and read paths remain functional.
    #[sqlx::test]
    async fn get_repo_returns_mirror_when_no_canonical(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6Lonely", "orphan", "/srv/m", None, false)
            .await
            .unwrap();

        let got = db
            .get_repo("z6Lonely", "orphan")
            .await
            .unwrap()
            .expect("get_repo should find the mirror");

        assert_eq!(got.id, "z6Lonely/orphan", "mirror row is returned");
        assert!(got.is_public, "mirror row's is_public should be true");
    }

    /// get_repo must NOT match a non-key DID row (e.g. did:gitlawb:) when queried
    /// with the bare short DID — the old LIKE '%:' || $1 || '%' was too broad and
    /// could rank a non-key canonical row ahead of the exact mirror.
    #[sqlx::test]
    async fn get_repo_does_not_match_non_key_did(pool: PgPool) {
        let db = db(pool).await;
        let short = "z6Mkwbud";

        // Mirror row for the bare short DID.
        db.upsert_mirror_repo(short, "shared-name", "/srv/m", None, false)
            .await
            .unwrap();

        // Non-key DID row sharing the same trailing id — must stay distinct.
        let non_key = RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "shared-name".into(),
            owner_did: format!("did:gitlawb:{short}"),
            description: None,
            is_public: false,
            default_branch: "main".into(),
            created_at: ts("2126-01-01T00:00:00Z"),
            updated_at: ts("2126-01-01T00:00:00Z"),
            disk_path: "/srv/other".into(),
            forked_from: None,
            machine_id: None,
        };
        db.create_repo(&non_key).await.unwrap();

        // Querying with the bare short DID must return the mirror, NOT the
        // did:gitlawb row (different DID method, separate owner).
        let got = db
            .get_repo(short, "shared-name")
            .await
            .unwrap()
            .expect("get_repo should find the mirror row");

        assert!(
            got.id.contains('/'),
            "must return the mirror (slash id), not a non-key canonical row"
        );
        assert!(got.is_public, "mirror row's is_public should be true");

        // Querying with the full non-key DID must return that exact row.
        let got = db
            .get_repo(&format!("did:gitlawb:{short}"), "shared-name")
            .await
            .unwrap()
            .expect("get_repo should find the non-key DID row");

        assert!(
            !got.id.contains('/'),
            "must return the non-key canonical row (UUID id)"
        );
        assert!(!got.is_public, "non-key row's is_public must be preserved");
    }

    /// Verify that the Rust `normalize_owner_key` and the `OWNER_KEY_CASE_SQL`
    /// expression agree on every boundary value in the owner-key normalization
    /// set. A mismatch would let the Rust code bind a different key than the SQL
    /// predicate filters on, silently breaking the did:key-only matching contract.
    #[sqlx::test]
    async fn normalize_owner_key_matches_sql_case(pool: PgPool) {
        // The full boundary set: did:key short/full, bare, non-key DIDs,
        // did:key with extra colon, empty, empty residual, uppercase.
        let boundary_values = [
            "did:key:z6Mkfoo",
            "z6Mkfoo",
            "did:gitlawb:z6Mkfoo",
            "did:web:example.com:alice",
            "did:key:did:gitlawb:z6Mkfoo",
            "",
            "did:key:",
            "DID:KEY:z6Mkfoo",
        ];

        // Build a VALUES list with the column aliased as `owner_did` so the
        // OWNER_KEY_CASE_SQL expression (which references `owner_did`) works
        // verbatim — no search-and-replace that could hide a drift.
        let values_sql: String = boundary_values
            .iter()
            .map(|v| format!("('{}'::text)", v))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH data(owner_did) AS (VALUES {values_sql})
             SELECT owner_did, ({key}) AS normalized FROM data ORDER BY owner_did",
            key = super::OWNER_KEY_CASE_SQL
        );

        let rows: Vec<(String, String)> = sqlx::query_as(&sql).fetch_all(&pool).await.unwrap();

        assert_eq!(
            rows.len(),
            boundary_values.len(),
            "every boundary value must produce a row"
        );

        for (val, sql_result) in &rows {
            let rust_result = super::normalize_owner_key(val);
            assert_eq!(
                sql_result, rust_result,
                "normalize_owner_key(\"{val}\") mismatch: Rust = \"{rust_result}\", SQL CASE = \"{sql_result}\""
            );
        }
    }
}

/// Exercises the iCaptcha single-use proof ledger (`icaptcha_consumed_proofs`),
/// which is what gives the gate its anti-replay security value.
#[cfg(test)]
mod icaptcha_ledger_tests {
    use super::Db;
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    /// First sighting of a jti is recorded (allowed); the same jti again is a
    /// replay (rejected); a distinct jti is independently allowed.
    #[sqlx::test]
    async fn consume_proof_jti_single_use(pool: PgPool) {
        let db = db(pool).await;
        let exp = 9_000_000_000i64; // far-future expiry

        assert!(
            db.consume_proof_jti("jti-a", exp).await.unwrap(),
            "first use of a jti is recorded and allowed"
        );
        assert!(
            !db.consume_proof_jti("jti-a", exp).await.unwrap(),
            "re-using the same jti is a replay and must be rejected"
        );
        assert!(
            db.consume_proof_jti("jti-b", exp).await.unwrap(),
            "a different jti is independent and allowed"
        );
    }

    /// The sweep deletes only rows whose `expires_at` is strictly before the
    /// cutoff, returns the deleted count, and leaves unexpired rows intact (so a
    /// still-valid spent proof keeps rejecting replays).
    #[sqlx::test]
    async fn sweep_expired_proofs_removes_only_expired(pool: PgPool) {
        let db = db(pool).await;
        db.consume_proof_jti("old-1", 100).await.unwrap();
        db.consume_proof_jti("old-2", 199).await.unwrap();
        db.consume_proof_jti("fresh", 500).await.unwrap();

        let deleted = db.sweep_expired_proofs(200).await.unwrap();
        assert_eq!(
            deleted, 2,
            "only the two rows with expires_at < 200 are swept"
        );

        // Swept jtis are fresh again; the unexpired one still rejects as a replay.
        assert!(db.consume_proof_jti("old-1", 100).await.unwrap());
        assert!(
            !db.consume_proof_jti("fresh", 500).await.unwrap(),
            "an unexpired spent proof survives the sweep and still blocks replays"
        );
    }

    /// A repo's creation proof round-trips through the side table so it can be
    /// served to mirroring peers; absent for an unknown repo.
    #[sqlx::test]
    async fn repo_proof_roundtrips(pool: PgPool) {
        let db = db(pool).await;
        assert_eq!(db.get_repo_proof_token("nope").await.unwrap(), None);

        db.record_repo_proof("repo-1", "tok.sig", "did:key:zX", 3, "jti-1", 123)
            .await
            .unwrap();
        assert_eq!(
            db.get_repo_proof_token("repo-1").await.unwrap().as_deref(),
            Some("tok.sig")
        );

        // Idempotent: re-recording overwrites in place.
        db.record_repo_proof("repo-1", "tok2.sig", "did:key:zX", 4, "jti-2", 456)
            .await
            .unwrap();
        assert_eq!(
            db.get_repo_proof_token("repo-1").await.unwrap().as_deref(),
            Some("tok2.sig")
        );
    }

    /// Mirror admission spends a jti against a forward retention window, never the
    /// proof's own (already-past) exp. A jti stored that way must survive a sweep
    /// keyed at the proof's original exp, so the token cannot admit a second mirror
    /// after cleanup. Pins the CR3/5 fix (`MIRROR_REPLAY_RETENTION_SECS`).
    #[sqlx::test]
    async fn mirror_jti_retention_survives_sweep_at_proof_exp(pool: PgPool) {
        let db = db(pool).await;
        let proof_exp = 1_000i64; // the proof is already expired on the mirror path
        let retain_until = 9_000_000_000i64; // forward retention window

        assert!(db
            .consume_proof_jti("mirror-jti", retain_until)
            .await
            .unwrap());

        // A sweep at (or just past) the proof's original exp must not free the row.
        let removed = db.sweep_expired_proofs(proof_exp + 1).await.unwrap();
        assert_eq!(
            removed, 0,
            "mirror replay record must outlive the proof's exp"
        );

        assert!(
            !db.consume_proof_jti("mirror-jti", retain_until)
                .await
                .unwrap(),
            "the token must stay spent so it can't admit a second mirror"
        );
    }
}

/// Exercises the iCaptcha propagation quarantine: the `quarantined` flag on
/// repos and its interaction with `upsert_mirror_repo` and the listing surfaces.
#[cfg(test)]
mod icaptcha_quarantine_tests {
    use super::Db;
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    /// A repo defaults to not-quarantined; the flag can be set and cleared, and
    /// reads of an unknown repo are false (not an error).
    #[sqlx::test]
    async fn quarantine_flag_set_and_release(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6owner", "good", "/srv/good", None, false)
            .await
            .unwrap();

        assert!(!db.is_repo_quarantined("z6owner/good").await.unwrap());
        assert!(!db.is_repo_quarantined("does-not-exist").await.unwrap());

        assert_eq!(
            db.set_repo_quarantine("z6owner/good", true).await.unwrap(),
            1
        );
        assert!(db.is_repo_quarantined("z6owner/good").await.unwrap());
        assert_eq!(
            db.list_quarantined_repo_ids().await.unwrap(),
            vec!["z6owner/good".to_string()]
        );

        // Release.
        assert_eq!(
            db.set_repo_quarantine("z6owner/good", false).await.unwrap(),
            1
        );
        assert!(!db.is_repo_quarantined("z6owner/good").await.unwrap());
        assert!(db.list_quarantined_repo_ids().await.unwrap().is_empty());
    }

    /// A mirror admitted quarantined stays quarantined across a re-sync — the
    /// admission decision is made once and an operator's later release (or the
    /// initial quarantine) must not be reverted by ON CONFLICT.
    #[sqlx::test]
    async fn quarantine_preserved_on_resync(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6owner", "garbage", "/srv/g", None, true)
            .await
            .unwrap();
        assert!(db.is_repo_quarantined("z6owner/garbage").await.unwrap());

        // A later re-sync passes quarantined=false but must not clear the flag.
        db.upsert_mirror_repo("z6owner", "garbage", "/srv/g", None, false)
            .await
            .unwrap();
        assert!(
            db.is_repo_quarantined("z6owner/garbage").await.unwrap(),
            "re-sync must preserve the prior quarantine decision"
        );
    }

    /// Quarantined repos are withheld from the deduped listing surfaces.
    #[sqlx::test]
    async fn listings_exclude_quarantined(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6good", "ok", "/srv/ok", None, false)
            .await
            .unwrap();
        db.upsert_mirror_repo("z6bad", "spam", "/srv/spam", None, true)
            .await
            .unwrap();

        let names: Vec<String> = db
            .list_all_repos_deduped()
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert!(names.contains(&"ok".to_string()));
        assert!(
            !names.contains(&"spam".to_string()),
            "quarantined mirror must not appear in listings"
        );

        let with_stars = db.list_all_repos_deduped_with_stars(None).await.unwrap();
        assert!(with_stars.iter().all(|(r, _)| r.name != "spam"));
    }

    /// `update_trust_score` must never create an agent row. Registration (behind
    /// the iCaptcha gate) is the only way in; otherwise a push/issue/PR from a
    /// deregistered DID would silently re-register it and bypass the gate.
    #[sqlx::test]
    async fn update_trust_score_never_creates_agent(pool: PgPool) {
        let db = db(pool).await;
        let did = "did:key:zNeverRegistered";

        // Unregistered DID: updating its score is a no-op, not an insert.
        db.update_trust_score(did, 0.9).await.unwrap();
        assert!(
            db.get_agent(did).await.unwrap().is_none(),
            "update_trust_score must not resurrect an unregistered DID"
        );

        // Once genuinely registered, the score updates in place.
        db.register_agent(did, &[]).await.unwrap();
        db.update_trust_score(did, 0.9).await.unwrap();
        assert_eq!(db.get_trust_score(did).await.unwrap(), 0.9);
    }
}

#[cfg(test)]
mod ref_update_keyset_paging_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    fn rru(id: &str, ts: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:zN".into(),
            pusher_did: "did:key:zP".into(),
            repo: "z6MkOwner/openrepo".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".into(),
            new_sha: "1".into(),
            timestamp: ts.into(),
            cert_id: None,
            received_at: ts.into(),
            from_peer: "peer".into(),
            owner_did: None,
        }
    }

    async fn seed_r1_to_r4(db: &Db) {
        for i in 1..=4 {
            db.insert_ref_update(&rru(
                &format!("r{i}"),
                &format!("2026-07-01T10:00:0{i}+00:00"),
            ))
            .await
            .unwrap();
        }
    }

    // Documents the bug jatmn flagged: OFFSET paging re-reads a page-1 row when a
    // newer row is inserted between page reads (the newer row shifts every offset).
    #[sqlx::test]
    async fn offset_paging_duplicates_a_row_under_concurrent_insert(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        seed_r1_to_r4(&db).await;

        let offset_page = |limit: i64, offset: i64| {
            let pool = db.pool.clone();
            async move {
                sqlx::query_scalar::<_, String>(
                    "SELECT id FROM received_ref_updates \
                     ORDER BY timestamp DESC, id DESC LIMIT $1 OFFSET $2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&pool)
                .await
                .unwrap()
            }
        };

        let p1 = offset_page(2, 0).await;
        assert_eq!(p1, vec!["r4", "r3"], "offset page 1");
        // concurrent insert of a newer row shifts every later offset by one
        db.insert_ref_update(&rru("r5", "2026-07-01T10:00:09+00:00"))
            .await
            .unwrap();
        let p2 = offset_page(2, 2).await;
        assert!(
            p2.contains(&"r3".to_string()),
            "OFFSET paging re-reads r3 after the concurrent insert (the bug keyset fixes); got {p2:?}"
        );
    }

    // The fix: keyset paging on (timestamp, id) reads strictly older rows each
    // page, so a concurrent newer insert cannot duplicate or skip a row.
    #[sqlx::test]
    async fn keyset_paging_is_stable_under_concurrent_insert(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        seed_r1_to_r4(&db).await;

        let p1 = db.list_ref_updates_keyset(None, 2, None).await.unwrap();
        let p1_ids: Vec<String> = p1.iter().map(|u| u.id.clone()).collect();
        assert_eq!(p1_ids, vec!["r4", "r3"], "keyset page 1");
        let last = p1.last().unwrap();
        let cursor = (last.timestamp.clone(), last.id.clone());

        // concurrent insert of a newer row between page reads
        db.insert_ref_update(&rru("r5", "2026-07-01T10:00:09+00:00"))
            .await
            .unwrap();

        let p2 = db
            .list_ref_updates_keyset(None, 2, Some((cursor.0.as_str(), cursor.1.as_str())))
            .await
            .unwrap();
        let p2_ids: Vec<String> = p2.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p2_ids,
            vec!["r2", "r1"],
            "keyset page 2 reads strictly older rows, unaffected by the concurrent insert"
        );

        let all: Vec<String> = p1_ids.into_iter().chain(p2_ids).collect();
        let uniq: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(uniq.len(), 4, "no row appears twice across pages");
        assert!(
            !all.iter().any(|id| id == "r5"),
            "a row inserted above the scan window is not folded in mid-scan"
        );
    }
}

#[cfg(test)]
mod ref_update_keyset_repo_filtered_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    fn rru_repo(id: &str, ts: &str, repo: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:zN".into(),
            pusher_did: "did:key:zP".into(),
            repo: repo.into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".into(),
            new_sha: "1".into(),
            timestamp: ts.into(),
            cert_id: None,
            received_at: ts.into(),
            from_peer: "peer".into(),
            owner_did: None,
        }
    }

    // Exercises the (Some(repo), Some(after)) keyset branch: a repo-filtered
    // multi-page continuation that emits `WHERE repo=$1 AND (timestamp,id)<($2,$3)`
    // with four binds. Also confirms the repo filter holds across pages, noise
    // rows are excluded, and a concurrent insert does not duplicate or skip.
    #[sqlx::test]
    async fn keyset_repo_filtered_multipage_stable_under_concurrent_insert(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        let target = "z6MkOwner/target";
        let other = "z6MkOwner/other";

        // 3 target rows (older) + 2 noise rows for another repo (newer, so they
        // sort to the front of the global order and must be filtered out).
        for (id, ts) in [("T1", "01"), ("T2", "02"), ("T3", "03")] {
            db.insert_ref_update(&rru_repo(
                id,
                &format!("2026-07-01T10:00:{ts}+00:00"),
                target,
            ))
            .await
            .unwrap();
        }
        for (id, ts) in [("O1", "04"), ("O2", "05")] {
            db.insert_ref_update(&rru_repo(
                id,
                &format!("2026-07-01T10:00:{ts}+00:00"),
                other,
            ))
            .await
            .unwrap();
        }

        // page 1: (Some(repo), None) -> two newest TARGET rows only
        let p1 = db
            .list_ref_updates_keyset(Some(target), 2, None)
            .await
            .unwrap();
        let p1_ids: Vec<String> = p1.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p1_ids,
            vec!["T3", "T2"],
            "repo-filtered page 1 excludes other-repo rows"
        );
        assert!(
            p1.iter().all(|u| u.repo == target),
            "no noise rows on page 1"
        );
        let last = p1.last().unwrap();
        let cursor = (last.timestamp.clone(), last.id.clone());

        // concurrent insert of a newer TARGET row between page reads
        db.insert_ref_update(&rru_repo("T4", "2026-07-01T10:00:06+00:00", target))
            .await
            .unwrap();

        // page 2: (Some(repo), Some(after)) -> the four-bind continuation branch
        let p2 = db
            .list_ref_updates_keyset(
                Some(target),
                2,
                Some((cursor.0.as_str(), cursor.1.as_str())),
            )
            .await
            .unwrap();
        let p2_ids: Vec<String> = p2.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p2_ids,
            vec!["T1"],
            "repo-filtered keyset page 2 reads only older target rows"
        );
        assert!(
            p2.iter().all(|u| u.repo == target),
            "no noise rows on page 2"
        );

        let all: Vec<String> = p1_ids.into_iter().chain(p2_ids).collect();
        let uniq: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(uniq.len(), 3, "each target row exactly once across pages");
        assert!(
            !all.iter().any(|id| id == "T4"),
            "concurrent newer row not folded in mid-scan"
        );
    }
}

#[cfg(test)]
mod ref_update_keyset_same_timestamp_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    fn row(id: &str, ts: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:zN".into(),
            pusher_did: "did:key:zP".into(),
            repo: "z6MkOwner/openrepo".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".into(),
            new_sha: "1".into(),
            timestamp: ts.into(),
            cert_id: None,
            received_at: ts.into(),
            from_peer: "peer".into(),
            owner_did: None,
        }
    }

    // Load-bearing for the `id` half of the (timestamp, id) keyset cursor: all
    // rows share ONE timestamp, so ordering and the page boundary fall entirely
    // on `id DESC`. A timestamp-only cursor would return nothing for page 2 and
    // silently skip b and a; the (timestamp, id) tie-break must advance instead.
    #[sqlx::test]
    async fn keyset_advances_within_an_equal_timestamp_run(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        let ts = "2026-07-01T10:00:00+00:00";
        for id in ["a", "b", "c", "d"] {
            db.insert_ref_update(&row(id, ts)).await.unwrap();
        }

        // id DESC over equal timestamps: d, c, b, a
        let p1 = db.list_ref_updates_keyset(None, 2, None).await.unwrap();
        let p1_ids: Vec<String> = p1.iter().map(|u| u.id.clone()).collect();
        assert_eq!(p1_ids, vec!["d", "c"], "page 1 by id DESC");
        let last = p1.last().unwrap();

        // page boundary lands INSIDE the equal-timestamp group (cursor = (ts, "c"))
        let p2 = db
            .list_ref_updates_keyset(None, 2, Some((last.timestamp.as_str(), last.id.as_str())))
            .await
            .unwrap();
        let p2_ids: Vec<String> = p2.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p2_ids,
            vec!["b", "a"],
            "keyset must advance by id within an equal-timestamp run (a timestamp-only cursor would skip these)"
        );

        let all: Vec<String> = p1_ids.into_iter().chain(p2_ids).collect();
        let uniq: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(
            uniq.len(),
            4,
            "no dup or skip across a same-timestamp page boundary"
        );
    }
}

#[cfg(test)]
mod ref_certificate_tests {
    use super::{Db, RefCertificate, RepoRecord};
    use chrono::Utc;
    use sqlx::PgPool;
    use std::sync::atomic::{AtomicI64, Ordering};

    static NEXT_SEQ: AtomicI64 = AtomicI64::new(1);

    fn next_seq() -> i64 {
        NEXT_SEQ.fetch_add(1, Ordering::Relaxed)
    }

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn make_cert(
        id: &str,
        repo_id: &str,
        ref_name: &str,
        old_sha: &str,
        new_sha: &str,
        issued_at: &str,
    ) -> RefCertificate {
        RefCertificate {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.to_string(),
            new_sha: new_sha.to_string(),
            pusher_did: "did:key:zPUSHER".to_string(),
            node_did: "did:key:zNODE".to_string(),
            signature: "sig".to_string(),
            issued_at: issued_at.to_string(),
            seq: next_seq(),
            prev: "0".repeat(64),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        }
    }

    #[sqlx::test]
    async fn list_ref_certificates_respects_limit(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = uuid::Uuid::new_v4().to_string();

        // Create a repo to satisfy FK
        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "limit-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/limit-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // Insert 5 certs with descending issued_at
        for i in 0..5 {
            db.insert_ref_certificate(&make_cert(
                &format!("cert-{i}"),
                &repo_id,
                &format!("refs/heads/feature-{i}"),
                "0000",
                "1111",
                &format!("2026-07-03T20:0{i}:00Z"),
            ))
            .await
            .unwrap();
        }

        // limit=2 returns only 2
        let certs = db.list_ref_certificates(&repo_id, 2).await.unwrap();
        assert_eq!(certs.len(), 2, "LIMIT 2 must return exactly 2 certs");
        assert_eq!(certs[0].id, "cert-4", "most recent first");
        assert_eq!(certs[1].id, "cert-3", "second most recent");

        // limit=10 returns all 5 (no padding)
        let all = db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(all.len(), 5, "LIMIT >= row count returns all rows");
    }

    #[sqlx::test]
    async fn insert_ref_certificate_append_only(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = uuid::Uuid::new_v4().to_string();

        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "append-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/append-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // First insert
        db.insert_ref_certificate(&make_cert(
            "cert-first",
            &repo_id,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-03T20:00:00Z",
        ))
        .await
        .unwrap();

        // Second insert for the same ref — append-only means both rows exist
        db.insert_ref_certificate(&make_cert(
            "cert-second",
            &repo_id,
            "refs/heads/main",
            "aaaa",
            "bbbb",
            "2026-07-03T21:00:00Z",
        ))
        .await
        .unwrap();

        // Two rows now exist for this ref (append-only)
        let certs = db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(certs.len(), 2, "append-only must keep both rows");
        assert_eq!(certs[0].id, "cert-second", "most recent first");
        assert_eq!(certs[1].id, "cert-first", "second most recent");
    }

    #[sqlx::test]
    async fn list_ref_certificates_clamps_negative_limit(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = uuid::Uuid::new_v4().to_string();

        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "clamp-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/clamp-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        db.insert_ref_certificate(&make_cert(
            "clamp-1",
            &repo_id,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-03T20:00:00Z",
        ))
        .await
        .unwrap();

        // Negative limit is clamped to 1 at the DB boundary
        let certs = db.list_ref_certificates(&repo_id, -5).await.unwrap();
        assert_eq!(certs.len(), 1, "negative limit clamped to min 1");
        assert_eq!(certs[0].id, "clamp-1");

        // Zero limit also clamped to 1
        let certs = db.list_ref_certificates(&repo_id, 0).await.unwrap();
        assert_eq!(certs.len(), 1, "zero limit clamped to min 1");
        assert_eq!(certs[0].id, "clamp-1");
    }

    #[sqlx::test]
    async fn list_ref_certificates_empty_repo_returns_empty(pool: PgPool) {
        let db = db(pool).await;
        let certs = db
            .list_ref_certificates("nonexistent-repo-id", 10)
            .await
            .unwrap();
        assert!(certs.is_empty());
    }

    /// NOTE: this test hand-copies the migration SQL as string literals and will
    /// silently drift if the v10 migration block changes.  The load-bearing
    /// upgrade-path test is `v10_upgrade_dedup_via_migration`, which fires the
    /// real MIGRATIONS[v10] entry via run_migrations().
    #[sqlx::test]
    async fn v10_dedup_removes_old_duplicates(pool: PgPool) {
        let db = db(pool.clone()).await;

        // Drop the unique indexes so we can simulate pre-v10 duplicate rows.
        // v13's (repo_id, seq) index must also be removed because raw INSERTS
        // without an explicit seq all get DEFAULT 1.
        sqlx::query("DROP INDEX IF EXISTS idx_ref_certs_repo_ref")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP INDEX IF EXISTS idx_ref_certs_repo_seq")
            .execute(&pool)
            .await
            .unwrap();

        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "dedup-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/dedup-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // Insert two rows for the same (repo_id, ref_name) with raw INSERT
        // (no ON CONFLICT — the unique index was dropped above to simulate a
        // pre-v10 database). The second row has the newer timestamp and should
        // survive the dedup.
        sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("keep-id")
        .bind(&repo_id)
        .bind("refs/heads/main")
        .bind("0000")
        .bind("1111")
        .bind("did:key:zPUSHER")
        .bind("did:key:zNODE")
        .bind("sig-first")
        .bind("2026-07-03T20:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("remove-id")
        .bind(&repo_id)
        .bind("refs/heads/main")
        .bind("aaaa")
        .bind("bbbb")
        .bind("did:key:zPUSHER")
        .bind("did:key:zNODE")
        .bind("sig-dup")
        .bind("2026-07-03T19:00:00Z") // older timestamp → should be removed
        .execute(&pool)
        .await
        .unwrap();

        // Apply the v10 dedup logic: keep the most recent per (repo_id, ref_name).
        sqlx::query(
            "DELETE FROM ref_certificates
             WHERE id IN (
                 SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (
                         PARTITION BY repo_id, ref_name ORDER BY issued_at DESC, id DESC
                     ) AS rn
                     FROM ref_certificates
                 ) dups WHERE dups.rn > 1
             )",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Re-create the unique index — must succeed after dedup.
        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_ref_certs_repo_ref ON ref_certificates(repo_id, ref_name)")
            .execute(&pool)
            .await
            .unwrap();

        // Only the most recent row survives.
        let certs = db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(certs.len(), 1, "dedup leaves one row per ref");
        assert_eq!(
            certs[0].id, "keep-id",
            "dedup keeps the most recent (later issued_at)"
        );
    }

    /// INV-7: upgrade-path test — seed a database at v9 with duplicate
    /// ref_certificates, then let the real v10 migration fire via
    /// run_migrations().  This exercises the migration code path rather than
    /// hand-copying its SQL, so the test stays in sync with MIGRATIONS[v10].
    #[sqlx::test]
    async fn v10_upgrade_dedup_via_migration(pool: PgPool) {
        // 1. Bootstrap schema via the full migration chain.
        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        // 2. Roll back to v9: remove unique indexes and the
        //    schema_migrations record so that run_migrations() re-applies v10.
        //    Also drop v13's (repo_id, seq) index so raw INSERTS below work.
        sqlx::query("DROP INDEX IF EXISTS idx_ref_certs_repo_ref")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP INDEX IF EXISTS idx_ref_certs_repo_seq")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 10")
            .execute(&pool)
            .await
            .unwrap();

        // 3. Seed repos and duplicate certs (raw INSERT — no ON CONFLICT
        //    since the index is gone).
        let r1 = uuid::Uuid::new_v4().to_string();
        let r2 = uuid::Uuid::new_v4().to_string();
        for (id, name) in [(&r1, "upgrade-repo-a"), (&r2, "upgrade-repo-b")] {
            db.create_repo(&RepoRecord {
                id: id.clone(),
                name: name.into(),
                owner_did: "did:key:zOWNER".into(),
                description: None,
                is_public: true,
                default_branch: "main".into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                disk_path: format!("/tmp/{name}"),
                forked_from: None,
                machine_id: None,
            })
            .await
            .unwrap();
        }

        // Helper macro for raw INSERT.
        macro_rules! insert_cert {
            ($id:expr, $repo_id:expr, $ref_name:expr, $old_sha:expr, $new_sha:expr, $issued_at:expr) => {
                sqlx::query(
                    "INSERT INTO ref_certificates
                     (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                )
                .bind($id)
                .bind($repo_id)
                .bind($ref_name)
                .bind($old_sha)
                .bind($new_sha)
                .bind("did:key:zPUSHER")
                .bind("did:key:zNODE")
                .bind("sig")
                .bind($issued_at)
                .execute(&pool)
                .await
                .unwrap();
            };
        }

        // Repo A, ref "main": two rows with distinct timestamps.
        insert_cert!(
            "dup-a-old",
            &r1,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );
        insert_cert!(
            "dup-a-new",
            &r1,
            "refs/heads/main",
            "aaaa",
            "bbbb",
            "2026-07-02T10:00:00Z"
        );

        // Repo A, ref "feature": two rows with IDENTICAL timestamps — the
        // id-DESC tiebreaker must choose the higher id (alphabetical: "z" > "a").
        insert_cert!(
            "dup-feat-a",
            &r1,
            "refs/heads/feature",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );
        insert_cert!(
            "dup-feat-z",
            &r1,
            "refs/heads/feature",
            "cccc",
            "dddd",
            "2026-07-01T10:00:00Z"
        );

        // Repo B, ref "main": two rows with distinct timestamps.
        insert_cert!(
            "dup-b-old",
            &r2,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );
        insert_cert!(
            "dup-b-new",
            &r2,
            "refs/heads/main",
            "eeee",
            "ffff",
            "2026-07-02T10:00:00Z"
        );

        // A non-duplicate singleton row (single row per ref) — must survive
        // untouched.
        insert_cert!(
            "singleton",
            &r2,
            "refs/heads/singleton",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );

        // 4. Run migrations — the v10 dedup fires inside run_pending_migrations.
        db.run_migrations().await.unwrap();

        // 5. Assert each ref has exactly one survivor.
        let all_r1 = db.list_ref_certificates(&r1, 10).await.unwrap();
        assert_eq!(all_r1.len(), 2, "repo A: 2 refs, 1 survivor each");

        let r1_main: Vec<_> = all_r1
            .iter()
            .filter(|c| c.ref_name == "refs/heads/main")
            .collect();
        assert_eq!(r1_main.len(), 1, "repo A main deduped to one row");
        assert_eq!(r1_main[0].id, "dup-a-new", "newer timestamp survives");
        assert_eq!(r1_main[0].old_sha, "aaaa");
        assert_eq!(r1_main[0].new_sha, "bbbb");

        let r1_feat: Vec<_> = all_r1
            .iter()
            .filter(|c| c.ref_name == "refs/heads/feature")
            .collect();
        assert_eq!(r1_feat.len(), 1, "repo A feature deduped to one row");
        assert_eq!(
            r1_feat[0].id, "dup-feat-z",
            "same-timestamp tiebreaker: higher id wins (id DESC)"
        );

        let all_r2 = db.list_ref_certificates(&r2, 10).await.unwrap();
        assert_eq!(all_r2.len(), 2, "repo B: 2 refs, 1 survivor each");

        let r2_main: Vec<_> = all_r2
            .iter()
            .filter(|c| c.ref_name == "refs/heads/main")
            .collect();
        assert_eq!(r2_main.len(), 1, "repo B main deduped to one row");
        assert_eq!(r2_main[0].id, "dup-b-new", "newer timestamp survives");

        let all_r2 = db.list_ref_certificates(&r2, 10).await.unwrap();
        assert_eq!(
            all_r2.iter().filter(|c| c.id == "singleton").count(),
            1,
            "non-duplicate singleton untouched"
        );

        // 6. Verify the unique indexes exist: an append-only INSERT for
        //    a new (repo_id, ref_name) succeeds, and a raw INSERT for an
        //    existing (repo_id, ref_name) must fail (catches regressions).
        db.insert_ref_certificate(&make_cert(
            "post-migration-insert",
            &r1,
            "refs/heads/new-ref",
            "1111",
            "2222",
            "2026-07-03T10:00:00Z",
        ))
        .await
        .unwrap();
        let after_migration = db.list_ref_certificates(&r1, 10).await.unwrap();
        assert!(
            after_migration
                .iter()
                .any(|c| c.id == "post-migration-insert"),
            "append-only insert for new ref succeeds"
        );

        // A raw INSERT for the same (repo_id, ref_name) must now fail.
        let err = sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("should-fail")
        .bind(&r1)
        .bind("refs/heads/main")
        .bind("xxxx")
        .bind("yyyy")
        .bind("did:key:zPUSHER")
        .bind("did:key:zNODE")
        .bind("sig")
        .bind("2026-07-04T10:00:00Z")
        .execute(&pool)
        .await;
        assert!(
            err.is_err(),
            "raw duplicate INSERT must be rejected by the unique index"
        );
    }

    /// INV-7: upgrade-path test for migration v13 — seed a database at v12
    /// with multiple same-repo/different-ref certificates (all at seq=1),
    /// then let run_migrations() apply v13 and verify (a) seq values are
    /// distinct per repo, (b) the (repo_id, seq) unique index exists and
    /// rejects a raw INSERT with a colliding seq.
    #[sqlx::test]
    async fn v13_seq_backfill_via_migration(pool: PgPool) {
        // 1. Bootstrap schema via the full migration chain.
        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        // 2. Roll back to v12: drop the (repo_id, seq) index and the
        //    schema_migrations record for v13 so run_migrations() re-applies it.
        sqlx::query("DROP INDEX IF EXISTS idx_ref_certs_repo_seq")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 13")
            .execute(&pool)
            .await
            .unwrap();

        // 3. Seed repos and certs (all with seq=DEFAULT 1).
        let r1 = uuid::Uuid::new_v4().to_string();
        db.create_repo(&RepoRecord {
            id: r1.clone(),
            name: "v13-upgrade-a".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/v13-upgrade-a".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // Insert 3 certs for repo r1 on different refs — all with seq=1 (DEFAULT).
        for (i, ref_name) in ["refs/heads/main", "refs/heads/feature", "refs/heads/dev"]
            .iter()
            .enumerate()
        {
            sqlx::query(
                "INSERT INTO ref_certificates
                 (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(format!("v13-cert-{i}"))
            .bind(&r1)
            .bind(ref_name)
            .bind("0000")
            .bind("1111")
            .bind("did:key:zPUSHER")
            .bind("did:key:zNODE")
            .bind("sig")
            .bind(format!("2026-07-0{}T12:00:00Z", i + 1))
            .execute(&pool)
            .await
            .unwrap();
        }

        // 4. Re-run migrations — v13 backfills seq.
        db.run_migrations().await.unwrap();

        // 5. Assert distinct seq values per repo.
        let certs = db.list_ref_certificates(&r1, 10).await.unwrap();
        assert_eq!(certs.len(), 3, "all three certs survive the migration");
        let mut seqs: Vec<i64> = certs.iter().map(|c| c.seq).collect();
        seqs.sort();
        assert_eq!(seqs, vec![1, 2, 3], "seq values are distinct and ascending");

        // 6. Raw INSERT with colliding seq must be rejected by the unique index.
        let err = sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("collide-seq")
        .bind(&r1)
        .bind("refs/heads/other")
        .bind("xxxx")
        .bind("yyyy")
        .bind("did:key:zPUSHER")
        .bind("did:key:zNODE")
        .bind("sig-collide")
        .bind("2026-07-10T12:00:00Z")
        .execute(&pool)
        .await;
        assert!(
            err.is_err(),
            "raw INSERT with default seq=1 must be rejected by the unique index"
        );
    }

    #[sqlx::test]
    async fn get_most_recent_cert_returns_highest_seq(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "most-recent-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/most-recent-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // Insert certs with increasing seq
        for i in 1..=3 {
            let mut cert = make_cert(
                &format!("cert-seq-{i}"),
                &repo_id,
                "refs/heads/main",
                "0000",
                "1111",
                &format!("2026-07-03T20:0{i}:00Z"),
            );
            cert.seq = i;
            db.insert_ref_certificate(&cert).await.unwrap();
        }

        let most_recent = db.get_most_recent_cert(&repo_id).await.unwrap();
        assert!(most_recent.is_some(), "should find a cert");
        assert_eq!(most_recent.unwrap().seq, 3, "highest seq returned");
    }

    #[sqlx::test]
    async fn get_most_recent_cert_returns_none_for_empty_repo(pool: PgPool) {
        let db = db(pool).await;
        let result = db
            .get_most_recent_cert("nonexistent-repo-id")
            .await
            .unwrap();
        assert!(result.is_none(), "empty repo returns None");
    }
}

#[cfg(test)]
mod arweave_anchor_tests {
    use super::{Db, RecordAnchorInputV2};
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    #[sqlx::test]
    async fn record_and_list_arweave_anchors(pool: PgPool) {
        let db = db(pool).await;

        let input = RecordAnchorInputV2 {
            repo: "alice/myrepo",
            owner_did: "did:key:zOWNER",
            ref_name: "refs/heads/main",
            old_sha: "0000000000000000000000000000000000000000",
            new_sha: "1111111111111111111111111111111111111111",
            cid: Some("bafyreib5..."),
            arweave_tx_id: "test-tx-id-123",
            node_did: "did:key:zNODE",
            cert_id: None,
        };

        db.record_arweave_anchor(&input).await.unwrap();

        let anchors = db
            .list_arweave_anchors(Some("alice/myrepo"), 10)
            .await
            .unwrap();
        assert_eq!(anchors.len(), 1, "one anchor recorded");
        assert_eq!(anchors[0].status, "pending", "default status is pending");
        assert_eq!(anchors[0].arweave_tx_id, "test-tx-id-123");
    }
}
#[cfg(test)]
mod ref_update_db_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn update(
        id: &str,
        repo: &str,
        owner_did: Option<&str>,
        ref_name: &str,
        sha: &str,
    ) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.to_string(),
            node_did: "did:key:zNode".into(),
            pusher_did: "did:key:zPusher".into(),
            repo: repo.to_string(),
            owner_did: owner_did.map(|s| s.to_string()),
            ref_name: ref_name.to_string(),
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: sha.to_string(),
            timestamp: "2026-07-02T12:00:00Z".into(),
            cert_id: None,
            received_at: "2026-07-02T12:00:01Z".into(),
            from_peer: "12D3KooWTest".into(),
        }
    }

    #[sqlx::test]
    async fn insert_and_list_with_owner_did(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u1",
            "zOwner/myrepo",
            Some("did:key:zOwner"),
            "refs/heads/main",
            "aaaa",
        ))
        .await
        .unwrap();

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].owner_did.as_deref(), Some("did:key:zOwner"));
        assert_eq!(all[0].repo, "zOwner/myrepo");
    }

    #[sqlx::test]
    async fn insert_and_list_without_owner_did(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u2",
            "zOwner/myrepo",
            None,
            "refs/heads/main",
            "bbbb",
        ))
        .await
        .unwrap();

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].owner_did, None);
    }

    #[sqlx::test]
    async fn list_repo_ref_updates_filters_by_repo(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u3",
            "alice/repo1",
            Some("did:key:zAlice"),
            "refs/heads/main",
            "cccc",
        ))
        .await
        .unwrap();
        db.insert_ref_update(&update(
            "u4",
            "bob/repo2",
            Some("did:key:zBob"),
            "refs/heads/feat",
            "dddd",
        ))
        .await
        .unwrap();

        let alice_events = db
            .list_ref_updates_keyset(Some("alice/repo1"), 100, None)
            .await
            .unwrap();
        assert_eq!(alice_events.len(), 1);
        assert_eq!(alice_events[0].id, "u3");
        assert_eq!(alice_events[0].owner_did.as_deref(), Some("did:key:zAlice"));

        let bob_events = db
            .list_ref_updates_keyset(Some("bob/repo2"), 100, None)
            .await
            .unwrap();
        assert_eq!(bob_events.len(), 1);
        assert_eq!(bob_events[0].id, "u4");
        assert_eq!(bob_events[0].owner_did.as_deref(), Some("did:key:zBob"));

        let empty = db
            .list_ref_updates_keyset(Some("other/repo"), 100, None)
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[sqlx::test]
    async fn list_ref_updates_filtered_by_repo(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u5",
            "ownerA/proj",
            Some("did:key:zA"),
            "refs/heads/main",
            "eeee",
        ))
        .await
        .unwrap();
        db.insert_ref_update(&update(
            "u6",
            "ownerB/proj",
            Some("did:web:host:zB"),
            "refs/heads/main",
            "ffff",
        ))
        .await
        .unwrap();

        let filtered = db
            .list_ref_updates_keyset(Some("ownerA/proj"), 100, None)
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "u5");

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[sqlx::test]
    async fn insert_update_idempotent_on_conflict(pool: PgPool) {
        let db = db(pool).await;
        let u = update(
            "u7",
            "repo/x",
            Some("did:key:zX"),
            "refs/heads/main",
            "gggg",
        );
        db.insert_ref_update(&u).await.unwrap();
        db.insert_ref_update(&u).await.unwrap();

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].new_sha, "gggg");
    }
}
