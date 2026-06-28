use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
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
    pool: PgPool,
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

    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
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
                issued_at   TEXT NOT NULL
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
                id          TEXT NOT NULL PRIMARY KEY,
                repo        TEXT NOT NULL,
                owner_did   TEXT NOT NULL,
                ref_name    TEXT NOT NULL,
                old_sha     TEXT NOT NULL,
                new_sha     TEXT NOT NULL,
                cid         TEXT,
                irys_tx_id  TEXT NOT NULL,
                arweave_url TEXT NOT NULL,
                node_did    TEXT NOT NULL,
                anchored_at TEXT NOT NULL
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
];

// ── Repos ─────────────────────────────────────────────────────────────────────

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
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{owner_short}/{name}");
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch,
                                created_at, updated_at, disk_path, machine_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_repo(&self, owner_did: &str, name: &str) -> Result<Option<RepoRecord>> {
        let row = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos
             WHERE (owner_did = $1 OR owner_did LIKE '%:' || $1 || '%') AND name = $2",
        )
        .bind(owner_did)
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
    const DEDUP_CTE: &'static str = "WITH deduped AS (
                 SELECT DISTINCT ON (CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END, name)
                     id, name, owner_did, description, is_public, default_branch,
                     created_at,
                     -- group MAX, not the canonical row's own value: pushes that
                     -- arrive via gossip touch only the mirror row, so the
                     -- canonical updated_at goes stale
                     MAX(updated_at) OVER (
                         PARTITION BY CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END, name
                     ) AS updated_at,
                     disk_path, forked_from, machine_id
                 FROM repos
                 -- Match the owner filter on the same did:key-aware owner key the
                 -- dedup groups on, so a full did:key: form matches a bare-owner
                 -- mirror row (and vice versa) exactly as crate::api::did_matches
                 -- does. Callers bind the already-normalized key ($1).
                 WHERE ($1::text IS NULL OR (CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END) = $1)
                 ORDER BY CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END, name,
                     -- mirror rows carry a slash-form id (\"{owner_short}/{name}\"),
                     -- written only by upsert_mirror_repo; canonical ids are UUIDs.
                     -- Rank canonical (no slash) ahead of the mirror in each group,
                     -- keyed on the structural id, not the user-settable description.
                     CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END,
                     created_at ASC, id ASC
             )";

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
        let owner_key = owner_filter.map(|o| match o.strip_prefix("did:key:") {
            Some(rest) if !rest.contains(':') => rest,
            _ => o,
        });
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
            Self::DEDUP_CTE
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
    /// the group's most recent activity. Shares `DEDUP_CTE` with the paged path so
    /// the dedup rule cannot drift; binds a NULL owner filter (all rows).
    pub async fn list_all_repos_deduped(&self) -> Result<Vec<RepoRecord>> {
        let sql = format!(
            "{}
             SELECT d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id
             FROM deduped d
             ORDER BY d.updated_at DESC",
            Self::DEDUP_CTE
        );
        let rows = sqlx::query(&sql)
            .bind(None::<&str>)
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
        let row = sqlx::query(
            "SELECT COUNT(DISTINCT (CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END, name)) AS cnt FROM repos",
        )
        .fetch_one(&self.pool)
        .await?;
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

    pub async fn get_trust_score(&self, agent_did: &str) -> Result<f64> {
        let row = sqlx::query("SELECT trust_score FROM agents WHERE did = $1")
            .bind(agent_did)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get::<f64, _>("trust_score")).unwrap_or(0.0))
    }

    pub async fn update_trust_score(&self, agent_did: &str, score: f64) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO agents (did, trust_score, capabilities, registered_at)
             VALUES ($1, $2, '[]', $3)
             ON CONFLICT(did) DO UPDATE SET trust_score = $2",
        )
        .bind(agent_did)
        .bind(score)
        .bind(&now)
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
    pub async fn insert_ref_certificate(&self, cert: &RefCertificate) -> Result<()> {
        sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_ref_certificates(&self, repo_id: &str) -> Result<Vec<RefCertificate>> {
        let rows = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at
             FROM ref_certificates WHERE repo_id = $1 ORDER BY issued_at DESC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_cert).collect())
    }

    pub async fn get_ref_certificate(&self, id: &str) -> Result<Option<RefCertificate>> {
        let row = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at
             FROM ref_certificates WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_cert))
    }
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
              cert_id, received_at, from_peer)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_ref_updates(&self, limit: i64) -> Result<Vec<ReceivedRefUpdate>> {
        let rows = sqlx::query(
            "SELECT id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, timestamp,
                    cert_id, received_at, from_peer
             FROM received_ref_updates ORDER BY timestamp DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_ref_update).collect())
    }

    pub async fn list_repo_ref_updates(
        &self,
        repo: &str,
        limit: i64,
    ) -> Result<Vec<ReceivedRefUpdate>> {
        let rows = sqlx::query(
            "SELECT id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, timestamp,
                    cert_id, received_at, from_peer
             FROM received_ref_updates WHERE repo = $1 ORDER BY timestamp DESC LIMIT $2",
        )
        .bind(repo)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_ref_update).collect())
    }

    /// Filtered ref updates — optionally scoped to a specific repo.
    pub async fn list_ref_updates_filtered(
        &self,
        repo: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ReceivedRefUpdate>> {
        let rows = if let Some(r) = repo {
            sqlx::query(
                "SELECT id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, timestamp,
                        cert_id, received_at, from_peer
                 FROM received_ref_updates WHERE repo=$1 ORDER BY timestamp DESC LIMIT $2",
            )
            .bind(r)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, timestamp,
                        cert_id, received_at, from_peer
                 FROM received_ref_updates ORDER BY timestamp DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };
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
    pub irys_tx_id: String,
    pub arweave_url: String,
    pub node_did: String,
    pub anchored_at: String,
}

/// Input parameters for recording an Arweave anchor.
pub struct RecordAnchorInput<'a> {
    pub repo: &'a str,
    pub owner_did: &'a str,
    pub ref_name: &'a str,
    pub old_sha: &'a str,
    pub new_sha: &'a str,
    pub cid: Option<&'a str>,
    pub irys_tx_id: &'a str,
    pub arweave_url: &'a str,
    pub node_did: &'a str,
}

impl Db {
    pub async fn record_arweave_anchor(&self, input: &RecordAnchorInput<'_>) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO arweave_anchors (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(&id)
        .bind(input.repo)
        .bind(input.owner_did)
        .bind(input.ref_name)
        .bind(input.old_sha)
        .bind(input.new_sha)
        .bind(input.cid)
        .bind(input.irys_tx_id)
        .bind(input.arweave_url)
        .bind(input.node_did)
        .bind(&now)
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
                "SELECT id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at
                 FROM arweave_anchors WHERE repo=$1 ORDER BY anchored_at DESC LIMIT $2",
            )
            .bind(repo)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at
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
                irys_tx_id: r.get("irys_tx_id"),
                arweave_url: r.get("arweave_url"),
                node_did: r.get("node_did"),
                anchored_at: r.get("anchored_at"),
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
        sql.push_str(&format!(" ORDER BY created_at DESC LIMIT ${idx}"));

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
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/mirror", None)
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
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/m", None)
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
        db.upsert_mirror_repo("z6Lonely", "orphan", "/srv/m", None)
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
        db.upsert_mirror_repo("z6Pair", "shared", "/srv/m", None)
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
}
