//! Admin subcommands (one-off maintenance), invoked as `gitlawb-node <cmd>`.
//! These run instead of the daemon and exit.

use anyhow::Result;

use crate::config::{Config, PurgeSpamArgs};
use crate::db::Db;
use crate::git::tigris::TigrisClient;

/// How many repos to delete per query/commit batch.
const BATCH: i64 = 500;

/// Bulk-delete repos whose name matches a Postgres regex, removing DB rows,
/// the on-disk bare repo, and (unless skipped) the Tigris archive.
///
/// Defaults to a dry run: it reports the match count and a sample and deletes
/// nothing. Pass `--execute` to actually delete.
pub async fn purge_spam(config: &Config, args: &PurgeSpamArgs) -> Result<()> {
    let db = Db::connect(&config.database_url).await?;

    let total = db.count_repos_by_name_regex(&args.regex).await?;
    println!("repos matching /{}/ : {total}", args.regex);

    let sample = db.list_repos_by_name_regex(&args.regex, 20).await?;
    println!("sample (up to 20):");
    for (id, name, owner, _disk) in &sample {
        println!("  {name}  owner={owner}  id={id}");
    }

    if !args.execute {
        println!(
            "\nDRY RUN — nothing deleted. Re-run with --execute to delete these {total} repos \
             ({}).",
            if args.bulk {
                "bulk set-based DB delete + on-disk .git"
            } else if args.skip_tigris {
                "DB rows + on-disk .git"
            } else {
                "DB rows + on-disk .git + Tigris archive"
            }
        );
        return Ok(());
    }

    // Bulk mode: set-based DB delete (a few statements) + on-disk removal. Far
    // faster on large match sets / small DB instances than per-repo cascade.
    if args.bulk {
        let disk_paths = db.list_disk_paths_by_name_regex(&args.regex).await?;
        println!(
            "collected {} on-disk paths; running bulk DB delete…",
            disk_paths.len()
        );
        let deleted = db.bulk_delete_by_name_regex(&args.regex).await?;
        println!("bulk DB delete done: {deleted} repos removed; removing on-disk repos…");
        let mut disk_removed = 0u64;
        for p in &disk_paths {
            if std::path::Path::new(p).exists() {
                match std::fs::remove_dir_all(p) {
                    Ok(()) => disk_removed += 1,
                    Err(e) => eprintln!("warning: rm {p} failed: {e}"),
                }
            }
        }
        println!("done: {deleted} repos purged (bulk), {disk_removed} on-disk dirs removed");
        return Ok(());
    }

    // Tigris client (best-effort; archive deletion failures are logged, not fatal).
    let tigris = if !args.skip_tigris && !config.tigris_bucket.is_empty() {
        match TigrisClient::new(&config.tigris_bucket).await {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("warning: could not init Tigris ({e}); skipping archive deletion");
                None
            }
        }
    } else {
        None
    };

    let mut deleted = 0i64;
    let mut disk_removed = 0i64;
    let mut tigris_removed = 0i64;

    loop {
        let take = match args.limit {
            n if n > 0 => (n - deleted).min(BATCH),
            _ => BATCH,
        };
        if take <= 0 {
            break;
        }
        let batch = db.list_repos_by_name_regex(&args.regex, take).await?;
        if batch.is_empty() {
            break;
        }

        for (id, name, owner_did, disk_path) in &batch {
            let short = owner_did.rsplit(':').next().unwrap_or(owner_did);
            let slug = format!("{short}/{name}");

            // DB first: once the row is gone the repo is invisible to all serve/
            // list paths even if disk/Tigris cleanup lags.
            db.delete_repo_cascade(id, &slug).await?;
            deleted += 1;

            if !disk_path.is_empty() && std::path::Path::new(disk_path).exists() {
                match std::fs::remove_dir_all(disk_path) {
                    Ok(()) => disk_removed += 1,
                    Err(e) => eprintln!("warning: rm {disk_path} failed: {e}"),
                }
            }

            if let Some(t) = &tigris {
                let owner_slug = owner_did.replace([':', '/'], "_");
                match t.delete(&owner_slug, name).await {
                    Ok(()) => tigris_removed += 1,
                    Err(e) => eprintln!("warning: tigris delete {owner_slug}/{name} failed: {e}"),
                }
            }
        }

        println!("… deleted {deleted}/{total} (disk {disk_removed}, tigris {tigris_removed})");
    }

    println!(
        "done: {deleted} repos purged (disk dirs removed: {disk_removed}, tigris archives removed: {tigris_removed})"
    );
    Ok(())
}
