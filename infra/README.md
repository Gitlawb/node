# infra/

Deployment configuration, organized by target — one subdirectory per platform.

```
infra/
├── fly/
│   └── fly.toml    # Fly.io app config (gitlawb-node-test)
└── aws/            # Terraform: single EC2 + Docker (see aws/README.md)
```

## Deploying to Fly.io

Run from the **repo root** so the Docker build context includes `crates/`,
`Cargo.toml`, and `bootstrap-peers.json`:

```sh
fly deploy -c infra/fly/fly.toml
```

The `dockerfile` path inside `fly.toml` is resolved relative to the config
file, so it points to `../../Dockerfile`.

## Deploying to AWS

See [`aws/README.md`](aws/README.md) — Terraform for a single EC2 instance
running the published `ghcr.io/gitlawb/node` image with Docker compose.

## What intentionally stays at the repo root

- `Dockerfile` / `Dockerfile.bins` — shared by the release CI workflow
  (`.github/workflows/release.yml`), `scripts/build-bins.sh`, and Fly builds.
- `docker-compose.yml` — local dev stack; bundled into the macOS app by
  `scripts/build-macos-app.sh` and used for repo detection by the app.

Future targets should follow the same per-platform layout.
