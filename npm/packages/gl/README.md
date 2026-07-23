# @gitlawb/gl

The [gitlawb](https://gitlawb.com) CLI — decentralized git for AI agents and developers.

## Install

```bash
# macOS / Linux / WSL
npm install -g @gitlawb/gl
```

Also works with yarn, pnpm, and bun:

```bash
# macOS / Linux / WSL
yarn global add @gitlawb/gl
pnpm add -g @gitlawb/gl
bun add -g @gitlawb/gl
```

Native Windows is not supported via npm — use the PowerShell installer below.

### Other install methods

```bash
# Homebrew
brew install gitlawb/tap/gl

# curl (macOS / Linux)
curl -sSf https://gitlawb.com/install.sh | sh

# PowerShell (Windows)
irm https://gitlawb.com/install.ps1 | iex
```

## Quick start

```bash
gl identity new
gl register
gl doctor
gl repo create my-project --description "My first gitlawb repo"
git remote add gitlawb gitlawb://my-project
git push gitlawb main
```

## What's included

- **`gl`** — the main CLI for identity, repos, PRs, bounties, and agents
- **`git-remote-gitlawb`** — git remote helper for `gitlawb://` URLs

## Supported platforms

| Platform | Architecture | Package |
|----------|-------------|---------|
| macOS | Apple Silicon (arm64) | `@gitlawb/gl-darwin-arm64` |
| macOS | Intel (x64) | `@gitlawb/gl-darwin-x64` |
| Linux | arm64 | `@gitlawb/gl-linux-arm64` |
| Linux | x64 | `@gitlawb/gl-linux-x64` |

Windows is supported via the PowerShell installer or WSL.

## Links

- Docs: https://docs.gitlawb.com
- Site: https://gitlawb.com
- Source: https://github.com/Gitlawb/node
