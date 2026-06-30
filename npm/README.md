# npm distribution for the gitlawb CLI

This directory packages the `gl` and `git-remote-gitlawb` binaries as the
[`@gitlawb/gl`](https://www.npmjs.com/package/@gitlawb/gl) npm package.

It uses the **optionalDependencies platform-package** pattern (the same one
esbuild/swc/turbo use): the wrapper `@gitlawb/gl` declares four per-platform
packages as `optionalDependencies`, each gated by `os`/`cpu`. npm installs only
the one matching the host, and the wrapper's `postinstall` (`install.js`) copies
the binary out of it into `bin/`. No binaries are downloaded at install time.

```
packages/
  gl/                  @gitlawb/gl            wrapper (postinstall, bin shims)
  gl-darwin-arm64/     @gitlawb/gl-darwin-arm64   aarch64-apple-darwin
  gl-darwin-x64/       @gitlawb/gl-darwin-x64     x86_64-apple-darwin
  gl-linux-arm64/      @gitlawb/gl-linux-arm64    aarch64-unknown-linux-musl
  gl-linux-x64/        @gitlawb/gl-linux-x64      x86_64-unknown-linux-musl
```

## Publishing

Publishing is **automated** by `.github/workflows/release.yml` (the `npm-publish`
job) on every release-please release. That job:

1. Downloads the four unix release tarballs from the `Gitlawb/node` GitHub release.
2. Lays `gl` + `git-remote-gitlawb` into each platform package.
3. Rewrites every `package.json` `version` (and the wrapper's
   `optionalDependencies` pins) to the release version.
4. Publishes the four platform packages first, then the wrapper, with
   `npm publish --provenance --access public`.

The committed `version` fields here are placeholders; the workflow is the single
source of truth and always uses the release tag. There is no manual publish step.

Windows is intentionally not published to npm — the wrapper points Windows users
at the curl/PowerShell installer instead.
