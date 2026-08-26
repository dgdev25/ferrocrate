# FerroCrate Release Process

**TL;DR**: Run one command to build, test, sign, and release to GitHub.

```bash
./scripts/build-and-release.sh v0.1.1
```

That's it. No more GitHub Actions free tier issues.

## How It Works

The `build-and-release.sh` script replaces the need for GitHub Actions CI/CD. It:

1. **Validates** - Checks all required tools exist
2. **Tests** - Runs `cargo fmt`, `cargo clippy`, `cargo test`
3. **Builds** - Compiles release artifacts with `cargo build --release`
4. **Signs** - Creates GPG signatures for all binaries
5. **Checksums** - Generates SHA256 checksums
6. **Tags** - Creates a git tag for the version
7. **Pushes** - Pushes the tag to GitHub
8. **Releases** - Creates a GitHub Release with all artifacts

## Quick Start

### First Time Setup (5 minutes)

```bash
# List your GPG keys
gpg --list-secret-keys --keyid-format short

# Set the key ID for releases
export FERROCRATE_GPG_KEY_ID="YOUR_KEY_ID"

# Verify GitHub CLI is authenticated
gh auth status
```

### Release a New Version

```bash
# From ferrocrate root directory

# Test build (creates tag but doesn't push)
./scripts/build-and-release.sh v0.1.1-test

# Production build (builds, signs, tags, pushes, and releases)
export FERROCRATE_GPG_KEY_ID="YOUR_KEY_ID"
./scripts/build-and-release.sh v0.1.1
```

### Verify Release

```bash
# Check what was built
ls -lh release-artifacts/

# View the GitHub Release
gh release view v0.1.1

# Edit release notes if needed
gh release edit v0.1.1 --notes "Release notes here"
```

## Why This Approach?

| Aspect | GitHub Actions | Local Build |
|--------|---|---|
| Free tier limits | 2,000 min/month | Unlimited |
| Billing blocks | Yes | No |
| Build feedback | 30+ seconds | Instant |
| Debugging | Hard (via logs) | Easy (live output) |
| Dependencies | Needs setup in workflow | Local system deps |
| Reproducibility | GitHub runner image | Your machine |

## The Script Does Everything

**No more:**
- ❌ GitHub Actions workflow debugging
- ❌ Billing issues blocking releases
- ❌ Waiting for GitHub's CI/CD
- ❌ Manual GPG signing
- ❌ Manual checksum generation

**Instead:**
- ✅ One command: `./scripts/build-and-release.sh v0.1.1`
- ✅ Full control over the process
- ✅ See exactly what's happening
- ✅ Release whenever you want

## What If It Fails?

The script has comprehensive error checking. If it fails, it tells you exactly where:

```
✓ All required tools found
✓ In ferrocrate root directory
✓ Version format valid: v0.1.1
✓ Code formatting OK
✓ Clippy checks passed
✓ All tests passed
✓ Build succeeded
✓ Found 3 binary artifacts
✓ Signed: ferro-cli
✓ Signed: ferro-mind
✓ Signed: ferrocrate
✓ Checksums written to: SHA256SUMS.txt
✓ Tag created: v0.1.1
✓ Tag pushed: v0.1.1
✓ GitHub release created/updated: v0.1.1
```

Fix any issues and run again. The script is idempotent for most operations.

## Next: Binary Distribution Phases

- **Phase 1 (DONE)**: GitHub Releases, installer, GPG signing
- **Phase 2**: Homebrew tap, .deb packaging, GitHub Package Registry
- **Phase 3**: Chocolatey, Winget, Snap store

See `docs/BINARY_DISTRIBUTION_PIPELINE.md` for full details.

## Files

- `scripts/build-and-release.sh` - Main build script
- `scripts/sign-binaries.sh` - GPG signing utility (called by build script)
- `scripts/install.sh` - Universal installer for end users
- `docs/BUILD_AND_RELEASE.md` - Detailed guide with troubleshooting
