# © 2026 Konstantin Gredeskoul 

set shell := ["bash", "-eu", "-o", "pipefail", "-c"] 

version := `grep -i '^version' Cargo.toml | awk '{print $3}' | tr -d '"'`

[no-exit-message]
recipes:
    @just --choose

# Setup the repo by installing dependencies and pre-commit hook
setup:
    brew bundle --no-upgrade
    lefthook install
    
# Use gitleads to scan for secrets.
secrets-scan:
    @echo "Scanning the full working tree"
    @gitleaks dir \
      --config .gitleaks.toml \
      --redact --no-banner --verbose \
      .

# Show any warnings and reformat Rust codebase
build: fmt warnings 
    cargo build --release

# install sopsy binary locally
install: build
    cargo install --path .

# Format Rust code
fmt: 
    cargo fmt

# Show warnings
warnings:
    cargo clippy -- -D warmings

# Run tests
test:
    cargo test

# Run sopsy doctor
doctor:
    cargo run -- doctor

# List cargo packages
package:
    cargo package --list

# Cargo publish (dry-run)
publish-dry-run: fmt warnings test
    cargo publish --dry-run

# Publish new release to crates.io
publish: fmt warnings test package publish-dry-run
    cargo publish

# Print the current version
version:
    @echo "sopsy current version is {{ version }}"

# How release works: tagging v{{ version }} and pushing it triggers
# .github/workflows/release.yml to build the per-platform binaries and publish
# the GitHub release; we then dispatch kigster/homebrew-tap's update-formula
# workflow so Formula/sopsy.rb is regenerated from the freshly-uploaded tarballs
# (it curls the assets to hash them, so we wait for the build to finish first).

# Tag v{{ version }}, publish the GH release, & refresh the Homebrew tap.
release:
    #!/usr/bin/env bash
    set -euo pipefail

    version="{{ version }}"
    tag="v${version}"
    tap="kigster/homebrew-tap"

    # ── Preflight ────────────────────────────────────────────────────────────
    branch="$(git symbolic-ref --short HEAD)"
    [[ "${branch}" == "main" ]] \
      || { echo "release: must be on 'main' (currently on '${branch}')"; exit 1; }
    [[ -z "$(git status --porcelain)" ]] \
      || { echo "release: working tree is dirty — commit or stash first"; exit 1; }

    git fetch --quiet --tags origin
    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
      echo "release: tag ${tag} already exists — bump the version in Cargo.toml first"; exit 1
    fi
    upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
    if [[ -n "${upstream}" && "$(git rev-parse HEAD)" != "$(git rev-parse '@{u}')" ]]; then
      echo "release: local main differs from ${upstream} — push or pull first"; exit 1
    fi

    read -rp "Release sopsy ${version} as ${tag}? [y/N] " reply
    [[ "${reply}" == [yY]* ]] || { echo "Aborted."; exit 1; }

    # ── Tag → GitHub release + binaries (via release.yml) ─────────────────────
    git tag -a "${tag}" -m "sopsy ${version}"
    git push origin "${tag}"
    gh release view "${tag}" >/dev/null 2>&1 \
      || gh release create "${tag}" --title "${tag}" --generate-notes

    # Wait for the release build so the per-platform tarballs are uploaded before
    # the tap regenerates the formula from them. Find the run by this tag's SHA.
    sha="$(git rev-parse "${tag}^{commit}")"
    echo "Waiting for the release build (commit ${sha:0:8})…"
    run_id=""
    for _ in $(seq 1 30); do
      run_id="$(gh run list --workflow release.yml --json databaseId,headSha \
        -q "map(select(.headSha == \"${sha}\")) | .[0].databaseId")"
      [[ -n "${run_id}" && "${run_id}" != "null" ]] && break
      sleep 4
    done
    [[ -n "${run_id}" && "${run_id}" != "null" ]] \
      || { echo "release: no release workflow run found — check the Actions tab"; exit 1; }
    gh run watch "${run_id}" --exit-status

    # ── Refresh Formula/sopsy.rb from the freshly-published assets ─────────────
    echo "Refreshing ${tap} Formula/sopsy.rb for ${tag}…"
    gh workflow run update-formula.yml -R "${tap}" -f "tag=${tag}"
    sleep 5
    tap_run="$(gh run list -R "${tap}" --workflow update-formula.yml --limit 1 \
      --json databaseId -q '.[0].databaseId')"
    if [[ -n "${tap_run}" && "${tap_run}" != "null" ]]; then
      gh run watch -R "${tap}" "${tap_run}" --exit-status
    fi

    echo "Released ${tag} and refreshed the ${tap} formula."

