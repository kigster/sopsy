# © 2026 Konstantin Gredeskoul 

set shell := ["bash", "-eu", "-o", "pipefail", "-c"] 

version := `grep -i '^version' Cargo.toml | awk '{print $3}' | tr -d '"'`
repo := 'git@github.com:kigster/sopsy'

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

# Tag v{{ version }}, publish the GH release, & refresh the Homebrew tap.
release:
    git fetch --tags
    git tag -f "v{{ version }}"
    git push -f --tags 
    gh release delete -y "v{{ version }}" --repo {{ repo }} 2>/dev/nul || true
    gh release create "v{{ version }}" --force --generate-notes --repo {{ repo }}

clean:
    /usr/bin/find . -type f -name sopsy -delete
    /usr/bin/find . -type f -name .DS_Store -delete
