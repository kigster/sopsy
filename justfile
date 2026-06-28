# © 2026 Konstantin Gredeskoul 

set shell := ["bash", "-eu", "-o", "pipefail", "-c"] 

version := `grep -i '^version' Cargo.toml | awk '{print $3}' | tr -d '"'`

[no-exit-message]
recipes:
    @just --choose

setup:
    brew bundle --no-upgrade
    lefthook install
    

secrets-scan:
    @echo "Scanning the full working tree"
    @gitleaks dir \
      --config .gitleaks.toml \
      --redact --no-banner --verbose \
      .
build: fmt warnings 
    cargo build --release

install: build
    cargo install --path .

fmt: 
    cargo fmt

warnings:
    cargo clippy -- -D warmings

test:
    cargo test

run:
    cargo run -- doctor

package:
    cargo package --list

publish-dry-run:
    cargo publish --dry-run

publish: fmt warnings package publish-dry-run
    cargo publish

release:
    git tag -f "v{{version}}"
    git push --tags
    gh release create "v{{version}}" --generate-notes 

