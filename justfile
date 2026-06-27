# © 2026 Konstantin Gredeskoul 

set shell := ["bash", "-eu", "-o", "pipefail", "-c"] 

[no-exit-message]
recipes:
    @just --choose


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

publish:
    cargo publish --dry-run

