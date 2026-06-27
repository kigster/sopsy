# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sopsy` is a Rust CLI (`edition = "2024"`) that wraps [SOPS](https://github.com/getsops/sops) and [age](https://github.com/FiloSottile/age) to give a better developer experience for managing Git-stored encrypted secrets. On macOS it targets Secure Enclave-backed identities via the external `age-plugin-se` binary. It shells out to these external tools rather than reimplementing encryption.

The project is at an early stage: only `doctor` is implemented. `init` and `edit` are stubs that print placeholder output (`src/main.rs`).

## Commands

The `justfile` is the task runner (`just <recipe>`); recipes wrap `cargo`:

- `just run` — runs `cargo run -- doctor`
- `just test` / `cargo test`
- `just fmt` — `cargo fmt`
- `just warnings` — `cargo clippy -- -D warnings` (note: the recipe currently has a typo `-D warmings`; the intent is to deny warnings)
- `just publish` — full release gate: fmt → warnings → test → package → publish-dry-run → `cargo publish`

Run a single test: `cargo test <test_name>`. Run the CLI directly: `cargo run -- <subcommand>` (e.g. `cargo run -- edit secrets.yaml -- --in-place`).

## Architecture

Single binary, entry point `src/main.rs`. Structure:

- CLI is defined with `clap` derive (`Cli` struct, `Commands` enum). New subcommands are added as variants of `Commands` and matched in `main()`.
- `doctor()` is the model for "check external tooling": it probes for required binaries (`git`, `sops`, `age-plugin-se`) using the `which` crate and reports presence with colored ✔/ｘ output. Any feature depending on an external tool should verify it the same way.
- `Edit` takes a file path plus trailing `sops_args` (everything after `--`, via `#[arg(last = true)]`) to forward through to `sops`.
- Error handling uses `anyhow::Result` with `color_eyre` installed in `main()` for pretty backtraces. Terminal output uses `owo_colors`. Interactive prompts (when built out) should use `inquire`; progress via `indicatif`.

## Domain model (from `docs/guide-admin.md`)

The secrets workflow sopsy automates:

- Each developer holds a private age key (Secure Enclave on macOS — private key never leaves the laptop); only **public** keys are committed.
- `.sops.yaml` `creation_rules` map a `path_regex` (e.g. `\.encrypted$`) to the list of recipient `age` public keys.
- Adding/removing a developer = editing the recipient list in `.sops.yaml` then re-encrypting everything with `sops updatekeys -r .`.
- Encrypted artifacts (`.env.encrypted`, `config/*.encrypted.yaml`) are committed; plaintext (`.env`, `*.key`, `*.pem`, credentials) never is.

When implementing `init`/`edit`/recipient-management/rotation, this is the behavior to honor: never write plaintext secrets to disk in a committed location, and drive recipients through `.sops.yaml`.
