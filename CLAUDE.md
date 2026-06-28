# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sopsy` is a Rust CLI (`edition = "2024"`) that wraps [SOPS](https://github.com/getsops/sops) and [age](https://github.com/FiloSottile/age) to give a better developer experience for managing Git-stored encrypted secrets. On macOS it targets Secure Enclave-backed identities via the external `age-plugin-se` binary, and uses `age-keygen` for portable (break-glass) keys. It shells out to these external tools rather than reimplementing encryption.

All commands are implemented: `init`, `doctor`, `edit`, `join`, `approve`, `recipient` (`add`/`remove`/`list`/`keygen`/`break-glass`), `check`, `deps`, and `completion`. The entry point is `src/lib.rs::run` (the binary in `src/main.rs` just maps errors to an exit code).

## Commands

The `justfile` is the task runner (`just <recipe>`); recipes wrap `cargo`:

- `just run` — runs `cargo run -- doctor`
- `just test` / `cargo test`
- `just fmt` — `cargo fmt`
- `just warnings` — `cargo clippy -- -D warnings` (note: the recipe currently has a typo `-D warmings`; the intent is to deny warnings)
- `just publish` — full release gate: fmt → warnings → test → package → publish-dry-run → `cargo publish`

Run a single test: `cargo test <test_name>`. Run the CLI directly: `cargo run -- <subcommand>` (e.g. `cargo run -- edit secrets.yaml -- --in-place`).

## Architecture

Library crate (`src/lib.rs::run` dispatches `Command`), thin binary in `src/main.rs`. Structure:

- CLI is defined with `clap` derive (`Cli` struct, `Command` enum in `src/cli.rs`). New subcommands are added as `Command` variants and matched in `lib.rs::dispatch`, each delegating to a `commands::<name>::run`.
- `doctor` is the model for "check external tooling": it probes for required binaries (`git`, `sops`, `age-plugin-se`) using the `which` crate and reports presence with colored ✔/ｘ output. Any feature depending on an external tool verifies it the same way (see `sops::ensure_available`, `enclave::ensure_available`, `age::ensure_available`).
- External-tool wrappers live in their own modules: `sops/` (encrypt/decrypt/edit/updatekeys), `enclave/` (`age-plugin-se keygen`, Secure Enclave identities), `age.rs` (`age-keygen`, portable keys for break-glass), `git/`. Each honors a `SOPSY_*_BIN` env override so tests can inject fakes.
- `Edit` takes a file path plus trailing `sops_args` (everything after `--`, via `#[arg(last = true)]`) forwarded to `sops`. `recipient keygen` and `join` likewise forward trailing args to `age-plugin-se keygen`.
- Error handling uses the `Error`/`Result` in `error.rs` (thiserror) with `color_eyre` installed in `main()`. Terminal output and prompting funnel through `ui.rs` (`owo_colors`, `inquire`, `indicatif`); `SOPSY_ASSUME_YES` bypasses interactive confirmations for automation/tests.
- Shared recipient helpers (`current_repo_root`, `load_config`, `add_key_to_sops_yaml`, `run_updatekeys`, `ConfigSnapshot`, `rewrap_error`) are `pub(crate)` in `commands/recipient.rs` and reused by `join`/`approve`/`init`.

## Domain model (see `docs/guide-owner.md` / `docs/guide-member.md`)

The secrets workflow sopsy automates:

- Each member holds a private age key (Secure Enclave on macOS — private key never leaves the laptop); only **public** keys are committed.
- `.sops.yaml` `creation_rules` map a `path_regex` (e.g. `\.encrypted$`) to the list of recipient `age` public keys. `.sopsy.yml` is sopsy's own metadata: member name, `username`, lifecycle `state` (`pending`/`active`), `break_glass` marker, `encrypted_globs`, `join_request_ttl`, `sops_version`.
- Onboarding is self-service: `sopsy join` records a **pending** member (key generated locally; not yet in `.sops.yaml`, so it grants nothing); any active member runs `sopsy approve` to add the key to `.sops.yaml`, flip to `active`, and `sops updatekeys` (re-wraps the data key — does not re-encrypt bodies; requires the approver to already be able to decrypt). `recipient add`/`remove` are the direct equivalents.
- **Crypto reality to honor:** reading == re-granting (any recipient holds the data key and can re-wrap it), so roles are soft guardrails, not enforcement; Enclave age keys can't sign. Break-glass keys are **portable** (`age-keygen`), stored offline, registered with `recipient break-glass` (or during `init`).
- Encrypted artifacts (`.env.encrypted`, `config/*.encrypted.yaml`) are committed; plaintext (`.env`, `*.key`, `*.pem`, `*.private`, `*.public`, credentials) never is.

When changing membership/rotation, the behavior to honor: never write plaintext secrets (or private keys) to a committed location, and drive recipients through `.sops.yaml`.
