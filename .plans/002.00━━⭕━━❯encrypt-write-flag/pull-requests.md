# Pull Requests

| Pull Request Number | Pull Request Name | Status |
| ------------------: | :---------------- | -----: |
| 30 | [\[002.00\](A) Encrypt Write Flag](https://github.com/kigster/sopsy/pull/30) | Open 🟡 |

## Round 1 (backend-coder)

Frontend-less plan; backend-coder owns it. Checks run in the worktree:

- `cargo fmt --all` — clean
- `cargo clippy --all-targets --all-features -- -D warnings` — clean
- `cargo test` (commit signing disabled via `GIT_CONFIG_*`) — all suites pass; lib 250, `tests/secrets.rs` 13 (8 new)
- `sopsy completion zsh` includes `--write` and `--overwrite`

Baseline: pre-change failures were not recorded before editing (missed); the post-change suite has 0 failures, so there is nothing beyond baseline.
- Coverage (`.openlanes.yml` `coverage:` added): `rustup run stable cargo llvm-cov …` → **95.05%** lines, minimum 95. Uses `rustup run stable` because Homebrew's `cargo` has no `llvm-tools`.

Not done here, by D4: file modes / atomic writes (change 2) and the git-ignore warning (change 3) need their own plan folders. No CHANGELOG exists in the repo, so the `-o` behaviour change (now prompts/errors on an existing target) is noted here for the PR description.

## Findings: design-reviewer

### F201 [minor] src/lib.rs:51
`assume_yes` now has two sources of truth. `Ui::with_assume_yes(--yes || SOPSY_ASSUME_YES)` is new, but `approve` (`approve.rs:279`) and `recipient/ceremony.rs:170` still read `recipient::assume_yes()` (env only) directly. Scenario: `sopsy --yes encrypt .env -w` overwrites silently, while `sopsy --yes approve X` still refuses to vouch non-interactively because it ignores the flag. Two ways to answer one question; migrate those callers to `ui.assumes_yes()` (or note why they must not).

### F202 [minor] src/commands/secrets/target.rs:13
The `.encrypted` suffix rule is now written twice: `target::SUFFIX`/`ends_with_encrypted`/`without_encrypted_suffix` and the existing `.encrypted` stripping in `sops::FileType::from_path` (`sops/mod.rs:111`). Scenario: someone changes the convention (e.g. accepts `.enc`) in one place; `-w` and type detection then disagree. Have one owner (sops module) expose the suffix helpers and let `target.rs` call them.

### F203 [minor] src/cli.rs:557
The `destination` ArgGroup is declared by an identical `#[command(group(...))]` on both `SecretsEncryptArgs` and `SecretsDecryptArgs`, while `WriteArgs` (which names the group in `requires`) lives in another file and the `output` field it groups lives in the parent structs. Scenario: a third command flattens `WriteArgs` and forgets the group attribute; clap then fails at parse/debug-assert time for `-O`. The contract is split across three places; a doc note or a debug-assert test over every flattening struct would keep it honest.

### F204 [minor] src/commands/secrets/mod.rs:69
`encrypt` and `decrypt` repeat the same preamble (exists check, file-type resolve, `target::destination`), and `Sink` (file delivery policy) sits in the facade file beside dispatch. Not wrong, but `mod.rs` is the facade and now also holds a second responsibility; moving `Sink` to `sink.rs` would match the `existing`/`target` split.

Positive: splitting `secrets.rs` into `mod.rs` facade + `target` + `existing` with `pub(super)` internals follows AGENTS.md's facade rule well.

## Answers, round 2

PR #30 has no inline review threads (`gh api repos/kigster/sopsy/pulls/30/comments` returns `[]`) and no review objects; every finding is in a top-level conversation comment, so there is no thread to reply in. `gh pr comment` is withheld from this role, so the answers are recorded here for the harness to post.

| Comment (finding) | Answer | Files |
| :--- | :--- | :--- |
| design-reviewer F201 | fix: `Ui::assumes_yes()` is now the only owner of the question (`--yes` flag via `with_assume_yes`, or `SOPSY_ASSUME_YES` read inside it). `recipient::assume_yes()` is gone; `approve` and the break-glass/CI ceremony call `ui.assumes_yes()`, so `sopsy --yes approve X` now vouches like `SOPSY_ASSUME_YES` does. `ASSUME_YES_ENV` moved to `ui.rs`, re-exported from `recipient`. | `src/ui.rs`, `src/lib.rs`, `src/commands/approve.rs`, `src/commands/recipient/mod.rs`, `src/commands/recipient/ceremony.rs` |
| design-reviewer F202 | fix: new `sops::suffix` owns `ENCRYPTED_SUFFIX`, `ends_with_encrypted`, `with_encrypted_suffix`, `without_encrypted_suffix` (tests moved with them). `FileType::from_path` and `secrets::target` both call it. | `src/sops/suffix.rs`, `src/sops/mod.rs`, `src/commands/secrets/target.rs`, `src/commands/secrets/mod.rs` |
| design-reviewer F203 | fix: `WriteArgs` doc states the group contract, and `every_flattener_declares_the_destination_group` walks every subcommand via `Cli::command()`; any command with `--overwrite` but no `destination` group of `[write, output]` fails it. | `src/cli/write_args.rs` |
| design-reviewer F204 | fix: `Sink` moved to `secrets/sink.rs`; `mod.rs` is dispatch only. The two-line preamble repetition stays: encrypt and decrypt diverge right after it (suffix validation vs. YubiKey prompt). | `src/commands/secrets/sink.rs`, `src/commands/secrets/mod.rs` |
| staff-reviewer F1 | fix: a same-second collision takes the next free `FILE.YYYY-MM-DD.HHMMSS-1.bak`, `-2`, … (cap 100, then an error). Tests cover the second backup and the cap. | `src/commands/secrets/existing.rs` |
| staff-reviewer F2 | fix: `target::destination` rejects `-o` that canonicalises to the input file ("names the input file; refusing to overwrite it"), before sops runs. Test covers the direct and `./`-aliased path. | `src/commands/secrets/target.rs` |
| staff-reviewer F3 | rebuttal: out of scope by D4. The git-ignore warning is change 3, which gets its own plan folder (journal todo 6); both reviewers already called it non-blocking and pointed it there. Backups of non-dotenv plaintext should be part of that plan's spec. | — |
| security F101 | rebuttal: same as F3 (D4, change 3). The 0600-mode / `O_NOFOLLOW` / backup TOCTOU notes go to change 2's spec. | — |

Checks after the fixes (commit signing off via `GIT_CONFIG_*`):

- `cargo fmt --all -- --check` — clean
- `cargo clippy --all-targets --all-features -- -D warnings` — clean
- `cargo test --all` — 476 passed, 0 failed (lib 253, was 250: +3 new tests)
- coverage (`.openlanes.yml` command) — **95.08%** lines, minimum 95

## Answers, round 3

| Comment (finding) | Answer | Files |
| :--- | :--- | :--- |
| Grok review 🛑 (`--non-interactive` means "yes to everything"); human mail #11 | fix: "don't prompt" and "assume yes" are separate inputs again. `Ui::with_yes_flag` records `-y`/`--yes`/`--non-interactive`; `Ui::consents_to_overwrite()` (flag or `SOPSY_ASSUME_YES`) is read only by `secrets::existing::decide`. `Ui::assumes_yes()` is env-only, so `approve`'s vouch and the break-glass/CI "keys stored" confirmation need `SOPSY_ASSUME_YES` as before this PR. This overrides the round-2 F201 answer for those two callers. Flag help and README row say so. New tests: `approve_with_yes_flag_but_no_optin_still_fails` (`--non-interactive`, `--yes`, `-y`: exits non-zero, bob stays pending), `break_glass_with_yes_flag_but_no_optin_still_fails`, `ui::tests::yes_flag_consents_to_overwrite_but_never_assumes_yes`. Both integration tests fail when `assumes_yes` reads the flag again (checked). | `src/ui.rs`, `src/lib.rs`, `src/cli.rs`, `src/commands/approve.rs`, `src/commands/secrets/existing.rs`, `tests/recipient.rs`, `README.md` |
| Grok review 🤔 "No" on decrypt still overwrites | rebuttal: the behaviour is D5 in spec.md, chosen by the owner; changing the prompt wording is a product call outside this round's fix scope. | — |
| Grok review 🤔 plaintext 0600 modes; `*.bak` in `init`'s gitignore | rebuttal: out of scope by D4 (change 2 modes/atomic writes, change 3 git-ignore warning), as for F3/F101 in round 2. | — |
| Grok review 🤔 `state.json` in the diff | rebuttal: `.plans/` is published by the openlanes harness, not by this role. | — |

Checks after the fix (commit signing off via `GIT_CONFIG_*`):

- `cargo fmt --all -- --check` — clean
- `cargo clippy --all-targets --all-features -- -D warnings` — clean
- `cargo test --all` — 480 passed, 0 failed (lib 254, recipient 71)

- coverage (`.openlanes.yml` command) — **95.08%** lines, minimum 95
