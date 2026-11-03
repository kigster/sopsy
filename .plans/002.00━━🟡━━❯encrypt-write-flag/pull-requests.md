# Pull Requests

## Round 1 (backend-coder)

Frontend-less plan; backend-coder owns it. Checks run in the worktree:

- `cargo fmt --all` — clean
- `cargo clippy --all-targets --all-features -- -D warnings` — clean
- `cargo test` (commit signing disabled via `GIT_CONFIG_*`) — all suites pass; lib 250, `tests/secrets.rs` 13 (8 new)
- `sopsy completion zsh` includes `--write` and `--overwrite`

Baseline: pre-change failures were not recorded before editing (missed); the post-change suite has 0 failures, so there is nothing beyond baseline.
- Coverage (`.openlanes.yml` `coverage:` added): `rustup run stable cargo llvm-cov …` → **95.05%** lines, minimum 95. Uses `rustup run stable` because Homebrew's `cargo` has no `llvm-tools`.

Not done here, by D4: file modes / atomic writes (change 2) and the git-ignore warning (change 3) need their own plan folders. No CHANGELOG exists in the repo, so the `-o` behaviour change (now prompts/errors on an existing target) is noted here for the PR description.
