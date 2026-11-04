---
created: 2026-11-03
starts: planning
depth: medium
frontend: false
implementation_requirements:
  - "No behaviour change. Every command's output, exit codes and file effects stay as they are; this is a refactor only."
  - "Build on `main` after PR #26 (recipient rotate) and PR #27 (run, set, unset, rotate-data-key) have merged: both change the code being moved."
  - "Every module touched has a facade: its `mod.rs` declares the submodules private (`mod x;`) and re-exports only what other modules call (`pub(crate) use x::item;`). Nothing outside a module names its submodules."
  - "Other modules call a module only through its facade, never its internals."
  - "No non-test source file in the touched modules is longer than about 400 lines. Unit tests live in their own `tests` submodule beside the code they test."
  - "The existing test suite passes unchanged except for `use` paths. The integration tests in `tests/` keep working against the public API."
implementation_suggestions:
  - "Split by activity, as sketched under What we are trying to achieve; the agent may pick better names and say why."
  - "Move one module per commit, each commit building and passing tests on its own, so a reviewer can follow it."
task-completed-when:
  - "`src/commands/recipient/mod.rs` holds only the facade and `run` dispatch; each subcommand lives in its own file."
  - "Repository, `.sops.yaml` editing, encrypted-file discovery and re-keying each live in their own module with a facade, and `init`, `join`, `approve`, `doctor`, `keys` and `env` use those facades instead of `commands::recipient` helpers."
  - "fmt, clippy `-D warnings` and `cargo test --all` are green."
---
# Split Recipient Module

## What we are trying to achieve

Apply the global **Modularity and SOLID** rule to `src/commands/recipient/`: small files with one job each, grouped into modules that other code reaches only through a facade.

After #26 the module is `recipient/{mod,rotate,ceremony}.rs`, but `mod.rs` is still 1,116 lines and does five unrelated jobs. Other commands also reach into it for about ten helpers that have nothing to do with recipients.

Target layout (a sketch; names are suggestions):

| Module | Job | Moves there from `recipient/mod.rs` |
| --- | --- | --- |
| `commands/recipient/` | the `recipient` subcommands | `add.rs`, `remove.rs`, `list.rs` (+ `approved_cell`, `date_only`, `truncate`), `keygen.rs`, plus the existing `rotate.rs` and `ceremony.rs`; `mod.rs` keeps only `run` |
| `repo/` | the repository a command runs in | `current_repo_root`, `load_config`, `sops_config_path`, `membership_paths`, `maybe_stage`, `system_username`, `assume_yes`, `SOPS_CONFIG_FILE_NAME` |
| `repo/encrypted_files.rs` (or its own module) | find the managed encrypted files | `collect_encrypted_files`, `expand_glob`, `glob_match`, `is_encrypted_file` |
| `sops/config.rs` (behind the `sops` facade) | read and edit `.sops.yaml` | `add_key_to_sops_yaml`, `remove_key_from_sops_yaml`, `sops_yaml_age_keys`, `mutate_sops_yaml`, `parse_age_keys`, `age_keys_to_value` |
| `rekey/` | re-wrap secrets for a new recipient set, as one transaction | `run_updatekeys`, `updatekeys_file`, `sops_command`, `ConfigSnapshot` (capture, restore, `roll_back`), `rewrap_error` |

`rekey` may expose a single transaction call (snapshot, mutate, run updatekeys, roll back on failure) so that `add`, `remove`, `rotate`, `approve` and the ceremony stop repeating the same five lines.

## Why it matters

- `recipient/mod.rs` changes for unrelated reasons (a `.sops.yaml` parsing fix, a new subcommand, a re-key fix), which breaks single responsibility and makes review noisy: the #26 review flagged its size as blocking.
- `init`, `join`, `approve`, `doctor`, `keys` and `env` depend on `commands::recipient` for repository and re-key plumbing. A change to recipients can break them, and the dependency direction is backwards: commands should depend on shared modules, not on each other.
- Small modules behind facades make the next features (`sopsy keys` for local identity management, plan 005) cheaper to add without touching working code.

## What already exists

- `src/commands/recipient/mod.rs` (1,116 lines, tests included), `rotate.rs` (196), `ceremony.rs` (346), after PR #26.
- External callers today, as `crate::commands::recipient::…`:
  - `approve.rs`: `ConfigSnapshot`, `SOPS_CONFIG_FILE_NAME`, `add_key_to_sops_yaml`, `assume_yes`, `current_repo_root`, `load_config`, `membership_paths`, `run_updatekeys`, `sops_config_path`, `system_username`
  - `init.rs`: `add_key_to_sops_yaml`, `sops_yaml_age_keys`, `system_username`, `run` (to invoke break-glass)
  - `join.rs`: `system_username`, `current_repo_root`, `load_config`
  - `doctor.rs`, `keys.rs`: `current_repo_root`, `system_username`
  - `env.rs` (PR #27): `current_repo_root`, `collect_encrypted_files`
- `init` invokes break-glass through `recipient::run(RecipientCommand::BreakGlass(..))`; keep that or expose the ceremony through the facade.

Out of scope, follow-ups for separate plans: `ui.rs` (1,104 lines), `cli.rs` (1,077), `commands/init.rs` (927), `commands/keys.rs` (888), `hardware/yubikey.rs` (841) and `hardware/mod.rs` (730) break the same rule.

## What research needs to settle

Nothing external: this is an internal refactor and the planner can work from the code. The open choices are naming (`repo` versus `workspace`; `.sops.yaml` editing in `sops::config` versus its own module) and whether `rekey` exposes a transaction helper. The planner decides and records why in `plan.md`.

## How to tell it's working?

- cargo fmt --all -- --check
- cargo clippy --all-targets --all-features -- -D warnings
- GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false cargo test --all
- fd -e rs . src/commands/recipient src/repo src/rekey | xargs wc -l  # no file far above 400 lines
- rg -n 'commands::recipient::' src --glob '!src/commands/recipient/**' --glob '!src/lib.rs'  # prints nothing
