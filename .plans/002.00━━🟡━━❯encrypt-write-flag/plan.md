## Decisions

### B1 (answered) — Backup file name

`spec.md` and `plan.md` gave two different backup names.

### D1 (decision) — Backups are named `FILE.YYYY-MM-DD.HHMMSS.bak`

Answered:

- 2026-11-03
- By kig

Keep the extension last, so editors and globs still find the file. The spec's `FILE.bak.YYYY-MM-DD.HHMMSS` form is dropped.

### B2 (answered) — Does encrypt create backups?

`spec.md` backs up on both directions. This plan backs up only on decrypt.

### D2 (decision) — Only decrypt creates backups

Answered:

- 2026-11-03
- By kig

The encrypted file is not plaintext, and a backup of it adds clutter. Encrypt overwrites without a backup, as the Existing target table below already states.

### B3 (answered) — Is `-O` a short flag for `--overwrite`?

`spec.md` gives `--overwrite` no short form. This plan gives it `-O`.

### D3 (decision) — `-O` is the short flag for `--overwrite`

Answered:

- 2026-11-03
- By kig

`--overwrite / -O` stays as written in the Flags section below.

### B4 (answered) — Split the plan first

The plan carries three changes: `-w` naming and target-exists rules, file modes and atomic writes, and the git ignore warning. It touches `src/cli.rs` (already past the size limit), `src/commands/secrets.rs`, `src/lib.rs`, `src/sops/mod.rs` and the tests.

Options offered: (a) move to `starts: planning` and split into three plans; (b) build change 1 here; (c) build all three here.

### D4 (decision) — Split into three plans before building

Answered:

- 2026-11-03
- By kig

Move this plan to `starts: planning` and split it into three plans, one per change in D4 of `spec.md`. No build happens in this folder until the split is done.

### B5 (answered) — Behaviour on a "No" answer at the overwrite prompt

The Existing target table and D2 disagree with the spec, which says a backup is made before writing. It does not say whether a "No" answer still writes the new file.

Options offered: (a) on "No", leave the target untouched and write nothing; (b) on "No", back up the target, then write the new file.

### D5 (decision) — On "No", back up the target, then write the new file

Answered:

- 2026-11-03
- By kig

On "No" at the interactive overwrite prompt, back up the existing target as `FILE.YYYY-MM-DD.HHMMSS.bak`, then write the new file. This matches the Existing target table row for an interactive TTY. Only the decrypt direction backs up on "Yes" under `--overwrite` or `--yes`, as D2 states.

## Design

### Flags (on both arg structs, so `secrets encrypt|decrypt` get them too)

- `-w / --write`, conflicts with `-o`.
- `--overwrite / -O`, which requires `--write` (see Q1). It replaces an existing target without asking. 
- During decryption, with either `--overwrite / -O` or with `--yes | -y` should the destination file already exist, before we overwrite it we create a backup, with the name `FILE.YYYY-MM-DD.HHMMSS.backup` assuming that `FILE` was the decrypted name. When encrypting files, overwriting the encrypted file happens without creating a backup, the file is simply overwritten if one of `--overwrite / -O` or `-y / --yes` is passed. Otherwise, initeractive mode question.

### Target path

- encrypt: `with_encrypted_suffix(&file)`. Input already ending in `.encrypted` is an error (no `x.encrypted.encrypted`).
- decrypt: `file` with the trailing `.encrypted` stripped (new helper `without_encrypted_suffix`). Input not ending in `.encrypted` is an error ("can't derive a plaintext name; use `-o`").

### Existing target

| Situation | Behaviour |
| --- | --- |
| Target absent | Write it |
| Target exists + `--overwrite / -O`  | Overwrite. When decrypting, automatically create the backup of the previous file, named `FILE.YYYY-MM-DD.HHMMSS.bak` | 
| Target exists + interactive TTY | `ui.confirm("<target> exists. Overwrite?")`, default **No**; on No, create backup, on yes, overwrite without a backup |
| Target exists + no TTY, no `--overwrite / -O` | Error: "`<target>` exists; pass `--overwrite`". Never overwrites silently |

### Writing

- Decrypt the full payload into memory before touching the target, so a failed decrypt never truncates an existing `.env`.
- Write to a temp file in the same directory, then rename it into place (atomic). The plaintext file gets mode `0600`. An executable script (check the first line for `#!`) gets `0700`.

### Plaintext guard (decrypt only)

When the target is inside a git repo and `git check-ignore <target>` says it is **not** ignored, print a warning ("`.env` is not git-ignored; it may get committed"). Writing still goes ahead. This uses the same `git/` helpers `check` already relies on.

## Tests

- [ ] encrypt `-w` round trips for dotenv, YAML and JSON. decrypt `-w` restores the original bytes.
- [ ] The `secrets encrypt|decrypt` forms behave identically.
- [ ] `-w` with `-o` is a clap error. `--overwrite | -O` without `-w` is a clap error.
- [ ] Wrong suffix is a validation error in both directions.
- [ ] Existing target: `--overwrite` overwrites; `SOPSY_ASSUME_YES=1` overwrites; no TTY and no flag errors and leaves the file untouched; a prompt answered No leaves it untouched.
- [ ] A failed decrypt leaves an existing target byte-for-byte unchanged.
- [ ] Both decrypted and encrypted files that are the result of a sopsy operation have permissions of `0600`; or `0700` for an executable script. 
- [ ] CLI parse tests and `completion` output include the new flags.

## Open questions

1. **Scope of `--overwrite`:** should it also apply to `-o`, which today overwrites silently? 

Answer: yes, make `-o ALTERNATIVE-OUTPUT-FILE` follow the same prompt/flag rules. It's a small behaviour change, mentioned in the changelog.

## Scope of this folder (backend-coder, round 1)

Per D4, this folder builds **change 1 only**: `-w` naming and the target-exists rules (including `-o` following them, per the open-question answer). Changes 2 (file modes `0600`/`0700`, atomic temp-file + rename) and 3 (git-ignore warning on decrypt) are split out and still need their own plan folders (`ol create`); nothing for them was built here. Their test rows above are out of scope.

## Backend

- [x] **U1 CLI flags.** `WriteArgs` (`-w/--write`, `-O/--overwrite`) in `src/cli/write_args.rs`, flattened into both arg structs. `-w` conflicts with `-o`; `-O` requires `-w` or `-o` (clap group `destination`). Parse tests live beside it.
- [x] **U2 Target naming.** `src/commands/secrets/target.rs`: `destination`, `conventional_name`, `without_encrypted_suffix`; wrong suffix is a validation error in both directions.
- [x] **U3 Existing-target policy + backup.** `src/commands/secrets/existing.rs`: `decide` returns `Write` / `BackupThenWrite` / `Skip`; `back_up` copies to `FILE.YYYY-MM-DD.HHMMSS.bak` (UTC) and never replaces an existing backup.
- [x] **U4 Wiring.** `src/commands/secrets/mod.rs` (moved from `secrets.rs`) uses U2/U3 through `Sink::deliver`; `Ui::with_assume_yes` / `assumes_yes` carry `--yes`/`-y` and `SOPSY_ASSUME_YES` (set in `lib.rs::run`).
- [x] **U5 Integration tests** in `tests/secrets.rs` against real `sops` + `age`.

## Frontend

None: CLI only. `frontend-coder` is not started.

## Implementation decisions (round 1)

- **Encrypt + interactive "No"** leaves the existing `.encrypted` file untouched and writes nothing (D2: no ciphertext backups; D5 only covers the plaintext direction). A warning says so.
- **`-y`/`--yes`** is the existing global alias of `--non-interactive`; an explicit flag (or `SOPSY_ASSUME_YES`) counts as "yes" for overwrite. A missing TTY alone does not, so a pipe without a flag errors.
- **Backup is a copy**, made before the write, so a failed write still leaves the original in place. Timestamp is UTC (no local-time dependency in the crate).
- **"A prompt answered No leaves it untouched"** in Tests is superseded by D5 for decrypt (backup, then write).
- `src/cli.rs` was already past the size limit; the new flags went into a new `src/cli/write_args.rs` rather than growing it.

## How to test

Automated (from the worktree root):

- `cargo fmt --all -- --check`: prints nothing.
- `cargo clippy --all-targets --all-features -- -D warnings`: no warnings.
- `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false cargo test --all`: every suite passes, including the new parse tests in `src/cli/write_args.rs`, the unit tests in `src/commands/secrets/{target,existing}.rs` and the `-w` tests in `tests/secrets.rs` (real `sops` + `age`).
- `cargo test --test secrets`: 13 end-to-end tests pass, 8 of them new for `-w`/`-O`.
- Coverage, as `.openlanes.yml` runs it: `rustup run stable cargo llvm-cov --all-features --workspace --json --summary-only --output-path target/llvm-cov-summary.json`, then `jq '.data[0].totals.lines.percent' target/llvm-cov-summary.json` prints a number of 95 or more.

By hand, in a repo where `sopsy init` has run and you can decrypt:

- `printf 'A=1\n' > .env && cargo run -- encrypt .env -w`: success line "wrote … to .env.encrypted"; `.env.encrypted` holds ciphertext.
- `rm .env && cargo run -- decrypt .env.encrypted -w`: writes `.env` back with `A=1`.
- `cargo run -- decrypt .env.encrypted -w < /dev/null | cat` with `.env` present: fails with "`.env` exists; pass `--overwrite` to replace it"; `.env` is unchanged.
- `cargo run -- decrypt .env.encrypted -w -O`: prints "backed up .env to .env.YYYY-MM-DD.HHMMSS.bak" (UTC stamp), then rewrites `.env`; the `.bak` file holds the old contents.
- `cargo run -- encrypt .env -w --overwrite`: replaces `.env.encrypted`; no `.bak` is made for ciphertext.
- `cargo run -- --yes decrypt .env.encrypted -w` and `SOPSY_ASSUME_YES=1 cargo run -- decrypt .env.encrypted -w`: both behave like `-O` (backup, then write).
- At a terminal, `cargo run -- decrypt .env.encrypted -w` with `.env` present asks ".env exists. Overwrite?". "Yes" overwrites; "No" backs `.env` up, then writes (D5). For `encrypt … -w`, "No" warns "left .env.encrypted unchanged; nothing written".
- `cargo run -- decrypt .env.encrypted -o out.env` with `out.env` present: same rules as `-w` (errors without a TTY or flag; `-O` backs up).
- `cargo run -- encrypt .env.encrypted -w`: error "already ends in `.encrypted`; refusing to write …".
- `cargo run -- decrypt .env -w`: error "can't derive a plaintext name … use `-o`".
- `cargo run -- encrypt .env -w -o x`: clap rejects `-w` with `-o`. `cargo run -- encrypt .env -O`: clap requires `-w` or `-o`.
- `cargo run -- secrets encrypt .env -w` / `secrets decrypt … -w`: the hidden alias behaves the same.
- `cargo run -- encrypt .env` with no `-w`/`-o`: still prints to stdout, as before.
- `cargo run -- completion zsh | rg -- '--write|--overwrite'`: both flags appear.
