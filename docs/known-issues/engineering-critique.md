# sopsy — Engineering & Security Critique (merged, re-verified)

This document merges the two prior critiques — a security assessment (Barry
Anderson) and a staff-engineer review — into a single list, with every issue
re-verified against the working tree as of **2026-07-05** and its severity
re-calibrated. Where the code has changed since the original reviews, the
finding is marked **Resolved** or **Partially mitigated** rather than deleted, so
the history stays legible.

sopsy remains a security-conscious wrapper: it drives `sops`/`age`/`age-plugin-se`
through argv (no shell, so no command injection), never puts key material on the
command line, locks its keystore to `0600`/`0700`, and is honest in code and docs
about the crypto reality it cannot change ("reading == re-granting", Enclave keys
can't sign, roles are soft guardrails). Clippy is clean and the integration suite
drives real `sops`/`age`/`git`. The findings below are mostly about failure paths
and lifecycle edges, not novel crypto.

## Status summary

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | Nested `*.encrypted` files skipped by re-key globs | Medium | Confirmed |
| 2 | `recipient remove` re-wraps but never rotates the data key | Medium | Confirmed (partly by design) |
| 3 | Mid-mutation failures (before `updatekeys`) bypass rollback | Medium | Confirmed |
| 4 | Approver is never checked to be an active member | Medium | Confirmed |
| 5 | `check`'s hand-rolled regex mis-evaluates common `path_regex` syntax | Medium | Confirmed |
| 6 | `mutate_sops_yaml` destroys `.sops.yaml` comments/formatting | Medium | Confirmed |
| 7 | `secret-scan` push trigger targets `master`; repo is `main` | Medium | Confirmed |
| 8 | `just warnings` runs `-D warmings` (typo) — dead release gate | Medium | Confirmed |
| 9 | `.sopsy.sha` sidecar: friction-heavy, weak evidence, guards the wrong file | Medium (UX) / Low (security) | Confirmed |
| 10 | Portable break-glass/CI key lifecycle on disk | Medium | Partially mitigated |
| 11 | `Config::save` is a non-atomic two-file write | Low–Medium | Confirmed |
| 12 | `secrets decrypt -o <file>` writes plaintext with default perms | Low–Medium | Confirmed |
| 13 | Unpinned/unverified `sops`/`age` downloads in CI and docs | Low | Confirmed |
| 14 | `SOPSY_ASSUME_YES` is a presence check (`=false`/`=0` still enable) | Low | Confirmed |
| 15 | `doctor` silently re-blesses a tampered config | Low | Confirmed |
| 16 | Join-request TTL freshness trivially bypassed | Low | Confirmed (advisory by design) |
| 17 | `approved_by` derived from spoofable `$USER`; "audit trail" oversold | Low | Confirmed |
| 18 | No `--` end-of-options guard before user file paths | Low | Confirmed |
| 19 | `recipient list` truncates public keys to 24 chars | Low | Confirmed |
| 20 | `approve` next-steps references nonexistent `sopsy decrypt` | Low | Confirmed |
| 21 | Unused `toml` dependency | Low | Confirmed |
| 22 | No format validation of supplied age public keys | Low | Confirmed |
| 23 | Global gitleaks allowlist for `age1…` can mask adjacent secrets | Info | Confirmed |
| — | Re-key rollback didn't restore already-re-wrapped encrypted bodies | (was Medium) | **Resolved** |
| — | Failed `init` left plaintext in `.env.encrypted` | (was Critical) | **Resolved** |

______________________________________________________________________

## Medium

### 1. Nested `*.encrypted` files are silently skipped during re-keying

*Was: Staff #3. Rated High; calibrated to Medium.*

`sops` matches by regex, so `.sops.yaml`'s `\.encrypted$`
(`init.rs:367`) matches an artifact at **any** depth. sopsy re-keys by
single-level globs (`expand_glob`, `recipient.rs:860-887`; defaults
`config.rs:176-182`): `*` never crosses `/` and there is no `**`. So a
`secrets/prod.env.encrypted` that `sops` will happily create is never re-wrapped
by `add`/`remove`/`approve`. `check` uses the same glob semantics, so CI passes
vacuously.

**Verified:** still present. Defaults cover top-level (`*.encrypted`,
`.env.encrypted`) and one nested pattern (`config/*.encrypted.yaml`); arbitrary
nesting is missed. `secrets encrypt -o <path>` only validates the `.encrypted`
suffix (`secrets.rs:45-56`), not that the path is within a managed glob.

**Impact (calibrated):** A newly approved member can't decrypt nested files
(confusing but visible); a *removed* member keeps a live key stanza in nested
files (invisible — a revocation gap). Only bites repos that place encrypted
files below the two default directories.

**Fix:** Derive the re-key/check file set from `.sops.yaml` itself — walk the
tree (as `check` already does) and match repo-relative paths against the
creation-rule regexes, exactly as `sops` will. Failing that, add `**` support,
change defaults to `**/*.encrypted`, and make `secrets encrypt -o` warn when the
output path matches no configured glob/rule.

### 2. `recipient remove` re-wraps but never rotates the data key

*Was: Staff #4. Rated High; calibrated to Medium (largely inherent to the model).*

`sops updatekeys` re-encrypts the *existing* data key for the new recipient set;
it does not generate a new one (that is `sops rotate`). A removed member who ever
decrypted a file can retain the data key and read every *future* revision until a
full rotation — which sopsy never performs. The success line "recipient `X`
removed" (`recipient.rs:252`) reads stronger than the guarantee.

**Verified:** still uses `updatekeys`, never `rotate`.

**Impact (calibrated):** This is the documented "reading == re-granting" reality,
not a bug in the crypto. The actionable gap is that the one command whose purpose
is revocation neither rotates nor warns. Rotation is genuinely heavier (rewrites
bodies, bigger diffs), so a default rotation may not be wanted.

**Fix:** At minimum, print an unmissable warning on `remove`: "the data key was
re-wrapped, not rotated; a member who previously decrypted may retain access to
future revisions — run `sops rotate -i <file>` to fully rotate." Optionally add a
`--rotate` flag. Silence is the only unacceptable option.

### 3. Mid-mutation failures before `updatekeys` bypass the rollback entirely

*Was: Staff #6. Medium.*

The `ConfigSnapshot` is only restored when `run_updatekeys` fails. Earlier
fallible steps after the snapshot — `config.save_to_dir(&repo)?`
(`recipient.rs:158`) and `add_key_to_sops_yaml(...)?` (`:162`) — return via `?`
without restoring. Concrete trigger: `.sops.yaml` exists (passes the check at
`:91-100`) but has a YAML syntax error; `add` writes the recipient into
`.sopsy.yml`+`.sopsy.sha`, then `mutate_sops_yaml` fails to parse
(`recipient.rs:976-979`) and the command exits leaving `.sopsy.yml` listing a
recipient `.sops.yaml` doesn't have.

**Verified:** same structure in `add`, `remove`, ceremony, and `approve`
(`approve.rs:100` then `:109`).

**Impact (calibrated):** Leaves the two config files inconsistent; no secret is
exposed and no access is granted (nothing was re-keyed). Recoverable by hand or
by re-running, but confusing.

**Fix:** Wrap the mutation phase so any `Err` triggers `snapshot.restore()`
before returning (see the closure sketch in the original Staff review). Also
parse-validate `.sops.yaml` up front (`serde_yaml_ng::from_str`) so the common
failure never mutates anything.

### 4. Nothing checks that the approver is an active member

*Was: Staff #9, related Security #11. Medium.*

`approve.rs` documents "any **active** member can approve" but enforces nothing.
Normally the crypto gate (`updatekeys` needs decryption ability) provides de-facto
enforcement — but `sopsy approve <me> --no-updatekeys` skips exactly that gate. A
pending member could flip themselves to `active`, insert their key, self-vouch
(`SOPSY_ASSUME_YES` or their own terminal), and record `approved_by: themselves`;
the next legitimate re-keying then grants them the data key.

**Verified:** `resolve_approver` (`approve.rs:140-150`) is label-only; no gate.

**Impact (calibrated):** Requires the attacker to already have repo write access
and get a poisoned commit merged — git review is the real backstop, as the docs
note. Still, this is an invariant the tool *can* check locally and currently
doesn't.

**Fix:** In `approve::run`, require the resolved approver to map (via `username`
or an explicit `--as <name>`) to an active, non-pending recipient; refuse
self-approval; and warn loudly when `--no-updatekeys` skips the crypto gate. Keep
`--force` as the documented escape hatch.

### 5. `check`'s hand-rolled regex engine mis-evaluates common `path_regex` syntax

*Was: Staff #11. Medium.*

`regex_is_match` (`check.rs:359-398`) is a Kernighan/Pike matcher supporting only
`^ $ . * \`. Real `.sops.yaml` files use `\.ya?ml$`, `(dev|prod)\.enc$`,
`[^/]+\.encrypted$` — here `? ( | ) [ ]` all match as *literal characters*. So a
valid rule can make invariant 4 report "encrypted file matches no creation rule"
and fail CI, or an unsupported pattern that *should* flag a gap silently doesn't.

**Verified:** still literal-only for unsupported metacharacters; no "cannot
evaluate this pattern" path.

**Impact (calibrated):** A CI gate that is confidently wrong on valid input.
Likelihood depends on how fancy the repo's regexes are; the sopsy-generated
defaults (`\.encrypted$`) are fine.

**Fix:** Use a small real engine (`regex-lite`) for `check`, or scan the pattern
for unsupported metacharacters and report "unsupported path_regex `…` — cannot
evaluate this rule" as an explicit failure rather than treating them as literals.

### 6. Every recipient mutation destroys `.sops.yaml` comments and formatting

*Was: Staff #12. Medium.*

`mutate_sops_yaml` (`recipient.rs:971-1004`) round-trips the file through
`serde_yaml_ng::Value`, which drops all comments (including the
`# Managed by sopsy.` header `init` writes, `init.rs:363`), resolves anchors, and
rewrites quoting/indentation. The doc comment (`recipient.rs:945-947`,
"preserving all other YAML") claims the opposite; the existing test only checks
that *data* keys survive, not comments.

**Verified:** still a full serde round-trip.

**Impact (calibrated):** No security impact — data (rules, keys) is preserved.
It's a correctness/UX papercut: teams that annotate rules ("# prod keys — ask
@alice") lose those annotations on every `add`/`remove`/`approve`, and the doc
comment is misleading.

**Fix:** Minimal honest fix — correct the doc comment and re-emit the managed-by
header after serialization. Better — do a targeted textual splice of the `age:`
value (already normalized to a single comma-separated string), falling back to
the serde round-trip with a warning only when the structure is unrecognizable.

### 7. `secret-scan` push trigger targets `master`, but the repo's branch is `main`

*Was: Security #4, Staff #13. Medium.*

`.github/workflows/secret-scan.yml:23-24` triggers the push-path scan on
`branches: [master]`, and the header (`:16-18`) tells the maintainer to mark the
check required "for `master`". The default branch is `main` (`origin/HEAD → main`;
`ci.yml:13` correctly uses `main`). So the full-tree `gitleaks dir` scan never
runs on direct pushes to `main` — only the PR commit-range scan fires — despite
the file calling itself "the authoritative, non-bypassable secret gate".

**Verified:** still `[master]` in both the trigger and the comments.

**Impact (calibrated):** The PR trigger still covers the normal path, so this is a
gap in defense-in-depth (direct pushes), not a wide-open door. Branch protection
keyed to a nonexistent `master` would silently protect nothing.

**Fix:** `branches: [main]`, update the comments, and mark `secret-scan` required
in branch protection for `main` (a repo setting the code can't enforce — verify
in the GitHub UI). Grep for other `master` remnants while there.

### 8. `just warnings` runs `-D warmings` — the release gate is a no-op

*Was: Staff #10. Medium.*

`justfile:32` is `cargo clippy -- -D warmings` — denying a lint that doesn't
exist. rustc emits "unknown lint" *as a warning* and exits 0, so `build` and the
whole `publish` chain (`justfile:22,46`) never actually deny warnings.
Secondary: `publish` depends on `fmt`, which *mutates* the tree (`cargo fmt`, not
`--check`) right before `cargo publish`, so the published crate can differ from
the committed code. CLAUDE.md documents the typo instead of fixing it.

**Verified:** typo still present; `publish: fmt warnings test …`.

**Fix:** `warnings: cargo clippy --all-targets --all-features -- -D warnings`
(matching CI), change the `publish`/`build` dependency to a non-mutating
`fmt-check: cargo fmt --all -- --check`, and remove the CLAUDE.md sentence that
enshrines the typo.

### 9. `.sopsy.sha`: high friction, weak evidence, guards the metadata not the grant

*Was: Security #6, Security #9, Staff #5. Rated up to Critical-ish; calibrated to
Medium (UX) / Low (security).*

Three related observations about the integrity sidecar:

- **Guards the wrong file.** `.sopsy.sha` covers `.sopsy.yml` (metadata)
  only (`config.rs:218-229`). The file `sops` actually consumes to decide who can
  decrypt is `.sops.yaml`, which has **no** sidecar. Appending a rogue recipient
  to `.sops.yaml` triggers no integrity warning.
- **Merge friction.** `Config::load` hard-fails on a checksum mismatch
  (`config.rs:245-252`). Two concurrent join PRs both rewrite the single-line
  sidecar, so merging the second conflicts in both files; after any hand-resolve,
  every sopsy command fails "edited outside sopsy" until someone runs `doctor`.
- **Weak evidence + auto-bless.** The checksum is keyless (SHA-256 of raw bytes +
  the *public* admin key, `config.rs:218-223`), so anyone recomputes it; and
  `doctor` re-blesses whatever is on disk (see #15). By the project's own
  admission it is "evidence, not proof."

**Verified:** all three still hold as described.

**Impact (calibrated):** The security value was always modest and is documented as
such (Enclave keys can't sign; git history is the real audit trail). The concrete
harm is UX: honest users hit a scary error on routine merges and learn to
reflexively run the command that blesses any edit.

**Fix:** Demote `Config::load` to *warn* on mismatch (reserve hard failure for an
explicit `check`), hash a canonicalized serialization instead of raw bytes so a
clean merge doesn't invalidate it, and ship a `.gitattributes`/doc note pointing
conflicts at `doctor`. If integrity of `.sops.yaml` matters, the real control is a
required human PR review of recipient changes — say so plainly rather than
implying the sidecar provides it.

### 10. Portable break-glass / CI private key lifecycle on disk

*Was: Security #1 (High), Staff #8 (Medium). Calibrated to Medium; the interrupt
case is now mitigated.*

The ceremony (`recipient.rs:586-743`) writes the `AGE-SECRET-KEY-1…` private half
to `<output>.private` in the working directory, hands it to the operator, waits
for ENTER, then deletes it. Since the original review, two mitigations were added:

- A `KeyFileGuard` (RAII `Drop`, `recipient.rs:553-578`) shreds both halves on
  every normal/error return and panic.
- A signal handler (`arm_ceremony_signal_cleanup`, `:530-545`) shreds them on
  SIGINT/SIGTERM/SIGHUP — so Ctrl-C at the prompt no longer strands the key.

**Still open, verified:**

- **Permission window.** `std::fs::write(&private_path, …)` (`:642`) then
  `restrict_permissions` (`:644`) — the file exists at the umask (often `0644`)
  between the two.
- **No secure erase.** Deletion is plain `remove_file`; on CoW SSDs the blocks may
  remain recoverable, and the file is a candidate for Time Machine / Spotlight /
  iCloud sync while it exists.
- **EOF counts as confirmation.** Interactivity is stdout-only
  (`ui.rs:66-71`); stdin is never checked. `press_enter` (`ui.rs:219-232`) returns
  `Ok(())` on `read_line` EOF. So `break-glass -o bg < /dev/null` (stdout a TTY),
  or Ctrl-D instead of ENTER, proceeds to delete the disaster-recovery key before
  the operator stored it.
- **Delete-before-register ordering.** The local copies are removed (`:702-703`)
  *before* the recipient is registered and re-keyed (`:708-733`); if registration
  fails, the only copy is already off-box.

**Impact (calibrated):** The guard/signal work closed the worst interrupt paths.
The residual risks are a short world-readable window, non-guaranteed erase, and
the EOF/ordering foot-guns — real, but each requires either local co-tenancy or an
operator error. Down from High to Medium.

**Fix:** Create the private file atomically with `0600`
(`OpenOptions::create_new().mode(0o600)`); best-effort overwrite before unlink;
treat EOF as *refusal* in `press_enter` (`read_line` returning 0 → error) and fold
`stdin().is_terminal()` into interactivity detection; reorder so deletion happens
*after* the recipient is registered and re-keyed. Document that any key that ever
hit disk should be treated as rotatable.

______________________________________________________________________

## Low

### 11. `Config::save` is a non-atomic two-file write

*Was: Staff #7.* `save` (`config.rs:283-292`) writes `.sopsy.yml` then `.sopsy.sha`
with plain `std::fs::write`. A crash between the two makes the next `load` fail the
integrity check for a file sopsy half-wrote. The crate already depends on
`tempfile`. **Fix:** write to a `NamedTempFile` in the same dir and `persist()`
over each target. (Combined with #9's warn-not-fail posture, a one-save-behind
sidecar costs a warning, not an outage.)

### 12. `secrets decrypt -o <file>` writes plaintext with default permissions

*Was: Security #5.* `write_output` (`secrets.rs:104-114`) is a bare
`std::fs::write(path, data)`, inheriting the umask (often `0644`). The README CI
recipe (`README.md:818`) recommends `sopsy secrets decrypt .env.encrypted -o .env`,
materializing a group/world-readable plaintext file. **Fix:** create `-o` targets
`0600` (atomic `create_new` + `mode`); prefer the in-memory
`eval "$(… decrypt …)"` pattern in docs and `chmod 600`/clean up when a file is
unavoidable. (Env-var secrets remain visible via `/proc/<pid>/environ` to the same
user — inherent, document it.)

### 13. Unpinned/unverified `sops`/`age` downloads in CI and docs

*Was: Security #7.* `ci.yml:45-56,86-94` install `sops`/`age` via
`curl … -o …; chmod +x` with no checksum/signature; the README deploy workflow
(`README.md:807-810`) does the same, and `cargo install sopsy` is unpinned.
GitHub Actions are tag-pinned (`@v4`/`@v2`/`@v5`) not SHA-pinned — note
`release.yml` *does* SHA-pin its upload action, so the discipline exists but is
applied inconsistently. **Fix:** download to a temp path, verify a pinned SHA-256
before install, SHA-pin third-party actions, and pin `sopsy`
(`--version x.y.z --locked`).

### 14. `SOPSY_ASSUME_YES` is a presence check

*Was: Security #8.* `assume_yes()` (`recipient.rs:40-42`) returns true whenever the
var `is_some()`, so `SOPSY_ASSUME_YES=false`/`=0`/`""` all *enable* the bypass —
auto-vouching (`approve.rs:262`) and skipping the break-glass confirmation.
**Fix:** parse truthiness (`""`/`0`/`false`/`no`/`off` → disabled). **Impact:**
low — it takes a user actively setting the var to the "wrong" falsey value.

### 15. `doctor` silently re-blesses a tampered config

*Was: Security #9.* `checksum_check` (`doctor.rs:258-280`) rewrites `.sopsy.sha` to
match whatever is on disk, emitting only a yellow `⚠`. Since `doctor` is
documented as safe and is run reflexively, a tampered `.sopsy.yml` gets
"verified". **Fix:** report a stale/mismatched sidecar as a prominent failure and
repair only behind an explicit `--repair-checksum` (or an interactive confirm that
shows `git diff` first). Closely tied to #9; if `load` only warns, this matters
less.

### 16. Join-request TTL freshness is trivially bypassed

*Was: Security #10.* `check_freshness` (`approve.rs:204-209`) treats a **missing**
`requested_at` as "proceed", and `request_age` (`:244-251`) maps a **future**
timestamp to `Duration::ZERO` (always fresh). The timestamp is joiner-written in an
editable YAML file. **Impact:** advisory by design — the vouch and PR review are
the real gate — so this is low, but it shouldn't be described as an access-control
window. **Fix:** make a missing `requested_at` a hard stop in strict (named) mode
and clamp implausible future timestamps to "reject", not "fresh".

### 17. `approved_by` is derived from spoofable `$USER`; "audit trail" is oversold

*Was: Security #11.* `resolve_approver` (`approve.rs:140-150`) reads
`$USER`/`$LOGNAME` and writes it into the committed record as "Full Name
(username)". Both env vars are user-controlled, so the "who approved" column can
name anyone. The code comments it as a soft record, but README (`:79`, `:464`)
calls it "a built-in audit trail". **Fix:** label the field in output as
self-reported and point to git commit signatures / branch-protection review as the
authoritative record; soften the README wording.

### 18. No `--` end-of-options guard before user file paths

*Was: Security #12.* `sops/mod.rs` appends the file path as a positional with no
preceding `--` in `edit` (`:169-190`), `encrypt_in_place` (`:196-206`),
`encrypt_to_string` (`:215-231`), and `decrypt` (`:237-247`). A path beginning with
`-` is parsed by `sops` as an option. Low impact (the attacker already controls a
filename), but `--` is free defense in depth. **Fix:** push `"--"` before the file
argument in each invocation.

### 19. `recipient list` truncates public keys to 24 characters

*Was: Staff #14.* `KEY_COL_MAX = 24` (`recipient.rs:400`) shows almost none of a
~62-char age key, so two keys can render identically — in the very table an
approver eyeballs while vouching. (`truncate` also yields max+1 chars, so the
"cap" isn't one; codified by the test at `recipient.rs:1064`.) **Fix:** show the
full key (this table is the audit surface), or keep prefix *and* suffix.

### 20. `approve` next-steps references a nonexistent `sopsy decrypt`

*Was: Staff #15.* `approve.rs:289` prints "can `sopsy edit`/`sopsy decrypt`" — the
command is `sopsy secrets decrypt`. The newcomer's first suggested action is an
argument-parse error. **Fix:** one-line correction to `sopsy secrets decrypt`; add
a cheap test that greps next-steps strings for `sopsy <word>` tokens and asserts
each is a real subcommand.

### 21. Unused `toml` dependency

*Was: Staff #16.* `Cargo.toml:37` declares `toml = "1.1.2"`; `rg` finds zero uses
in `src/`/`tests/`. Dead compile time and supply-chain surface. **Fix:** remove it;
consider `cargo machete`/`cargo-udeps` in CI.

### 22. No format validation of supplied age public keys

*Was: Staff #17.* `join` (`join.rs:108-114`), `recipient add`
(`recipient.rs:120-129`), and `init --public-key` (`init.rs:249-255`) only check
for emptiness. A garbage key is persisted and then makes *every* later re-keying
op fail (and roll back) until hand-edited — which then trips #9's tamper error.
**Fix:** a shared validator (`age1`/`age1se1` prefix, bech32 charset, sane length)
applied at all three entry points, rejecting with "that does not look like an age
public key (age1…)".

______________________________________________________________________

## Info

### 23. Global gitleaks allowlist for `age1…` can mask adjacent secrets

*Was: Security #13.* `.gitleaks.toml:44-46` allowlists `age1[0-9a-z]{8,}` at global
scope (applies to every rule). It correctly avoids matching private
`AGE-SECRET-KEY-…`/`AGE-PLUGIN-SE-…` material, but as a global line-level
allowlist, a committed line that *also* contains an `age1…` token could have a
genuine adjacent secret suppressed. **Fix:** scope the allowlist to the paths where
public keys legitimately appear (tests, fixtures, `.sops.yaml`, `.sopsy.yml`) via a
`paths`-qualified entry; verify with a seeded test secret.

______________________________________________________________________

## Resolved since the original reviews

### Re-key rollback now restores already-re-wrapped encrypted bodies

*Was: Security #2, Staff #2 (both rated High; calibrated to Medium). Fixed on
this branch.*

`ConfigSnapshot` (`recipient.rs:262-...`) previously captured only the three
config files (`.sopsy.yml`, `.sopsy.sha`, `.sops.yaml`), so a mid-loop
`sops updatekeys` failure left the files already re-wrapped for the new recipient
set carrying the new key stanza even though `add`/`remove`/`approve`/the
portable-key ceremony reported a clean rollback. It now **also snapshots the
bytes of every managed encrypted file** — the same set `run_updatekeys` re-wraps,
stable because these commands never change `encrypted_globs` — and `restore()`
rewrites those bodies first (the security-critical data), then the config files.
`capture` stays infallible and no callsite signatures changed, so every caller
gains correct rollback for free; `run_updatekeys` stays fail-fast. Covered by
`add_rollback_restores_already_rewrapped_bodies` and
`remove_rollback_restores_already_rewrapped_bodies` in `tests/recipient.rs`
(a fake `sops` that re-wraps `a.encrypted`, fails on `b.encrypted`, and asserts
`a.encrypted` is restored to its pre-command bytes).

### Failed `init` left plaintext secrets in a committable `.env.encrypted`

*Was: Security #3 (Medium), Staff #1 (Critical).*

The original flow wrote the seed plaintext directly into `.env.encrypted` and then
encrypted in place, so a `sops` failure left cleartext in a committable file. This
is **fixed**: `init` now (`init.rs:120-136`) writes the seed to a
`tempfile::NamedTempFile` (`0600`, in the system temp dir, outside the repo),
encrypts straight to a string via `sops::encrypt_to_string`, and writes the
ciphertext to `.env.encrypted` only on success. The `.gitignore` step was also
moved *before* encryption (step 7, `init.rs:86-112`), so even a crash mid-encrypt
lands in an ignored-by-default state. Plaintext no longer touches the committable
artifact path.

Residual nit: the idempotency branch still keeps a pre-existing `.env.encrypted`
untouched (`init.rs:121-122`); it can't recreate the leak (nothing writes plaintext
there anymore), but a stricter check could refuse to "keep" a file lacking sops
markers.
