# sopsy — Security Assessment (Barry Anderson)

sopsy is, on the whole, a security-conscious wrapper. It refuses to reimplement
crypto, it drives `sops`/`age`/`age-plugin-se` through argv (not a shell) so
classic command injection never gets a foothold, it never puts secret key
material on the command line, and it locks its keystore down to `0600`/`0700`.
The design is honest about the crypto reality it cannot change — "reading ==
re-granting", Enclave keys can't sign, roles are soft guardrails — and it says
so in code comments and docs rather than pretending otherwise. The rollback
snapshots around membership changes and the fail-fast non-interactive guards
(refusing to write key material to disk when it cannot prompt) are genuinely
good instincts. That said, the working-tree changes add real key-material and
integrity surface, and several of the new mechanisms either protect the wrong
thing, clean up incompletely, or are trivially disabled. The most serious issue
is not novel crypto — it is the mundane lifecycle of the portable break-glass/CI
private key on local disk, which is the crown jewel and is handled less
carefully than the far-less-sensitive Enclave handle. None of the findings below
are theoretical; each cites a concrete path in the current tree.

## Issues Found

1. **[HIGH] Portable break-glass / CI private key left recoverable on disk (CWE-459 incomplete cleanup, CWE-378 insecure temp file, CWE-276 permissions window).**
   `src/commands/recipient.rs:581-585` writes the `AGE-SECRET-KEY-1…` private
   half to `<output>.private` in the working directory, and only *then* calls
   `restrict_permissions` (`:583`). Between the `std::fs::write` and the
   `chmod 0600` the file exists at the process umask (commonly `0644`,
   world-readable). Deletion at `:634` is a plain `std::fs::remove_file`
   (unlink), not a secure erase — on APFS/copy-on-write SSDs the plaintext key
   blocks remain recoverable, and the file is a candidate for Time Machine,
   Spotlight indexing, and iCloud "Desktop & Documents" sync before it is
   removed. If the operator interrupts the ceremony at the ENTER prompt
   (`:629`) — Ctrl-C, crash, power loss — the `remove_file` never runs and the
   plaintext key persists in the repo tree. This key can decrypt **every**
   sopsy-managed secret.
   *Scenario:* on a shared/managed Mac, a second local user (or a backup/sync
   agent, or forensic recovery of the unlinked blocks) reads `ci.private` /
   `break-glass.private` during the write→chmod window or after an interrupted
   ceremony, and obtains a portable master key that is valid forever and off the
   Secure Enclave. `.gitignore` stops it reaching git; it does nothing for
   at-rest exposure.

2. **[MEDIUM] Re-key rollback is not atomic across the per-file `updatekeys` loop (CWE-460 improper cleanup on exception, CWE-362).**
   `run_updatekeys` (`src/commands/recipient.rs:725-727`) iterates
   `for file in &files { updatekeys_file(file)?; }`, re-wrapping each encrypted
   file in place. `ConfigSnapshot` (`:262-293`) only snapshots `.sopsy.yml`,
   `.sopsy.sha`, and `.sops.yaml` — **not** the encrypted bodies. If the loop
   succeeds for files 1–2 and fails on file 3, the caller (`add`/`remove`/
   `approve`/ceremony) restores the three config files and reports "rolled back —
   no recipient was added", yet files 1–2 already carry the new recipient's key
   stanza on disk.
   *Scenario (add/approve):* an operator adds recipient X; `updatekeys` fails
   partway (Touch ID timeout on a later file). sopsy says X was not added and
   the config no longer lists X, but X can now decrypt the files that were
   re-keyed before the failure — a silent, unrecorded grant. The mirror case
   (remove) silently strips a legitimate recipient from a subset of files while
   the config claims they are still a member.

3. **[MEDIUM] `init` stages plaintext secrets in `.env.encrypted` before encrypting, leaving cleartext in a git-committable file on failure (CWE-312 cleartext storage).**
   `src/commands/init.rs:91-96` does `let seed = read_seed(&root)?;
   std::fs::write(&env_encrypted, seed)?;` then `sops::encrypt_in_place(...)`.
   `read_seed` (`:362-372`) prefers an existing real `.env`, so on a re-run in a
   populated project the *real* secrets are written verbatim into
   `.env.encrypted` first. That path is explicitly **un-ignored**
   (`!*.encrypted` at `:106-119`), so git will track it. If `encrypt_in_place`
   errors or the process is interrupted between the write and the encryption,
   `.env.encrypted` holds plaintext secrets in a file the repo is configured to
   commit.
   *Scenario:* `sops` is misconfigured/absent-mid-run or the user Ctrl-Cs during
   the "Encrypting…" spinner; `git add .env.encrypted` (which the README quick
   start explicitly instructs) then commits cleartext secrets. `sopsy check`
   would catch it *if* re-run, but nothing forces that before the commit.

4. **[MEDIUM] The "non-bypassable" secret-scan gate is bound to a branch that does not exist (CWE-1327 / misconfiguration).**
   `.github/workflows/secret-scan.yml:24-25` triggers the push-path scan on
   `branches: [master]`, and the header comment (`:16-18`) tells the maintainer
   to mark the check required "for `master`". The repository's default branch is
   `main` (confirmed: `origin/HEAD → main`; `ci.yml:13` correctly uses `main`).
   The full-working-tree `gitleaks dir` scan therefore **never runs on push** —
   only the PR commit-range scan fires. Direct pushes to `main`, and any branch
   protection keyed to a non-existent `master`, provide no secret scanning at
   all, defeating the stated "authoritative, non-bypassable" gate.

5. **[MEDIUM] `secrets decrypt -o <file>` writes plaintext with default permissions, no `0600` (CWE-276 incorrect default permissions).**
   `src/commands/secrets.rs:104-114` writes decrypted output with a bare
   `std::fs::write(path, data)` — inheriting the umask (typically `0644`). The
   private-key ceremony bothers to `chmod 0600`, but the *decrypted secret
   payload* does not get the same care. The README's own CI recipe
   (`README.md:817-818`) recommends `sopsy secrets decrypt .env.encrypted -o .env`,
   materializing a group/world-readable plaintext secrets file on the runner (or
   the developer's multi-user host).
   *Scenario:* on a shared CI host or a developer box with other local accounts,
   any user with read access to the working tree reads the freshly written
   `.env` before it is deleted (if it ever is).

6. **[MEDIUM] The integrity checksum protects `.sopsy.yml` (metadata) but not `.sops.yaml` (the file that actually grants decryption) — false sense of protection (CWE-345 insufficient verification of data authenticity).**
   `.sopsy.sha` covers `.sopsy.yml` only (`src/config.rs:218-254`,
   `checksum_path` at `:227-229`). The file that `sops` actually consumes to
   decide who can decrypt is `.sops.yaml`, and it has **no** integrity sidecar.
   An attacker who appends their own `age` recipient to a `.sops.yaml`
   `creation_rules` block — the real privilege escalation — triggers no
   integrity warning anywhere; `sopsy check` only verifies that encrypted files
   *match a rule*, not that the rule set is unchanged. Meanwhile the checksum is
   keyless (SHA-256 of raw bytes + the *public* admin key, `:218-223`), so it is
   trivially recomputable and, by the project's own admission, "evidence, not
   proof". The net effect is that the mechanism draws attention to the
   low-value file and leaves the high-value one unguarded.

7. **[MEDIUM] Unverified/unpinned toolchain fetches in CI and in the documented user CI patterns (CWE-494 download of code without integrity check).**
   `.github/workflows/ci.yml:44-58` (and the coverage job `:84-94`) install
   `sops` and `age` with `curl … -o /usr/local/bin/sops; chmod +x` and no
   checksum or signature verification; the README's user-facing deploy workflow
   does the same (`README.md:805-810`) and `cargo install sopsy` is unpinned
   throughout. GitHub Actions in `ci.yml` are tag-pinned (`actions/checkout@v4`,
   `dtolnay/rust-toolchain@stable`, `codecov/codecov-action@v5`,
   `taiki-e/install-action@v2`) rather than SHA-pinned — note `release.yml`
   *does* SHA-pin its binary-upload action (`:58-65`), so the discipline exists
   but is applied inconsistently.
   *Scenario:* a compromised or MITM'd release asset (or a moved tag on a
   third-party action) executes attacker code in a CI context that, for the
   decrypt jobs, holds `SOPS_AGE_KEY` — i.e. the master decryption key.

8. **[LOW] `SOPSY_ASSUME_YES` is a presence check, so `=false` / `=0` / empty all *enable* the bypass (CWE-1254 / CWE-183 incorrect truthiness).**
   `assume_yes()` (`src/commands/recipient.rs:40-42`) returns true whenever the
   variable `is_some()`, regardless of value. This flag disables the only human
   trust decision in the approve flow — the vouch (`src/commands/approve.rs:262-265`)
   — and the "is the key stored safely?" confirmation before the portable key is
   deleted (`src/commands/recipient.rs:624-630`). A user who exports
   `SOPSY_ASSUME_YES=false` (or `=0`) to *disable* auto-confirm actually turns it
   *on*, auto-vouching for unverified keys and deleting break-glass material
   without confirmation.

9. **[LOW] `sopsy doctor` silently launders a tampered config by rewriting `.sopsy.sha` to match it (CWE-345).**
   `checksum_check` (`src/commands/doctor.rs:258-280`) loads `.sopsy.yml` via
   `Config::load_unverified` (`src/config.rs:262-273`, which skips the integrity
   check by design) and, when the sidecar is "stale", **overwrites** it with the
   checksum of whatever is currently on disk — emitting only a yellow `⚠` line
   buried in the doctor's wall of output. `doctor` is documented as safe,
   informational, and "always exit 0", so operators run it reflexively.
   *Scenario:* an attacker edits `.sopsy.yml` out of band; the next `sopsy load`
   would flag the mismatch, but a single `sopsy doctor` (run by the attacker or
   an unsuspecting teammate) re-blesses the tampered file into a "verified"
   state, and the strict loader stops complaining thereafter.

10. **[LOW] Join-request TTL freshness is trivially bypassed (CWE-807 reliance on untrusted input for a security decision).**
    `check_freshness` (`src/commands/approve.rs:196-241`) treats a **missing**
    `requested_at` as "cannot verify freshness → proceed" (`:204-209`), and
    `request_age` (`:244-251`) maps a **future** timestamp to `Duration::ZERO`
    (always fresh). The timestamp is written by the joiner and lives in an
    editable YAML file, so a stale request is re-freshed by deleting the field
    or setting a future date in a PR. This is advisory by design, but it should
    not be described or relied on as an access-control window.

11. **[LOW] `approved_by` provenance is derived from spoofable `$USER`/`$LOGNAME` (CWE-290 spoofing).**
    `resolve_approver` (`src/commands/approve.rs:140-150`) reads the system
    username via `system_username` (`src/commands/recipient.rs:48-58`) and writes
    it into the committed audit trail as "Full Name (username)". Both env vars
    are attacker-controlled, so the "who approved this" column in
    `recipient list` can be forged to name any teammate. The code comments it as
    a soft record, and git commit authorship is the real trail — but the README
    (`:79`, `:464`) presents it as "a built-in audit trail", which oversells a
    field that cannot be trusted.

12. **[LOW] User-controlled file paths reach `sops`/`age` without an end-of-options (`--`) guard (CWE-88 argument injection).**
    `src/sops/mod.rs` builds `edit` (`:169-190`), `encrypt_in_place` (`:196-206`),
    `encrypt_to_string` (`:215-231`), and `decrypt` (`:237-247`) by appending the
    file path as a positional with no preceding `--`. A path beginning with `-`
    (e.g. a file literally named `--output=/tmp/x`) is parsed by `sops` as an
    option rather than a filename. The `updatekeys` path
    (`src/commands/recipient.rs:746-762`) is safe because it feeds absolute
    `repo.join(...)` paths, but the user-facing `edit`/`secrets` paths accept
    relative names verbatim. Low impact (the attacker already controls a
    filename), but the `--` separator is free defense in depth.

13. **[INFO] Global gitleaks allowlist for age public keys can suppress unrelated findings (CWE-1230 weak allowlist).**
    `.gitleaks.toml:44-47` allowlists `age1[0-9a-z]{8,}` at global scope (applies
    to every rule). It correctly avoids matching `AGE-SECRET-KEY-…` /
    `AGE-PLUGIN-SE-…` private material, but because it is a global line-level
    allowlist, any committed line that *also* contains an `age1…` token could
    have a genuine adjacent secret suppressed. Low likelihood, worth scoping.

## Rectifying These Problems

1. **Stop writing the portable key to the repo tree, close the permission
   window, and clean up robustly.** Create the private file with restrictive
   mode *atomically* (e.g. `OpenOptions::new().write(true).create_new(true)
   .mode(0o600)` on unix) rather than write-then-chmod. Prefer a path under a
   `0700` dir in `$TMPDIR` (or, better, print the key to a paged/one-shot prompt
   and never touch disk) instead of the working directory. Best-effort overwrite
   the bytes before unlink, and register a cleanup guard (Rust `Drop` / signal
   handler) so an interrupted ceremony still deletes the file. Document that
   users on managed Macs should disable iCloud Desktop sync / exclude the repo
   from Time Machine for the duration. Residual risk: secure erase is not
   guaranteed on CoW SSDs — treat any key that ever hit disk as rotatable and
   say so.

2. **Make the re-key transactional.** Extend `ConfigSnapshot` to also snapshot
   (or copy aside) every file `run_updatekeys` will touch, and on any per-file
   failure restore *all* of them — encrypted bodies included — before restoring
   the config. Sketch: capture `Vec<(PathBuf, Vec<u8>)>` for the collected
   encrypted files at `recipient.rs:719`, and have the error arms in
   `add`/`remove`/`approve`/ceremony call a `restore_all()` that rewrites those
   too. Residual risk: a crash mid-restore still leaves a mixed state; pair with
   a `sopsy check`/`doctor` invariant that flags "a recipient in `.sops.yaml`
   whose stanza is absent from some encrypted files".

3. **Never place plaintext at a committable path.** Encrypt from a private
   staging location: write the seed to a `0600` temp file outside the repo (or
   feed it to `sops` on stdin) and only write `.env.encrypted` once `sops`
   returns success. On encryption failure, ensure the partially written target
   is removed. Sketch: replace the `write(&env_encrypted, seed); encrypt_in_place`
   pair (`init.rs:92-96`) with an encrypt-to-string into a temp then atomic
   rename of the ciphertext into place. Residual risk: none material once
   plaintext never lands at `*.encrypted`.

4. **Fix the branch filter.** Change `secret-scan.yml:25` to
   `branches: [main]` (and update the comments at `:16-18`), then mark the
   `secret-scan` check required in branch protection for `main`. Residual risk:
   branch protection is a repo setting the code cannot enforce — verify it in
   the GitHub UI.

5. **Restrict decrypted output files.** In `write_output`
   (`secrets.rs:104-114`), create `-o` targets with mode `0600` (atomic
   `create_new` + `mode`, matching `restrict_permissions`), and warn when the
   target is inside the repo. Update the README CI example to prefer the
   `eval "$(… decrypt …)"` in-memory pattern over materializing `.env`, and to
   `chmod 600`/clean up if a file is unavoidable. Residual risk: env-var secrets
   are still visible via `/proc/<pid>/environ` to the same user/root — inherent
   to the model, document it.

6. **Extend integrity coverage to `.sops.yaml`, or drop the false comfort.**
   Either add a sidecar/known-good hash for `.sops.yaml` (the file that actually
   grants access) and verify it on the read paths, or reposition `.sopsy.sha`
   explicitly as a formatting/accident tripwire only. If keeping it, bind it to
   something the committing author controls that a metadata editor does not
   (still not cryptographic proof — say plainly that git history + PR review of
   `.sops.yaml` diffs is the real control). Residual risk: without signing
   (Enclave keys can't sign), none of this is tamper-*proof*; make PR review of
   recipient changes a required, human step.

7. **Pin and verify everything you download.** In `ci.yml`, download `sops`/`age`
   to a temp path, verify a pinned SHA-256 (the projects publish checksums)
   before `install`, and SHA-pin every third-party action (as `release.yml`
   already does for `upload-rust-binary-action`). Update the README deploy
   snippet to verify the `sops` checksum and to pin `sopsy`
   (`cargo install sopsy --version x.y.z --locked`). Residual risk: trust root
   is still the upstream publisher — pinning bounds the blast radius to a
   knowingly-chosen artifact.

8. **Parse the flag as a boolean.** Replace `assume_yes()`'s `is_some()`
   (`recipient.rs:40-42`) with a truthiness check that treats `""`, `0`,
   `false`, `no`, `off` as *disabled* and only `1`/`true`/`yes`/`on` as enabled;
   log which interpretation was taken. Residual risk: the flag still fully
   bypasses the vouch — keep it out of any shared/default environment and
   document that it is CI-only.

9. **Do not silently re-bless.** Have `checksum_check` (`doctor.rs:258-280`)
   *report* a stale/mismatched sidecar as a prominent failure (`ui.failure`) and
   only repair behind an explicit, opt-in flag (e.g. `sopsy doctor --repair-checksum`)
   or an interactive confirmation that shows the `git diff` first. Residual
   risk: an operator can still approve a malicious diff — but now it is a
   deliberate, visible act, not a side effect of a "safe" command.

10. **Treat freshness as advisory and fail closed where it matters.** Make a
    missing `requested_at` a hard stop in strict (named) mode instead of
    warn-and-proceed (`approve.rs:204-209`), and clamp future timestamps to
    "reject as implausible" rather than "fresh" (`:244-251`). Residual risk: the
    field is still editable in a PR — the vouch and PR review remain the real
    gate; document the TTL as a reminder, not a control.

11. **Downgrade the audit-trail claims, or anchor them.** Keep `approved_by` but
    label it in output as self-reported, and point operators to git commit
    signatures / branch-protection review as the authoritative record. Update
    README wording (`:79`, `:464`) so "audit trail" is not read as tamper-proof.
    Residual risk: without signing there is no cryptographic approver identity —
    accept and disclose this.

12. **Add `--` before user file paths.** In each `sops`/`age` invocation in
    `src/sops/mod.rs` (and any user-path invocation), push `"--"` immediately
    before the file argument so a leading-`-` filename can never be read as an
    option. Residual risk: negligible; this is a pure hardening change.

13. **Scope the allowlist.** Constrain the `age1…` allowlist in `.gitleaks.toml`
    to the files/paths where public keys legitimately appear (tests, fixtures,
    `.sops.yaml`, `.sopsy.yml`) via a `paths`-qualified `[[allowlists]]` entry
    rather than a global regex, so it cannot mask a secret elsewhere. Residual
    risk: low; verify with a seeded test secret.
