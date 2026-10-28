# 001 — Pluggable key stores (YubiKey, Intel Mac, Linux)

Status: **spec — synced with `spec.md` on 2026-10-28; all questions decided; verify "Facts" before coding**

Source of intent: [`spec.md`](spec.md). This file is the implementation plan for it.

## Problem

sopsy generates member identities only through `age-plugin-se` (Secure Enclave), and only Apple Silicon is supported. As a result `init`, `join` and `recipient keygen` fail on:

- Intel Macs. T2 Macs do have a Secure Enclave, but `age-plugin-se` v0.2.1 doesn't build there today (see Findings).
- Linux, which has no Secure Enclave.

Today those users can only take part by pasting a portable `age1…` key with `--public-key`, and that leaves a plaintext `AGE-SECRET-KEY-1…` somewhere sopsy doesn't manage.

## Goal

Let every member choose where their private key lives (a **store**) from what their machine supports, with the same commands they use today:

Stores fall into three **groups**. `auto` walks the groups in priority order (default `onchip,exthardware,software`, overridable via `SOPSY_PRIVATE_KEY_STORE_PRIORITY`, see §2):

| Group | Stores in the group, in order | Notes |
| --- | --- | --- |
| `onchip` | `enclave` (Apple Silicon, T2), `tpm` (Linux) | Built into the machine; probe-only, nothing to plug in |
| `exthardware` | `yubikey`, `fido2` | External, removable hardware token |
| `software` | `keychain` (macOS Keychain / Linux Secret Service), then `file` | `file` is the last resort |

Resulting default order per platform:

| Platform | Default `auto` order |
| --- | --- |
| macOS Apple Silicon | `enclave` → `yubikey` → `fido2` → `keychain` → `file` |
| macOS Intel | `enclave` (T2, when `age-plugin-se` works) → `yubikey` → `fido2` → `keychain` → `file` |
| Linux | `tpm` → `yubikey` → `fido2` → `keychain` → `file` |

## Principle

**sopsy auto-detects the local hardware and defaults to the most secure place it can put the private key.** Users shouldn't need flags or env vars to get the safest option. `--store` and `SOPSY_PRIVATE_KEY_STORE_PRIORITY` exist only to deviate from that default deliberately.

Security ranking used for the default order (most secure first):

1. **Non-exportable hardware.** The key is generated inside the device and can't be copied out, and each use needs presence/PIN.
   - `onchip` (`enclave`, `tpm`): bound to this machine. Nothing to lose or leave plugged in.
   - `exthardware` (`yubikey`, `fido2`): bound to a token that leaves with the person, but can be lost or left in the port. Gated by a PIN.
1. **Software, encrypted at rest** (`keychain`): unlocked with the login session; any process running as the user can read it.
1. **Plaintext** (`file`).

Consequences:

- **Detection probes the hardware, not just the tooling.** "TPM present but `age-plugin-tpm` missing" counts as *capable*, never as "skip to the next store". auto must not downgrade because a plugin isn't installed.
  - Interactive: offer to install the missing tool (same code path as `sopsy deps`), then continue with that store.
  - Non-interactive: fail with the exact install command. sopsy never silently picks a weaker store because of a missing binary.
- Downgrading is allowed only when the stronger *hardware* is absent, or unusable for a reason the user can't fix by installing a tool (e.g. no `/dev/tpmrm0` permission still counts as fixable: print the `tss` group hint and fail).
- Each store also defaults to its strictest reasonable policy: enclave with Touch ID, `tpm` with a PIN, YubiKey PIN `once` + touch `cached` (Q2), and a keychain item that requires confirmation on access where the OS supports it.
- Whenever the chosen store is weaker than the strongest the machine *could* support, sopsy says so and explains why (e.g. "YubiKey detected but you set the priority to software").

## Non-goals

- Windows.
- Reimplementing any plugin, PIV, PC/SC, TPM or FIDO2 in Rust. sopsy keeps shelling out to external binaries.
- Device administration: YubiKey PIN/PUK/management keys, TPM ownership, FIDO2 PINs. Those belong to the vendor tools.
- Changing how break-glass or CI portable keys work.

## Stores

| Store | Kind | Backing | Recipient prefix | What sopsy keeps locally | External tool |
| --- | --- | --- | --- | --- | --- |
| `enclave` | hardware | Apple Secure Enclave (Apple Silicon, T2) | `age1se1…` | `AGE-PLUGIN-SE-1…` handle in `keys.txt` | `age-plugin-se` |
| `yubikey` | hardware | YubiKey PIV retired slot (1–20) | `age1yubikey1…` | `AGE-PLUGIN-YUBIKEY-1…` handle in `keys.txt` | `age-plugin-yubikey` (+ `pcscd` on Linux) |
| `tpm` | hardware | TPM 2.0 | `age1tpm1…` (verify) | `AGE-PLUGIN-TPM-1…` handle in `keys.txt` (verify) | `age-plugin-tpm` (needs `/dev/tpmrm0`) |
| `fido2` | hardware | Any FIDO2 key (hmac-secret) | `age1fido2-hmac1…` (verify) | identity handle in `keys.txt` (verify) | `age-plugin-fido2-hmac` (+ libfido2) |
| `keychain` | **software** | macOS Keychain (`security`); Linux Secret Service (`secret-tool`) | `age1…` | nothing on disk; the secret key lives in the keyring | `age-keygen` + OS keyring CLI |
| `file` | **plaintext** | `AGE-SECRET-KEY-1…` in `keys.txt`, mode `0600` | `age1…` | the secret key itself | `age-keygen` |

For the four hardware stores, the local identity line is a non-secret handle: the private key never leaves the device. `keystore::store_identity` and `SOPS_AGE_KEY_FILE` work for them unchanged, and sops calls the matching `age-plugin-*` from `PATH`.

`keychain` keys are generated by `age-keygen` with output captured in memory (never written to a file) and stored straight into the keyring. On decrypt, sopsy reads the key and passes it to the child `sops` process only, via `SOPS_AGE_KEY`. For people who run raw `sops` or direnv, docs show the `SOPS_AGE_KEY_CMD` equivalent.

`file` is the current portable-key behaviour turned into a named store. It is the last resort.

## Design

### 1. Module layout

`src/enclave/` becomes `src/hardware/` (Q1) with one file per store: `enclave.rs`, `yubikey.rs`, `tpm.rs`, `fido2.rs`, `keychain.rs`, `file.rs`, plus `mod.rs` holding:

```rust
pub enum Store { Enclave, YubiKey, Tpm, Fido2, Keychain, File }
pub enum StoreKind { Hardware, Software, Plaintext }

pub struct GeneratedIdentity {
    pub store: Store,
    pub public_key: String,
    /// Plugin handle (hardware) or secret key (keychain/file); never logged.
    pub identity: String,
}
```

Each store implements `ensure_available()`, `probe() -> Availability`, `generate(opts, extra_args)`, `persist(&GeneratedIdentity)`, `brew_formula()`, `kind()`, `display_name()` and its doctor lines. Every external binary is overridable through `SOPSY_<TOOL>_BIN` for tests, as `SOPSY_AGE_PLUGIN_SE_BIN` is today.

### 2. Store selection

The **repo** states a preference (set by `init`, committed in `.sopsy.yml`, see §2a). The **member's** machine decides what is actually possible, and the member may override the preference for themselves.

Precedence (first match wins):

1. `--store <value>` on `init`, `join`, `recipient keygen`
1. `SOPSY_PRIVATE_KEY_STORE_PRIORITY` (the member's personal order)
1. The repo's `key_policy.preferred` from `.sopsy.yml`: the preferred group/store goes first, and the rest follows the security ranking
1. The built-in default `onchip,exthardware,software`

**`key_policy.required`, when present, filters all of the above, `--store` included.** Nothing overrides it (§2a).

Rules:

- Matching is case-insensitive. An unknown value is an error that lists the valid ones.
- An explicit store the machine can't use (for example `enclave` on Linux) is an error with a remedy, never a silent fallback.
- `auto` expands the priority list (below) into stores and picks the first store whose probe passes. It is a pure function over a probe struct and the priority list, so it can be unit-tested.

#### `SOPSY_PRIVATE_KEY_STORE_PRIORITY`

Controls how `auto` orders the stores; only `--store` bypasses it. To pin one store with no fallback, list just that store (e.g. `SOPSY_PRIVATE_KEY_STORE_PRIORITY=yubikey`): it errors when that store isn't viable. There is no separate `SOPSY_DEFAULT_STORE` (dropped, Q-B).

- Comma-separated, case-insensitive, whitespace trimmed. Example: `SOPSY_PRIVATE_KEY_STORE_PRIORITY="exthardware,onchip,software"`.
- Each entry is a **group** (`onchip`, `exthardware`, `software`) or an **individual store** (`enclave`, `tpm`, `yubikey`, `fido2`, `keychain`, `file`). A group expands to its stores in the order shown in **Goal**. Duplicates are ignored after their first appearance.
- **Groups and stores left out of the list are excluded.** `"onchip,exthardware"` means `auto` will never fall back to software; it errors instead. That lets a person or team forbid plaintext keys.
- Unset or empty means the default, `onchip,exthardware,software`. Note that `yubikey` in the list now means only the YubiKey store, not the group.
- An unknown entry is an error listing the valid names. An empty expansion (e.g. `",,"`) is also an error.
- `doctor` prints the effective priority list, its source (default or env), and the expanded store order with a ✔/ｘ probe result next to each store.
- In interactive `auto` with more than one viable store, sopsy prompts (default = first in the order) and suggests exporting `SOPSY_PRIVATE_KEY_STORE_PRIORITY`.
- **If `auto` lands on `file`,** sopsy prints a prominent warning saying the key is plaintext and naming the safer stores it couldn't use and why. Non-interactive runs get the same warning on stderr.
- `doctor` shows the effective store and where it came from.

Probe definitions. Each probe reports **hardware** (present / absent) and **tooling** (ready / missing, with install command) separately; see Principle:

| Store | Viable when |
| --- | --- |
| `enclave` | macOS, Secure Enclave present (arm64, or T2 via `system_profiler SPiBridgeDataType`), and `age-plugin-se` runs |
| `yubikey` | `age-plugin-yubikey` present and `--list-all` reports ≥ 1 key |
| `tpm` | Linux, `/dev/tpmrm0` readable/writable by the user, and `age-plugin-tpm` present |
| `fido2` | `age-plugin-fido2-hmac` present and ≥ 1 FIDO2 device detected |
| `keychain` | macOS: `security` present. Linux: `secret-tool` present and a Secret Service on D-Bus |
| `file` | always |

### 2a. Repo key policy (`sopsy init`)

`init` records the team's key policy in `.sopsy.yml` (covered by `.sopsy.sha`). It asks interactively, or takes flags:

| Flag | Values | Default | Meaning |
| --- | --- | --- | --- |
| `--preferred-method` | `onchip` \| `exthardware` \| `yubikey` \| `fido2` | `onchip` (the security ranking) | Store or group members should use. `exthardware` = USB/NFC tokens that move between machines |
| `--require` | one or more of `onchip` \| `exthardware` \| `yubikey` \| `fido2` \| `keychain` \| `file` (comma-separated or repeated) | unset | **Allowed set**: member keys must come from one of these methods, otherwise they're refused. Exact match: `exthardware` does *not* admit `onchip` |
| `--ux-priority` | `security` \| `convenience` | `security` | Presence/PIN policy for keys generated in this repo (table below) |
| `--cache-ttl` | duration (`humantime`, e.g. `15m`) | `15m` | Agent cache lifetime under `convenience` (§2b) |

```yaml
# .sopsy.yml
key_policy:
  preferred: exthardware
  required: [exthardware]   # allowed set; omit for no requirement
  ux_priority: convenience
  cache_ttl: 15m
```

Behaviour:

- **Prefer (default):** if a member lacks the preferred method, sopsy uses the most secure store they *do* have, warns them, and records the store on their recipient entry.
- **Require (`required` in `.sopsy.yml`, set via `--require` or `sopsy policy set`):** an allowed set of methods, matched exactly (a group admits its member stores; nothing admits stores outside the set, regardless of ranking).
  - **It overrides every other source.** `--store`, `SOPSY_PRIVATE_KEY_STORE_PRIORITY` and `preferred` are all filtered through it. A store outside the set is an error even when passed explicitly with `--store`, and `auto` only considers allowed stores.
  - If the member has no allowed store, `join`/`init`/`recipient keygen` refuse with a remedy ("this repo requires exthardware: insert a YubiKey or FIDO2 key"). There's no fallback.
  - `recipient add --public-key` must also declare `--store`, which is checked against the set. Unknown-store keys are refused while `required` is set.
  - `preferred` must be inside `required` when both are set (validated on save).
  - **Exempt:** break-glass and CI keys (`recipient break-glass` / `recipient ci`). They are portable by design and are marked as such in `.sopsy.yml`; `required` applies to member keys only.
  - `check` fails CI when an active recipient's `store` is outside the set. `doctor` lists offenders. Like everything here, this is a soft guardrail: crypto can't enforce it, and `.sopsy.sha` only gives tamper evidence.
- A member's `SOPSY_PRIVATE_KEY_STORE_PRIORITY` overrides `preferred`, but never `required`.
- `ux_priority` maps to per-store generation policy:

| Store | `security` | `convenience` |
| --- | --- | --- |
| `enclave` | biometry/passcode on every use | same prompt; repeat decrypts served by the agent cache |
| `tpm` | PIN on every use | no PIN at the TPM; agent cache |
| `yubikey` | `--pin-policy always --touch-policy always` | `--pin-policy once --touch-policy cached` + agent cache |
| `fido2` | PIN + touch every use | touch every use; agent cache |
| `keychain` | OS confirmation on every access | no prompt; agent cache |

- YubiKey PIN/touch policies are fixed when the key is generated. Changing `ux_priority` later only affects newly generated keys; `doctor` lists members whose keys don't match the current policy. The Q6 "reuse an existing YubiKey identity" rule only reuses a slot whose policies match.
- Changing the policy after `init`: `sopsy policy show|set` (new small command), rather than re-running `init`.

### 2b. `sopsy agent` (convenience caching)

The YubiKey's own caching can't be tuned: the PIN stays cached until unplug, and touch caching is fixed in firmware at about 15s. A configurable timeout therefore has to come from sopsy.

- `sopsy agent start|stop|status|lock`: a per-user daemon that implements the **sops keyservice** gRPC protocol on a `0600` Unix socket under `$XDG_RUNTIME_DIR` (or `~/Library/Caches/sopsy` on macOS).
- When the agent is running and the repo is `convenience`, sopsy runs `sops` with `--keyservice unix://<socket>`. The agent unwraps each file's data key through the normal age identity (plugin prompts happen once), then caches the **data key only**, in memory, keyed by the hash of the wrapped key.
- TTL resolution: `--cache-ttl` flag on `edit`/`decrypt`/`secrets` > `SOPSY_CACHE_TTL` > repo `cache_ttl` > `15m`. The agent clamps it to a hard max (e.g. 8h).
- The cache is cleared on TTL expiry, on `sopsy agent lock`, when the YubiKey serial that unlocked an entry disappears or changes (PC/SC presence polling), and when the agent stops. Nothing is ever written to disk.
- Under `security` sopsy never talks to the agent, even if one is running.
- Auto-start: `convenience` repos start the agent on first decrypt, and `doctor` reports its status.
- New dependencies, to be justified per REQUIREMENTS: `tonic`/`prost` for gRPC and the `age` crate (str4d) for plugin-aware unwrapping, or shelling out to `age` instead.

### 3. CLI surface

| Flag | Commands | Meaning |
| --- | --- | --- |
| `--store <auto\|enclave\|yubikey\|tpm\|fido2\|keychain\|file>` | `init`, `join`, `recipient keygen` | Overrides `SOPSY_PRIVATE_KEY_STORE_PRIORITY` |
| `--yubikey-serial <S>` | same | Pick a device when several are connected (required non-interactively) |
| `--yubikey-slot <1-20>` | same | Use this slot; reuse the key if one is there |
| `--new-slot` | same | Don't reuse; generate in a free slot (Q6) |
| `--pin-policy <always\|once\|never>` | same | YubiKey; default `once` (Q2) |
| `--touch-policy <always\|cached\|never>` | same | YubiKey; default `cached` (Q2) |
| `-t, --without-touch-id` | `join` | enclave: `--access-control none`. yubikey: `--touch-policy never`, PIN unchanged (Q4). Other stores: rejected with an error |
| `-- <args>` | existing | Forwarded verbatim to the selected store's tool |

### 4. Committed state (`.sopsy.yml`)

The store can't always be read from the public key (`keychain`, `file`, break-glass and CI keys all look like `age1…`). So `Recipient` gains an optional, informational `store:` field, written by `init`/`join`/`recipient add`. It is omitted when unknown (legacy entries) and inferred from the prefix where possible. `Config::save` already refreshes `.sopsy.sha`.

`recipient list` gains **Store** and **Kind** columns (`hardware` / `software` / `plaintext`). `check` gets an optional, off-by-default rule that fails CI when any active recipient is `plaintext`, for teams that want to forbid it.

One person, several keys: names stay unique. A person's second key gets a suffix, e.g. `kig-yubikey-<serial>` (Q3).

### 5. `doctor`

The macOS-only `system_checks` is replaced by per-OS probes, each a pure `*_line` interpreter, as today:

- macOS: version, arch, T2/Secure Enclave presence. The current "requires Apple Silicon" wording is fixed.
- Linux: distro (`/etc/os-release`), `pcscd` reachable, `/dev/tpmrm0` access (hint: add yourself to the `tss` group), and a Secret Service on D-Bus.
- Every store: tool present, version, and device detected.
- Effective store and its source; a warning if it is `file`.
- "Can this machine decrypt?": whether any local identity matches a `.sops.yaml` recipient.
- A minimum sops version is enforced (Q7).

### 6. `deps`

The installed set depends on the platform. `age-plugin-yubikey` is always installed (Q5). Store-specific tools (`age-plugin-tpm`, `age-plugin-fido2-hmac`) are installed when that store is selected or would be chosen by `auto`. On Linux without `brew`, sopsy prints distro commands (`pcscd`, `libfido2`, `tpm2-tss`, `libsecret-tools`) and **never runs `sudo`**.

### 7. Edit / decrypt UX

- Pre-flight: when the only matching identity needs a device that isn't present, fail fast ("insert YubiKey #S", "no FIDO2 device found") instead of sops' generic error.
- Spinner and prompt text depend on the store.
- PIN and touch prompts belong to the plugin. sopsy never captures or proxies a PIN.

### 8. Docs

- `docs/guide-member.md`: choosing a store on each platform, and `SOPSY_PRIVATE_KEY_STORE_PRIORITY`.
- `docs/guide-owner.md`: mixed-store teams, the `plaintext` check, and how a YubiKey differs from break-glass.
- `docs/enclave-security-model.mmd` becomes a key-store security model that covers all three kinds.
- `docs/REQUIREMENTS.md`: Linux, TPM and YubiKey removed from out-of-scope.
- README: platform × store support matrix, with `Kind` spelled out.

## Testing

- A fake binary per tool (`age-plugin-yubikey`, `age-plugin-tpm`, `age-plugin-fido2-hmac`, `security`, `secret-tool`) covering success, error exits and 0/1/2 devices.
- Table-driven tests: output parsers, store resolution (flag, env, auto, invalid, unusable explicit store, fallback to `file` with warning), doctor interpreters per OS, `deps` per platform.
- Dev-only test age plugin (Rust, wraps a portable key) so CI runs a real sops → plugin → decrypt (Q8).
- Linux CI e2e on `ubuntu-latest` (dotenv included): `init --store yubikey` (faked) → encrypt → `join --store file` → `approve` → decrypt. Plus a `keychain` run against a headless `gnome-keyring-daemon`.
- Real-hardware smoke tests are `#[ignore]`d and gated on `SOPSY_REAL_<STORE>=1`.

### Hardware CI (CircleCI)

The aim is to exercise the `tpm` store against a real TPM 2.0 stack, not a fake binary. CircleCI doesn't advertise a TPM on its machine executors (unverified either way), so the plan is layered:

| Tier | Where | TPM | Runs |
| --- | --- | --- | --- |
| 1. Emulated | CircleCI `machine` executor (full VM with `sudo`) | `swtpm --tpm2` exposed as a real `/dev/tpmrm0` via the `tpm_vtpm_proxy` kernel module | every PR |
| 2. Probe | same executor | `ls /dev/tpm* /sys/class/tpm` as a one-off job | once; if a vTPM is present, tier 1 uses it directly |

- Tier 1 runs the real `tpm` e2e: `init --store tpm` → encrypt → decrypt, dotenv included. A Docker executor can't do this, because the kernel module and device node need the VM.
- No self-hosted runners (Q-D): everything runs on hosted CircleCI / GitHub Actions machines, defined in repo config only.
- Hosted macOS executors are VMs; a Secure Enclave is expected to be unavailable there (verify). If confirmed, `enclave` can't be tested in CI.
- No hosted runner has a YubiKey or FIDO2 token. In CI those stores run only against fake binaries plus the dev-only test plugin. FIDO2 might also be tested with a software FIDO2 authenticator on a Linux VM (verify feasibility).
- **Manual pre-release checklist** on the maintainer's own machines (not CI): `enclave` on Apple Silicon (and T2 if the plugin builds), `yubikey`, `fido2`, `keychain` on macOS. For each: `init` → `edit` → `join`/`approve` across stores → decrypt.
- Release gate: GitHub Actions + CircleCI green on the release commit, and the manual checklist ticked.
- Coverage stays above 95%.

## Rollout (one PR per line, atomic commits)

1. [ ] Refactor: `enclave/` → `hardware/`, `Store` + `GeneratedIdentity`, enclave moved behind it. No behaviour change.
1. [ ] `SOPSY_PRIVATE_KEY_STORE_PRIORITY` / `--store` resolution and the `file` store (formalises today's portable path).
1. [ ] `yubikey` store.
1. [ ] `keychain` store (macOS + Secret Service).
1. [ ] `enclave` on T2 Intel Macs (depends on getting `age-plugin-se` to build; see Findings).
1. [ ] `tpm` store.
1. [ ] `fido2` store.
1. [ ] `key_policy` in `.sopsy.yml` + `init --preferred-method/--require/--ux-priority/--cache-ttl` + `sopsy policy`.
1. [ ] `sopsy agent` (keyservice, TTL, YubiKey-removal invalidation).
1. [ ] `.sopsy.yml` `store:` field, `recipient list` columns, optional `check` rule.
1. [ ] Per-OS `doctor`, platform-aware `deps`, decrypt pre-flight.
1. [ ] Linux CI e2e, docs, README matrix; minor version bump.

## Acceptance criteria

- [ ] Apple Silicon with no flag and no `SOPSY_PRIVATE_KEY_STORE_PRIORITY` behaves exactly as today (`auto` → `enclave`).
- [ ] `SOPSY_PRIVATE_KEY_STORE_PRIORITY` reorders and restricts `auto` on every platform; `--store` overrides it.
- [ ] On Linux and Intel macOS, `init` → `edit .env.encrypted` works end to end with each viable store.
- [ ] Hardware and keychain stores never write an `AGE-SECRET-KEY-1…` to disk; only `file` does, and always with a warning.
- [ ] Members with different stores can all decrypt the same repo; `join`/`approve` work across stores.
- [ ] `recipient list` and `doctor` show each key's store and kind.
- [ ] `just fmt`, `just warnings` and `just test` pass; coverage above 95%.

## Decisions (2026-10-28)

- **Q1** `hardware/`, one file per store.
- **Q2** YubiKey defaults are `--pin-policy once --touch-policy cached`.
- **Q3** Unique names; a person's extra keys get a suffix.
- **Q4** `--without-touch-id`: enclave → `--access-control none`; yubikey → touch `never`, PIN kept; other stores reject it.
- **Q5** `deps` always installs `age-plugin-yubikey`.
- **Q6** Reuse an existing YubiKey identity by default; `--new-slot` opts out.
- **Q7** `doctor` enforces a minimum sops version.
- **Q8** Dev-only test age plugin for CI decrypts.
- **Q9** Linux distribution is Homebrew plus the existing release tarballs.
- **Q10** `keychain` is in this plan (supersedes the earlier "plan 002"). It is labelled `software`.
- **Q11** T2 `enclave` is in scope and is the Intel default when it works (supersedes "arm64-only").
- **Sync-3** `file` store exists and is `auto`'s last fallback, with a loud warning.
- **Sync-4** Linux also gets `tpm`, `fido2` and `keychain` (Secret Service).
- **Sync-5** Intel `auto` order is `enclave` → `yubikey` → `keychain`: hardware always beats software (overrides the order listed in `spec.md`).
- **Sync-6** `tpm` is `onchip` like `enclave`: probed via `/dev/tpmrm0`, key generated inside and non-exportable. Default priority `onchip,exthardware,software` puts it first on Linux.
- **Release** All stores ship together in one release, after CI (both providers) is green and the manual hardware checklist is done.
- **Principle** Default is the most secure option the hardware supports; a missing plugin triggers install-or-fail, never a downgrade. `tpm` defaults to PIN-protected.
- **Repo policy** `init --preferred-method onchip|exthardware|yubikey|fido2` (prefer by default; `required` is an exact-match allowed set that overrides everything, `--store` included) and `--ux-priority security|convenience` live in `.sopsy.yml` `key_policy`. Precedence: `--store` > `SOPSY_PRIVATE_KEY_STORE_PRIORITY` > repo preference > built-in ranking; env never beats `--require`.
- **Caching** is a sopsy agent (sops keyservice) with `--cache-ttl` / `SOPSY_CACHE_TTL` / repo `cache_ttl`, invalidated on YubiKey removal.
- **Sync-7** `SOPSY_PRIVATE_KEY_STORE_PRIORITY` (groups or individual stores, unlisted ones excluded) drives `auto`. Default `onchip,exthardware,software`.
- **Q-B** `SOPSY_DEFAULT_STORE` dropped; `SOPSY_PRIVATE_KEY_STORE_PRIORITY` is the only env control.
- **Q-C** Keep GitHub Actions (lint, unit, e2e) and add CircleCI (TPM/VM jobs).
- **Q-D** No self-hosted runners; hardware coverage beyond CI is a manual pre-release checklist.
- **Q-A** The token group is named `exthardware` (`yubikey`, `fido2`). `yubikey` stays an individual store name.

## Needs confirmation

None open.

## Facts to verify before coding

- That the sops keyservice protocol supports age keys, and that `--keyservice` with a custom server works alongside local plugin identities.
- YubiKey: the touch `cached` duration, that policies are immutable after generation, and whether the `once` PIN cache survives across separate plugin processes on YubiKey 5.

- Whether CircleCI `machine` executors expose a vTPM, and whether `tpm_vtpm_proxy` can be loaded there. Also whether `age-plugin-tpm` can target swtpm directly (TCTI/socket) without a device node.
- R5: CircleCI terms of service and privacy policy before adding it.

- `age-plugin-yubikey` 0.5.x output for `--generate`, `--identity`, `--list`, `--list-all`, and whether first-use PIN/PUK/management-key prompts block non-interactive runs.
- `age-plugin-tpm` and `age-plugin-fido2-hmac`: current flags, recipient and identity prefixes, maintenance status, and Homebrew/distro packaging.
- The sops release that added age plugin identities and `SOPS_AGE_KEY_CMD`, and how sops merges `SOPS_AGE_KEY` with `SOPS_AGE_KEY_FILE` (the keychain path depends on both being honoured).
- Whether `age-plugin-yubikey` builds on Linux via Homebrew (`pcsc-lite`).
- R5: licences and terms of every new external tool before adding it to `deps`.

## Findings

- 2026-10-28: the Intel dev Mac (x86_64, macOS 26.7.1) has an **Apple T2 Security Chip**. `age-plugin-se` requires "macOS 14 (Sonoma) with a Secure Enclave processor" and doesn't mention Apple Silicon. Homebrew has no Intel bottle. A `swift build` of v0.2.1 fails at the manifest (`.macOS(.v26)` can't be resolved with PackageDescription 6.2, CommandLineTools Swift 6.3.3). The next step is to patch the platform declaration (or build with full Xcode) and test `keygen` on T2.
