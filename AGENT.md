[![CI](https://github.com/kigster/sopsy/actions/workflows/ci.yml/badge.svg)](https://github.com/kigster/sopsy/actions/workflows/ci.yml)

![crates](https://img.shields.io/crates/v/sopsy?logo=rust&style=flat-square&color=E05D44)

![repo](https://img.shields.io/badge/repo-kigster/sopsy-1370D3?style=flat-square&logo=github)

![mit](https://img.shields.io/crates/l/ratatui?style=flat-square&color=1370D3)

# Sopsy

## What this is?

`sopsy` is a CLI tool written in Rust that combines sops, age, and age-plugin-se for MacOS to provide seamless and yet hardware-protected way of encrypting the application secrets that can be safely checked into the repo. It's meant for developer settings and API keys, but can be used for staging and production as well.

______________________________________________________________________

It's the "missing developer experience for SOPS".

Sopsy bootstraps encrypted repositories using SOPS and age, manages Secure Enclave-backed identities on macOS, and makes working with encrypted secrets simple.

## Features

- 🔐 Secure Enclave-backed identities
- 📦 Repository bootstrap
- 🩺 `doctor` health checks
- ✏️ `edit` using your preferred editor
- 🤝 Self-service onboarding (`join` / `approve`)
- 👥 Recipient management
- 🚨 Break-glass emergency key ceremony
- 🔄 SOPS key rotation
- 🧪 Safe defaults

## Roughly Cargo Project

```txt
sopsy/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── commands/   # init, doctor, edit, join, approve, recipient, check, …
│   ├── sops/
│   ├── enclave/    # age-plugin-se (Secure Enclave)
│   ├── age.rs      # age-keygen (portable break-glass keys)
│   └── git/
├── tests/
├── docs/
└── README.md
```

## MVP Breakdown

MVP breakdown Workstream Estimate Rust CLI skeleton with clap 0.5 day doctor checks: macOS, tools, git repo, .sops.yaml, ignored plaintext files 1 day Secure Enclave identity generation via age-plugin-se 0.5–1 day .sops.yaml init/update logic 1 day Emergency/break-glass key instructions + validation warning 0.5 day edit wrapper around EDITOR=vim sops <file> 0.5 day add-recipient, remove-recipient, list-recipients, updatekeys 1–1.5 days Integration tests using temp git repos + mocked commands 1–1.5 days README + manager/developer docs 0.5 day

## Solid MVP with tests: 4–7 days

Includes:

- clean error handling
- temp repo integration tests
- fake/mock binaries for sops, age-plugin-se, git
- .sops.yaml mutation tests
- .gitignore safety checks
- idempotent init
- good README
- Polished v1: 2–3 weeks

Adds:

- Homebrew formula
- GitHub releases
- shell completions
- man page
- CI matrix
- codesigning/notarization
- real macOS integration test notes
- better onboarding UX with inquire

## Project philosophy

Sopsy does not replace SOPS.

It makes SOPS delightful to use.

_That immediately sets expectations and reduces the maintenance burden. Sopsy orchestrates and enhances; SOPS remains the encryption engine._

> [!IMPORTANT]
>
> The name sopsy has been pushed to Crates.io and it's on Github at <https://github.com/kigster/sopsy.git>

I believe I've got something that could genuinely become the standard onboarding tool for SOPS.

What I like most is that the scope is crisp. It's not "another secret manager."

It's — The missing DX for SOPS.

Hopefully, that's a project people immediately understand.

## The Vision

Opinionated developer experience for SOPS.

• Bootstrap a repository in minutes • Secure Enclave-backed identities • Safe defaults • Team onboarding • Recipient management • Great diagnostics

## Commands

### `sopsy init`

Performs:

```bash
# Initialize a repository:
# Verify Homebrew
# Verify sops
# Verify age-plugin-se
# Generate Secure Enclave identity (if needed)
# Print public recipient
# Create .sops.yaml
# Create .env.example
# Encrypt .env.encrypted
# Update .gitignore
# Creates .sopsy.yml (internal configuration file)
# sopsy doctor
```

Checks everything.

This should become the command people paste into GitHub Issues.

✓ macOS 15.5 ✓ Apple Silicon ✓ Secure Enclave available ✓ Touch ID enabled

✓ `sops` ✓ `age-plugin-se` ✓ `git`

✓ `.sops.yaml`

✓ Repository healthy

⚠ Break-glass Emergency: Create a pair of keys and place them in 1Password, a vault that only a few admins have access to,

## `sopsy edit`

This is simply `EDITOR=vim sops file` with nicer errors.

## `sopsy recipient add [ name ]`

Updates `.sops.yaml` with user's public key.

It runs an external process:

```bash
sops updatekeys -r .
```

- Verifies everything.

## `sopsy recipient remove [ name ]`

Same idea.

## `sopsy recipient keygen [ -- age flags ]`

Generates a Secure Enclave identity (`age-plugin-se keygen`) and prints the public key + identity, without touching any config. Trailing args after `--` are forwarded to the plugin.

## `sopsy recipient break-glass -o <file>`

Generates a portable (`age-keygen`) emergency key, writes `<file>.private` / `<file>.public`, prompts the owner to copy them to an offline vault (1Password), waits, then deletes the local copies and registers the key as the break-glass recipient. Also offered automatically during `sopsy init`.

## `sopsy join <name>`

Self-service onboarding for a newcomer: generates their Enclave key and records a **pending** entry in `.sopsy.yml` (with a timestamp). Pending grants nothing — they push it as a pull request.

## `sopsy approve <name>`

Run by any active member: checks the request is fresh (`join_request_ttl`), vouches for the key, adds it to `.sops.yaml`, flips the member to `active`, and runs `sops updatekeys`.

## `sopsy check`

This command run in CI.

```bash
sopsy check
```

It ensures:

- .env isn't committed
- .env is ignored
- .sops.yaml is valid
- every encrypted file matches a creation rule
- no plaintext secrets exist in tracked files
- all encrypted files can be parsed
- break-glass recipient exists

Exit 0/1.

That gives teams an easy pre-commit hook and CI check.

## Excluded from v1.0

I'd deliberately not implement these until people ask for them:

- Linux
- TPM
- YubiKey
- KMS
- 1Password integration
- Vault integration
- GitHub Actions helpers
- Ratatui
- Native Rust SOPS implementation

**The fastest path to adoption is a polished macOS experience.**

______________________________________________________________________

## Other Notes

The user interaction must be top-notch, and use color freely, especially animations of lines changing color, etc.

The prompt library should ask the user questions, and save
