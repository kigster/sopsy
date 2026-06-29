# Sopsy

[![crates](https://img.shields.io/crates/v/sopsy?logo=rust&style=flat-square&color=E05D44)](https://crates.io/crates/sopsy)  [![CI](https://github.com/kigster/sopsy/actions/workflows/ci.yml/badge.svg)](https://github.com/kigster/sopsy/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/kigster/sopsy/graph/badge.svg)](https://codecov.io/gh/kigster/sopsy) [![repository](https://img.shields.io/badge/repo-kigster/sopsy-1370D3?style=flat-square&logo=github)](https://github.com/kigster/sopsy) ![License](https://img.shields.io/crates/l/sopsy?style=flat-square&color=1370D3) [![docs](https://img.shields.io/badge/docs-sopsy-1370D3?style=flat-square&logo=rust)](https://docs.rs/crate/sopsy/latest) 

> The missing developer experience for [SOPS](https://github.com/getsops/sops).
  
`sopsy` is a small, fast, colorful Rust CLI that makes it delightful to keep
encrypted secrets in Git. It bootstraps a repository in minutes, generates
hardware-backed identities using the macOS **Secure Enclave**, manages the team's
recipients, and ships a CI gate that fails the build the moment a plaintext
secret sneaks in.

> [!NOTE]
> **sopsy does not replace SOPS. It makes SOPS delightful.**
> SOPS remains the encryption engine; `age` remains the cryptography; the Secure
> Enclave holds the private key. sopsy orchestrates and enhances them with safe
> defaults, great diagnostics, and a scriptable interface.

---

## Table of Contents

- [What it is](#what-it-is)
- [Philosophy](#philosophy)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Install](#install)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [How encryption flows](#how-encryption-flows)
- [The Secure Enclave security model](#the-secure-enclave-security-model)
  - [Where your identity lives](#where-your-identity-lives)
  - [Console session, Touch ID, and one-laptop testing](#console-session-touch-id-and-one-laptop-testing)
- [Break-glass keys](#break-glass-keys)
- [Files sopsy manages](#files-sopsy-manages)
- [Command Reference](#command-reference)
  - [Global flags](#global-flags)
  - [`sopsy init`](#sopsy-init)
  - [`sopsy doctor`](#sopsy-doctor)
  - [`sopsy edit`](#sopsy-edit)
  - [`sopsy join`](#sopsy-join)
  - [`sopsy approve`](#sopsy-approve)
  - [`sopsy recipient`](#sopsy-recipient)
  - [`sopsy secrets`](#sopsy-secrets)
  - [`sopsy list-supported-types`](#sopsy-list-supported-types)
  - [`sopsy check`](#sopsy-check)
  - [`sopsy deps`](#sopsy-deps)
  - [`sopsy completion`](#sopsy-completion)
- [Using sopsy in CI](#using-sopsy-in-ci)
- [Environment variables](#environment-variables)
- [Scope and roadmap](#scope-and-roadmap)
- [Further reading](#further-reading)

---

## What it is

`sopsy` combines **SOPS**, **age**, and **age-plugin-se** into a seamless,
hardware-protected way to encrypt application secrets that can be safely
committed to a repository. It is built for developer settings and API keys, but
works equally well for staging and production secrets.

The killer property: the secret values live in Git in *encrypted* form, while
the private key that can decrypt them never leaves your Mac's Secure Enclave.

## Philosophy

- **Sopsy does not replace SOPS** — it orchestrates and enhances it. That keeps
  the scope crisp and the maintenance burden low.
- **Opinionated, safe defaults** — the right thing should be the easy thing.
  Plaintext `.env` files are gitignored automatically; a CI gate stops mistakes.
- **Fully scriptable** — every interactive prompt has an equivalent flag, so the
  same tool serves a human at a terminal and an unattended CI job.
- **Great diagnostics** — `sopsy doctor` produces a report you can paste straight
  into a GitHub issue.

## Features

- 🔐 **Secure Enclave-backed identities** — private key bound to the hardware,
  protected by Touch ID, and impossible to exfiltrate.
- 📦 **Repository bootstrap** — one command writes `.sops.yaml`, `.env.example`,
  an encrypted `.env.encrypted`, `.gitignore` safety rules, and `.sopsy.yml`.
- 🩺 **`doctor` health checks** — macOS / Apple Silicon / Secure Enclave / Touch
  ID, the external tools, repo health, and a break-glass reminder.
- ✏️ **`edit`** — open an encrypted file in your editor through SOPS, with nicer
  errors and automatic file-type detection (including `dotenv`).
- 🤝 **Self-service onboarding** — newcomers `sopsy join` to generate a key and
  request access via a pull request; any active member `sopsy approve`s them.
- 👥 **Recipient management** — add, remove, and list the people who can decrypt.
- 🔁 **`secrets encrypt`/`decrypt`** — one-shot encrypt/decrypt of `.env`/YAML/JSON/INI
  files to stdout (or `-o`), ideal for `direnv` and process wrappers.
- 🚨 **Break-glass ceremony** — `sopsy recipient break-glass` generates a portable
  emergency key, hands it off for offline storage, then deletes the local copy.
- 🔄 **SOPS key rotation** — every membership change re-wraps the existing secrets
  via `sops updatekeys`.
- 🧪 **Safe defaults & a CI gate** — `sopsy check` enforces seven hygiene
  invariants and exits non-zero on any violation.

---

## Prerequisites

`sopsy` is **macOS-first** (v1). It orchestrates three external tools, all
installable with [Homebrew](https://brew.sh):

```bash
brew install sops age age-plugin-se
```

| Tool            | Purpose                                                      |
| --------------- | ----------------------------------------------------------- |
| `sops`          | The encryption engine sopsy drives for every crypto op.     |
| `age`           | The modern encryption library SOPS uses under the hood.     |
| `age-plugin-se` | Generates Secure Enclave-backed `age` identities on macOS.  |
| `git`           | sopsy is repository-aware (already present on most Macs).    |

> [!IMPORTANT]
> Secure Enclave identity generation requires **Apple Silicon** (M-series) with a
> Secure Enclave. On other hardware you can still use sopsy by supplying an
> existing `age` public key (`--public-key`), but you lose hardware protection.

> [!TIP]
> Not sure what's installed? Run `sopsy doctor` — it prints exactly which tools
> were found on your `PATH` and where.

## Install

From [crates.io](https://crates.io/crates/sopsy):

```bash
cargo install sopsy
```

Or build from source:

```bash
git clone https://github.com/kigster/sopsy.git
cd sopsy
cargo build --release
# binary at ./target/release/sopsy
```

---

## Quick Start

```bash
# 1. Start (or enter) a git repository.
git init my-app && cd my-app

# 2. Bootstrap everything: tools check, Secure Enclave identity, config files.
sopsy init

# 3. Put real secrets in. sopsy decrypts to your editor and re-encrypts on save.
sopsy edit .env.encrypted

# 4. Verify hygiene before you commit (also your CI command).
sopsy check

# 5. Commit the *encrypted* artifacts. Plaintext .env is already gitignored.
git add .sops.yaml .sopsy.yml .env.example .env.encrypted .gitignore
git commit -m "Add encrypted secrets managed by sopsy"
```

> [!CAUTION]
> Never `git add .env` or any plaintext secret. `sopsy init` configures
> `.gitignore` to prevent this, and `sopsy check` will fail the build if a
> plaintext secret is ever tracked — but the first line of defense is you.

The `sopsy init` run prints your **public recipient** prominently. That string
(an `age1se1...` key) is what your teammates and admins need to grant you
access — it is safe to share. The matching **private key never leaves the Secure
Enclave**.

> [!TIP]
> **Joining a repo someone else bootstrapped?** Don't run `init`. Run
> `sopsy join <your-name>` to generate your key and record a pending request, open
> a pull request, and ask any current member to run `sopsy approve <your-name>`.
> See the [Member guide](docs/guide-member.md).

---

## Architecture

`sopsy` is a thin, well-factored Rust crate: a `clap` CLI dispatches to one
module per command, and the commands lean on small helper modules that wrap the
external tools. All terminal output and prompting funnels through a single `ui`
layer.

```mermaid
flowchart TD
    subgraph Binary
        main["main.rs<br/>ExitCode mapping"]
    end
    subgraph Library["sopsy crate (lib.rs::run)"]
        cli["cli.rs<br/>clap parser + flags"]
        ui["ui.rs<br/>color, spinners, prompts"]
        config["config.rs<br/>.sopsy.yml model"]
        error["error.rs<br/>Error / Result"]

        subgraph Commands["commands/"]
            init["init"]
            doctor["doctor"]
            edit["edit"]
            join["join"]
            approve["approve"]
            recipient["recipient<br/>add / remove / list<br/>keygen / break-glass"]
            check["check"]
        end

        subgraph Helpers["external-tool wrappers"]
            sops["sops/<br/>encrypt, decrypt, edit, updatekeys"]
            enclave["enclave/<br/>age-plugin-se keygen"]
            age["age<br/>age-keygen (portable keys)"]
            git["git/<br/>repo root, tracked, ignored"]
        end
    end

    subgraph External["External tools"]
        sopsbin([sops])
        agebin([age / age-keygen])
        sebin([age-plugin-se])
        gitbin([git])
    end

    main --> cli
    cli --> Commands
    Commands --> ui
    Commands --> config
    Commands --> error
    init --> sops & enclave & git
    doctor --> git
    edit --> sops
    join --> enclave & git
    approve --> sops & git
    recipient --> sops & enclave & age & git
    check --> git & config
    sops --> sopsbin
    sopsbin --> agebin
    enclave --> sebin
    age --> agebin
    git --> gitbin
```

| Module          | Responsibility                                                        |
| --------------- | -------------------------------------------------------------------- |
| `cli.rs`        | Authoritative `clap` definition of every command and flag.           |
| `ui.rs`         | All output and `inquire`-backed prompts; color/TTY/`NO_COLOR` logic. |
| `config.rs`     | The serde model for `.sopsy.yml` (members, states, globs, TTL, …).   |
| `commands/`     | One module per subcommand (`init`, `join`, `approve`, `recipient`, …).|
| `sops/`         | Wraps `sops` (`encrypt`, `decrypt`, `edit`, `updatekeys`).           |
| `enclave/`      | Wraps `age-plugin-se keygen` (Secure Enclave identities).            |
| `age.rs`        | Wraps `age-keygen` for portable keys (used by break-glass).          |
| `git/`          | Repo root, tracked files, ignore status, `.gitignore` editing.       |
| `error.rs`      | `Error`/`Result`; the binary maps any `Err` to a non-zero exit.      |

### The `init` bootstrap flow

```mermaid
sequenceDiagram
    actor Dev as Developer
    participant Sopsy as sopsy init
    participant Git as git
    participant SE as age-plugin-se
    participant Sops as sops
    participant FS as Repo files

    Dev->>Sopsy: sopsy init
    Sopsy->>Git: rev-parse --show-toplevel
    Git-->>Sopsy: repo root (or error)
    Sopsy->>Sops: ensure `sops` on PATH
    alt --public-key supplied
        Sopsy->>Sopsy: use existing age recipient
    else generate identity (default)
        Sopsy->>SE: age-plugin-se keygen
        SE-->>Sopsy: public key age1se1… (private key stays in Enclave)
    end
    Sopsy->>Dev: print public recipient (animated)
    Sopsy->>FS: write .sops.yaml creation rules
    Sopsy->>FS: write .env.example
    Sopsy->>FS: seed .env.encrypted (from .env or .env.example)
    Sopsy->>Sops: --encrypt --in-place .env.encrypted (dotenv)
    Sops-->>FS: encrypted .env.encrypted
    Sopsy->>FS: update .gitignore (ignore plaintext secrets)
    Sopsy->>FS: write .sopsy.yml (recipients, sops version)
    opt break-glass (prompted, or --break-glass)
        Sopsy->>Dev: generate portable key, "copy to 1Password", wait for ENTER
        Sopsy->>FS: delete local key files; register break-glass + re-key
    end
    Sopsy->>Dev: health summary
```

> [!NOTE]
> `init` is **idempotent**: existing files are preserved unless you pass
> `--force`. Re-running it is always safe.

> [!TIP]
> In **interactive** mode `init` offers to set up the break-glass key right then —
> the moment you're most likely to actually do it. It prints a yellow prompt to
> copy the generated `break-glass.private` / `.public` into 1Password, waits for
> you, then deletes the local copies. Use `--break-glass` / `--no-break-glass` to
> decide explicitly (e.g. in scripts).

---

## How encryption flows

sopsy never touches ciphertext itself — it shells out to `sops`, which uses
`age` recipients drawn from `.sops.yaml`'s `creation_rules`. The primary path is
the dotenv format: a plaintext `.env` becomes an encrypted `.env.encrypted`.

```mermaid
flowchart LR
    subgraph Plaintext["Plaintext (never committed)"]
        env[".env<br/>KEY=value"]
    end
    subgraph Rules[".sops.yaml"]
        cr["creation_rules<br/>path_regex → age recipients"]
    end
    subgraph Encrypted["Committed to Git"]
        enc[".env.encrypted<br/>encrypted values + sops metadata"]
    end

    env -- "sops --encrypt --input-type dotenv" --> enc
    cr -. supplies recipients .-> enc
    enc -- "sops --decrypt (needs a private key)" --> view["plaintext in your editor"]
    view -- "save → re-encrypt" --> enc
```

- **Encrypt** — `sops --encrypt --input-type dotenv --output-type dotenv
  --in-place .env.encrypted`. The recipients come from `.sops.yaml`.
- **Decrypt / edit** — `sopsy edit` runs `EDITOR=<editor> sops <file>`, which
  decrypts into a temp file, opens your editor, then re-encrypts on save. This
  requires a private key one of the recipients holds.
- **File-type detection** — `.env`, `.env.*`, and `*.env` map to `dotenv`;
  `.yaml`/`.yml` to `yaml`; `.json` to `json`; everything else to `binary`.

> [!IMPORTANT]
> Only **encrypted** files (`.env.encrypted`, `*.encrypted`,
> `config/*.encrypted.yaml`) and **public** metadata (`.sops.yaml`, `.sopsy.yml`,
> `.env.example`) belong in Git. The plaintext `.env` must always stay local.

---

## The Secure Enclave security model

Each developer owns an individual key pair. On macOS Apple Silicon the private
key is generated *inside* the Secure Enclave and is bound to that hardware — it
cannot be read, copied, or exported by anyone or anything. Only the **public
recipient** is ever shared or committed.

```mermaid
flowchart TB
    subgraph Laptop["Developer's Mac"]
        subgraph SE["Secure Enclave (hardware)"]
            priv["🔒 Private key<br/>never leaves the chip<br/>gated by Touch ID"]
        end
        plugin["age-plugin-se"]
        plugin -. references .-> priv
    end

    pub["📢 Public recipient<br/>age1se1…"]
    priv -- derives --> pub

    subgraph Repo["Git repository (shared)"]
        sopsyaml[".sops.yaml<br/>age: age1se1…"]
        sopsyyml[".sopsy.yml<br/>name + public key"]
    end

    pub -- "safe to commit" --> sopsyaml
    pub -- "safe to commit" --> sopsyyml

    priv -. "decrypt (Touch ID prompt)" .-> secrets[".env.encrypted"]
```

> [!WARNING]
> Because the private key is bound to one device, **losing that device means
> losing that key**. The repository stays decryptable as long as *another*
> recipient — a teammate or the break-glass key — can still read it. This is why
> a break-glass key is mandatory in `sopsy check`.

### Where your identity lives

When `sopsy init` or `sopsy join` generates a Secure Enclave identity, the
**identity handle** (`AGE-PLUGIN-SE-1…`) is written to your per-user `sops` age
keys file:

| Platform        | Location                                              |
| --------------- | ---------------------------------------------------- |
| macOS           | `~/Library/Application Support/sops/age/keys.txt`    |
| Linux / others  | `${XDG_CONFIG_HOME:-~/.config}/sops/age/keys.txt`    |

That handle is **not** secret key material — the private key never leaves the
Secure Enclave, and the handle only works on *this* device, behind Touch ID — so
keeping it on disk is safe. `sops` reads this file automatically (sopsy also
points at it explicitly via `SOPS_AGE_KEY_FILE`), and that is what lets
`sopsy edit` and `sopsy secrets decrypt` unlock your secrets. Override the path
with `SOPSY_KEYS_FILE` if you keep identities elsewhere.

> [!NOTE]
> Lose this file and you lose the *reference* to your Enclave key — re-run
> `sopsy join` (or `init`) to mint a fresh identity and get re-approved. The
> portable **break-glass** key is the repo-wide safety net.

### Console session, Touch ID, and one-laptop testing

Secure Enclave keys can only be **used to decrypt** from the user's *active GUI
login session*. `sudo`, `su`, and SSH cannot raise the Touch ID prompt, so
decryption from those contexts fails with `no identity matched any of the
recipients` — often with no prompt at all. Encryption and key generation are
unaffected (they never touch the private key).

You are prompted for Touch ID on every operation that **reads** a secret:
`sopsy secrets decrypt`, `sopsy edit`, and `sopsy approve` (once per encrypted
file — so approve can prompt more than once). There is no time-based "remember
me"; to prompt less often, decrypt once per shell with [direnv](#sopsy-secrets).

This matters when simulating a **team on a single Mac** — e.g. exercising the
owner → member (`join` / `approve`) flow with two accounts:

- Switch with **Fast User Switching** (log the second account in at the login
  screen). Do **not** `sudo`/`su` into it — the Enclave won't be reachable.
- Touch ID is enrolled **per macOS account**. The second user must add a
  fingerprint in *System Settings → Touch ID & Password*, or the default
  `any-biometry-or-passcode` policy falls back to that account's **login
  password**.
- Each account has its **own** keystore and its **own** Enclave keys — an
  identity minted by one user cannot be unwrapped by another. That is the whole
  point: every member holds a private key only they can use.

> [!NOTE]
> Because Enclave identities only work interactively at the console, they are
> useless for CI, automation, and headless/SSH use — which is exactly what the
> portable **break-glass** key (next section) is for.

## Break-glass keys

A **break-glass key** is a separate emergency `age` key pair stored *offline*
(for example in 1Password) and shared with only a few admins. It is your
disaster-recovery path: if every developer's Secure Enclave device is lost, the
break-glass key can still decrypt and re-key the repository. It is a **portable**
age key (not Enclave-backed), precisely so it can survive the loss of any device.

`sopsy recipient break-glass` runs the whole ceremony — generate, hand off, delete,
register — in one command:

```bash
sopsy recipient break-glass -o break-glass
#  1. generates a portable age key pair
#  2. writes break-glass.private and break-glass.public
#  3. prompts you to copy them into 1Password, then WAITS for ENTER
#  4. deletes both local files and registers the key, re-keying every secret
```

> [!CAUTION]
> If you lose your Secure Enclave device **and** have no break-glass key, every
> secret in the repository becomes permanently undecryptable. Set up break-glass
> on day one. `sopsy doctor` and `sopsy check` both nag you until you do, and
> sopsy refuses to remove the *sole* break-glass recipient.

---

## Files sopsy manages

| File             | Committed? | Purpose                                                              |
| ---------------- | ---------- | ------------------------------------------------------------------- |
| `.sops.yaml`     | ✅ yes     | SOPS `creation_rules`: maps file patterns → `age` recipients.       |
| `.sopsy.yml`     | ✅ yes     | sopsy's own state: member names, usernames, `pending`/`active` state, break-glass marker, `join_request_ttl`, sops version. |
| `.env.example`   | ✅ yes     | Placeholder variables; the template for a real `.env`.              |
| `.env.encrypted` | ✅ yes     | The encrypted secrets (`KEY=ENC[…]` + sops metadata).               |
| `.gitignore`     | ✅ yes     | Updated to ignore plaintext secrets and un-ignore the safe files.   |
| `.env`           | 🚫 never   | Your real plaintext secrets — gitignored, never committed.          |

The `.gitignore` rules `sopsy init` ensures are present:

```gitignore
.env
.env.*
!.env.example
!.env.encrypted
*.key
*.pem
```

A minimal generated `.sops.yaml` looks like:

```yaml
# Managed by sopsy. Maps encrypted files to their age recipients.
creation_rules:
  - path_regex: '\.env\.encrypted$'
    age: 'age1se1qg8vw…'
  - path_regex: '\.encrypted$'
    age: 'age1se1qg8vw…'
```

---

## Command Reference

The CLI is `clap`-based, so `sopsy --help` and `sopsy <command> --help` are
always authoritative. Every interactive prompt has an equivalent flag.

```
sopsy [GLOBAL FLAGS] <COMMAND> [ARGS]
```

### Global flags

These apply to **every** subcommand (they are global and may appear before or
after the subcommand):

| Flag                          | Description                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------- |
| `-y`, `--yes`, `--non-interactive` | Disable all prompts; fail with a clear error instead of asking. Auto-enabled when stdout is not a TTY. |
| `--no-color`                  | Disable colored output. Also honored via the `NO_COLOR` environment variable.                 |
| `-v`, `--verbose`             | Increase verbosity (show debug detail such as the resolved editor and file type).             |

> [!TIP]
> In CI you don't even need `-y`: when stdout is not a terminal, sopsy detects it
> and refuses to block on prompts automatically. Passing `-y` explicitly is still
> good hygiene and makes intent obvious in scripts.

### `sopsy init`

Bootstrap an encrypted repository. Verifies the toolchain, acquires an `age`
recipient (a generated Secure Enclave identity or a supplied public key), and
writes `.sops.yaml`, `.env.example`, an encrypted `.env.encrypted`, `.gitignore`
safety rules, and `.sopsy.yml`.

| Flag                       | Description                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| `--recipient-name <NAME>`  | Name to record for the recipient created/registered during init (default: `primary`).        |
| `--username <NAME>`        | Username of who generated the key, recorded in `.sopsy.yml`. When generating interactively, this is the default offered at the prompt (falls back to `$USER`). |
| `--public-key <age1...>`   | Use an existing `age` public key instead of generating a new Secure Enclave identity.        |
| `--no-generate`            | Skip Secure Enclave identity generation. Requires `--public-key`, else init errors.          |
| `--break-glass`            | Run the break-glass ceremony as part of init (interactive mode prompts by default).          |
| `--no-break-glass`         | Skip break-glass setup during init (you'll get a reminder to run it later).                   |
| `--force`                  | Overwrite/recreate `.sops.yaml` and `.env.encrypted` even if they already exist.             |

```bash
# Interactive: generate a Secure Enclave identity (Touch ID may prompt).
sopsy init

# Interactive but name the recipient:
sopsy init --recipient-name alice

# Non-interactive / CI: bring your own age key, never touch the Enclave.
sopsy init -y --recipient-name ci-bot \
  --public-key age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p \
  --no-generate
```

> [!IMPORTANT]
> `init` must run inside a git repository — run `git init` first. It is
> idempotent: existing config files are kept unless `--force` is given.

### `sopsy doctor`

Print a colorful, grouped health report and **always exit 0** — it is purely
informational and safe to paste into a bug report. Takes no flags.

It reports four groups:

- **System** — macOS version, Apple Silicon, Secure Enclave, Touch ID (macOS
  only; a neutral "n/a" line elsewhere).
- **Tools** — where `sops`, `age-plugin-se`, and `git` resolve on `PATH`.
- **Repository** — git presence, `.sops.yaml`, `.sopsy.yml` presence and parsing.
- **Recipients** — a loud reminder if no break-glass recipient is configured.

```bash
sopsy doctor
```

### `sopsy edit`

Edit an encrypted file with your editor through SOPS — "the missing DX" wrapper
around `EDITOR=<editor> sops <file>`, with friendlier errors and automatic
file-type detection.

| Argument / Flag        | Description                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------- |
| `<file>`               | The encrypted file to edit (required).                                                 |
| `--editor <EDITOR>`    | Editor to use. Overrides `$EDITOR`. Resolution: `--editor` → `$EDITOR` → `$VISUAL` → `vi`. |
| `-- <sops args>`       | Everything after `--` is forwarded verbatim to `sops` (can override sopsy's defaults). |

```bash
# Use your $EDITOR (or vi):
sopsy edit .env.encrypted

# Force a specific editor:
sopsy edit .env.encrypted --editor "code --wait"

# Forward extra flags straight to sops:
sopsy edit config/db.encrypted.yaml -- --indent 4
```

> [!NOTE]
> sopsy detects the file type (`dotenv`/`yaml`/`json`/`binary`) and passes
> `--input-type`/`--output-type` to sops, because encrypted file names like
> `.env.encrypted` don't carry an extension sops recognizes. Anything you pass
> after `--` is appended afterward and can override these defaults.

### `sopsy join`

Request membership in a repo someone else bootstrapped. Generates your Secure
Enclave identity (or uses `--public-key`) and records a **pending** entry in
`.sopsy.yml` with a timestamp. A pending entry is *not* added to `.sops.yaml`, so it
grants no access — it is purely a request you then push as a pull request.

| Argument / Flag           | Description                                                                       |
| ------------------------- | -------------------------------------------------------------------------------- |
| `<name>`                  | Your member name / handle (required).                                            |
| `--public-key <age1...>`  | Use an existing public key instead of generating a new Secure Enclave identity.  |
| `--sopsy-file <FILE>`     | Path to the `.sopsy.yml` to update (defaults to the one in the repo root).       |
| `-- <age flags>`          | Everything after `--` is forwarded to `age-plugin-se keygen`.                    |

```bash
sopsy join alice                          # generate a key, record a pending request
sopsy join alice --public-key age1se1…    # reuse an existing public key
# then:
git add .sopsy.yml && git commit -m "join: request access for alice" && git push
```

> [!NOTE]
> After pushing, open a pull request and ask any active member to run
> `sopsy approve alice`. Approve promptly — the request expires after the repo's
> `join_request_ttl` (default 72h); just re-run `sopsy join` to refresh it.

### `sopsy approve`

Approve a pending member (run by **any active member**, on their PR branch). Checks
the request is fresh, asks you to vouch that the key belongs to the person, adds the
key to `.sops.yaml`, flips them to `active`, and runs `sops updatekeys` so every
encrypted file gains a stanza they can open. Rolls back atomically if the re-key
fails.

| Argument / Flag     | Description                                                                |
| ------------------- | ------------------------------------------------------------------------- |
| `<name>`            | The pending member to approve (required).                                 |
| `--force`           | Approve even if the join request is older than `join_request_ttl`.        |
| `--no-updatekeys`   | Skip the `sops updatekeys` re-encryption step after editing `.sops.yaml`. |

```bash
git fetch origin pull/123/head:join-alice && git switch join-alice
sopsy approve alice                       # vouch, re-key, activate (Touch ID prompts)
git add -A && git commit -m "approve: alice" && git push   # then merge the PR
```

> [!WARNING]
> Encrypted files do **not** merge. If `.env.encrypted` changes on `main` between
> your `approve` and the merge, the PR will conflict — rebase onto latest `main`
> right before approving, and merge promptly. In non-interactive contexts the vouch
> step requires `SOPSY_ASSUME_YES` (it cannot be left unattended).

### `sopsy recipient`

Manage the repository's recipients. `add`/`remove` keep `.sopsy.yml` and
`.sops.yaml` in sync and then re-wrap the existing encrypted files for the new
recipient set (`sops updatekeys`, per file). `keygen` and `break-glass` are key
generation helpers.

#### `recipient add`

| Argument / Flag           | Description                                                                  |
| ------------------------- | ---------------------------------------------------------------------------- |
| `[name]`                  | Positional recipient name (equivalent to `--name`).                          |
| `--name <NAME>`           | Recipient name (prompted if omitted in interactive mode).                    |
| `--public-key <age1...>`  | The recipient's `age` public key (prompted if omitted in interactive mode).  |
| `--break-glass`           | Mark this recipient as the offline emergency break-glass key.                |
| `--no-updatekeys`         | Skip the `sops updatekeys` re-encryption step after editing `.sops.yaml`.    |

```bash
# Interactive: prompts for name + key.
sopsy recipient add

# Non-interactive: add a teammate by positional name.
sopsy recipient add bob --public-key age1se1qg8vw…

# Register the break-glass emergency key.
sopsy recipient add break-glass --public-key age1q… --break-glass
```

> [!WARNING]
> `recipient add` rejects duplicate names and duplicate public keys. With
> `--no-updatekeys`, the config is changed but existing secrets are **not**
> re-encrypted for the new recipient — they cannot decrypt until you run
> `sops updatekeys` (or re-add without the flag).

#### `recipient remove`

| Argument / Flag     | Description                                                                |
| ------------------- | -------------------------------------------------------------------------- |
| `[name]`            | Positional recipient name (equivalent to `--name`).                       |
| `--name <NAME>`     | Recipient to remove (a multi-select prompt is shown if omitted).          |
| `--no-updatekeys`   | Skip the `sops updatekeys` re-encryption step after editing `.sops.yaml`. |

```bash
sopsy recipient remove alice
sopsy recipient remove --name alice   # equivalent
```

> [!CAUTION]
> sopsy refuses to remove the **last remaining recipient** (the repo would
> become undecryptable) or the **sole break-glass recipient**. Removing a person
> re-encrypts the secrets so the departed key can no longer read *new* commits —
> but anyone who already cloned old ciphertext still holds it, so **rotate the
> underlying secret values too** when offboarding.

#### `recipient list`

Print all configured recipients as a colorful aligned table (name, truncated
public key, break-glass marker). Takes no flags.

```bash
sopsy recipient list
```

#### `recipient keygen`

Generate a fresh Secure Enclave identity and print its public key + identity
**without** touching any config (use the printed key with `recipient add`). Trailing
args after `--` are forwarded to `age-plugin-se keygen`.

```bash
sopsy recipient keygen
sopsy recipient keygen -- --access-control=any-biometry-or-passcode
```

#### `recipient break-glass`

Generate the offline emergency key in one guided ceremony: write
`<output>.private` / `<output>.public`, prompt you to copy them into a secure store,
wait for ENTER, then delete the local files and register the key as the break-glass
recipient (re-keying every secret).

| Argument / Flag        | Description                                                          |
| ---------------------- | ------------------------------------------------------------------- |
| `-o, --output <FILE>`  | Output prefix; writes `<output>.private` and `<output>.public`.     |
| `--name <NAME>`        | Recipient name to record (defaults to `break-glass`).               |
| `--force`              | Overwrite the `.private` / `.public` files if they already exist.   |
| `--no-updatekeys`      | Skip the `sops updatekeys` re-encryption step.                      |

```bash
sopsy recipient break-glass -o break-glass
```

> [!IMPORTANT]
> This step is interactive by design (it waits for you to confirm the key is stored
> safely before deleting it). For automation set `SOPSY_ASSUME_YES`, which assumes
> the confirmation — use it only when something else handles secure storage.

### `sopsy secrets`

One-shot encrypt/decrypt of a single file, defaulting to **stdout** so it composes
in pipelines. Unlike `edit` (which opens an editor) these are non-interactive and
scriptable. The encrypted artifact always ends in `.encrypted`, so the default
`.sops.yaml` rule covers it.

#### `secrets encrypt`

| Argument / Flag        | Description                                                                  |
| ---------------------- | ---------------------------------------------------------------------------- |
| `<file>`               | The plaintext file to encrypt (`.env`/`.yaml`/`.json`/`.ini`/…).             |
| `-o, --output <FILE>`  | Write ciphertext to a file (**must end in `.encrypted`**) instead of stdout. |
| `--type <T>`           | Override the format (`dotenv`/`yaml`/`json`/`ini`/`binary`) if the name lacks a usable extension. |

```bash
sopsy secrets encrypt .env -o .env.encrypted        # the committed artifact
sopsy secrets encrypt config.json > config.json.encrypted
```

#### `secrets decrypt`

| Argument / Flag        | Description                                                        |
| ---------------------- | ----------------------------------------------------------------- |
| `<file>`               | The encrypted file to decrypt.                                    |
| `-o, --output <FILE>`  | Write plaintext to a file instead of stdout.                     |
| `--type <T>`           | Override the format (rarely needed; inferred from the name).      |

```bash
sopsy secrets decrypt .env.encrypted                 # → plaintext on stdout
sopsy secrets decrypt config.json.encrypted -o config.json
```

> [!TIP]
> **Load secrets into your shell with `direnv`** — drop this in `.envrc` so the
> decrypted values live only in memory, only inside the project directory:
> ```bash
> eval "$(sopsy secrets decrypt .env.encrypted | sed -E '/^#/d; /^$/d; s/^([A-Z])/export \1/g')"
> ```
> The same idea works in a wrapper that `exec`s your app (Rails, etc.) with the
> secrets in its environment — nothing is ever written to disk in plaintext.

> [!NOTE]
> Structured formats (`dotenv`/`yaml`/`json`/`ini`) encrypt **values only**, so
> keys and structure stay readable and diffable in Git. Everything else is
> `binary` (the whole file is encrypted as one opaque blob).

### `sopsy list-supported-types`

Print the file formats sopsy understands (the valid values for `--type`) and which
extensions auto-detect to each. Takes no flags.

```bash
sopsy list-supported-types
#   dotenv   .env, .env.*, *.env
#   yaml     .yaml, .yml
#   json     .json
#   ini      .ini
#   binary   anything else (whole-file)
```

### `sopsy check`

The CI gate. Runs seven hygiene invariants over the repository, prints a
pass/fail checklist, and **exits non-zero if any invariant fails**. It never
needs a decryption key — encrypted files are validated by their on-disk sops
metadata, not by decrypting them. Takes no flags.

```mermaid
flowchart TD
    start([sopsy check]) --> cfg{.sopsy.yml present?}
    cfg -- no --> skip["warn: not sopsy-managed"] --> ok0([exit 0])
    cfg -- yes --> i1["1 · .env not tracked by git"]
    i1 --> i2["2 · .env is gitignored"]
    i2 --> i3["3 · .sops.yaml valid + has creation_rules"]
    i3 --> i4["4 · every encrypted file matches a creation rule"]
    i4 --> i5["5 · no plaintext secrets tracked"]
    i5 --> i6["6 · every encrypted file carries sops metadata"]
    i6 --> i7["7 · a break-glass recipient is configured"]
    i7 --> verdict{any failures?}
    verdict -- no --> ok(["✔ all checks passed · exit 0"])
    verdict -- yes --> fail(["✗ checks failed · exit 1"])
```

The seven invariants:

1. `.env` is **not** tracked by git.
2. `.env` **is** gitignored.
3. `.sops.yaml` exists and parses with at least one `creation_rules` entry.
4. Every encrypted file (matching `.sopsy.yml`'s `encrypted_globs`) matches at
   least one `.sops.yaml` `path_regex`.
5. No plaintext secrets are tracked (`.env`/`.env.*` that isn't
   `.env.example`/`*.encrypted`, or any `*.key`/`*.pem`).
6. Every encrypted file carries sops metadata (`sops` section + `ENC[`).
7. A break-glass recipient exists in `.sopsy.yml`.

```bash
sopsy check && echo "secrets hygiene: OK"
```

> [!NOTE]
> If `.sopsy.yml` is absent, the repository is not sopsy-managed, so `check`
> prints a notice and exits **0** rather than failing unrelated repositories.

---

### `sopsy deps`

Install the external tools sopsy needs (`sops`, `age`, `age-plugin-se`) with
[Homebrew](https://brew.sh). It probes for each tool first and only installs the
ones that are missing, so it is safe to run repeatedly. This is the *remedy* that
pairs with `sopsy doctor`'s *diagnosis*.

| Flag        | Effect                                                       |
| ----------- | ------------------------------------------------------------ |
| `--check`   | Report status only; exit **non-zero** if anything is missing.|
| `--dry-run` | Print the `brew install …` command without running it.       |

```bash
sopsy deps              # install whatever is missing
sopsy deps --check      # CI / pre-flight: fail if a dependency is absent
sopsy deps --dry-run    # preview the brew command without touching the system
```

> [!NOTE]
> `git` is intentionally **not** installed here — it ships with macOS / the Xcode
> Command Line Tools. If `brew` itself is missing, `deps` points you to
> <https://brew.sh>.

> [!TIP]
> `sopsy doctor` tells you *what* is missing; `sopsy deps` *fixes* it. For tests
> and sandboxes, the `brew` binary can be overridden with `SOPSY_BREW_BIN`.

---

### `sopsy completion`

Generate a shell completion script. Completions are derived directly from the
CLI definition, so they never drift from the real commands and flags. Supports
`bash`, `zsh`, `fish`, `powershell`, and `elvish`. The script is written to
**stdout**.

```bash
# zsh — write into a directory on your $fpath
sopsy completion zsh > "${fpath[1]}/_sopsy"

# bash — into Homebrew's bash-completion directory
sopsy completion bash > "$(brew --prefix)/etc/bash_completion.d/sopsy"

# fish
sopsy completion fish > ~/.config/fish/completions/sopsy.fish

# …or load it ephemerally from your shell rc
eval "$(sopsy completion zsh)"
```

> [!TIP]
> After installing a zsh completion you may need to restart your shell (or run
> `compinit`) for it to take effect.

---

## Using sopsy in CI

`sopsy check` is the one command you want in CI and in a pre-commit hook.

### GitHub Actions

```yaml
name: secrets-hygiene
on: [push, pull_request]
jobs:
  check:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - run: brew install sops age age-plugin-se
      - run: cargo install sopsy
      - run: sopsy check          # non-interactive auto-detected; exits 1 on failure
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
exec sopsy check
```

> [!TIP]
> `sopsy check` only inspects on-disk metadata and never decrypts, so it needs
> **no private key and no Secure Enclave** — it runs perfectly on a Linux CI
> runner too. Pass `-y` to be explicit about non-interactive intent.

---

## Environment variables

| Variable                    | Effect                                                                        |
| --------------------------- | ----------------------------------------------------------------------------- |
| `EDITOR` / `VISUAL`         | Editor for `sopsy edit` (after `--editor`, before the `vi` default).          |
| `NO_COLOR`                  | Disables colored output (same as `--no-color`).                               |
| `SOPSY_KEYS_FILE`           | Override where sopsy stores/reads the age identity (default: the per-user `sops` keys file). |
| `SOPS_AGE_KEY_FILE`         | Standard `sops` var for the age identity file; if you set it, sopsy honors it and stores there. |
| `SOPSY_SOPS_BIN`            | Override the `sops` binary path (primarily for testing).                      |
| `SOPSY_AGE_PLUGIN_SE_BIN`   | Override the `age-plugin-se` binary path (primarily for testing).             |
| `SOPSY_AGE_KEYGEN_BIN`      | Override the `age-keygen` binary path (used by break-glass; for testing).     |
| `SOPSY_ASSUME_YES`          | Assume interactive confirmations (break-glass press-ENTER, `approve` vouch). For automation/CI only. |

---

## Scope and roadmap

`sopsy` is **macOS-first** for v1 — the fastest path to a polished experience.
Deliberately **out of scope** until requested: Linux, TPM, YubiKey, KMS,
1Password/Vault integration, GitHub Actions helpers, a native-Rust SOPS, and a
Ratatui TUI.

## Further reading

- 📘 **[Member guide](docs/guide-member.md)** — joining a sopsy-managed repo with
  `sopsy join`, day-to-day workflow, and troubleshooting.
- 🛠️ **[Owner guide](docs/guide-owner.md)** — bootstrapping, break-glass, the
  join/approve membership lifecycle, and offboarding.
- 🔗 Repository: <https://github.com/kigster/sopsy>
- 🔗 Crate: <https://crates.io/crates/sopsy>
- 🔗 [SOPS](https://github.com/getsops/sops) ·
  [age](https://github.com/FiloSottile/age) ·
  [age-plugin-se](https://github.com/remko/age-plugin-se)
</content>
</invoke>
