---
created: 2026-10-30
starts: research
depth: deep
implementation_suggestions:
  - "Implement the agent as a `sopsy agent` subcommand of the existing binary (no second executable), listening on a per-user Unix socket such as `$XDG_RUNTIME_DIR/sopsy/agent.sock` or `~/Library/Caches/sopsy/agent.sock`"
  - "Cache the unwrapped sops data key, not the decrypted file: key the cache by SHA-256 of the file's encrypted age stanza (`sops.age[].enc`). Every worktree of a repo holds the same `.env.encrypted`, so one touch covers all of them"
  - "Evaluate speaking the sops keyservice gRPC protocol (`sops --keyservice unix://…`), so sops itself asks the agent to unwrap the data key and sopsy does not reimplement any sops decryption"
  - "Hold the daily session key only in agent memory (mlock where available, zeroize on drop); persist nothing by default"
  - "Derive the key that protects any persisted state from the user's agent password with Argon2id; generate the session key itself from the OS CSPRNG"
  - "Use YAML for every config layer, with the same schema at every layer"
  - "Nice to have: a basic status page showing the session, its expiry and the cached entries, with actions to clear one entry, clear all, restart the agent, or shut it down. Access follows 'Opening the status page' below"
  - "Optional extra factor to evaluate: `sopsy agent register [USERNAME] --public-key ~/.ssh/id_ed25519.pub` stores an SSH public key in the Keychain / Secret Service, and `sopsy agent web` must also prove possession of the private key before a grant is issued: either decrypt a token the agent encrypted to it (age accepts `ssh-ed25519` recipients) or sign a nonce with `ssh-keygen -Y sign -n sopsy-agent` (which also works with keys in ssh-agent, 1Password or Secretive)"
  - "The bootstrap page is a minimal bundled HTML+JS page with no third-party assets; it reads the ticket from the fragment, strips it with `history.replaceState`, POSTs it to `/session`, and keeps the returned credential in JavaScript memory only"
  - "Ship `sopsy agent install` / `uninstall`, which write and load a launchd user agent (`~/Library/LaunchAgents/…plist`) on macOS and a systemd user unit (`~/.config/systemd/user/sopsy-agent.service`, socket-activated if practical) on Linux"
  - "Add `sopsy exec -- <cmd>` that injects decrypted variables only into the child process, as a lazy alternative to decrypting on every `cd` in `.envrc`"
implementation_requirements:
  - "The agent is opt-in. With no agent running, or with `SOPSY_AGENT=off`, every command behaves exactly as it does today"
  - "No plaintext secret, sops data key, private key or session key is ever written to disk unencrypted, logged, placed in argv, or put in an environment variable of any process other than the one the user asked to run"
  - "The agent socket is reachable only by the user who started the agent: socket mode 0600 in a 0700 directory, and every connection is checked with the peer credentials (getpeereid / SO_PEERCRED); other UIDs are refused"
  - "Every cache entry has a TTL, and the effective TTL can never exceed the repository's ceiling from its committed `.sopsy.yml`"
  - "The session expires after at most 24 hours; after expiry the next decrypt requires the user to log in again"
  - "The agent runs under the OS service manager, never as a stray background process: a launchd user agent on macOS, a systemd user service on Linux. Other platforms report that the agent is unsupported"
  - "If the status page is built, browser access is granted only through `sopsy agent web`, which asks the agent over the peer-checked Unix socket. The caller's identity comes from the OS peer credentials; a username in the request is never treated as authentication"
  - "If the status page is built, each grant records the authenticated OS user, the permitted operations, an absolute deadline of creation + 15 minutes, the hash of a one-time ticket, and the listener it belongs to. Every web request is checked against the grant's permissions on the server, not by hiding controls in the page"
  - "If the status page is built, the agent opens the grant's listener on `127.0.0.1` with an OS-assigned ephemeral port (never a wildcard address, no SO_REUSEPORT) before returning the URL, which has the form `http://127.0.0.1:<port>/bootstrap#ticket=<32 random bytes, base64url>`"
  - "If the status page is built, the ticket is consumed atomically (two concurrent exchanges cannot both succeed), expires at the grant deadline, and is never reused as the session credential. The session credential is sent as `Authorization: Bearer …`, is accepted only on its own listener, and is never stored in a cookie or in persistent browser storage (cookies are not isolated by port, RFC 6265)"
  - "If the status page is built, every request checks the exact Host including the port; the ticket exchange and every write require the exact expected Origin (missing or `null` is rejected) and a JSON body; no GET request mutates state; there is no CORS access; responses carry a restrictive Content-Security-Policy with `frame-ancestors 'none'`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`; tickets and credentials never appear in logs"
  - "If the status page is built, the deadline is checked on every request against a monotonic clock and is not extended by the ticket exchange. At the deadline, or on `sopsy agent lock`, the grant is invalidated first, then the listener and every open connection (including streams or WebSockets) are closed"
  - "`sopsy agent lock` (or equivalent) wipes the session key and every cache entry immediately"
  - "TTLs are configurable at four layers (global, repository, user, device), and every layer uses the same file format and the same keys"
  - "Login supports at least these password sources: typed at a prompt, the macOS Keychain, the Linux Secret Service, a YubiKey, and 1Password via the `op` CLI"
  - "Every external tool the agent uses (`op`, `security`, `secret-tool`, `ykman`, `age-plugin-yubikey`) is probed the way `sopsy doctor` probes tools today, and honours a `SOPSY_*_BIN` override so tests can inject fakes"
task-completed-when:
  - "After `sopsy agent login` once, `sopsy secrets decrypt .env.encrypted` run in five different worktrees of one repository asks for a YubiKey touch or Touch ID at most once"
  - "After the TTL passes, or after `sopsy agent lock`, the next decrypt asks for the hardware again"
  - "A process running as another UID cannot obtain anything from the agent socket"
  - "`sopsy agent status` shows whether a session exists, when it expires, how many entries are cached, and the effective TTL with the layer each value came from"
  - "`sopsy agent install` on macOS leaves a loaded launchd job, and on Linux an enabled systemd user unit, that survives logout and login; `sopsy agent uninstall` removes it and its socket"
  - "`sopsy doctor` reports the agent's state and the config files it read"
  - "The guides in `docs/` describe the agent, its threat model, the config layers and the direnv recipe"
---
# Sopsy Caching Agent

## What we are trying to achieve

A per-user `sopsy agent` that lets a developer authenticate once at the start of the day and then decrypt without re-authenticating, in any worktree. Today every decrypt costs a hardware gesture: Touch ID for the Secure Enclave, or a PIN and touch for a YubiKey.

The user's model:

1. **Register** (`sopsy agent register`): choose an agent password, enter it twice, and choose where it lives. The choices are a prompt every time, the macOS Keychain, the Linux Secret Service, a YubiKey, or 1Password (fetched with `op read`).
2. **Log in** each morning (`sopsy agent login`): the agent verifies the password and opens a session. The session holds a fresh random session key, valid for at most one day.
3. **Use**: sopsy commands talk to the agent. The first decrypt of a given file still needs the hardware. After that, the agent serves that file's unwrapped data key from its cache, encrypted under the session key, until the entry's TTL expires.
4. **Inspect** (nice to have): a basic status page shows the session, its expiry and the cached entries. It can clear one or all entries, restart the agent, or shut it down.
5. **Lock / expire**: an explicit `sopsy agent lock`, the session's 24-hour limit, or (to be decided) screen lock or sleep wipes everything.

The thing to cache is the result of the hardware authorization, not the decrypted file. Hardware private keys never leave the chip, so the agent cannot cache the key itself. It can cache what the chip produced: the file's sops data key. With the data key in hand, sops decrypts the file body without touching the hardware.

The agent runs as an OS service: a launchd user agent on macOS and a systemd user unit on Linux, installed by `sopsy agent install`. It never runs as a detached process that sopsy forks.

### Opening the status page

Nobody without a terminal session as the user can reach the page. The guarantee: a sopsy command authenticated as a local OS user delegates limited access to whoever holds its one-time link, until a fixed deadline. A browser cannot independently prove it belongs to the user who ran the command.

```text
$ sopsy agent web
    sopsy → agent (Unix socket)   request a grant; agent reads the peer UID from the OS
    agent                         creates grant {user, operations, deadline = now + 15m, hash(ticket), listener}
                                  opens 127.0.0.1:<ephemeral port> for this grant
    agent → sopsy                 the URL

sopsy-caching-agent is ready for you at
http://127.0.0.1:52817/bootstrap#ticket=<random>

browser  GET  /bootstrap                     the fragment never leaves the browser
         JS   history.replaceState           ticket removed from the address bar
         POST /session {ticket}              Origin and Host checked; ticket consumed atomically
         ←    session credential             kept in JS memory only
         API  Authorization: Bearer <cred>   checked against the grant on every request
at the deadline: grant invalidated → listener and open connections closed
```

Reloading the page needs a new link from `sopsy agent web`; that is accepted for a temporary admin page.

The threat model for the page covers remote websites and other unprivileged local users. A compromised browser, malware running as the same user, and the machine's administrator are out of scope.

An SSH-key proof of possession (decrypt a challenge, or sign a nonce) is an optional extra on top of the socket check, for users whose SSH key has a passphrase or lives in hardware. Research decides whether to include it.

TTLs come from four layers, all in one YAML schema:

- global: `/etc/sopsy/agent.yml`
- user: `~/.config/sopsy/agent.yml`
- repository: an `agent:` section in the committed `.sopsy.yml`. It sets the ceiling a repository's owners allow.
- device: a section in the user file keyed by YubiKey serial or machine identifier, e.g. a laptop that leaves the house gets a shorter TTL.

A sketch, not binding:

```yaml
agent:
  session_ttl: 12h          # ≤ 24h
  cache_ttl: 4h
  lock_on_screen_lock: true
  devices:
    "yubikey:19108090": { cache_ttl: 8h }
    "machine:office-imac":  { cache_ttl: 10h }
```

### Lazy loading for direnv

The user's `.envrc`:

- loads `.env` when it exists and is newer than `.env.encrypted`;
- otherwise evals `sopsy decrypt` output on every directory entry.

So every worktree without a `.env` triggers a hardware prompt on every `cd`. Two complementary fixes are in scope:

- The agent makes repeated decrypts free while the session lasts. All worktrees share the same ciphertext, so they share one cache entry.
- `sopsy exec -- <cmd>` (name to be settled) decrypts only when a command that needs secrets actually runs. The variables go into that child's environment alone, never the interactive shell's. A documented `.envrc` recipe shows how to use it, for example wrapping `bin/rails`, `just` or `npm run` through it.

## Why it matters

- **The constant re-authentication undermines the hardware keys.** A developer with ten worktrees open is asked for a thumb or a touch dozens of times an hour. People respond by keeping a plaintext `.env` around, which defeats the point of keeping the key in hardware.
- **A cache with explicit, layered ceilings keeps the security story honest.** Repository owners decide the longest window they accept. Individuals can only shorten it.

## What already exists

- **How sopsy runs sops today.** `src/sops/mod.rs` shells out to `sops`. `src/keystore.rs` sets `SOPS_AGE_KEY_FILE` (hardware identity handles) and `SOPS_AGE_KEY` (Keychain-held secrets, via the environment) on the child.
  - For enclave and YubiKey identities, `sops` launches `age-plugin-se` or `age-plugin-yubikey` once per run, which is why every run asks again.
  - The YubiKey touch cache is fixed at 15 s in firmware. A cached PIN lasts one PC/SC session, and every sops run is a new session.
  - Touch ID is asked per decrypt.
- **Key stores are being added in PR #18** (`hermes/add-key-stores-ui`, open and not yet merged): enclave / yubikey / keychain / file, with `key_policy.required` in `.sopsy.yml`. This plan builds on that PR's `keystore.rs` and `hardware/` modules and should rebase on it once it merges.
- **The secrets commands.** `sopsy secrets decrypt` writes to stdout for direnv and other wrappers. `docs/guide-member.md` shows the direnv recipe users copy today.
- **Config.** `.sopsy.yml` is committed, protected by the `.sopsy.sha` sidecar, and loaded through `Config::load` in `src/config.rs`. A new `agent:` section must survive older sopsy versions; today an older version that saves the file drops unknown fields.
- **Tests.** Tests inject fake tools through `SOPSY_*_BIN` variables. Integration tests in `tests/` need `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false` on machines that sign commits.

## What research needs to settle

1. **Where the agent intercepts, and three options to compare.** Recommend one.
   - The sops keyservice protocol (`--keyservice`). Does its Decrypt RPC carry age stanzas, and can a keyservice serve age recipients?
   - An age plugin shim (`age-plugin-sopsy`) that wraps the real plugin and consults the agent.
   - sopsy unwrapping the data key itself and handing sops the plaintext data key. Does sops even accept one?
2. **What the cache key is.** Is the SHA-256 of the encrypted age stanza stable across worktrees and across `sops updatekeys`? Is it per-file or per-data-key? What happens when the file is re-keyed?
3. **The session-key derivation the user proposed.** The proposal derives the key from the login, the time and a hash of `ps -ef`. Evaluate it against a CSPRNG session key.
   - Every one of those inputs is observable or guessable by any local process, so they add no secrecy.
   - Confirm or refute that the password's job is to authenticate the login and protect persisted state (Argon2id), while the session key must come from the CSPRNG.
4. **Whether anything survives a restart of the agent or the machine.** Memory-only is simplest and safest. If a persisted encrypted cache is wanted, decide what wraps it.
5. **Threat model, written down.** Compare it with `ssh-agent`, `gpg-agent`, and 1Password's SSH agent.
   - Same-UID malware can talk to the agent. That is true of `ssh-agent` too. What, if anything, mitigates it: per-request confirmation, binding to a process tree, a code-signing check on macOS?
   - What it means for a repository whose policy requires hardware keys (`key_policy.required`). Should such repositories be able to forbid the agent, or cap it at a TTL?
6. **Lock triggers.** Screen lock, sleep, YubiKey removal, logout. What can be detected on macOS and on Linux, and how?
7. **The YubiKey as a password store.**
   - PIV slot, HMAC challenge-response (OTP slot 2), or FIDO2 hmac-secret? Which needs no extra tools beyond `ykman`?
   - How does it relate to the YubiKey that already holds the age key?
8. **The 1Password password source.** Check how `op read op://…` behaves, and review 1Password's CLI terms for automated use (R5).
9. **Config precedence.**
   - The proposal is that the repository sets a ceiling, user and device can only lower it, and the global layer sets a default. Confirm it, and define how the device keys are spelled (`yubikey:<serial>`, `machine:<id>`).
   - Pick the machine identifier: macOS `IOPlatformUUID`, Linux `/etc/machine-id`, or hostname.
10. **Service integration.**
    - launchd: `KeepAlive` versus on-demand `Sockets` activation, and where the socket lives.
    - systemd: a `.socket` unit for activation versus a plain user service; `loginctl enable-linger` or not.
    - How "restart" and "shut down" from the status page map onto `launchctl kickstart` / `bootout` and `systemctl --user restart` / `stop`. Without that mapping the service manager just respawns the agent.
    - How the first command in a non-interactive context (direnv) avoids blocking on a login prompt when no session exists.
11. **The lazy-loading design.**
    - Command name and shape (`sopsy exec`, `sopsy run`).
    - Whether direnv can export a stub that resolves on first use.
    - What the recommended `.envrc` looks like with and without the agent.
12. **The status page.**
    - Whether the optional SSH-key proof of possession is worth having, given the socket's peer-UID check already identifies the user. If it stays, choose between decrypting a challenge and signing a nonce (only signing works for keys in ssh-agent, 1Password or Secretive).
    - How SSH-key registration relates to the agent password from the main flow: a second factor, a replacement, or for the web page only.
    - Whether a single long-lived listener with per-grant credentials is simpler and still safe, compared with one listener per grant.
    - The HTTP server crate, and how the bootstrap page and assets get bundled into the binary.

## How to tell it's working?

- just warnings && just test
- An integration test in `tests/` drives login, decrypt from two temporary worktrees, and lock, with a fake `age-plugin-yubikey` that counts its invocations; the count is 1 before lock and 2 after
- An integration test connects to the socket as a different peer (or with a forged peer check) and is refused
- An integration test asserts that no file under `$HOME` or the repository contains the data key or the session key after a full login → decrypt → lock cycle
