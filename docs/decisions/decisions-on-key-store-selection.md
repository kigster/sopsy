# Decisions on key store selection and `init`

Decided 2026-11-03, PR #25.

## `--allow-stores` replaces `--require`

- The list is an allow-list: a member's key must live in **any one** of the listed stores. `--require` read as "all of these", so it was renamed to `-A, --allow-stores`.
- `-a` stays with `--always-new-slot`; `-A` was free.
- No alias for `--require`: a clean break.
- `.sopsy.yml` writes `key_policy.allowed`. The legacy `key_policy.required` key is still read, so existing repositories keep working.

## The allow list is also the default priority

`--store auto` resolves its order, first match wins:

1. `--store <STORE>` on the command line (still checked against the allow list).
2. `SOPSY_PRIVATE_KEY_STORE_PRIORITY`, a per-developer override. It is filtered by the allow list, so it can reorder or narrow it, never widen it.
3. The repository's `key_policy.allowed`, in the order given to `init` **within each tier**: hardware stores always come before software, software before plaintext. Added after the security review: a committed list must not steer members onto a weaker store while a stronger one is allowed.
4. Without a restriction: `enclave, yubikey, keychain, file`.

Stores the machine cannot support (no Enclave on Linux or Intel Macs, no YubiKey plugged in) are skipped at run time; the committed list is never rewritten per machine.

Rejected: a special rule that a plugged-in YubiKey always wins. It would silently override the order the admin chose; listing `yubikey` first expresses the same intent explicitly.

## `init` flag help

- `--store` on `init` applies to the admin only; members choose theirs with `sopsy join --store`.
- `init --help` groups flags into Repository options (affect everyone), Personal options (affect only you), YubiKey options, Options and Global options, and ends with Examples.
- CI never runs `init`: runners have no Enclave or YubiKey. CI gets a portable key from `sopsy recipient ci`.

## `init` installs supporting tools

- `init` runs the `sopsy deps` install step first. Interactive runs ask; `-y` installs without asking; without Homebrew it warns and carries on. `--skip-deps` turns the step off (added after review, for shared or managed machines).
- `sopsy deps` installs the full set, including `age-plugin-yubikey` and `ykman`, on every platform (`age-plugin-se` on Apple Silicon only).

## Emergency (break-glass) key

- `-e, --generate-emergency-keys` is removed.
- Interactive `init` always creates the break-glass key; `--no-emergency-keys` opts out.
- Unattended `init` (`-y`) skips it, since nobody is there to store it offline. `sopsy recipient break-glass` creates it at any time, and `sopsy check` flags a repository without one.

## Policy edits

`.sopsy.yml` can be edited by hand. The `.sopsy.sha` checksum then fails, every command refuses to run, and `sopsy doctor` accepts the edit. This is tamper evidence, not protection; code review of `.sopsy.yml` is the real gate.

## Waiting for a YubiKey

- Interactive runs ask the user to insert a missing YubiKey and check again, rather than failing: before generating a key with `--store yubikey`, and before decrypt, edit and re-keying when every active key the user (`$USER`) has in the repository lives on a YubiKey.
- `encrypt` never asks, since it needs only public keys. Unattended runs and `SOPS_AGE_KEY` skip the prompt.

## Rotating keys and plugin pass-through

- `sopsy recipient rotate [NAME]` replaces a member's key under the same name and re-keys the secrets. It is how you switch between keys on one YubiKey (or change a PIN or touch policy, which is fixed per key): the repository's recipient decides which key decrypts. Only your own key (`username` = `$USER`), never the break-glass key.
- `recipient keygen` saves hardware identity handles to `keys.txt`, like `init` and `join`.
- `--yubikey-slot` is visible now, for scripts that pick a key.
- `sopsy yubikey …` and `sopsy enclave …` pass their arguments unchanged to `age-plugin-yubikey` and `age-plugin-se`. sopsy is the UX for every tool it wraps.
