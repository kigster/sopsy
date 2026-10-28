# 002 — `encrypt -w` / `decrypt -w`

Status: **spec — independent of 001; can ship first**

## Request

- `sopsy encrypt <file> -w|--write` encrypts into `<file>.encrypted` (`.env` → `.env.encrypted`).
- `sopsy decrypt <file>.encrypted -w|--write` decrypts into `<file>` (`.env.encrypted` → `.env`).
- If the target already exists, sopsy asks interactively, unless `--overwrite` is passed.

## Current state

- `sopsy encrypt`/`decrypt` and `sopsy secrets encrypt`/`decrypt` share `SecretsEncryptArgs`/`SecretsDecryptArgs` (`src/cli.rs`) and `commands::secrets`.
- Output goes to stdout by default, or to `-o <path>` (encrypt requires the path to end in `.encrypted`).
- `with_encrypted_suffix(&file)` already builds `<file>.encrypted`.

## Design

### Flags (on both arg structs, so `secrets encrypt|decrypt` get them too)

- `-w, --write`, conflicts with `-o`.
- `--overwrite`, which requires `--write` (see Q1). It replaces an existing target without asking.

### Target path

- encrypt: `with_encrypted_suffix(&file)`. Input already ending in `.encrypted` is an error (no `x.encrypted.encrypted`).
- decrypt: `file` with the trailing `.encrypted` stripped (new helper `without_encrypted_suffix`). Input not ending in `.encrypted` is an error ("can't derive a plaintext name; use `-o`").

### Existing target

| Situation | Behaviour |
| --- | --- |
| Target absent | Write it |
| Target exists + `--overwrite` | Overwrite |
| Target exists + interactive TTY | `ui.confirm("<target> exists. Overwrite?")`, default **No**; on No, exit non-zero, nothing written |
| Target exists + `SOPSY_ASSUME_YES` | Overwrite (same as every other confirmation in sopsy) |
| Target exists + no TTY, no `--overwrite` | Error: "`<target>` exists; pass `--overwrite`". Never overwrites silently |

### Writing

- Decrypt the full payload into memory before touching the target, so a failed decrypt never truncates an existing `.env`.
- Write to a temp file in the same directory, then rename it into place (atomic). The plaintext file gets mode `0600`.

### Plaintext guard (decrypt only)

When the target is inside a git repo and `git check-ignore <target>` says it is **not** ignored, print a warning ("`.env` is not git-ignored; it may get committed"). Writing still goes ahead. This uses the same `git/` helpers `check` already relies on.

## Tests

- [ ] encrypt `-w` round trips for dotenv, YAML and JSON. decrypt `-w` restores the original bytes.
- [ ] The `secrets encrypt|decrypt` forms behave identically.
- [ ] `-w` with `-o` is a clap error. `--overwrite` without `-w` is a clap error.
- [ ] Wrong suffix is a validation error in both directions.
- [ ] Existing target: `--overwrite` overwrites; `SOPSY_ASSUME_YES` overwrites; no TTY and no flag errors and leaves the file untouched; a prompt answered No leaves it untouched.
- [ ] A failed decrypt leaves an existing target byte-for-byte unchanged.
- [ ] The decrypted file is `0600`; the not-ignored warning fires in a temp git repo.
- [ ] CLI parse tests and `completion` output include the new flags.

## Open questions

1. **Scope of `--overwrite`:** should it also apply to `-o`, which today overwrites silently? Recommendation: yes, make `-o` follow the same prompt/flag rules. It's a small behaviour change, mentioned in the changelog.
