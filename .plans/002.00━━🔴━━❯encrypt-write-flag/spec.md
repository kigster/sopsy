---
created: 2026-10-30
starts: planning
---

# Spec for `--write` 

## Feature Description

Today to encrypt or decrypt a file you must pass the file name, and `-o output-file-name`. However, there is a relationship between encrypted file names and non-encrypted:

Typically, encrypting `.env` results in `.env.encrypted`.

Therefore the proposal here is to add a single new flag `-w | --write` to both operations `encrypt` and `decrypt`, which would apply the above convention to both directions:

## Encrypt & Decrypt with `-w`

```bash
sopsy encrypt FILE -w|--write
```

automatically encrypts into `<file>.encrypted` (example: `.env` → `.env.encrypted`)

```bash
sopsy decrypt FILE.encrypted -w|--write
```

automatically decrypts the result into `FILE` (example: `.env.encrypted` → `.env`).          

### What if the destination file already exists?

**Interactive Mode**

If the target already exists, sopsy asks interactively if the user wishes to overwrite the destination file, and if the user chooses NO, then prior to writing the encrypted file creates a backup of the target file, with the extension "`.bak.YYYY-MM-DD.HHMMSS`", unless `--overwrite` is passed.

**Non-Interactive**

If `--yes | -y` was passed, the backup of an existing file is created silently and without confirmation.s
   
## Decisions

### B4 (answered) — Scope of the change

The spec wants the prompt rules applied to `-o` as well, and the plan adds file modes, an atomic write and a git warning. Each is a separate design choice, so one plan carries several changes.

### D4 (decision) — Split the work into three changes

Answered:

- 2026-11-03
- By kig

Split this feature into three changes:

1. `-w` naming and the target-exists rules.
2. File modes (`0600` / `0700`) and atomic writes.
3. The git ignore warning on decrypt.

# Research

## Current state                                                                                           

 - `sopsy encrypt`/`decrypt` and `sopsy secrets encrypt`/`decrypt` share `SecretsEncryptArgs`/`SecretsDecryptArgs` (`src/cli.rs`) an `commands::secrets`.
 - Output goes to stdout by default, or to `-o <path>` (encrypt requires the path to end in `.encrypted`). 
 - `with_encrypted_suffix(&file)` already builds `<file>.encrypted`.
 