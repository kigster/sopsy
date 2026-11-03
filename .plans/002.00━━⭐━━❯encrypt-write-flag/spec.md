---
created: 2026-10-30
starts: building
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
   
# Research

## Current state                                                                                           

 - `sopsy encrypt`/`decrypt` and `sopsy secrets encrypt`/`decrypt` share `SecretsEncryptArgs`/`SecretsDecryptArgs` (`src/cli.rs`) an `commands::secrets`.
 - Output goes to stdout by default, or to `-o <path>` (encrypt requires the path to end in `.encrypted`). 
 - `with_encrypted_suffix(&file)` already builds `<file>.encrypted`.
 