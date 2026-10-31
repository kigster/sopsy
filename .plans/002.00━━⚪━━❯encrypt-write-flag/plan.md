## Design

### Flags (on both arg structs, so `secrets encrypt|decrypt` get them too)

- `-w / --write`, conflicts with `-o`.
- `--overwrite / -O`, which requires `--write` (see Q1). It replaces an existing target without asking. 
- During decryption, with either `--overwrite / -O` or with `--yes | -y` should the destination file already exist, before we overwrite it we create a backup, with the name `FILE.YYYY-MM-DD.HHMMSS.backup` assuming that `FILE` was the decrypted name. When encrypting files, overwriting the encrypted file happens without creating a backup, the file is simply overwritten if one of `--overwrite / -O` or `-y / --yes` is passed. Otherwise, initeractive mode question.

### Target path

- encrypt: `with_encrypted_suffix(&file)`. Input already ending in `.encrypted` is an error (no `x.encrypted.encrypted`).
- decrypt: `file` with the trailing `.encrypted` stripped (new helper `without_encrypted_suffix`). Input not ending in `.encrypted` is an error ("can't derive a plaintext name; use `-o`").

### Existing target

| Situation | Behaviour |
| --- | --- |
| Target absent | Write it |
| Target exists + `--overwrite / -O`  | Overwrite. When decrypting, automatically create the backup of the previous file, named `FILE.YYYY-MM-DD.HHMMSS.bak` | 
| Target exists + interactive TTY | `ui.confirm("<target> exists. Overwrite?")`, default **No**; on No, create backup, on yes, overwrite without a backup |
| Target exists + no TTY, no `--overwrite / -O` | Error: "`<target>` exists; pass `--overwrite`". Never overwrites silently |

### Writing

- Decrypt the full payload into memory before touching the target, so a failed decrypt never truncates an existing `.env`.
- Write to a temp file in the same directory, then rename it into place (atomic). The plaintext file gets mode `0600`. An executable script (check the first line for `#!`) gets `0700`.

### Plaintext guard (decrypt only)

When the target is inside a git repo and `git check-ignore <target>` says it is **not** ignored, print a warning ("`.env` is not git-ignored; it may get committed"). Writing still goes ahead. This uses the same `git/` helpers `check` already relies on.

## Tests

- [ ] encrypt `-w` round trips for dotenv, YAML and JSON. decrypt `-w` restores the original bytes.
- [ ] The `secrets encrypt|decrypt` forms behave identically.
- [ ] `-w` with `-o` is a clap error. `--overwrite | -O` without `-w` is a clap error.
- [ ] Wrong suffix is a validation error in both directions.
- [ ] Existing target: `--overwrite` overwrites; `SOPSY_ASSUME_YES=1` overwrites; no TTY and no flag errors and leaves the file untouched; a prompt answered No leaves it untouched.
- [ ] A failed decrypt leaves an existing target byte-for-byte unchanged.
- [ ] Both decrypted and encrypted files that are the result of a sopsy operation have permissions of `0600`; or `0700` for an executable script. 
- [ ] CLI parse tests and `completion` output include the new flags.

## Open questions

1. **Scope of `--overwrite`:** should it also apply to `-o`, which today overwrites silently? 

Answer: yes, make `-o ALTERNATIVE-OUTPUT-FILE` follow the same prompt/flag rules. It's a small behaviour change, mentioned in the changelog.
