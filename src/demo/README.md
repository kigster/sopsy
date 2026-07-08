# sopsy demos (VHS tapes)

Terminal recordings authored as code with [VHS](https://github.com/charmbracelet/vhs). Each `.txt` is a VHS "tape" you render into an animated GIF.

## Render

```bash
brew install vhs            # once
vhs src/demo/vhs.txt        # -> sopsy-demo.gif   (full team flow)
vhs src/demo/vhs-quick.txt  # -> sopsy-quick.gif  (20s README hero)
```

Requires `sopsy`, `git`, `sops`, `age-plugin-se`, and `bat` on `PATH` (the tapes declare these with `Require`, so VHS fails fast if one is missing).

## The tapes

| Tape            | Shows                                                                                                     | Length |
| --------------- | --------------------------------------------------------------------------------------------------------- | ------ |
| `vhs-quick.txt` | init → add a secret → encrypt → `check` → commit                                                          | ~20s   |
| `vhs.txt`       | the full team flow: init, two `join`s, `approve`, encrypt, decrypt as a teammate, and `edit` in `$EDITOR` | ~50s   |

## How the multi-user demo works (and why it's hands-free)

A real team is one macOS account per developer, each with its own Secure Enclave keystore. The full tape **emulates several developers inside one account** by giving each a separate keystore file and switching `SOPSY_KEYS_FILE` to "become" that person:

```bash
export SOPSY_KEYS_FILE=$KALAN   # now acting as Alan
sopsy join "Alan Turing" --without-touch-id
```

Two deliberate choices keep the recording free of Touch ID system dialogs (which can't be captured or automated):

- **`--without-touch-id`** on `join` mints the Enclave key with no biometric gate (`age-plugin-se --access-control none`). The private key still never leaves the Enclave — it just doesn't prompt. Drop the flag for real biometric security.
- **`approve --no-updatekeys`** adds a teammate without re-keying existing files. The `init` admin key *is* Touch-ID-gated (there's no `--without-touch-id` on `init`), so re-keying during approve would prompt. Instead the real secret is encrypted *after* everyone is a recipient — written for the whole team at once.

Everything runs in throwaway `mktemp -d` workspaces with throwaway keystores, so recording a demo never touches your real repo or your real `~/.../sops/age/keys.txt`.

## Tweaking

- Faster/slower typing: `Set TypingSpeed 22ms`.
- Different look: `Set Theme "..."` (see `vhs themes`), `Set FontSize`, `Set Width/Height`.
- The `edit` step drives `vim` (`EDITOR=vim`); adjust the keystrokes if you use a different editor.
