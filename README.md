# Sopsy — The Missing Developer Encryptor

## Secrets Management Guide (Engineering Manager)

### Overview

This repository stores shared development secrets in Git in **encrypted form** using:

- SOPS
- age encryption

No plaintext secrets should ever be committed.

Only developers possessing an approved age private key can decrypt repository secrets.

---

## Security Model

Each developer owns an individual key pair.

```
Developer
───────────────
Private Key  → stays on developer laptop
Public Key   → shared with repository maintainers
```

Only public keys are checked into the repository.

The repository contains:

```
.sops.yaml
.env.encrypted
config/*.encrypted.yaml
```

The repository never contains:

```
.env
.env.production
*.pem
*.key
AWS credentials
API keys
```

---

## Initial Setup

Each developer generates their own key pair.

```
age-keygen -o ~/.config/sops/age/keys.txt
```

They send only their public key.

Example:

```
# public key: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## Adding a Developer

1. Obtain the developer's public key.

2. Edit `.sops.yaml`

Example:

```yaml
creation_rules:
  - path_regex: \.encrypted$
    age: >
      age1alice...
      age1bob...
      age1charlie...
```

3. Re-encrypt all secrets.

```
sops updatekeys -r .
```

Commit the result.

---

# Removing a Developer

When someone leaves:

1. Remove their public key from `.sops.yaml`

2. Run

```
sops updatekeys -r .
```

3. Rotate all affected secrets.

Although the former developer can still decrypt previously downloaded files, they will not be able to decrypt future versions.

For sensitive credentials:

- rotate API tokens
- rotate database passwords
- rotate cloud credentials

---

## Rotating Secrets

Whenever a secret changes:

```
sops secrets.env.encrypted
```

Edit the values.

Save.

Commit.

No additional encryption step is required.

---

# Rotating Encryption Keys

If an age private key is lost or compromised:

1. Generate a new keypair.
2. Replace the public key in `.sops.yaml`
3. Run

```
sops updatekeys -r .
```

Commit the changes.

---

## CI/CD

CI should possess its own dedicated age private key.

Never reuse a developer key.

Recommended:

```
GitHub Actions Secret

SOPS_AGE_KEY
```

During CI:

```
export SOPS_AGE_KEY="$SOPS_AGE_KEY"

sops --decrypt .env.encrypted > .env
```

---

## Repository Layout

```
.
├── .sops.yaml
├── .env.example
├── .env.encrypted
├── config/
│   └── production.encrypted.yaml
└── docs/
```

---

# Best Practices

✅ One key pair per developer

✅ Never share private keys

✅ Rotate production credentials periodically

✅ Review encrypted files like normal code

✅ Keep plaintext files in `.gitignore`

---

## Emergency Recovery

Keep one offline backup administrator key in a secure password manager or hardware token.

Without at least one private key, encrypted secrets cannot be recovered.
# Developer Guide

This project stores secrets using **SOPS** and **age**.

You only need to perform the setup once.

---

## 1. Install Tools

macOS

```bash
brew install age sops
```

Ubuntu

```bash
sudo apt install age
```

Then install SOPS from:

https://github.com/getsops/sops/releases

---

## 2. Generate Your Identity

Run

```bash
mkdir -p ~/.config/sops/age

age-keygen \
  -o ~/.config/sops/age/keys.txt
```

Example output

```
Public key: age1xyz...
```

Send **only** the public key to your engineering manager.

Never send:

```
~/.config/sops/age/keys.txt
```

This is your private key.

---

## 3. Verify SOPS Can Find Your Key

Run

```bash
sops --version
```

Then

```bash
sops secrets.env.encrypted
```

If the file opens, setup is complete.

---

## 4. Editing Secrets

Never decrypt files manually.

Instead run

```bash
sops .env.encrypted
```

Your configured editor will open.

Save.

Exit.

SOPS automatically encrypts the updated values.

---

## 5. Export Secrets

If your application expects a plaintext `.env`

```bash
sops --decrypt .env.encrypted > .env
```

Do not commit `.env`.

---

## 6. Configure Git

Ensure

```
.env
.env.local
.env.production
```

are ignored.

---

## 7. Protect Your Private Key

Recommended locations

```
~/.config/sops/age/keys.txt
```

or

```
1Password Secure Notes
```

or

```
YubiKey backup
```

Never commit this file.

Never upload it to Slack.

Never email it.

---

## 8. Backups

Back up your private key.

If it is lost, existing encrypted files cannot be decrypted without another authorized key holder.

---

## 9. Recommended Editor Configuration

Set your preferred editor.

Examples:

VS Code

```bash
export EDITOR="code --wait"
```

Neovim

```bash
export EDITOR=nvim
```

Vim

```bash
export EDITOR=vim
```

---

## 10. Optional: Using Biometrics

The age private key itself does **not** support biometric authentication.

Instead, store the private key inside a password manager that supports biometrics.

Recommended:

- 1Password
- Apple Passwords (where appropriate)
- Bitwarden

This gives:

```
Fingerprint
        ↓
Unlock password manager
        ↓
Retrieve age private key
        ↓
Decrypt repository secrets
```

This protects the key when your workstation is locked.

---

## 11. Biometrics Timeout

Recommended unlock frequency:

| Environment | Recommendation |
|-------------|---------------|
| Personal laptop | Require Face ID / Touch ID every 12 hours |
| Corporate laptop | Every 4 hours |
| High-security environment | Every unlock or every 1 hour |

Avoid "Never require biometric unlock."

---

## 12. Troubleshooting

### Permission denied

Verify

```
~/.config/sops/age/keys.txt
```

exists.

---

### Cannot decrypt

Ensure your public key is listed in

```
.sops.yaml
```

---

### Wrong editor opens

Set

```bash
export EDITOR=nvim
```

(or your preferred editor)

---

### Lost private key

Contact the repository maintainers.

A new key can be added and repository secrets re-encrypted, but previously encrypted files cannot be recovered using your lost key.
