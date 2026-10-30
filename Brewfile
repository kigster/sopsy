
brew 'sops'
brew 'age'
# Secure Enclave keys: Apple Silicon only (there is no Intel build).
brew 'age-plugin-se' if Hardware::CPU.arm?
# YubiKey keys, and ykman to set a PUK separate from the PIN.
brew 'age-plugin-yubikey'
brew 'ykman'

brew 'gitleaks'
brew 'detect-secrets'
