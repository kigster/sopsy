require 'etc'

brew 'sops'
brew 'age'

# Secure Enclave on Apple Silicon; YubiKey works on every platform.
brew 'age-plugin-se' if Etc.uname[:sysname] == 'Darwin' && Etc.uname[:machine] == 'arm64'
brew 'age-plugin-yubikey'
# ykman sets a YubiKey PUK separate from the PIN (`sopsy init` offers it).
brew 'ykman'

brew 'gitleaks'
brew 'detect-secrets'
