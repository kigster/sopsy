require 'etc'

brew 'sops'
brew 'age'

# Secure Enclave on Apple Silicon; YubiKey works on every platform.
brew 'age-plugin-se' if Etc.uname[:sysname] == 'Darwin' && Etc.uname[:machine] == 'arm64'
brew 'age-plugin-yubikey'

brew 'gitleaks'
brew 'detect-secrets'
