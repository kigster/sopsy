require 'etc'

brew 'sops'
brew 'age'

if Etc.uname[:sysname] == 'Darwin' && Etc.uname[:x86_64]
  brew 'age-plugin-se'
else
  brew 'age-plugin-yubikey'
end

brew 'gitleaks'
brew 'detect-secrets'
