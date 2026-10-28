# Add YubiKey and MacOS Intel Support

This feature adds more diverse hardware support to sopsy:

On a MacOS the choice becomes:

1. Apple Silicon Chips (M1, M2, ...):
   - secure enclave
   - yubikey
   - keychain

2. Apple Intel
   - if it has a secure chip like enclave, try using it (and if so, that's the default)
   - keychain
   - yubikey

3. Linux 
   - yubikey 
   - plain text files
   - is there any other secure way to store private keys?

