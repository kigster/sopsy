//! Helpers for Secure Enclave-backed age identities via `age-plugin-se`.
//!
//! On macOS with Apple Silicon, `age-plugin-se` generates an age identity whose
//! private key is bound to the Secure Enclave and never leaves the device.
//! sopsy shells out to this binary.
//!
//! > [!IMPORTANT]
//! > Real identity generation requires Apple hardware with a Secure Enclave, so
//! > these paths cannot run in CI. Tests exercise them against a **faked**
//! > `age-plugin-se` binary; production use requires the real plugin on macOS.
//!
//! Functions here are **stubs** for now; signatures and contracts are fixed for
//! the implementation phase.

use crate::error::Result;

/// The name of the external binary this module drives.
pub const PLUGIN_BIN: &str = "age-plugin-se";

/// A freshly generated Secure Enclave identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveIdentity {
    /// The age recipient (public key), e.g. `age1se1...`.
    pub public_key: String,
    /// The identity stanza to store (references the Secure Enclave key).
    pub identity: String,
}

/// Verify the `age-plugin-se` binary is available on `PATH`.
///
/// TODO: also confirm the host is macOS / Apple Silicon with a Secure Enclave.
pub fn ensure_available() -> Result<()> {
    let _ = which::which(PLUGIN_BIN);
    todo!("verify age-plugin-se is installed and the platform supports it")
}

/// Generate a new Secure Enclave-backed identity, returning its public key and
/// identity stanza.
///
/// TODO: run `age-plugin-se keygen --access-control=any-biometry-or-passcode`,
/// parse stdout, and persist the identity to the sops age key store.
pub fn generate_identity() -> Result<EnclaveIdentity> {
    todo!("generate a Secure Enclave identity via age-plugin-se")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enclave_identity_is_constructible() {
        let id = EnclaveIdentity {
            public_key: "age1se1qexample".into(),
            identity: "AGE-PLUGIN-SE-1...".into(),
        };
        assert!(id.public_key.starts_with("age1se1"));
    }
}
