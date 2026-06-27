//! Integration tests for [`sopsy::enclave`].
//!
//! Real Secure Enclave identity generation requires Apple hardware and user
//! interaction, so these drive a **fake** `age-plugin-se` shell script injected
//! via the `SOPSY_AGE_PLUGIN_SE_BIN` environment variable. That env var is
//! process-wide, so the tests are `#[serial]`.

use std::path::Path;

use assert_fs::TempDir;
use serial_test::serial;
use sopsy::enclave;

/// Write an executable fake `age-plugin-se` to `dir` that emits `body` (verbatim
/// shell after the shebang) and return its path.
fn write_fake_plugin(dir: &Path, body: &str) -> std::path::PathBuf {
    let script = dir.join("age-plugin-se");
    std::fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    script
}

#[test]
#[serial]
fn generate_identity_parses_fake_keygen_output() {
    let dir = TempDir::new().unwrap();
    // Mimics the real `age-plugin-se keygen` identity file printed to stdout,
    // with the `Public key:` summary on stderr.
    let body = r#"
cat <<'EOF'
# created: 2026-06-27T00:00:00Z
# access control: any biometry or passcode
# public key: age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258
AGE-PLUGIN-SE-1QFAKEIDENTITYDATA
EOF
echo "Public key: age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258" 1>&2
"#;
    let script = write_fake_plugin(dir.path(), body);

    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(enclave::PLUGIN_BIN_ENV, &script);
    }

    enclave::ensure_available().unwrap();
    let id = enclave::generate_identity(Some("any-biometry-or-passcode")).unwrap();

    assert_eq!(
        id.public_key,
        "age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258"
    );
    assert_eq!(id.identity, "AGE-PLUGIN-SE-1QFAKEIDENTITYDATA");

    // SAFETY: see above.
    unsafe {
        std::env::remove_var(enclave::PLUGIN_BIN_ENV);
    }
}

#[test]
#[serial]
fn generate_identity_surfaces_nonzero_exit() {
    let dir = TempDir::new().unwrap();
    let script = write_fake_plugin(dir.path(), "echo 'boom' 1>&2\nexit 3\n");

    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(enclave::PLUGIN_BIN_ENV, &script);
    }

    let err = enclave::generate_identity(None).unwrap_err();
    match err {
        sopsy::error::Error::ProcessFailed { code, message, .. } => {
            assert_eq!(code, 3);
            assert!(message.contains("boom"));
        }
        other => panic!("expected ProcessFailed, got {other:?}"),
    }

    // SAFETY: see above.
    unsafe {
        std::env::remove_var(enclave::PLUGIN_BIN_ENV);
    }
}

#[test]
#[serial]
fn ensure_available_errors_when_missing() {
    // SAFETY: serialized via `#[serial]`.
    unsafe {
        std::env::set_var(enclave::PLUGIN_BIN_ENV, "/nonexistent/age-plugin-se-xyz");
    }
    let err = enclave::ensure_available().unwrap_err();
    assert!(matches!(err, sopsy::error::Error::ToolNotFound(_)));
    // SAFETY: see above.
    unsafe {
        std::env::remove_var(enclave::PLUGIN_BIN_ENV);
    }
}
