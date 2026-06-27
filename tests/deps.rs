//! Integration tests for `sopsy deps`.
//!
//! Each test runs the real binary with `PATH` pointed at a temp directory
//! holding exactly the fake tool/`brew` executables we want, so the dependency
//! probe is deterministic regardless of what is installed on the host.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;

/// Write an executable script into `dir`.
fn write_exe(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A no-op tool that simply exists on `PATH`.
fn present(dir: &Path, name: &str) {
    write_exe(dir, name, "#!/bin/sh\nexit 0\n");
}

/// `sopsy` with a clean `SOPSY_BREW_BIN` so only the test's `PATH` decides.
fn sopsy() -> Command {
    let mut cmd = Command::cargo_bin("sopsy").unwrap();
    cmd.env_remove("SOPSY_BREW_BIN");
    cmd
}

#[test]
fn reports_nothing_to_do_when_all_present() {
    let bin = TempDir::new().unwrap();
    for tool in ["sops", "age", "age-plugin-se"] {
        present(bin.path(), tool);
    }
    sopsy()
        .args(["deps", "-y"])
        .env("PATH", bin.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("already installed"));
}

#[test]
fn installs_only_missing_tools_via_brew() {
    let bin = TempDir::new().unwrap();
    present(bin.path(), "sops");
    present(bin.path(), "age");
    // age-plugin-se intentionally absent.
    let log = bin.path().join("brew.log");
    write_exe(
        bin.path(),
        "brew",
        &format!("#!/bin/sh\necho \"$@\" >> {log:?}\nexit 0\n"),
    );

    sopsy()
        .args(["deps", "-y"])
        .env("PATH", bin.path())
        .assert()
        .success();

    let recorded = fs::read_to_string(&log).unwrap();
    assert!(
        recorded.contains("install age-plugin-se"),
        "brew should install the missing tool; got: {recorded}"
    );
    assert!(
        !recorded.contains("sops"),
        "tools already present must not be reinstalled; got: {recorded}"
    );
}

#[test]
fn installs_all_dependencies_when_none_present() {
    let bin = TempDir::new().unwrap();
    // None of the tools are present; only a recording `brew`.
    let log = bin.path().join("brew.log");
    write_exe(
        bin.path(),
        "brew",
        &format!("#!/bin/sh\necho \"$@\" >> {log:?}\nexit 0\n"),
    );

    sopsy()
        .args(["deps", "-y"])
        .env("PATH", bin.path())
        .assert()
        .success();

    let recorded = fs::read_to_string(&log).unwrap();
    assert!(
        recorded.contains("install sops age age-plugin-se"),
        "all three missing tools should install in one brew call; got: {recorded}"
    );
}

#[test]
fn honors_brew_bin_override() {
    let bin = TempDir::new().unwrap();
    present(bin.path(), "sops");
    present(bin.path(), "age");
    // age-plugin-se missing; `brew` is NOT on PATH — only via SOPSY_BREW_BIN.
    let brew_dir = TempDir::new().unwrap();
    let log = brew_dir.path().join("brew.log");
    write_exe(
        brew_dir.path(),
        "fake-brew",
        &format!("#!/bin/sh\necho \"$@\" >> {log:?}\nexit 0\n"),
    );

    Command::cargo_bin("sopsy")
        .unwrap()
        .args(["deps", "-y"])
        .env("PATH", bin.path())
        .env("SOPSY_BREW_BIN", brew_dir.path().join("fake-brew"))
        .assert()
        .success();

    let recorded = fs::read_to_string(&log).unwrap();
    assert!(
        recorded.contains("install age-plugin-se"),
        "the SOPSY_BREW_BIN override should be invoked; got: {recorded}"
    );
}

#[test]
fn dry_run_prints_command_without_running_brew() {
    let bin = TempDir::new().unwrap();
    present(bin.path(), "sops");
    present(bin.path(), "age");
    let log = bin.path().join("brew.log");
    write_exe(
        bin.path(),
        "brew",
        &format!("#!/bin/sh\necho ran >> {log:?}\nexit 0\n"),
    );

    sopsy()
        .args(["deps", "--dry-run", "-y"])
        .env("PATH", bin.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("brew install age-plugin-se"));

    assert!(!log.exists(), "brew must not run in --dry-run mode");
}

#[test]
fn surfaces_brew_failure() {
    let bin = TempDir::new().unwrap();
    present(bin.path(), "sops");
    present(bin.path(), "age");
    // age-plugin-se missing; brew exists but fails.
    write_exe(bin.path(), "brew", "#!/bin/sh\necho 'boom' >&2\nexit 1\n");
    sopsy()
        .args(["deps", "-y"])
        .env("PATH", bin.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("brew").and(predicate::str::contains("failed")));
}

#[test]
fn check_exits_nonzero_when_a_tool_is_missing() {
    let bin = TempDir::new().unwrap();
    present(bin.path(), "sops");
    // age + age-plugin-se missing.
    sopsy()
        .args(["deps", "--check"])
        .env("PATH", bin.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("age is not installed"));
}

#[test]
fn check_exits_zero_when_all_present() {
    let bin = TempDir::new().unwrap();
    for tool in ["sops", "age", "age-plugin-se"] {
        present(bin.path(), tool);
    }
    sopsy()
        .args(["deps", "--check"])
        .env("PATH", bin.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("all dependencies are installed"));
}

#[test]
fn errors_with_guidance_when_brew_missing() {
    let bin = TempDir::new().unwrap();
    present(bin.path(), "sops");
    present(bin.path(), "age");
    // age-plugin-se missing AND no `brew` on PATH.
    sopsy()
        .args(["deps", "-y"])
        .env("PATH", bin.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("brew.sh"));
}
