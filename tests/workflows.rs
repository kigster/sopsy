//! Contract tests for the checked-in GitHub Actions workflows.
//!
//! A workflow whose `push` filter names a branch the repository does not have
//! never runs on a direct push, and nothing else notices. These tests read the
//! YAML and pin the triggers we rely on.

use serde_yaml_ng::Value;
use std::path::Path;

/// Parse `.github/workflows/<name>` from the repository root.
fn workflow(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github/workflows")
        .join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    serde_yaml_ng::from_str(&raw)
        .unwrap_or_else(|err| panic!("cannot parse {}: {err}", path.display()))
}

/// The branch names in a workflow's `on.push.branches` filter.
fn push_branches(workflow: &Value) -> Vec<String> {
    workflow["on"]["push"]["branches"]
        .as_sequence()
        .expect("`on.push.branches` should be a list")
        .iter()
        .map(|branch| {
            branch
                .as_str()
                .expect("branch names are strings")
                .to_string()
        })
        .collect()
}

#[test]
fn secret_scan_runs_on_pushes_to_the_default_branch() {
    let branches = push_branches(&workflow("secret-scan.yml"));
    assert!(
        branches.iter().any(|b| b == "main"),
        "secret-scan must run on pushes to `main`, got {branches:?}"
    );
}

#[test]
fn secret_scan_and_ci_agree_on_the_push_branches() {
    // CI defines which branch is the default; the secret gate must cover it.
    assert_eq!(
        push_branches(&workflow("secret-scan.yml")),
        push_branches(&workflow("ci.yml")),
    );
}

#[test]
fn secret_scan_keeps_its_pull_request_and_manual_triggers() {
    let on = &workflow("secret-scan.yml")["on"];
    assert!(
        on.get("pull_request").is_some(),
        "secret-scan must still run on pull requests"
    );
    assert!(
        on.get("workflow_dispatch").is_some(),
        "secret-scan must still be runnable by hand"
    );
}
