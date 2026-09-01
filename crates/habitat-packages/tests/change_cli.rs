use std::process::Command;

#[test]
fn explicit_description_is_read_only_and_versioned() {
    let output = Command::new(env!("CARGO_BIN_EXE_habitat-packages"))
        .arg("--describe")
        .output()
        .unwrap();
    assert!(output.status.success());
    let declaration: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(declaration["schema_version"], "2.1");
    assert_eq!(declaration["component"], "packages");
    assert_eq!(declaration["abi"], "2.1");
    assert_eq!(declaration["mode"], "peer-authenticated-service");
}

#[test]
fn obsolete_in_process_governed_change_cli_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_habitat-packages"))
        .args([
            "qualify-change",
            "/definitely/absent/state.sock",
            "sha256:source",
            "sha256:closure",
            "sha256:tests",
            "evidence:qualification",
            "evaluator:protected",
            "sha256:evaluator-closure",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
}

#[test]
fn package_service_cannot_bypass_governed_change_roles() {
    let package_source = include_str!("../src/main.rs");
    assert!(!package_source.contains("fn qualify_change"));
    assert!(!package_source.contains("change_propose"));
    assert!(!package_source.contains("change_transition"));
}
