use std::process::Command;

#[test]
fn governed_change_cli_fails_closed_without_deployed_state_repository() {
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
fn governed_change_cli_has_no_process_local_success_mode() {
    let source = include_str!("../src/main.rs");
    assert!(!source.contains("ChangeJournal::new"));
    assert!(source.contains("change_propose"));
    assert!(source.contains("change_transition"));
    assert!(source.contains("change_get"));
}
