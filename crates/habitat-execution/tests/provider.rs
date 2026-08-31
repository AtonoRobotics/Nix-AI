use habitat_execution::{OfflineProvider, ProviderCommand, ProviderError};
use serde_json::json;
use tempfile::tempdir;
fn effect() -> String {
    "effect:sha256:".to_owned() + &"a".repeat(64)
}
fn execute(id: &str, command: &str, key: &str, digest: &str, value: i64) -> ProviderCommand {
    ProviderCommand::Execute {
        effect_id: id.into(),
        command_id: command.into(),
        idempotency_key: key.into(),
        request_digest: digest.into(),
        operation: "offline.write".into(),
        payload: json!({"value":value}),
    }
}
#[test]
fn durable_execute_observe_duplicate_and_conflict() {
    let root = tempdir().unwrap();
    let provider = OfflineProvider::open(root.path()).unwrap();
    let id = effect();
    let digest = "sha256:".to_owned() + &"b".repeat(64);
    let first = provider
        .execute(
            &execute(&id, "command:1", "idempotency:1", &digest, 1),
            None,
        )
        .unwrap();
    assert_eq!(provider.observe(&id, &digest).unwrap(), first);
    assert_eq!(
        provider
            .execute(
                &execute(&id, "command:1", "idempotency:1", &digest, 1),
                None
            )
            .unwrap(),
        first
    );
    assert!(matches!(
        provider.execute(
            &execute(
                &id,
                "command:2",
                "idempotency:1",
                &("sha256:".to_owned() + &"c".repeat(64)),
                2
            ),
            None
        ),
        Err(ProviderError::Conflict)
    ));
    let changed_payload = ProviderCommand::Execute {
        effect_id: id.clone(),
        command_id: "command:1".into(),
        idempotency_key: "idempotency:1".into(),
        request_digest: digest.clone(),
        operation: "offline.delete".into(),
        payload: json!({"value":99}),
    };
    assert!(matches!(
        provider.execute(&changed_payload, None),
        Err(ProviderError::Conflict)
    ));
}

#[test]
fn compensation_changes_and_independently_observes_external_world_state() {
    let root = tempdir().unwrap();
    let provider = OfflineProvider::open(root.path()).unwrap();
    let original = effect();
    let digest = "sha256:".to_owned() + &"b".repeat(64);
    provider
        .execute(
            &execute(&original, "command:1", "idempotency:1", &digest, 1),
            None,
        )
        .unwrap();
    let compensation = "effect:sha256:".to_owned() + &"e".repeat(64);
    let command = ProviderCommand::Execute {
        effect_id: compensation.clone(),
        command_id: "command:compensate".into(),
        idempotency_key: "idempotency:compensate".into(),
        request_digest: digest.clone(),
        operation: "compensate".into(),
        payload: json!({"compensates_effect_id":original}),
    };
    let applied = provider.execute(&command, None).unwrap();
    assert_eq!(provider.observe(&compensation, &digest).unwrap(), applied);
    assert!(matches!(
        provider.observe(&effect(), &digest),
        Err(ProviderError::NotFound)
    ));
}
#[test]
fn crash_boundaries_are_reconciled_without_redispatch() {
    let root = tempdir().unwrap();
    let id = effect();
    let digest = "sha256:".to_owned() + &"b".repeat(64);
    let before = OfflineProvider::open(root.path()).unwrap();
    assert!(matches!(
        before.execute(
            &execute(&id, "command:1", "idempotency:1", &digest, 0),
            Some("before-commit")
        ),
        Err(ProviderError::Storage(_))
    ));
    assert!(matches!(
        before.observe(&id, &digest),
        Err(ProviderError::NotFound)
    ));
    let id2 = "effect:sha256:".to_owned() + &"d".repeat(64);
    let after = OfflineProvider::open(root.path()).unwrap();
    assert!(matches!(
        after.execute(
            &execute(&id2, "command:2", "idempotency:2", &digest, 0),
            Some("after-commit")
        ),
        Err(ProviderError::Storage(_))
    ));
    assert_eq!(after.observe(&id2, &digest).unwrap().outcome, "SUCCEEDED");
}
