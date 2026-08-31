use habitat_execution::{provider_request_digest, OfflineProvider, ProviderCommand, ProviderError};
use serde_json::json;
use tempfile::tempdir;
fn effect() -> String {
    "effect:sha256:".to_owned() + &"a".repeat(64)
}
fn execute(id: &str, command: &str, key: &str, value: i64) -> ProviderCommand {
    let payload = json!({"value":value});
    ProviderCommand::Execute {
        effect_id: id.into(),
        command_id: command.into(),
        idempotency_key: key.into(),
        request_digest: provider_request_digest("commit", &payload).unwrap(),
        operation: "commit".into(),
        payload,
    }
}
#[test]
fn durable_execute_observe_duplicate_and_conflict() {
    let root = tempdir().unwrap();
    let provider = OfflineProvider::open(root.path()).unwrap();
    let id = effect();
    let command = execute(&id, "command:1", "idempotency:1", 1);
    let ProviderCommand::Execute {
        request_digest: digest,
        ..
    } = &command
    else {
        unreachable!()
    };
    let first = provider.execute(&command, None).unwrap();
    assert_eq!(provider.observe(&id, digest).unwrap(), first);
    assert_eq!(provider.execute(&command, None).unwrap(), first);
    assert!(matches!(
        provider.execute(&execute(&id, "command:2", "idempotency:1", 2), None),
        Err(ProviderError::Conflict)
    ));
    let changed_payload = execute(&id, "command:1", "idempotency:1", 99);
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
    let original_command = execute(&original, "command:1", "idempotency:1", 1);
    let ProviderCommand::Execute {
        request_digest: original_digest,
        ..
    } = &original_command
    else {
        unreachable!()
    };
    provider.execute(&original_command, None).unwrap();
    let compensation = "effect:sha256:".to_owned() + &"e".repeat(64);
    let command = ProviderCommand::Execute {
        effect_id: compensation.clone(),
        command_id: "command:compensate".into(),
        idempotency_key: "idempotency:compensate".into(),
        request_digest: provider_request_digest(
            "compensate",
            &json!({"compensates_effect_id":original}),
        )
        .unwrap(),
        operation: "compensate".into(),
        payload: json!({"compensates_effect_id":original}),
    };
    let applied = provider.execute(&command, None).unwrap();
    assert_eq!(
        provider
            .observe(&compensation, &applied.request_digest)
            .unwrap(),
        applied
    );
    assert!(matches!(
        provider.observe(&effect(), original_digest),
        Err(ProviderError::NotFound)
    ));
}
#[test]
fn crash_boundaries_are_reconciled_without_redispatch() {
    let root = tempdir().unwrap();
    let id = effect();
    let before_command = execute(&id, "command:1", "idempotency:1", 0);
    let ProviderCommand::Execute {
        request_digest: digest,
        ..
    } = &before_command
    else {
        unreachable!()
    };
    let before = OfflineProvider::open(root.path()).unwrap();
    assert!(matches!(
        before.execute(&before_command, Some("before-commit")),
        Err(ProviderError::Storage(_))
    ));
    assert!(matches!(
        before.observe(&id, digest),
        Err(ProviderError::NotFound)
    ));
    let world_id = "effect:sha256:".to_owned() + &"c".repeat(64);
    let world_command = execute(&world_id, "command:world", "idempotency:world", 0);
    let ProviderCommand::Execute {
        request_digest: world_digest,
        ..
    } = &world_command
    else {
        unreachable!()
    };
    assert!(matches!(
        before.execute(&world_command, Some("after-world")),
        Err(ProviderError::Storage(_))
    ));
    assert!(matches!(
        before.observe(&world_id, world_digest),
        Err(ProviderError::NotFound)
    ));
    before.execute(&world_command, None).unwrap();
    assert_eq!(
        before.observe(&world_id, world_digest).unwrap().outcome,
        "SUCCEEDED"
    );
    let id2 = "effect:sha256:".to_owned() + &"d".repeat(64);
    let after = OfflineProvider::open(root.path()).unwrap();
    assert!(matches!(
        after.execute(
            &execute(&id2, "command:2", "idempotency:2", 0),
            Some("after-commit")
        ),
        Err(ProviderError::Storage(_))
    ));
    let ProviderCommand::Execute {
        request_digest: digest2,
        ..
    } = execute(&id2, "command:2", "idempotency:2", 0)
    else {
        unreachable!()
    };
    assert_eq!(after.observe(&id2, &digest2).unwrap().outcome, "SUCCEEDED");
}
