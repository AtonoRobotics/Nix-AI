use habitat_runtime::coordinator::*;

fn objective(state: ObjectiveState, effects: Vec<Effect>) -> ObjectiveSnapshot {
    ObjectiveSnapshot {
        id: ObjectiveId::new("objective:one").unwrap(),
        state,
        generation: GenerationId::new("generation:7").unwrap(),
        context: Some(ContextId::new("context:one").unwrap()),
        package: Some(PackageId::new("package:one").unwrap()),
        effects,
        completion_evidence: None,
    }
}

#[test]
fn cold_boot_resumes_each_nonterminal_objective_and_fails_readiness_closed() {
    let coordinator = Coordinator::new();
    let snapshots = vec![
        objective(ObjectiveState::Claimed, vec![]),
        objective(ObjectiveState::Preparing, vec![]),
    ];
    let plan = coordinator
        .cold_boot(StateReadiness::Recovering, &snapshots)
        .unwrap();
    assert_eq!(plan.readiness, RuntimeReadiness::Recovering);
    assert_eq!(plan.commands.len(), 2);
    assert!(plan
        .commands
        .iter()
        .all(|command| matches!(command, Command::Resume { .. })));
    assert!(coordinator
        .cold_boot(StateReadiness::Unavailable, &snapshots)
        .is_err());
}

#[test]
fn committed_effect_is_not_dispatched_twice_after_interruption_or_lost_wake() {
    let effect = Effect::committed("effect:sha256:one", "idempotency:one").unwrap();
    let decision = Coordinator::new()
        .resume(&objective(ObjectiveState::Executing, vec![effect.clone()]))
        .unwrap();
    assert!(!decision
        .commands
        .iter()
        .any(|command| matches!(command, Command::DispatchEffect { .. })));
    assert!(decision.commands.iter().any(
        |command| matches!(command, Command::ObserveEffect { effect_id, .. }
        if effect_id == effect.id())
    ));
}

#[test]
fn compensation_selects_exact_committed_effect_and_rejects_nonmember() {
    let first = Effect::committed("effect:sha256:first", "idempotency:first").unwrap();
    let second = Effect::committed("effect:sha256:second", "idempotency:second").unwrap();
    let snapshot = objective(ObjectiveState::Executing, vec![first.clone(), second]);
    let decision = Coordinator::new()
        .compensate(&snapshot, first.id())
        .unwrap();
    assert_eq!(
        decision.commands,
        vec![Command::CompensateEffect {
            objective_id: snapshot.id.clone(),
            original_effect_id: first.id().clone(),
            idempotency_key: IdempotencyKey::new("compensation:effect:sha256:first").unwrap(),
        }]
    );
    assert!(Coordinator::new()
        .compensate(&snapshot, &EffectId::new("effect:sha256:absent").unwrap())
        .is_err());
}

#[test]
fn compensated_objective_is_terminal_and_never_completed_or_redispatched() {
    let snapshot = objective(
        ObjectiveState::Compensated,
        vec![Effect::committed("effect:sha256:reversed", "idempotency:reversed").unwrap()],
    );
    assert_eq!(
        Coordinator::new().resume(&snapshot),
        Err(CoordinationError::TerminalObjective)
    );
}
