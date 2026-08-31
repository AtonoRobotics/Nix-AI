//! Typed runtime coordination policy. Transport and wire compatibility are adapters.

use std::fmt;

macro_rules! identifier {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CoordinationError> {
                let value = value.into();
                if !value.starts_with($prefix)
                    || value.len() <= $prefix.len()
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_:/ .".contains(&byte))
                {
                    return Err(CoordinationError::InvalidIdentifier(value));
                }
                Ok(Self(value))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier!(ObjectiveId, "objective:");
identifier!(GenerationId, "generation:");
identifier!(ContextId, "context:");
identifier!(PackageId, "package:");
identifier!(EffectId, "effect:sha256:");
identifier!(IdempotencyKey, "");
identifier!(EvidenceId, "evidence:");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectiveState {
    Claimed,
    Preparing,
    Executing,
    Verifying,
    Satisfied,
    Compensated,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectState {
    Authorized,
    Dispatched,
    Committed,
    Failed,
    Compensated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Effect {
    id: EffectId,
    idempotency_key: IdempotencyKey,
    pub state: EffectState,
}

impl Effect {
    pub fn new(
        id: &str,
        idempotency_key: &str,
        state: EffectState,
    ) -> Result<Self, CoordinationError> {
        Ok(Self {
            id: EffectId::new(id)?,
            idempotency_key: IdempotencyKey::new(idempotency_key)?,
            state,
        })
    }
    pub fn committed(id: &str, idempotency_key: &str) -> Result<Self, CoordinationError> {
        Self::new(id, idempotency_key, EffectState::Committed)
    }
    pub fn id(&self) -> &EffectId {
        &self.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectiveSnapshot {
    pub id: ObjectiveId,
    pub state: ObjectiveState,
    pub generation: GenerationId,
    pub context: Option<ContextId>,
    pub package: Option<PackageId>,
    pub effects: Vec<Effect>,
    pub completion_evidence: Option<EvidenceId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateReadiness {
    Recovering,
    Operational,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeReadiness {
    Recovering,
    Operational,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Resume {
        objective_id: ObjectiveId,
        generation: GenerationId,
    },
    PrepareContext {
        objective_id: ObjectiveId,
    },
    RequestCognition {
        objective_id: ObjectiveId,
        context_id: ContextId,
    },
    AuthorizeEffect {
        objective_id: ObjectiveId,
        effect_id: EffectId,
    },
    DispatchEffect {
        objective_id: ObjectiveId,
        effect_id: EffectId,
        idempotency_key: IdempotencyKey,
    },
    ObserveEffect {
        objective_id: ObjectiveId,
        effect_id: EffectId,
    },
    ActivatePackage {
        objective_id: ObjectiveId,
        package_id: PackageId,
    },
    RecordEvidence {
        objective_id: ObjectiveId,
        evidence_id: EvidenceId,
    },
    Complete {
        objective_id: ObjectiveId,
        evidence_id: EvidenceId,
    },
    CompensateEffect {
        objective_id: ObjectiveId,
        original_effect_id: EffectId,
        idempotency_key: IdempotencyKey,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub readiness: RuntimeReadiness,
    pub commands: Vec<Command>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinationError {
    InvalidIdentifier(String),
    StateUnavailable,
    DuplicateEffect(EffectId),
    EffectNotCommitted(EffectId),
    TerminalObjective,
}

pub struct Coordinator;

impl Coordinator {
    pub fn new() -> Self {
        Self
    }

    pub fn cold_boot(
        &self,
        readiness: StateReadiness,
        objectives: &[ObjectiveSnapshot],
    ) -> Result<Decision, CoordinationError> {
        if readiness == StateReadiness::Unavailable {
            return Err(CoordinationError::StateUnavailable);
        }
        let commands = objectives
            .iter()
            .filter(|objective| {
                !matches!(
                    objective.state,
                    ObjectiveState::Satisfied
                        | ObjectiveState::Compensated
                        | ObjectiveState::Failed
                )
            })
            .map(|objective| Command::Resume {
                objective_id: objective.id.clone(),
                generation: objective.generation.clone(),
            })
            .collect();
        Ok(Decision {
            readiness: if readiness == StateReadiness::Operational {
                RuntimeReadiness::Operational
            } else {
                RuntimeReadiness::Recovering
            },
            commands,
        })
    }

    pub fn resume(&self, objective: &ObjectiveSnapshot) -> Result<Decision, CoordinationError> {
        if matches!(
            objective.state,
            ObjectiveState::Satisfied | ObjectiveState::Compensated | ObjectiveState::Failed
        ) {
            return Err(CoordinationError::TerminalObjective);
        }
        let mut ids = objective
            .effects
            .iter()
            .map(|effect| effect.id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(CoordinationError::DuplicateEffect(pair[0].clone()));
        }
        let commands = if objective.effects.is_empty() {
            vec![Command::Resume {
                objective_id: objective.id.clone(),
                generation: objective.generation.clone(),
            }]
        } else {
            objective
                .effects
                .iter()
                .map(|effect| match effect.state {
                    EffectState::Authorized => Command::DispatchEffect {
                        objective_id: objective.id.clone(),
                        effect_id: effect.id.clone(),
                        idempotency_key: effect.idempotency_key.clone(),
                    },
                    EffectState::Dispatched | EffectState::Committed => Command::ObserveEffect {
                        objective_id: objective.id.clone(),
                        effect_id: effect.id.clone(),
                    },
                    EffectState::Failed | EffectState::Compensated => Command::RecordEvidence {
                        objective_id: objective.id.clone(),
                        evidence_id: EvidenceId::new(format!("evidence:{}", effect.id))
                            .expect("typed effect"),
                    },
                })
                .collect()
        };
        Ok(Decision {
            readiness: RuntimeReadiness::Operational,
            commands,
        })
    }

    pub fn compensate(
        &self,
        objective: &ObjectiveSnapshot,
        effect_id: &EffectId,
    ) -> Result<Decision, CoordinationError> {
        let effect = objective
            .effects
            .iter()
            .find(|effect| &effect.id == effect_id && effect.state == EffectState::Committed)
            .ok_or_else(|| CoordinationError::EffectNotCommitted(effect_id.clone()))?;
        Ok(Decision {
            readiness: RuntimeReadiness::Operational,
            commands: vec![Command::CompensateEffect {
                objective_id: objective.id.clone(),
                original_effect_id: effect.id.clone(),
                idempotency_key: IdempotencyKey::new(format!("compensation:{}", effect.id))?,
            }],
        })
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}
