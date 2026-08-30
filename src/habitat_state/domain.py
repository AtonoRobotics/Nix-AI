"""Validated value types forming the public W02 state/evidence ABI."""

from dataclasses import dataclass
from enum import StrEnum
import re
import uuid


IDENTITY = re.compile(r"^[a-z][a-z0-9_-]{0,62}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class EntityKind(StrEnum):
    AGENT = "AGENT"
    OBJECTIVE = "OBJECTIVE"
    ACTIVATION = "ACTIVATION"
    WAKE = "WAKE"


class State(StrEnum):
    REGISTERED = "REGISTERED"
    AVAILABLE = "AVAILABLE"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"
    PROPOSED = "PROPOSED"
    ACTIVE = "ACTIVE"
    WAITING = "WAITING"
    SATISFIED = "SATISFIED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REQUESTED = "REQUESTED"
    LEASED = "LEASED"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    WAITING_CONTEXT = "WAITING_CONTEXT"
    WAITING_EFFECT = "WAITING_EFFECT"
    SLEEPING = "SLEEPING"
    COMPLETED = "COMPLETED"
    PENDING = "PENDING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


INITIAL = {
    EntityKind.AGENT: State.REGISTERED,
    EntityKind.OBJECTIVE: State.PROPOSED,
    EntityKind.ACTIVATION: State.REQUESTED,
    EntityKind.WAKE: State.PENDING,
}
LEGAL = {
    (EntityKind.AGENT, State.REGISTERED): {State.AVAILABLE},
    (EntityKind.AGENT, State.AVAILABLE): {State.SUSPENDED, State.RETIRED},
    (EntityKind.AGENT, State.SUSPENDED): {State.AVAILABLE, State.RETIRED},
    (EntityKind.OBJECTIVE, State.PROPOSED): {State.ACTIVE, State.CANCELLED},
    (EntityKind.OBJECTIVE, State.ACTIVE): {State.WAITING, State.SATISFIED, State.FAILED, State.CANCELLED},
    (EntityKind.OBJECTIVE, State.WAITING): {State.ACTIVE, State.FAILED, State.CANCELLED},
    (EntityKind.ACTIVATION, State.REQUESTED): {State.LEASED, State.CANCELLED},
    (EntityKind.ACTIVATION, State.LEASED): {State.PREPARING, State.FAILED, State.CANCELLED},
    (EntityKind.ACTIVATION, State.PREPARING): {State.RUNNING, State.FAILED, State.CANCELLED},
    (EntityKind.ACTIVATION, State.RUNNING): {State.WAITING_CONTEXT, State.WAITING_EFFECT, State.SLEEPING,
                                             State.COMPLETED, State.FAILED, State.CANCELLED},
    (EntityKind.WAKE, State.PENDING): {State.LEASED},
    (EntityKind.WAKE, State.LEASED): {State.ACKNOWLEDGED, State.RELEASED, State.EXPIRED},
}


@dataclass(frozen=True)
class EntityId:
    kind: EntityKind
    value: uuid.UUID

    @classmethod
    def new(cls, kind: EntityKind):
        return cls(kind, uuid.uuid4())


@dataclass(frozen=True)
class CommandId:
    value: uuid.UUID

    @classmethod
    def new(cls):
        return cls(uuid.uuid4())


@dataclass(frozen=True)
class EvidenceId:
    value: str

    def __post_init__(self):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.value):
            raise ValueError("invalid evidence content identity")


@dataclass(frozen=True)
class Version:
    value: int

    def __post_init__(self):
        if self.value < 0:
            raise ValueError("version cannot be negative")


@dataclass(frozen=True)
class PrincipalId:
    value: str

    def __post_init__(self):
        if not IDENTITY.fullmatch(self.value):
            raise ValueError("principal must be a typed, validated identity")


@dataclass(frozen=True)
class Correlation:
    trace_id: uuid.UUID
    agent_id: uuid.UUID
    objective_id: uuid.UUID
    generation_id: str

    def __post_init__(self):
        if not re.fullmatch(r"[0-9a-f]{32}", self.generation_id):
            raise ValueError("generation_id must be 32 lowercase hexadecimal characters")


@dataclass(frozen=True)
class EvidenceMetadata:
    producer: PrincipalId
    subject: str
    source_version: Version
    retention_class: str
    access_policy: str
    correlation: Correlation

    def __post_init__(self):
        if not self.subject or not self.retention_class or not self.access_policy:
            raise ValueError("evidence subject, retention class, and access policy are required")


def assert_legal(kind: EntityKind, previous: State | None, new: State):
    if previous is None:
        if INITIAL[kind] != new:
            raise ValueError(f"illegal initial {kind} state: {new}")
    elif new not in LEGAL.get((kind, previous), set()):
        raise ValueError(f"illegal {kind} transition: {previous} -> {new}")
