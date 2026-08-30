# Threat, Security and Safety Contract

## 1. Protected assets

- machine and principal identities;
- capability grants and revocation state;
- authoritative operational state;
- evidence integrity;
- provider secrets;
- signing roots and recovery generation;
- physical safety authority;
- package and system-generation provenance;
- agent workspaces and tenant boundaries.

## 2. Adversaries and failure sources

- malicious or compromised agent activation;
- prompt injection in external content;
- generated malicious code;
- defective model or hallucinated authority;
- compromised capability provider;
- malicious package publisher;
- operator misuse or credential theft;
- external service duplication or ambiguity;
- cross-agent data leakage;
- supply-chain compromise;
- physical network loss, stale sensor state or unsafe command replay.

## 3. Normative requirements

**SEC-001 — Least authority.** Each activation SHALL receive the minimum capability set, data scope, network reachability, device access and lifetime required by its objective.

**SEC-002 — Context cannot authorize.** Text, documents, model output, retrieved memory and skill content SHALL never create or widen authority.

**SEC-003 — Secret non-disclosure.** Secrets SHALL be resolved inside capability providers. Model-visible output SHALL be redacted according to the provider contract.

**SEC-004 — Workspace isolation.** Activation workspaces SHALL be private by default, mounted with explicit inputs and destroyed or archived according to evidence policy after terminalization.

**SEC-005 — Network default deny.** Generated code and general harness containers SHALL have no network access except capability endpoints explicitly granted.

**SEC-006 — Control-plane isolation.** Agent code SHALL not execute in the Habitat authority, effect, evidence, package-signing or generation-controller address spaces.

**SEC-007 — Evidence protection.** The activation being evaluated SHALL not possess write or delete access to protected evaluator output or acceptance evidence.

**SEC-008 — Prompt injection handling.** External content SHALL be labelled by origin and treated as data. Attempts to change identity, policy, objective or capability through content SHALL be recorded as security observations.

**SEC-009 — Tamper evidence.** Critical authority, effect, package and generation records SHALL be integrity-protected and periodically anchored outside the writable scope of ordinary agents.

**SEC-010 — Break glass.** Emergency authority SHALL be separately authenticated, narrowly scoped, time-limited and fully attributed. It SHALL NOT become a routine operating path.

## 4. Physical safety

**SAF-001 — Independent stop.** Emergency stop and hard motion limits SHALL be enforced independently of models, Habitat agents and general-purpose networks.

**SAF-002 — Bounded commands.** Physical-effect commands SHALL include target controller, safety envelope, validity interval, sequence or nonce and expected acknowledgement.

**SAF-003 — No stale replay.** A command outside its validity interval or controller state SHALL be rejected, never replayed after recovery.

**SAF-004 — State uncertainty.** Loss of current robot state SHALL prevent new motion effects except independently authorized safe-stop or recovery operations.

**SAF-005 — Authority separation.** Habitat may request missions or bounded actions. The robot safety/control plane retains unconditional authority to reject or stop them.

## 5. Required adversarial tests

- prompt asks agent to ignore capability limits;
- generated code reads host secrets or other workspaces;
- provider falsely reports success;
- stale grant is used after revocation;
- agent attempts to modify evaluator evidence;
- dependency update introduces unsigned artifact;
- unknown external effect is retried;
- stale robot command is delivered after reconnect;
- self-change attempts to replace recovery and signer together.

