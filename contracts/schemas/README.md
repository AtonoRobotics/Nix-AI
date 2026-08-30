# Schema Registry

These schemas use JSON Schema draft 2020-12. Implementations SHALL register every local schema by its `$id` before compiling references. The `habitat.invalid` authority is a stable, non-routable identifier namespace; runtime validation SHALL resolve it from the signed package, not the network.

Model-facing payloads are validated before they can become ABI commands. Schema validity does not establish authority; the receiving Habitat service performs identity, capability, state-version and idempotency checks after validation.

Breaking semantics require a new `$id` and major contract version. Existing persisted payloads retain their original schema identity.

