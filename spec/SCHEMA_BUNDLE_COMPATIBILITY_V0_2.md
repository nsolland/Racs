# Schema Bundle and Compatibility Matrix (P0.2, issue #140)

Status: NORMATIVE.

Completes the schema bundle inventory and extends the compatibility matrix
beyond the AgentBound delta (`AGENTBOUND_DELTA_V0_2_V0_3_COMPATIBILITY.md`).

## Bundle inventory (complete)

The canonical RACS schema bundle is the set of `.schema.json` / `.yaml` files
under `spec/`. Every contract referenced by `CANONICAL_CONTRACTS.md` is part
of the bundle. This spec adds the remaining normative artifacts:

| Artifact | Schema | Status |
|----------|--------|--------|
| Revocation registry snapshot | `revocation-registry-snapshot-v0.2.schema.json` | added (issue #138) |
| Core state-transition conformance | `CORE_STATE_TRANSITION_CONFORMANCE_V0_2.md` | added (issue #145) |
| Active-session cross-artifact rules | `ACTIVE_SESSION_CROSS_ARTIFACT_VERIFICATION_V0_2.md` | added (issue #143) |
| Transport bindings | `TRANSPORT_BINDINGS_V0_2.md` | added (issue #139) |
| Signed golden vectors | `test-vectors/0.2/*.json` | added (issue #141) |

## Compatibility matrix

| Contract | v0.2 | v0.3 | Delta beyond AgentBound |
|----------|------|------|--------------------------|
| Action Envelope | yes | yes | optional portable extension; core unchanged |
| Admissibility Determination | yes | yes | `revocation_registry_ref` required; workspace/kernel binding pair |
| Governance Evaluation | yes | yes | vocabulary unchanged |
| Clearance | yes | yes | signed, scoped, time-bounded unchanged |
| Execution Receipt | yes | yes | v0.3 optional portable extension |
| Outcome Receipt | yes | yes | observed consequence, separate from execution |
| Revocation Registry Snapshot | yes | — | new in 0.2 (this spec) |
| Core State-Transition Profile | yes | — | new in 0.2 (this spec) |

## Rule (B1)

Legacy payloads remain valid unless a delta explicitly supersedes a field.
A `sha256:` digest computed over the RFC 8785 canonical form is stable across
transports and versions that do not change the payload's normative fields.