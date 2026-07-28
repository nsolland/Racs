# Runtime Continuity v0.2 — Contract Reuse and Ownership Map

Status: implementation anchor  
Canonical base: `faf9d2efacf00626c8458085b0191059d8b2d0aa`  
Branch: `build/runtime-continuity-contracts-v02`  
Owner: RACS contract layer

## Active delivery

Extend Draft 0.2 for active, embodied and multi-transition execution without
creating a new authority, clearance or execution-decision layer.

## Reused canonical contracts

| Concern | Existing RACS contract | Runtime-continuity use |
|---|---|---|
| Human or organisational authority | `AuthorityGrant`, `DelegationChain` | remains upstream and narrowing-only |
| Exact proposed action | `ActionEnvelope` | binds capability-manifest and environment-profile digests |
| Evaluation | `GovernanceEvaluation` | VAIG evidence and risk input |
| Admissibility | `AdmissibilityDetermination` | REHT legitimacy determination |
| Clearance | `GovernanceClearance` | exact-action, time-bounded clearance |
| Launch enforcement | `CoreExecutionPermit`, `CommitToken` | only valid launch path |
| Material change | `ContinuousIntegrityEvent` | signals required revalidation |
| Stop control | `RevocationEvent`, `HALT` | dominates active sessions |
| Technical proof | `ExecutionReceipt` | proves attempted or completed execution |
| Consequence proof | `OutcomeReceipt` | proves observed effect separately |

## New canonical payloads

| Payload | Why it is distinct |
|---|---|
| `GovernedCapabilityManifest` | immutable executable artifact, interface, telemetry and postconditions |
| `EnvironmentGovernanceProfile` | environment constraints and fail-closed policy |
| `GovernedExecutionSession` | binds an active execution after launch |
| `RuntimeObservation` | source-bound runtime evidence |
| `ContinuityDecision` | deterministic decision for the next transition |
| `InterventionReceipt` | proves applied or failed intervention |
| `RecoveryPlan` | bounded evidence-only recovery proposal |
| `RecoveryReceipt` | proves governed recovery attempt and postcondition |

## Frozen duplicate concepts

The following names MUST NOT become parallel authoritative contracts:

- Runtime Governance Authorization
- Watcher Authorization
- Capability Allow
- Safety ALLOW
- Recovery Authorization embedded in a plan
- Human Approved boolean as authority
- Session Permit independent of `CoreExecutionPermit`
- Runtime Receipt combining clearance, intervention, recovery and outcome

Compatibility adapters may translate legacy data into the canonical payloads but
must not emit execution authority.

## Decision ownership

```text
Watcher / substrate
→ RuntimeObservation evidence

VAIG where semantic or risk evaluation is required
→ GovernanceEvaluation evidence

REHT
→ admissibility and exact-action clearance

RACS
→ ContinuityDecision wire semantics

Core / bounded adapter
→ deterministic enforcement

Receipts
→ InterventionReceipt, ExecutionReceipt, RecoveryReceipt, OutcomeReceipt
```

## Self-digest ruling

Runtime-continuity payloads do not contain their own current digest. The existing
canonical signed artifact envelope carries `payload_digest`.

This prevents recursive digest fields and keeps the Draft 0.2 envelope model
canonical. Previous-artifact digests remain allowed for chain binding.

## Cross-language integer ruling

`RuntimeObservation.timestamp_ns` is a decimal string.

Nanosecond epoch values exceed JavaScript's interoperable integer range. Encoding
them as JSON numbers would make Python/Rust and TypeScript canonical bytes diverge.
The decimal-string representation preserves exact value and byte-identical digests.

## Dependency order

1. Existing RACS-JCS-1 canonicalization and digest helpers.
2. Existing authority, action, evaluation, admissibility, clearance and permit chain.
3. New Draft 0.2 schemas.
4. Python, Rust and TypeScript typed payloads.
5. Shared golden vectors.
6. Runtime schema registration.
7. Cross-artifact verification and narrowing proof.
8. Core and platform integrations.

Stages 3–6 are this delivery. Stage 7 is the next RACS delivery. Stage 8 belongs to
downstream repositories after contract stability.

## Owned files

- `SPECIFICATION.md`
- `spec/CANONICAL_CONTRACTS.md`
- `spec/RUNTIME_CONTINUITY_V0_2.md`
- eight capability, environment, session, observation, continuity and recovery schemas
- `reference/bindings/v0.2/*` continuity bindings and tests
- `test-vectors/0.2/runtime-continuity/canonical-vectors.json`
- this reuse map

## Acceptance

- one canonical owner per contract
- no new authority source
- no new REHT clearance type
- no replacement for existing permit or commit token
- unknown fields rejected in typed bindings
- schema payloads reject forbidden self-authorization
- Python, Rust and TypeScript reproduce the same golden digests
- atomic action path remains unchanged
