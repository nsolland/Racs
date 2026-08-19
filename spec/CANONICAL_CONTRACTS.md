# RACS Canonical Contract Index (P0.2, issue #991)

Status: NORMATIVE. Source of truth for runtime execution-governance contracts in the
VALO execution chain: `VAIG evaluates → REHT clears → RACS expresses the deterministic decision contract → Core enforces → Receipts prove`.

Ruling #991:

1. **RACS/spec is canonical** for runtime execution-governance contracts, decisions,
   canonicalization and digest semantics.
2. reht-standard remains canonical ONLY for REHT-specific clearance/authorization
   standards; it MUST reference these RACS contracts, not duplicate them.
3. valo-v5-core is the deterministic enforcement kernel after RACS. It MUST NOT
   redefine upstream decisions, schemas, authority or policy semantics.
4. ACS/VACS is deprecated as an execution decision layer. Preserve only genuinely
   distinct VAIG evaluation artifacts with compatibility adapters.
5. Runtime continuity extends the same chain. Capability manifests, environment
   profiles, watchers, execution substrates and recovery planners are not authority
   sources and cannot issue a parallel ALLOW.
6. Consequence-bearing execution MUST have one governed effect path, and every observed
   effect MUST be attributable to the required governance and receipt chain. A chainless
   effect is a control failure and suspected execution bypass, not governed success.
7. `NO_DIRECT_EFFECT_PATH`, `NULL_EFFECT_ON_DENY`, the Structural Coupling Test,
   effector-exclusive execution capability and deterministic pinned boundary replay are
   canonical conformance requirements. Boundary replay does not include token-level LLM replay.

## Canonical contracts

| # | Contract | RACS schema (canonical) | Notes |
|---|----------|-------------------------|-------|
| 1 | Action Envelope | `action-envelope-v0.2.schema.json` | wire format of one exact proposed action |
| 2 | Authority Context | `authority-context.yaml` | delegated authority context |
| 3 | Policy Context | `policy-context.yaml` | policy data, never policy authority in code |
| 4 | Evidence Package | `evidence-package.yaml` | facts, observations and evaluator evidence |
| 5 | Governance State | `governance-state.schema.json` | runtime governance state |
| 6 | Delegation Chain | `delegation-chain-v0.2.schema.json` | narrowing authority chain |
| 7 | VAIG Evaluation | `governance-evaluation-v0.2.schema.json` | ALLOW/MODIFY/DEFER/DENY/STEP_UP/HALT evaluation vocabulary |
| 8 | REHT Admissibility | `admissibility-determination-v0.2.schema.json` | exact-action admissibility |
| 9 | REHT Clearance | `governance-clearance.schema.json` | signed, scoped, time-bounded clearance |
| 10 | RACS Decision | `CANONICAL_VERDICT_MAPPING.md` | deterministic decision and binding semantics |
| 11 | Continuous Integrity Event | `continuous-integrity-event-v0.2.schema.json` | material-change and WORM integrity event |
| 12 | Governed Capability Manifest | `governed-capability-manifest-v0.2.schema.json` | immutable capability artifact, interface, telemetry and postconditions |
| 13 | Environment Governance Profile | `environment-governance-profile-v0.2.schema.json` | environment constraints; policy/context evidence, not authority |
| 14 | Governed Execution Session | `governed-execution-session-v0.2.schema.json` | active multi-transition execution binding |
| 15 | Runtime Observation | `runtime-observation-v0.2.schema.json` | source-bound telemetry and watcher evidence |
| 16 | Continuity Decision | `continuity-decision-v0.2.schema.json` | CONTINUE/MODIFY_RUNTIME_BOUNDS/PAUSE/STOP/REAUTHORIZE/ROLLBACK/HANDOVER/HALT |
| 17 | Intervention Receipt | `intervention-receipt-v0.2.schema.json` | applied or failed runtime intervention |
| 18 | Recovery Plan / Receipt | `recovery-plan-v0.2.schema.json` + `recovery-receipt-v0.2.schema.json` | recovery is evidence-only until separately governed |
| 19 | Execution and Outcome Receipts | `execution-receipt-v0.2.schema.json`, `execution-receipt-v0.3.schema.json` + `outcome-receipt-v0.2.schema.json` | v0.3 adds the optional portable extension; technical execution and observed consequence remain separate |
| 20 | Role Boundary Contract | `role-contract-v1.schema.json` | wire format of module role boundary contracts |
| 21 | Role Integrity Evaluation | `role-integrity-evaluation-v1.schema.json` | evaluation result for role fidelity and role-drift detection |
| 22 | Governed Workspace Lineage | `governed-workspace-lineage-v0.2.schema.json` | optional, exact, non-authoritative transport binding from a Kernel-governed workspace through determination, clearance, permit and receipts; legacy payloads remain valid |


Normative runtime-continuity semantics are defined in `RUNTIME_CONTINUITY_V0_2.md`.
Normative effect-path and effect-chain integrity semantics are defined in `EFFECT_CHAIN_INTEGRITY_V0_2.md`.

## Canonicalization and digest (RACS-JCS-1)

- Canonicalization: RFC 8785. Sorted keys, no insignificant whitespace, UTF-8
  and ES2018 number formatting.
- Digest: SHA-256 over canonical bytes, represented as `sha256:<lowercase-hex>`.
- Payloads do not contain their own current digest. The canonical signed artifact
  envelope carries `payload_digest`; previous-artifact digests may appear for chain binding.
- Nanosecond timestamps are decimal strings where values can exceed the interoperable
  JSON integer range. This preserves byte-identical Python, Rust and TypeScript digests.
- Rules: `spec/CANONICALIZATION.md`.

## Golden vectors

`test-vectors/0.2/runtime-continuity/canonical-vectors.json` carries pinned payloads,
canonical strings and payload digests for all eight runtime-continuity payloads.

Python, Rust and TypeScript bindings MUST reproduce the same canonical bytes and digest.

## Ownership and compatibility

- VAIG evaluates; it does not clear or execute.
- REHT determines admissibility and issues exact-action clearance.
- RACS owns wire contracts, decision vocabulary, canonicalization and conformance.
- RACS owns effect-path and effect-chain integrity semantics; observed effects without the required governed chain are treated as suspected bypass/control failure.
- Decision-relevant state and memory writes are consequence-bearing effects and require an appropriate governed write boundary.
- RACS transports workspace and verified Kernel-context bindings. Kernel owns authoritative state and conformance; REHT owns fresh exact-action authorization.
- Core enforces permits, revocation, HALT and continuity decisions.
- Watchers produce evidence. They do not authorize intervention or recovery.
- Bounded adapters apply decisions and return receipts. They cannot widen bindings.
- reht-standard MUST reference corresponding RACS contracts instead of copying them.
- Existing atomic actions retain the current permit and bounded-connector path.
- Active, embodied or multi-transition actions additionally use the runtime-continuity contracts.

## Supersession record

See `SUPERSEDED.md` for schemas retired by the original ruling and their compatibility
adapter status. Runtime continuity adds contracts; it does not supersede the existing
authority, evaluation, clearance, permit, execution or outcome artifacts.
