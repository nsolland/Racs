# RACS AAEC Trajectory Governance Profile v0.3

Status: NORMATIVE ADDITIVE PROFILE  
Issue: #128  
Threat class: `AUTONOMOUS_ADVERSARIAL_EXECUTION_CHAIN`

## 1. Purpose

This profile binds cross-action trajectory evidence into the existing RACS governance chain.

It addresses sequences in which individual actions may each be technically valid while their accumulated effect creates unauthorized authority, persistence, lateral reach, integrity degradation, data destruction or irreversible consequence.

The motivating JADEPUFFER report is treated as assessed threat evidence. The profile remains applicable whether a sequence is fully autonomous, human-supervised or scripted.

This profile is additive. It does not replace authority, VAIG evaluation, REHT clearance, Core enforcement, CommitToken, ExecutionReceipt or OutcomeReceipt.

## 2. Canonical responsibility boundary

```text
Reality observations and receipts
→ VAIG trajectory evaluation
→ REHT exact-action clearance
→ RACS trajectory binding and deterministic conformance
→ Core enforcement
→ bounded execution
→ ExecutionReceipt / OutcomeReceipt
→ next trajectory state
```

RACS defines the artifact, canonicalization, reason codes, monotone composition and fail-closed consumer behavior.

RACS does not establish organisational authority, decide admissibility, issue REHT clearance or execute an action.

## 3. Canonical artifact

Schema:

`spec/aaec-trajectory-context-v0.3.schema.json`

Version:

`aaec-trajectory-context-0.3`

The artifact binds:

- trajectory identity and immutable root;
- sequence number;
- prior and current terminal receipt lineage;
- authority, principal and agent continuity;
- current target set;
- cumulative consequence counters;
- action-specific observations;
- evidence obligations;
- validity window;
- independent HALT state;
- a canonical context digest.

It declares:

```text
authority_effect = NO_AUTHORITY_CREATION
execution_authority = NONE
```

A valid artifact is evidence. It is never a clearance, permit, token or credential.

## 4. Normative invariants

### 4.1 Receipt continuity

For sequence zero, `prior_terminal_receipt_digest` MUST be null.

For every later sequence:

- `sequence_no` MUST increment by exactly one;
- `prior_terminal_receipt_digest` MUST equal the preceding context's `terminal_receipt_digest`;
- trajectory identity and root MUST remain unchanged.

Missing lineage is `INCOMPLETE`. Substituted lineage is `MISMATCH`.

### 4.2 Authority continuity

The following MUST remain exact unless a fresh upstream authority transition is independently established and rebound into a new trajectory root:

- authority lineage;
- principal binding;
- agent identity.

A credential harvested during the trajectory MUST NOT establish legitimate authority.

An identity created by the trajectory MUST NOT authorize that same creator trajectory.

### 4.3 Target-set continuity

Target discovery is observation, not authority.

A newly discovered target MUST NOT silently enter the executable target set. Expansion requires:

- the target to be inside an upstream authorized set;
- `target_expansion_authorized=true`;
- a bound `target_expansion_clearance_digest`.

### 4.4 Monotone consequence composition

Cumulative counters MUST equal the prior counters plus the current action deltas.

Counters MUST NOT decrease.

Ceilings are monotone hard limits. Exceeding any ceiling requires `HALT` as the minimum downstream response.

The required counters are:

- action count;
- destructive action count;
- irreversible action count;
- secret access count;
- privilege change count;
- persistence change count;
- lateral target expansion count;
- observed egress bytes.

### 4.5 Mandatory action evidence

The following action classes require bound evidence:

| Action class | Mandatory evidence |
|---|---|
| `IDENTITY_CREATE` | `authority_transition_clearance` |
| `PRIVILEGE_CHANGE` | `authority_transition_clearance` |
| `PERSISTENCE_CREATE` | `persistence_clearance` |
| `INTEGRITY_CONTROL_CHANGE` | `integrity_control_change_clearance` |
| `DATA_ENCRYPT` | `destructive_action_clearance`, `reversibility_assessment` |
| `DATA_DELETE` | `destructive_action_clearance`, `reversibility_assessment` |
| `DATABASE_DROP` | destructive clearance, reversibility assessment and fresh human approval |

Presence of evidence does not prove legitimacy. The upstream verifier and REHT chain remain authoritative.

### 4.6 Claims are not observations

Agent narration is represented as a claim.

A claim marked `VERIFIED` MUST carry an observed evidence digest.

An unverified exfiltration claim MUST NOT be counted as observed egress or a completed outcome.

### 4.7 Machine-speed adaptation

Machine-speed plan–act–observe–retry behavior is a risk signal. It is not proof of malicious intent.

The reference validator raises the minimum downstream response to `STEP_UP`, while preserving structural status `MATCH` when no other invariant fails.

### 4.8 HALT dominance

An independent HALT signal dominates all lower responses.

No evidence, confidence, favourable sub-result or successful previous action may erase HALT.

## 5. Deterministic validation output

The reference validator returns:

- `validation_status`: `MATCH`, `MISMATCH`, `INCOMPLETE` or `UNVERIFIABLE`;
- `minimum_response`: `NONE`, `STEP_UP`, `DENY` or `HALT`;
- canonical reason codes;
- observed and unverified claim classes;
- the context digest and trajectory coordinates;
- `execution_authority=NONE`.

`minimum_response` is a fail-closed lower bound for downstream governance. It is not an action decision or clearance.

## 6. Canonical reason codes

- `AAEC_CONTEXT_DIGEST_MISMATCH`
- `AAEC_UNSUPPORTED_VERSION`
- `AAEC_AUTHORITY_CREATION_FORBIDDEN`
- `AAEC_CONTEXT_EXPIRED`
- `AAEC_CONTEXT_NOT_YET_VALID`
- `AAEC_TRAJECTORY_LINEAGE_MISSING`
- `AAEC_TRAJECTORY_LINEAGE_MISMATCH`
- `AAEC_ACTION_SEQUENCE_GAP`
- `AAEC_AUTHORITY_LINEAGE_CHANGED`
- `AAEC_PRINCIPAL_BINDING_CHANGED`
- `AAEC_AGENT_IDENTITY_CHANGED`
- `AAEC_TARGET_SET_DIGEST_MISMATCH`
- `AAEC_TARGET_SET_EXPANSION`
- `AAEC_TARGET_EXPANSION_EVIDENCE_MISSING`
- `AAEC_COUNTER_REGRESSION`
- `AAEC_COUNTER_TRANSITION_MISMATCH`
- `AAEC_CUMULATIVE_CEILING_EXCEEDED`
- `AAEC_HARVESTED_CREDENTIAL_PROVENANCE`
- `AAEC_SELF_CREATED_AUTHORITY`
- `AAEC_MANDATORY_EVIDENCE_MISSING`
- `AAEC_DESTRUCTIVE_OBLIGATION_MISSING`
- `AAEC_UNVERIFIED_EXFILTRATION_CLAIM`
- `AAEC_VERIFIED_CLAIM_EVIDENCE_MISSING`
- `AAEC_MACHINE_SPEED_ADAPTIVE_RETRY`
- `AAEC_INDEPENDENT_HALT`

## 7. Compatibility

A deployment may use existing RACS v0.2 or v0.3 profiles without claiming AAEC conformance.

When an action class or deployment policy requires this profile:

- the AAEC context is mandatory;
- missing prior receipt lineage cannot resolve to executable `ALLOW`;
- referenced trajectory evidence must verify;
- the exact context digest must bind through VAIG evaluation, REHT clearance, RACS commit, Core permit and terminal receipts;
- existing exact-action authorization remains mandatory.

The profile MUST NOT be used to synthesize missing authority, clearance or receipt evidence.

## 8. Minimum conformance cases

A conformant reference implementation demonstrates:

1. valid first action;
2. missing prior receipt fails closed;
3. substituted prior receipt is rejected;
4. harvested credential cannot bootstrap authority;
5. self-created identity cannot authorize its creator trajectory;
6. target discovery cannot silently expand scope;
7. explicitly cleared target expansion is representable;
8. cumulative destructive limits halt the trajectory;
9. database destruction requires fresh human approval;
10. unverified exfiltration remains an unverified claim;
11. machine-speed retry is represented as a risk signal;
12. independent HALT dominates;
13. counter regression is rejected;
14. context mutation is unverifiable.

## 9. Non-claims

This profile does not claim:

- that the JADEPUFFER operation was conclusively autonomous;
- that trajectory evidence proves malicious intent;
- that schema validity proves authority;
- that RACS evaluates admissibility;
- that a valid trajectory artifact permits execution;
- that receipts prove business outcome or value;
- that deterministic conformance eliminates production risk.
