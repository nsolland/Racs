# Portable Execution Receipt Extension Analysis

> **Status:** non-normative research input
> **Receipt schemas:** unchanged `spec/execution-receipt-v0.2.schema.json`; opt-in extension in `spec/execution-receipt-v0.3.schema.json`
> **Boundary reference:** `docs/architecture/BOUNDARIES.md`
> **Delivery:** issue #1 reconciliation; the versioned v0.3 schema is the normative extension contract

This document is an analytic handoff. It does not alter normative schemas, grant authority to external formats, or create new mandatory core fields. Its purpose is to make portable proof-of-execution patterns comparable against the current RACS execution receipt, identify extension opportunities, and preserve the separation between evidence and admissibility.

---

## 1. Field comparative matrix

The matrix compares issue #1 scope fields against the current RACS v0.2 execution receipt. Status values:

- `core` — already represented as a required or explicit optional field.
- `mapped external reference` — portable value may be referenced, but external format is not governance authority; used when the portable pattern is fundamentally outside RACS ownership but can be referenced by digest or envelope id.
- `optional extension` — can be added in the proposed namespace without changing normative core semantics; used when the portable pattern fits inside the existing receipt boundary and only needs additional fields.
- `unsupported` — no mapping yet; gap is explicit.

| Issue #1 field | RACS status | Current field or mechanism | Notes |
|---|---|---|---|
| action identity | core | `action_id`, `action_envelope_digest` | Action envelope digest binds the canonical action bytes. |
| actor and principal | optional extension | none | Actor/principal is outside the current receipt boundary; can be mapped from authorization context. |
| authority reference | core | `clearance_id`, `clearance_digest` | Ties execution to a specific clearance instance. |
| delegation scope | mapped external reference | none | Mapped because delegation authority lives outside the receipt boundary; carried as a referenced delegation envelope digest. |
| policy fingerprint | mapped external reference | none | Mapped because policy fingerprint is outside receipt ownership; may be mapped from policy context digest or rule-set identifier. |
| evidence references | optional extension | none | Pointer to an evidence package bundle or location. |
| pre-action state | optional extension | none | Required for reversible/idempotent actions; modeled as a bounded state snapshot reference. |
| execution environment | core | `connector_id`, `capability`, `provider_reference` | Environment and runtime adapter are present. |
| decision | core | `technical_outcome` | Outcome reflects decision/result together; see semantic conflict note below. |
| execution outcome | core | `technical_outcome` | `SUCCEEDED`, `FAILED`, `REVERSED`, etc. |
| post-action state | optional extension | none | Replay/duplicate detection benefits from explicit post-state evidence. |
| timestamps and latency | core | `started_at`, `completed_at` | Latency can be computed from these fields. |
| reversibility | core | `reversal_status` | Explicit reversal lifecycle is present. |
| cost | optional extension | none | Must remain a typed claim with provenance. |
| value created/protected/avoided | optional extension | none | Must remain a typed claim with method, evidence, and confidence. |
| external proof reference | optional extension | none | Vendor-neutral mapping point. |
| cryptographic signature | mapped external reference | `response_digest` | Response/content digest exists; full signature binding is external. |
| chain linkage | core | `previous_receipt_hash` | Linear chaining is present. |
| idempotency and replay status | optional extension | none | See extension proposal. |

---

## 2. Gaps and semantic conflicts

### 2.1 Proof-of-execution versus admissibility

A portable proof-of-execution format can imply admissibility. RACS must not import that implication.

Current RACS separates:
- governance clearance in `clearance_id`/`clearance_digest`
- execution outcome in `technical_outcome`

Portable execution receipts often conflate these. If an extension references an external proof format, it must remain a `mapped external reference` and must not be treated as admissible evidence by RACS alone.

### 2.2 Activity versus value

`technical_outcome` records activity/result. It does not carry economic or protected-value semantics.

Value claims must include:
- method: how value was measured or estimated
- evidence: artifact identifier or digest
- confidence: bounded uncertainty representation

Adding value fields to the core schema would make value normative, which contradicts the boundary that RACS standardizes evidence exchange but does not own truth determination or value judgment.

### 2.3 Replay and duplicate execution

The current schema lacks explicit replay/duplicate detection. The extension namespace should expose:
- replay status enum
- duplicate execution reference, if any
- idempotency token or deterministic outcome fingerprint

These fields must not override the core receipt's chronological chain role.

---

## 3. Proposed optional extension namespace

The namespace is vendor-neutral. It is normative only in the opt-in v0.3 receipt schema; v0.2 remains byte-for-byte compatible with its pre-extension contract.

### Namespace concept

```text
receipt_ext:
  actor_principal:
    type: object
  delegation_scope_ref:
    type: string
  policy_fingerprint_ref:
    type: string
  evidence_refs:
    type: array
    items:
      type: string
  pre_state:
    type: object
  post_state:
    type: object
  cost:
    type: object
    required:
      - method
      - evidence_ref
      - confidence
  value_claim:
    type: object
    required:
      - method
      - evidence_ref
      - confidence
  external_proof_ref:
    type: string
  signature_binding_ref:
    type: string
  replay_status:
    type: string
    enum: [FIRST_EXECUTION, REPLAY, DUPLICATE, UNVERIFIED]
  idempotency_token:
    type: string
```

### Design rules

1. External references are references only. They do not replace RACS authority or evidence semantics.
2. Cost and value claims must always include method, evidence reference, and confidence.
3. Pre/post state evidence is represented as bounded references or digests, not full payload duplication.
4. Replay status does not grant authority. The v0.3 schema requires `REPLAY` and `DUPLICATE` to carry an idempotency token plus an exact prior receipt id and hash; `FIRST_EXECUTION` and `UNVERIFIED` cannot name a duplicate receipt. `validators/execution_receipt_validator.py` validates those claims against an ordered receipt set, including the receipt-chain hash and shared idempotency lineage.
5. Unknown extension fields are rejected. Receivers must not silently accept semantics they do not implement; new portable fields require a later versioned schema.

---

## 4. Value claim structure

```json
{
  "receipt_ext": {
    "cost": {
      "method": "provider_reported",
      "evidence_ref": "sha256:...",
      "confidence": "high",
      "unit": "token",
      "amount": 142
    },
    "value_claim": {
      "method": "estimated_monetary_impact",
      "evidence_ref": "sha256:...",
      "confidence": "medium",
      "direction": "protected",
      "amount": 8900,
      "currency": "NOK"
    }
  }
}
```

Confidence should be typed. The schema should allow extensions such as `low`, `medium`, `high`, or bounded numeric intervals, but those levels are not normative here.

---

## 5. Replay and duplicate status

```json
{
  "receipt_ext": {
    "replay_status": "FIRST_EXECUTION",
    "idempotency_token": "sha256:..."
  }
}
```

If replay detection later requires cross-system signals, those signals should be mapped through the extension namespace rather than promoted to core required fields.

---

## 6. Pre/post state evidence

Pre and post state are not full environment snapshots. They are bounded evidence references that preserve compactness and immutability.

```json
{
  "receipt_ext": {
    "pre_state": {
      "evidence_ref": "sha256:...",
      "scope": "bounded:target_digest"
    },
    "post_state": {
      "evidence_ref": "sha256:...",
      "scope": "bounded:target_digest"
    }
  }
}
```

Scope uses the closed `bounded:<scope-name>` syntax. Free-form or unbounded scope labels are rejected, preventing an extension from claiming an unlimited environment snapshot.

---

## 7. Mapping to external proof formats

External proof formats may be referenced, but not trusted as governance authority.

Allowed mapping patterns:
- `external_proof_ref` → proof-system-specific receipt identifier or bundle location
- `signature_binding_ref` → verification material digest or URI
- `evidence_refs` → list of supporting evidence package identifiers

Disallowed patterns:
- external format fields replacing `technical_outcome` semantics
- external proof format becoming a substitute for RACS clearance/commit linkage
- vendor-specific fields promoted to mandatory core fields

---

## 8. Backward compatibility and migration

Current RACS v0.2 receipts remain valid because v0.2 was restored to its original contract. The portable namespace is additive and optional only in v0.3. A v0.2 producer does not need to migrate; a producer that emits `receipt_ext` must declare and validate the v0.3 payload.

Implementation guidance:
- parsers must reject unknown `receipt_ext` properties rather than silently assigning them semantics
- validators reject extension fields under v0.2 and validate known fields under v0.3
- no mandatory migration path is introduced; adoption is receiver-driven

---

## 9. Reward Economy compatibility note

If value-claim fields are used in a reward-economy context:
- RACS receipt remains evidence, not authority
- policy and legitimacy remain outside RACS ownership per boundary rules
- value claims should be interpreted by the consuming reward system, not by RACS validators

---

## 10. Compliance and test impact

The v0.3 schema and conformance delivery covers:
- rejected attempts to use extension fields as authority inputs
- malformed value claims missing method, evidence, or confidence
- replay/duplicate/idempotency relationship mismatches against an ordered receipt set while preserving the mandatory receipt-chain hash
- pre/post state references that exceed declared scope

---

## 11. Research input declaration

This document remains non-normative analysis. `spec/execution-receipt-v0.3.schema.json` is the versioned normative contract; v0.2 consumers are unaffected. External portable formats remain evidence references and never become governance authority.
