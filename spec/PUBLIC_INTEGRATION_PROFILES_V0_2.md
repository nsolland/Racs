# Public Integration Profiles (P0.2, issue #146)

Status: NORMATIVE.

Public integration profiles for the canonical runtime partners in the VALO
execution chain. These profiles are the machine-readable contract each partner
implements to interoperate with RACS.

## Profile: REHT

Role: sole final execution-admissibility authority.

- Produces `admissibility-determination-v0.2.schema.json` and signed clearance.
- Accepts exact-action envelopes; binds `workspace_binding_digest` +
  `kernel_context_digest` as a pair.
- Revocation via `revocation-registry-snapshot-v0.2.schema.json`.
- Transport: HTTPS (T3), idempotent (T4), authenticated (T5).

## Profile: valo-platform

Role: governed platform surface (workspace, agents, dashboards) — proposes,
never authorizes.

- Forms exact action envelopes and submits for determination/clearance.
- Consumes permits; routes effects through the single governed effect path.
- Observes and publishes receipts; never emits a parallel ALLOW.
- Integrates the active-session cross-artifact rules (S1–S5).

## Profile: valo-v5-core

Role: deterministic enforcement kernel after RACS.

- Enforces the Core state-transition conformance profile (issue #145).
- Rejects illegal transitions before external effect (P3).
- Implements `MODIFY_RUNTIME_BOUNDS` with the narrowing proof (issue #142).
- Emits execution and outcome receipts; verifies golden vectors (issue #141).

## Shared rules (X1–X3)

1. **X1 — no re-authorization.** No partner may issue a parallel ALLOW or
   supersede an upstream decision.
2. **X2 — exact contracts.** Partners use the canonical schemas from this
   bundle; references, not copies.
3. **X3 — fail closed.** Any partner that cannot verify returns DENY/denied
   with zero external effect.