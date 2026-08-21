# Transport Bindings (P0.2, issue #139)

Status: NORMATIVE.

Defines the permitted transport bindings for RACS contracts. The contracts
are canonical at the wire-format level (JSON Schema + RFC 8785 canonical
digest); transport is a delivery concern and MUST NOT change semantics.

## Binding rules (T1–T5)

1. **T1 — semantics over transport.** The same contract payload has the same
   meaning regardless of transport. A transport binding MUST NOT add or remove
   normative fields.
2. **T2 — digest over the canonical payload.** Any signed binding transmits the
   canonical (RFC 8785) digest of the payload, never a transport-rewritten copy.
   A transport that rewrites JSON (key order, whitespace, number form) MUST
   canonicalize before hashing.
3. **T3 — HTTPS for bearer/authority-bearing flows.** Authority-bearing flows
   (clearance, determination, permit, revocation, intervention) use HTTPS with
   TLS >= 1.2. No plaintext bearer transmission.
4. **T4 — idempotency.** Mutating deliveries MUST carry an idempotency key
   (e.g. the contract `*_id`). Retries MUST NOT produce a second effect.
5. **T5 — authenticated receivers.** Receivers of signed contracts verify
   signature and issuer identity; a receiver never trusts transport headers
   for authority.

## Bindings

| Flow | Transport | Notes |
|------|-----------|-------|
| Action envelope submission | HTTPS POST | single exact-action envelope, one effect path |
| Determination / clearance | HTTPS response | signed, scoped, time-bounded |
| Permit issuance | HTTPS response | `permit:` ref returned by the enforcement boundary |
| Receipt publishing | HTTPS PUT / queue | append-only, WORM, hash-chained |
| Revocation broadcast | HTTPS + registry snapshot | always consult the registry |
| Runtime observation | HTTPS / streaming | watcher evidence, source-bound |
| Intervention | HTTPS | signed, idempotent, single effect |

## Non-bindings

- No UDP for consequence-bearing flows (T4 idempotency and T3 TLS cannot be
  guaranteed).
- No message-bus redelivery without idempotency keys (T4).
- No policy or authority materialized from transport metadata alone (T5).