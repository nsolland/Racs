# REHT Issuance Binding Profile v0.2

Status: NORMATIVE

## Invariant

`no_commit_token_without_verified_clearance_chain`

A CoreExecutionPermit or CommitToken MUST NOT be issued from technical possession of an upstream artifact alone. Every upstream artifact MUST be schema-valid, digest-bound, cryptographically signed by an active authorized issuer, temporally valid, and exactly bound to the same action, tenant, connector, capability, target and payload.

Issuance narrows authority. It never creates, repairs or expands authority.

## Required chain

1. REHT issues a signed GovernanceClearance.
2. Core verifies the clearance envelope, payload digest, signature, issuer role, issuer scope, revocation status and expiry.
3. Core verifies that the requested target and payload digests exactly equal the clearance bindings.
4. Core issues a signed CoreExecutionPermit whose lifetime cannot exceed either clearance lifetime.
5. Before issuing a CommitToken, Core verifies the exact permit envelope, payload digest, signature, issuer role, issuer scope, revocation status and expiry.
6. Core issues a single-use CommitToken whose lifetime cannot exceed the permit lifetime.
7. The bounded connector executes only when the token is valid and unconsumed.

## Fail-closed rules

A conforming implementation MUST reject:

- unsigned, locally constructed, unknown-issuer or revoked-issuer clearance
- clearance payload or signature mutation
- missing required clearance bindings
- placeholder or reconstructed authority, policy, evidence, purpose or state digests
- target or payload substitution after clearance
- a permit or token that outlives its upstream authorization
- permit payload, digest or signature mutation
- tenant or trust-domain mismatch
- a non-`ALLOW`/`MODIFY` clearance or a non-admissible state

No fallback permit, token or parallel execution path may be created after rejection.

## Binding continuity

The chain MUST preserve:

`GovernanceClearance.payload_digest`
→ `CoreExecutionPermit.clearance_digest`
→ `CommitToken.clearance_digest`

and:

`CoreExecutionPermit.payload_digest`
→ `CommitToken.execution_permit_digest`

The exact `action_envelope_digest`, `connector_id`, `capability`, `target_digest`, `payload_digest` and `reservation_id` MUST remain unchanged from permit to token.

## Separation of proof

GovernanceClearance proves that execution is authorized.

CoreExecutionPermit proves that Core verified and reserved the exact authorized execution.

CommitToken proves that the bounded connector may perform that exact execution once.

ExecutionReceipt remains separate proof of what actually happened.
