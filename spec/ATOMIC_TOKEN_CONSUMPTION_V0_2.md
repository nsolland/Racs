# Atomic CommitToken Consumption Profile v0.2

Status: NORMATIVE

## Invariant

`no_external_consequence_before_atomic_token_consumption`

A bounded connector MUST verify and atomically consume the exact CommitToken before invoking any provider operation that may create external consequence.

A consumed token MUST never be accepted again, including when the provider returns failure, timeout or an indeterminate result. Retry requires a newly authorized execution identity and a new CommitToken.

## Required order

1. Validate the canonical artifact envelope and CommitToken payload schema.
2. Verify payload digest, signature, issuer role, issuer scope, trust domain, key, revocation status and validity interval.
3. Verify `single_use = true`.
4. Verify exact tenant, connector, capability, target digest and payload digest bindings.
5. Validate the previous receipt-chain hash.
6. Atomically record token consumption using compare-and-set semantics.
7. Only after successful consumption, invoke the provider.
8. Emit a signed ExecutionReceipt for success, failure or indeterminate provider outcome.

Any failure before step 6 MUST prevent provider invocation and MUST leave the valid token unconsumed. Any failure after step 6 MUST leave the token consumed.

## Replay semantics

The consumption key is the globally unique `commit_token_id` within the referenced consumption domain.

Concurrent attempts using the same token MUST produce at most one successful consumption. All later or losing attempts MUST fail closed before provider invocation.

The token payload digest, execution identity and consumption time MUST be retained in the consumption record.

## Request binding

The connector MUST compute canonical digests from the actual target and request payload presented at the commit boundary.

Caller-supplied digest assertions are insufficient. The computed values MUST exactly equal the signed CommitToken bindings.

## Receipt semantics

The ExecutionReceipt MUST bind:

- exact CommitToken ID and payload digest
- execution, action and clearance identity
- connector and capability
- target and payload digests
- provider reference
- response digest
- technical outcome
- start and completion time
- previous receipt hash

Provider exceptions MUST produce a `FAILED` ExecutionReceipt without exposing raw error content in the canonical receipt payload. The error class may be recorded.

An ExecutionReceipt is evidence of the technical attempt. It does not prove intended outcome or value.

## Production requirement

`InMemoryConsumptionRegistry` is a process-local reference implementation only.

Production deployments MUST use a shared, durable and linearizable compare-and-set registry at the token's consumption domain. Multi-process or multi-region connectors MUST NOT rely on process-local memory.

Atomic token consumption prevents replay at the connector boundary. It does not alone guarantee distributed exactly-once external effect. Provider adapters MUST additionally use the bound execution identity as an idempotency key and SHOULD use a transactional outbox or equivalent durable receipt mechanism where supported.
