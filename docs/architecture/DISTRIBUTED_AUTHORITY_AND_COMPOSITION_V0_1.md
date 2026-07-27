# GOS-002 — Distributed authority and compositional consequence control

## Purpose

GOS-002 extends the GOS-001 Governance OS vertical slice so separate execution
substrates can enforce locally against the same independently issued authority
without requiring every technical path to converge on one execution gateway.

The gate does not create, reinterpret or widen authority. It verifies a signed
authority grant, the current live authority state, the local snapshot and the
proposed consequential action. Authority consumption is committed through a
revisioned compare-and-set transition before execution.

## Canonical flow

`BoardIntent → ExecutableBusinessCase → EnterpriseMandate → AuthorityGrant → AuthorityState → LocalAuthoritySnapshot → GovernanceClearance → AuthorityTransition → ExecutionReceipt → Outcome`

The existing RACS evaluation, admissibility, constitutional hierarchy and clearance chain remains
canonical. GOS-002 supplies authority, evidence and consequence gate results to that hierarchy;
it cannot issue a parallel ALLOW outside the hierarchy.

## Contracts

### AuthorityGrant

An immutable organisational decision issued outside the agent, workflow and
gate. It binds:

- issuer and validity period;
- exact enterprise mandate digest;
- total consequence exposure;
- per-consequence count and exposure limits;
- explicitly forbidden consequence combinations;
- signature scheme, signature digest and verified result.

Signature verification is upstream and provider-neutral. An unverified grant is
inadmissible.

### AuthorityState

The live, mutable remainder of the grant:

- authority and mandate identity;
- monotonic revision;
- remaining exposure;
- revocation state;
- latest transition digest;
- update time.

Every allowed clearance proposes exactly one next revision. Applying it requires
compare-and-set against the current revision and remaining authority. Two gates
cannot validly consume the same revision.

### LocalAuthoritySnapshot

A substrate-local view of the current authority state. It must match the grant,
mandate, revision and substrate and remain inside the configured freshness
window. Stale or future snapshots fail closed.

### Canonical hierarchy binding

GOS-002 emits three hard gate results at the existing hierarchy levels:

- `distributed-authority` at `authority_mandate`;
- `distributed-evidence` at `evidence_representation`;
- `distributed-consequence` at `consequence`.

These are combined with upstream constitutional, purpose, rights and other gate
results and resolved by the canonical hierarchy. The clearance binds the profile,
full gate-result set and hierarchy decision digests. Only the canonical `ALLOW`
verdict may consume authority.

### GovernanceClearance receipt

The clearance binds the exact grant, state, local snapshot, action, prior
transition set, composition state, hierarchy result, exposure and proposed state
revision. It is not proof that execution occurred.

### AuthorityTransition receipt

The transition proves that an allowed clearance consumed authority in the
canonical live state. Transition receipts form a digest-linked, contiguous
revision chain across substrates.

### Execution receipt

Execution is recorded separately and must bind both the clearance and committed
authority transition. Reusing one clearance for a second execution is rejected.

## Compositional consequence controls

GOS-002 does not attempt to predict every technical route. It constrains the
consequences available along any route through:

- global exposure consumption;
- per-consequence count limits;
- per-consequence cumulative exposure limits;
- replay protection across substrates;
- forbidden combinations of consequence classes;
- digest-linked transition history.

This governs harmful accumulation, substitution and known combinations even
when technical paths do not share a gateway.

## Constitutional invariants

1. Human organisational authority remains final.
2. Authority is issued independently of the agent, workflow and gate.
3. The gate verifies authority; it never creates or reinterprets it.
4. Delegation and authority grants may only narrow the enterprise mandate.
5. Every consequential clearance binds the current live authority revision.
6. Authority consumption is atomic and monotonic.
7. Separate substrates enforce against the same current authority state.
8. Clearance, authority transition and execution are separate receipts.
9. Original receipts are immutable; later correction requires a new governed action.
10. Unknown or genuinely emergent harm is not represented as pre-execution proof.

## Explicit boundary

The reference implementation governs distributed execution where consequences
can be represented as declared classes, limits, accumulation or forbidden
combinations. It does not claim to certify all emergent harms whose harmful
property is absent from every individual action and cannot be declared or
observed before composition.

## Reference implementation

- `reference/distributed_authority_v0_1.py`
- `reference/test_distributed_authority_v0_1.py`

The implementation is deterministic, uses only the Python standard library and
fails closed on missing, stale, inconsistent, widened, replayed or tampered
authority evidence.
