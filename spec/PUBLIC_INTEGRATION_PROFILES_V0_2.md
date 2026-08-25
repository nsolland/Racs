# Public Integration Profiles (P0.2)

Status: NORMATIVE.

These profiles define role boundaries for implementations interoperating with RACS without requiring knowledge of any private product or repository topology.

## Authorization provider

Role: establishes the current authorization or admissibility basis for the exact proposed action under the governing system.

- Produces the required signed determination/clearance artifacts.
- Binds the exact action and any material governed-state references required by the declared profile.
- Supports current revocation and freshness semantics.
- Must not rely on RACS schema validity as a substitute for authority.

## Proposing client

Role: forms exact action envelopes and submits them for governed determination.

- May consume public RACS contracts and resulting permits.
- Must not issue a parallel authorization for its own proposed consequence.
- Must preserve required receipt and correlation references.

## Enforcement implementation

Role: mechanically enforces the bound decision at the effect boundary.

- Rejects invalid, stale, replayed or mismatched bindings before external effect.
- Applies only narrowing transformations explicitly allowed by the governing contract.
- Emits the public execution/evidence artifacts required by the selected profile.

## Shared rules

1. **No re-authorization.** A downstream implementation cannot widen or replace the admitted upstream authority basis.
2. **Exact contracts.** Implementations use the canonical public RACS schemas or declared interoperable mappings.
3. **Fail closed.** Failure to verify a required binding produces no external effect.
