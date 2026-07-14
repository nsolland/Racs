# RACS Trust Model

Status: Draft 0.2 normative baseline

## Trust principle

No artifact is authoritative because it is well-formed, locally constructed or contains a positive decision. Authoritative use requires a valid signature from an issuer trusted for that artifact type, tenant, trust domain and validity period.

## Required trust registry fields

A trust registry entry MUST contain:

- `issuer_id`
- `issuer_role`
- `tenant_scope`
- `trust_domain`
- `allowed_artifact_types`
- `key_id`
- `algorithm`
- `public_key`
- `valid_from`
- `valid_until`
- `revocation_status`
- `revoked_at`
- `registry_version`
- registry issuer and signature

## Canonical issuer roles

- `AUTHORITY_PROVIDER`
- `EVIDENCE_PROVIDER`
- `VAIG_EVALUATOR`
- `REHT_CLEARANCE_ISSUER`
- `CORE_ENFORCER`
- `CONNECTOR_EXECUTOR`
- `OUTCOME_OBSERVER`
- `SETTLEMENT_ISSUER`
- `REVOCATION_AUTHORITY`

## Fail-closed rules

The verifier MUST reject authoritative use when any of the following is true:

- issuer is unknown
- key is unknown, expired or revoked
- issuer is not allowed to issue the artifact type
- tenant or trust domain does not match
- schema version is unknown
- canonicalization profile is unknown
- signature is missing or invalid
- payload digest does not match
- artifact is expired, revoked or superseded
- a required referenced artifact cannot be resolved and verified

## GovernanceClearance issuer rule

Only an issuer registered as `REHT_CLEARANCE_ISSUER` may issue a `GovernanceClearance`. VAIG evaluation artifacts may be referenced by a clearance but cannot themselves authorize execution.

## Core enforcement rule

A CoreExecutionPermit is accepted only when:

1. its signature is valid,
2. its GovernanceClearance reference and digest resolve,
3. the clearance was issued by an authorized REHT issuer,
4. all action, target, payload, purpose, authority, policy, evidence and state digests match,
5. replay and idempotency identities are unused,
6. the permit remains within its validity interval,
7. no relevant revocation event is effective.

## Revocation

Revocation is represented by signed append-only events. Mutable local fields are not an authoritative revocation mechanism. A verifier MUST consult the required revocation registry before consequence-bearing execution.
