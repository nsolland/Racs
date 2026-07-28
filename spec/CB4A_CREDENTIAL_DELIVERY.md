# CB4A Credential Delivery Specification

## Overview

This document defines the RACS artifacts for CB4A (Credential Broker for Agents) compatible clearance-bound credential delivery. These artifacts enable secure credential delivery that is bound to specific governance clearances without making RACS itself a credential broker, IAM system, or authorization authority.

## Design Principles

1. **Boundary Definition**: RACS defines the contract and structure for credential delivery records, but does not implement credential brokering itself.
2. **Clearance Binding**: All credential deliveries are explicitly bound to a signed REHT GovernanceClearance.
3. **No Authority Assumption**: RACS does not make authorization decisions; it only defines the structure for recording credential delivery events.
4. **Revocation Support**: All credential deliveries include revocation hooks for proper lifecycle management.

## Artifacts

### 1. Clearance-Bound Credential Delivery

The `ClearanceBoundCredentialDelivery` artifact records the details of a credential delivery that is bound to a specific REHT GovernanceClearance.

Key fields:
- `delivery_id`: Unique identifier for the delivery record
- `clearance_id`: Identifier of the governing clearance
- `requesting_principal`: Identity of the requesting entity
- `scoped_resource`: The specific resource the credential accesses
- `lease_duration_seconds`: Time-limited validity of the delivery
- `revocation_hook`: Endpoint for revoking the delivery if needed

### 2. Credential Lease

The `CredentialLease` artifact represents the actual credential lease that is issued as a result of an approved delivery request.

Key fields:
- `lease_id`: Unique identifier for the lease
- `issuer`: Entity that issued the lease
- `subject`: Principal to whom the lease is issued
- `bound_clearance_id`: Reference to the governing clearance
- `token_reference`: Secure reference to the actual credential token
- `valid_from`/`valid_until`: Temporal bounds of the lease

## Relationship to CB4A

These artifacts align with the patterns defined in the CB4A draft (draft-hartman-credential-broker-4-agents-00) while maintaining RACS' role as a specification standard rather than an implementation. RACS provides the normative artifacts that implementations can use to ensure interoperability.

## Implementation Boundary

RACS defines WHAT a clearance-bound credential delivery looks like, not HOW it is implemented. Implementation details are left to the ExecutionSubstrate layer in valo-platform, ensuring proper separation of concerns.