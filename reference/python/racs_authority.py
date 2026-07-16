import os
import json
import jsonschema
import os
import json
import jsonschema
from racs_crypto import Ed25519PrivateKey, sign_artifact
from racs_canonical import sha256_digest

class AuthorityGrantIssuer:
    """Issues Authority Grants with specific scopes, delegations, and conditions."""

    def __init__(self, issuer_id: str, tenant_id: str, private_key: Ed25519PrivateKey, key_id: str):
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.private_key = private_key
        self.key_id = key_id

    def issue_grant(self, grantee_id: str, allowed_actions: list, resource_scope: dict, standing_ref: str) -> dict:
        """Create a grant for a specific grantee and allowed actions."""
        if not isinstance(standing_ref, str):  # Validate type for standing_ref
            raise ValueError("standing_ref must be a string.")
        grant = {
            "grant_id": f"grant-{self.tenant_id}",
            "tenant_id": self.tenant_id,
            "grantor_id": self.issuer_id,
            "grantee_id": grantee_id,
            "standing_ref": standing_ref,
            "allowed_action_types": allowed_actions,
            "resource_scope": resource_scope,
            "delegation_allowed": True,
            "max_delegation_depth": 5,
            "valid_from": "2026-07-14T00:00:00Z",
            "valid_until": "2026-08-14T00:00:00Z",
            "revocation_registry_ref": "snapshot-1",
            "signature": {
                "value": None  # Initialize placeholder
            }
        }
        grant["signature"]["value"] = self.sign(grant)
        return grant

    def sign(self, grant: dict) -> str:
        return sign_artifact(grant, self.private_key)

class DelegationChain:
    """Manages a chain of delegated authorities based on previous grants."""
    def __init__(self):
        self.delegations = []

    def add_grant(self, grant: dict) -> None:
        self.delegations.append(grant)  # Store delegated grant for processing

class RevocationRegistry:
    """Tracks revoked grants and maintains snapshots of the registry state."""
    def __init__(self):
        self.registry = []

    def revoke(self, grant: dict) -> None:
        self.registry.append(grant)  # Record revoked grant in registry
    
    def is_revoked(self, grant_id: str) -> bool:
        return any(g['grant_id'] == grant_id for g in self.registry)  # Check if grant is revoked

    def generate_snapshot(self) -> dict:
        return {
            "registry_id": "revocation-registry-1",
            "tenant_id": "tenant-acme",
            "trust_domain": "trust-domain-acme",
            "sequence": len(self.registry),
            "generated_at": "2026-07-14T00:00:00Z",
            "valid_until": "2027-07-14T00:00:00Z",
            "previous_snapshot_digest": sha256_digest(self.registry),
            "revocations": self.registry
        }

class AuthorityGrantIssuer:
    """Issues Authority Grants with specific scopes, delegations, and conditions."""

    def __init__(self, issuer_id: str, tenant_id: str, private_key: Ed25519PrivateKey, key_id: str):
        self.issuer_id = issuer_id
        self.tenant_id = tenant_id
        self.private_key = private_key
        self.key_id = key_id

    def issue_grant(self, grantee_id: str, allowed_actions: list, resource_scope: dict, standing_ref: str) -> dict:
        """Create a grant for a specific grantee and allowed actions."""
        if not isinstance(standing_ref, str):  # Validate type for standing_ref
            raise ValueError("standing_ref must be a string.")
        grant = {
            "grant_id": f"grant-{self.tenant_id}",
            "tenant_id": self.tenant_id,
            "grantor_id": self.issuer_id,
            "grantee_id": grantee_id,
            "standing_ref": standing_ref,
            "allowed_action_types": allowed_actions,
            "resource_scope": resource_scope,
            "delegation_allowed": True,
            "max_delegation_depth": 5,
            "valid_from": "2026-07-14T00:00:00Z",
            "valid_until": "2026-08-14T00:00:00Z",
            "revocation_registry_ref": "snapshot-1",
            "signature": {
                "value": None  # Initialize placeholder
            }
        }
        grant["signature"]["value"] = self.sign(grant)
        return grant

    def sign(self, grant: dict) -> str:
        return sign_artifact(grant, self.private_key)

class DelegationChain:
    """Manages a chain of delegated authorities based on previous grants."""
    def __init__(self):
        self.delegations = []

    def add_grant(self, grant: dict) -> None:
        self.delegations.append(grant)  # Store delegated grant for processing

class RevocationRegistry:
    """Tracks revoked grants and maintains snapshots of the registry state."""
    def __init__(self):
        self.registry = []

    def revoke(self, grant: dict) -> None:
        self.registry.append(grant)  # Record revoked grant in registry
    
    def is_revoked(self, grant_id: str) -> bool:
        return any(g['grant_id'] == grant_id for g in self.registry)  # Check if grant is revoked

    def generate_snapshot(self) -> dict:
        return {
            "registry_id": "revocation-registry-1",
            "tenant_id": "tenant-acme",
            "trust_domain": "trust-domain-acme",
            "sequence": len(self.registry),
            "generated_at": "2026-07-14T00:00:00Z",
            "valid_until": "2027-07-14T00:00:00Z",
            "previous_snapshot_digest": sha256_digest(self.registry),
            "revocations": self.registry
        }