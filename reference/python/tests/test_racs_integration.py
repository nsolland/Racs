"""Tests for RACS authority management classes: AuthorityGrantIssuer, DelegationChain, and RevocationRegistry."""
import pytest
from racs_crypto import generate_keypair, load_private_key
from racs_authority import AuthorityGrantIssuer, DelegationChain, RevocationRegistry
from jsonschema.exceptions import ValidationError

@pytest.fixture()
def setup_issuer():
    priv, _ = generate_keypair()
    return AuthorityGrantIssuer(
        issuer_id='issuer-1', tenant_id='tenant-1',
        private_key=load_private_key(priv), key_id='key-1'
    )

@pytest.fixture()
def delegation_chain():
    return DelegationChain()

@pytest.fixture()
def revocation_registry():
    return RevocationRegistry()


def test_authority_integration(setup_issuer):
    grant = setup_issuer.issue_grant(
        grantee_id='delegated-grantee-1',
        allowed_actions=["read"],
        resource_scope={"resource_id": "resource-1"},
        standing_ref="valid-standing-ref"
    )

    delegation_chain = DelegationChain()
    delegation_chain.add_grant(grant)

    # Perform assertions to confirm delegation added successfully
    assert len(delegation_chain.delegations) == 1
    assert delegation_chain.delegations[0]["grantee_id"] == "delegated-grantee-1"


def test_revocation_registry(setup_issuer):
    revocation_registry = RevocationRegistry()

    # Create and revoke the grant
    grant = setup_issuer.issue_grant(
        grantee_id='revoked-grantee-1',
        allowed_actions=["write"],
        resource_scope={"resource_id": "resource-1"},
        standing_ref="revocation-standing-ref"
    )
    revocation_registry.revoke(grant)

    # Check if the grant is properly revoked
    assert revocation_registry.is_revoked(grant["grant_id"])
    assert len(revocation_registry.registry) == 1

    # Generate a snapshot of current state
    snapshot = revocation_registry.generate_snapshot()
    assert snapshot["sequence"] == 1
