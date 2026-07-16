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


def test_grant_valid_schema(setup_issuer):
    grant = setup_issuer.issue_grant(
        grantee_id='grantee-1',
        allowed_actions=["read", "write"],
        resource_scope={"resource_id": "resource-1"},
        standing_ref="standing-1"  # Required parameter
    )
    assert grant["grantor_id"] == "issuer-1"
    assert grant["grantee_id"] == "grantee-1"
    assert "signature" in grant


def test_grant_invalid_schema(setup_issuer):
    invalid_values = [1234, None, True, ["not", "a", "string"], {"key": "value"}]  # Various invalid types
    for invalid in invalid_values:
        with pytest.raises(ValueError):  # Expecting to catch ValueError for inappropriate types
            setup_issuer.issue_grant(
                grantee_id='grantee-1',
                allowed_actions=["read", "write"],
                resource_scope={"resource_id": "resource-1"},
                standing_ref=invalid  # Passing different invalid types
            )
