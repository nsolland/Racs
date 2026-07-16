"""RACS Draft 0.2 Ed25519 signing primitives.

Minimal, dependency-light wrapper around ``cryptography`` for issuing and
verifying canonical signed artifacts. Signing uses the RACS-JCS-1 signature
input defined in ``racs_canonical.signature_input_bytes`` (the signature value
is zeroed before canonicalization).
"""

from __future__ import annotations

import base64
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from racs_canonical import signature_input_bytes


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private_pem, public_pem) as PEM-encoded bytes."""
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_pem, pub_pem


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem)


def sign_artifact(artifact: dict, private_key: Ed25519PrivateKey) -> None:
    """Sign *artifact* in place, writing ``artifact["signature"]["value"]``.

    Raises ``CanonicalizationError`` if the artifact lacks a signature object.
    """
    signature_input_bytes(artifact)  # validates structure + zeroes value
    digest = signature_input_bytes(artifact)
    sig = private_key.sign(digest)
    artifact["signature"]["value"] = base64.b64encode(sig).decode("ascii")


def verify_artifact_signature(artifact: dict, public_key: Ed25519PublicKey) -> bool:
    """Return True iff the artifact signature verifies under *public_key*."""
    try:
        digest = signature_input_bytes(artifact)
    except Exception:
        return False
    raw = artifact.get("signature", {}).get("value")
    if not isinstance(raw, str):
        return False
    try:
        sig = base64.b64decode(raw, validate=True)
    except Exception:
        return False
    try:
        public_key.verify(sig, digest)
        return True
    except (InvalidSignature, Exception):
        return False


__all__ = [
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "sign_artifact",
    "verify_artifact_signature",
]
