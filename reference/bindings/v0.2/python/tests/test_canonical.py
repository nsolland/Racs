"""Cross-language canonicalization gate tests for RACS v0.2 Python binding (3A).

These tests verify that this Python binding reproduces the OFFICIAL RFC 8785
vectors and the shared RACS GovernanceEvaluation vector byte-for-byte, with an
identical SHA-256 digest. The same vectors are run by the Rust and TypeScript
bindings; CI asserts all three produce identical canonical bytes + digest.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from racs_v02.canonical import canonical_bytes, canonical_str
from racs_v02.digest import sha256_digest, verify_payload_digest

REPO_ROOT = Path(__file__).resolve().parents[5]
OFFICIAL_DIR = REPO_ROOT / "test-vectors" / "jcs" / "official"
RACS_DIR = REPO_ROOT / "test-vectors" / "jcs" / "racs-v0.2"


def _official_vectors():
    files = sorted(OFFICIAL_DIR.glob("vector-*.json"))
    assert files, f"no official JCS vectors found in {OFFICIAL_DIR}"
    return [json.load(open(f)) for f in files]


@pytest.mark.parametrize("vec", _official_vectors(), ids=lambda v: v["name"])
def test_official_jcs_vectors(vec):
    got_canon = canonical_str(vec["input"])
    got_digest = sha256_digest(vec["input"])
    assert got_canon == vec["expected_canonical"], (
        f"canonical mismatch:\n got={got_canon}\n exp={vec['expected_canonical']}"
    )
    assert got_digest == vec["expected_digest"]
    # also assert the digest is over the canonical bytes
    assert got_digest == "sha256:" + __import__("hashlib").sha256(
        canonical_bytes(vec["input"])
    ).hexdigest()


def test_racs_governance_evaluation_vector():
    vec = json.load(open(RACS_DIR / "governance-evaluation.json"))
    assert canonical_str(vec["payload"]) == vec["canonical_payload"]
    assert sha256_digest(vec["payload"]) == vec["payload_digest"]
    assert verify_payload_digest(vec) is True


def test_racs_vector_digest_is_rfc8785_not_json_dumps():
    """Guard: ensure we are NOT using json.dumps(sort_keys=True), which is not
    RFC 8785-conformant. We check the RFC 8785 specifics:
      - integer-valued float 1.0 renders as "1" (not "1.0")
      - -0.0 renders as "0" (not "-0.0")
      - 1e-9 renders as "1e-9" (not "1e-09")
      - non-ASCII is serialized "as is" (NOT escaped) per RFC 8785 3.2.2.2
        (e.g. € stays €, not \\u20AC)
    """
    import json as _json

    edge = {"a": -0.0, "b": 1e-9, "c": "€"}
    rfc = canonical_str(edge)
    dumps = _json.dumps(edge, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert rfc != dumps, "RFC 8785 output accidentally equals non-conformant json.dumps"
    # RFC 8785 specifics:
    assert '"a":0' in rfc, "RFC 8785 must render -0.0 as 0"
    assert '"b":1e-9' in rfc, "RFC 8785 must use shortest exponent form"
    assert "€" in rfc, "RFC 8785 serializes non-ASCII 'as is' (not \\uXXXX)"
