"""P0.2 golden-vector digest test (issue #991).

Re-canonicalizes each pinned payload with RFC 8785 and asserts the SHA-256 digest is
byte-identical to the pinned value. This proves the same vector produces the same digest
across any RFC 8785 + SHA-256 implementation (PHP/JS/Py/Rust) — the P0.2 exit gate.
"""
import hashlib
import json
import os

import jsonschema
from jsoncanon import canonicalize

SPEC = os.path.join(os.path.dirname(__file__), "..", "spec")


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(obj)).hexdigest()


def load_vectors():
    with open(os.path.join(SPEC, "golden-vectors.json"), encoding="utf-8") as f:
        return json.load(f)["vectors"]


def test_golden_digests_byte_identical():
    vectors = load_vectors()
    assert vectors, "golden-vectors.json is empty"
    for name, body in vectors.items():
        got = digest(body["payload"])
        assert got == body["payload_digest"], (
            f"{name}: digest mismatch\n  got={got}\n  pin={body['payload_digest']}"
        )


def test_golden_payloads_validate_against_schema():
    """Each golden payload must validate against its canonical RACS schema (named in the vector)."""
    vectors = load_vectors()
    for name, body in vectors.items():
        schema_file = body.get("schema")
        if not schema_file:
            continue
        with open(os.path.join(SPEC, schema_file), encoding="utf-8") as f:
            schema = json.load(f)
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(instance=body["payload"], schema=schema)


def test_canonicalization_is_deterministic_across_key_order():
    a = {"b": 2, "a": 1, "c": [1.5, 2e3, 0.0001]}
    b = {"c": [1.5, 2000, 1e-4], "a": 1, "b": 2}
    assert digest(a) == digest(b), "key order must not affect digest"
