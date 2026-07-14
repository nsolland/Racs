from __future__ import annotations

import json
from pathlib import Path
import unittest

from racs_canonical import canonical_json_bytes, sha256_digest


ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "test-vectors" / "0.2" / "governance-clearance-payload.json"
EXPECTED = ROOT / "test-vectors" / "0.2" / "governance-clearance-payload.sha256"


class CanonicalizationTests(unittest.TestCase):
    def test_governance_clearance_digest_vector(self) -> None:
        payload = json.loads(VECTOR.read_text(encoding="utf-8"))
        expected = EXPECTED.read_text(encoding="utf-8").strip()
        self.assertEqual(sha256_digest(payload), f"sha256:{expected}")

    def test_object_order_does_not_change_bytes(self) -> None:
        self.assertEqual(
            canonical_json_bytes({"b": 2, "a": 1}),
            canonical_json_bytes({"a": 1, "b": 2}),
        )

    def test_whitespace_is_not_emitted(self) -> None:
        self.assertEqual(canonical_json_bytes({"a": [1, 2]}), b'{"a":[1,2]}')


if __name__ == "__main__":
    unittest.main()
