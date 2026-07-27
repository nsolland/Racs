import importlib.util
from pathlib import Path
import sys
import unittest

HELPER = Path(__file__).with_name("test_distributed_authority_v0_1.py")
spec = importlib.util.spec_from_file_location("distributed_authority_test_helpers", HELPER)
helpers = importlib.util.module_from_spec(spec)
sys.modules.setdefault("distributed_authority_test_helpers", helpers)
spec.loader.exec_module(helpers)

distributed = helpers.distributed


class DistributedAuthorityBypassConformance(unittest.TestCase):
    def test_legacy_or_hierarchy_bypassing_clearance_cannot_consume_authority(self):
        mandate, grant, state, snapshot, action = helpers.fixtures()
        clearance = helpers.evaluate(mandate, grant, state, snapshot, action, [])

        legacy = dict(clearance)
        legacy["receipt_version"] = "distributed-authority-0.1"
        legacy.pop("receipt_digest")
        legacy["receipt_digest"] = distributed.digest(legacy)
        with self.assertRaisesRegex(distributed.GovernanceError, "unsupported"):
            distributed.apply_authority_transition(
                grant, state, legacy, "2026-07-27T05:01:00Z"
            )

        bypass = dict(clearance)
        bypass["evaluated_gate_ids"] = ["constitution", "purpose"]
        bypass.pop("receipt_digest")
        bypass["receipt_digest"] = distributed.digest(bypass)
        with self.assertRaisesRegex(distributed.GovernanceError, "bypassed"):
            distributed.apply_authority_transition(
                grant, state, bypass, "2026-07-27T05:01:00Z"
            )


if __name__ == "__main__":
    unittest.main()
