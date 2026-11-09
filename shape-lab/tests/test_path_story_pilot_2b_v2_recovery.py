"""Model-free checks for the pinned path-story slot-3 cost reconciliation."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import path_story_pilot_2b_v2 as pilot
from experiment_controller import path_story_pilot_2b_v2_recovery as recovery


class PathStoryV2RecoveryTests(unittest.TestCase):
    def test_exact_archive_proves_priceable_upstream_responses(self) -> None:
        expected = recovery._expected()
        self.assertEqual(expected["classification"], "infrastructure_invalid_controller_error")
        self.assertEqual(expected["upstream_responses_with_usage"], 193)
        self.assertEqual(expected["downstream_finishes"], 192)
        self.assertEqual(expected["last_response_request_id"], 193)
        self.assertEqual(expected["cost_evidence"]["estimated_cost_usd"], "9.785370680")
        self.assertFalse(expected["archive_modified"])
        with patch.object(recovery, "GATEWAY_SHA256", "0" * 64):
            with self.assertRaises(pilot.PilotIntegrityError):
                recovery._expected()

    def test_committed_overlay_prices_once_and_keeps_attempt_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "slot3-reconciliation.json"
            with patch.object(recovery, "RECONCILIATION", path):
                frozen = recovery.freeze_reconciliation()
                self.assertEqual(recovery.load_reconciliation(), frozen)
                baseline = pilot.status(recovery.PILOT_ID)
                report = recovery.status()
                self.assertEqual(report["completed_slots"], baseline["completed_slots"])
                self.assertEqual(report["next_slot"], baseline["next_slot"])
                self.assertEqual(report["invalid_attempts"], baseline["invalid_attempts"])
                self.assertIn({
                    "slot": 3,
                    "run_id": recovery.RUN_ID,
                    "reason": "controller_error",
                }, report["invalid_attempts"])
                self.assertEqual(
                    report["funding"]["attempts_priced"],
                    baseline["funding"]["attempts_priced"] + 1,
                )
                self.assertEqual(
                    Decimal(report["funding"]["accrued_usd"]),
                    Decimal(baseline["funding"]["accrued_usd"])
                    + Decimal("9.785370680"),
                )
                self.assertEqual(
                    report["funding"]["errors"],
                    [row for row in baseline["funding"]["errors"]
                     if row["run_id"] != recovery.RUN_ID],
                )
                with patch.object(pilot, "fingerprint", side_effect=AssertionError("Docker touched")) as guarded:
                    with self.assertRaisesRegex(ValueError, "max_new_runs"):
                        recovery.execute(max_new_runs=0)
                    guarded.assert_not_called()
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaises(pilot.PilotIntegrityError):
                    recovery.load_reconciliation()


if __name__ == "__main__":
    unittest.main()
