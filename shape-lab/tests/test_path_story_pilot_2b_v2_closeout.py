"""Model-free closeout checks for the second gateway reply boundary failure."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import path_story_pilot_2b_v2 as pilot
from experiment_controller import path_story_pilot_2b_v2_closeout as closeout


class PathStoryV2CloseoutTests(unittest.TestCase):
    def test_real_archive_reconciles_cost_without_validating_slot(self) -> None:
        run_dir = pilot.LAB / "runs" / closeout.RUN_ID
        fixed = [
            pilot.pilot_dir(closeout.PILOT_ID) / "schedule.json",
            run_dir / "result.json",
            run_dir / "attempt-manifest.json",
            run_dir / "gateway-events.jsonl",
        ]
        before = {str(path): pilot._sha(path) for path in fixed}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(closeout, "RECONCILIATION", Path(temporary) / "slot4.json"):
                record = closeout.freeze_reconciliation()
                self.assertEqual(record["cost_evidence"]["estimated_cost_nano_usd"], 8_913_747_080)
                self.assertEqual(record["upstream_responses_with_usage"], 132)
                self.assertEqual(record["downstream_finishes"], 131)
                self.assertEqual(record["classification"], "infrastructure_invalid_controller_error")
                self.assertEqual(closeout.freeze_reconciliation(), record)
                status = closeout.status()
        self.assertEqual(status["completed_slots"], [1, 2, 3])
        self.assertEqual(status["next_slot"], 4)
        self.assertEqual(status["invalid_attempts"][-1], {
            "slot": 4, "run_id": closeout.RUN_ID, "reason": "controller_error",
        })
        self.assertEqual(status["phase"], "paused_repeated_gateway_closeout")
        self.assertFalse(status["execution_available"])
        self.assertFalse(status["funding"]["may_start_new_run"])
        self.assertEqual(status["funding"]["accounting_state"], "complete")
        self.assertEqual(status["funding"]["accrued_usd"], "46.339601000")
        self.assertEqual(status["funding"]["remaining_usd"], "53.660399000")
        self.assertEqual(status["funding"]["attempts_priced"], 5)
        self.assertEqual(status["funding"]["errors"], [])
        self.assertEqual({str(path): pilot._sha(path) for path in fixed}, before)

    def test_raw_gateway_hash_mismatch_fails_closed(self) -> None:
        with patch.object(closeout, "GATEWAY_SHA256", "0" * 64):
            with self.assertRaisesRegex(pilot.PilotIntegrityError, "gateway-events.jsonl"):
                closeout._expected()


if __name__ == "__main__":
    unittest.main()
