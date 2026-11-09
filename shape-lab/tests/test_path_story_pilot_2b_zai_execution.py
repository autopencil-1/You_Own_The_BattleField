"""Model-free admission checks for the shared Coding Plan budget."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import unittest

from experiment_controller import path_story_pilot_2b_zai_execution as pilot


class ZaiAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)

    def row(self, credits: str, age: timedelta) -> dict:
        return {
            "credits": Decimal(credits),
            "finished_utc": (self.now - age).isoformat(),
        }

    def test_invalid_attempts_consume_the_same_credit_share(self) -> None:
        result = pilot.credit_admission([
            self.row("6500", timedelta(minutes=30)),
            self.row("1000", timedelta(minutes=20)),
        ], self.now)
        self.assertEqual(result["accrued_total"], "7500.000000000")
        self.assertEqual(result["remaining_rolling_five_hour"], "6500.000000000")
        self.assertFalse(result["admitted_by_local_share"])

    def test_five_hour_share_refreshes_but_total_never_resets(self) -> None:
        result = pilot.credit_admission([
            self.row("8000", timedelta(hours=5)),
            self.row("6000", timedelta(hours=1)),
        ], self.now)
        self.assertEqual(result["accrued_total"], "14000.000000000")
        self.assertEqual(result["accrued_rolling_five_hour"], "6000.000000000")
        self.assertTrue(result["admitted_by_local_share"])

    def test_total_share_blocks_another_run(self) -> None:
        result = pilot.credit_admission([
            self.row("28000", timedelta(hours=6)),
        ], self.now)
        self.assertEqual(result["remaining_total"], "7000.000000000")
        self.assertFalse(result["admitted_by_local_share"])


if __name__ == "__main__":
    unittest.main()
