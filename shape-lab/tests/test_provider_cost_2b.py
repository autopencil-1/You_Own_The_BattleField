"""Model-free checks for admission-only provider-cost governance."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from experiment_controller.provider_cost_2b import (
    admission_decision,
    estimate_archived_run_cost,
    estimate_gateway_events_cost,
    estimate_usage_cost,
    gateway_usage,
)
from experiment_controller.support_pilot_2b_candidate_contract import load_contract


class ProviderCost2BTests(unittest.TestCase):
    def setUp(self) -> None:
        self.governance = load_contract()["provider_cost_governance"]

    def test_frozen_rates_price_reported_usage_exactly(self) -> None:
        observed = estimate_usage_cost(
            {
                "model_calls": 2,
                "input_tokens": 1_000_000,
                "output_tokens": 1_000_000,
                "cache_read_input_tokens": 1_000_000,
                "cache_creation_input_tokens": 0,
            },
            self.governance,
        )
        self.assertEqual(observed["estimated_cost_usd"], "6.060000000")
        self.assertEqual(observed["estimated_cost_nano_usd"], 6_060_000_000)

    def test_cache_creation_is_charged_at_ordinary_input_rate(self) -> None:
        observed = estimate_usage_cost(
            {
                "model_calls": 1,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 1_000_000,
            },
            self.governance,
        )
        self.assertEqual(observed["input_rate_tokens"], 1_000_000)
        self.assertEqual(observed["estimated_cost_usd"], "1.400000000")

    def test_gateway_accounting_is_aggregate_and_fails_closed_without_usage(self) -> None:
        events = [
            {
                "event_type": "model_call",
                "status": 200,
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "cache_read_input_tokens": 5,
                    "cache_creation_input_tokens": 1,
                },
            },
            {"event_type": "model_call", "status": 429, "usage": None},
        ]
        usage = gateway_usage(events)
        self.assertEqual(usage["model_calls"], 1)
        self.assertEqual(usage["total_tokens"], 18)
        self.assertNotIn("arm", estimate_gateway_events_cost(events, self.governance))
        with self.assertRaisesRegex(ValueError, "lacks provider usage"):
            gateway_usage([{"event_type": "model_call", "status": 200}])

    def test_admission_pauses_only_before_a_new_run(self) -> None:
        exact = admission_decision(85_000_000_000, self.governance)
        self.assertTrue(exact["may_start_new_run"])
        self.assertEqual(exact["state"], "admitted")
        paused = admission_decision(85_000_000_001, self.governance)
        self.assertFalse(paused["may_start_new_run"])
        self.assertEqual(paused["state"], "paused_insufficient_reserve")
        self.assertFalse(paused["active_run_termination_allowed"])
        self.assertFalse(paused["creates_trial_attempt"])
        self.assertFalse(paused["creates_censored_outcome"])

    def test_completed_archive_cost_uses_gateway_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "mode": "support_pilot",
                        "run_id": "2b-supp-cost-fixture",
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "gateway-events.jsonl").write_text(
                json.dumps(
                    {
                        "event_type": "model_call",
                        "status": 200,
                        "usage": {
                            "input_tokens": 1_000_000,
                            "output_tokens": 0,
                            "cache_read_input_tokens": 0,
                            "cache_creation_input_tokens": 0,
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            observed = estimate_archived_run_cost(run_dir, self.governance)
            self.assertEqual(observed["run_id"], "2b-supp-cost-fixture")
            self.assertEqual(observed["estimated_cost_usd"], "1.400000000")


if __name__ == "__main__":
    unittest.main()
