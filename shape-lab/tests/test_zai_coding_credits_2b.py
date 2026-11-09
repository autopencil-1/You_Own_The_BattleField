"""Published Coding Plan credit arithmetic and fail-closed evidence checks."""

from __future__ import annotations

import unittest

from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits


def _call(timestamp: str, **changes: object) -> dict:
    value = {
        "event_type": "model_call", "provider": "zai", "model": "glm-5.3",
        "served_model": "glm-5.3", "path": "/v1/messages", "status": 200,
        "timestamp_utc": timestamp,
        "usage": {"input_tokens": 10000, "cache_creation_input_tokens": 0,
                  "cache_read_input_tokens": 10000, "output_tokens": 10000},
    }
    value.update(changes)
    return value


class CreditEstimateTests(unittest.TestCase):
    def test_peak_and_off_peak_boundaries(self) -> None:
        rows = [
            _call("2026-11-09T06:00:00Z"),
            _call("2026-11-09T10:00:00Z"),
            _call("2026-11-08T08:00:00Z"),
        ]
        value = estimate_gateway_events_credits(rows)
        self.assertEqual(value["peak_model_calls"], 1)
        self.assertEqual(value["off_peak_model_calls"], 2)
        self.assertEqual(value["estimated_peak_credits"], "32.600000000")
        self.assertEqual(value["estimated_off_peak_credits"], "32.600000000")
        self.assertEqual(value["estimated_total_credits"], "65.200000000")

    def test_unreported_or_changed_model_fails_closed(self) -> None:
        for changes in ({"usage": None}, {"served_model": "other"},
                        {"provider": "ollama"}, {"timestamp_utc": "bad"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                estimate_gateway_events_credits([_call("2026-11-09T06:00:00Z", **changes)])

    def test_non_billable_status_does_not_add_credits(self) -> None:
        value = estimate_gateway_events_credits([
            _call("2026-11-09T06:00:00Z", status=429, usage=None),
        ])
        self.assertEqual(value["model_calls"], 0)
        self.assertEqual(value["estimated_total_credits"], "0.000000000")


if __name__ == "__main__":
    unittest.main()
