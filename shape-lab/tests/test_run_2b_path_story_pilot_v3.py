"""Model-free checks for separated provider and downstream closeout."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from experiment_controller import run_2b_path_story_pilot_v3 as runner


def _rows(*items: dict) -> list[dict]:
    return [{"sequence": index, **item} for index, item in enumerate(items, 1)]


class PathStoryV3RunnerTests(unittest.TestCase):
    def test_completed_provider_response_and_downstream_finish(self) -> None:
        events = _rows(
            {"event_type": "request_started", "request_id": 1},
            {"event_type": "model_call", "request_id": 1, "call_number": 1,
             "attempt_number": 1, "status": 200, "usage": {"input_tokens": 2, "output_tokens": 3}},
            {"event_type": "provider_response_complete", "request_id": 1,
             "call_number": 1, "attempt_number": 1, "status": 200,
             "usage_recorded": True},
            {"event_type": "request_finished", "request_id": 1},
        )
        lifecycle = runner._gateway_lifecycle(events)
        self.assertEqual(lifecycle["provider_completed_request_count"], 1)
        self.assertEqual(lifecycle["finished_request_count"], 1)
        self.assertEqual(lifecycle["unaccounted_request_ids"], [])
        with patch.object(runner, "_events", return_value=events), patch.object(
            runner, "MIN_GATEWAY_QUIET_SECONDS", 0
        ):
            settlement = runner._settle_gateway("local", {}, max_wait_seconds=1)
        self.assertEqual(settlement["state"], "complete")

    def test_wall_cap_downstream_failure_remains_priceable(self) -> None:
        events = _rows(
            {"event_type": "request_started", "request_id": 1},
            {"event_type": "model_call", "request_id": 1, "call_number": 1,
             "attempt_number": 1, "status": 200, "usage": {"input_tokens": 2, "output_tokens": 3}},
            {"event_type": "provider_response_complete", "request_id": 1,
             "call_number": 1, "attempt_number": 1, "status": 200,
             "usage_recorded": True},
            {"event_type": "downstream_delivery_failed", "request_id": 1,
             "error_type": "BrokenPipeError"},
        )
        lifecycle = runner._gateway_lifecycle(events)
        self.assertEqual(lifecycle["downstream_delivery_failed_ids"], [1])
        self.assertEqual(lifecycle["unaccounted_request_ids"], [])
        self.assertEqual(lifecycle["unmatched_request_ids"], [])
        with patch.object(runner, "_events", return_value=events), patch.object(
            runner, "MIN_GATEWAY_QUIET_SECONDS", 0
        ):
            settlement = runner._settle_gateway("local", {}, max_wait_seconds=1)
        self.assertEqual(settlement["state"], "complete")

    def test_missing_provider_completion_cannot_clear_cost_pause(self) -> None:
        events = _rows(
            {"event_type": "request_started", "request_id": 1},
            {"event_type": "model_call", "request_id": 1, "call_number": 1,
             "attempt_number": 1, "status": 200, "usage": {"input_tokens": 2}},
            {"event_type": "downstream_delivery_failed", "request_id": 1},
        )
        self.assertEqual(runner._gateway_lifecycle(events)["unaccounted_request_ids"], [1])
        with patch.object(runner, "_events", return_value=events):
            settlement = runner._settle_gateway("local", {}, max_wait_seconds=1)
        self.assertEqual(settlement["state"], "incomplete")
        with self.assertRaisesRegex(ValueError, "matching usage"):
            runner._gateway_lifecycle(_rows(
                events[0], events[1],
                {"event_type": "provider_response_complete", "request_id": 1,
                 "call_number": 1, "attempt_number": 1, "status": 200,
                 "usage_recorded": False},
            ))

    def test_local_rejection_is_accounted_without_provider_call(self) -> None:
        events = _rows(
            {"event_type": "request_started", "request_id": 1},
            {"event_type": "request_rejected", "request_id": 1,
             "method": "POST", "status": 400},
            {"event_type": "request_finished", "request_id": 1},
        )
        lifecycle = runner._gateway_lifecycle(events)
        self.assertEqual(lifecycle["local_rejection_request_count"], 1)
        self.assertEqual(lifecycle["provider_completed_request_count"], 0)
        self.assertEqual(lifecycle["unaccounted_request_ids"], [])

    def test_gateway_error_still_pauses_accounting(self) -> None:
        events = _rows(
            {"event_type": "request_started", "request_id": 1},
            {"event_type": "gateway_error", "request_id": 1},
            {"event_type": "request_finished", "request_id": 1},
        )
        self.assertEqual(runner._gateway_lifecycle(events)["unaccounted_request_ids"], [1])
        with patch.object(runner, "_events", return_value=events):
            self.assertEqual(
                runner._settle_gateway("local", {}, max_wait_seconds=1)["state"],
                "incomplete",
            )


if __name__ == "__main__":
    unittest.main()
