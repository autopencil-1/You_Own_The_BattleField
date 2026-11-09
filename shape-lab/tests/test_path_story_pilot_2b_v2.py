"""Model-free funding amendment checks for the versioned path-story pilot."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import path_story_pilot_2b as old
from experiment_controller import path_story_pilot_2b_v2 as pilot
from experiment_controller import run_2b_path_story_pilot_v2 as runner
from telemetry import review_2b_path_story_pilot_v2 as review


class PathStoryPilotV2Tests(unittest.TestCase):
    def test_versioned_contract_preserves_task_and_review_protocol(self) -> None:
        contract = pilot.load_contract()
        self.assertEqual(contract["pilot_protocol"], "2b-path-story-pilot-v2")
        self.assertEqual(contract["task_sha256"], old._sha(old.TASK))
        self.assertEqual(contract["fixture_sha256"], old._sha(old.FIXTURE))
        self.assertEqual(contract["provider_cost_governance"]["minimum_uncommitted_reserve_per_new_run_usd"], "10.000000000")
        self.assertEqual(contract["provider_cost_governance"]["maximum_total_authorization_usd"], "100.000000000")
        self.assertFalse(contract["provider_cost_governance"]["active_run_cost_termination"])
        self.assertEqual(review.PILOT_PROTOCOL, contract["pilot_protocol"])
        self.assertNotEqual(contract["pilot_protocol"], old.PROTOCOL)

    def test_new_schedule_and_cumulative_authorization_ceiling(self) -> None:
        contract = pilot.load_contract()
        images = {role: f"sha256:{index:064x}" for index, role in enumerate(pilot.IMAGES, 1)}
        frozen = {
            "agent_task_sha256": pilot._sha(pilot.TASK),
            "fixture_sha256": pilot._sha(pilot.FIXTURE),
            "images": images,
        }
        preflights = [
            {
                "status": "passed", "arm": arm,
                "seed_sha256": hashlib.sha256(contract["block_seeds"][block].encode()).hexdigest(),
                "images": images, "model_calls": 0, "agent_started": False,
            }
            for block, arm in (("1", "B0"), ("2", "B3"))
        ]
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(pilot, "STUDIES", Path(temporary)),
                patch.object(pilot, "build_images", return_value=b"model-free\n"),
                patch.object(pilot, "fingerprint", return_value=frozen),
                patch("experiment_controller.run_2b_path_story_pilot_v2.preflight_no_model", side_effect=preflights),
            ):
                schedule = pilot.prepare(randomization_seed="v1-fixed-assignment-seed")
                pilot_id = schedule["pilot_id"]
                self.assertEqual(schedule["execution_policy"]["minimum_uncommitted_reserve_usd"], "10.000000000")
                self.assertEqual(schedule["execution_policy"]["maximum_total_authorization_usd"], "100.000000000")
                self.assertEqual(pilot.status(pilot_id)["funding"]["authorized_usd"], "0.000000000")
                with patch.object(pilot, "fingerprint", side_effect=AssertionError("Docker touched")):
                    with self.assertRaisesRegex(pilot.PilotIntegrityError, "awaits an explicit"):
                        pilot.execute(pilot_id, max_new_runs=1)
                funded = pilot.authorize(pilot_id, "100.000000000")
                self.assertEqual(funded["funding"]["required_reserve_usd"], "10.000000000")
                self.assertEqual(funded["funding"]["authorization_ceiling_usd"], "100.000000000")
                self.assertTrue(funded["funding"]["may_start_new_run"])
                with self.assertRaisesRegex(ValueError, "exceed the \\$100 pilot ceiling"):
                    pilot.authorize(pilot_id, "0.000000001")
                self.assertEqual(len(pilot._tranches(pilot_id)), 1)

    def test_cost_admission_boundary_is_ten_dollars(self) -> None:
        run_id = "2b-path-20261109123456-abcdef"
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "gateway-events.jsonl").write_text("", encoding="utf-8")
            result = {"manifest": {
                "run_id": run_id,
                "provider_settlement": {
                    "state": "complete", "started_request_count": 0,
                    "finished_request_count": 0,
                    "aborted_request_ids": [], "unmatched_request_ids": [],
                    "max_wait_seconds": 190, "quiet_seconds_observed": 5,
                },
            }}
            for cents, admitted in ((90_000_000_000, True), (90_000_000_001, False)):
                with (
                    patch.object(pilot, "_tranches", return_value=[{"amount_nano_usd": 100_000_000_000}]),
                    patch.object(pilot, "_verify_attempt_artifacts", return_value=run_dir),
                    patch.object(pilot, "estimate_gateway_events_cost", return_value={
                        "estimated_cost_nano_usd": cents,
                        "estimated_cost_usd": pilot._format_nano_usd(cents),
                    }),
                ):
                    snapshot = pilot._cost_snapshot("unused", {1: [result]})
                self.assertEqual(snapshot["may_start_new_run"], admitted)
                self.assertEqual(snapshot["required_reserve_usd"], "10.000000000")

    def test_runner_accepts_v2_protocol_and_frozen_sources(self) -> None:
        contract = pilot.load_contract()
        images = {"decoy": "sha256:" + "a" * 64, "gateway": "sha256:" + "b" * 64, "agent": "sha256:" + "c" * 64}
        frozen = {
            "agent_task_sha256": runner._sha(runner.TASK),
            "fixture_sha256": runner._sha(runner.FIXTURE),
            "compose_sha256": {
                path.name: runner._sha(path)
                for path in (runner.BASE_COMPOSE, runner.STORY_COMPOSE, runner.PILOT_COMPOSE)
            },
            "source_sha256": {
                "experiment_controller/run_2b_path_story_pilot_v2.py": runner._sha(Path(runner.__file__)),
            },
            "images": images,
        }
        kwargs = dict(pilot_id="v2-test", slot=1, block=1, arm="B0", seed=contract["block_seeds"]["1"],
                      run_id="2b-path-20261109000000-abcdef", frozen_fingerprint=frozen, contract=contract)
        with patch.object(runner, "_image_id", side_effect=images.values()):
            caps, actual = runner._validate_assignment(**kwargs)
        self.assertEqual(caps["post_entry_wall_seconds"], 600)
        self.assertEqual(actual, images)
        kwargs["contract"] = old.load_contract()
        with patch.object(runner, "_image_id", side_effect=images.values()):
            with self.assertRaisesRegex(ValueError, "contract differs"):
                runner._validate_assignment(**kwargs)


if __name__ == "__main__":
    unittest.main()
