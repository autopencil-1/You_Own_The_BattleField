"""Model-free contract, schedule, and admission tests for the successor pilot."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import path_story_pilot_2b as pilot


class PathStoryPilotTests(unittest.TestCase):
    def test_contract_and_two_seed_horizons(self) -> None:
        contract = pilot.load_contract()
        self.assertEqual(contract["pilot_protocol"], pilot.PROTOCOL)
        self.assertEqual(contract["task_sha256"], pilot._sha(pilot.TASK))
        self.assertEqual(contract["fixture_sha256"], pilot._sha(pilot.FIXTURE))
        for block, seed in contract["block_seeds"].items():
            horizon = pilot._seed_horizon(seed)
            self.assertEqual(horizon["successful_distinct_directory_listings"], 500)
            self.assertGreater(horizon["unopened_directory_frontier"], 0, block)
            self.assertGreater(horizon["last_action_children"], 0, block)

    def test_balanced_schedule_is_deterministic_and_seed_paired(self) -> None:
        contract = pilot.load_contract()
        seed = "fixed-test-randomization"
        first = pilot.assignments(contract, seed)
        second = pilot.assignments(contract, seed)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 8)
        for block in (1, 2):
            rows = [row for row in first if row["block"] == block]
            self.assertEqual({row["arm"] for row in rows}, set(pilot.ARMS))
            self.assertEqual(
                {row["seed"] for row in rows},
                {contract["block_seeds"][str(block)]},
            )

    def test_prepare_opens_zero_funding_and_execute_refuses_before_fingerprint(self) -> None:
        contract = pilot.load_contract()
        fake_images = {role: f"sha256:{index:064x}" for index, role in enumerate(pilot.IMAGES, 1)}
        fake_fingerprint = {
            "agent_task_sha256": pilot._sha(pilot.TASK),
            "fixture_sha256": pilot._sha(pilot.FIXTURE),
            "images": fake_images,
        }
        preflight = [
            {
                "status": "passed",
                "arm": arm,
                "seed_sha256": hashlib.sha256(seed.encode()).hexdigest(),
                "images": fake_images,
                "model_calls": 0,
                "agent_started": False,
            }
            for arm, seed in (
                ("B0", contract["block_seeds"]["1"]),
                ("B3", contract["block_seeds"]["2"]),
            )
        ]
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(pilot, "STUDIES", Path(temporary)),
                patch.object(pilot, "build_images", return_value=b"model-free-build\n") as build,
                patch.object(pilot, "fingerprint", return_value=fake_fingerprint) as fingerprint,
                patch(
                    "experiment_controller.run_2b_path_story_pilot.preflight_no_model",
                    side_effect=preflight,
                ) as preflight_call,
            ):
                schedule = pilot.prepare(randomization_seed="fixed-test-randomization")
                pilot_id = schedule["pilot_id"]
                self.assertEqual(len(schedule["assignments"]), 8)
                self.assertEqual(len(schedule["model_free_preflight"]), 2)
                self.assertEqual(preflight_call.call_count, 2)
                build.assert_called_once()
                fingerprint.assert_called_once()
                opening = pilot._read_committed(pilot.pilot_dir(pilot_id) / "funding.json")
                self.assertEqual(opening["tranches"], [])
                self.assertEqual(opening["opening_authorization_nano_usd"], 0)
                status = pilot.status(pilot_id)
                self.assertEqual(status["phase"], "awaiting_authorization")
                self.assertEqual(status["funding"]["authorized_usd"], "0.000000000")
                self.assertFalse(status["funding"]["may_start_new_run"])
                with patch.object(pilot, "fingerprint", side_effect=AssertionError("Docker touched")) as guarded:
                    with self.assertRaisesRegex(pilot.PilotIntegrityError, "awaits an explicit"):
                        pilot.execute(pilot_id, max_new_runs=1)
                    guarded.assert_not_called()

    def test_committed_tranche_is_append_only_and_detects_tampering(self) -> None:
        contract = pilot.load_contract()
        fake = {
            "agent_task_sha256": pilot._sha(pilot.TASK),
            "fixture_sha256": pilot._sha(pilot.FIXTURE),
            "images": {"decoy": "d", "gateway": "g", "agent": "a"},
        }
        preflights = [
            {
                "status": "passed",
                "arm": arm,
                "seed_sha256": hashlib.sha256(contract["block_seeds"][block].encode()).hexdigest(),
                "images": fake["images"],
                "model_calls": 0,
                "agent_started": False,
            }
            for block, arm in (("1", "B0"), ("2", "B3"))
        ]
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(pilot, "STUDIES", Path(temporary)),
                patch.object(pilot, "build_images", return_value=b""),
                patch.object(pilot, "fingerprint", return_value=fake),
                patch(
                    "experiment_controller.run_2b_path_story_pilot.preflight_no_model",
                    side_effect=preflights,
                ),
            ):
                schedule = pilot.prepare(randomization_seed="funding-test")
                pilot_id = schedule["pilot_id"]
                ledger = pilot.pilot_dir(pilot_id) / "funding.json"
                original = ledger.read_bytes()
                after = pilot.authorize(pilot_id, "20.000000000")
                self.assertEqual(ledger.read_bytes(), original)
                self.assertEqual(after["funding"]["authorized_usd"], "20.000000000")
                self.assertTrue(after["funding"]["may_start_new_run"])
                pilot._record_rate_limit_pause(
                    pilot_id, "2b-path-20261109123456-abcdef"
                )
                paused = pilot.status(pilot_id)
                self.assertEqual(paused["phase"], "paused_provider_rate_limit")
                self.assertFalse(paused["funding"]["may_start_new_run"])
                with patch.object(
                    pilot, "fingerprint", side_effect=AssertionError("Docker touched")
                ) as guarded:
                    self.assertEqual(
                        pilot.execute(pilot_id, max_new_runs=1)["phase"],
                        "paused_provider_rate_limit",
                    )
                    guarded.assert_not_called()
                resumed = pilot.resume_rate_limit(pilot_id)
                self.assertEqual(resumed["phase"], "execution_enabled")
                tranche = pilot.pilot_dir(pilot_id) / "funding-tranches" / "0001.json"
                tranche.write_bytes(tranche.read_bytes().replace(b"20.000000000", b"21.000000000"))
                with self.assertRaises(pilot.PilotIntegrityError):
                    pilot.status(pilot_id)

    def test_gateway_lifecycle_requires_one_finish_per_start(self) -> None:
        settlement = {
            "started_request_count": 1,
            "finished_request_count": 1,
            "aborted_request_ids": [],
            "unmatched_request_ids": [],
        }
        pilot._reconcile_gateway_requests(
            [
                {"sequence": 1, "event_type": "request_started", "request_id": 1},
                {"sequence": 2, "event_type": "request_finished", "request_id": 1},
            ],
            settlement,
        )
        for invalid in (
            [{"event_type": "model_call", "request_id": 1}],
            [
                {"event_type": "request_started", "request_id": 1},
                {"event_type": "model_call", "status": 200, "usage": {}},
                {"event_type": "request_finished", "request_id": 1},
            ],
            [{"event_type": "request_started", "request_id": 1}],
            [
                {"event_type": "request_started", "request_id": 1},
                {"event_type": "request_started", "request_id": 1},
                {"event_type": "request_finished", "request_id": 1},
            ],
            [
                {"event_type": "request_started", "request_id": 1},
                {"event_type": "request_aborted", "request_id": 1},
            ],
        ):
            with self.assertRaises(ValueError):
                pilot._reconcile_gateway_requests(
                    [{**row, "sequence": sequence} for sequence, row in enumerate(invalid, 1)],
                    settlement,
                )

    def test_rejected_get_requires_no_post_lifecycle(self) -> None:
        settlement = {
            "started_request_count": 1,
            "finished_request_count": 1,
            "aborted_request_ids": [],
            "unmatched_request_ids": [],
        }
        rows = [
            {"event_type": "request_rejected", "method": "GET", "status": 404},
            {"event_type": "request_started", "request_id": 1},
            {"event_type": "request_rejected", "method": "POST", "request_id": 1},
            {"event_type": "request_finished", "request_id": 1},
        ]
        pilot._reconcile_gateway_requests(
            [{**row, "sequence": index} for index, row in enumerate(rows, 1)],
            settlement,
        )
        for row in (
            {"event_type": "request_rejected", "method": "POST"},
            {"event_type": "request_rejected"},
            {"event_type": "model_call", "status": 200},
        ):
            invalid = [
                {"sequence": 1, "event_type": "request_started", "request_id": 1},
                {"sequence": 2, **row},
                {"sequence": 3, "event_type": "request_finished", "request_id": 1},
            ]
            with self.assertRaisesRegex(ValueError, "lacks request ID"):
                pilot._reconcile_gateway_requests(invalid, settlement)

    def test_attempt_artifact_hashes_cover_gateway_and_trace(self) -> None:
        run_id = "2b-path-20261109123456-abcdef"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "runs" / run_id
            trace = run_dir / "agent" / "traces" / "events.jsonl"
            trace.parent.mkdir(parents=True)
            trace.write_bytes(b'{"type":"tool_call"}\n')
            gateway = run_dir / "gateway-events.jsonl"
            gateway.write_bytes(b'{"event_type":"request_started","request_id":1}\n')
            hashes = {
                path.relative_to(run_dir).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (trace, gateway)
            }
            manifest = {"run_id": run_id, "artifact_sha256": hashes}
            result = {"manifest": manifest, "run_dir": str(run_dir)}
            (run_dir / "attempt-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            (run_dir / "result.json").write_text(json.dumps(result), encoding="utf-8")
            with patch.object(pilot, "LAB", root):
                self.assertEqual(pilot._verify_attempt_artifacts(result), run_dir)
                trace.write_bytes(b'{"type":"changed"}\n')
                with self.assertRaises(pilot.PilotIntegrityError):
                    pilot._verify_attempt_artifacts(result)

    def test_gateway_error_pauses_cost_admission(self) -> None:
        run_id = "2b-path-20261109123456-abcdef"
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "gateway-events.jsonl").write_text(
                "\n".join(
                    json.dumps({**row, "sequence": sequence}) for sequence, row in enumerate((
                        {"event_type": "request_started", "request_id": 1},
                        {"event_type": "gateway_error", "call_number": 1, "request_id": 1},
                        {"event_type": "request_finished", "request_id": 1},
                    ), 1)
                ) + "\n",
                encoding="utf-8",
            )
            result = {
                "manifest": {
                    "run_id": run_id,
                    "provider_settlement": {
                        "state": "complete",
                        "started_request_count": 1,
                        "finished_request_count": 1,
                        "aborted_request_ids": [],
                        "unmatched_request_ids": [],
                        "max_wait_seconds": 190,
                        "quiet_seconds_observed": 5.0,
                    },
                }
            }
            with (
                patch.object(pilot, "_verify_attempt_artifacts", return_value=run_dir),
                patch.object(pilot, "_tranches", return_value=[]),
            ):
                snapshot = pilot._cost_snapshot("fake-pilot", {1: [result]})
            self.assertEqual(snapshot["accounting_state"], "incomplete")
            self.assertFalse(snapshot["may_start_new_run"])

    def test_missing_gateway_log_is_replaceable_but_blocks_cost_admission(self) -> None:
        contract = pilot.load_contract()
        run_id = "2b-path-20261109123456-abcdef"
        pilot_id = "2b-path-story-pilot-v1-20261109120000-123abc"
        assignment = {
            "pilot_id": pilot_id,
            "slot": 1,
            "block": 1,
            "arm": "B0",
            "seed": "path-story-pilot-v1-block-01",
        }
        frozen = {
            "agent_task_sha256": "task",
            "fixture_sha256": "fixture",
            "images": {"decoy": "d", "gateway": "g", "agent": "a"},
            "compose_sha256": {"base": "b"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "runs" / run_id
            run_dir.mkdir(parents=True)
            stdout = run_dir / "agent-stdout.log"
            stdout.write_bytes(b"agent stopped before gateway log capture\n")
            manifest = {
                "run_id": run_id,
                "assignment": assignment,
                "pilot_protocol": pilot.PROTOCOL,
                "environment_protocol": pilot.ENVIRONMENT,
                "mode": "path_story_pilot",
                "arm": "B0",
                "seed": assignment["seed"],
                "pilot_fingerprint": frozen,
                "agent_task_sha256": frozen["agent_task_sha256"],
                "fixture_sha256": frozen["fixture_sha256"],
                "images": frozen["images"],
                "compose_sha256": frozen["compose_sha256"],
                "termination_reason": "controller_error",
                "artifact_sha256": {
                    "agent-stdout.log": hashlib.sha256(stdout.read_bytes()).hexdigest()
                },
            }
            result = {"manifest": manifest, "run_dir": str(run_dir)}
            (run_dir / "attempt-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            (run_dir / "result.json").write_text(json.dumps(result), encoding="utf-8")
            schedule = {"pilot_id": pilot_id, "fingerprint": frozen}
            with (
                patch.object(pilot, "LAB", root),
                patch.object(pilot, "_tranches", return_value=[]),
                patch.object(pilot, "load_contract", return_value=contract),
            ):
                self.assertEqual(
                    pilot._invalid_reason(result, schedule, assignment),
                    "missing_required_telemetry",
                )
                snapshot = pilot._cost_snapshot(pilot_id, {1: [result]})
            self.assertEqual(snapshot["accounting_state"], "incomplete")
            self.assertFalse(snapshot["may_start_new_run"])


if __name__ == "__main__":
    unittest.main()
