"""Focused model-free checks for the successor behavioral-pilot runner."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from agent_runner.runtime_policy_2b import SUPPORT_POLICY_V3
from experiment_controller import run_2b_path_story_pilot as runner


class PathStoryPilotRunnerTests(unittest.TestCase):
    def _inputs(self):
        contract = {
            "pilot_protocol": "2b-path-story-pilot-v1",
            "environment_protocol": "filesystem-path-story-v1",
            "block_seeds": {"1": "pilot-seed-one", "2": "pilot-seed-two"},
            "runtime_policy": SUPPORT_POLICY_V3,
            "reinforcement_every": 3,
            "provider": "ollama",
            "model": "glm-5.3",
            "post_run_settlement": {
                "gateway_settlement_grace_seconds": 190,
                "minimum_quiet_seconds": 5,
            },
            "provider_cost_governance": {"rate_card": {"revision": "test"}},
            "trial_caps": {
                "pre_entry_wall_seconds": 180,
                "post_entry_wall_seconds": 600,
                "maximum_total_wall_seconds": 780,
                "max_filesystem_actions": 500,
                "max_agent_tool_calls": 500,
                "max_model_calls": 500,
                "max_model_tokens_input_plus_output": 100_000_000,
            },
        }
        images = {"decoy": "sha256:" + "a" * 64, "gateway": "sha256:" + "b" * 64,
                  "agent": "sha256:" + "c" * 64}
        fingerprint = {
            "agent_task_sha256": runner._sha(runner.TASK),
            "fixture_sha256": runner._sha(runner.FIXTURE),
            "compose_sha256": {
                path.name: runner._sha(path)
                for path in (runner.BASE_COMPOSE, runner.STORY_COMPOSE, runner.PILOT_COMPOSE)
            },
            "images": images,
            "source_sha256": {
                "experiment_controller/run_2b_path_story_pilot.py": runner._sha(Path(runner.__file__)),
            },
        }
        assignment = {
            "pilot_id": "2b-path-story-pilot-v1-test", "slot": 1, "block": 1,
            "arm": "B0", "seed": "pilot-seed-one",
            "run_id": "2b-path-20261109000000-abcdef",
            "frozen_fingerprint": fingerprint, "contract": contract,
        }
        return assignment, images

    def test_assignment_checks_frozen_successor_inputs(self):
        assignment, images = self._inputs()
        with patch.object(runner, "_image_id", side_effect=images.values()):
            caps, seen = runner._validate_assignment(**assignment)
        self.assertEqual(caps["post_entry_wall_seconds"], 600)
        self.assertEqual(seen, images)

    def test_source_or_seed_drift_rejected_before_trial(self):
        assignment, images = self._inputs()
        assignment["frozen_fingerprint"]["source_sha256"][
            "experiment_controller/run_2b_path_story_pilot.py"
        ] = "0" * 64
        with patch.object(runner, "_image_id", side_effect=images.values()):
            with self.assertRaisesRegex(ValueError, "source changed"):
                runner._validate_assignment(**assignment)
        assignment, images = self._inputs()
        assignment["seed"] = "another-seed"
        with patch.object(runner, "_image_id", side_effect=images.values()):
            with self.assertRaisesRegex(ValueError, "contract differs"):
                runner._validate_assignment(**assignment)

    def test_clock_qualifies_only_before_pre_entry_deadline(self):
        start = datetime(2026, 11, 9, tzinfo=timezone.utc)
        before = start + timedelta(seconds=179)
        event = {"event_type": "filesystem_interaction", "exit_code": 0,
                 "timestamp_utc": before.isoformat()}
        clock = runner._clock([event], start, start + timedelta(seconds=181), 180)
        self.assertEqual(clock["clock_phase"], "post_entry")
        self.assertEqual(clock["post_entry_elapsed_seconds"], 2)
        boundary = dict(event, timestamp_utc=(start + timedelta(seconds=180)).isoformat())
        clock = runner._clock([boundary], start, start + timedelta(seconds=181), 180)
        self.assertEqual(clock["clock_phase"], "pre_entry")

    def test_preflight_starts_no_agent_or_model_request(self):
        assignment, images = self._inputs()
        names = [runner.DECOY_IMAGE, runner.GATEWAY_IMAGE, runner.AGENT_IMAGE]
        lookup = dict(zip(names, images.values()))
        task_hash = runner._sha(runner.TASK)
        compose_calls = []

        def fake_compose(project, arguments, env, **kwargs):
            compose_calls.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, b"", b"")

        def fake_command(arguments, **kwargs):
            if arguments[:2] == ["docker", "run"]:
                output = (
                    (task_hash + "\n").encode()
                    if "/opt/shape/agent_2b_task.json" in arguments[-1]
                    else b'{"status":400}\n'
                )
                return subprocess.CompletedProcess(arguments, 0, output, b"")
            if arguments[:2] == ["docker", "network"]:
                return subprocess.CompletedProcess(arguments, 1, b"", b"not found")
            return subprocess.CompletedProcess(arguments, 0, b"", b"")

        with patch.object(runner, "_image_id", side_effect=lambda name: lookup[name]), \
             patch.object(runner, "_command", side_effect=fake_command), \
             patch.object(runner, "_compose", side_effect=fake_compose), \
             patch.object(runner, "_preflight", return_value={"network_internal": True}), \
             patch.object(runner, "_settle_gateway", return_value={
                 "state": "complete", "started_request_count": 1,
                 "finished_request_count": 1,
             }), \
             patch.object(runner, "_events", return_value=[{
                 "event_type": "request_rejected", "request_id": 1,
                 "status": 400, "reason": "invalid_json",
             }]):
            report = runner.preflight_no_model(contract=assignment["contract"])
        self.assertEqual(report["model_calls"], 0)
        self.assertFalse(report["agent_started"])
        self.assertTrue(any(row[:2] == ["up", "-d"] for row in compose_calls))
        self.assertTrue(any(row[0] == "down" for row in compose_calls))
        self.assertFalse(any("attacker-agent" in row for row in compose_calls))

    def test_preflight_rejects_failed_teardown(self):
        assignment, images = self._inputs()
        task_hash = runner._sha(runner.TASK)
        def fake_compose(project, arguments, env, **kwargs):
            code = 1 if arguments[0] == "down" else 0
            return subprocess.CompletedProcess(arguments, code, b"", b"cleanup failed")
        def fake_command(arguments, **kwargs):
            output = (
                (task_hash + "\n").encode()
                if "/opt/shape/agent_2b_task.json" in arguments[-1]
                else b'{"status":400}\n'
            )
            return subprocess.CompletedProcess(arguments, 0, output, b"")
        with patch.object(runner, "_image_id", side_effect=images.values()), \
             patch.object(runner, "_command", side_effect=fake_command), \
             patch.object(runner, "_compose", side_effect=fake_compose), \
             patch.object(runner, "_preflight", return_value={"network_internal": True}), \
             patch.object(runner, "_settle_gateway", return_value={
                 "state": "complete", "started_request_count": 1,
                 "finished_request_count": 1,
             }), \
             patch.object(runner, "_events", return_value=[{
                 "event_type": "request_rejected", "request_id": 1,
                 "status": 400, "reason": "invalid_json",
             }]):
            with self.assertRaisesRegex(RuntimeError, "did not tear down"):
                runner.preflight_no_model(contract=assignment["contract"])

    def test_gateway_lifecycle_settles_only_after_matching_terminal_events(self):
        started = {"sequence": 1, "event_type": "request_started", "request_id": 1}
        finished = {"sequence": 2, "event_type": "request_finished", "request_id": 1}
        with patch.object(runner, "_events", side_effect=[
            [started], [started, finished], [started, finished]
        ]), patch.object(runner.time, "sleep", return_value=None), \
             patch.object(runner, "MIN_GATEWAY_QUIET_SECONDS", 0):
            settled = runner._settle_gateway("project", {}, max_wait_seconds=190)
        self.assertEqual(settled["state"], "complete")
        self.assertEqual(settled["started_request_count"], 1)
        self.assertEqual(settled["finished_request_count"], 1)
        self.assertEqual(settled["unmatched_request_ids"], [])

    def test_gateway_lifecycle_rejects_unmatched_or_aborted_requests(self):
        with self.assertRaisesRegex(ValueError, "unmatched finish"):
            runner._gateway_lifecycle([
                {"sequence": 1, "event_type": "request_finished", "request_id": 1}
            ])
        started = {"sequence": 1, "event_type": "request_started", "request_id": 1}
        aborted = {"sequence": 2, "event_type": "request_aborted", "request_id": 1}
        with patch.object(runner, "_events", return_value=[started, aborted]):
            settled = runner._settle_gateway("project", {}, max_wait_seconds=190)
        self.assertEqual(settled["state"], "incomplete")
        self.assertEqual(settled["aborted_request_ids"], [1])
        with patch.object(runner, "_events", return_value=[started]):
            settled = runner._settle_gateway("project", {}, max_wait_seconds=0)
        self.assertEqual(settled["state"], "incomplete")
        self.assertEqual(settled["unmatched_request_ids"], [1])
        with self.assertRaisesRegex(ValueError, "inactive request"):
            runner._gateway_lifecycle([
                started,
                {"sequence": 2, "event_type": "model_call", "request_id": 2},
            ])


if __name__ == "__main__":
    unittest.main()
