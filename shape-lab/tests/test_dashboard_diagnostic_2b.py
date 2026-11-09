"""Model-free checks for one-click diagnostic admission and guarded Stop."""

from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException, Request

from dashboard import app, core, diagnostic_pilot_2b as pilot, diagnostic_pilot_2b_worker as worker, jobs
from experiment_controller import path_story_diagnostic_2b_v1 as controller
from experiment_controller import path_story_pilot_2b_v2 as committed


def local_request(path: str) -> Request:
    return Request({
        "type": "http", "method": "POST", "path": path,
        "headers": [(b"host", b"127.0.0.1:8787"),
                    (b"origin", b"http://127.0.0.1:8787")],
        "client": ("127.0.0.1", 30000), "server": ("127.0.0.1", 8787),
        "scheme": "http", "http_version": "1.1",
    })


class DashboardDiagnosticTests(unittest.TestCase):
    def test_status_is_separate_and_omits_future_assignment(self) -> None:
        state = {
            "pilot_id": controller.PILOT_ID,
            "pilot_protocol": controller.PROTOCOL,
            "schedule_sha256": "a" * 64,
            "next_slot": 3,
            "phase": "ready_for_next_run",
            "pending_run": None,
            "invalid_attempts": [],
            "launch_available": True,
            "launch_reason": None,
            "credits": {"may_start_new_run": True},
        }
        with tempfile.TemporaryDirectory() as temporary:
            schedule = Path(temporary) / "schedule.json"
            schedule.write_text("{}", encoding="utf-8")
            fake = SimpleNamespace(PILOT_ID=controller.PILOT_ID, PROTOCOL=controller.PROTOCOL,
                                   SCHEDULE=schedule, status=lambda: state)
            with patch.object(pilot, "_controller", return_value=fake), \
                    patch.object(pilot, "key_configured", return_value=True):
                current = pilot.public_status()
        self.assertTrue(current["launch_available"])
        self.assertEqual(current["next_slot"], 3)
        for hidden in ("next_arm", "seed", "assignments"):
            self.assertNotIn(hidden, current)

    def test_launch_queues_only_one_admitted_attempt(self) -> None:
        current = {
            "pilot_id": controller.PILOT_ID, "schedule_sha256": "b" * 64,
            "next_slot": 3, "launch_available": True,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs = root / "runs"
            jobs_dir = runs / ".dashboard-jobs"
            admissions = root / "studies" / controller.PILOT_ID / "admissions"
            admissions.mkdir(parents=True)
            (admissions / "previous.json").write_text("{}", encoding="utf-8")
            with patch.object(pilot, "JOBS", jobs_dir), \
                    patch.object(pilot, "RUNS", runs), \
                    patch.object(jobs, "JOBS", jobs_dir), \
                    patch.object(jobs, "_active_job", return_value=None), \
                    patch.object(pilot, "public_status", return_value=current), \
                    patch("experiment_controller.run_2a.read_key", return_value="dummy"), \
                    patch.object(pilot.subprocess, "Popen") as spawn:
                response = pilot.launch_next(current)
            request = core.read_json(jobs_dir / response["job_id"] / "request.json")
            self.assertEqual(request["baseline_admissions"], ["previous.json"])
            self.assertEqual(request["slot"], 3)
            self.assertNotIn("arm", request)
            self.assertNotIn("seed", request)
            spawn.assert_called_once()
            self.assertIn("dashboard.diagnostic_pilot_2b_worker", spawn.call_args.args[0])

    def test_incomplete_provider_settlement_blocks_another_dashboard_launch(self) -> None:
        run_id = "2b-path-20261110000001-a1b2c3"
        state = {"invalid_attempts": [{"run_id": run_id, "slot": 3,
                                       "reason": "controller_error"}]}
        with tempfile.TemporaryDirectory() as temporary:
            runs = Path(temporary) / "runs"
            core.private_json(runs / run_id / "attempt-manifest.json", {
                "provider_settlement": {"state": "incomplete", "unaccounted_request_ids": [1]},
            })
            with patch.object(pilot, "RUNS", runs):
                reason = pilot._unreconciled_provider_exposure(state)
        self.assertIn(run_id, reason)
        self.assertIn("incomplete provider settlement", reason)

    def test_worker_finds_only_matching_committed_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            admissions = root / "studies" / controller.PILOT_ID / "admissions"
            earlier = {"pilot_id": controller.PILOT_ID, "schedule_sha256": "c" * 64,
                       "run_id": "2b-path-20261110000000-a1b2c3", "slot": 3}
            newest = {**earlier, "run_id": "2b-path-20261110000001-a1b2c3"}
            committed._write_committed(admissions / (earlier["run_id"] + ".json"), earlier)
            committed._write_committed(admissions / (newest["run_id"] + ".json"), newest)
            request = {"pilot_id": controller.PILOT_ID, "schedule_sha256": "c" * 64,
                       "slot": 3, "baseline_admissions": [earlier["run_id"] + ".json"]}
            with patch.object(worker, "LAB", root):
                self.assertEqual(worker._admitted_run(request), newest)
                self.assertIsNone(worker._admitted_run({**request, "slot": 4}))

    def test_stop_api_requires_local_session_token(self) -> None:
        async def run_inline(function, *args):
            return function(*args)

        payload = app.PilotLaunchEnvelope(launch_token="test-token")
        path = "/api/2b/path-story-diagnostic/runs/2b-path-20261110000001-a1b2c3/stop"
        with patch.object(app, "_session_token", return_value="test-token"), \
                patch.object(app.asyncio, "to_thread", side_effect=run_inline), \
                patch.object(app, "request_diagnostic_stop", return_value={
                    "run_id": "2b-path-20261110000001-a1b2c3", "stop_requested": True,
                }) as stop:
            result = asyncio.run(app.path_story_diagnostic_stop(
                local_request(path), "2b-path-20261110000001-a1b2c3", payload))
            self.assertTrue(result["stop_requested"])
            stop.assert_called_once()
            with self.assertRaises(HTTPException) as context:
                asyncio.run(app.path_story_diagnostic_stop(
                    local_request(path), "2b-path-20261110000001-a1b2c3",
                    app.PilotLaunchEnvelope(launch_token="wrong")))
        self.assertEqual(context.exception.status_code, 403)
        stop.assert_called_once()

    def test_pending_stop_is_invalid_and_failed_command_can_be_retried(self) -> None:
        run_id = "2b-path-20261110000001-a1b2c3"
        admission = {"pilot_id": controller.PILOT_ID, "pilot_protocol": controller.PROTOCOL,
                     "slot": 3, "provider": "zai", "trial_caps": {}}
        with patch.object(core, "job_status", return_value=None), \
                patch.object(core, "_pending_path_story", return_value={run_id: admission}), \
                patch.object(core, "_diagnostic_stop_requested", return_value=True), \
                patch.object(core, "_diagnostic_stop_retry_available", return_value=False):
            stopped = core.provisional_snapshot(run_id)
        self.assertEqual(stopped["status"], "stopping")
        self.assertEqual(stopped["attempt_classification"], "infrastructure_invalid")
        with patch.object(core, "job_status", return_value=None), \
                patch.object(core, "_pending_path_story", return_value={run_id: admission}), \
                patch.object(core, "_diagnostic_stop_requested", return_value=True), \
                patch.object(core, "_diagnostic_stop_retry_available", return_value=True):
            failed_stop = core.provisional_snapshot(run_id)
        self.assertEqual(failed_stop["status"], "running")
        self.assertTrue(failed_stop["diagnostic_stop_retry_available"])


if __name__ == "__main__":
    unittest.main()
