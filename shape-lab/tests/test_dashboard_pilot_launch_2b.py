"""Model-free checks for dashboard admission to the frozen 2B pilot."""

from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException, Request

from dashboard import app, core, jobs, pilot_2b, pilot_2b_worker


def local_request() -> Request:
    return Request({
        "type": "http", "method": "POST", "path": "/api/2b/path-story-pilot/run-next",
        "headers": [(b"host", b"127.0.0.1:8787"),
                    (b"origin", b"http://127.0.0.1:8787")],
        "client": ("127.0.0.1", 30000), "server": ("127.0.0.1", 8787),
        "scheme": "http", "http_version": "1.1",
    })


class DashboardPilotLaunchTests(unittest.TestCase):
    def test_public_status_uses_controller_admission_without_future_assignment(self) -> None:
        from experiment_controller import path_story_pilot_2b_zai_v5 as controller

        controller_status = {
            "pilot_protocol": controller.PROTOCOL, "schedule_sha256": "a" * 64,
            "scheduled_runs": 8, "valid_runs": 2, "completed_slots": [1, 2],
            "invalid_attempts": [], "next_slot": 3, "pending_run": None,
            "phase": "ready_for_next_run", "credits": {"may_start_new_run": True},
        }
        with patch.object(controller, "status", return_value=controller_status) as status, \
                patch.object(pilot_2b, "key_configured", return_value=True):
            value = pilot_2b.public_status()
        status.assert_called_once_with(pilot_2b.PILOT_ID)
        self.assertTrue(value["launch_available"])
        self.assertEqual(value["next_slot"], 3)
        self.assertNotIn("next_arm", value)
        self.assertNotIn("next_block", value)
        self.assertNotIn("assignments", value)

    def test_paused_pilot_cannot_spawn_a_worker(self) -> None:
        state = {"pilot_id": pilot_2b.PILOT_ID, "phase": "paused_provider_rate_limit",
                 "launch_available": False, "launch_reason": "Provider rate-limit pause"}
        with patch.object(pilot_2b.subprocess, "Popen") as spawn:
            with self.assertRaises(RuntimeError):
                pilot_2b.launch_next(state)
        spawn.assert_not_called()

    def test_launch_queues_one_detached_job_and_never_sets_arm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs = root / "runs"
            jobs_dir = runs / ".dashboard-jobs"
            admissions = root / "studies" / pilot_2b.PILOT_ID / "admissions"
            admissions.mkdir(parents=True)
            (admissions / "earlier.json").write_text("{}")
            current = {"pilot_id": pilot_2b.PILOT_ID, "phase": "ready_for_next_run",
                       "launch_available": True, "schedule_sha256": "b" * 64, "next_slot": 3}
            with patch.object(pilot_2b, "JOBS", jobs_dir), \
                    patch.object(pilot_2b, "RUNS", runs), \
                    patch.object(jobs, "JOBS", jobs_dir), \
                    patch.object(jobs, "_active_job", return_value=None), \
                    patch("experiment_controller.run_2a.read_key", return_value="dummy"), \
                    patch.object(pilot_2b.subprocess, "Popen") as spawn:
                response = pilot_2b.launch_next(current)
            self.assertEqual(response["status"], "queued")
            self.assertIsNone(core.read_json(jobs_dir / response["job_id"] / "status.json")["run_id"])
            request = core.read_json(jobs_dir / response["job_id"] / "request.json")
            self.assertEqual(request["baseline_admissions"], ["earlier.json"])
            self.assertEqual(request["slot"], 3)
            self.assertNotIn("arm", request)
            self.assertNotIn("seed", request)
            spawn.assert_called_once()
            self.assertIn("dashboard.pilot_2b_worker", spawn.call_args.args[0])

    def test_api_guard_and_integrity_state(self) -> None:
        payload = app.PilotLaunchEnvelope(launch_token="test-token")
        ready = {"pilot_id": pilot_2b.PILOT_ID, "launch_available": True,
                 "schedule_sha256": "c" * 64, "next_slot": 3}
        with patch.object(app, "_session_token", return_value="test-token"), \
                patch.object(app, "public_status", return_value=ready), \
                patch.object(app, "launch_next", return_value={"job_id": "2b-pilo-test", "status": "queued"}) as launch:
            result = asyncio.run(app.path_story_pilot_run_next(local_request(), payload))
        self.assertEqual(result["status"], "queued")
        launch.assert_called_once_with(ready)
        with patch.object(app, "_session_token", return_value="test-token"), \
                patch.object(app, "launch_next") as launch:
            with self.assertRaises(HTTPException) as context:
                asyncio.run(app.path_story_pilot_run_next(local_request(),
                            app.PilotLaunchEnvelope(launch_token="wrong")))
        self.assertEqual(context.exception.status_code, 403)
        launch.assert_not_called()
        with patch.object(app, "public_status", side_effect=RuntimeError("image ID differs")):
            unavailable = asyncio.run(app.path_story_pilot_status())
        self.assertEqual(unavailable["phase"], "integrity_error")
        self.assertFalse(unavailable["launch_available"])
        self.assertIn("image ID differs", unavailable["launch_reason"])

    def test_worker_discovers_only_signed_admission_for_expected_slot(self) -> None:
        from experiment_controller import path_story_pilot_2b_v2 as prior

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            admissions = root / "studies" / pilot_2b.PILOT_ID / "admissions"
            original = {"pilot_id": pilot_2b.PILOT_ID, "schedule_sha256": "e" * 64,
                        "run_id": "2b-path-20261110000000-a1b2c3", "slot": 2}
            admitted = {**original, "run_id": "2b-path-20261110000001-a1b2c3", "slot": 3}
            prior._write_committed(admissions / (original["run_id"] + ".json"), original)
            prior._write_committed(admissions / (admitted["run_id"] + ".json"), admitted)
            request = {"schedule_sha256": "e" * 64, "slot": 3,
                       "baseline_admissions": [original["run_id"] + ".json"]}
            with patch.object(pilot_2b_worker, "LAB", root):
                self.assertEqual(pilot_2b_worker._admitted_run(request), admitted)
                self.assertIsNone(pilot_2b_worker._admitted_run({**request, "slot": 4}))

    def test_worker_reports_no_admission_as_terminal_not_admitted(self) -> None:
        from experiment_controller import path_story_pilot_2b_zai_v5 as controller

        with tempfile.TemporaryDirectory() as temporary:
            jobs_dir = Path(temporary) / ".dashboard-jobs"
            job_id = "2b-pilo-20261110000000-a1b2c3"
            folder = jobs_dir / job_id
            core.private_json(folder / "request.json", {
                "kind": "path_story_pilot_v5", "pilot_id": pilot_2b.PILOT_ID,
                "schedule_sha256": "d" * 64, "slot": 3, "baseline_admissions": [],
            })
            core.private_json(folder / "status.json", {
                "job_id": job_id, "pilot_id": pilot_2b.PILOT_ID, "run_id": None,
                "status": "queued", "created_utc": core.utc_now(),
            })
            with patch.object(pilot_2b_worker, "JOBS", jobs_dir), \
                    patch.object(core, "JOBS", jobs_dir), \
                    patch.object(pilot_2b_worker, "_admitted_run", return_value=None), \
                    patch.object(controller, "execute", return_value={
                        "phase": "paused_credit_share_admission", "credits": {},
                    }) as execute:
                exit_code = pilot_2b_worker.main(job_id)
            execute.assert_called_once_with(pilot_2b.PILOT_ID)
            self.assertEqual(exit_code, 1)
            status = core.read_json(folder / "status.json")
            self.assertEqual(status["status"], "not_admitted")
            self.assertIsNone(status["run_id"])


if __name__ == "__main__":
    unittest.main()
