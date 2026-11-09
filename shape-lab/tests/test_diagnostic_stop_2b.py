"""Model-free identity and evidence checks for diagnostic attacker Stop."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dashboard import diagnostic_stop_2b as stop
from experiment_controller import path_story_diagnostic_2b_v1 as diagnostic
from experiment_controller import path_story_pilot_2b_v2 as committed


RUN_ID = "2b-path-20261110000000-a1b2c3"
CONTAINER_ID = "b" * 64
IMAGE_ID = "sha256:" + "a" * 64


class DiagnosticStopTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.lab = Path(temporary.name)
        self.schedule = self.lab / "studies" / diagnostic.PILOT_ID / "schedule.json"
        parent_path = self.lab / "studies" / diagnostic.PARENT_PILOT_ID / "schedule.json"
        committed._write_committed(parent_path, {
            "pilot_id": diagnostic.PARENT_PILOT_ID,
            "fingerprint": {"images": {"agent": IMAGE_ID}},
        })
        parent_sha = hashlib.sha256(parent_path.read_bytes()).hexdigest()
        committed._write_committed(self.schedule, {
            "pilot_id": diagnostic.PILOT_ID,
            "parent_pilot_id": diagnostic.PARENT_PILOT_ID,
            "parent_schedule_sha256": parent_sha,
            "assignments": [{"slot": slot} for slot in range(3, 9)],
        })
        self.admission = {
            "schema_version": 1,
            "pilot_id": diagnostic.PILOT_ID,
            "parent_pilot_id": diagnostic.PARENT_PILOT_ID,
            "parent_schedule_sha256": parent_sha,
            "schedule_sha256": hashlib.sha256(self.schedule.read_bytes()).hexdigest(),
            "run_id": RUN_ID, "slot": 3,
        }
        committed._write_committed(self.schedule.parent / "admissions" / f"{RUN_ID}.json",
                                   self.admission)
        committed._write_committed(self.schedule.parent / "pending-run.json", self.admission)
        for name, value in (("_diagnostic_paths", (diagnostic.PILOT_ID, self.schedule)),
                            ("JOBS", self.lab / "runs" / ".dashboard-jobs")):
            replacement = patch.object(stop, name, return_value=value) if name == "_diagnostic_paths" else patch.object(stop, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

    def _inspect(self, *, image: str = IMAGE_ID, run_id: str = RUN_ID,
                 running: bool = True, service: str = "attacker-agent") -> str:
        return json.dumps([{
            "Id": CONTAINER_ID, "Image": image,
            "Config": {
                "Labels": {
                    "com.docker.compose.project": "shape" + RUN_ID,
                    "com.docker.compose.service": service,
                },
                "Env": ["SHAPE_RUN_ID=" + run_id],
            },
            "State": {"Running": running},
        }])

    def test_exact_container_only_and_signed_request_precedes_stop(self) -> None:
        commands: list[list[str]] = []
        request_path = stop._request_path(self.schedule, RUN_ID)

        def docker(arguments: list[str], *, timeout: int = 15) -> str:
            commands.append(arguments)
            if arguments[1] == "ps":
                return CONTAINER_ID
            if arguments[1] == "inspect":
                return self._inspect()
            self.assertEqual(arguments, ["docker", "stop", "--time", "5", CONTAINER_ID])
            request = committed._read_committed(request_path)
            self.assertEqual(request["container_id"], CONTAINER_ID)
            self.assertEqual(request["project"], "shape" + RUN_ID)
            return CONTAINER_ID

        with patch.object(stop, "_docker", side_effect=docker):
            first = stop.request_stop(RUN_ID)
            second = stop.request_stop(RUN_ID)
        self.assertEqual(first["state"], "stop_command_succeeded")
        self.assertTrue(first["stop_requested"])
        self.assertTrue(second["repeated"])
        self.assertEqual([row[1] for row in commands].count("stop"), 1)
        self.assertEqual(commands[0][-2:], [
            "--filter", "label=com.docker.compose.service=attacker-agent"])
        outcome = committed._read_committed(stop._outcome_path(self.schedule, RUN_ID))
        self.assertEqual(outcome["request_sha256"], hashlib.sha256(request_path.read_bytes()).hexdigest())
        self.assertTrue(stop.stop_requested(RUN_ID, diagnostic.PILOT_ID))

    def test_wrong_container_identity_never_commits_request(self) -> None:
        for inspected in (self._inspect(image="sha256:" + "c" * 64),
                          self._inspect(run_id="another-run"),
                          self._inspect(service="dashboard"),
                          self._inspect(running=False)):
            with self.subTest(inspected=inspected), patch.object(
                stop, "_docker", side_effect=[CONTAINER_ID, inspected]) as docker:
                with self.assertRaises(stop.StopConflict):
                    stop.request_stop(RUN_ID)
                self.assertEqual(docker.call_count, 2)
                self.assertFalse(stop._request_path(self.schedule, RUN_ID).exists())

    def test_unsigned_pending_and_archived_run_are_rejected(self) -> None:
        pending = self.schedule.parent / "pending-run.json"
        pending.with_suffix(".sha256").unlink()
        with patch.object(stop, "_docker") as docker:
            with self.assertRaises(stop.StopConflict):
                stop.request_stop(RUN_ID)
            docker.assert_not_called()
        pending.with_suffix(".sha256").write_text(
            hashlib.sha256(pending.read_bytes()).hexdigest() + "\n", encoding="utf-8")
        result = self.lab / "runs" / RUN_ID / "result.json"
        result.parent.mkdir(parents=True)
        result.write_text("{}", encoding="utf-8")
        with patch.object(stop, "_docker", side_effect=[CONTAINER_ID, self._inspect()]) as docker:
            with self.assertRaises(stop.StopConflict):
                stop.request_stop(RUN_ID)
            self.assertEqual(docker.call_count, 2)
            self.assertFalse(stop._request_path(self.schedule, RUN_ID).exists())

    def test_stop_command_failure_keeps_signed_intent_and_can_retry(self) -> None:
        stop_calls = 0

        def docker(arguments: list[str], *, timeout: int = 15) -> str:
            nonlocal stop_calls
            if arguments[1] == "ps":
                return CONTAINER_ID
            if arguments[1] == "inspect":
                return self._inspect()
            stop_calls += 1
            if stop_calls == 1:
                raise stop.StopConflict("Docker scoped stop command exited 1")
            return CONTAINER_ID

        with patch.object(stop, "_docker", side_effect=docker):
            failed = stop.request_stop(RUN_ID)
            self.assertEqual(failed["state"], "stop_failed")
            self.assertTrue(failed["stop_requested"])
            self.assertTrue(failed["retry_available"])
            self.assertTrue(stop.stop_retry_available(RUN_ID, diagnostic.PILOT_ID))
            self.assertFalse(stop._outcome_path(self.schedule, RUN_ID).exists())
            response = stop.request_stop(RUN_ID)
        self.assertEqual(response["state"], "stop_command_succeeded")
        self.assertTrue(response["repeated"])
        self.assertFalse(response["retry_available"])
        self.assertFalse(stop.stop_retry_available(RUN_ID, diagnostic.PILOT_ID))
        self.assertEqual(stop_calls, 2)
        self.assertTrue(stop.stop_requested(RUN_ID, diagnostic.PILOT_ID))
        failure = committed._read_committed(stop._failure_path(self.schedule, RUN_ID, 1))
        self.assertEqual(failure["state"], "stop_failed")
        self.assertEqual(failure["docker_exit_code"], 1)
        outcome = committed._read_committed(stop._outcome_path(self.schedule, RUN_ID))
        self.assertEqual(outcome["docker_exit_code"], 0)

    def test_malformed_failure_record_disables_retry_and_fails_closed(self) -> None:
        committed._write_committed(stop._request_path(self.schedule, RUN_ID), {
            "schema_version": 1, "pilot_id": diagnostic.PILOT_ID, "run_id": RUN_ID,
            "slot": 3, "requested_utc": "2026-11-10T00:00:00Z",
            "actor": "local_dashboard", "reason": "operator_stop",
            "project": "shape" + RUN_ID, "container_id": CONTAINER_ID,
        })
        failure = stop._failure_path(self.schedule, RUN_ID, 1)
        committed._write_committed(failure, {"state": "stop_failed", "sequence": 1})
        with self.assertRaises(ValueError):
            stop.stop_retry_available(RUN_ID, diagnostic.PILOT_ID)

    def test_retry_after_request_commit_does_not_stop_an_exited_container(self) -> None:
        request_path = stop._request_path(self.schedule, RUN_ID)
        committed._write_committed(request_path, {
            "schema_version": 1, "pilot_id": diagnostic.PILOT_ID, "run_id": RUN_ID,
            "slot": 3, "requested_utc": "2026-11-10T00:00:00Z",
            "actor": "local_dashboard", "reason": "operator_stop",
            "project": "shape" + RUN_ID, "container_id": CONTAINER_ID,
        })
        with patch.object(stop, "_docker", side_effect=[CONTAINER_ID,
                                                          self._inspect(running=False)]) as docker:
            response = stop.request_stop(RUN_ID)
        self.assertEqual(response["state"], "container_already_stopped")
        self.assertTrue(response["stop_requested"])
        self.assertEqual(docker.call_count, 2)
        self.assertEqual(committed._read_committed(
            stop._outcome_path(self.schedule, RUN_ID))["docker_exit_code"], None)

    def test_retry_after_request_commit_accepts_container_already_removed(self) -> None:
        committed._write_committed(stop._request_path(self.schedule, RUN_ID), {
            "schema_version": 1, "pilot_id": diagnostic.PILOT_ID, "run_id": RUN_ID,
            "slot": 3, "requested_utc": "2026-11-10T00:00:00Z",
            "actor": "local_dashboard", "reason": "operator_stop",
            "project": "shape" + RUN_ID, "container_id": CONTAINER_ID,
        })
        with patch.object(stop, "_docker", return_value="") as docker:
            response = stop.request_stop(RUN_ID)
        self.assertEqual(response["state"], "container_already_stopped")
        docker.assert_called_once()

    def test_malformed_committed_request_raises_instead_of_disappearing(self) -> None:
        path = stop._request_path(self.schedule, RUN_ID)
        committed._write_committed(path, {
            "schema_version": 1, "pilot_id": diagnostic.PILOT_ID, "run_id": RUN_ID,
            "slot": 3, "requested_utc": "2026-11-10T00:00:00Z",
            "actor": "local_dashboard", "reason": "operator_stop",
            "project": "wrong", "container_id": CONTAINER_ID,
        })
        with self.assertRaises(ValueError):
            stop.stop_requested(RUN_ID, diagnostic.PILOT_ID)
        self.assertFalse(stop.stop_requested(RUN_ID, "other-pilot"))


if __name__ == "__main__":
    unittest.main()
