"""Model-free checks of the dashboard's launch schema and event projection."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from pydantic import ValidationError
    from dashboard import core
except ModuleNotFoundError:
    ValidationError = None  # type: ignore[assignment]
    core = None  # type: ignore[assignment]


@unittest.skipIf(core is None, "Dashboard dependencies are not installed")
class DashboardFirstSliceTests(unittest.TestCase):
    def test_closed_fixture_launch_schema(self) -> None:
        assert core is not None
        value = core.FixtureRequest(experiment="2B", arm="B3", seed="preview-7", branching_factor=6)
        self.assertEqual(value.mode, "deterministic")
        for invalid in (
            {"experiment": "2A", "arm": "B3"},
            {"experiment": "2B", "arm": "B3", "mode": "connectivity"},
            {"experiment": "2A", "arm": "C2", "seed": "other"},
            {"experiment": "2B", "arm": "B1", "seed": "bad seed"},
            {"experiment": "2B", "arm": "B1", "branching_factor": 16},
            {"experiment": "2B", "arm": "B1", "SHAPE_KEY_FILE": "/tmp/key"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                core.FixtureRequest.model_validate(invalid)

    def test_live_and_final_decoy_lines_deduplicate_and_verify(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2b-dete-20261026000000-a1b2c3"
            run_dir = root / run_id
            run_dir.mkdir()
            body = b'{"output":"/home/lab\\n"}'
            rows = [
                {"run_id": run_id, "sequence": 1, "timestamp_utc": "2026-10-26T00:00:01.000Z",
                 "event_type": "decoy_request", "route": "/exec"},
                {"run_id": run_id, "sequence": 2, "timestamp_utc": "2026-10-26T00:00:01.001Z",
                 "event_type": "decoy_response", "route": "/exec", "status": 200,
                 "body_b64": base64.b64encode(body).decode(),
                 "body_sha256": hashlib.sha256(body).hexdigest()},
            ]
            text = "".join(json.dumps(row) + "\n" for row in rows)
            (run_dir / "decoy-live.jsonl").write_text(text)
            with patch.object(core, "RUNS", root):
                collector = core.Collector()
                first = collector.collect(run_id)
                self.assertEqual([item["event_id"] for item in first], [1, 2])
                self.assertTrue(first[1]["detail"]["body_hash_verified"])
                self.assertEqual(first[1]["detail"]["response_text"], body.decode())
                (run_dir / "decoy-events.jsonl").write_text(text)
                self.assertEqual(len(collector.collect(run_id)), 2)

    def test_agent_role_and_start_anchor_are_projected(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-conn-20261026000000-a1b2c3"
            run_dir = root / run_id
            trace = run_dir / "agent" / "runs" / run_id / "traces" / "executor-1"
            trace.mkdir(parents=True)
            (trace / "input.json").write_text('{"role":"executor"}')
            (trace / "events.jsonl").write_text(json.dumps({
                "sequence": 1, "recorded_at": 1792972801.0, "type": "tool_call",
                "name": "Bash", "input": {"command": "pwd"}, "call_id": "call-1",
            }) + "\n")
            (run_dir / "agent-live.log").write_text("AGENT_STARTED=2026-10-26T00:00:00.000Z\n")
            with patch.object(core, "RUNS", root):
                events = core.Collector().collect(run_id)
                self.assertEqual([item["kind"] for item in events], ["agent_started", "tool_call"])
                self.assertEqual(events[1]["role"], "executor")
                self.assertEqual(events[1]["call_id"], "call-1")

    def test_job_is_visible_before_run_directory_exists(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / ".dashboard-jobs"
            run_id = "2a-dete-20261026000000-a1b2c3"
            core.private_json(jobs / run_id / "status.json", {
                "run_id": run_id, "experiment": "2A", "mode": "deterministic",
                "arm": "C0", "status": "queued", "created_utc": "2026-10-26T00:00:00.000Z",
            })
            with patch.object(core, "JOBS", jobs):
                snapshot = core.provisional_snapshot(run_id)
            self.assertIsNotNone(snapshot)
            self.assertEqual(snapshot["status"], "queued")
            self.assertEqual(snapshot["event_count"], 0)


if __name__ == "__main__":
    unittest.main()
