"""Model-free checks of the dashboard's launch schema and event projection."""

from __future__ import annotations

import base64
import asyncio
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

try:
    from pydantic import ValidationError
    from fastapi import HTTPException, Request, Response
    from dashboard import app, core, worker
except ModuleNotFoundError:
    ValidationError = None  # type: ignore[assignment]
    Response = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    Request = None  # type: ignore[assignment]
    app = None  # type: ignore[assignment]
    core = None  # type: ignore[assignment]
    worker = None  # type: ignore[assignment]


@unittest.skipIf(core is None, "Dashboard dependencies are not installed")
class DashboardFirstSliceTests(unittest.TestCase):
    def test_launch_envelope_keeps_token_out_of_worker_request(self) -> None:
        assert app is not None and Request is not None
        request = Request({
            "type": "http", "method": "POST", "path": "/api/runs",
            "headers": [(b"host", b"127.0.0.1:8787"),
                        (b"origin", b"http://127.0.0.1:8787")],
            "client": ("127.0.0.1", 30000), "server": ("127.0.0.1", 8787),
            "scheme": "http", "http_version": "1.1",
        })
        envelope = app.LaunchEnvelope.model_validate({
            "launch_token": "test-token",
            "run": {"experiment": "2A", "arm": "C0", "mode": "deterministic"},
        })
        with patch.object(app, "_session_token", return_value="test-token"), \
                patch.object(app, "launch_run", return_value={"run_id": "test-run"}) as launch:
            self.assertEqual(asyncio.run(app.start_run(request, envelope, None)), {"run_id": "test-run"})
            self.assertEqual(launch.call_args.args[0].arm, "C0")
            self.assertNotIn("launch_token", launch.call_args.args[0].model_dump())

    def test_launch_guard_rejects_preview_and_cross_site_origins(self) -> None:
        assert app is not None and Request is not None and HTTPException is not None
        def request(host: str, origin: str) -> Request:
            return Request({
                "type": "http", "method": "POST", "path": "/api/runs",
                "headers": [(b"host", host.encode()), (b"origin", origin.encode())],
                "client": ("127.0.0.1", 30000), "server": ("127.0.0.1", 8787),
                "scheme": "http", "http_version": "1.1",
            })
        with patch.object(app, "_session_token", return_value="test-token"):
            app._guard_launch(request("127.0.0.1:8787", "http://127.0.0.1:8787"), "test-token")
            with self.assertRaises(HTTPException):
                app._guard_launch(request("preview.example", "https://preview.example"), "test-token")
            with self.assertRaises(HTTPException):
                app._guard_launch(request("evil.example", "http://evil.example"), "test-token")
            with self.assertRaises(HTTPException):
                app._guard_launch(request("127.0.0.1:8787", "http://127.0.0.1:8787"), "wrong-token")

    def test_agent_failure_surfaces_supervisor_contract_error(self) -> None:
        from experiment_controller.run_2a import agent_trial_failure
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-pilo-20261101054800-e22ef6"
            trial = root / "runs" / run_id
            trial.mkdir(parents=True)
            (trial / "summary.json").write_text(json.dumps({
                "status": "failed",
                "error": "supervisor_contract: Supervisor failed after 2 attempts: episode stream ended without TurnCompleted",
            }))
            self.assertIn("without TurnCompleted", agent_trial_failure(root, run_id) or "")

    def test_missing_supervisor_terminal_event_is_identified(self) -> None:
        assert core is not None
        outcome = core._outcome_detail(
            {"termination_reason": "agent_exit", "agent_exit_code": 1}, [],
            {"error": "supervisor_contract: Supervisor failed after 2 attempts: episode stream ended without TurnCompleted"},
        )
        self.assertEqual(outcome["cause"], "supervisor_stream_incomplete")

    def test_archived_supervisor_failure_is_visible_without_rewriting_events(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-pilo-20261101054800-e22ef6"
            trial = root / run_id
            summary = trial / "agent" / "runs" / run_id
            summary.mkdir(parents=True)
            core.private_json(trial / "manifest.json", {
                "mode": "pilot", "arm": "C2", "termination_reason": "agent_exit", "agent_exit_code": 1,
                "error": "Attacker agent exited with code 1",
            })
            core.private_json(summary / "summary.json", {
                "status": "failed", "error": "supervisor_contract: episode stream ended without TurnCompleted",
            })
            with patch.object(core, "RUNS", root):
                snapshot = core.run_snapshot(run_id)
            self.assertEqual(snapshot["diagnosed_cause"], "supervisor_stream_incomplete")
            self.assertIn("without TurnCompleted", snapshot["error"])

    def test_closed_launch_mode_matrix(self) -> None:
        assert core is not None
        value = core.RunRequest(experiment="2B", arm="B3", seed="preview-7", branching_factor=6)
        self.assertEqual(value.mode, "deterministic")
        self.assertEqual(core.RunRequest(experiment="2A", arm="C2", mode="pilot").mode, "pilot")
        self.assertEqual(core.RunRequest(experiment="2A", arm="C2", mode="pilot").provider, "ollama")
        self.assertEqual(core.RunRequest(experiment="2A", arm="C2", mode="pilot", provider="zai").provider, "zai")
        for arm in ("C0", "C1", "C2"):
            self.assertEqual(core.RunRequest(experiment="2A", arm=arm, mode="engineering").arm, arm)
        self.assertEqual(core.RunRequest(experiment="2B", arm="B0", mode="connectivity").mode, "connectivity")
        for invalid in (
            {"experiment": "2A", "arm": "B3"},
            {"experiment": "2A", "arm": "C0", "mode": "pilot"},
            {"experiment": "2B", "arm": "B3", "mode": "connectivity"},
            {"experiment": "2B", "arm": "B0", "mode": "pilot"},
            {"experiment": "2B", "arm": "B0", "mode": "connectivity", "branching_factor": 7},
            {"experiment": "2A", "arm": "C2", "seed": "other"},
            {"experiment": "2B", "arm": "B1", "seed": "bad seed"},
            {"experiment": "2B", "arm": "B1", "branching_factor": 16},
            {"experiment": "2B", "arm": "B1", "SHAPE_KEY_FILE": "/tmp/key"},
            {"experiment": "2A", "arm": "C2", "provider": "custom"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                core.RunRequest.model_validate(invalid)

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

    def test_session_v2_monitor_and_raw_api_redact_cookie_and_nonces(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-enge-20261101000000-a1b2c3"
            run_dir = root / run_id
            trace = run_dir / "agent" / "runs" / run_id / "traces" / "executor-1"
            trace.mkdir(parents=True)
            core.private_json(run_dir / "manifest.json", {"decoy_protocol": "session-v2", "mode": "engineering", "arm": "C1"})
            (trace / "input.json").write_text('{"role":"executor"}')
            nonce = "a" * 32
            cookie = "b" * 32
            (trace / "events.jsonl").write_text(json.dumps({
                "sequence": 1, "recorded_at": 1793510001.0, "type": "tool_result",
                "call_id": "call-1", "output": f"Set-Cookie: shape_session={cookie}; /session/verify?token={nonce}",
            }) + "\n")
            body = f"<p>/session/verify?token={nonce}</p>".encode()
            (run_dir / "decoy-events.jsonl").write_text(json.dumps({
                "run_id": run_id, "sequence": 1, "timestamp_utc": "2026-11-01T00:00:01Z",
                "event_type": "decoy_response", "route": "/login", "status": 200,
                "body_b64": base64.b64encode(body).decode(),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "headers": [["Set-Cookie", f"shape_session={cookie}"]],
            }) + "\n")
            with patch.object(core, "RUNS", root):
                events = core.Collector().collect(run_id)
                self.assertEqual(len(events), 2)
                indexed = core.monitor_index_path(run_id).read_text()
                self.assertFalse((run_dir / "monitor-events.jsonl").exists())
                self.assertNotIn(nonce, indexed)
                self.assertNotIn(cookie, indexed)
                self.assertIn("[redacted]", indexed)
                for event in events:
                    raw = core.raw_event_record(run_id, event["event_id"])
                    exposed = json.dumps(raw)
                    self.assertNotIn(nonce, exposed)
                    self.assertNotIn(cookie, exposed)
                    self.assertNotIn("body_b64", exposed)

    def test_session_v2_executor_traces_keep_stable_public_keys_and_raw_refs(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-pilo-20261102000000-a1b2c3"
            run_dir = root / run_id
            core.private_json(run_dir / "manifest.json", {"decoy_protocol": "session-v2"})
            episodes = ("executor-" + "a" * 32, "executor-" + "b" * 32)
            for number, episode in enumerate(episodes):
                trace = run_dir / "agent" / "runs" / run_id / "traces" / episode
                trace.mkdir(parents=True)
                core.private_json(trace / "input.json", {"role": "executor"})
                (trace / "events.jsonl").write_text(json.dumps({
                    "sequence": 1, "recorded_at": 1793510001.0 + number,
                    "type": "assistant_text", "text": f"Safe trace {number}",
                }) + "\n")
            with patch.object(core, "RUNS", root):
                collector = core.Collector()
                first = collector.collect(run_id)
                self.assertEqual(len(first), 2)
                self.assertEqual(collector.collect(run_id), first)
                self.assertEqual(len({event["source_key"] for event in first}), 2)
                self.assertEqual(len({event["episode_id"] for event in first}), 2)
                indexed = core.monitor_index_path(run_id).read_text()
                for episode in episodes:
                    self.assertNotIn(episode, indexed)
                for event in first:
                    self.assertTrue(event["episode_id"].startswith("trace-"))
                    self.assertEqual(
                        core.raw_event_record(run_id, event["event_id"])["record"]["text"],
                        event["detail"]["text"],
                    )

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

    def test_committed_task_transition_is_projected_once(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-pilo-20261030000000-a1b2c3"
            state = root / run_id / "agent" / "runs" / run_id / "state.sqlite3"
            state.parent.mkdir(parents=True)
            with sqlite3.connect(state) as connection:
                connection.execute("CREATE TABLE tasks (run_id TEXT, task_id TEXT, kind TEXT, target TEXT, objective TEXT, done_when TEXT, status TEXT)")
                connection.execute("CREATE TABLE transitions (run_id TEXT, revision INTEGER, kind TEXT, task_id TEXT, attempt_id TEXT, detail TEXT, created_at REAL)")
                connection.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
                                   (run_id, "T1", "discover", "http://target", "Map the target", "Evidence exists", "done"))
                connection.execute("INSERT INTO transitions VALUES (?, ?, ?, ?, ?, ?, ?)",
                                   (run_id, 1, "plan_committed", None, "attempt-1",
                                    json.dumps({"summary": "Start discovery", "next_task_id": "T1", "new_task_ids": ["T1"]}), 1793345375.0))
            with patch.object(core, "RUNS", root):
                collector = core.Collector()
                events = collector.collect(run_id)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["kind"], "state_transition")
                self.assertEqual(events[0]["detail"]["task"]["objective"], "Map the target")
                self.assertEqual(events[0]["raw_ref"]["revision"], 1)
                self.assertEqual(collector.collect(run_id), events)
                self.assertEqual(core.raw_event_record(run_id, 1)["record"]["kind"], "plan_committed")

    def test_run_outcome_identifies_a_gateway_token_cap(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-pilo-20261030000000-a1b2c3"
            run_dir = root / run_id
            trace = run_dir / "agent" / "runs" / run_id / "traces" / "executor-1"
            trace.mkdir(parents=True)
            (trace / "input.json").write_text('{"role":"executor"}')
            (trace / "events.jsonl").write_text(json.dumps({
                "sequence": 1, "recorded_at": 1793345375.0, "type": "assistant_text",
                "text": 'API Error: {"error":"trial_cap_reached"}',
            }) + "\n")
            (run_dir / "gateway-events.jsonl").write_text(json.dumps({
                "run_id": run_id, "sequence": 1, "timestamp_utc": "2026-10-30T07:29:35Z",
                "event_type": "cap_reached", "calls": 6, "tokens": 212322,
            }) + "\n")
            core.private_json(run_dir / "manifest.json", {
                "mode": "pilot", "finished_utc": "2026-10-30T07:29:40Z",
                "termination_reason": "agent_exit", "agent_exit_code": 1,
                "max_model_tokens": 200000, "max_model_calls": 60,
                "error": "Attacker agent exited with code 1",
            })
            core.private_json(run_dir / "agent" / "runs" / run_id / "summary.json", {
                "status": "failed", "tasks": [{"id": "T1", "status": "done"}],
            })
            with patch.object(core, "RUNS", root), patch.object(core, "JOBS", root / ".jobs"):
                snapshot = core.run_snapshot(run_id)
                self.assertEqual(snapshot["diagnosed_cause"], "model_token_cap")
                self.assertIn("212,322/200,000", snapshot["error"])
                outcomes = [event for event in core.collector.collect(run_id) if event["kind"] == "run_outcome"]
                self.assertEqual(len(outcomes), 1)
                self.assertEqual(core.raw_event_record(run_id, outcomes[0]["event_id"])["record"]["agent_summary"]["tasks"][0]["status"], "done")

    def test_expanded_raw_record_is_complete_and_path_checked(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-conn-20261030000000-a1b2c3"
            run_dir = root / run_id
            trace = run_dir / "agent" / "runs" / run_id / "traces" / "executor-1"
            trace.mkdir(parents=True)
            (trace / "input.json").write_text('{"role":"executor"}')
            full_text = "x" * 13000
            (trace / "events.jsonl").write_text(json.dumps({
                "sequence": 1, "recorded_at": 1793345375.0, "type": "assistant_text", "text": full_text,
            }) + "\n")
            with patch.object(core, "RUNS", root):
                event = core.Collector().collect(run_id)[0]
                self.assertIn("[display truncated]", event["detail"]["text"])
                self.assertEqual(core.raw_event_record(run_id, event["event_id"])["record"]["text"], full_text)
                core.monitor_index_path(run_id).write_text(json.dumps({
                    "event_id": 1, "source_key": "tampered", "raw_ref": {"file": "../.env", "line": 1},
                }) + "\n")
                with self.assertRaises(FileNotFoundError):
                    core.raw_event_record(run_id, 1)

    def test_failed_agent_archive_is_not_shown_as_complete(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_id = "2a-pilo-20261029075930-33830d"
            run_dir = root / run_id
            trace = run_dir / "agent" / "runs" / run_id / "traces" / "supervisor-r0"
            trace.mkdir(parents=True)
            (trace / "input.json").write_text('{"role":"supervisor"}')
            rows = [
                {"sequence": 1, "recorded_at": 1793260785.1, "type": "raw_event", "kind": "system:thinking_tokens", "data_omitted": True},
                {"sequence": 2, "recorded_at": 1793260785.2, "type": "raw_event", "kind": "system:thinking_tokens", "data_omitted": True},
                {"sequence": 3, "recorded_at": 1793260785.3, "type": "raw_event", "kind": "assistant_error:rate_limit", "data_omitted": True},
            ]
            (trace / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            core.private_json(run_dir / "manifest.json", {"mode": "pilot", "arm": "C2",
                "termination_reason": "agent_exit", "agent_exit_code": 1, "error": None})
            core.private_json(run_dir / "result.json", {"score": {"request_count": 0}})
            jobs = root / ".dashboard-jobs"
            core.private_json(jobs / run_id / "status.json", {"status": "complete"})
            with patch.object(core, "RUNS", root), patch.object(core, "JOBS", jobs):
                snapshot = core.run_snapshot(run_id)
                self.assertEqual(snapshot["status"], "failed")
                self.assertEqual(snapshot["error"], "Attacker agent exited with code 1")
                self.assertEqual(core.list_runs()[0]["status"], "failed")
                self.assertEqual([row["detail"].get("kind") for row in core.collector.collect(run_id)],
                                 ["assistant_error:rate_limit"])

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

    def test_worker_dispatches_agent_modes_without_changing_settings(self) -> None:
        assert core is not None and worker is not None
        for experiment, mode, arm, run_id, target in (
            ("2A", "pilot", "C2", "2a-pilo-20261026000000-a1b2c3", "experiment_controller.run_2a.run"),
            ("2A", "engineering", "C1", "2a-engi-20261026000000-a1b2c3", "experiment_controller.run_2a.run"),
            ("2B", "connectivity", "B0", "2b-conn-20261026000000-a1b2c3", "experiment_controller.run_2b.run_connectivity"),
        ):
            with self.subTest(experiment=experiment), tempfile.TemporaryDirectory() as temporary:
                jobs = Path(temporary) / ".dashboard-jobs"
                request = core.RunRequest(experiment=experiment, mode=mode, arm=arm,
                                          provider="ollama", build=False)
                core.private_json(jobs / run_id / "request.json", request.model_dump())
                core.private_json(jobs / run_id / "status.json", {"run_id": run_id, "status": "queued"})
                with patch.object(core, "JOBS", jobs), patch.object(worker, "JOBS", jobs), \
                     patch(target, return_value={"manifest": {"termination_reason": "connectivity_observed", "error": None}}) as mocked:
                    self.assertEqual(worker.main(run_id), 0)
                    self.assertEqual(core.job_status(run_id)["status"], "complete")
                if experiment == "2A":
                    mocked.assert_called_once_with(mode, arm, build=False, run_id=run_id,
                                                   provider="ollama")
                else:
                    mocked.assert_called_once_with(build=False, seed="fixture-seed", run_id=run_id,
                                                   provider="ollama")

    def test_provider_credential_presence_is_independent(self) -> None:
        assert core is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text('OLLAMA_API_KEY="test-ollama"\n')
            with patch.object(core, "LAB", root / "shape-lab"):
                self.assertTrue(core.key_configured("ollama"))
                self.assertFalse(core.key_configured("zai"))

    def test_session_token_is_private_and_reused(self) -> None:
        assert app is not None and Response is not None
        with tempfile.TemporaryDirectory() as temporary, patch.object(app, "JOBS", Path(temporary)):
            first = asyncio.run(app.session(Response()))["launch_token"]
            second = asyncio.run(app.session(Response()))["launch_token"]
            self.assertEqual(first, second)
            self.assertEqual((Path(temporary) / "session.token").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
