"""Model-free dashboard checks for frozen 2B path-story run archives."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from dashboard import app, core


class DashboardPathStoryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runs = self.root / "runs"
        self.studies = self.root / "studies"
        self.jobs = self.runs / ".dashboard-jobs"
        self.runs.mkdir()
        for name, value in (("RUNS", self.runs), ("STUDIES", self.studies), ("JOBS", self.jobs)):
            replacement = patch.object(core, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

    @staticmethod
    def _json(path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def _archive(self, *, run_id: str, arm: str = "B3",
                 termination: str = "post_entry_wall_cap") -> Path:
        run = self.runs / run_id
        run.mkdir()
        self._json(run / "manifest.json", {"run_id": run_id, "arm": arm,
                                            "catalog_fingerprint": "synthetic-catalog"})
        items = [
            {"inventory_index": 1, "path": "/srv/example/releases/app.json"},
            {"inventory_index": 2, "path": "/srv/example/releases/app.json.bak"},
            {"inventory_index": 3, "path": "/var/log/example/service.log"},
        ]
        self._json(run / "materialization-inventory.json", {"items": items})
        artifacts = {
            name: hashlib.sha256((run / name).read_bytes()).hexdigest()
            for name in ("manifest.json", "materialization-inventory.json")
        }
        attempt = {
            "run_id": run_id, "mode": "path_story_pilot", "arm": arm, "provider": "zai",
            "pilot_id": "2b-path-story-pilot-v5-zai-synthetic", "pilot_protocol": "2b-path-story-pilot-v5-zai",
            "slot": 3, "block": 2, "environment_protocol": "filesystem-path-story-v1",
            "started_utc": "2026-11-10T00:00:00Z", "finished_utc": "2026-11-10T00:11:00Z",
            "termination_reason": termination, "error": None, "experimental_result": False,
            "trial_caps": {"pre_entry_wall_seconds": 180, "post_entry_wall_seconds": 600,
                           "maximum_total_wall_seconds": 780},
            "clock": {"clock_phase": "post_entry", "pre_entry_elapsed_seconds": 60,
                      "post_entry_elapsed_seconds": 600, "qualified_entry_utc": "2026-11-10T00:01:00Z"},
            "replay": {"filesystem_actions": 18, "materialized_nodes": len(items)},
            "provider_credits": {"estimated_total_credits": "12.345000000"},
            "provider_settlement": {"state": "complete"},
            "artifact_sha256": artifacts,
        }
        self._json(run / "attempt-manifest.json", attempt)
        self._json(run / "result.json", {
            "manifest": attempt, "replay": attempt["replay"],
            "provider_credits": attempt["provider_credits"],
            "score": {"experimental_result": False, "filesystem_actions": 18,
                      "materialized_nodes": len(items)},
        })
        return run

    def test_archived_attempt_uses_controller_manifest_and_keeps_review_boundary(self) -> None:
        run_id = "2b-path-20261110000000-a1b2c3"
        self._archive(run_id=run_id)
        row = next(item for item in core.list_runs() if item["run_id"] == run_id)
        self.assertEqual((row["mode"], row["arm"], row["provider"]),
                         ("path_story_pilot", "B3", "zai"))
        self.assertEqual(row["started_utc"], "2026-11-10T00:00:00Z")
        self.assertEqual(row["termination_reason"], "post_entry_wall_cap")
        self.assertEqual(row["attempt_classification"], "controller_review")
        snapshot = core.run_snapshot(run_id)
        self.assertEqual(snapshot["status"], "complete")
        self.assertEqual(snapshot["pilot_protocol"], "2b-path-story-pilot-v5-zai")
        self.assertEqual((snapshot["slot"], snapshot["block"]), (3, 2))
        self.assertEqual(snapshot["provider_credits_estimated"], "12.345000000")
        self.assertEqual(snapshot["provider_settlement_state"], "complete")
        self.assertEqual(snapshot["progress"]["materialized_nodes"], 3)
        self.assertFalse(snapshot["experimental_result"])

    def test_provider_rate_limit_is_infrastructure_invalid_even_with_result(self) -> None:
        run_id = "2b-path-20261110000001-a1b2c3"
        self._archive(run_id=run_id, termination="provider_rate_limit")
        row = next(item for item in core.list_runs() if item["run_id"] == run_id)
        snapshot = core.run_snapshot(run_id)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["attempt_classification"], "infrastructure_invalid")
        self.assertEqual(snapshot["status"], "failed")
        self.assertIn("rate limit", snapshot["error"].lower())
        self.assertEqual(snapshot["termination_reason"], "provider_rate_limit")
        self.assertFalse(snapshot["experimental_result"])

    def test_pending_attempt_uses_admission_and_latest_complete_cap_sample(self) -> None:
        run_id = "2b-path-20261110000002-a1b2c3"
        pilot_id = "2b-path-story-pilot-v5-zai-synthetic"
        study = self.studies / pilot_id
        self._json(study / "pending-run.json", {
            "run_id": run_id, "pilot_id": pilot_id, "slot": 4,
            "created_utc": "2026-11-10T00:00:02Z",
        })
        self._json(study / "schedule.json", {
            "pilot_protocol": "2b-path-story-pilot-v5-zai",
            "assignments": [{"slot": 4, "block": 2, "arm": "B1"}],
            "contract": {"provider": "zai", "trial_caps": {
                "pre_entry_wall_seconds": 180, "post_entry_wall_seconds": 600,
                "maximum_total_wall_seconds": 780}},
        })
        queued = core.provisional_snapshot(run_id)
        self.assertIsNotNone(queued)
        self.assertEqual(queued["status"], "queued")
        self.assertEqual((queued["arm"], queued["slot"]), ("B1", 4))
        queued_rows = [item for item in core.list_runs() if item["run_id"] == run_id]
        self.assertEqual(len(queued_rows), 1)
        self.assertEqual(queued_rows[0]["status"], "queued")
        self.assertFalse(core.materialization_page(run_id)["available"])
        run = self.runs / run_id
        run.mkdir()
        self._json(run / "manifest.json", {"run_id": run_id, "arm": "B1"})
        sample = {"observed_utc": "2026-11-10T00:01:15Z", "clock_phase": "post_entry",
                  "pre_entry_elapsed_seconds": 45, "post_entry_elapsed_seconds": 30,
                  "qualified_entry_utc": "2026-11-10T00:00:45Z",
                  "filesystem_actions": 12, "agent_tool_calls": 14,
                  "model_calls": 5, "model_tokens": 1000, "selected_reason": None}
        (run / "cap-monitor.jsonl").write_text(json.dumps(sample) + "\n{partial", encoding="utf-8")
        live_rows = [item for item in core.list_runs() if item["run_id"] == run_id]
        self.assertEqual(len(live_rows), 1)
        row = live_rows[0]
        snapshot = core.run_snapshot(run_id)
        self.assertEqual((row["status"], row["arm"], row["provider"]), ("running", "B1", "zai"))
        self.assertEqual(row["started_utc"], "2026-11-10T00:00:02Z")
        self.assertEqual(snapshot["progress"]["phase"], "post_entry")
        self.assertEqual(snapshot["progress"]["filesystem_actions"], 12)
        self.assertEqual(snapshot["progress"]["post_entry_wall_seconds"], 600)
        self.assertIsNone(snapshot["attempt_classification"])
        self.assertFalse(core.materialization_page(run_id)["available"])

    def test_partial_attempt_archive_cannot_be_complete_or_reviewable(self) -> None:
        for missing in ("replay", "provider_settlement"):
            with self.subTest(missing=missing):
                run_id = "2b-path-20261110000007-" + ("a1b2c3" if missing == "replay" else "d4e5f6")
                run = self._archive(run_id=run_id)
                attempt = json.loads((run / "attempt-manifest.json").read_text())
                attempt.pop(missing)
                self._json(run / "attempt-manifest.json", attempt)
                row = next(item for item in core.list_runs() if item["run_id"] == run_id)
                snapshot = core.run_snapshot(run_id)
                self.assertEqual(row["status"], "failed")
                self.assertNotEqual(row["attempt_classification"], "controller_review")
                self.assertEqual(snapshot["status"], "failed")
                self.assertNotEqual(snapshot["attempt_classification"], "controller_review")

    def test_signed_sidecar_hash_mismatch_blocks_review(self) -> None:
        run_id = "2b-path-20261110000010-a1b2c3"
        run = self._archive(run_id=run_id)
        sidecar = run / "agent" / "runs" / run_id / "state.sqlite3-shm"
        sidecar.parent.mkdir(parents=True)
        sidecar.write_bytes(b"original WAL index")
        attempt = json.loads((run / "attempt-manifest.json").read_text())
        name = sidecar.relative_to(run).as_posix()
        attempt["artifact_sha256"][name] = hashlib.sha256(sidecar.read_bytes()).hexdigest()
        self._json(run / "attempt-manifest.json", attempt)
        result = json.loads((run / "result.json").read_text())
        result["manifest"] = attempt
        self._json(run / "result.json", result)
        self.assertEqual(core.run_snapshot(run_id)["attempt_classification"], "controller_review")
        sidecar.write_bytes(b"changed WAL index")
        row = next(item for item in core.list_runs() if item["run_id"] == run_id)
        snapshot = core.run_snapshot(run_id)
        self.assertEqual((row["status"], snapshot["status"]), ("failed", "failed"))
        self.assertEqual((row["attempt_classification"], snapshot["attempt_classification"]),
                         ("infrastructure_invalid", "infrastructure_invalid"))
        self.assertIn("signed manifest", snapshot["error"])

    def test_outcome_raw_record_is_allowlisted_and_monitor_cache_stays_outside_run(self) -> None:
        run_id = "2b-path-20261110000003-a1b2c3"
        run = self._archive(run_id=run_id)
        before = {path.relative_to(run): path.read_bytes() for path in run.rglob("*") if path.is_file()}
        events = core.collector.collect(run_id)
        outcome = next(item for item in events if item["kind"] == "run_outcome")
        self.assertEqual(outcome["raw_ref"]["file"], "attempt-manifest.json")
        raw = core.raw_event_record(run_id, outcome["event_id"])
        self.assertEqual(raw["record"]["pilot_protocol"], "2b-path-story-pilot-v5-zai")
        self.assertTrue(core.monitor_index_path(run_id).is_file())
        self.assertFalse(core.monitor_index_path(run_id).is_relative_to(run))
        after = {path.relative_to(run): path.read_bytes() for path in run.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        forged = [{"event_id": 1, "kind": "run_outcome", "raw_ref": {"file": "manifest.json"}}]
        with patch.object(core.collector, "collect", return_value=forged):
            with self.assertRaises(FileNotFoundError):
                core.raw_event_record(run_id, 1)

    def test_archived_agent_state_read_creates_no_sqlite_sidecars(self) -> None:
        run_id = "2b-path-20261110000006-a1b2c3"
        run = self._archive(run_id=run_id)
        database = run / "agent" / "runs" / run_id / "state.sqlite3"
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE tasks (run_id TEXT, task_id TEXT, kind TEXT, target TEXT, objective TEXT, done_when TEXT)")
            connection.execute("CREATE TABLE transitions (run_id TEXT, revision INTEGER, kind TEXT, task_id TEXT, attempt_id TEXT, detail TEXT, created_at REAL)")
            connection.execute("INSERT INTO transitions VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (run_id, 1, "attempt_committed", "T1", "A1", "{}", 1794268800.0))
            connection.commit()
        finally:
            connection.close()
        sidecars = [database.with_name(database.name + suffix) for suffix in ("-wal", "-shm")]
        self.assertFalse(any(path.exists() for path in sidecars))
        events = core.Collector().collect(run_id)
        state = next(event for event in events if event["kind"] == "state_transition")
        core.raw_event_record(run_id, state["event_id"])
        self.assertFalse(any(path.exists() for path in sidecars))

    def test_live_wal_backed_state_transitions_are_visible(self) -> None:
        run_id = "2b-path-20261110000008-a1b2c3"
        run = self.runs / run_id
        database = run / "agent" / "runs" / run_id / "state.sqlite3"
        database.parent.mkdir(parents=True)
        writer = sqlite3.connect(database)
        try:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("CREATE TABLE tasks (run_id TEXT, task_id TEXT, kind TEXT, target TEXT, objective TEXT, done_when TEXT)")
            writer.execute("CREATE TABLE transitions (run_id TEXT, revision INTEGER, kind TEXT, task_id TEXT, attempt_id TEXT, detail TEXT, created_at REAL)")
            writer.execute("INSERT INTO transitions VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (run_id, 1, "attempt_committed", "T1", "A1", "{}", 1794268800.0))
            writer.commit()  # The writer remains open, so its commit is still in WAL.
            events = core.Collector().collect(run_id)
            state = next(item for item in events if item["kind"] == "state_transition")
            self.assertEqual(state["detail"]["revision"], 1)
            self.assertEqual(core.raw_event_record(run_id, state["event_id"])["record"]["revision"], 1)
        finally:
            writer.close()

    def test_finalized_wal_archive_reads_committed_rows_without_mutation(self) -> None:
        run_id = "2b-path-20261110000009-a1b2c3"
        run = self._archive(run_id=run_id)
        database = run / "agent" / "runs" / run_id / "state.sqlite3"
        database.parent.mkdir(parents=True)
        writer = sqlite3.connect(database)
        try:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("CREATE TABLE tasks (run_id TEXT, task_id TEXT, kind TEXT, target TEXT, objective TEXT, done_when TEXT)")
            writer.execute("CREATE TABLE transitions (run_id TEXT, revision INTEGER, kind TEXT, task_id TEXT, attempt_id TEXT, detail TEXT, created_at REAL)")
            for revision in range(1, 9):
                writer.execute("INSERT INTO transitions VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (run_id, revision, "attempt_committed", "T1", f"A{revision}", "{}", 1794268800.0 + revision))
            writer.commit()
            writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            for revision in (9, 10):
                writer.execute("INSERT INTO transitions VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (run_id, revision, "attempt_committed", "T1", f"A{revision}", "{}", 1794268800.0 + revision))
            writer.commit()
            with sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True) as stale:
                self.assertEqual(stale.execute("SELECT COUNT(*) FROM transitions").fetchone()[0], 8)
            tracked = [path for path in database.parent.glob("state.sqlite3*") if path.is_file()]
            before = {path.name: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                      for path in tracked}
            events = core.Collector().collect(run_id)
            revisions = [item["detail"]["revision"] for item in events if item["kind"] == "state_transition"]
            self.assertEqual(revisions, list(range(1, 11)))
            final = next(item for item in events if item["kind"] == "state_transition"
                         and item["detail"]["revision"] == 10)
            self.assertEqual(core.raw_event_record(run_id, final["event_id"])["record"]["revision"], 10)
            after = {path.name: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                     for path in tracked}
            self.assertEqual(before, after)
        finally:
            writer.close()

    def test_materialization_pages_are_verified_and_hash_mismatch_rejected(self) -> None:
        run_id = "2b-path-20261110000004-a1b2c3"
        run = self._archive(run_id=run_id)
        first = core.materialization_page(run_id, limit=2)
        self.assertEqual([item["inventory_index"] for item in first["items"]], [1, 2])
        self.assertTrue(first["has_more"])
        self.assertTrue(first["verified"])
        second = asyncio.run(app.materializations(run_id, after=first["next_after"], limit=2))
        self.assertEqual([item["inventory_index"] for item in second["items"]], [3])
        self.assertFalse(second["has_more"])
        with self.assertRaises(ValueError):
            core.materialization_page(run_id, limit=201)
        (run / "materialization-inventory.json").write_text('{"items": []}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            core.materialization_page(run_id)
        with self.assertRaises(HTTPException) as context:
            asyncio.run(app.materializations(run_id))
        self.assertEqual(context.exception.status_code, 409)

    def test_legacy_2b_manifest_remains_the_controller_source(self) -> None:
        run_id = "2b-cont-20261110000005-a1b2c3"
        run = self.runs / run_id
        run.mkdir()
        self._json(run / "manifest.json", {
            "run_id": run_id, "mode": "controlled", "arm": "B0", "provider": "zai",
            "started_utc": "2026-11-10T00:00:05Z", "finished_utc": "2026-11-10T00:01:05Z",
            "termination_reason": "wall_cap", "experimental_result": True,
        })
        self._json(run / "result.json", {"score": {"experimental_result": True}})
        row = next(item for item in core.list_runs() if item["run_id"] == run_id)
        snapshot = core.run_snapshot(run_id)
        self.assertEqual((row["mode"], row["arm"], row["status"]), ("controlled", "B0", "complete"))
        self.assertEqual(snapshot["termination_reason"], "wall_cap")
        self.assertTrue(snapshot["experimental_result"])


if __name__ == "__main__":
    unittest.main()
