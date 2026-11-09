"""Model-free checks for the separately signed v5 diagnostic continuation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from experiment_controller import path_story_diagnostic_2b_v1 as diagnostic
from experiment_controller import path_story_pilot_2b_v2 as prior
from experiment_controller import path_story_pilot_2b_zai_v5 as parent
from experiment_controller import run_2b_path_story_pilot_zai_v5 as runner
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits


class DiagnosticContinuationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.parent_dir = self.root / "parent"
        self.parent_dir.mkdir()
        (self.parent_dir / "schedule.json").write_text("parent schedule", encoding="utf-8")
        self.schedule = self.root / "diagnostic" / "schedule.json"
        assignments = [
            {"slot": slot, "block": 1 if slot <= 4 else 2,
             "arm": ("B0", "B1", "B3", "B2")[(slot - 1) % 4],
             "seed": "frozen-seed"}
            for slot in range(1, 9)
        ]
        self.original = {
            "assignments": assignments,
            "contract": {"pilot_protocol": parent.PROTOCOL, "provider": "zai", "trial_caps": {"post_entry_wall_seconds": 600}},
            "fingerprint": {"images": {"agent": "sha256:fake"}},
        }
        self.parent_state = {
            "completed_slots": [1, 2], "next_slot": 3,
            "invalid_attempts": [{"slot": 3, "run_id": "2b-path-20261109160000-abcdef", "reason": "provider_rate_limit"}],
            "pending_run": None, "phase": "paused_provider_rate_limit",
            "credits": {"accounting_kind": "estimated_from_reported_usage",
                        "accrued_total": "1000.000000000",
                        "accrued_rolling_five_hour": "1000.000000000"},
        }
        for target, name, replacement in (
            (diagnostic, "SCHEDULE", self.schedule),
            (parent, "_folder", lambda _pilot_id: self.parent_dir),
            (parent, "load_schedule", lambda _pilot_id: self.original),
            (parent, "status", lambda _pilot_id: self.parent_state),
            (prior, "_results", lambda _pilot_id: {}),
        ):
            handle = patch.object(target, name, replacement)
            handle.start()
            self.addCleanup(handle.stop)

    def test_prepare_is_explicit_idempotent_and_freezes_remaining_assignments(self) -> None:
        with patch.object(runner, "run_path_story_pilot", side_effect=AssertionError("provider execution")):
            first = diagnostic.prepare()
            second = diagnostic.prepare()
        frozen = prior._read_committed(self.schedule)
        self.assertEqual(frozen["assignments"], self.original["assignments"][2:])
        self.assertEqual(frozen["contract"], self.original["contract"])
        self.assertEqual(frozen["parent_completed_slots_at_freeze"], [1, 2])
        self.assertFalse(frozen["execution_policy"]["five_hour_429_pause"])
        self.assertEqual(first["phase"], "ready_for_next_run")
        self.assertEqual(first["next_slot"], 3)
        self.assertEqual(second["schedule_sha256"], first["schedule_sha256"])

    def test_execute_uses_original_runner_once_and_signed_diagnostic_admission(self) -> None:
        diagnostic.prepare()
        called = []

        def fake_run(**kwargs: object) -> None:
            called.append(kwargs)
            pending = prior._read_committed(self.schedule.parent / "pending-run.json")
            admission = prior._read_committed(self.schedule.parent / "admissions" / f"{kwargs['run_id']}.json")
            self.assertEqual(pending, admission)
            self.assertEqual(admission["slot"], 3)
            self.assertTrue(admission["credits"]["may_start_new_run"])
            self.assertTrue((self.parent_dir / "execute.lock").exists())
            raise RuntimeError("simulated interruption before archive")

        with patch.object(runner, "run_path_story_pilot", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                diagnostic.execute()
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0]["pilot_id"], diagnostic.PILOT_ID)
        self.assertEqual(called[0]["arm"], "B3")
        self.assertEqual(called[0]["contract"], self.original["contract"])
        self.assertEqual(called[0]["frozen_fingerprint"], self.original["fingerprint"])
        self.assertFalse((self.parent_dir / "execute.lock").exists())
        self.assertEqual(diagnostic.status()["phase"], "pending_attempt_reconciliation")

    def test_429_is_invalid_and_signed_stop_request_takes_precedence(self) -> None:
        diagnostic.prepare()
        run_id = "2b-path-20261110120000-abcdef"
        started = datetime.now(timezone.utc) - timedelta(minutes=2)
        finished = started + timedelta(minutes=1)
        gateway = [{"event_type": "provider_rate_limit_rejected"}]
        credits = estimate_gateway_events_credits(gateway)
        manifest = {
            "run_id": run_id, "started_utc": started.isoformat(), "finished_utc": finished.isoformat(),
            "project": "shape" + run_id, "provider": "zai", "pilot_protocol": parent.PROTOCOL,
            "pilot_fingerprint": self.original["fingerprint"],
            "assignment": {**self.original["assignments"][2], "pilot_id": diagnostic.PILOT_ID},
            "provider_credits": credits, "provider_settlement": {"state": "complete"},
            "termination_reason": "agent_exit", "error": None,
            "confirmed_containment_escape_incident": False,
        }
        result = {"manifest": manifest, "provider_credits": credits}
        run_dir = self.root / "archive"
        run_dir.mkdir()
        (run_dir / "gateway-events.jsonl").write_text(json.dumps(gateway[0]) + "\n", encoding="utf-8")
        admission = {
            "pilot_id": diagnostic.PILOT_ID, "pilot_protocol": diagnostic.PROTOCOL,
            "schedule_sha256": diagnostic._sha(self.schedule), "run_id": run_id, "slot": 3,
            "created_utc": (started - timedelta(seconds=1)).isoformat(),
            "credits": {"may_start_new_run": True},
        }
        prior._write_committed(self.schedule.parent / "admissions" / f"{run_id}.json", admission)
        found = {3: [result]}
        with patch.object(prior, "_results", return_value=found), patch.object(
            prior, "_verify_attempt_artifacts", return_value=run_dir
        ):
            state = diagnostic.status()
            self.assertEqual(state["invalid_attempts"][0]["reason"], "provider_rate_limit")
            self.assertEqual(state["next_slot"], 3)
            self.assertEqual(state["credits"]["accrued_total"], "1000.000000000")
            for suffix in ("abcde1", "abcde2"):
                another_id = "2b-path-20261110120000-" + suffix
                another_manifest = {**manifest, "run_id": another_id, "project": "shape" + another_id}
                found[3].append({"manifest": another_manifest, "provider_credits": credits})
                prior._write_committed(self.schedule.parent / "admissions" / f"{another_id}.json", {
                    **admission, "run_id": another_id,
                })
            state = diagnostic.status()
            self.assertEqual(len(state["invalid_attempts"]), 3)
            self.assertEqual(state["phase"], "ready_for_next_run")
            request_path = self.schedule.parent / "operator-stops" / f"{run_id}.request.json"
            prior._write_committed(request_path, {
                "schema_version": 1, "pilot_id": diagnostic.PILOT_ID, "run_id": run_id, "slot": 3,
                "requested_utc": (started + timedelta(seconds=30)).isoformat(),
                "actor": "local_dashboard", "reason": "operator_stop",
                "project": manifest["project"], "container_id": "a" * 64,
            })
            self.assertEqual(diagnostic.status()["invalid_attempts"][0]["reason"], "operator_stop")
            request_path.with_suffix(".sha256").write_text("0" * 64 + "\n", encoding="utf-8")
            with self.assertRaises(prior.PilotIntegrityError):
                diagnostic.status()

    def test_diagnostic_spend_counts_with_parent_share(self) -> None:
        self.parent_state["credits"]["accrued_total"] = "6000"
        self.parent_state["credits"]["accrued_rolling_five_hour"] = "6000"
        priced = [{"finished_utc": datetime.now(timezone.utc).isoformat(), "credits": Decimal("1000") }]
        decision = diagnostic._credits(self.parent_state, priced)
        self.assertEqual(decision["accrued_total"], "7000.000000000")
        self.assertEqual(decision["remaining_rolling_five_hour"], "7000.000000000")
        self.assertFalse(decision["admitted_by_local_share"])


if __name__ == "__main__":
    unittest.main()
