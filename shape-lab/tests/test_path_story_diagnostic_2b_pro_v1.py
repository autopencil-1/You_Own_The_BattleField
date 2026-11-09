"""Model-free checks for the Pro B3 successor and 401 cost attestation."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from experiment_controller import path_story_diagnostic_2b_pro_v1 as pro
from experiment_controller import path_story_pilot_2b_v2 as committed
from experiment_controller import path_story_pilot_2b_zai_v5 as parent
from experiment_controller import run_2b_path_story_pilot_zai_v5 as runner
from experiment_controller import path_story_diagnostic_2b_v1 as previous
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits


class ProB3ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.parent_dir = self.root / "parent"
        self.parent_dir.mkdir()
        (self.parent_dir / "schedule.json").write_text("parent schedule", encoding="utf-8")
        self.schedule = self.root / "pro" / "schedule.json"
        self.reconciliation = self.schedule.parent / "auth-401-reconciliation.json"
        self.previous_schedule = self.root / "old" / "schedule.json"
        self.previous_schedule.parent.mkdir()
        self.previous_schedule.write_text("old schedule", encoding="utf-8")
        self.assignment = {"slot": 3, "block": 1, "arm": "B3", "seed": "frozen-seed"}
        self.original = {
            "assignments": [{"slot": 1}, {"slot": 2}, self.assignment],
            "contract": {
                "pilot_protocol": parent.PROTOCOL,
                "coding_plan_credit_governance": {
                    "plan_tier": "Max", "rate_revision": "zai-glm-5.3-coding-plan-2026-11-09",
                },
                "trial_caps": {"pre_entry_wall_seconds": 180, "post_entry_wall_seconds": 600},
            },
            "fingerprint": {"images": {"agent": "sha256:" + "a" * 64}},
        }
        self.parent_state = {
            "completed_slots": [1, 2], "next_slot": 3, "pending_run": None,
            "credits": {"accounting_kind": "estimated_from_reported_usage",
                        "accrued_total": "1000.000000000",
                        "accrued_rolling_five_hour": "1000.000000000"},
        }
        self.old_evidence = {"run_id": pro.OLD_401_RUN_ID, "pilot_id": pro.PILOT_ID,
                             "reported_usage_credits": "0.000000000",
                             "operator_attested_no_charge": True,
                             "provider_charge_independently_verified": False}
        for target, name, replacement in (
            (pro, "SCHEDULE", self.schedule),
            (pro, "RECONCILIATION", self.reconciliation),
            (pro, "_old_401_evidence", lambda: self.old_evidence),
            (parent, "_folder", lambda _id: self.parent_dir),
            (parent, "load_schedule", lambda _id: self.original),
            (parent, "status", lambda _id: self.parent_state),
            (previous, "SCHEDULE", self.previous_schedule),
            (committed, "_results", lambda _id: {}),
        ):
            handle = patch.object(target, name, replacement)
            handle.start()
            self.addCleanup(handle.stop)

    def test_prepare_freezes_one_b3_assignment_and_pro_share(self) -> None:
        with patch.object(runner, "run_path_story_pilot", side_effect=AssertionError("model call")):
            first = pro.prepare()
            second = pro.prepare()
        frozen = committed._read_committed(self.schedule)
        self.assertEqual(frozen["assignments"], [self.assignment])
        self.assertEqual(frozen["fingerprint"], self.original["fingerprint"])
        self.assertEqual(frozen["contract"]["coding_plan_credit_governance"]["plan_tier"], "Pro")
        self.assertEqual(frozen["contract"]["coding_plan_credit_governance"]["pilot_five_hour_share_credits"], 6000)
        self.assertEqual(frozen["contract"]["coding_plan_credit_governance"]["pilot_total_share_credits"], 15000)
        self.assertEqual(first["reconciled_run_id"], pro.OLD_401_RUN_ID)
        self.assertEqual(first["schedule_sha256"], second["schedule_sha256"])
        self.assertEqual(first["next_slot"], 3)
        self.assertEqual(first["credits"]["minimum_uncommitted_per_new_run"], "3000")
        self.assertTrue(first["launch_available"])

    def test_credit_gate_uses_smaller_pro_shares_and_carries_parent_usage(self) -> None:
        self.parent_state["credits"].update({"accrued_total": "4000", "accrued_rolling_five_hour": "4000"})
        decision = pro._credits(self.parent_state, [])
        self.assertEqual(decision["remaining_total"], "11000.000000000")
        self.assertEqual(decision["remaining_rolling_five_hour"], "2000.000000000")
        self.assertFalse(decision["admitted_by_local_share"])
        self.parent_state["credits"].update({"accrued_total": "1000", "accrued_rolling_five_hour": "1000"})
        decision = pro._credits(self.parent_state, [{"finished_utc": datetime.now(timezone.utc).isoformat(),
                                                      "credits": Decimal("1500")}])
        self.assertEqual(decision["accrued_total"], "2500.000000000")
        self.assertEqual(decision["remaining_rolling_five_hour"], "3500.000000000")
        self.assertTrue(decision["admitted_by_local_share"])

    def test_execute_writes_pro_admission_and_calls_frozen_runner_once(self) -> None:
        pro.prepare()
        called = []

        def fake_run(**kwargs: object) -> None:
            called.append(kwargs)
            admission = committed._read_committed(self.schedule.parent / "admissions" / f"{kwargs['run_id']}.json")
            pending = committed._read_committed(self.schedule.parent / "pending-run.json")
            self.assertEqual(admission, pending)
            self.assertEqual(admission["pilot_protocol"], pro.PROTOCOL)
            self.assertEqual(admission["credits"]["plan_tier"], "Pro")
            self.assertEqual(admission["reconciliation_sha256"], pro._sha(self.reconciliation))
            self.assertTrue((self.parent_dir / "execute.lock").exists())
            raise RuntimeError("simulated interruption")

        with patch.object(runner, "run_path_story_pilot", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                pro.execute()
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0]["pilot_id"], pro.PILOT_ID)
        self.assertEqual(called[0]["arm"], "B3")
        self.assertEqual(called[0]["contract"]["coding_plan_credit_governance"]["plan_tier"], "Pro")
        self.assertEqual(pro.status()["phase"], "pending_attempt_reconciliation")

    def test_429_keeps_b3_available_for_a_separate_next_click(self) -> None:
        pro.prepare()
        run_id = "2b-path-20261110120000-abcdef"
        now = datetime.now(timezone.utc).isoformat()
        gateway = [{"event_type": "provider_rate_limit_rejected"}]
        credits = estimate_gateway_events_credits(gateway)
        manifest = {
            "run_id": run_id, "pilot_protocol": parent.PROTOCOL, "provider": "zai",
            "pilot_fingerprint": self.original["fingerprint"],
            "trial_caps": self.original["contract"]["trial_caps"],
            "assignment": {**self.assignment, "pilot_id": pro.PILOT_ID},
            "started_utc": now, "finished_utc": now,
            "provider_credits": credits,
            "provider_settlement": {"state": "complete"},
            "termination_reason": "provider_rate_limit", "error": None,
            "confirmed_containment_escape_incident": False,
        }
        result = {"manifest": manifest, "provider_credits": credits}
        archive = self.root / "archive-429"
        archive.mkdir()
        (archive / "gateway-events.jsonl").write_text(json.dumps(gateway[0]) + "\n", encoding="utf-8")
        committed._write_committed(self.schedule.parent / "admissions" / f"{run_id}.json", {
            "pilot_id": pro.PILOT_ID, "pilot_protocol": pro.PROTOCOL,
            "schedule_sha256": pro._sha(self.schedule),
            "reconciliation_sha256": pro._sha(self.reconciliation),
            "run_id": run_id, "slot": 3,
            "credits": {"may_start_new_run": True}, "created_utc": now,
        })
        with patch.object(committed, "_results", return_value={3: [result]}), \
                patch.object(committed, "_verify_attempt_artifacts", return_value=archive):
            observed = pro.status()
        self.assertEqual(observed["invalid_attempts"], [{"slot": 3, "run_id": run_id,
                                                        "reason": "provider_rate_limit"}])
        self.assertEqual(observed["phase"], "ready_for_next_run")
        self.assertEqual(observed["next_slot"], 3)
        self.assertTrue(observed["launch_available"])

    def test_incomplete_new_settlement_blocks_more_pro_attempts(self) -> None:
        pro.prepare()
        run_id = "2b-path-20261110120000-abcdef"
        now = datetime.now(timezone.utc).isoformat()
        credits = estimate_gateway_events_credits([])
        manifest = {
            "run_id": run_id, "pilot_protocol": parent.PROTOCOL, "provider": "zai",
            "pilot_fingerprint": self.original["fingerprint"],
            "trial_caps": self.original["contract"]["trial_caps"],
            "assignment": {**self.assignment, "pilot_id": pro.PILOT_ID},
            "started_utc": now, "finished_utc": now,
            "provider_credits": credits,
            "provider_settlement": {"state": "incomplete"},
            "termination_reason": "controller_error", "error": "settlement incomplete",
            "confirmed_containment_escape_incident": False,
        }
        result = {"manifest": manifest, "provider_credits": credits}
        archive = self.root / "archive"
        archive.mkdir()
        (archive / "gateway-events.jsonl").write_text("", encoding="utf-8")
        committed._write_committed(self.schedule.parent / "admissions" / f"{run_id}.json", {
            "pilot_id": pro.PILOT_ID, "pilot_protocol": pro.PROTOCOL,
            "schedule_sha256": pro._sha(self.schedule),
            "reconciliation_sha256": pro._sha(self.reconciliation),
            "run_id": run_id, "slot": 3,
            "credits": {"may_start_new_run": True}, "created_utc": now,
        })
        with patch.object(committed, "_results", return_value={3: [result]}), \
                patch.object(committed, "_verify_attempt_artifacts", return_value=archive):
            observed = pro.status()
        self.assertEqual(observed["phase"], "paused_unreconciled_provider_exposure")
        self.assertFalse(observed["launch_available"])
        self.assertEqual(observed["invalid_attempts"][0]["run_id"], run_id)


class Old401ReconciliationTests(unittest.TestCase):
    def test_exact_rejected_lifecycle_is_required(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            schedule = root / "old" / "schedule.json"
            committed._write_committed(schedule, {"assignments": [{"slot": 3, "block": 1,
                                                                     "arm": "B3", "seed": "frozen-seed"}]})
            archive = root / pro.OLD_401_RUN_ID
            archive.mkdir()
            rows = []
            for request_id in range(1, 277):
                common = {"request_id": request_id, "run_id": pro.OLD_401_RUN_ID,
                          "source": "model-gateway"}
                rows.extend([
                    {**common, "event_type": "request_started"},
                    {**common, "event_type": "model_call", "call_number": request_id,
                     "attempt_number": 1, "provider": "zai", "model": "glm-5.3",
                     "status": 401, "usage": None},
                    {**common, "event_type": "provider_response_complete", "call_number": request_id,
                     "attempt_number": 1, "status": 401, "usage_recorded": False},
                    {**common, "event_type": "request_finished"},
                ])
            for sequence, row in enumerate(rows, 1):
                row["sequence"] = sequence
            gateway = archive / "gateway-events.jsonl"
            gateway.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            credits = estimate_gateway_events_credits(rows)
            replay = {"filesystem_actions": 0}
            manifest = {
                "run_id": pro.OLD_401_RUN_ID, "pilot_id": previous.PILOT_ID,
                "assignment": {"pilot_id": previous.PILOT_ID, "slot": 3, "block": 1,
                               "arm": "B3", "seed": "frozen-seed"},
                "provider": "zai", "termination_reason": "controller_error",
                "error": "Gateway request lifecycle did not settle",
                "confirmed_containment_escape_incident": False,
                "provider_credits": credits,
                "provider_settlement": {
                    "state": "incomplete", "started_request_count": 276,
                    "finished_request_count": 276, "provider_completed_request_count": 0,
                    "local_rejection_request_count": 0,
                    "unaccounted_request_ids": list(range(1, 277)),
                    "unmatched_request_ids": [], "aborted_request_ids": [],
                    "downstream_delivery_failed_ids": [],
                },
            }
            result = {"manifest": manifest, "provider_credits": credits, "replay": replay}
            (archive / "attempt-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (archive / "result.json").write_text(json.dumps(result), encoding="utf-8")
            state = {"completed_slots": [], "invalid_attempts": [{"slot": 3,
                    "run_id": pro.OLD_401_RUN_ID, "reason": "controller_error"}], "pending_run": None}
            with patch.object(previous, "SCHEDULE", schedule), \
                    patch.object(previous, "status", return_value=state), \
                    patch.object(committed, "_results", return_value={3: [result]}), \
                    patch.object(committed, "_verify_attempt_artifacts", return_value=archive), \
                    patch.object(pro, "verify_path_story_bundle", return_value=replay):
                evidence = pro._old_401_evidence()
                self.assertEqual(evidence["request_count"], 276)
                self.assertFalse(evidence["provider_charge_independently_verified"])
                rows[5]["status"] = 200
                gateway.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                with self.assertRaises(pro.ProDiagnosticIntegrityError):
                    pro._old_401_evidence()


if __name__ == "__main__":
    unittest.main()
