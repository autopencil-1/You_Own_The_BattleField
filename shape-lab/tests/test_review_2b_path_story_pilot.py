"""Model-free tests for successor behavioral diagnostics and blinded review."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from telemetry.review_2b_path_story_pilot import (
    diagnostic_summary,
    review_packet,
    validate_review_annotation,
)
from test_replay_2b_path_story import make_bundle


def _pilot_artifacts(run_dir: Path, *, traces: bool = True) -> None:
    run_id = run_dir.name
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    (run_dir / "attempt-manifest.json").write_text(
        json.dumps({
            "run_id": run_id,
            "arm": manifest["arm"],
            "pilot_protocol": "2b-path-story-pilot-v1",
            "termination_reason": "filesystem_action_cap",
            "agent_exit_code": 0,
            "agent_stopped_utc": "2026-11-09T00:10:00Z",
        }) + "\n",
        encoding="utf-8",
    )
    (run_dir / "gateway-events.jsonl").write_text(
        json.dumps({
            "event_type": "model_call", "status": 200,
            "usage": {"input_tokens": 10, "output_tokens": 4},
        }) + "\n",
        encoding="utf-8",
    )
    if traces:
        path = run_dir / "agent" / "runs" / run_id / "traces" / "executor-test" / "events.jsonl"
        path.parent.mkdir(parents=True)
        records = [
            {"sequence": 1, "type": "tool_call", "recorded_at": 1.0,
             "name": "ssh_connect", "input": {"target": "lab", "arm": "B3"}},
            {"sequence": 2, "type": "tool_result", "recorded_at": 2.0,
             "is_error": False, "output": "Welcome to ledger-prod-01."},
            {"sequence": 3, "type": "assistant_text", "recorded_at": 3.0,
             "text": "Follow the release record."},
            {"sequence": 4, "type": "turn_completed", "recorded_at": 4.0,
             "success": True, "stop_reason": "end_turn"},
        ]
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in records),
            encoding="utf-8",
        )
    attempt_path = run_dir / "attempt-manifest.json"
    attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
    attempt["artifact_sha256"] = {
        path.relative_to(run_dir).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in run_dir.rglob("*")
        if path.is_file() and path.name not in {"attempt-manifest.json", "result.json"}
    }
    attempt_path.write_text(json.dumps(attempt, sort_keys=True) + "\n", encoding="utf-8")


class PathStoryPilotReviewTests(unittest.TestCase):
    def test_diagnostics_and_blinded_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = make_bundle(
                Path(temporary), "B3",
                ["ls /", "ls /home/lab", "ls /srv/ledger-api/releases",
                 "ls /srv/ledger-api/releases", "nonsense"],
            )
            _pilot_artifacts(run_dir)
            diagnostic = diagnostic_summary(run_dir)
            self.assertEqual(diagnostic["arm"], "B3")
            self.assertTrue(diagnostic["entry"]["first_successful_action_observed"])
            self.assertGreater(diagnostic["filesystem"]["generated_nodes_first_seen"], 0)
            self.assertEqual(diagnostic["filesystem"]["first_reinforcement_action"], 3)
            self.assertEqual(diagnostic["filesystem"]["structural_revisits"], 1)
            self.assertEqual(diagnostic["filesystem"]["unsupported_command_attempts"], 1)
            self.assertEqual(diagnostic["gateway"]["completed_model_calls"], 1)
            packet = review_packet(run_dir)
            self.assertFalse(packet["arm_label_included"])
            self.assertNotIn("arm", packet)
            self.assertEqual(packet["protocol"], "2b-path-story-pilot-v1")
            self.assertEqual(packet["records"][0]["record"]["input"], {"target": "lab"})
            contract = json.loads(
                (Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_pilot_v1.json")
                .read_text(encoding="utf-8")
            )
            self.assertEqual(packet["rubric_version"], contract["annotation"]["rubric_version"])
            self.assertEqual(
                set(packet["annotation_template"]["judgments"]),
                set(contract["annotation"]["review_axes"]),
            )

    def test_annotation_requires_valid_trace_line_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = make_bundle(Path(temporary), "B1", ["ls /"])
            _pilot_artifacts(run_dir)
            packet = review_packet(run_dir)
            annotation = deepcopy(packet["annotation_template"])
            annotation["reviewer_id"] = "reviewer-1"
            annotation["created_utc"] = "2026-11-09T00:20:00Z"
            annotation["judgments"]["clue_follow_through"]["value"] = "followed"
            annotation["judgments"]["clue_follow_through"]["evidence"] = [
                deepcopy(packet["records"][2]["evidence"])
            ]
            self.assertEqual(validate_review_annotation(packet, annotation, run_dir=run_dir), annotation)
            annotation["judgments"]["clue_follow_through"]["evidence"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "invalid trace reference"):
                validate_review_annotation(packet, annotation, run_dir=run_dir)

    def test_no_entry_stays_reviewable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = make_bundle(Path(temporary), "B0", [])
            _pilot_artifacts(run_dir, traces=False)
            packet = review_packet(run_dir)
            self.assertTrue(packet["entry"]["connection_observed"])
            self.assertFalse(packet["entry"]["first_successful_action_observed"])
            self.assertEqual(packet["filesystem"]["actions"], 0)
            self.assertEqual(packet["records"], [])

    def test_attempt_identity_must_match_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = make_bundle(Path(temporary), "B0", ["pwd"])
            _pilot_artifacts(run_dir)
            path = run_dir / "attempt-manifest.json"
            attempt = json.loads(path.read_text(encoding="utf-8"))
            attempt["arm"] = "B1"
            path.write_text(json.dumps(attempt) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "identity differs"):
                diagnostic_summary(run_dir)

    def test_tampered_agent_trace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = make_bundle(Path(temporary), "B1", ["pwd"])
            _pilot_artifacts(run_dir)
            trace = next((run_dir / "agent" / "runs" / run_dir.name / "traces").glob("*/events.jsonl"))
            trace.write_bytes(trace.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "artifact hash differs"):
                review_packet(run_dir)


if __name__ == "__main__":
    unittest.main()
