"""Model-free checks for the prospective gateway closeout candidate."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import path_story_pilot_2b_v3 as candidate


class PathStoryV3CandidateTests(unittest.TestCase):
    def test_candidate_binds_paused_v2_without_enrollment_or_funding(self) -> None:
        observed = candidate.check()
        self.assertEqual(observed["candidate_protocol"], "2b-path-story-pilot-v3-candidate")
        self.assertEqual(observed["prior_v2_closeout_context"]["accrued_usd"], "46.339601000")
        self.assertEqual(
            observed["prior_v2_closeout_context"]["remaining_authorization_usd"],
            "53.660399000",
        )
        self.assertFalse(observed["schedule_frozen"])
        self.assertFalse(observed["authorization_transferred"])
        self.assertEqual(observed["model_calls"], 0)
        self.assertEqual(observed["task_sha256"], candidate._sha(candidate.TASK))

    def test_candidate_rejects_implicit_authorization_transfer(self) -> None:
        raw = json.loads(candidate.CONFIG.read_text(encoding="utf-8"))
        raw["provider_cost_governance"]["v2_authorization_transfer_performed"] = True
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "candidate.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with patch.object(candidate, "CONFIG", path):
                with self.assertRaises(candidate.CandidateIntegrityError):
                    candidate.load_contract()

    def test_docker_check_uses_dummy_key_preflights_only(self) -> None:
        contract = candidate.load_contract()
        fake_preflight = [
            {"status": "passed", "arm": arm, "model_calls": 0, "agent_started": False}
            for arm in ("B0", "B3")
        ]
        commands: list[list[str]] = []

        def fake_run(args, **kwargs):
            commands.append(args)
            if args[:3] == ["docker", "image", "inspect"]:
                return subprocess.CompletedProcess(args, 0, b"sha256:" + b"a" * 64 + b"\n", b"")
            return subprocess.CompletedProcess(args, 0, b"build complete\n", b"")

        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(candidate, "REPORTS", Path(temporary)),
                patch.object(candidate, "load_contract", return_value=contract),
                patch.object(candidate, "check", return_value={"schedule_frozen": False}),
                patch.object(candidate.subprocess, "run", side_effect=fake_run),
                patch(
                    "experiment_controller.run_2b_path_story_pilot_v3.preflight_no_model",
                    side_effect=fake_preflight,
                ) as preflight,
            ):
                report = candidate.docker_check()
                self.assertEqual(preflight.call_count, 2)
                self.assertEqual([call.kwargs["arm"] for call in preflight.call_args_list], ["B0", "B3"])
                self.assertEqual(report["model_calls"], 0)
                self.assertFalse(report["authorization_transferred"])
                self.assertFalse(report["schedule_frozen"])
                self.assertEqual(len(report["preflights"]), 2)
                self.assertTrue((Path(temporary) / report["report_id"] / "report.sha256").is_file())
        self.assertEqual(sum("build" in command for command in commands), 1)
        self.assertFalse(any("attacker-agent" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
