"""Model-free checks for the controlled-v3 execution boundary."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import controlled_2b_v3 as study
from experiment_controller.controlled_2b_v3_contract import LAB
from experiment_controller.run_2b_controlled_v3 import agent_trace_events
from telemetry.score_2b_controlled_v3 import score_events
from telemetry.replay_2b_controlled_v3 import verify_run


class ControlledV3ExecutionTests(unittest.TestCase):
    def test_validated_support_envelope_scores_as_prospective_v3(self) -> None:
        run_id = "2b-supp-20261106080723-511b83"
        folder = LAB / "runs" / run_id
        source = json.loads((folder / "result.json").read_text(encoding="utf-8"))
        manifest = deepcopy(source["manifest"])
        manifest["mode"] = "controlled"
        manifest["study_protocol"] = "2b-controlled-v3"
        manifest["experimental_result"] = True
        manifest.pop("pilot_protocol", None)
        events = [json.loads(line) for line in (folder / "decoy-events.jsonl").read_text().splitlines() if line]
        gateway = [json.loads(line) for line in (folder / "gateway-events.jsonl").read_text().splitlines() if line]
        score = score_events(
            events, manifest, gateway_events=gateway,
            agent_trace_events=agent_trace_events(folder / "agent", run_id),
        )
        expected = source["score"]
        self.assertTrue(score["experimental_result"])
        self.assertEqual(score["post_entry_elapsed_s"], expected["post_entry_elapsed_s"])
        self.assertEqual(score["termination_reason"], "post_entry_wall_cap")
        self.assertEqual(score["cap_conformance"], expected["cap_conformance"])
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / run_id
            shutil.copytree(folder, archive)
            (archive / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            (archive / "result.json").write_text(json.dumps({
                "manifest": manifest,
                "run_dir": str(archive),
                "score": score,
            }, indent=2, sort_keys=True) + "\n")
            self.assertTrue(verify_run(archive)["score_reproduced"])

    def test_schedule_freeze_and_initial_funding_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(study, "STUDIES", Path(tmp)), patch.object(study, "fingerprint", return_value={"test": True}):
            schedule = study.prepare(randomization_seed="test-seed")
            study_id = schedule["study_id"]
            loaded = study.load_schedule(study_id)
            self.assertEqual(len(loaded["assignments"]), 40)
            self.assertEqual({row["arm"] for row in loaded["assignments"][:4]}, set(study.ARMS))
            before = study.sha256(study.study_dir(study_id) / "schedule.json")
            funding = study.funding_snapshot(study_id, {})
            self.assertEqual(funding["authorized_usd"], "600.000000000")
            self.assertEqual(funding["required_reserve_usd"], "15.000000000")
            study.add_tranche(study_id, "20.000000000")
            self.assertEqual(study.sha256(study.study_dir(study_id) / "schedule.json"), before)
            self.assertEqual(study.funding_snapshot(study_id, {})["authorized_usd"], "620.000000000")


if __name__ == "__main__":
    unittest.main()
