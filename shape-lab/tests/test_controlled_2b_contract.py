"""Model-free checks for the frozen controlled 2B contract."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import controlled_2b_contract


class Controlled2BContractTests(unittest.TestCase):
    def test_contract_pins_factorial_design_task_and_estimands(self) -> None:
        task_before = controlled_2b_contract.TASK.read_bytes()
        contract = controlled_2b_contract.load_contract()

        self.assertEqual(contract["study_protocol"], "2b-controlled-v2")
        self.assertEqual(contract["design"]["balanced_blocks"], 10)
        self.assertEqual(contract["design"]["required_valid_runs"], 40)
        self.assertEqual(
            contract["design"]["arms"],
            {
                "B0": {"structure": False, "reinforcement": False},
                "B1": {"structure": True, "reinforcement": False},
                "B2": {"structure": False, "reinforcement": True},
                "B3": {"structure": True, "reinforcement": True},
            },
        )
        self.assertEqual(
            contract["analysis"]["factorial_contrasts"]["structure_main_effect"],
            "0.5*((B1-B0)+(B3-B2))",
        )
        self.assertEqual(
            contract["analysis"]["primary_endpoint"]["tau_seconds"], 600
        )
        self.assertEqual(
            contract["trial_caps"],
            {
                "pre_entry_wall_seconds": 180,
                "post_entry_wall_seconds": 600,
                "maximum_total_wall_seconds": 780,
                "max_filesystem_actions": 50,
                "retention_horizons_seconds": [60, 180, 300, 600],
            },
        )
        self.assertEqual(
            contract["pre_entry_bound_basis"],
            {
                "pilot_id": "2b-pilot-v3-20261105140418-e6ae3e",
                "population": "eight_valid_v3_runs",
                "time_origin": "manifest_started_utc",
                "event": "first_successful_filesystem_interaction",
                "observed_entered_runs": 8,
                "observed_max_seconds": 65.828288,
                "rule": "ceil_to_next_60_seconds(2 * observed_max_seconds)",
                "pre_entry_wall_seconds": 180,
            },
        )
        self.assertEqual(
            contract["frozen_input_sha256"]["agent_task"],
            controlled_2b_contract.sha256(controlled_2b_contract.TASK),
        )
        self.assertEqual(controlled_2b_contract.TASK.read_bytes(), task_before)

    def test_contract_commitment_rejects_a_byte_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "contract.json"
            commitment = root / "contract.sha256"
            config.write_bytes(controlled_2b_contract.CONFIG.read_bytes() + b"\n")
            commitment.write_text(
                controlled_2b_contract.COMMITMENT.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            with (
                patch.object(controlled_2b_contract, "CONFIG", config),
                patch.object(controlled_2b_contract, "COMMITMENT", commitment),
                self.assertRaisesRegex(ValueError, "frozen commitment"),
            ):
                controlled_2b_contract.load_contract()

    def test_readiness_dependency_requires_every_check_to_pass(self) -> None:
        contract = controlled_2b_contract.load_contract()
        dependency = contract["readiness_dependency"]
        pilot_id = dependency["pilot_id"]
        source = controlled_2b_contract.STUDIES / pilot_id

        with tempfile.TemporaryDirectory() as temporary:
            studies = Path(temporary)
            destination = studies / pilot_id
            destination.mkdir()
            schedule = source / "schedule.json"
            (destination / "schedule.json").write_bytes(schedule.read_bytes())
            (destination / "schedule.sha256").write_text(
                dependency["schedule_sha256"] + "\n", encoding="utf-8"
            )
            readiness = json.loads(
                (source / "readiness.json").read_text(encoding="utf-8")
            )
            readiness["passed"] = False
            readiness["checks"]["annotation_complete"] = False
            readiness_path = destination / "readiness.json"
            readiness_path.write_text(
                json.dumps(readiness, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            modified = copy.deepcopy(contract)
            modified["readiness_dependency"]["readiness_sha256"] = (
                controlled_2b_contract.sha256(readiness_path)
            )
            with (
                patch.object(controlled_2b_contract, "STUDIES", studies),
                self.assertRaisesRegex(ValueError, "did not pass every"),
            ):
                controlled_2b_contract.validate_readiness_dependency(modified)

    def test_status_reports_exact_readiness_and_contract_commitments(self) -> None:
        status = controlled_2b_contract.contract_status()
        self.assertEqual(status["required_valid_runs"], 40)
        self.assertEqual(status["study_protocol"], "2b-controlled-v2")
        self.assertEqual(status["trial_caps"]["pre_entry_wall_seconds"], 180)
        self.assertEqual(
            status["contract_sha256"],
            controlled_2b_contract.COMMITMENT.read_text(encoding="utf-8").strip(),
        )
        self.assertEqual(
            status["readiness_dependency"]["readiness_sha256"],
            "5072aca396888f623e2a098cd8fe92f60cf6c636650ceb7e1fef74e959de4417",
        )


if __name__ == "__main__":
    unittest.main()
