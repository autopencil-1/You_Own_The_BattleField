"""Integrity checks for the execution-enabled support-pilot freeze."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import support_pilot_2b_candidate_contract as candidate
from experiment_controller import support_pilot_2b_contract as execution


class SupportPilot2BExecutionContractTests(unittest.TestCase):
    def test_v3_execution_freeze_layers_over_immutable_reviewed_candidate(self) -> None:
        reviewed = candidate.load_contract()
        contract = execution.load_contract()
        self.assertFalse(reviewed["execution"]["available"])
        self.assertTrue(contract["execution"]["available"])
        self.assertTrue(contract["execution"]["schedule_freeze_available"])
        self.assertEqual(contract["pilot_protocol"], "2b-support-pilot-v3")
        self.assertEqual(contract["runtime_policy"]["max_decisions"], 500)
        self.assertEqual(contract["runtime_policy"]["max_supervisor_attempts"], 500)
        self.assertEqual(contract["runtime_policy"]["max_attempts_per_task"], 500)
        self.assertEqual(contract["runtime_policy"]["supervisor_max_turns"], 500)
        self.assertEqual(contract["runtime_policy"]["executor_max_turns"], 500)
        self.assertEqual(contract["attempt_bounds"]["max_supervisor_attempts"], 500)
        self.assertEqual(contract["attempt_bounds"]["max_attempts_per_task"], 500)
        self.assertEqual(contract["trial_caps"]["max_filesystem_actions"], 500)
        self.assertEqual(contract["trial_caps"]["max_agent_tool_calls"], 500)
        self.assertEqual(contract["trial_caps"]["max_model_calls"], 500)
        self.assertTrue(
            contract["execution"][
                "provider_cost_admission_required_before_every_attempt"
            ]
        )
        self.assertFalse(contract["execution"]["active_run_cost_termination"])
        self.assertEqual(
            contract["provider_cost_carry_forward"]["accrued_cost_usd"],
            "10.684347160",
        )
        self.assertEqual(
            contract["provider_cost_carry_forward"]["completed_attempts_priced"],
            2,
        )
        self.assertIn(
            "cap_taxonomy",
            contract["execution_freeze"]["frozen_source_sha256"],
        )
        self.assertEqual(
            contract["execution_freeze"]["base_candidate_sha256"],
            execution.sha256(candidate.CONFIG),
        )
        self.assertEqual(
            contract["execution_freeze"]["supersedes_execution_contract_sha256"],
            execution.sha256(execution.PREVIOUS_EXECUTION_CONFIG),
        )
        self.assertEqual(
            execution.sha256(execution.TASK),
            "72f1d9978b51e3508905100653ecab5e44d6db5d4f3adbea30dbfe7ab1052689",
        )

    def test_execution_contract_rejects_byte_mutation(self) -> None:
        source = execution.CONFIG.read_text(encoding="utf-8")
        commitment = execution.COMMITMENT.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "execution.json"
            digest = root / "execution.sha256"
            config.write_text(source + " ", encoding="utf-8")
            digest.write_text(commitment, encoding="utf-8")
            with (
                patch.object(execution, "CONFIG", config),
                patch.object(execution, "COMMITMENT", digest),
                self.assertRaisesRegex(ValueError, "frozen commitment"),
            ):
                execution.load_freeze()


if __name__ == "__main__":
    unittest.main()
