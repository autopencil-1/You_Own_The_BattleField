"""Checks for the controlled-v3 non-executable scientific freeze."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import controlled_2b_v3_contract as contract_v3


class Controlled2BV3ContractTests(unittest.TestCase):
    def test_freeze_binds_support_gate_and_preserves_scientific_design(self) -> None:
        contract = contract_v3.load_contract()
        self.assertEqual(contract["study_protocol"], "2b-controlled-v3")
        self.assertEqual(contract["design"]["required_valid_runs"], 40)
        self.assertEqual(contract["design"]["balanced_blocks"], 10)
        self.assertEqual(contract["analysis"]["primary_endpoint"]["tau_seconds"], 600)
        self.assertEqual(contract["trial_caps"]["post_entry_wall_seconds"], 600)
        self.assertEqual(contract["trial_caps"]["max_filesystem_actions"], 500)
        self.assertEqual(contract["runtime_policy"]["executor_max_turns"], 500)
        self.assertEqual(
            contract["readiness_dependency"]["readiness_sha256"],
            "9da0aa07061fbfcba584c7c509b478df976be2cde77a7b8c4375ef03488522cc",
        )
        self.assertEqual(
            contract["closeout_dependency"]["bundle_manifest_sha256"],
            "cff71bbd1e0df6561c4d80d4c1fbfd0307d9e6907f11b155962640cb8c03b600",
        )
        self.assertFalse(contract["execution"]["available"])
        self.assertFalse(contract["execution"]["schedule_freeze_available"])
        self.assertTrue(contract["execution"]["task_unchanged"])

    def test_resource_boundary_is_explicit_and_not_an_in_run_censor(self) -> None:
        review = contract_v3.load_contract()["provider_cost_review"]
        self.assertEqual(
            review["status"], "authorization_required_before_execution_overlay"
        )
        self.assertEqual(review["observed_valid_cost_usd"], "74.685878880")
        self.assertEqual(
            review["projected_40_valid_at_observed_mean_usd"], "373.429394400"
        )
        self.assertIsNone(review["main_study_authorization_usd"])
        self.assertIsNone(review["minimum_uncommitted_reserve_per_new_run_usd"])
        self.assertFalse(review["active_run_cost_termination"])
        self.assertTrue(review["admission_must_be_effect_blind"])

    def test_semantic_mutation_is_rejected_even_if_recommitted(self) -> None:
        contract = json.loads(contract_v3.CONFIG.read_text(encoding="utf-8"))
        contract["trial_caps"]["max_filesystem_actions"] = 499
        rendered = json.dumps(contract, indent=2, sort_keys=True) + "\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "contract.json"
            commitment = root / "contract.sha256"
            config.write_text(rendered, encoding="utf-8")
            commitment.write_text(
                hashlib.sha256(rendered.encode("utf-8")).hexdigest() + "\n",
                encoding="utf-8",
            )
            with (
                patch.object(contract_v3, "CONFIG", config),
                patch.object(contract_v3, "COMMITMENT", commitment),
                self.assertRaisesRegex(ValueError, "committed evidence"),
            ):
                contract_v3.load_contract()

    def test_byte_mutation_is_rejected_by_commitment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "contract.json"
            commitment = root / "contract.sha256"
            original = contract_v3.CONFIG.read_bytes()
            config.write_bytes(original + b" ")
            commitment.write_text(
                hashlib.sha256(original).hexdigest() + "\n", encoding="utf-8"
            )
            with (
                patch.object(contract_v3, "CONFIG", config),
                patch.object(contract_v3, "COMMITMENT", commitment),
                self.assertRaisesRegex(ValueError, "commitment"),
            ):
                contract_v3.load_contract()


if __name__ == "__main__":
    unittest.main()
