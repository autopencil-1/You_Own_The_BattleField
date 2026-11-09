"""Model-free tests for the prospective 2B horizon-support pilot."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import support_pilot_2b
from experiment_controller import (
    support_pilot_2b_candidate_contract as support_pilot_2b_contract,
)


class SupportPilot2BTests(unittest.TestCase):
    def test_contract_freezes_candidate_envelope_and_unchanged_task(self) -> None:
        before = support_pilot_2b_contract.sha256(support_pilot_2b_contract.TASK)
        contract = support_pilot_2b_contract.load_contract()
        self.assertEqual(contract["pilot_protocol"], "2b-support-pilot-v1")
        self.assertEqual(
            contract["candidate_status"],
            "resource_reviewed_candidate_not_execution_frozen",
        )
        self.assertEqual(contract["design"]["balanced_blocks"], 2)
        self.assertEqual(contract["design"]["required_valid_runs"], 8)
        self.assertTrue(contract["design"]["excluded_from_effect_estimate"])
        self.assertFalse(contract["execution"]["schedule_freeze_available"])
        self.assertFalse(contract["execution"]["available"])
        self.assertTrue(contract["execution"]["resource_review_complete"])
        self.assertEqual(
            contract["runtime_policy"],
            {
                "schema_version": 1,
                "name": "horizon-support-v1",
                "max_decisions": 25,
                "supervisor_max_turns": 4,
                "executor_max_turns": 12,
                "executor_turn_policy": "full_declared_ceiling",
            },
        )
        self.assertEqual(
            contract["trial_caps"],
            {
                "max_filesystem_actions": 325,
                "max_agent_tool_calls": 350,
                "max_model_calls": 150,
                "max_model_tokens_input_plus_output": 100000000,
                "pre_entry_wall_seconds": 180,
                "post_entry_wall_seconds": 600,
                "maximum_total_wall_seconds": 780,
                "retention_horizons_seconds": [60, 180, 300, 600],
            },
        )
        self.assertEqual(
            contract["attempt_bounds"],
            {
                "max_supervisor_attempts": 2,
                "max_attempts_per_task": 2,
                "gateway_429_retry_count": 0,
                "claude_retry_count": 0,
                "structured_output_retry_count": None,
                "structured_output_retry_count_status": (
                    "provider_managed_not_exposed"
                ),
            },
        )
        self.assertEqual(
            contract["transport_bounds"],
            {
                "gateway_upstream_timeout_seconds": 180,
                "agent_api_timeout_milliseconds": 180000,
                "gateway_max_request_bytes": 4 * 1024 * 1024,
                "gateway_max_response_bytes": 16 * 1024 * 1024,
            },
        )
        self.assertEqual(
            contract["container_bounds"],
            {
                "filesystem-decoy-2b": {
                    "pids_limit": 64,
                    "memory_limit_bytes": 256 * 1024 * 1024,
                },
                "model-gateway": {
                    "pids_limit": 64,
                    "memory_limit_bytes": 256 * 1024 * 1024,
                },
                "attacker-agent": {
                    "pids_limit": 128,
                    "memory_limit_bytes": 2 * 1024 * 1024 * 1024,
                },
            },
        )
        self.assertEqual(contract["frozen_input_sha256"]["agent_task"], before)
        self.assertEqual(
            support_pilot_2b_contract.sha256(support_pilot_2b_contract.TASK),
            before,
        )

    def test_contract_keeps_provider_cost_outside_active_runs_and_gate(self) -> None:
        contract = support_pilot_2b_contract.load_contract()
        governance = contract["provider_cost_governance"]
        self.assertEqual(governance["pilot_authorization_usd"], "100.00")
        self.assertEqual(
            governance["minimum_uncommitted_reserve_per_new_run_usd"], "15.00"
        )
        self.assertFalse(governance["active_run_cost_termination"])
        self.assertFalse(governance["budget_pause_creates_trial_attempt"])
        self.assertFalse(governance["budget_pause_creates_censored_outcome"])
        self.assertFalse(governance["arm_specific_cost_used_for_admission"])
        self.assertFalse(governance["cost_used_in_support_gate"])
        self.assertNotIn(
            "provider_cost_cap",
            contract["termination_policy"]["right_censored_reasons"],
        )
        self.assertEqual(
            contract["trial_caps"]["max_model_tokens_input_plus_output"],
            100_000_000,
        )

    def test_contract_freezes_terminal_and_policy_exhaustion_taxonomy(self) -> None:
        contract = support_pilot_2b_contract.load_contract()
        self.assertEqual(
            contract["termination_policy"]["right_censored_reasons"],
            [
                "pre_entry_wall_cap",
                "post_entry_wall_cap",
                "filesystem_action_cap",
                "agent_tool_call_cap",
                "model_call_cap",
                "model_token_cap",
                "agent_decision_cap",
                "supervisor_turn_cap",
                "executor_turn_cap",
                "task_attempt_cap",
                "supervisor_attempt_cap",
                "structured_output_retry_cap",
            ],
        )
        exhaustion = contract["termination_policy"]["policy_exhaustion_inventory"]
        self.assertEqual(
            exhaustion["reasons"][-3:],
            [
                "task_attempt_cap",
                "supervisor_attempt_cap",
                "structured_output_retry_cap",
            ],
        )
        self.assertTrue(exhaustion["requires_structured_terminal_evidence"])
        self.assertTrue(exhaustion["record_nonterminal_occurrences"])
        self.assertIn(
            "post_entry_elapsed_seconds", exhaustion["required_evidence_fields"]
        )
        self.assertEqual(
            exhaustion["terminal_with_structured_evidence"],
            {"valid_outcome": True, "right_censored": True, "replaceable": False},
        )
        self.assertEqual(
            exhaustion["terminal_without_structured_evidence"],
            {
                "valid_outcome": False,
                "infrastructure_invalid_reason": "missing_required_telemetry",
                "replaceable": True,
            },
        )
        self.assertFalse(
            contract["replacement_policy"][
                "replace_structured_terminal_policy_exhaustion"
            ]
        )
        self.assertIn(
            "model_usage_missing",
            contract["replacement_policy"]["infrastructure_invalid_reasons"],
        )
        self.assertEqual(
            contract["support_gate"]["forbidden_early_censor_reasons"],
            exhaustion["reasons"],
        )

    def test_contract_freezes_earliest_trigger_tie_precedence(self) -> None:
        policy = support_pilot_2b_contract.load_contract()["cap_policy"]
        self.assertEqual(
            policy["trigger_selection"],
            "earliest_durable_trigger_timestamp_across_streams",
        )
        self.assertEqual(
            policy["trigger_tie_precedence"],
            [
                "model_usage_missing",
                "provider_rate_limit",
                "pre_entry_wall_cap",
                "post_entry_wall_cap",
                "filesystem_action_cap",
                "agent_tool_call_cap",
                "model_token_cap",
                "model_call_cap",
                "agent_decision_cap",
                "supervisor_turn_cap",
                "executor_turn_cap",
                "structured_output_retry_cap",
                "supervisor_attempt_cap",
                "task_attempt_cap",
                "agent_exit",
            ],
        )

    def test_support_gate_is_per_run_effect_blind_and_scans_exhaustion_history(
        self,
    ) -> None:
        gate = support_pilot_2b_contract.load_contract()["support_gate"]
        self.assertTrue(gate["reject_any_pre_600_policy_exhaustion"])
        self.assertTrue(gate["reject_any_structured_output_retry_cap_occurrence"])
        self.assertEqual(gate["policy_exhaustion_manifest_field"], "policy_exhaustions")
        self.assertTrue(
            gate["final_termination_reason_does_not_override_policy_exhaustions"]
        )
        scan = gate["policy_exhaustion_scan"]
        self.assertEqual(scan["source"], "manifest.policy_exhaustions")
        self.assertEqual(
            scan["reject_comparison"],
            "pre_entry_phase_or_post_entry_elapsed_seconds_strictly_less_than_600",
        )
        self.assertTrue(scan["scan_all_occurrences"])
        procedure = gate["effect_blind_estimability_procedure"]
        self.assertEqual(
            procedure["aggregate_pass_rule"],
            "every_entered_analyzable_run_passes",
        )
        self.assertEqual(
            procedure["event_comparison"],
            "event_disposition_and_duration_strictly_less_than_tau",
        )
        self.assertEqual(procedure["followup_comparison"], "duration_at_least_tau")
        self.assertEqual(procedure["arm_label_use"], "coverage_only")
        self.assertEqual(
            procedure["arm_coverage_rule"],
            "at_least_one_entered_analyzable_run_in_every_arm",
        )
        self.assertFalse(procedure["computes_arm_outcome_summaries"])
        self.assertFalse(procedure["computes_effect_estimates"])

    def test_contract_rejects_byte_and_semantic_mutation(self) -> None:
        source = support_pilot_2b_contract.CONFIG.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "contract.json"
            commitment = root / "contract.sha256"
            config.write_text(source + " ", encoding="utf-8")
            commitment.write_text(
                support_pilot_2b_contract.COMMITMENT.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            with (
                patch.object(support_pilot_2b_contract, "CONFIG", config),
                patch.object(support_pilot_2b_contract, "COMMITMENT", commitment),
                self.assertRaisesRegex(ValueError, "frozen commitment"),
            ):
                support_pilot_2b_contract.load_contract()

            value = json.loads(source)
            value["unexpected"] = True
            rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
            config.write_text(rendered, encoding="utf-8")
            commitment.write_text(
                hashlib.sha256(rendered.encode("utf-8")).hexdigest() + "\n",
                encoding="utf-8",
            )
            with (
                patch.object(support_pilot_2b_contract, "CONFIG", config),
                patch.object(support_pilot_2b_contract, "COMMITMENT", commitment),
                self.assertRaisesRegex(ValueError, "unexpected shape"),
            ):
                support_pilot_2b_contract.load_contract()

            value = json.loads(source)
            value["attempt_bounds"]["claude_retry_count"] = 1
            rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
            config.write_text(rendered, encoding="utf-8")
            commitment.write_text(
                hashlib.sha256(rendered.encode("utf-8")).hexdigest() + "\n",
                encoding="utf-8",
            )
            with (
                patch.object(support_pilot_2b_contract, "CONFIG", config),
                patch.object(support_pilot_2b_contract, "COMMITMENT", commitment),
                self.assertRaisesRegex(ValueError, "attempt bounds differ"),
            ):
                support_pilot_2b_contract.load_contract()

    def test_pure_schedule_is_deterministic_and_balanced(self) -> None:
        kwargs = {
            "pilot_id": "2b-support-pilot-v3-20261106010101-abcdef",
            "created_utc": "2026-11-06T01:01:01+00:00",
            "randomization_seed": "support-fixture-seed",
            "frozen_fingerprint": {"fixture": "fingerprint"},
        }
        first = support_pilot_2b.build_schedule(**kwargs)
        second = support_pilot_2b.build_schedule(**kwargs)
        self.assertEqual(first, second)
        self.assertEqual(len(first["assignments"]), 8)
        for block in (1, 2):
            rows = [row for row in first["assignments"] if row["block"] == block]
            self.assertEqual({row["arm"] for row in rows}, set(support_pilot_2b.ARMS))

    def test_public_prepare_freezes_schedule_without_executing(self) -> None:
        task_before = support_pilot_2b_contract.sha256(support_pilot_2b_contract.TASK)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(support_pilot_2b, "PILOTS", Path(temporary)),
            patch.object(
                support_pilot_2b,
                "fingerprint",
                return_value={"fixture": "fingerprint"},
            ),
            patch.object(
                support_pilot_2b,
                "execute",
                side_effect=AssertionError("must not execute"),
            ) as execute,
        ):
            schedule = support_pilot_2b.prepare(
                randomization_seed="support-fixture-seed"
            )
            execute.assert_not_called()
            loaded = support_pilot_2b.load_schedule(schedule["pilot_id"])
            self.assertEqual(loaded, schedule)
            folder = Path(temporary) / schedule["pilot_id"]
            self.assertTrue((folder / "schedule.json").is_file())
            self.assertTrue((folder / "schedule.sha256").is_file())
        self.assertEqual(
            support_pilot_2b_contract.sha256(support_pilot_2b_contract.TASK),
            task_before,
        )

    def test_loader_rejects_semantic_schedule_mutation_even_if_recommitted(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(support_pilot_2b, "PILOTS", Path(temporary)),
            patch.object(
                support_pilot_2b,
                "fingerprint",
                return_value={"fixture": "fingerprint"},
            ),
        ):
            schedule = support_pilot_2b._write_schedule(
                randomization_seed="support-fixture-seed"
            )
            folder = Path(temporary) / schedule["pilot_id"]
            path = folder / "schedule.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["assignments"][0]["arm"] = value["assignments"][1]["arm"]
            rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
            path.write_text(rendered, encoding="utf-8")
            (folder / "schedule.sha256").write_text(
                hashlib.sha256(rendered.encode("utf-8")).hexdigest() + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "not balanced"):
                support_pilot_2b.load_schedule(schedule["pilot_id"])

    def test_status_and_readiness_are_pending_and_effect_blind(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(support_pilot_2b, "PILOTS", Path(temporary)),
            patch.object(
                support_pilot_2b,
                "fingerprint",
                return_value={"fixture": "fingerprint"},
            ),
            patch.object(support_pilot_2b, "assigned_results", return_value={}),
        ):
            schedule = support_pilot_2b._write_schedule(
                randomization_seed="support-fixture-seed"
            )
            observed = support_pilot_2b.status(schedule["pilot_id"])
            self.assertEqual(observed["phase"], "execution_enabled")
            self.assertEqual(observed["valid_runs"], 0)
            self.assertTrue(observed["execution_available"])
            self.assertTrue(observed["provider_cost"]["admission"]["may_start_new_run"])
            self.assertEqual(
                observed["provider_cost"]["carried_forward_cost_usd"],
                "10.684347160",
            )
            self.assertEqual(
                observed["provider_cost"]["current_pilot_cost_usd"],
                "0.000000000",
            )
            self.assertEqual(
                observed["provider_cost"]["accrued_cost_usd"],
                "10.684347160",
            )
            self.assertEqual(
                observed["provider_cost"]["admission"]["remaining_authorization_usd"],
                "89.315652840",
            )
            self.assertFalse(
                observed["provider_cost"]["admission"]["active_run_termination_allowed"]
            )
            readiness = support_pilot_2b.readiness(schedule["pilot_id"])
            self.assertIsNone(readiness["passed"])
            self.assertTrue(readiness["effect_blind"])
            self.assertFalse(readiness["provider_cost_used_in_gate"])
            self.assertEqual(
                set(readiness["checks"]),
                set(support_pilot_2b_contract.READINESS_CHECKS),
            )
            self.assertEqual(
                readiness["forbidden_effect_inputs"],
                ["arm_contrasts", "factorial_effect_estimates", "arm_rankings"],
            )
            self.assertEqual(
                readiness["policy_exhaustion_scan"]["source"],
                "manifest.policy_exhaustions",
            )
            self.assertEqual(
                readiness["estimability_procedure"]["aggregate_pass_rule"],
                "every_entered_analyzable_run_passes",
            )

    def test_execute_checks_admission_then_uses_frozen_wrapper(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(support_pilot_2b, "PILOTS", Path(temporary)),
            patch.object(
                support_pilot_2b,
                "fingerprint",
                return_value={"fixture": "fingerprint"},
            ),
        ):
            schedule = support_pilot_2b._write_schedule(
                randomization_seed="support-fixture-seed"
            )
            expected_status = {"pilot_id": schedule["pilot_id"], "valid_runs": 0}
            with (
                patch.object(support_pilot_2b, "assigned_results", return_value={}),
                patch.object(
                    support_pilot_2b,
                    "provider_cost_snapshot",
                    return_value={"admission": {"may_start_new_run": True}},
                ),
                patch.object(support_pilot_2b, "invalid_reason", return_value=None),
                patch.object(
                    support_pilot_2b, "run_support_pilot", return_value={}
                ) as runner,
                patch.object(support_pilot_2b, "status", return_value=expected_status),
            ):
                observed = support_pilot_2b.execute(
                    schedule["pilot_id"], max_new_runs=1
                )
            self.assertEqual(observed, expected_status)
            runner.assert_called_once()

    def test_cost_snapshot_rejects_cross_pilot_rows(self) -> None:
        pilot_id = "2b-support-pilot-v3-20261106010101-abcdef"
        result = {
            "manifest": {
                "run_id": "2b-supp-cross-pilot",
                "assignment": {"pilot_id": "2b-support-pilot-v2-other"},
            }
        }
        with self.assertRaisesRegex(
            support_pilot_2b.SupportPilotIntegrityError,
            "cross-pilot",
        ):
            support_pilot_2b.provider_cost_snapshot(pilot_id, {1: [result]})


if __name__ == "__main__":
    unittest.main()
