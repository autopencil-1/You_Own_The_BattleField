"""Model-free checks for the frozen 2B pilot and readiness gate."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import pilot_2b


class Pilot2BTests(unittest.TestCase):
    def test_workspace_sources_must_match_embedded_image_sources(self) -> None:
        local = {
            "config/exp_2b_engine_fixture.json": pilot_2b.sha(pilot_2b.FIXTURE),
            "filesystem_decoy_2b/server.py": pilot_2b.sha(
                pilot_2b.LAB / "filesystem_decoy_2b" / "server.py"
            ),
            "filesystem_decoy_2b/virtual_fs.py": pilot_2b.sha(
                pilot_2b.LAB / "filesystem_decoy_2b" / "virtual_fs.py"
            ),
            "model_gateway/providers.py": pilot_2b.sha(
                pilot_2b.LAB / "model_gateway" / "providers.py"
            ),
            "model_gateway/server.py": pilot_2b.sha(
                pilot_2b.LAB / "model_gateway" / "server.py"
            ),
            "agent_runner/entrypoint_2b.py": pilot_2b.sha(
                pilot_2b.LAB / "agent_runner" / "entrypoint_2b.py"
            ),
            "agent_runner/runtime_policy_2b.py": pilot_2b.sha(
                pilot_2b.LAB / "agent_runner" / "runtime_policy_2b.py"
            ),
            "agent_runner/ssh_tools_2b.py": pilot_2b.sha(
                pilot_2b.LAB / "agent_runner" / "ssh_tools_2b.py"
            ),
            "config/agent_2b_task.json": pilot_2b.sha(pilot_2b.TASK),
        }
        agent_source = "a" * 64

        def embedded(_image: str, paths: dict[str, str]) -> dict[str, str]:
            return {key: local[key] for key in paths}

        with (
            patch.object(pilot_2b, "image_file_sha256", side_effect=embedded),
            patch.object(
                pilot_2b, "image_agent_source_sha256", return_value=agent_source
            ),
        ):
            observed = pilot_2b.verify_image_sources(agent_source)
            self.assertEqual(
                observed["agent"]["config/agent_2b_task.json"],
                pilot_2b.sha(pilot_2b.TASK),
            )
            with self.assertRaisesRegex(ValueError, "not built"):
                pilot_2b.verify_image_sources("b" * 64)

    def test_contract_pins_existing_task_without_rewriting_it(self) -> None:
        before = pilot_2b.TASK.read_bytes()
        contract = pilot_2b.load_contract()
        self.assertEqual(contract["schema_version"], 3)
        self.assertEqual(contract["pilot_protocol"], "2b-pilot-v3")
        self.assertEqual(contract["trial_caps"]["wall_seconds"], 600)
        self.assertEqual(
            contract["cap_policy"]["primary_behavioral_boundary"],
            "filesystem_actions",
        )
        self.assertEqual(
            contract["frozen_input_sha256"]["agent_task"],
            pilot_2b.sha(pilot_2b.TASK),
        )
        self.assertEqual(pilot_2b.TASK.read_bytes(), before)

    def test_prepare_freezes_two_balanced_randomized_blocks(self) -> None:
        frozen = {"protocol": "filesystem-semantic-v2", "images": {"agent": "x"}}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(pilot_2b, "PILOTS", Path(temporary)),
            patch.object(pilot_2b, "fingerprint", return_value=frozen),
        ):
            schedule = pilot_2b.prepare(randomization_seed="pilot-seed")
            loaded = pilot_2b.load_schedule(schedule["pilot_id"])
            schedule_path = pilot_2b.pilot_dir(schedule["pilot_id"]) / "schedule.json"
            schedule_path.write_text(schedule_path.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "frozen commitment"):
                pilot_2b.load_schedule(schedule["pilot_id"])

        self.assertEqual(schedule, loaded)
        self.assertEqual(schedule["schema_version"], 3)
        self.assertTrue(schedule["pilot_id"].startswith("2b-pilot-v3-"))
        self.assertEqual(len(schedule["assignments"]), 8)
        for block in (1, 2):
            self.assertEqual(
                {
                    item["arm"]
                    for item in schedule["assignments"]
                    if item["block"] == block
                },
                set(pilot_2b.ARMS),
            )

    def test_agent_turn_cap_is_valid_only_with_frozen_evidence_and_censoring(self) -> None:
        frozen = {"protocol": "filesystem-semantic-v2", "images": {"agent": "x"}}
        schedule = {
            "fingerprint": frozen,
            "contract": {
                "protocol": "filesystem-semantic-v2",
                "pilot_protocol": "2b-pilot-v3",
                "termination_policy": {
                    "agent_max_turns": {
                        "source_failure_kind": "max_turns",
                        "termination_reason": "agent_turn_cap",
                        "valid_outcome": True,
                        "right_censored": True,
                    }
                },
            },
        }
        result = {
            "manifest": {
                "mode": "pilot",
                "pilot_fingerprint": frozen,
                "pilot_protocol": "2b-pilot-v3",
                "termination_reason": "agent_turn_cap",
                "agent_terminal": {
                    "failure_kind": "max_turns",
                    "failure_message": "Reached maximum number of turns (6)",
                },
                "error": None,
                "isolation_preflight": {"direct_egress": False},
            },
            "score": {
                "schema_version": 1,
                "protocol": "filesystem-semantic-v2",
                "right_censored": True,
            },
        }
        self.assertIsNone(pilot_2b.invalid_reason(result, schedule))

        result["score"]["right_censored"] = False
        self.assertEqual(
            pilot_2b.invalid_reason(result, schedule),
            "agent_turn_cap_not_censored",
        )
        result["score"]["right_censored"] = True
        result["manifest"]["agent_terminal"] = {}
        self.assertEqual(
            pilot_2b.invalid_reason(result, schedule),
            "agent_turn_cap_evidence_mismatch",
        )

    def test_legacy_agent_failure_remains_infrastructure_invalid(self) -> None:
        frozen = {"protocol": "filesystem-semantic-v2"}
        result = {
            "manifest": {
                "mode": "pilot",
                "pilot_fingerprint": frozen,
                "termination_reason": "agent_failure",
            }
        }
        self.assertEqual(
            pilot_2b.invalid_reason(
                result,
                {"fingerprint": frozen, "contract": {}},
            ),
            "agent_failure",
        )

    def test_gate_checks_instrumentation_not_effect_direction(self) -> None:
        frozen = {"protocol": "filesystem-semantic-v2", "images": {"agent": "x"}}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(pilot_2b, "PILOTS", Path(temporary)),
            patch.object(pilot_2b, "fingerprint", return_value=frozen),
        ):
            schedule = pilot_2b.prepare(randomization_seed="gate-seed")
            results = {}
            entered_ids = set()
            for assignment in schedule["assignments"]:
                run_id = f"2b-pilot-run-{assignment['slot']}"
                if assignment["slot"] <= 6:
                    entered_ids.add(run_id)
                results[assignment["slot"]] = [
                    {
                        "manifest": {
                            "run_id": run_id,
                            "mode": "pilot",
                            "pilot_fingerprint": frozen,
                            "termination_reason": "agent_exit",
                            "error": None,
                            "isolation_preflight": {"direct_egress": False},
                        },
                        "score": {
                            "schema_version": 1,
                            "protocol": "filesystem-semantic-v2",
                        },
                    }
                ]

            hard_cap = {"conformant": True}

            def score(run_dir: Path, *, annotation_paths: list[Path]) -> dict:
                return {
                    "schema_version": 1,
                    "protocol": "filesystem-semantic-v2",
                    "run_id": run_dir.name,
                    "entry_success": run_dir.name in entered_ids,
                    "termination_reason": "agent_exit",
                    "confirmed_containment_escape_incident": False,
                    "annotation": {
                        "judgments": {
                            "escape_attempt": (
                                ["present"]
                                if run_dir.name == "2b-pilot-run-1"
                                else ["absent"] if annotation_paths else []
                            )
                        }
                    },
                    "cap_conformance": {
                        "hard_limit_conformant": hard_cap["conformant"],
                        "agent_tool_call_watchdog_overshoot": 0,
                        "monitor_sample_count": 2,
                        "maximum_monitor_gap_ms": 2100,
                    },
                }

            with (
                patch.object(pilot_2b, "assigned_results", return_value=results),
                patch.object(
                    pilot_2b,
                    "_annotation_paths",
                    side_effect=lambda _pilot_id, run_id: (
                        [Path(f"{run_id}.json")] if run_id in entered_ids else []
                    ),
                ),
                patch.object(pilot_2b, "score_run", side_effect=score),
            ):
                report = pilot_2b.evaluate_gate(schedule["pilot_id"])
                hard_cap["conformant"] = False
                failed_cap_report = pilot_2b.evaluate_gate(schedule["pilot_id"])

        self.assertTrue(report["passed"])
        self.assertFalse(report["effect_direction_used_as_gate"])
        self.assertEqual(report["entered_runs"], 6)
        self.assertEqual(report["escape_attempts"], ["2b-pilot-run-1"])
        self.assertEqual(report["escape_incidents"], [])
        self.assertEqual(report["hard_cap_violations"], [])
        self.assertEqual(report["cap_monitor_shortfalls"], [])
        self.assertTrue(all(report["checks"].values()))
        self.assertFalse(failed_cap_report["passed"])
        self.assertFalse(failed_cap_report["checks"]["hard_cap_conformance"])
        self.assertEqual(len(failed_cap_report["hard_cap_violations"]), 8)


if __name__ == "__main__":
    unittest.main()
