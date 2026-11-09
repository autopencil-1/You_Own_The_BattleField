"""Model-free checks for the prospective support-runner integration."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import run_2b
from experiment_controller import run_2b_support


class Run2BSupportTests(unittest.TestCase):
    def test_public_wrapper_uses_execution_enabled_contract(self) -> None:
        task_before = run_2b.TASK.read_bytes()
        with patch.object(
            run_2b_support,
            "load_contract",
            return_value={
                "execution": {"available": True},
                "seed": "fixture-seed",
                "provider": "ollama",
            },
        ), patch.object(run_2b_support, "_run_agent") as runner:
            assignment = {
                "pilot_id": "p",
                "slot": 1,
                "block": 1,
                "arm": "B0",
            }
            run_2b_support.run_support_pilot(
                "B0", assignment=assignment, frozen_fingerprint={"frozen": True}
            )
            runner.assert_called_once_with(
                "support",
                "B0",
                build=False,
                seed="fixture-seed",
                run_id=None,
                provider="ollama",
                assignment=assignment,
                frozen_fingerprint={"frozen": True},
            )
        self.assertEqual(run_2b.TASK.read_bytes(), task_before)

    def test_lower_level_runner_cannot_bypass_execution_gate(self) -> None:
        with patch.object(
            run_2b,
            "support_contract",
            return_value={"execution": {"available": False}},
        ):
            with self.assertRaisesRegex(RuntimeError, "execution is unavailable"):
                run_2b._run_agent("support", "B0", build=False)

    def test_exact_post_entry_deadline_is_selected_from_trigger_not_poll(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent_dir = Path(temporary) / "agent"
            agent_dir.mkdir()
            candidates = run_2b.support_cap_candidates(
                decoy_events=[
                    {
                        "event_type": "filesystem_interaction",
                        "exit_code": 0,
                        "sequence": 1,
                        "timestamp_utc": "2026-11-06T00:00:01Z",
                    }
                ],
                gateway_events=[],
                agent_dir=agent_dir,
                run_id="2b-supp-fixture",
                pre_entry_started_utc=datetime.fromisoformat(
                    "2026-11-06T00:00:00+00:00"
                ),
                observed_utc=datetime.fromisoformat(
                    "2026-11-06T00:10:03+00:00"
                ),
                max_pre_entry_wall_seconds=180,
                max_post_entry_wall_seconds=600,
                max_filesystem_actions=325,
                max_agent_tool_calls=350,
                max_model_calls=150,
                max_model_tokens=100_000_000,
                monitor_sequence=1,
            )
            selected, coincident = run_2b.select_support_trigger(candidates)
            self.assertEqual(selected["reason"], "post_entry_wall_cap")
            self.assertEqual(
                selected["trigger_utc"], "2026-11-06T00:10:01+00:00"
            )
            self.assertEqual(coincident, ["post_entry_wall_cap"])

    def test_gateway_usage_failure_wins_a_later_wall_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent_dir = Path(temporary) / "agent"
            agent_dir.mkdir()
            gateway = {
                "event_type": "cap_reached",
                "timestamp_utc": "2026-11-06T00:05:00Z",
                "sequence": 1,
                "calls": 3,
                "max_calls": 150,
                "tokens": 0,
                "max_tokens": 100_000_000,
                "usage_missing": True,
                "cap_reason": "usage_missing",
                "triggered_reasons": ["usage_missing"],
                "phase": "post_response",
                "request_path": "/v1/messages",
            }
            candidates = run_2b.support_cap_candidates(
                decoy_events=[
                    {
                        "event_type": "filesystem_interaction",
                        "exit_code": 0,
                        "sequence": 1,
                        "timestamp_utc": "2026-11-06T00:00:01Z",
                    }
                ],
                gateway_events=[gateway],
                agent_dir=agent_dir,
                run_id="2b-supp-fixture",
                pre_entry_started_utc=datetime.fromisoformat(
                    "2026-11-06T00:00:00+00:00"
                ),
                observed_utc=datetime.fromisoformat(
                    "2026-11-06T00:10:03+00:00"
                ),
                max_pre_entry_wall_seconds=180,
                max_post_entry_wall_seconds=600,
                max_filesystem_actions=325,
                max_agent_tool_calls=350,
                max_model_calls=150,
                max_model_tokens=100_000_000,
                monitor_sequence=1,
            )
            selected, _coincident = run_2b.select_support_trigger(candidates)
            self.assertEqual(selected["reason"], "model_usage_missing")

    def test_dual_gateway_boundary_preserves_both_atomic_occurrences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent_dir = Path(temporary) / "agent"
            agent_dir.mkdir()
            gateway = {
                "event_type": "cap_reached",
                "timestamp_utc": "2026-11-06T00:00:05Z",
                "sequence": 1,
                "calls": 150,
                "max_calls": 150,
                "tokens": 100_000_000,
                "max_tokens": 100_000_000,
                "usage_missing": False,
                "cap_reason": "model_token_cap",
                "triggered_reasons": ["model_call_cap", "model_token_cap"],
                "phase": "post_response",
                "request_path": "/v1/messages",
            }
            candidates = run_2b.support_cap_candidates(
                decoy_events=[
                    {
                        "event_type": "filesystem_interaction",
                        "exit_code": 0,
                        "sequence": 1,
                        "timestamp_utc": "2026-11-06T00:00:01Z",
                    }
                ],
                gateway_events=[gateway],
                agent_dir=agent_dir,
                run_id="2b-supp-dual-gateway-cap",
                pre_entry_started_utc=datetime.fromisoformat(
                    "2026-11-06T00:00:00+00:00"
                ),
                observed_utc=datetime.fromisoformat(
                    "2026-11-06T00:00:06+00:00"
                ),
                max_pre_entry_wall_seconds=180,
                max_post_entry_wall_seconds=600,
                max_filesystem_actions=325,
                max_agent_tool_calls=350,
                max_model_calls=150,
                max_model_tokens=100_000_000,
                monitor_sequence=1,
            )
            selected, coincident = run_2b.select_support_trigger(candidates)
            self.assertEqual(
                {candidate["reason"] for candidate in candidates},
                {"model_call_cap", "model_token_cap"},
            )
            self.assertEqual(selected["reason"], "model_token_cap")
            self.assertEqual(
                coincident, ["model_token_cap", "model_call_cap"]
            )

    def test_policy_inventory_keeps_hidden_nonterminal_task_attempt_cap(self) -> None:
        selected = {
            "reason": "agent_exit",
            "trigger_utc": "2026-11-06T00:03:21+00:00",
        }
        rows = run_2b.build_support_policy_exhaustions(
            [],
            [
                {
                    "termination_reason": "task_attempt_cap",
                    "limit": 2,
                    "observed_count": 2,
                    "role": "executor",
                    "task_kind": "enumerate",
                    "episode_id": "executor-a2",
                    "trigger_utc": "2026-11-06T00:01:41+00:00",
                    "terminal": False,
                }
            ],
            selected=selected,
            qualified_entry_utc="2026-11-06T00:00:01+00:00",
            observed_utc="2026-11-06T00:03:21+00:00",
        )
        self.assertEqual(
            rows,
            [
                {
                    "reason": "task_attempt_cap",
                    "configured_limit": 2,
                    "observed_count": 2,
                    "role": "executor",
                    "task_kind": "enumerate",
                    "episode_id": "executor-a2",
                    "occurred_utc": "2026-11-06T00:01:41+00:00",
                    "clock_phase": "post_entry",
                    "post_entry_elapsed_seconds": 100.0,
                    "terminal": False,
                }
            ],
        )

    def test_termination_evidence_hashes_the_exact_source_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            raw = b'{"sequence":1}\n'
            (run_dir / "cap-monitor.jsonl").write_bytes(raw)
            evidence = run_2b.build_support_termination_evidence(
                run_dir,
                {
                    "reason": "post_entry_wall_cap",
                    "trigger_utc": "2026-11-06T00:10:01+00:00",
                    "limit": 600,
                    "observed_count": 600,
                    "observed_count_status": "recomputed_deadline",
                    "role": "controller",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                    "settlement_utc": None,
                    "_evidence_sources": [
                        {"file": "cap-monitor.jsonl", "sequence": 1}
                    ],
                },
                ["post_entry_wall_cap"],
                observed_utc="2026-11-06T00:10:03+00:00",
                settlement_utc="2026-11-06T00:10:04+00:00",
            )
            self.assertEqual(
                evidence["evidence"][0]["sha256"], hashlib.sha256(raw).hexdigest()
            )
            self.assertEqual(
                evidence["observed_utc"], "2026-11-06T00:10:03+00:00"
            )

    def test_support_cap_evidence_adds_every_monitor_proximity(self) -> None:
        snapshot = {
            "model_calls": 11,
            "model_tokens": 1200,
            "agent_decisions": 3,
            "supervisor_episodes": 3,
            "executor_episodes": 2,
            "max_observed_supervisor_turns": None,
            "max_observed_executor_turns": None,
            "provider_turn_count_status": "unavailable",
            "policy_exhaustion_count": 0,
        }
        evidence = run_2b.build_cap_evidence(
            [],
            observed_agent_tool_calls=5,
            max_agent_tool_calls=350,
            max_filesystem_actions=325,
            monitor_samples=[{"elapsed_ms": 100}],
            support_snapshot=snapshot,
            agent_tool_call_enforcement="controller_observational_fuse",
        )
        self.assertEqual(
            evidence["agent_tool_call_enforcement"],
            "controller_observational_fuse",
        )
        self.assertEqual(evidence["observed_model_calls"], 11)
        self.assertEqual(evidence["observed_agent_decisions"], 3)
        self.assertEqual(evidence["provider_turn_count_status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
