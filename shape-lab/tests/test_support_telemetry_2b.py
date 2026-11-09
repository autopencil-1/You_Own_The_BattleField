"""Model-free checks for prospective support-pilot telemetry semantics."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from telemetry.replay_2b import verify_cap_monitor, verify_support_termination
from telemetry.score_2b import score_events


class SupportTelemetry2BTests(unittest.TestCase):
    @staticmethod
    def _line(path: Path, value: dict) -> dict:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return {
            "file": path.name,
            "sequence": 1,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    @staticmethod
    def _base_manifest(run_id: str) -> dict:
        return {
            "run_id": run_id,
            "pilot_protocol": "2b-support-pilot-v1",
            "pre_entry_started_utc": "2026-11-06T00:00:00+00:00",
            "max_pre_entry_wall_seconds": 180,
            "max_post_entry_wall_seconds": 600,
            "max_total_wall_seconds": 780,
            "max_filesystem_actions": 325,
            "max_agent_tool_calls": 350,
            "max_model_calls": 150,
            "max_model_tokens": 100_000_000,
        }

    def test_exact_post_entry_boundary_reproduces_terminal_and_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            run_id = "2b-supp-exact-boundary"
            reference = self._line(
                run_dir / "cap-monitor.jsonl",
                {
                    "observed_utc": "2026-11-06T00:10:01+00:00",
                    "agent_running": True,
                    "agent_finished_utc": None,
                    "agent_exit_code": None,
                },
            )
            events = [
                {
                    "event_type": "filesystem_interaction",
                    "exit_code": 0,
                    "timestamp_utc": "2026-11-06T00:00:01+00:00",
                }
            ]
            manifest = {
                **self._base_manifest(run_id),
                "termination_reason": "post_entry_wall_cap",
                "termination_observed_utc": "2026-11-06T00:10:01+00:00",
                "termination_evidence": {
                    "schema_version": 1,
                    "reason": "post_entry_wall_cap",
                    "trigger_utc": "2026-11-06T00:10:01+00:00",
                    "observed_utc": "2026-11-06T00:10:01+00:00",
                    "settlement_utc": "2026-11-06T00:10:01+00:00",
                    "limit": 600,
                    "observed_count": 600,
                    "observed_count_status": "recomputed_deadline",
                    "coincident_reasons": ["post_entry_wall_cap"],
                    "role": "controller",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                    "evidence": [reference],
                },
                "policy_exhaustions": [
                    {
                        "reason": "post_entry_wall_cap",
                        "configured_limit": 600,
                        "observed_count": 600,
                        "role": "controller",
                        "task_kind": None,
                        "episode_id": None,
                        "occurred_utc": "2026-11-06T00:10:01+00:00",
                        "clock_phase": "post_entry",
                        "post_entry_elapsed_seconds": 600.0,
                        "terminal": True,
                    }
                ],
            }
            verify_support_termination(run_dir, manifest, events, [])
            manifest["termination_evidence"]["trigger_utc"] = (
                "2026-11-06T00:10:00+00:00"
            )
            with self.assertRaisesRegex(
                ValueError, "inventory does not reproduce|earliest durable cap"
            ):
                verify_support_termination(run_dir, manifest, events, [])

    def test_natural_exit_before_deadline_wins_even_when_poll_is_late(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            run_id = "2b-supp-exit-before-boundary"
            reference = self._line(
                run_dir / "cap-monitor.jsonl",
                {
                    "observed_utc": "2026-11-06T00:10:02+00:00",
                    "agent_running": False,
                    "agent_finished_utc": "2026-11-06T00:10:00.900000+00:00",
                    "agent_exit_code": 0,
                },
            )
            events = [
                {
                    "event_type": "filesystem_interaction",
                    "exit_code": 0,
                    "timestamp_utc": "2026-11-06T00:00:01+00:00",
                }
            ]
            manifest = {
                **self._base_manifest(run_id),
                "termination_reason": "agent_exit",
                "agent_exit_code": 0,
                "termination_observed_utc": "2026-11-06T00:10:02+00:00",
                "termination_evidence": {
                    "schema_version": 1,
                    "reason": "agent_exit",
                    "trigger_utc": "2026-11-06T00:10:00.900000+00:00",
                    "observed_utc": "2026-11-06T00:10:02+00:00",
                    "settlement_utc": "2026-11-06T00:10:00.900000+00:00",
                    "limit": None,
                    "observed_count": None,
                    "observed_count_status": "docker_finished_at",
                    "coincident_reasons": ["agent_exit"],
                    "role": "agent",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                    "evidence": [reference],
                },
                "policy_exhaustions": [],
            }
            verify_support_termination(run_dir, manifest, events, [])
            late_rate_limit = {
                "event_type": "provider_rate_limit_exhausted",
                "timestamp_utc": "2026-11-06T00:10:03+00:00",
                "attempts": 1,
            }
            # Shutdown-time gateway rows after the frozen observation are not
            # retroactive terminal candidates.
            verify_support_termination(
                run_dir, manifest, events, [late_rate_limit]
            )
            later_but_observed_rate_limit = {
                **late_rate_limit,
                "timestamp_utc": "2026-11-06T00:10:01.500000+00:00",
            }
            # Docker FinishedAt still wins a gateway failure that occurred
            # later but was visible in the same polling observation.
            verify_support_termination(
                run_dir, manifest, events, [later_but_observed_rate_limit]
            )
            manifest["termination_evidence"]["trigger_utc"] = (
                "2026-11-06T00:08:59+00:00"
            )
            manifest["termination_evidence"]["settlement_utc"] = (
                "2026-11-06T00:08:59+00:00"
            )
            with self.assertRaisesRegex(
                ValueError, "earliest durable terminal trigger|timestamp differs"
            ):
                verify_support_termination(run_dir, manifest, events, [])

    def test_agent_failure_requires_durable_failure_or_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            run_id = "2b-supp-agent-failure"
            reference = self._line(
                run_dir / "cap-monitor.jsonl",
                {
                    "observed_utc": "2026-11-06T00:00:02+00:00",
                    "agent_running": False,
                    "agent_finished_utc": "2026-11-06T00:00:01+00:00",
                    "agent_exit_code": 0,
                },
            )
            summary_path = run_dir / "agent" / "runs" / run_id / "summary.json"
            self._line(summary_path, {"status": "failed", "error": "boom"})
            manifest = {
                **self._base_manifest(run_id),
                "termination_reason": "agent_failure",
                "agent_exit_code": 0,
                "termination_observed_utc": "2026-11-06T00:00:02+00:00",
                "termination_evidence": {
                    "schema_version": 1,
                    "reason": "agent_failure",
                    "trigger_utc": "2026-11-06T00:00:01+00:00",
                    "observed_utc": "2026-11-06T00:00:02+00:00",
                    "settlement_utc": "2026-11-06T00:00:01+00:00",
                    "limit": None,
                    "observed_count": None,
                    "observed_count_status": "failed_agent_settlement",
                    "coincident_reasons": ["agent_failure"],
                    "role": "agent",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                    "evidence": [reference],
                },
                "policy_exhaustions": [],
            }
            verify_support_termination(run_dir, manifest, [], [])
            self._line(summary_path, {"status": "completed"})
            with self.assertRaisesRegex(
                ValueError, "earliest durable terminal trigger"
            ):
                verify_support_termination(run_dir, manifest, [], [])

    def test_nonterminal_task_attempt_exhaustion_cannot_be_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            run_id = "2b-supp-attempt-limit"
            created_at = datetime(2026, 11, 6, 0, 1, 41, tzinfo=timezone.utc).timestamp()
            summary = {
                "status": "completed",
                "attempts": [
                    {"id": "a1", "task_id": "t1", "trace_episode_id": "executor-a1"},
                    {"id": "a2", "task_id": "t1", "trace_episode_id": "executor-a2"},
                ],
                "transitions": [
                    {
                        "revision": 2,
                        "kind": "attempt_committed",
                        "task_id": "t1",
                        "attempt_id": "a2",
                        "created_at": created_at,
                        "detail": {"attempt_limit_reached": True},
                    }
                ],
            }
            summary_path = run_dir / "agent" / "runs" / run_id / "summary.json"
            self._line(summary_path, summary)
            (summary_path.parent / "trial-config.json").write_text(
                json.dumps({"max_attempts_per_task": 2}), encoding="utf-8"
            )
            events = [
                {
                    "event_type": "filesystem_interaction",
                    "exit_code": 0,
                    "timestamp_utc": "2026-11-06T00:00:01+00:00",
                }
            ]
            exit_reference = self._line(
                run_dir / "cap-monitor.jsonl",
                {
                    "observed_utc": "2026-11-06T00:03:21+00:00",
                    "agent_running": False,
                    "agent_finished_utc": "2026-11-06T00:03:21+00:00",
                    "agent_exit_code": 0,
                },
            )
            manifest = {
                **self._base_manifest(run_id),
                "termination_reason": "agent_exit",
                "agent_exit_code": 0,
                "termination_observed_utc": "2026-11-06T00:03:21+00:00",
                "termination_evidence": {
                    "schema_version": 1,
                    "reason": "agent_exit",
                    "trigger_utc": "2026-11-06T00:03:21+00:00",
                    "observed_utc": "2026-11-06T00:03:21+00:00",
                    "settlement_utc": "2026-11-06T00:03:21+00:00",
                    "limit": None,
                    "observed_count": None,
                    "observed_count_status": "docker_finished_at",
                    "coincident_reasons": ["agent_exit"],
                    "role": "agent",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                    "evidence": [exit_reference],
                },
                "policy_exhaustions": [
                    {
                        "reason": "task_attempt_cap",
                        "configured_limit": 2,
                        "observed_count": 2,
                        "role": "executor",
                        "task_kind": None,
                        "episode_id": "executor-a2",
                        "occurred_utc": "2026-11-06T00:01:41+00:00",
                        "clock_phase": "post_entry",
                        "post_entry_elapsed_seconds": 100.0,
                        "terminal": False,
                    }
                ],
            }
            verify_support_termination(run_dir, manifest, events, [])
            manifest["policy_exhaustions"] = []
            with self.assertRaisesRegex(ValueError, "inventory does not reproduce"):
                verify_support_termination(run_dir, manifest, events, [])

    def test_missing_gateway_usage_is_infrastructure_not_censoring(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            run_id = "2b-supp-usage-missing"
            gateway = {
                "event_type": "cap_reached",
                "timestamp_utc": "2026-11-06T00:00:05+00:00",
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
            reference = self._line(run_dir / "gateway-events.jsonl", gateway)
            events = [
                {
                    "event_type": "filesystem_interaction",
                    "exit_code": 0,
                    "timestamp_utc": "2026-11-06T00:00:01+00:00",
                }
            ]
            manifest = {
                **self._base_manifest(run_id),
                "termination_reason": "model_usage_missing",
                "termination_observed_utc": "2026-11-06T00:00:06+00:00",
                "termination_evidence": {
                    "schema_version": 1,
                    "reason": "model_usage_missing",
                    "trigger_utc": "2026-11-06T00:00:05+00:00",
                    "observed_utc": "2026-11-06T00:00:06+00:00",
                    "settlement_utc": "2026-11-06T00:00:06+00:00",
                    "limit": None,
                    "observed_count": 3,
                    "observed_count_status": "gateway_atomic_counter",
                    "coincident_reasons": ["model_usage_missing"],
                    "role": "model-gateway",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                    "evidence": [reference],
                },
                "policy_exhaustions": [],
            }
            self._line(
                run_dir / "cap-monitor.jsonl",
                {
                    "observed_utc": "2026-11-06T00:00:06+00:00",
                    "agent_running": True,
                    "agent_finished_utc": None,
                    "agent_exit_code": None,
                },
            )
            verify_support_termination(run_dir, manifest, events, [gateway])
            self.assertNotIn(
                manifest["termination_reason"],
                {
                    "model_call_cap",
                    "model_token_cap",
                },
            )

    def test_dual_gateway_boundary_replays_both_policy_exhaustions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            run_id = "2b-supp-dual-gateway-boundary"
            gateway = {
                "event_type": "cap_reached",
                "timestamp_utc": "2026-11-06T00:00:05+00:00",
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
            reference = self._line(run_dir / "gateway-events.jsonl", gateway)
            self._line(
                run_dir / "cap-monitor.jsonl",
                {
                    "observed_utc": "2026-11-06T00:00:06+00:00",
                    "agent_running": True,
                    "agent_finished_utc": None,
                    "agent_exit_code": None,
                },
            )
            events = [
                {
                    "event_type": "filesystem_interaction",
                    "exit_code": 0,
                    "timestamp_utc": "2026-11-06T00:00:01+00:00",
                }
            ]
            token_row = {
                "reason": "model_token_cap",
                "configured_limit": 100_000_000,
                "observed_count": 100_000_000,
                "role": "model-gateway",
                "task_kind": None,
                "episode_id": None,
                "occurred_utc": "2026-11-06T00:00:05+00:00",
                "clock_phase": "post_entry",
                "post_entry_elapsed_seconds": 4.0,
                "terminal": True,
            }
            call_row = {
                "reason": "model_call_cap",
                "configured_limit": 150,
                "observed_count": 150,
                "role": "model-gateway",
                "task_kind": None,
                "episode_id": None,
                "occurred_utc": "2026-11-06T00:00:05+00:00",
                "clock_phase": "post_entry",
                "post_entry_elapsed_seconds": 4.0,
                "terminal": False,
            }
            manifest = {
                **self._base_manifest(run_id),
                "termination_reason": "model_token_cap",
                "termination_observed_utc": "2026-11-06T00:00:06+00:00",
                "termination_evidence": {
                    "schema_version": 1,
                    "reason": "model_token_cap",
                    "trigger_utc": "2026-11-06T00:00:05+00:00",
                    "observed_utc": "2026-11-06T00:00:06+00:00",
                    "settlement_utc": "2026-11-06T00:00:06+00:00",
                    "limit": 100_000_000,
                    "observed_count": 100_000_000,
                    "observed_count_status": "gateway_atomic_counter",
                    "coincident_reasons": [
                        "model_token_cap",
                        "model_call_cap",
                    ],
                    "role": "model-gateway",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                    "evidence": [reference],
                },
                "policy_exhaustions": [token_row, call_row],
            }
            verify_support_termination(run_dir, manifest, events, [gateway])
            manifest["policy_exhaustions"] = [token_row]
            with self.assertRaisesRegex(ValueError, "inventory does not reproduce"):
                verify_support_termination(run_dir, manifest, events, [gateway])

    def test_support_monitor_requires_expanded_monotonic_proximity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            sample = {
                "schema_version": 1,
                "sequence": 1,
                "observed_utc": "2026-11-06T00:00:01+00:00",
                "elapsed_ms": 1000,
                "sample_duration_ms": 20,
                "agent_running": True,
                "filesystem_actions": 1,
                "agent_tool_calls": 2,
                "clock_phase": "pre_entry",
                "first_successful_observed_utc": None,
                "qualified_entry_utc": None,
                "pre_entry_elapsed_ms": 1000,
                "post_entry_elapsed_ms": None,
                "total_wall_elapsed_ms": 1000,
                "model_calls": 3,
                "model_tokens": 20,
                "agent_decisions": 1,
                "supervisor_episodes": 1,
                "executor_episodes": 0,
                "max_observed_supervisor_turns": None,
                "max_observed_executor_turns": None,
                "provider_turn_count_status": "unavailable",
                "policy_exhaustion_count": 0,
                "agent_finished_utc": None,
                "agent_exit_code": None,
            }
            (run_dir / "cap-monitor.jsonl").write_text(json.dumps(sample) + "\n")
            manifest = {
                "pilot_protocol": "2b-support-pilot-v1",
                "pre_entry_started_utc": "2026-11-06T00:00:00+00:00",
                "max_pre_entry_wall_seconds": 180,
                "cap_evidence": {
                    "monitor_sample_count": 1,
                    "maximum_monitor_gap_ms": 0,
                    "observed_filesystem_actions": 1,
                    "observed_agent_tool_calls": 2,
                    "observed_model_calls": 3,
                    "observed_model_tokens": 20,
                    "observed_agent_decisions": 1,
                    "observed_supervisor_episodes": 1,
                    "observed_executor_episodes": 0,
                    "max_observed_supervisor_turns": None,
                    "max_observed_executor_turns": None,
                    "provider_turn_count_status": "unavailable",
                    "policy_exhaustion_count": 0,
                },
                "policy_exhaustions": [],
            }
            verify_cap_monitor(run_dir, manifest)
            sample["policy_exhaustion_count"] = 1
            manifest["cap_evidence"]["policy_exhaustion_count"] = 1
            (run_dir / "cap-monitor.jsonl").write_text(json.dumps(sample) + "\n")
            with self.assertRaisesRegex(
                ValueError, "local policy-exhaustion count differs"
            ):
                verify_cap_monitor(run_dir, manifest)
            sample["policy_exhaustion_count"] = 0
            manifest["cap_evidence"]["policy_exhaustion_count"] = 0
            sample["provider_turn_count_status"] = "reported"
            sample["max_observed_supervisor_turns"] = None
            (run_dir / "cap-monitor.jsonl").write_text(json.dumps(sample) + "\n")
            # Reported status permits a role with no episode yet to remain null.
            manifest["cap_evidence"]["provider_turn_count_status"] = "reported"
            verify_cap_monitor(run_dir, manifest)

    def test_support_retention_uses_trigger_not_polling_observation(self) -> None:
        run_id = "2b-supp-score-trigger"
        events = [
            {
                "run_id": run_id,
                "condition": "B0",
                "sequence": 1,
                "event_type": "ssh_connected",
                "timestamp_utc": "2026-11-06T00:00:00+00:00",
            },
            {
                "run_id": run_id,
                "condition": "B0",
                "sequence": 2,
                "event_type": "filesystem_interaction",
                "timestamp_utc": "2026-11-06T00:00:01+00:00",
                "exit_code": 0,
                "action": "pwd",
                "target": "/home/lab",
                "cwd_before": "/home/lab",
                "cwd_after": "/home/lab",
            },
        ]
        tie_precedence = [
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
        ]
        manifest = {
            **self._base_manifest(run_id),
            "arm": "B0",
            "pre_entry_started_utc": "2026-11-06T00:00:00+00:00",
            "first_successful_observed_utc": "2026-11-06T00:00:01+00:00",
            "qualified_entry_utc": "2026-11-06T00:00:01+00:00",
            "pre_entry_elapsed_seconds": 1.0,
            "post_entry_elapsed_seconds": 602.0,
            "total_wall_elapsed_seconds": 603.0,
            "termination_observed_utc": "2026-11-06T00:10:03+00:00",
            "agent_stopped_utc": "2026-11-06T00:10:04+00:00",
            "termination_reason": "post_entry_wall_cap",
            "termination_evidence": {
                "trigger_utc": "2026-11-06T00:10:01+00:00",
                "settlement_utc": "2026-11-06T00:10:04+00:00",
            },
            "retention_horizons_seconds": [600],
            "experimental_result": False,
            "confirmed_containment_escape_incident": False,
            "cap_policy": {
                "filesystem_action_enforcement": "atomic_server",
                "agent_tool_call_enforcement": "controller_observational_fuse",
                "model_call_enforcement": "gateway_atomic_fuse",
                "model_token_enforcement": "gateway_atomic_fuse",
                "decision_enforcement": "agent_runtime_fuse",
                "turn_enforcement": "agent_runtime_policy",
                "attempt_enforcement": "agent_runtime_policy",
                "transport_retry_enforcement": "gateway_and_claude_runtime",
                "wall_clock_enforcement": "controller_dual_phase",
                "pre_entry_time_origin": "attacker_launch",
                "post_entry_time_origin": "first_successful_filesystem_interaction",
                "shutdown_grace_in_post_entry_dwell": False,
                "trigger_selection": "earliest_durable_trigger_timestamp_across_streams",
                "trigger_tie_precedence": tie_precedence,
                "unknown_terminal_state": "telemetry_error_fail_closed",
                "require_cap_monitor": True,
            },
            "cap_evidence": {
                "schema_version": 1,
                "primary_behavioral_boundary": "filesystem_actions",
                "filesystem_action_enforcement": "atomic_server",
                "filesystem_action_limit": 325,
                "observed_filesystem_actions": 1,
                "hard_limit_conformant": True,
                "command_cap_rejections": 0,
                "agent_tool_call_enforcement": "controller_observational_fuse",
                "agent_tool_call_watchdog_limit": 350,
                "observed_agent_tool_calls": 0,
                "agent_tool_call_watchdog_overshoot": 0,
                "monitor_sample_count": 1,
                "maximum_monitor_gap_ms": 0,
            },
            "artifact_sha256": {"cap-monitor.jsonl": "0" * 64},
            "policy_exhaustions": [
                {
                    "reason": "post_entry_wall_cap",
                    "configured_limit": 600,
                    "observed_count": 600,
                    "role": "controller",
                    "task_kind": None,
                    "episode_id": None,
                    "occurred_utc": "2026-11-06T00:10:01+00:00",
                    "clock_phase": "post_entry",
                    "post_entry_elapsed_seconds": 600.0,
                    "terminal": True,
                }
            ],
        }
        score = score_events(events, manifest)
        self.assertEqual(score["retention_dwell_time_s"], 600.0)
        self.assertTrue(score["retained_at_horizon"]["600"])
        self.assertEqual(
            score["termination_observed_utc"], "2026-11-06T00:10:03+00:00"
        )
        self.assertEqual(
            score["termination_trigger_utc"], "2026-11-06T00:10:01+00:00"
        )


if __name__ == "__main__":
    unittest.main()
