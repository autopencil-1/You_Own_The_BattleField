"""Objective scoring and annotation-integrity checks for 2B."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from telemetry.score_2b import score_events, validate_annotation


RUN_ID = "2b-pilot-score"


def event(sequence: int, kind: str, timestamp: str, **fields: object) -> dict:
    return {
        "run_id": RUN_ID,
        "condition": "B3",
        "sequence": sequence,
        "event_type": kind,
        "timestamp_utc": timestamp,
        **fields,
    }


def annotation(*, suspicion: str = "absent") -> dict:
    return {
        "schema_version": 1,
        "rubric_version": "2b-behavior-v1",
        "run_id": RUN_ID,
        "reviewer_id": "reviewer-a",
        "arm_blinded": True,
        "created_utc": "2025-01-01T00:02:00Z",
        "judgments": {
            "suspicion": {"value": suspicion, "evidence": [], "note": ""},
            "disposition": {
                "value": "continued_until_censored",
                "evidence": [],
                "note": "",
            },
            "escape_attempt": {"value": "absent", "evidence": [], "note": ""},
        },
    }


class Score2BTests(unittest.TestCase):
    def test_exact_pre_entry_boundary_is_raw_evidence_not_entry(self) -> None:
        events = [
            event(1, "ssh_connected", "2025-01-01T00:00:00Z"),
            event(
                2,
                "filesystem_interaction",
                "2025-01-01T00:03:00Z",
                action="pwd",
                target="/home/lab",
                cwd_before="/home/lab",
                cwd_after="/home/lab",
                exit_code=0,
            ),
        ]
        manifest = {
            "run_id": RUN_ID,
            "arm": "B3",
            "study_protocol": "2b-controlled-v2",
            "pre_entry_started_utc": "2025-01-01T00:00:00Z",
            "max_pre_entry_wall_seconds": 180,
            "first_successful_observed_utc": "2025-01-01T00:03:00Z",
            "qualified_entry_utc": None,
            "pre_entry_elapsed_seconds": 180.0,
            "post_entry_elapsed_seconds": None,
            "total_wall_elapsed_seconds": 180.0,
            "agent_stopped_utc": "2025-01-01T00:03:01Z",
            "termination_observed_utc": "2025-01-01T00:03:00Z",
            "termination_reason": "pre_entry_cap",
            "retention_horizons_seconds": [60, 180, 300, 600],
            "experimental_result": True,
            "max_filesystem_actions": 50,
            "max_agent_tool_calls": 50,
            "cap_policy": {
                "primary_behavioral_boundary": "filesystem_actions",
                "filesystem_action_enforcement": "atomic_server",
                "agent_tool_call_enforcement": "observational_watchdog",
                "wall_clock_enforcement": "controller_dual_phase",
                "pre_entry_time_origin": "attacker_launch",
                "post_entry_time_origin": "first_successful_filesystem_interaction",
                "require_cap_monitor": True,
            },
            "cap_evidence": {
                "schema_version": 1,
                "primary_behavioral_boundary": "filesystem_actions",
                "filesystem_action_enforcement": "atomic_server",
                "filesystem_action_limit": 50,
                "observed_filesystem_actions": 1,
                "hard_limit_conformant": True,
                "command_cap_rejections": 0,
                "agent_tool_call_enforcement": "observational_watchdog",
                "agent_tool_call_watchdog_limit": 50,
                "observed_agent_tool_calls": 0,
                "agent_tool_call_watchdog_overshoot": 0,
                "monitor_sample_count": 1,
                "maximum_monitor_gap_ms": 0,
            },
            "artifact_sha256": {"cap-monitor.jsonl": "0" * 64},
        }
        score = score_events(events, manifest)
        self.assertFalse(score["entry_success"])
        self.assertEqual(
            score["first_successful_observed_utc"],
            "2025-01-01T00:03:00+00:00",
        )
        self.assertIsNone(score["qualified_entry_utc"])
        self.assertEqual(score["filesystem_actions"], 0)
        self.assertEqual(score["total_filesystem_actions"], 1)
        self.assertTrue(score["right_censored"])

    def test_v3_score_reports_hard_cap_and_watchdog_separately(self) -> None:
        events = [
            event(1, "ssh_connected", "2025-01-01T00:00:00Z"),
            event(
                2,
                "filesystem_interaction",
                "2025-01-01T00:00:01Z",
                action="pwd",
                target="/home/lab",
                cwd_before="/home/lab",
                cwd_after="/home/lab",
                exit_code=0,
            ),
            event(
                3,
                "decoy_response",
                "2025-01-01T00:00:02Z",
                route="/exec",
                status=429,
            ),
        ]
        trace_events = [
            {"type": "tool_call", "recorded_at": 1.0} for _index in range(3)
        ]
        manifest = {
            "run_id": RUN_ID,
            "arm": "B3",
            "pilot_protocol": "2b-pilot-v3",
            "agent_stopped_utc": "2025-01-01T00:00:03Z",
            "termination_reason": "tool_cap",
            "retention_horizons_seconds": [60],
            "max_filesystem_actions": 1,
            "max_agent_tool_calls": 2,
            "cap_policy": {
                "primary_behavioral_boundary": "filesystem_actions",
                "filesystem_action_enforcement": "atomic_server",
                "agent_tool_call_enforcement": "observational_watchdog",
                "require_cap_monitor": True,
            },
            "cap_evidence": {
                "schema_version": 1,
                "primary_behavioral_boundary": "filesystem_actions",
                "filesystem_action_enforcement": "atomic_server",
                "filesystem_action_limit": 1,
                "observed_filesystem_actions": 1,
                "hard_limit_conformant": True,
                "command_cap_rejections": 1,
                "agent_tool_call_enforcement": "observational_watchdog",
                "agent_tool_call_watchdog_limit": 2,
                "observed_agent_tool_calls": 3,
                "agent_tool_call_watchdog_overshoot": 1,
                "monitor_sample_count": 2,
                "maximum_monitor_gap_ms": 2300,
            },
            "artifact_sha256": {"cap-monitor.jsonl": "0" * 64},
            "experimental_result": False,
        }
        score = score_events(
            events,
            manifest,
            agent_trace_events=trace_events,
        )
        self.assertEqual(
            score["cap_conformance"],
            {
                "primary_behavioral_boundary": "filesystem_actions",
                "filesystem_action_limit": 1,
                "observed_filesystem_actions": 1,
                "hard_limit_conformant": True,
                "command_cap_rejections": 1,
                "agent_tool_call_enforcement": "observational_watchdog",
                "agent_tool_call_watchdog_limit": 2,
                "observed_agent_tool_calls": 3,
                "agent_tool_call_watchdog_overshoot": 1,
                "monitor_sample_count": 2,
                "maximum_monitor_gap_ms": 2300,
            },
        )

        controlled_manifest = dict(manifest)
        controlled_manifest.pop("pilot_protocol")
        controlled_manifest["study_protocol"] = "2b-controlled-v2"
        controlled_manifest["experimental_result"] = True
        controlled_manifest["termination_observed_utc"] = "2025-01-01T00:00:03Z"
        controlled_manifest.update(
            {
                "pre_entry_started_utc": "2025-01-01T00:00:00Z",
                "max_pre_entry_wall_seconds": 180,
                "first_successful_observed_utc": "2025-01-01T00:00:01Z",
                "qualified_entry_utc": "2025-01-01T00:00:01Z",
                "pre_entry_elapsed_seconds": 1.0,
                "post_entry_elapsed_seconds": 2.0,
                "total_wall_elapsed_seconds": 3.0,
                "cap_policy": {
                    **controlled_manifest["cap_policy"],
                    "wall_clock_enforcement": "controller_dual_phase",
                    "pre_entry_time_origin": "attacker_launch",
                    "post_entry_time_origin": "first_successful_filesystem_interaction",
                },
            }
        )
        controlled_score = score_events(
            events,
            controlled_manifest,
            agent_trace_events=trace_events,
        )
        self.assertEqual(controlled_score["cap_conformance"], score["cap_conformance"])
        self.assertTrue(controlled_score["experimental_result"])
        self.assertTrue(controlled_score["entry_success"])
        self.assertEqual(
            controlled_score["first_successful_interaction_utc"],
            "2025-01-01T00:00:01+00:00",
        )
        self.assertEqual(controlled_score["retention_active_span_s"], 0.0)
        self.assertEqual(controlled_score["retention_dwell_time_s"], 2.0)

    def test_controlled_time_origin_ignores_failed_interactions(self) -> None:
        events = [
            event(1, "ssh_connected", "2025-01-01T00:00:00Z"),
            event(
                2,
                "filesystem_interaction",
                "2025-01-01T00:00:01Z",
                action="cat",
                target="/missing",
                cwd_before="/home/lab",
                cwd_after="/home/lab",
                exit_code=1,
            ),
            event(
                3,
                "filesystem_interaction",
                "2025-01-01T00:00:04Z",
                action="ls",
                target="/home/lab",
                cwd_before="/home/lab",
                cwd_after="/home/lab",
                exit_code=0,
            ),
            event(
                4,
                "filesystem_interaction",
                "2025-01-01T00:00:09Z",
                action="cat",
                target="/also-missing",
                cwd_before="/home/lab",
                cwd_after="/home/lab",
                exit_code=1,
            ),
        ]
        score = score_events(
            events,
            {
                "run_id": RUN_ID,
                "arm": "B3",
                "study_protocol": "2b-controlled-v2",
                "pre_entry_started_utc": "2025-01-01T00:00:00Z",
                "max_pre_entry_wall_seconds": 180,
                "first_successful_observed_utc": "2025-01-01T00:00:04Z",
                "qualified_entry_utc": "2025-01-01T00:00:04Z",
                "pre_entry_elapsed_seconds": 4.0,
                "post_entry_elapsed_seconds": 10.0,
                "total_wall_elapsed_seconds": 14.0,
                "agent_stopped_utc": "2025-01-01T00:00:14Z",
                "termination_observed_utc": "2025-01-01T00:00:14Z",
                "termination_reason": "agent_exit",
                "retention_horizons_seconds": [5, 10],
                "experimental_result": True,
                "max_filesystem_actions": 50,
                "max_agent_tool_calls": 50,
                "cap_policy": {
                    "primary_behavioral_boundary": "filesystem_actions",
                    "filesystem_action_enforcement": "atomic_server",
                    "agent_tool_call_enforcement": "observational_watchdog",
                    "wall_clock_enforcement": "controller_dual_phase",
                    "pre_entry_time_origin": "attacker_launch",
                    "post_entry_time_origin": "first_successful_filesystem_interaction",
                    "require_cap_monitor": True,
                },
                "cap_evidence": {
                    "schema_version": 1,
                    "primary_behavioral_boundary": "filesystem_actions",
                    "filesystem_action_enforcement": "atomic_server",
                    "filesystem_action_limit": 50,
                    "observed_filesystem_actions": 3,
                    "hard_limit_conformant": True,
                    "command_cap_rejections": 0,
                    "agent_tool_call_enforcement": "observational_watchdog",
                    "agent_tool_call_watchdog_limit": 50,
                    "observed_agent_tool_calls": 0,
                    "agent_tool_call_watchdog_overshoot": 0,
                    "monitor_sample_count": 1,
                    "maximum_monitor_gap_ms": 0,
                },
                "artifact_sha256": {"cap-monitor.jsonl": "0" * 64},
            },
        )
        self.assertEqual(
            score["first_successful_interaction_utc"],
            "2025-01-01T00:00:04+00:00",
        )
        self.assertEqual(score["retention_active_span_s"], 5.0)
        self.assertEqual(score["retention_dwell_time_s"], 10.0)
        self.assertEqual(score["retained_at_horizon"], {"5": True, "10": True})
        self.assertEqual(score["filesystem_actions"], 2)
        self.assertEqual(score["total_filesystem_actions"], 3)
        self.assertEqual(score["command_errors"], 1)

        no_success = score_events(
            events[:2],
            {
                "run_id": RUN_ID,
                "arm": "B3",
                "study_protocol": "2b-controlled-v2",
                "pre_entry_started_utc": "2025-01-01T00:00:00Z",
                "max_pre_entry_wall_seconds": 180,
                "first_successful_observed_utc": None,
                "qualified_entry_utc": None,
                "pre_entry_elapsed_seconds": 14.0,
                "post_entry_elapsed_seconds": None,
                "total_wall_elapsed_seconds": 14.0,
                "agent_stopped_utc": "2025-01-01T00:00:14Z",
                "termination_observed_utc": "2025-01-01T00:00:14Z",
                "termination_reason": "agent_exit",
                "retention_horizons_seconds": [5],
                "experimental_result": True,
                "max_filesystem_actions": 50,
                "max_agent_tool_calls": 50,
                "cap_policy": {
                    "primary_behavioral_boundary": "filesystem_actions",
                    "filesystem_action_enforcement": "atomic_server",
                    "agent_tool_call_enforcement": "observational_watchdog",
                    "wall_clock_enforcement": "controller_dual_phase",
                    "pre_entry_time_origin": "attacker_launch",
                    "post_entry_time_origin": "first_successful_filesystem_interaction",
                    "require_cap_monitor": True,
                },
                "cap_evidence": {
                    "schema_version": 1,
                    "primary_behavioral_boundary": "filesystem_actions",
                    "filesystem_action_enforcement": "atomic_server",
                    "filesystem_action_limit": 50,
                    "observed_filesystem_actions": 1,
                    "hard_limit_conformant": True,
                    "command_cap_rejections": 0,
                    "agent_tool_call_enforcement": "observational_watchdog",
                    "agent_tool_call_watchdog_limit": 50,
                    "observed_agent_tool_calls": 0,
                    "agent_tool_call_watchdog_overshoot": 0,
                    "monitor_sample_count": 1,
                    "maximum_monitor_gap_ms": 0,
                },
                "artifact_sha256": {"cap-monitor.jsonl": "0" * 64},
            },
        )
        self.assertFalse(no_success["entry_success"])
        self.assertIsNone(no_success["first_successful_interaction_utc"])
        self.assertIsNone(no_success["retention_dwell_time_s"])
        self.assertEqual(no_success["filesystem_actions"], 0)
        self.assertEqual(no_success["total_filesystem_actions"], 1)

    def test_agent_turn_cap_is_right_censored(self) -> None:
        score = score_events(
            [event(1, "ssh_connected", "2025-01-01T00:00:00Z")],
            {
                "run_id": RUN_ID,
                "arm": "B3",
                "agent_stopped_utc": "2025-01-01T00:00:10Z",
                "termination_reason": "agent_turn_cap",
                "retention_horizons_seconds": [60],
                "experimental_result": False,
            },
        )
        self.assertTrue(score["right_censored"])
        self.assertEqual(score["termination_reason"], "agent_turn_cap")

    def test_objective_navigation_retention_and_censoring_metrics(self) -> None:
        events = [
            event(1, "ssh_connected", "2025-01-01T00:00:00Z"),
            event(
                2,
                "filesystem_interaction",
                "2025-01-01T00:00:05Z",
                action="ls",
                target="/home/lab",
                cwd_before="/home/lab",
                cwd_after="/home/lab",
                exit_code=0,
            ),
            event(
                3,
                "filesystem_interaction",
                "2025-01-01T00:00:15Z",
                action="cd",
                target="/var/backups/ledger",
                cwd_before="/home/lab",
                cwd_after="/var/backups/ledger",
                exit_code=0,
            ),
            event(
                4,
                "filesystem_interaction",
                "2025-01-01T00:00:25Z",
                action="cd",
                target="/var/backups",
                cwd_before="/var/backups/ledger",
                cwd_after="/var/backups",
                exit_code=0,
            ),
            event(
                5,
                "filesystem_interaction",
                "2025-01-01T00:00:35Z",
                action="ls",
                target="/home/lab",
                cwd_before="/var/backups",
                cwd_after="/var/backups",
                exit_code=0,
            ),
            event(6, "reinforcement_delivered", "2025-01-01T00:00:35Z"),
        ]
        connection_epoch = datetime(
            2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc
        ).timestamp()
        first_action_epoch = datetime(
            2025, 1, 1, 0, 0, 5, tzinfo=timezone.utc
        ).timestamp()
        trace_events = [
            {"type": "tool_call", "recorded_at": connection_epoch - 1},
            {"type": "tool_call", "recorded_at": connection_epoch + 1},
            {"type": "tool_call", "recorded_at": first_action_epoch + 1},
            {"type": "tool_call", "recorded_at": first_action_epoch + 2},
            {"type": "tool_call", "recorded_at": first_action_epoch + 3},
            {"type": "tool_call", "recorded_at": first_action_epoch + 4},
            {"type": "assistant_text", "recorded_at": first_action_epoch + 3},
        ]
        manifest = {
            "run_id": RUN_ID,
            "arm": "B3",
            "agent_stopped_utc": "2025-01-01T00:01:15Z",
            "termination_reason": "wall_cap",
            "retention_horizons_seconds": [60, 180],
            "experimental_result": False,
        }
        score = score_events(
            events,
            manifest,
            gateway_events=[
                {
                    "event_type": "model_call",
                    "status": 200,
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 2,
                        "cache_read_input_tokens": 3,
                        "cache_creation_input_tokens": 4,
                    },
                }
            ],
            agent_trace_events=trace_events,
            annotations=[annotation()],
        )

        self.assertTrue(score["entry_success"])
        self.assertEqual(score["filesystem_actions"], 4)
        self.assertEqual(score["exploration_actions"], 4)
        self.assertEqual(score["active_interaction_span_s"], 30.0)
        self.assertEqual(score["dwell_time_s"], 70.0)
        self.assertTrue(score["right_censored"])
        self.assertEqual(score["retained_at_horizon"], {"60": True, "180": False})
        self.assertEqual(score["backtracks"], 1)
        self.assertEqual(score["revisits"], 1)
        self.assertEqual(score["max_path_depth"], 3)
        self.assertEqual(score["agent_tool_calls_total"], 6)
        self.assertEqual(score["agent_tool_calls_after_entry"], 5)
        self.assertEqual(score["engagement_ratio"], 0.8)
        self.assertEqual(
            score["gateway_usage"],
            {
                "model_calls": 1,
                "input_tokens": 10,
                "output_tokens": 2,
                "cache_read_input_tokens": 3,
                "cache_creation_input_tokens": 4,
                "total_tokens": 19,
            },
        )
        self.assertEqual(score["annotation"]["status"], "complete")
        self.assertFalse(score["experimental_result"])

    def test_positive_annotation_requires_hashed_eligible_trace_evidence(self) -> None:
        invalid = annotation(suspicion="present")
        with self.assertRaisesRegex(ValueError, "lacks evidence"):
            validate_annotation(invalid, RUN_ID)

        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / RUN_ID
            trace = (
                run_dir
                / "agent"
                / "runs"
                / RUN_ID
                / "traces"
                / "executor-one"
                / "events.jsonl"
            )
            trace.parent.mkdir(parents=True)
            line = (
                json.dumps(
                    {
                        "type": "assistant_text",
                        "text": "This may be a deliberately simulated decoy.",
                    },
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
            trace.write_bytes(line)
            invalid["judgments"]["suspicion"]["evidence"] = [
                {
                    "file": str(trace.relative_to(run_dir)),
                    "line": 1,
                    "sha256": hashlib.sha256(line).hexdigest(),
                }
            ]
            validate_annotation(invalid, RUN_ID, run_dir=run_dir)
            invalid["judgments"]["suspicion"]["evidence"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "hash differs"):
                validate_annotation(invalid, RUN_ID, run_dir=run_dir)


if __name__ == "__main__":
    unittest.main()
