"""Check the 2B fixture evidence and image task without a model call."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from experiment_controller import run_2b
from telemetry.replay_2b import (
    verify_agent_artifacts,
    verify_cap_monitor,
    verify_controlled_timing,
    verify_run,
)
from telemetry.score_2b import score_events


class Run2BConfigTests(unittest.TestCase):
    def test_exact_pre_entry_boundary_is_observed_but_does_not_qualify(self) -> None:
        clock = run_2b.controlled_clock_evidence(
            [
                {
                    "event_type": "filesystem_interaction",
                    "exit_code": 0,
                    "timestamp_utc": "2026-11-06T00:03:00Z",
                }
            ],
            pre_entry_started_utc=run_2b.datetime.fromisoformat(
                "2026-11-06T00:00:00+00:00"
            ),
            observed_utc=run_2b.datetime.fromisoformat(
                "2026-11-06T00:03:01+00:00"
            ),
            pre_entry_limit_seconds=180,
        )
        self.assertEqual(clock["clock_phase"], "pre_entry")
        self.assertEqual(
            clock["first_successful_observed_utc"],
            "2026-11-06T00:03:00+00:00",
        )
        self.assertIsNone(clock["qualified_entry_utc"])
        self.assertEqual(clock["pre_entry_elapsed_seconds"], 181.0)
        self.assertIsNone(clock["post_entry_elapsed_seconds"])

    def test_finished_after_wall_deadline_is_bound_to_stopped_monitor_sample(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            monitor = run_dir / "cap-monitor.jsonl"
            (run_dir / "decoy-events.jsonl").write_text(
                json.dumps(
                    {
                        "event_type": "filesystem_interaction",
                        "exit_code": 0,
                        "timestamp_utc": "2026-11-06T00:00:00.500000Z",
                    }
                )
                + "\n"
            )
            monitor.write_text(
                json.dumps(
                    {
                        "observed_utc": "2026-11-06T00:10:01Z",
                        "agent_running": False,
                    }
                )
                + "\n"
            )
            manifest = {
                "study_protocol": "2b-controlled-v2",
                "wall_time_origin": "dual_phase_first_success",
                "pre_entry_started_utc": "2026-11-06T00:00:00Z",
                "termination_observed_utc": "2026-11-06T00:10:00.500000Z",
                "max_pre_entry_wall_seconds": 180,
                "max_post_entry_wall_seconds": 600,
                "max_total_wall_seconds": 780,
                "clock_phase": "post_entry",
                "first_successful_observed_utc": "2026-11-06T00:00:00.500000Z",
                "qualified_entry_utc": "2026-11-06T00:00:00.500000Z",
                "pre_entry_elapsed_seconds": 0.5,
                "post_entry_elapsed_seconds": 600.0,
                "total_wall_elapsed_seconds": 600.5,
                "termination_reason": "wall_cap",
            }
            score = {
                "termination_observed_utc": "2026-11-06T00:10:00.500000+00:00",
                "first_successful_observed_utc": "2026-11-06T00:00:00.500000Z",
                "qualified_entry_utc": "2026-11-06T00:00:00.500000Z",
                "pre_entry_elapsed_s": 0.5,
                "post_entry_elapsed_s": 600.0,
                "total_wall_elapsed_s": 600.5,
            }
            verify_controlled_timing(run_dir, manifest, score)
            row = json.loads(monitor.read_text(encoding="utf-8"))
            row["agent_running"] = True
            monitor.write_text(json.dumps(row) + "\n")
            with self.assertRaisesRegex(ValueError, "matching monitor"):
                verify_controlled_timing(run_dir, manifest, score)

    def test_cap_evidence_separates_hard_boundary_from_soft_watchdog(self) -> None:
        events = [
            {"event_type": "filesystem_interaction"}
            for _index in range(50)
        ] + [
            {
                "event_type": "decoy_response",
                "route": "/exec",
                "status": 429,
            }
        ]
        evidence = run_2b.build_cap_evidence(
            events,
            observed_agent_tool_calls=56,
            max_agent_tool_calls=50,
            max_filesystem_actions=50,
            monitor_samples=[
                {"elapsed_ms": 1000},
                {"elapsed_ms": 3300},
                {"elapsed_ms": 7100},
            ],
        )
        self.assertTrue(evidence["hard_limit_conformant"])
        self.assertEqual(evidence["observed_filesystem_actions"], 50)
        self.assertEqual(evidence["command_cap_rejections"], 1)
        self.assertEqual(evidence["agent_tool_call_watchdog_overshoot"], 6)
        self.assertEqual(evidence["maximum_monitor_gap_ms"], 3800)

    def test_cap_monitor_is_replay_verified_for_pilot_and_controlled(self) -> None:
        samples = [
            {
                "schema_version": 1,
                "sequence": 1,
                "observed_utc": "2026-11-05T00:00:01+00:00",
                "elapsed_ms": 1000,
                "sample_duration_ms": 300,
                "agent_running": True,
                "filesystem_actions": 2,
                "agent_tool_calls": 4,
            },
            {
                "schema_version": 1,
                "sequence": 2,
                "observed_utc": "2026-11-05T00:00:03+00:00",
                "elapsed_ms": 3200,
                "sample_duration_ms": 400,
                "agent_running": True,
                "filesystem_actions": 5,
                "agent_tool_calls": 8,
            },
        ]
        controlled_samples = [
            {
                **row,
                "clock_phase": "pre_entry",
                "first_successful_observed_utc": None,
                "qualified_entry_utc": None,
                "pre_entry_elapsed_ms": row["elapsed_ms"],
                "post_entry_elapsed_ms": None,
                "total_wall_elapsed_ms": row["elapsed_ms"],
            }
            for row in samples
        ]
        controlled_samples[1]["pre_entry_elapsed_ms"] = 3000
        controlled_samples[1]["total_wall_elapsed_ms"] = 3000
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            monitor = run_dir / "cap-monitor.jsonl"
            evidence = {
                "monitor_sample_count": 2,
                "maximum_monitor_gap_ms": 2200,
                "observed_filesystem_actions": 5,
                "observed_agent_tool_calls": 8,
            }
            pilot_manifest = {
                "pilot_protocol": "2b-pilot-v3",
                "cap_evidence": evidence,
            }
            controlled_manifest = {
                "study_protocol": "2b-controlled-v2",
                "pre_entry_started_utc": "2026-11-05T00:00:00+00:00",
                "max_pre_entry_wall_seconds": 180,
                "cap_evidence": evidence,
            }
            for rows, manifest in (
                (samples, pilot_manifest),
                (controlled_samples, controlled_manifest),
            ):
                monitor.write_text(
                    "".join(json.dumps(row) + "\n" for row in rows)
                )
                verify_cap_monitor(run_dir, manifest)
            controlled_samples[1]["sequence"] = 3
            monitor.write_text(
                "".join(json.dumps(row) + "\n" for row in controlled_samples)
            )
            with self.assertRaisesRegex(ValueError, "sample values"):
                verify_cap_monitor(run_dir, controlled_manifest)

    def test_agent_turn_cap_requires_durable_terminal_max_turns_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent_dir = Path(temporary) / "agent"
            summary = agent_dir / "runs" / "run-one" / "summary.json"
            summary.parent.mkdir(parents=True)
            summary.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "error": "max_turns: Reached maximum number of turns (6)",
                        "attempts": [
                            {
                                "status": "error",
                                "failure_kind": "max_turns",
                                "failure_message": "Reached maximum number of turns (6)",
                            }
                        ],
                    }
                )
            )
            self.assertEqual(
                run_2b.agent_turn_cap_evidence(agent_dir, "run-one"),
                {
                    "failure_kind": "max_turns",
                    "failure_message": "Reached maximum number of turns (6)",
                },
            )

            summary.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "error": "provider_error: unavailable",
                        "attempts": [
                            {
                                "status": "error",
                                "failure_kind": "provider_error",
                                "failure_message": "unavailable",
                            }
                        ],
                    }
                )
            )
            self.assertIsNone(
                run_2b.agent_turn_cap_evidence(agent_dir, "run-one")
            )

    def test_pilot_wrapper_uses_frozen_contract_without_changing_task(self) -> None:
        before = run_2b.TASK.read_bytes()
        contract = {
            "seed": "fixture-seed",
            "provider": "ollama",
        }
        with patch.object(run_2b, "pilot_contract", return_value=contract), patch.object(
            run_2b, "_run_agent", return_value={"manifest": {}}
        ) as mocked:
            run_2b.run_pilot(
                "B3",
                assignment={"pilot_id": "p", "slot": 1, "block": 1, "arm": "B3"},
                frozen_fingerprint={"images": {}},
            )
        mocked.assert_called_once_with(
            "pilot",
            "B3",
            build=False,
            seed="fixture-seed",
            run_id=None,
            provider="ollama",
            assignment={"pilot_id": "p", "slot": 1, "block": 1, "arm": "B3"},
            frozen_fingerprint={"images": {}},
        )
        self.assertEqual(run_2b.TASK.read_bytes(), before)

    def test_controlled_wrapper_uses_frozen_contract_without_changing_task(self) -> None:
        before = run_2b.TASK.read_bytes()
        contract = {
            "seed": "fixture-seed",
            "provider": "ollama",
        }
        assignment = {
            "study_id": "2b-study-example",
            "slot": 1,
            "block": 1,
            "arm": "B1",
        }
        with patch.object(
            run_2b, "controlled_contract", return_value=contract
        ), patch.object(
            run_2b, "_run_agent", return_value={"manifest": {}}
        ) as mocked:
            run_2b.run_controlled(
                "B1",
                assignment=assignment,
                frozen_fingerprint={"images": {}},
            )
        mocked.assert_called_once_with(
            "controlled",
            "B1",
            build=False,
            seed="fixture-seed",
            run_id=None,
            provider="ollama",
            assignment=assignment,
            frozen_fingerprint={"images": {}},
        )
        self.assertEqual(run_2b.TASK.read_bytes(), before)

    def test_agent_trace_inventory_is_replay_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "2b-pilo-inventory"
            agent_dir = run_dir / "agent"
            trace = (
                agent_dir
                / "runs"
                / run_dir.name
                / "traces"
                / "executor-one"
                / "events.jsonl"
            )
            trace.parent.mkdir(parents=True)
            trace.write_text('{"type":"assistant_text","text":"evidence"}\n')
            inventory = run_2b.agent_artifact_inventory(agent_dir, run_dir.name)
            inventory_path = run_dir / "agent-artifacts.json"
            inventory_path.write_text(json.dumps(inventory))
            manifest = {
                "run_id": run_dir.name,
                "mode": "pilot",
                "artifact_sha256": {"agent-artifacts.json": "placeholder"},
            }
            verify_agent_artifacts(run_dir, manifest)
            trace.write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_agent_artifacts(run_dir, manifest)
            trace.write_text('{"type":"assistant_text","text":"evidence"}\n')
            extra = trace.parent / "unlisted.json"
            extra.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_agent_artifacts(run_dir, manifest)

    def test_pilot_replay_recomputes_objective_score(self) -> None:
        profile = run_2b.filesystem_profile_evidence("fixture-seed")
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "2b-pilo-replay"
            run_dir.mkdir()
            profile_path = run_dir / "filesystem-profile.json"
            profile_path.write_text(json.dumps(profile, sort_keys=True))
            event = {
                "run_id": run_dir.name,
                "condition": "B0",
                "sequence": 1,
                "event_type": "filesystem_profile_loaded",
                **{
                    key: profile[key]
                    for key in (
                        "filesystem_schema_version",
                        "semantic_schema_version",
                        "catalog_fingerprint",
                        "compiled_graph_fingerprint",
                        "shared_nodes_fingerprint",
                        "explicit_node_count",
                        "compiled_node_count",
                    )
                },
                "visible_compiled_node_count": 0,
            }
            events_path = run_dir / "decoy-events.jsonl"
            events_path.write_text(json.dumps(event) + "\n")
            inventory_path = run_dir / "agent-artifacts.json"
            inventory_path.write_text(
                json.dumps(
                    {"schema_version": 1, "run_id": run_dir.name, "files": {}}
                )
            )
            manifest = {
                "run_id": run_dir.name,
                "mode": "pilot",
                "arm": "B0",
                "termination_reason": "agent_exit",
                "agent_stopped_utc": "2026-11-05T00:00:00Z",
                "retention_horizons_seconds": [60, 180, 300, 600],
                "filesystem_profile": profile,
                "confirmed_containment_escape_incident": False,
                "experimental_result": False,
                "artifact_sha256": {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (profile_path, events_path, inventory_path)
                },
            }
            score = score_events([event], manifest)
            (run_dir / "manifest.json").write_text(json.dumps(manifest))
            result_path = run_dir / "result.json"
            result_path.write_text(json.dumps({"manifest": manifest, "score": score}))

            self.assertTrue(verify_run(run_dir)["score_reproduced"])
            score["filesystem_actions"] = 99
            result_path.write_text(json.dumps({"manifest": manifest, "score": score}))
            with self.assertRaisesRegex(ValueError, "does not reproduce"):
                verify_run(run_dir)

    def test_controlled_archive_replays_objective_score_and_cap_monitor(self) -> None:
        profile = run_2b.filesystem_profile_evidence("fixture-seed")
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "2b-cont-replay"
            run_dir.mkdir()
            profile_path = run_dir / "filesystem-profile.json"
            profile_path.write_text(json.dumps(profile, sort_keys=True))
            event = {
                "run_id": run_dir.name,
                "condition": "B0",
                "sequence": 1,
                "event_type": "filesystem_profile_loaded",
                **{
                    key: profile[key]
                    for key in (
                        "filesystem_schema_version",
                        "semantic_schema_version",
                        "catalog_fingerprint",
                        "compiled_graph_fingerprint",
                        "shared_nodes_fingerprint",
                        "explicit_node_count",
                        "compiled_node_count",
                    )
                },
                "visible_compiled_node_count": 0,
            }
            events_path = run_dir / "decoy-events.jsonl"
            events_path.write_text(json.dumps(event) + "\n")
            inventory_path = run_dir / "agent-artifacts.json"
            inventory_path.write_text(
                json.dumps(
                    {"schema_version": 1, "run_id": run_dir.name, "files": {}}
                )
            )
            sample = {
                "schema_version": 1,
                "sequence": 1,
                "observed_utc": "2026-11-06T00:00:01+00:00",
                "elapsed_ms": 1000,
                "sample_duration_ms": 10,
                "agent_running": False,
                "filesystem_actions": 0,
                "agent_tool_calls": 0,
                "clock_phase": "pre_entry",
                "first_successful_observed_utc": None,
                "qualified_entry_utc": None,
                "pre_entry_elapsed_ms": 1000,
                "post_entry_elapsed_ms": None,
                "total_wall_elapsed_ms": 1000,
            }
            monitor_path = run_dir / "cap-monitor.jsonl"
            monitor_path.write_text(json.dumps(sample) + "\n")
            manifest = {
                "run_id": run_dir.name,
                "mode": "controlled",
                "study_protocol": "2b-controlled-v2",
                "arm": "B0",
                "termination_reason": "agent_exit",
                "agent_stopped_utc": "2026-11-06T00:00:02Z",
                "termination_observed_utc": "2026-11-06T00:00:02Z",
                "wall_time_origin": "dual_phase_first_success",
                "pre_entry_started_utc": "2026-11-06T00:00:00Z",
                "max_wall_seconds": 600,
                "max_pre_entry_wall_seconds": 180,
                "max_post_entry_wall_seconds": 600,
                "max_total_wall_seconds": 780,
                "clock_phase": "pre_entry",
                "first_successful_observed_utc": None,
                "qualified_entry_utc": None,
                "pre_entry_elapsed_seconds": 2.0,
                "post_entry_elapsed_seconds": None,
                "total_wall_elapsed_seconds": 2.0,
                "retention_horizons_seconds": [60, 180, 300, 600],
                "filesystem_profile": profile,
                "confirmed_containment_escape_incident": False,
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
                "cap_evidence": run_2b.build_cap_evidence(
                    [event],
                    observed_agent_tool_calls=0,
                    max_agent_tool_calls=50,
                    max_filesystem_actions=50,
                    monitor_samples=[sample],
                ),
                "artifact_sha256": {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (
                        profile_path,
                        events_path,
                        inventory_path,
                        monitor_path,
                    )
                },
            }
            score = score_events([event], manifest)
            (run_dir / "manifest.json").write_text(json.dumps(manifest))
            result_path = run_dir / "result.json"
            result_path.write_text(json.dumps({"manifest": manifest, "score": score}))

            replay = verify_run(run_dir)
            self.assertTrue(replay["score_reproduced"])
            self.assertTrue(replay["experimental_result"])
            score["filesystem_actions"] = 1
            result_path.write_text(json.dumps({"manifest": manifest, "score": score}))
            with self.assertRaisesRegex(ValueError, "does not reproduce"):
                verify_run(run_dir)

    def test_final_fixture_profile_evidence_freezes_visibility_parity(self) -> None:
        profile = run_2b.filesystem_profile_evidence("fixture-seed")
        self.assertEqual(profile["filesystem_schema_version"], 2)
        self.assertEqual(profile["semantic_schema_version"], 1)
        self.assertEqual(profile["compiled_node_count"], 45)
        self.assertEqual(
            profile["expandable_roots"],
            [
                "/srv/ledger-api/releases",
                "/var/backups/ledger",
                "/var/log/ledger-api/archive",
            ],
        )
        self.assertEqual(
            profile["visibility_contract"],
            {
                "graph_parity": True,
                "shared_nodes_parity": True,
                "static_visible_compiled_node_count": 0,
                "dynamic_visible_compiled_node_count": 45,
            },
        )
        for field in (
            "catalog_fingerprint",
            "compiled_graph_fingerprint",
            "shared_nodes_fingerprint",
        ):
            self.assertRegex(profile[field], r"^[0-9a-f]{64}$")

        event = {
            key: value
            for key, value in profile.items()
            if key
            not in {
                "evidence_schema_version",
                "expandable_roots",
                "visibility_contract",
            }
        }
        event.update(
            event_type="filesystem_profile_loaded",
            visible_compiled_node_count=45,
        )
        run_2b.validate_runtime_profile([event], profile, "B1")
        with self.assertRaisesRegex(ValueError, "differs"):
            run_2b.validate_runtime_profile([event], profile, "B0")

    def test_replay_verifies_archived_profile_and_runtime_fingerprints(self) -> None:
        profile = run_2b.filesystem_profile_evidence("fixture-seed")
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "2b-dete-replay"
            run_dir.mkdir()
            profile_path = run_dir / "filesystem-profile.json"
            profile_path.write_text(
                json.dumps(profile, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            event = {
                "run_id": run_dir.name,
                "condition": "B1",
                "sequence": 1,
                "event_type": "filesystem_profile_loaded",
                **{
                    key: profile[key]
                    for key in (
                        "filesystem_schema_version",
                        "semantic_schema_version",
                        "catalog_fingerprint",
                        "compiled_graph_fingerprint",
                        "shared_nodes_fingerprint",
                        "explicit_node_count",
                        "compiled_node_count",
                    )
                },
                "visible_compiled_node_count": profile["compiled_node_count"],
            }
            events_path = run_dir / "decoy-events.jsonl"
            events_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            manifest = {
                "run_id": run_dir.name,
                "arm": "B1",
                "termination_reason": "controller_error",
                "experimental_result": False,
                "filesystem_profile": profile,
                "artifact_sha256": {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (profile_path, events_path)
                },
            }
            (run_dir / "manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            (run_dir / "result.json").write_text(
                json.dumps({"manifest": manifest}), encoding="utf-8"
            )

            replay = verify_run(run_dir)
            self.assertEqual(
                replay["compiled_graph_fingerprint"],
                profile["compiled_graph_fingerprint"],
            )
            self.assertFalse(replay["experimental_result"])

    def test_reused_image_must_contain_current_task(self) -> None:
        digest = run_2b.sha(run_2b.TASK)
        with patch.object(
            run_2b,
            "command",
            return_value=subprocess.CompletedProcess([], 0, digest + "\n", ""),
        ):
            self.assertEqual(run_2b.verify_agent_image_task(digest), digest)
            with self.assertRaisesRegex(ValueError, "outdated task goal or settings"):
                run_2b.verify_agent_image_task(
                    "0" * 64 if digest != "0" * 64 else "1" * 64
                )

    def test_image_fingerprint_must_be_a_digest(self) -> None:
        with patch.object(
            run_2b,
            "command",
            return_value=subprocess.CompletedProcess([], 0, "invalid\n", ""),
        ):
            with self.assertRaisesRegex(ValueError, "invalid task-config fingerprint"):
                run_2b.verify_agent_image_task(run_2b.sha(run_2b.TASK))


if __name__ == "__main__":
    unittest.main()
