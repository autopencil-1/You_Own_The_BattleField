"""Model-free checks for explicit 2B bounded-terminal classification."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from telemetry.cap_taxonomy_2b import (
    classify_agent_policy_terminal,
    classify_gateway_policy_terminal,
    collect_agent_policy_exhaustions,
)


class CapTaxonomy2BTests(unittest.TestCase):
    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    @staticmethod
    def write_terminal_trace(
        root: Path,
        episode: str,
        *,
        role: str,
        stop_reason: str,
        turns: int | None,
        task_id: str | None = None,
        attempt_id: str | None = None,
        task_kind: str | None = None,
        state_revision: int = 0,
    ) -> None:
        trace = root / "traces" / episode
        CapTaxonomy2BTests.write_json(
            trace / "input.json",
            {
                "role": role,
                "max_turns": 12 if role == "executor" else 4,
                "task_kind": task_kind,
                "task_id": task_id,
                "attempt_id": attempt_id,
                "state_revision": state_revision,
                "opened_at": 1.0,
            },
        )
        event = {
            "type": "turn_completed",
            "success": False,
            "stop_reason": stop_reason,
            "recorded_at": 2.0,
            "num_turns": turns,
        }
        (trace / "events.jsonl").write_text(json.dumps(event) + "\n")
        CapTaxonomy2BTests.write_json(
            trace / "output.json",
            {"success": False, "error": stop_reason, "num_turns": turns},
        )

    def test_executor_turn_cap_requires_final_canonical_attempt_and_typed_trace(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent = Path(temporary)
            run_id = "2b-supp-taxonomy"
            root = agent / "runs" / run_id
            episode = "executor-attempt-one"
            self.write_json(
                root / "trial-config.json",
                {"max_decisions": 25, "max_attempts_per_task": 2},
            )
            self.write_json(
                root / "summary.json",
                {
                    "status": "failed",
                    "attempts": [
                        {
                            "id": "attempt-one",
                            "task_id": "task-one",
                            "failure_kind": "max_turns",
                            "trace_episode_id": episode,
                        }
                    ],
                    "transitions": [
                        {
                            "revision": 2,
                            "kind": "attempt_failed",
                            "task_id": "task-one",
                            "attempt_id": "attempt-one",
                            "created_at": 3.0,
                            "detail": {"failure_kind": "max_turns", "terminal": True},
                        }
                    ],
                },
            )
            self.write_terminal_trace(
                root,
                episode,
                role="executor",
                stop_reason="error_max_turns",
                turns=12,
                task_id="task-one",
                attempt_id="attempt-one",
                task_kind="enumerate",
                state_revision=1,
            )
            evidence = classify_agent_policy_terminal(agent, run_id)
            self.assertEqual(evidence["termination_reason"], "executor_turn_cap")
            self.assertEqual(evidence["observed_count"], 12)
            self.assertEqual(evidence["attempt_id"], "attempt-one")

            summary = json.loads((root / "summary.json").read_text())
            summary["transitions"][-1]["attempt_id"] = "different-attempt"
            self.write_json(root / "summary.json", summary)
            self.assertIsNone(classify_agent_policy_terminal(agent, run_id))

    def test_supervisor_turn_cap_is_bound_to_final_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent = Path(temporary)
            run_id = "2b-supp-supervisor"
            root = agent / "runs" / run_id
            self.write_json(
                root / "summary.json",
                {
                    "status": "failed",
                    "attempts": [],
                    "transitions": [
                        {
                            "revision": 1,
                            "kind": "supervisor_failed",
                            "created_at": 3.0,
                            "detail": {"failure_kind": "max_turns"},
                        }
                    ],
                },
            )
            self.write_terminal_trace(
                root,
                "supervisor-r0-a2",
                role="supervisor",
                stop_reason="error_max_turns",
                turns=None,
                state_revision=0,
            )
            evidence = classify_agent_policy_terminal(agent, run_id)
            self.assertEqual(evidence["termination_reason"], "supervisor_turn_cap")
            self.assertEqual(
                evidence["observed_count_status"],
                "unavailable_from_pinned_provider_adapter",
            )

            trace_input = root / "traces" / "supervisor-r0-a2" / "input.json"
            value = json.loads(trace_input.read_text())
            value["state_revision"] = 9
            self.write_json(trace_input, value)
            self.assertIsNone(classify_agent_policy_terminal(agent, run_id))

    def test_decision_and_nonterminal_task_attempt_exhaustion_are_distinct(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent = Path(temporary)
            decision_id = "2b-supp-decision"
            decision_root = agent / "runs" / decision_id
            self.write_json(decision_root / "trial-config.json", {"max_decisions": 25})
            self.write_json(
                decision_root / "summary.json",
                {
                    "status": "failed",
                    "attempts": [],
                    "transitions": [
                        {"kind": "plan_committed", "detail": {}},
                        {
                            "kind": "decision_limit_reached",
                            "created_at": 3.0,
                            "detail": {"failure_kind": "decision_limit"},
                        },
                    ],
                },
            )
            decision = classify_agent_policy_terminal(agent, decision_id)
            self.assertEqual(decision["termination_reason"], "agent_decision_cap")
            self.assertEqual(decision["limit"], 25)

            run_id = "2b-supp-progress"
            root = agent / "runs" / run_id
            self.write_json(root / "trial-config.json", {"max_attempts_per_task": 2})
            self.write_json(
                root / "summary.json",
                {
                    "status": "completed",
                    "tasks": [{"id": "t1", "kind": "enumerate"}],
                    "attempts": [
                        {
                            "id": "a1",
                            "task_id": "t1",
                            "trace_episode_id": "executor-a1",
                        },
                        {
                            "id": "a2",
                            "task_id": "t1",
                            "trace_episode_id": "executor-a2",
                        },
                    ],
                    "transitions": [
                        {
                            "kind": "attempt_committed",
                            "task_id": "t1",
                            "attempt_id": "a2",
                            "created_at": 4.0,
                            "detail": {"attempt_limit_reached": True},
                        },
                        {"kind": "run_completed", "detail": {}},
                    ],
                },
            )
            exhaustion = collect_agent_policy_exhaustions(agent, run_id)
            self.assertEqual(len(exhaustion), 1)
            self.assertEqual(exhaustion[0]["termination_reason"], "task_attempt_cap")
            self.assertFalse(exhaustion[0]["terminal"])
            self.assertEqual(exhaustion[0]["observed_count"], 2)
            self.assertEqual(exhaustion[0]["task_kind"], "enumerate")

    def test_recovered_trace_exhaustions_are_all_inventoried_without_fabricated_retries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent = Path(temporary)
            run_id = "2b-supp-recovered-exhaustions"
            root = agent / "runs" / run_id
            self.write_json(
                root / "summary.json",
                {
                    "status": "completed",
                    "attempts": [],
                    "transitions": [{"kind": "run_completed", "detail": {}}],
                },
            )
            self.write_terminal_trace(
                root,
                "executor-recovered-turn-cap",
                role="executor",
                stop_reason="error_max_turns",
                turns=None,
                task_kind="enumerate",
            )
            self.write_terminal_trace(
                root,
                "supervisor-recovered-structured-retry",
                role="supervisor",
                stop_reason="error_max_structured_output_retries",
                turns=4,
            )

            rows = collect_agent_policy_exhaustions(agent, run_id)
            self.assertEqual(
                [row["termination_reason"] for row in rows],
                ["executor_turn_cap", "structured_output_retry_cap"],
            )
            self.assertTrue(all(row["terminal"] is False for row in rows))
            turn = rows[0]
            self.assertEqual(turn["limit"], 12)
            self.assertIsNone(turn["observed_count"])
            self.assertEqual(
                turn["observed_count_status"],
                "unavailable_from_pinned_provider_adapter",
            )
            structured = rows[1]
            self.assertIsNone(structured["limit"])
            self.assertIsNone(structured["observed_count"])
            self.assertEqual(
                structured["observed_count_status"],
                "provider_managed_not_exposed",
            )

    def test_external_stop_recovers_attempt_exhaustion_from_durable_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            agent = Path(temporary)
            run_id = "2b-supp-external-stop"
            root = agent / "runs" / run_id
            root.mkdir(parents=True)
            self.write_json(root / "trial-config.json", {"max_attempts_per_task": 2})
            connection = sqlite3.connect(root / "state.sqlite3")
            try:
                connection.executescript(
                    """
                    CREATE TABLE runs (
                        run_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL
                    );
                    CREATE TABLE tasks (
                        run_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        created_revision INTEGER NOT NULL
                    );
                    CREATE TABLE attempts (
                        attempt_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        started_revision INTEGER NOT NULL,
                        trace_episode_id TEXT,
                        failure_kind TEXT
                    );
                    CREATE TABLE transitions (
                        run_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        kind TEXT NOT NULL,
                        task_id TEXT,
                        attempt_id TEXT,
                        detail TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    """
                )
                connection.execute(
                    "INSERT INTO runs (run_id, status) VALUES (?, ?)",
                    (run_id, "active"),
                )
                connection.execute(
                    "INSERT INTO tasks VALUES (?, ?, ?, ?)",
                    (run_id, "task-one", "enumerate", 1),
                )
                connection.executemany(
                    "INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        ("attempt-one", run_id, "task-one", 2, "executor-one", None),
                        ("attempt-two", run_id, "task-one", 3, "executor-two", None),
                    ),
                )
                connection.execute(
                    "INSERT INTO transitions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        4,
                        "attempt_committed",
                        "task-one",
                        "attempt-two",
                        json.dumps({"attempt_limit_reached": True}),
                        4.0,
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            rows = collect_agent_policy_exhaustions(agent, run_id)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["termination_reason"], "task_attempt_cap")
            self.assertEqual(rows[0]["observed_count"], 2)
            self.assertEqual(rows[0]["task_kind"], "enumerate")
            self.assertFalse(rows[0]["terminal"])

    def test_gateway_call_token_tie_and_missing_usage_are_not_conflated(self) -> None:
        base = {
            "event_type": "cap_reached",
            "timestamp_utc": "2026-11-06T00:00:01Z",
            "sequence": 3,
            "phase": "post_response",
            "request_path": "/v1/messages",
            "max_calls": 150,
            "max_tokens": 100_000_000,
            "usage_missing": False,
        }
        call = classify_gateway_policy_terminal(
            [
                {
                    **base,
                    "calls": 150,
                    "tokens": 10,
                    "cap_reason": "model_call_cap",
                    "triggered_reasons": ["model_call_cap"],
                }
            ],
            max_calls=150,
            max_tokens=100_000_000,
        )
        self.assertEqual(call["termination_reason"], "model_call_cap")

        tied = classify_gateway_policy_terminal(
            [
                {
                    **base,
                    "calls": 150,
                    "tokens": 100_000_001,
                    "cap_reason": "model_token_cap",
                    "triggered_reasons": ["model_call_cap", "model_token_cap"],
                }
            ],
            max_calls=150,
            max_tokens=100_000_000,
        )
        self.assertEqual(tied["termination_reason"], "model_token_cap")
        self.assertEqual(tied["triggered"], ["model_call_cap", "model_token_cap"])

        missing = classify_gateway_policy_terminal(
            [
                {
                    **base,
                    "calls": 3,
                    "tokens": 0,
                    "usage_missing": True,
                    "cap_reason": "usage_missing",
                    "triggered_reasons": ["usage_missing"],
                }
            ],
            max_calls=150,
            max_tokens=100_000_000,
        )
        self.assertEqual(missing["termination_reason"], "model_usage_missing")
        self.assertTrue(missing["infrastructure_invalid"])


if __name__ == "__main__":
    unittest.main()
