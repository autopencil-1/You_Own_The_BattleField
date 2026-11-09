"""Durable, prospective taxonomy for bounded 2B runtime states.

Historical pilot-v3 and controlled-v2 labels are intentionally not rewritten
here. This module defines only the explicit support-pilot vocabulary and
requires a terminal policy classification to agree with canonical PentestGPT
state and the exact terminal provider trace.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Any, Iterable


SUPPORT_TERMINAL_CAP_REASONS = frozenset(
    {
        "pre_entry_wall_cap",
        "post_entry_wall_cap",
        "filesystem_action_cap",
        "agent_tool_call_cap",
        "model_call_cap",
        "model_token_cap",
        "agent_decision_cap",
        "supervisor_turn_cap",
        "executor_turn_cap",
        "supervisor_attempt_cap",
        "structured_output_retry_cap",
        "task_attempt_cap",
    }
)
SUPPORT_RIGHT_CENSORED_REASONS = SUPPORT_TERMINAL_CAP_REASONS
SUPPORT_POLICY_EXHAUSTION_REASONS = frozenset(
    {
        "agent_decision_cap",
        "supervisor_turn_cap",
        "executor_turn_cap",
        "supervisor_attempt_cap",
        "structured_output_retry_cap",
        "task_attempt_cap",
    }
)


def _json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            return []
        if not isinstance(value, dict):
            return []
        rows.append(value)
    return rows


def _durable_state_summary(run_root: Path) -> dict[str, Any] | None:
    """Reconstruct the policy-relevant summary after an external controller stop."""

    database = run_root / "state.sqlite3"
    if not database.is_file():
        return None
    # Opening an archived WAL database directly can checkpoint or rewrite its
    # sidecars even for a read-only query. Query a disposable byte copy so
    # replay never mutates the evidence it is verifying.
    with tempfile.TemporaryDirectory() as temporary:
        copied = Path(temporary) / database.name
        try:
            for source in (
                database,
                database.with_name(database.name + "-wal"),
                database.with_name(database.name + "-shm"),
            ):
                if source.is_file():
                    shutil.copy2(source, Path(temporary) / source.name)
            connection = sqlite3.connect(copied)
            try:
                run = connection.execute(
                    "SELECT status FROM runs WHERE run_id = ?",
                    (run_root.name,),
                ).fetchone()
                if run is None or not isinstance(run[0], str):
                    return None
                tasks = [
                    {"id": task_id, "kind": kind}
                    for task_id, kind in connection.execute(
                        "SELECT task_id, kind FROM tasks WHERE run_id = ? "
                        "ORDER BY created_revision, task_id",
                        (run_root.name,),
                    )
                ]
                attempts = [
                    {
                        "id": attempt_id,
                        "task_id": task_id,
                        "trace_episode_id": trace_episode_id,
                        "failure_kind": failure_kind,
                    }
                    for attempt_id, task_id, trace_episode_id, failure_kind in connection.execute(
                        "SELECT attempt_id, task_id, trace_episode_id, failure_kind "
                        "FROM attempts WHERE run_id = ? ORDER BY started_revision, attempt_id",
                        (run_root.name,),
                    )
                ]
                transitions = []
                for (
                    revision,
                    kind,
                    task_id,
                    attempt_id,
                    raw_detail,
                    created_at,
                ) in connection.execute(
                    "SELECT revision, kind, task_id, attempt_id, detail, created_at "
                    "FROM transitions WHERE run_id = ? ORDER BY revision",
                    (run_root.name,),
                ):
                    try:
                        detail = json.loads(raw_detail)
                    except (TypeError, json.JSONDecodeError):
                        detail = {}
                    transitions.append(
                        {
                            "revision": revision,
                            "kind": kind,
                            "task_id": task_id,
                            "attempt_id": attempt_id,
                            "detail": detail if isinstance(detail, dict) else {},
                            "created_at": created_at,
                        }
                    )
            finally:
                connection.close()
        except (OSError, sqlite3.Error):
            return None
    return {
        "status": run[0],
        "tasks": tasks,
        "attempts": attempts,
        "transitions": transitions,
    }


def _positive_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _unix_utc(value: Any) -> str | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return None
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat()


def _typed_trace_evidence(
    run_root: Path,
    episode_id: str,
    *,
    expected_role: str,
    expected_stop_reason: str,
) -> dict[str, Any] | None:
    """Bind a policy exhaustion to one typed, unsuccessful terminal trace."""

    trace_root = run_root / "traces" / episode_id
    trace_input = _json(trace_root / "input.json")
    trace_output = _json(trace_root / "output.json")
    events = _jsonl(trace_root / "events.jsonl")
    if trace_input is None or trace_output is None or not events:
        return None
    terminal = next(
        (row for row in reversed(events) if row.get("type") == "turn_completed"),
        None,
    )
    role = trace_input.get("role")
    if (
        role != expected_role
        or trace_output.get("success") is not False
        or not isinstance(terminal, dict)
        or terminal.get("success") is not False
        or terminal.get("stop_reason") != expected_stop_reason
    ):
        return None
    task_kind = trace_input.get("task_kind")
    if task_kind is not None and not isinstance(task_kind, str):
        return None
    if expected_stop_reason == "error_max_turns":
        limit = _positive_int(trace_input.get("max_turns"))
        if limit is None:
            return None
        observed = terminal.get("num_turns", trace_output.get("num_turns"))
        if not (
            isinstance(observed, int)
            and not isinstance(observed, bool)
            and observed >= 0
        ):
            observed = None
        observed_status = (
            "reported_by_provider"
            if observed is not None
            else "unavailable_from_pinned_provider_adapter"
        )
    else:
        # The pinned provider owns this retry loop and exposes neither its
        # configured retry ceiling nor its attempt count. A turn ceiling/count
        # would be the wrong unit, so preserve the typed stop without inventing
        # numeric retry evidence.
        limit = None
        observed = None
        observed_status = "provider_managed_not_exposed"
    return {
        "source_failure_kind": (
            "max_turns"
            if expected_stop_reason == "error_max_turns"
            else "max_structured_output_retries"
        ),
        "role": role,
        "limit": limit,
        "observed_count": observed,
        "observed_count_status": observed_status,
        "trigger_utc": _unix_utc(terminal.get("recorded_at")),
        "episode_id": episode_id,
        "task_kind": task_kind,
        "task_id": trace_input.get("task_id"),
        "attempt_id": trace_input.get("attempt_id"),
    }


def _trial_limits(run_root: Path, summary: dict[str, Any]) -> dict[str, int]:
    identity = _json(run_root / "trial-config.json") or {}
    values: dict[str, int] = {}
    defaults = {"max_supervisor_attempts": 2, "max_attempts_per_task": 2}
    for name in (
        "max_decisions",
        "max_supervisor_attempts",
        "max_attempts_per_task",
        "supervisor_max_turns",
        "executor_max_turns",
    ):
        value = _positive_int(summary.get(name))
        if value is None:
            value = _positive_int(identity.get(name))
        if value is None:
            value = defaults.get(name)
        if value is not None:
            values[name] = value
    return values


def _terminal_transition(summary: dict[str, Any]) -> dict[str, Any] | None:
    transitions = summary.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return None
    if not all(isinstance(item, dict) for item in transitions):
        return None
    terminal = transitions[-1]
    return terminal if isinstance(terminal.get("detail"), dict) else None


def _matching_supervisor_trace(
    run_root: Path,
    terminal: dict[str, Any],
    *,
    stop_reason: str,
) -> dict[str, Any] | None:
    revision = terminal.get("revision")
    expected_state_revision = (
        revision - 1
        if isinstance(revision, int) and not isinstance(revision, bool)
        else None
    )
    candidates: list[tuple[float, dict[str, Any]]] = []
    for trace_root in (run_root / "traces").glob("supervisor-*"):
        trace_input = _json(trace_root / "input.json")
        if trace_input is None or (
            expected_state_revision is not None
            and trace_input.get("state_revision") != expected_state_revision
        ):
            continue
        evidence = _typed_trace_evidence(
            run_root,
            trace_root.name,
            expected_role="supervisor",
            expected_stop_reason=stop_reason,
        )
        if evidence is None:
            continue
        opened_at = trace_input.get("opened_at")
        candidates.append(
            (
                float(opened_at)
                if isinstance(opened_at, (int, float))
                and not isinstance(opened_at, bool)
                else 0.0,
                evidence,
            )
        )
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


def _terminal_attempt(
    summary: dict[str, Any], terminal: dict[str, Any]
) -> dict[str, Any] | None:
    attempts = summary.get("attempts")
    if not isinstance(attempts, list):
        return None
    attempt_id = terminal.get("attempt_id")
    if not isinstance(attempt_id, str):
        return None
    return next(
        (
            attempt
            for attempt in attempts
            if isinstance(attempt, dict) and attempt.get("id") == attempt_id
        ),
        None,
    )


def classify_agent_policy_terminal(
    agent_dir: Path,
    run_id: str,
) -> dict[str, Any] | None:
    """Return only a cap that caused the final canonical agent settlement."""

    run_root = agent_dir / "runs" / run_id
    summary = _json(run_root / "summary.json") or _durable_state_summary(run_root)
    if summary is None or summary.get("status") != "failed":
        return None
    terminal = _terminal_transition(summary)
    if terminal is None:
        return None
    detail = terminal["detail"]
    failure_kind = detail.get("failure_kind")
    limits = _trial_limits(run_root, summary)
    transition_utc = _unix_utc(terminal.get("created_at"))

    if (
        terminal.get("kind") == "decision_limit_reached"
        and failure_kind == "decision_limit"
    ):
        limit = limits.get("max_decisions")
        if limit is None:
            return None
        transitions = summary.get("transitions", [])
        observed = sum(item.get("kind") == "plan_committed" for item in transitions)
        return {
            "termination_reason": "agent_decision_cap",
            "source_failure_kind": "decision_limit",
            "role": "orchestrator",
            "limit": limit,
            "observed_count": observed,
            "observed_count_status": "canonical_transition_count",
            "trigger_utc": transition_utc,
            "episode_id": None,
            "task_kind": None,
            "task_id": None,
            "attempt_id": None,
        }

    if terminal.get("kind") == "attempt_failed" and detail.get("terminal") is True:
        attempt = _terminal_attempt(summary, terminal)
        if attempt is None or attempt.get("failure_kind") != failure_kind:
            return None
        episode_id = attempt.get("trace_episode_id")
        if not isinstance(episode_id, str):
            return None
        stop_reason = {
            "max_turns": "error_max_turns",
            "max_structured_output_retries": "error_max_structured_output_retries",
        }.get(failure_kind)
        if stop_reason is None:
            return None
        evidence = _typed_trace_evidence(
            run_root,
            episode_id,
            expected_role="executor",
            expected_stop_reason=stop_reason,
        )
        if evidence is None or evidence.get("attempt_id") != terminal.get("attempt_id"):
            return None
        return {
            "termination_reason": (
                "executor_turn_cap"
                if failure_kind == "max_turns"
                else "structured_output_retry_cap"
            ),
            **evidence,
            "settlement_utc": transition_utc,
        }

    if terminal.get("kind") == "supervisor_failed":
        if failure_kind in {"max_turns", "max_structured_output_retries"}:
            stop_reason = (
                "error_max_turns"
                if failure_kind == "max_turns"
                else "error_max_structured_output_retries"
            )
            evidence = _matching_supervisor_trace(
                run_root,
                terminal,
                stop_reason=stop_reason,
            )
            if evidence is None:
                return None
            return {
                "termination_reason": (
                    "supervisor_turn_cap"
                    if failure_kind == "max_turns"
                    else "structured_output_retry_cap"
                ),
                **evidence,
                "settlement_utc": transition_utc,
            }
        if failure_kind in {
            "supervisor_output_contract",
            "supervisor_recovery_ambiguous",
            "supervisor_action_policy",
        }:
            limit = limits.get("max_supervisor_attempts")
            if limit is None:
                return None
            revision = terminal.get("revision")
            state_revision = revision - 1 if isinstance(revision, int) else None
            observed = 0
            for trace_root in (run_root / "traces").glob("supervisor-*"):
                trace_input = _json(trace_root / "input.json") or {}
                if trace_input.get("role") == "supervisor" and (
                    state_revision is None
                    or trace_input.get("state_revision") == state_revision
                ):
                    observed += 1
            if observed != limit:
                return None
            return {
                "termination_reason": "supervisor_attempt_cap",
                "source_failure_kind": failure_kind,
                "role": "supervisor",
                "limit": limit,
                "observed_count": observed,
                "observed_count_status": "canonical_trace_count",
                "trigger_utc": transition_utc,
                "settlement_utc": transition_utc,
                "episode_id": None,
                "task_kind": None,
                "task_id": None,
                "attempt_id": None,
            }
    return None


def collect_agent_policy_exhaustions(
    agent_dir: Path,
    run_id: str,
) -> list[dict[str, Any]]:
    """Inventory terminal and non-terminal local administrative exhaustion."""

    run_root = agent_dir / "runs" / run_id
    summary = _json(run_root / "summary.json") or _durable_state_summary(run_root)
    if summary is None:
        return []
    limits = _trial_limits(run_root, summary)
    attempts = (
        summary.get("attempts") if isinstance(summary.get("attempts"), list) else []
    )
    tasks = summary.get("tasks") if isinstance(summary.get("tasks"), list) else []
    terminal = classify_agent_policy_terminal(agent_dir, run_id)
    rows: list[dict[str, Any]] = []
    for trace_root in sorted((run_root / "traces").glob("*")):
        if not trace_root.is_dir():
            continue
        trace_input = _json(trace_root / "input.json")
        if trace_input is None or trace_input.get("role") not in {
            "supervisor",
            "executor",
        }:
            continue
        role = trace_input["role"]
        for stop_reason, failure_reason in (
            ("error_max_turns", f"{role}_turn_cap"),
            (
                "error_max_structured_output_retries",
                "structured_output_retry_cap",
            ),
        ):
            evidence = _typed_trace_evidence(
                run_root,
                trace_root.name,
                expected_role=role,
                expected_stop_reason=stop_reason,
            )
            if evidence is None:
                continue
            is_terminal = bool(
                terminal is not None
                and terminal.get("termination_reason") == failure_reason
                and terminal.get("episode_id") == trace_root.name
                and terminal.get("trigger_utc") == evidence.get("trigger_utc")
            )
            rows.append(
                {
                    "termination_reason": failure_reason,
                    **evidence,
                    "settlement_utc": (
                        terminal.get("settlement_utc")
                        if is_terminal and terminal is not None
                        else evidence.get("trigger_utc")
                    ),
                    "terminal": is_terminal,
                }
            )
            break
    terminal_already_recorded = terminal is not None and any(
        row.get("terminal") is True
        and row.get("termination_reason") == terminal.get("termination_reason")
        and row.get("episode_id") == terminal.get("episode_id")
        and row.get("trigger_utc") == terminal.get("trigger_utc")
        for row in rows
    )
    if terminal is not None and not terminal_already_recorded:
        rows.append({**terminal, "terminal": True})
    for transition in summary.get("transitions", []):
        if not isinstance(transition, dict) or not isinstance(
            transition.get("detail"), dict
        ):
            continue
        detail = transition["detail"]
        if (
            transition.get("kind") != "attempt_committed"
            or detail.get("attempt_limit_reached") is not True
        ):
            continue
        task_id = transition.get("task_id")
        task_kind = next(
            (
                task.get("kind")
                for task in tasks
                if isinstance(task, dict)
                and task.get("id") == task_id
                and isinstance(task.get("kind"), str)
            ),
            None,
        )
        observed = sum(
            isinstance(attempt, dict) and attempt.get("task_id") == task_id
            for attempt in attempts
        )
        rows.append(
            {
                "termination_reason": "task_attempt_cap",
                "source_failure_kind": "attempt_limit_reached",
                "role": "executor",
                "limit": limits.get("max_attempts_per_task"),
                "observed_count": observed,
                "observed_count_status": "canonical_attempt_count",
                "trigger_utc": _unix_utc(transition.get("created_at")),
                "settlement_utc": _unix_utc(transition.get("created_at")),
                "episode_id": next(
                    (
                        attempt.get("trace_episode_id")
                        for attempt in attempts
                        if isinstance(attempt, dict)
                        and attempt.get("id") == transition.get("attempt_id")
                    ),
                    None,
                ),
                "task_kind": task_kind,
                "task_id": task_id,
                "attempt_id": transition.get("attempt_id"),
                "terminal": False,
            }
        )
    return rows


def classify_gateway_policy_terminal(
    events: Iterable[dict[str, Any]],
    *,
    max_calls: int,
    max_tokens: int,
) -> dict[str, Any] | None:
    """Classify the first gateway refusal without conflating missing usage."""

    rows = [event for event in events if event.get("event_type") == "cap_reached"]
    if not rows:
        return None
    event = rows[0]
    calls = event.get("calls")
    tokens = event.get("tokens")
    usage_missing = event.get("usage_missing")
    if (
        not isinstance(calls, int)
        or isinstance(calls, bool)
        or calls < 0
        or not isinstance(tokens, int)
        or isinstance(tokens, bool)
        or tokens < 0
        or not isinstance(usage_missing, bool)
    ):
        return None
    if (
        event.get("max_calls", max_calls) != max_calls
        or event.get("max_tokens", max_tokens) != max_tokens
    ):
        return None
    if usage_missing:
        expected_reason = "usage_missing"
        triggered = ["usage_missing"]
    else:
        triggered = []
        if calls >= max_calls:
            triggered.append("model_call_cap")
        if tokens >= max_tokens:
            triggered.append("model_token_cap")
        if not triggered:
            return None
        expected_reason = (
            "model_token_cap" if "model_token_cap" in triggered else "model_call_cap"
        )
    if (
        event.get("cap_reason", expected_reason) != expected_reason
        or event.get("triggered_reasons", triggered) != triggered
    ):
        return None
    common = {
        "calls": calls,
        "tokens": tokens,
        "triggered": triggered,
        "trigger_utc": event.get("timestamp_utc"),
        "event_sequence": event.get("sequence"),
        "phase": event.get("phase"),
        "request_path": event.get("request_path"),
    }
    if usage_missing:
        return {
            "termination_reason": "model_usage_missing",
            "infrastructure_invalid": True,
            "limit": None,
            **common,
        }
    return {
        "termination_reason": expected_reason,
        "infrastructure_invalid": False,
        "limit": max_tokens if expected_reason == "model_token_cap" else max_calls,
        "observed_count": tokens if expected_reason == "model_token_cap" else calls,
        **common,
    }
