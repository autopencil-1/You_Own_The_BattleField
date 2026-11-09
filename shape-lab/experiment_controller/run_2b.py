"""Run isolated 2B fixture checks and explicitly gated engineering pilots."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import uuid
from typing import Any

from filesystem_decoy_2b.virtual_fs import FilesystemSpec, VirtualFilesystem
from agent_runner.runtime_policy_2b import POLICY_ENV

from .run_2a import (
    agent_source_sha256,
    agent_trial_failure,
    count_tool_calls,
    parsed_jsonl,
    read_key,
    validate_sources,
)
from model_gateway.providers import provider_spec
from telemetry.score_2b import score_events
from telemetry.cap_taxonomy_2b import (
    classify_agent_policy_terminal,
    classify_gateway_policy_terminal,
    collect_agent_policy_exhaustions,
)
from .live_capture import LiveCapture


LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parent
COMPOSE = LAB / "compose_2b.yaml"
FIXTURE = LAB / "config" / "exp_2b_engine_fixture.json"
TASK = LAB / "config" / "agent_2b_task.json"
PILOT_CONFIG = LAB / "config" / "exp_2b_pilot.json"
CONTROLLED_CONFIG = LAB / "config" / "exp_2b_controlled_v2.json"
SUPPORT_CONFIG = LAB / "config" / "exp_2b_support_pilot_v3.json"
DECOY_IMAGE = "shape-filesystem-decoy-2b:dev"
AGENT_IMAGE = "shape-2b-attacker:dev"
GATEWAY_IMAGE = "shape-model-gateway:dev"
SUPPORT_TIE_PRECEDENCE = (
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
)


def command(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 600,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args, cwd=LAB, env=env, text=True, capture_output=True, timeout=timeout
    )
    if check and result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(args)}\n{result.stderr[-2000:]}"
        )
    return result


def compose(
    project: str,
    args: list[str],
    env: dict[str, str],
    *,
    timeout: int = 600,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return command(
        ["docker", "compose", "-p", project, "-f", str(COMPOSE), *args],
        env=env,
        timeout=timeout,
        check=check,
    )


def compose_agent(
    project: str,
    args: list[str],
    env: dict[str, str],
    *,
    timeout: int = 600,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return command(
        [
            "docker",
            "compose",
            "--profile",
            "agent",
            "-p",
            project,
            "-f",
            str(COMPOSE),
            *args,
        ],
        env=env,
        timeout=timeout,
        check=check,
    )


def write_private(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(value)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pilot_contract() -> dict[str, Any]:
    raw = json.loads(PILOT_CONFIG.read_text(encoding="utf-8"))
    if (
        raw.get("schema_version") != 3
        or raw.get("pilot_protocol") != "2b-pilot-v3"
        or raw.get("protocol") != "filesystem-semantic-v2"
        or raw.get("profile") != "ledger-prod-01"
        or raw.get("seed") != "fixture-seed"
        or raw.get("frozen_input_sha256")
        != {"agent_task": sha(TASK), "filesystem_fixture": sha(FIXTURE)}
    ):
        raise ValueError("2B pilot contract or frozen inputs differ")
    if raw.get("termination_policy") != {
        "agent_max_turns": {
            "source_failure_kind": "max_turns",
            "termination_reason": "agent_turn_cap",
            "valid_outcome": True,
            "right_censored": True,
        }
    }:
        raise ValueError("2B pilot termination policy differs")
    if raw.get("cap_policy") != {
        "primary_behavioral_boundary": "filesystem_actions",
        "filesystem_action_enforcement": "atomic_server",
        "agent_tool_call_enforcement": "observational_watchdog",
        "require_cap_monitor": True,
    }:
        raise ValueError("2B pilot cap policy differs")
    return raw


def controlled_contract() -> dict[str, Any]:
    # Imported lazily so the standalone fixture modes do not require a local
    # pilot-readiness archive. Controlled execution deliberately does.
    from .controlled_2b_contract import load_contract

    return load_contract()


def support_contract() -> dict[str, Any]:
    """Load the separately committed support-pilot execution contract."""

    from .support_pilot_2b_contract import load_contract

    return load_contract()


def agent_turn_cap_evidence(agent_dir: Path, run_id: str) -> dict[str, str] | None:
    """Return bounded durable evidence for a terminal PentestGPT turn cap."""
    summary_path = agent_dir / "runs" / run_id / "summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(summary, dict) or summary.get("status") != "failed":
        return None
    detail = summary.get("error")
    attempts = summary.get("attempts")
    if not isinstance(detail, str) or not detail.startswith("max_turns:"):
        return None
    if not isinstance(attempts, list):
        return None
    terminal = next(
        (
            item
            for item in reversed(attempts)
            if isinstance(item, dict) and item.get("status") == "error"
        ),
        None,
    )
    if terminal is None or terminal.get("failure_kind") != "max_turns":
        return None
    message = terminal.get("failure_message")
    if not isinstance(message, str) or not message:
        return None
    return {
        "failure_kind": "max_turns",
        "failure_message": message[:500],
    }


def agent_artifact_inventory(agent_dir: Path, run_id: str) -> dict[str, Any]:
    root = agent_dir / "runs" / run_id
    files = {}
    if root.is_dir():
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = path.relative_to(agent_dir.parent).as_posix()
            files[relative] = {
                "sha256": sha(path),
                "size": path.stat().st_size,
            }
    return {"schema_version": 1, "run_id": run_id, "files": files}


def agent_trace_events(agent_dir: Path, run_id: str) -> list[dict[str, Any]]:
    rows = []
    root = agent_dir / "runs" / run_id / "traces"
    for path in sorted(root.glob("*/events.jsonl")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def agent_trace_records(agent_dir: Path, run_id: str) -> list[dict[str, Any]]:
    """Return trace rows with immutable archive locations for cap evidence."""

    rows = []
    root = agent_dir / "runs" / run_id / "traces"
    for path in sorted(root.glob("*/events.jsonl")):
        relative = path.relative_to(agent_dir.parent).as_posix()
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(
                    {
                        **row,
                        "_episode_id": path.parent.name,
                        "_evidence_file": relative,
                        "_evidence_sequence": line_number,
                    }
                )
    return rows


def gateway_usage_snapshot(events: list[dict[str, Any]]) -> dict[str, int]:
    """Count client requests (not upstream retries) and cumulative reported usage."""

    calls = [
        event.get("call_number")
        for event in events
        if event.get("event_type") == "model_call"
        and isinstance(event.get("call_number"), int)
        and not isinstance(event.get("call_number"), bool)
        and event["call_number"] >= 0
    ]
    cap_calls = [
        event.get("calls")
        for event in events
        if event.get("event_type") == "cap_reached"
        and isinstance(event.get("calls"), int)
        and not isinstance(event.get("calls"), bool)
        and event["calls"] >= 0
    ]
    tokens = [
        event.get("total_tokens")
        for event in events
        if event.get("event_type") == "model_call"
        and isinstance(event.get("total_tokens"), int)
        and not isinstance(event.get("total_tokens"), bool)
        and event["total_tokens"] >= 0
    ]
    cap_tokens = [
        event.get("tokens")
        for event in events
        if event.get("event_type") == "cap_reached"
        and isinstance(event.get("tokens"), int)
        and not isinstance(event.get("tokens"), bool)
        and event["tokens"] >= 0
    ]
    return {
        "model_calls": max([0, *calls, *cap_calls]),
        "model_tokens": max([0, *tokens, *cap_tokens]),
    }


def agent_policy_snapshot(agent_dir: Path, run_id: str) -> dict[str, Any]:
    """Read arm-blind proximity counters from durable local agent state."""

    trace_root = agent_dir / "runs" / run_id / "traces"
    roles: list[str] = []
    reported: dict[str, list[int]] = {"supervisor": [], "executor": []}
    missing_turn_count = False
    policy_exhaustions = 0
    trace_records = agent_trace_records(agent_dir, run_id)
    for episode in sorted(trace_root.glob("*")):
        if not episode.is_dir():
            continue
        try:
            trace_input = json.loads(
                (episode / "input.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue
        role = trace_input.get("role")
        if role not in reported:
            continue
        roles.append(role)
        output_path = episode / "output.json"
        if output_path.exists():
            try:
                output = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                missing_turn_count = True
                continue
            turns = output.get("num_turns")
            if isinstance(turns, int) and not isinstance(turns, bool) and turns >= 0:
                reported[role].append(turns)
            else:
                missing_turn_count = True
        for event in trace_records:
            if event.get("_episode_id") != episode.name:
                continue
            if event.get("type") == "turn_completed" and event.get("stop_reason") in {
                "error_max_turns",
                "error_max_structured_output_retries",
            }:
                policy_exhaustions += 1
    decisions = 0
    database = agent_dir / "runs" / run_id / "state.sqlite3"
    if database.is_file():
        try:
            connection = sqlite3.connect(
                f"file:{database}?mode=ro", uri=True, timeout=0.1
            )
            try:
                transitions = connection.execute(
                    "SELECT kind, detail FROM transitions ORDER BY revision"
                ).fetchall()
            finally:
                connection.close()
            for kind, raw_detail in transitions:
                decisions += int(kind == "plan_committed")
                if kind == "decision_limit_reached":
                    policy_exhaustions += 1
                if kind == "supervisor_failed":
                    try:
                        supervisor_detail = json.loads(raw_detail)
                    except (TypeError, json.JSONDecodeError):
                        supervisor_detail = {}
                    if isinstance(supervisor_detail, dict) and supervisor_detail.get(
                        "failure_kind"
                    ) in {
                        "supervisor_output_contract",
                        "supervisor_recovery_ambiguous",
                        "supervisor_action_policy",
                    }:
                        policy_exhaustions += 1
                if kind == "attempt_committed":
                    try:
                        detail = json.loads(raw_detail)
                    except (TypeError, json.JSONDecodeError):
                        detail = {}
                    policy_exhaustions += int(
                        isinstance(detail, dict)
                        and detail.get("attempt_limit_reached") is True
                    )
        except sqlite3.Error:
            pass
    completed_outputs = sum(len(values) for values in reported.values())
    status = (
        "reported"
        if roles and completed_outputs == len(roles) and not missing_turn_count
        else "unavailable"
    )
    return {
        "agent_decisions": decisions,
        "supervisor_episodes": roles.count("supervisor"),
        "executor_episodes": roles.count("executor"),
        "max_observed_supervisor_turns": (
            max(reported["supervisor"], default=None) if status == "reported" else None
        ),
        "max_observed_executor_turns": (
            max(reported["executor"], default=None) if status == "reported" else None
        ),
        "provider_turn_count_status": status,
        "policy_exhaustion_count": policy_exhaustions,
    }


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def container_finished_utc(state: dict[str, Any]) -> datetime:
    """Return Docker's immutable container-finish timestamp as UTC."""

    value = state.get("FinishedAt")
    if not isinstance(value, str):
        raise ValueError("Attacker container lacks a finish timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Attacker container finish timestamp is malformed") from exc
    if parsed.tzinfo is None or parsed.year < 2000:
        raise ValueError("Attacker container finish timestamp is invalid")
    return parsed.astimezone(timezone.utc)


def controlled_clock_evidence(
    decoy_events: list[dict[str, Any]],
    *,
    pre_entry_started_utc: datetime,
    observed_utc: datetime,
    pre_entry_limit_seconds: int,
) -> dict[str, Any]:
    """Compute reproducible dual-phase timing from archived decoy events."""

    first_success = next(
        (
            event.get("timestamp_utc")
            for event in decoy_events
            if event.get("event_type") == "filesystem_interaction"
            and event.get("exit_code") == 0
        ),
        None,
    )
    first_success_at = None
    if first_success is not None:
        if not isinstance(first_success, str):
            raise ValueError("Controlled first-success timestamp is malformed")
        try:
            first_success_at = datetime.fromisoformat(
                first_success.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("Controlled first-success timestamp is malformed") from exc
        if first_success_at.tzinfo is None:
            raise ValueError("Controlled first-success timestamp lacks a timezone")
        first_success_at = first_success_at.astimezone(timezone.utc)
    started = pre_entry_started_utc.astimezone(timezone.utc)
    observed = observed_utc.astimezone(timezone.utc)
    total_elapsed = max(0.0, (observed - started).total_seconds())
    if first_success_at is not None and first_success_at > observed:
        raise ValueError("Controlled first-success timestamp follows observation")
    raw_pre_entry_elapsed = (
        max(0.0, (first_success_at - started).total_seconds())
        if first_success_at is not None
        else total_elapsed
    )
    qualified = (
        first_success_at
        if first_success_at is not None
        and raw_pre_entry_elapsed < pre_entry_limit_seconds
        else None
    )
    return {
        "clock_phase": "post_entry" if qualified is not None else "pre_entry",
        "first_successful_observed_utc": (
            first_success_at.isoformat() if first_success_at is not None else None
        ),
        "qualified_entry_utc": qualified.isoformat() if qualified is not None else None,
        "pre_entry_elapsed_seconds": (
            max(0.0, (qualified - started).total_seconds())
            if qualified is not None
            else total_elapsed
        ),
        "post_entry_elapsed_seconds": (
            max(0.0, (observed - qualified).total_seconds())
            if qualified is not None
            else None
        ),
        "total_wall_elapsed_seconds": total_elapsed,
    }


def _event_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} lacks a timezone")
    return parsed.astimezone(timezone.utc)


def support_cap_candidates(
    *,
    decoy_events: list[dict[str, Any]],
    gateway_events: list[dict[str, Any]],
    agent_dir: Path,
    run_id: str,
    pre_entry_started_utc: datetime,
    observed_utc: datetime,
    max_pre_entry_wall_seconds: int,
    max_post_entry_wall_seconds: int,
    max_filesystem_actions: int,
    max_agent_tool_calls: int,
    max_model_calls: int,
    max_model_tokens: int,
    monitor_sequence: int,
    agent_finished_utc: datetime | None = None,
) -> list[dict[str, Any]]:
    """Reconstruct every durable support trigger available by an observation."""

    observed = observed_utc.astimezone(timezone.utc)
    effective_wall_observation = (
        agent_finished_utc.astimezone(timezone.utc)
        if agent_finished_utc is not None
        else observed
    )
    candidates: list[dict[str, Any]] = []

    def add(
        reason: str,
        trigger: datetime,
        *,
        limit: int | None,
        observed_count: int | None,
        observed_count_status: str,
        role: str | None,
        task_kind: str | None = None,
        episode_id: str | None = None,
        task_id: str | None = None,
        attempt_id: str | None = None,
        evidence_file: str,
        evidence_sequence: int,
        settlement_utc: str | None = None,
    ) -> None:
        trigger = trigger.astimezone(timezone.utc)
        if trigger <= observed:
            candidates.append(
                {
                    "reason": reason,
                    "trigger_utc": trigger.isoformat(),
                    "_trigger_at": trigger,
                    "limit": limit,
                    "observed_count": observed_count,
                    "observed_count_status": observed_count_status,
                    "role": role,
                    "task_kind": task_kind,
                    "episode_id": episode_id,
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "settlement_utc": settlement_utc,
                    "_evidence_sources": [
                        {
                            "file": evidence_file,
                            "sequence": evidence_sequence,
                        }
                    ],
                }
            )

    successful = [
        event
        for event in decoy_events
        if event.get("event_type") == "filesystem_interaction"
        and event.get("exit_code") == 0
    ]
    first_success = (
        _event_utc(successful[0].get("timestamp_utc"), "Support first success")
        if successful
        else None
    )
    pre_deadline = pre_entry_started_utc.astimezone(timezone.utc) + timedelta(
        seconds=max_pre_entry_wall_seconds
    )
    qualified = (
        first_success
        if first_success is not None and first_success < pre_deadline
        else None
    )
    if qualified is None and effective_wall_observation >= pre_deadline:
        add(
            "pre_entry_wall_cap",
            pre_deadline,
            limit=max_pre_entry_wall_seconds,
            observed_count=max_pre_entry_wall_seconds,
            observed_count_status="recomputed_deadline",
            role="controller",
            evidence_file="cap-monitor.jsonl",
            evidence_sequence=monitor_sequence,
        )
    if qualified is not None:
        post_deadline = qualified + timedelta(seconds=max_post_entry_wall_seconds)
        if effective_wall_observation >= post_deadline:
            add(
                "post_entry_wall_cap",
                post_deadline,
                limit=max_post_entry_wall_seconds,
                observed_count=max_post_entry_wall_seconds,
                observed_count_status="recomputed_deadline",
                role="controller",
                evidence_file="cap-monitor.jsonl",
                evidence_sequence=monitor_sequence,
            )

    interactions = [
        event
        for event in decoy_events
        if event.get("event_type") == "filesystem_interaction"
        and _event_utc(event.get("timestamp_utc"), "Filesystem interaction") <= observed
    ]
    if len(interactions) >= max_filesystem_actions:
        event = interactions[max_filesystem_actions - 1]
        add(
            "filesystem_action_cap",
            _event_utc(event.get("timestamp_utc"), "Filesystem cap trigger"),
            limit=max_filesystem_actions,
            observed_count=len(interactions),
            observed_count_status="accepted_event_count",
            role="filesystem-decoy",
            evidence_file="decoy-events.jsonl",
            evidence_sequence=int(event.get("sequence", max_filesystem_actions)),
        )

    tool_calls = sorted(
        (
            row
            for row in agent_trace_records(agent_dir, run_id)
            if row.get("type") == "tool_call"
            and isinstance(row.get("recorded_at"), (int, float))
            and not isinstance(row.get("recorded_at"), bool)
            and float(row["recorded_at"]) <= observed.timestamp()
        ),
        key=lambda row: (
            float(row["recorded_at"]),
            row["_evidence_file"],
            row["_evidence_sequence"],
        ),
    )
    if len(tool_calls) >= max_agent_tool_calls:
        event = tool_calls[max_agent_tool_calls - 1]
        add(
            "agent_tool_call_cap",
            datetime.fromtimestamp(float(event["recorded_at"]), timezone.utc),
            limit=max_agent_tool_calls,
            observed_count=len(tool_calls),
            observed_count_status="durable_trace_count",
            role="agent",
            episode_id=event["_episode_id"],
            evidence_file=event["_evidence_file"],
            evidence_sequence=event["_evidence_sequence"],
        )

    gateway = classify_gateway_policy_terminal(
        gateway_events,
        max_calls=max_model_calls,
        max_tokens=max_model_tokens,
    )
    if gateway is not None:
        cap_row_number = next(
            (
                index
                for index, row in enumerate(gateway_events, 1)
                if row.get("event_type") == "cap_reached"
            ),
            1,
        )
        gateway_trigger = _event_utc(
            gateway.get("trigger_utc"), "Gateway terminal trigger"
        )
        if gateway.get("infrastructure_invalid"):
            add(
                gateway["termination_reason"],
                gateway_trigger,
                limit=None,
                observed_count=gateway.get("calls"),
                observed_count_status="gateway_atomic_counter",
                role="model-gateway",
                evidence_file="gateway-events.jsonl",
                evidence_sequence=cap_row_number,
            )
        else:
            # One atomic refusal can cross both bounds. Preserve both
            # occurrences; selection applies token-before-call precedence.
            for reason in gateway.get("triggered", []):
                token_cap = reason == "model_token_cap"
                add(
                    reason,
                    gateway_trigger,
                    limit=max_model_tokens if token_cap else max_model_calls,
                    observed_count=(
                        gateway.get("tokens") if token_cap else gateway.get("calls")
                    ),
                    observed_count_status="gateway_atomic_counter",
                    role="model-gateway",
                    evidence_file="gateway-events.jsonl",
                    evidence_sequence=cap_row_number,
                )

    rate_limit = next(
        (
            (index, event)
            for index, event in enumerate(gateway_events, 1)
            if event.get("event_type")
            in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"}
        ),
        None,
    )
    if rate_limit is not None:
        index, event = rate_limit
        add(
            "provider_rate_limit",
            _event_utc(event.get("timestamp_utc"), "Provider-rate-limit trigger"),
            limit=None,
            observed_count=event.get("attempts"),
            observed_count_status="gateway_provider_attempt_count",
            role="model-gateway",
            evidence_file="gateway-events.jsonl",
            evidence_sequence=index,
        )

    local = classify_agent_policy_terminal(agent_dir, run_id)
    if local is not None and local.get("trigger_utc") is not None:
        episode_id = local.get("episode_id")
        evidence_file = "cap-monitor.jsonl"
        evidence_sequence = monitor_sequence
        if isinstance(episode_id, str):
            terminal_rows = [
                row
                for row in agent_trace_records(agent_dir, run_id)
                if row.get("_episode_id") == episode_id
                and row.get("type") == "turn_completed"
            ]
            if terminal_rows:
                terminal_row = terminal_rows[-1]
                evidence_file = terminal_row["_evidence_file"]
                evidence_sequence = terminal_row["_evidence_sequence"]
        add(
            local["termination_reason"],
            _event_utc(local["trigger_utc"], "Agent policy trigger"),
            limit=local.get("limit"),
            observed_count=local.get("observed_count"),
            observed_count_status=local.get("observed_count_status", "unknown"),
            role=local.get("role"),
            task_kind=local.get("task_kind"),
            episode_id=episode_id,
            task_id=local.get("task_id"),
            attempt_id=local.get("attempt_id"),
            evidence_file=evidence_file,
            evidence_sequence=evidence_sequence,
            settlement_utc=local.get("settlement_utc"),
        )

    if agent_finished_utc is not None:
        add(
            "agent_exit",
            agent_finished_utc,
            limit=None,
            observed_count=None,
            observed_count_status="docker_finished_at",
            role="agent",
            evidence_file="cap-monitor.jsonl",
            evidence_sequence=monitor_sequence,
            settlement_utc=agent_finished_utc.isoformat(),
        )
    return candidates


def select_support_trigger(
    candidates: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]] | None:
    """Choose the earliest trigger, applying one frozen tie precedence."""

    if not candidates:
        return None
    earliest = min(candidate["_trigger_at"] for candidate in candidates)
    coincident = [
        candidate for candidate in candidates if candidate["_trigger_at"] == earliest
    ]
    reasons = [
        reason
        for reason in SUPPORT_TIE_PRECEDENCE
        if any(candidate["reason"] == reason for candidate in coincident)
    ]
    unknown = sorted({candidate["reason"] for candidate in coincident} - set(reasons))
    reasons.extend(unknown)
    selected = next(
        candidate for candidate in coincident if candidate["reason"] == reasons[0]
    )
    return selected, reasons


def build_cap_evidence(
    decoy_events: list[dict[str, Any]],
    *,
    observed_agent_tool_calls: int,
    max_agent_tool_calls: int,
    max_filesystem_actions: int,
    monitor_samples: list[dict[str, Any]],
    support_snapshot: dict[str, Any] | None = None,
    agent_tool_call_enforcement: str = "observational_watchdog",
) -> dict[str, Any]:
    filesystem_actions = sum(
        event.get("event_type") == "filesystem_interaction" for event in decoy_events
    )
    command_cap_rejections = sum(
        event.get("event_type") == "decoy_response"
        and event.get("route") == "/exec"
        and event.get("status") == 429
        for event in decoy_events
    )
    elapsed_values = [
        sample.get("elapsed_ms")
        for sample in monitor_samples
        if isinstance(sample, dict)
        and isinstance(sample.get("elapsed_ms"), int)
        and not isinstance(sample.get("elapsed_ms"), bool)
    ]
    gaps = [
        later - earlier
        for earlier, later in zip(elapsed_values, elapsed_values[1:])
        if later >= earlier
    ]
    evidence = {
        "schema_version": 1,
        "primary_behavioral_boundary": "filesystem_actions",
        "filesystem_action_enforcement": "atomic_server",
        "filesystem_action_limit": max_filesystem_actions,
        "observed_filesystem_actions": filesystem_actions,
        "hard_limit_conformant": filesystem_actions <= max_filesystem_actions,
        "command_cap_rejections": command_cap_rejections,
        "agent_tool_call_enforcement": agent_tool_call_enforcement,
        "agent_tool_call_watchdog_limit": max_agent_tool_calls,
        "observed_agent_tool_calls": observed_agent_tool_calls,
        "agent_tool_call_watchdog_overshoot": max(
            0, observed_agent_tool_calls - max_agent_tool_calls
        ),
        "monitor_sample_count": len(monitor_samples),
        "maximum_monitor_gap_ms": max(gaps, default=0),
    }
    if support_snapshot is not None:
        evidence.update(
            {
                "observed_model_calls": support_snapshot["model_calls"],
                "observed_model_tokens": support_snapshot["model_tokens"],
                "observed_agent_decisions": support_snapshot["agent_decisions"],
                "observed_supervisor_episodes": support_snapshot["supervisor_episodes"],
                "observed_executor_episodes": support_snapshot["executor_episodes"],
                "max_observed_supervisor_turns": support_snapshot[
                    "max_observed_supervisor_turns"
                ],
                "max_observed_executor_turns": support_snapshot[
                    "max_observed_executor_turns"
                ],
                "provider_turn_count_status": support_snapshot[
                    "provider_turn_count_status"
                ],
                "policy_exhaustion_count": support_snapshot["policy_exhaustion_count"],
            }
        )
    return evidence


def _line_evidence(run_dir: Path, source: dict[str, Any]) -> dict[str, Any]:
    relative = source.get("file")
    sequence = source.get("sequence")
    if (
        not isinstance(relative, str)
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
    ):
        raise ValueError("Support evidence source is malformed")
    path = (run_dir / relative).resolve()
    root = run_dir.resolve()
    if path != root and root not in path.parents:
        raise ValueError("Support evidence source leaves the run archive")
    try:
        line = path.read_bytes().splitlines(keepends=True)[sequence - 1]
    except (OSError, IndexError) as exc:
        raise ValueError("Support evidence source line is missing") from exc
    return {
        "file": relative,
        "sequence": sequence,
        "sha256": hashlib.sha256(line).hexdigest(),
    }


def build_support_termination_evidence(
    run_dir: Path,
    selected: dict[str, Any],
    coincident_reasons: list[str],
    *,
    observed_utc: str,
    settlement_utc: str,
) -> dict[str, Any]:
    """Bind the selected trigger to immutable archived evidence lines."""

    evidence = [
        _line_evidence(run_dir, source)
        for source in selected.get("_evidence_sources", [])
    ]
    if not evidence:
        raise ValueError("Support termination lacks an evidence source")
    return {
        "schema_version": 1,
        "reason": selected["reason"],
        "trigger_utc": selected["trigger_utc"],
        "observed_utc": observed_utc,
        "settlement_utc": selected.get("settlement_utc") or settlement_utc,
        "limit": selected.get("limit"),
        "observed_count": selected.get("observed_count"),
        "observed_count_status": selected.get("observed_count_status"),
        "coincident_reasons": coincident_reasons,
        "role": selected.get("role"),
        "task_kind": selected.get("task_kind"),
        "episode_id": selected.get("episode_id"),
        "task_id": selected.get("task_id"),
        "attempt_id": selected.get("attempt_id"),
        "evidence": evidence,
    }


def build_support_policy_exhaustions(
    candidates: list[dict[str, Any]],
    local_rows: list[dict[str, Any]],
    *,
    selected: dict[str, Any],
    qualified_entry_utc: str | None,
    observed_utc: str,
) -> list[dict[str, Any]]:
    """Normalize controller, gateway, and agent policy bounds for the gate."""

    declared = {
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
    }
    qualified = (
        _event_utc(qualified_entry_utc, "Support qualified entry")
        if qualified_entry_utc is not None
        else None
    )
    observed = _event_utc(observed_utc, "Support exhaustion observation")
    normalized: list[dict[str, Any]] = []

    def append(
        *,
        reason: str,
        limit: Any,
        observed_count: Any,
        role: Any,
        task_kind: Any,
        episode_id: Any,
        occurred_utc: Any,
        terminal: bool,
    ) -> None:
        if reason not in declared or not isinstance(occurred_utc, str):
            return
        occurred = _event_utc(occurred_utc, "Support policy exhaustion")
        if occurred > observed:
            return
        post_elapsed = (
            max(0.0, (occurred - qualified).total_seconds())
            if qualified is not None and occurred >= qualified
            else None
        )
        normalized.append(
            {
                "reason": reason,
                "configured_limit": limit,
                "observed_count": observed_count,
                "role": role,
                "task_kind": task_kind,
                "episode_id": episode_id,
                "occurred_utc": occurred.isoformat(),
                "clock_phase": "post_entry"
                if post_elapsed is not None
                else "pre_entry",
                "post_entry_elapsed_seconds": post_elapsed,
                "terminal": terminal,
            }
        )

    for candidate in candidates:
        append(
            reason=candidate["reason"],
            limit=candidate.get("limit"),
            observed_count=candidate.get("observed_count"),
            role=candidate.get("role"),
            task_kind=candidate.get("task_kind"),
            episode_id=candidate.get("episode_id"),
            occurred_utc=candidate.get("trigger_utc"),
            terminal=(
                candidate["reason"] == selected["reason"]
                and candidate["trigger_utc"] == selected["trigger_utc"]
            ),
        )
    for row in local_rows:
        append(
            reason=row.get("termination_reason"),
            limit=row.get("limit"),
            observed_count=row.get("observed_count"),
            role=row.get("role"),
            task_kind=row.get("task_kind"),
            episode_id=row.get("episode_id"),
            occurred_utc=row.get("trigger_utc"),
            terminal=bool(row.get("terminal")),
        )
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in normalized:
        key = (
            row["reason"],
            row["occurred_utc"],
            row["episode_id"],
        )
        # Candidate rows come first and define whether this occurrence was the
        # controller-selected terminal trigger. The local inventory may
        # independently rediscover the same episode; do not duplicate it or
        # overwrite that overall-terminal classification.
        unique.setdefault(key, row)
    return sorted(
        unique.values(),
        key=lambda row: (
            row["occurred_utc"],
            SUPPORT_TIE_PRECEDENCE.index(row["reason"]),
            str(row["episode_id"]),
        ),
    )


def filesystem_profile_evidence(seed: str) -> dict[str, Any]:
    """Compile both visibility states and freeze their parity contract."""
    spec = FilesystemSpec.from_json(FIXTURE.read_text(encoding="utf-8"))
    static = VirtualFilesystem(spec, seed, dynamic=False)
    dynamic = VirtualFilesystem(spec, seed, dynamic=True)
    static_evidence = static.semantic_profile_evidence()
    dynamic_evidence = dynamic.semantic_profile_evidence()
    stable_keys = set(static_evidence) - {"visible_compiled_node_count"}
    if any(static_evidence[key] != dynamic_evidence[key] for key in stable_keys):
        raise ValueError("Static and dynamic filesystem profile fingerprints differ")
    if any(static.node(path) != dynamic.node(path) for path in spec.nodes):
        raise ValueError("Static and dynamic shared virtual nodes differ")
    graph = dynamic.semantic_graph
    if graph is None or not graph.nodes:
        raise ValueError("Final 2B fixture needs a nonempty compiled semantic graph")
    if any(static.node(path) is not None for path in graph.nodes):
        raise ValueError("Static filesystem exposes compiled semantic nodes")
    if any(dynamic.node(path) is None for path in graph.nodes):
        raise ValueError("Dynamic filesystem hides compiled semantic nodes")
    return {
        "evidence_schema_version": 1,
        **{key: static_evidence[key] for key in sorted(stable_keys)},
        "expandable_roots": sorted(spec.expandable_roots),
        "visibility_contract": {
            "graph_parity": True,
            "shared_nodes_parity": True,
            "static_visible_compiled_node_count": static_evidence[
                "visible_compiled_node_count"
            ],
            "dynamic_visible_compiled_node_count": dynamic_evidence[
                "visible_compiled_node_count"
            ],
        },
    }


def validate_runtime_profile(
    events: list[dict[str, Any]], profile: dict[str, Any], arm: str
) -> None:
    loaded = [
        event
        for event in events
        if event.get("event_type") == "filesystem_profile_loaded"
    ]
    if len(loaded) != 1:
        raise ValueError("Decoy must archive exactly one filesystem profile event")
    expected = {
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
    }
    expected["visible_compiled_node_count"] = profile["visibility_contract"][
        "dynamic_visible_compiled_node_count"
        if arm in {"B1", "B3"}
        else "static_visible_compiled_node_count"
    ]
    if any(loaded[0].get(key) != value for key, value in expected.items()):
        raise ValueError("Runtime filesystem profile differs from controller evidence")


def image_id(name: str = DECOY_IMAGE) -> str | None:
    result = command(
        ["docker", "image", "inspect", name, "--format", "{{.Id}}"],
        timeout=30,
        check=False,
    )
    return result.stdout.strip() or None


def verify_agent_image_task(expected_sha256: str) -> str:
    """Reject a reused attacker image whose embedded task differs from this run."""
    digest = command(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            AGENT_IMAGE,
            "-c",
            "import hashlib; from pathlib import Path; "
            "print(hashlib.sha256(Path('/opt/shape/agent_2b_task.json').read_bytes()).hexdigest())",
        ],
        timeout=30,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Attacker image returned an invalid task-config fingerprint")
    if digest != expected_sha256:
        raise ValueError(
            "Attacker image has an outdated task goal or settings; rebuild the image before this run"
        )
    return digest


def service_events(project: str, service: str, env: dict[str, str]) -> str:
    return compose_agent(
        project,
        ["logs", "--no-color", "--no-log-prefix", service],
        env,
        timeout=30,
        check=False,
    ).stdout


def container_info(project: str, service: str, env: dict[str, str]) -> dict[str, Any]:
    identifier = compose_agent(
        project, ["ps", "-a", "-q", service], env, timeout=30
    ).stdout.strip()
    if not identifier:
        raise RuntimeError(f"Missing {service} container")
    output = command(
        [
            "docker",
            "inspect",
            identifier,
            "--format",
            "{{json .State}}\n{{json .NetworkSettings.Networks}}\n{{json .Config.Env}}\n{{json .Mounts}}",
        ],
        timeout=30,
    ).stdout.splitlines()
    return {
        "state": json.loads(output[0]),
        "networks": sorted(json.loads(output[1])),
        "environment": json.loads(output[2]),
        "mounts": json.loads(output[3]),
    }


def credential_shape(info: dict[str, Any]) -> dict[str, bool]:
    names = {item.partition("=")[0] for item in info["environment"]}
    mounts = {item["Destination"] for item in info["mounts"]}
    return {
        "real_key_in_environment": bool({"ZAI_API_KEY", "OLLAMA_API_KEY"} & names),
        "real_key_file_mounted": "/run/secrets/model_api_key" in mounts,
        "arm_in_environment": "SHAPE_ARM" in names,
        "placeholder_auth": "ANTHROPIC_AUTH_TOKEN=shape-lab-placeholder"
        in info["environment"],
    }


def run_deterministic(
    arm: str,
    *,
    build: bool = True,
    seed: str = "fixture-seed",
    branching_factor: int = 4,
    run_id: str | None = None,
) -> dict[str, Any]:
    if arm not in {"B0", "B1", "B2", "B3"}:
        raise ValueError("Unknown 2B arm")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", seed):
        raise ValueError("Invalid seed")
    if not 1 <= branching_factor <= 15:
        raise ValueError("Invalid branching factor")
    run_id = (
        run_id
        or "2b-dete-"
        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        + "-"
        + uuid.uuid4().hex[:6]
    )
    if not re.fullmatch(r"2b-dete-[a-z0-9-]{1,53}", run_id):
        raise ValueError("Invalid run ID")
    project = "shape" + run_id
    run_dir = LAB / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    filesystem_profile = filesystem_profile_evidence(seed)
    write_private(
        run_dir / "filesystem-profile.json",
        json.dumps(filesystem_profile, indent=2, sort_keys=True) + "\n",
    )
    env = dict(os.environ)
    env.update(
        {
            "SHAPE_RUN_ID": run_id,
            "SHAPE_ARM": arm,
            "SHAPE_2B_SEED": seed,
            "SHAPE_2B_BRANCHING": str(branching_factor),
            "SHAPE_RUN_DIR": str(run_dir.resolve()),
            "LAB_UID": str(os.getuid()),
            "LAB_GID": str(os.getgid()),
        }
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "mode": "deterministic_fixture",
        "arm": arm,
        "seed": seed,
        "branching_factor": branching_factor,
        "project": project,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "fixture_sha256": sha(FIXTURE),
        "agent_task_sha256": sha(TASK),
        "filesystem_engine_sha256": sha(LAB / "filesystem_decoy_2b" / "virtual_fs.py"),
        "decoy_server_sha256": sha(LAB / "filesystem_decoy_2b" / "server.py"),
        "ssh_tools_sha256": sha(LAB / "agent_runner" / "ssh_tools_2b.py"),
        "compose_source_sha256": sha(COMPOSE),
        "filesystem_profile": filesystem_profile,
        "confirmed_containment_escape_incident": False,
        "experimental_result": False,
    }
    error: str | None = None
    reason = "not_started"
    live_capture: LiveCapture | None = None
    try:
        if build:
            output = compose_agent(
                project, ["build", "filesystem-decoy-2b", "attacker-agent"], env
            )
            write_private(run_dir / "build.log", output.stdout + output.stderr)
        manifest["decoy_image_id"] = image_id()
        manifest["agent_image_id"] = image_id(AGENT_IMAGE)
        if manifest["decoy_image_id"] is None or manifest["agent_image_id"] is None:
            raise RuntimeError("2B decoy and attacker images must be built")
        resolved = compose(project, ["config"], env, timeout=30).stdout
        write_private(run_dir / "compose.resolved.yaml", resolved)
        manifest["resolved_compose_sha256"] = hashlib.sha256(
            resolved.encode()
        ).hexdigest()
        compose(
            project,
            [
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                "30",
                "--no-build",
                "filesystem-decoy-2b",
            ],
            env,
            timeout=60,
        )
        validate_runtime_profile(
            parsed_jsonl(service_events(project, "filesystem-decoy-2b", env)),
            filesystem_profile,
            arm,
        )
        live_capture = LiveCapture(
            COMPOSE, project, run_dir, {"filesystem-decoy-2b": "decoy-live.jsonl"}, env
        )
        live_capture.start()
        network = project + "_trial_net"
        network_state = command(
            ["docker", "network", "inspect", network, "--format", "{{json .Internal}}"],
            timeout=30,
        ).stdout.strip()
        if network_state != "true":
            raise RuntimeError("Trial network is not internal")
        identifier = compose(
            project, ["ps", "-q", "filesystem-decoy-2b"], env, timeout=30
        ).stdout.strip()
        inspection = command(
            [
                "docker",
                "inspect",
                identifier,
                "--format",
                "{{json .NetworkSettings.Networks}}\n{{json .NetworkSettings.Ports}}",
            ],
            timeout=30,
        ).stdout.splitlines()
        if sorted(json.loads(inspection[0])) != [network]:
            raise RuntimeError("2B decoy joined an unexpected network")
        ports = json.loads(inspection[1])
        if any(value is not None for value in ports.values()):
            raise RuntimeError("2B decoy published a host port")
        manifest["isolation_preflight"] = {
            "internal_network": True,
            "no_host_ports": True,
        }
        client = command(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--mount",
                f"type=bind,src={LAB / 'tests'},dst=/smoke,readonly",
                "--env",
                f"SHAPE_SMOKE_ARM={arm}",
                "--entrypoint",
                "python",
                DECOY_IMAGE,
                "/smoke/docker_smoke_2b.py",
            ],
            timeout=60,
        )
        write_private(run_dir / "client.log", client.stdout + client.stderr)
        tool_probe = """
import socket
from ssh_tools_2b import ssh_connect, ssh_exec
assert "Already connected" in ssh_connect("ssh://lab@filesystem-decoy-2b")
assert "/home/lab/README.md" in ssh_exec("file /home/lab/README.md")
assert "ledger-prod-01" in ssh_exec("uname -a")
assert "ledger-api" in ssh_exec("cat /srv/ledger-api/current/release.yaml")
assert "command not found" in ssh_exec("mount")
try:
    with socket.create_connection(("1.1.1.1", 443), timeout=3):
        raise AssertionError("attacker image has direct external egress")
except OSError:
    pass
print("SSH_TOOL_TRANSPORT=passed")
"""
        tool_client = command(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--entrypoint",
                "python",
                AGENT_IMAGE,
                "-c",
                tool_probe,
            ],
            timeout=60,
        )
        write_private(
            run_dir / "tool-client.log", tool_client.stdout + tool_client.stderr
        )
        reason = "deterministic_complete"
    except Exception as exc:
        reason = "controller_error"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if live_capture is not None:
            live_capture.stop()
        try:
            logs = compose(
                project,
                ["logs", "--no-color", "--no-log-prefix", "filesystem-decoy-2b"],
                env,
                timeout=30,
                check=False,
            ).stdout
            write_private(run_dir / "decoy-events.jsonl", logs)
        except Exception:
            pass
        compose(project, ["down", "--remove-orphans"], env, timeout=90, check=False)
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["termination_reason"] = reason
    manifest["error"] = error
    manifest["artifact_sha256"] = {
        name: sha(run_dir / name)
        for name in (
            "compose.resolved.yaml",
            "client.log",
            "tool-client.log",
            "decoy-events.jsonl",
            "filesystem-profile.json",
        )
        if (run_dir / name).exists()
    }
    write_private(
        run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    result = {"manifest": manifest, "run_dir": str(run_dir)}
    write_private(
        run_dir / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    return result


def _run_agent(
    mode: str,
    arm: str,
    *,
    build: bool = True,
    seed: str = "fixture-seed",
    run_id: str | None = None,
    provider: str = "ollama",
    assignment: dict[str, Any] | None = None,
    frozen_fingerprint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run connectivity, a frozen pilot, or one frozen controlled assignment."""
    if mode not in {"connectivity", "pilot", "controlled", "support"}:
        raise ValueError("Unknown 2B agent-run mode")
    if arm not in {"B0", "B1", "B2", "B3"} or (mode == "connectivity" and arm != "B0"):
        raise ValueError("Invalid arm for 2B agent-run mode")
    provider_spec(provider)
    agent_task = json.loads(TASK.read_text(encoding="utf-8"))
    bounded_trial = mode in {"pilot", "controlled", "support"}
    dual_phase_trial = mode in {"controlled", "support"}
    contract = (
        pilot_contract()
        if mode == "pilot"
        else controlled_contract()
        if mode == "controlled"
        else support_contract()
        if mode == "support"
        else None
    )
    if mode == "support" and contract["execution"]["available"] is not True:
        raise RuntimeError(
            "2b-support-pilot-v3 execution is unavailable until a separately "
            "committed execution contract and schedule"
        )
    if bounded_trial:
        if build:
            raise ValueError("Build and fingerprint images before a frozen 2B trial")
        if provider != contract["provider"] or seed != contract["seed"]:
            raise ValueError("2B provider or filesystem seed differs from contract")
        assignment_keys = (
            {"study_id", "slot", "block", "arm"}
            if mode == "controlled"
            else {"pilot_id", "slot", "block", "arm"}
        )
        if (
            not isinstance(assignment, dict)
            or set(assignment) != assignment_keys
            or assignment["arm"] != arm
            or frozen_fingerprint is None
        ):
            raise ValueError("2B execution requires a frozen schedule assignment")
        if dual_phase_trial:
            max_pre_entry_wall = contract["trial_caps"]["pre_entry_wall_seconds"]
            max_wall = contract["trial_caps"]["post_entry_wall_seconds"]
            max_total_wall = contract["trial_caps"]["maximum_total_wall_seconds"]
        else:
            max_pre_entry_wall = None
            max_wall = contract["trial_caps"]["wall_seconds"]
            max_total_wall = max_wall
        max_filesystem_actions = contract["trial_caps"]["max_filesystem_actions"]
        max_agent_tool_calls = (
            contract["trial_caps"]["max_agent_tool_calls"]
            if mode == "support"
            else agent_task["caps_per_trial"]["max_agent_tool_calls"]
        )
        max_model_calls = (
            contract["trial_caps"]["max_model_calls"]
            if mode == "support"
            else agent_task["caps_per_trial"]["max_model_calls"]
        )
        retention_horizons = contract["trial_caps"].get(
            "retention_horizons_seconds", [60, 180, 300, 600]
        )
    else:
        max_pre_entry_wall = None
        max_wall = agent_task["caps_per_trial"]["wall_seconds"]
        max_total_wall = max_wall
        max_filesystem_actions = 50
        max_agent_tool_calls = 20
        max_model_calls = 8
        retention_horizons = []
    max_model_tokens = (
        contract["trial_caps"]["max_model_tokens_input_plus_output"]
        if mode == "support"
        else agent_task["caps_per_trial"]["max_model_tokens_input_plus_output"]
    )
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", seed):
        raise ValueError("Invalid seed")
    pentest_commit, unified_commit = validate_sources()
    prefix = {
        "connectivity": "2b-conn-",
        "pilot": "2b-pilo-",
        "controlled": "2b-cont-",
        "support": "2b-supp-",
    }[mode]
    run_id = run_id or (
        prefix
        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        + "-"
        + uuid.uuid4().hex[:6]
    )
    if not re.fullmatch(prefix + r"[a-z0-9-]{1,53}", run_id):
        raise ValueError("Invalid run ID")
    project = "shape" + run_id
    run_dir = LAB / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    agent_dir = run_dir / "agent"
    agent_dir.mkdir(mode=0o700)
    filesystem_profile = filesystem_profile_evidence(seed)
    write_private(
        run_dir / "filesystem-profile.json",
        json.dumps(filesystem_profile, indent=2, sort_keys=True) + "\n",
    )
    env = dict(os.environ)
    env.update(
        {
            "SHAPE_RUN_ID": run_id,
            "SHAPE_ARM": arm,
            "SHAPE_2B_SEED": seed,
            "SHAPE_RUN_DIR": str(run_dir.resolve()),
            "SHAPE_2B_PROFILE_STATUS": ("fixture" if mode == "connectivity" else mode),
            "SHAPE_2B_ALLOW_FIXTURE_MODEL": "1" if mode == "connectivity" else "0",
            "SHAPE_2B_SMOKE": "1" if mode == "connectivity" else "0",
            "SHAPE_2B_MAX_COMMANDS": str(max_filesystem_actions),
            "SHAPE_2B_REINFORCEMENT_EVERY": str(
                contract["reinforcement_every"] if contract else 3
            ),
            "SHAPE_MAX_MODEL_CALLS": str(max_model_calls),
            "SHAPE_MAX_MODEL_TOKENS": str(max_model_tokens),
            "SHAPE_PROVIDER_429_RETRY_DELAYS": "",
            POLICY_ENV: (
                json.dumps(
                    contract["runtime_policy"],
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if mode == "support"
                else ""
            ),
            "SHAPE_MODEL": agent_task["agent"]["model"],
            "SHAPE_MODEL_PROVIDER": provider,
            "LAB_UID": str(os.getuid()),
            "LAB_GID": str(os.getgid()),
        }
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "mode": "connectivity_fixture" if mode == "connectivity" else mode,
        "arm": arm,
        "model": agent_task["agent"]["model"],
        "provider": provider,
        "seed": seed,
        "project": project,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "fixture_sha256": sha(FIXTURE),
        "agent_task_sha256": sha(TASK),
        "filesystem_engine_sha256": sha(LAB / "filesystem_decoy_2b" / "virtual_fs.py"),
        "decoy_server_sha256": sha(LAB / "filesystem_decoy_2b" / "server.py"),
        "ssh_tools_sha256": sha(LAB / "agent_runner" / "ssh_tools_2b.py"),
        "agent_entrypoint_sha256": sha(LAB / "agent_runner" / "entrypoint_2b.py"),
        "agent_runtime_policy_sha256": sha(
            LAB / "agent_runner" / "runtime_policy_2b.py"
        ),
        "controller_sha256": sha(Path(__file__)),
        "pentestgpt_commit": pentest_commit,
        "agent_source_sha256": agent_source_sha256(),
        "unified_agent_commit": unified_commit,
        "max_wall_seconds": max_wall,
        "max_filesystem_actions": max_filesystem_actions,
        "max_agent_tool_calls": max_agent_tool_calls,
        "max_model_calls": max_model_calls,
        "max_model_tokens": max_model_tokens,
        "retention_horizons_seconds": retention_horizons,
        "filesystem_profile": filesystem_profile,
        "confirmed_containment_escape_incident": False,
        "experimental_result": mode == "controlled",
    }
    if mode == "pilot":
        manifest.update(
            {
                "protocol": contract["protocol"],
                "pilot_protocol": contract["pilot_protocol"],
                "pilot_contract_schema_version": contract["schema_version"],
                "pilot_config_sha256": sha(PILOT_CONFIG),
                "assignment": assignment,
                "pilot_fingerprint": frozen_fingerprint,
            }
        )
    elif mode == "controlled":
        manifest.update(
            {
                "protocol": contract["environment_protocol"],
                "study_protocol": contract["study_protocol"],
                "controlled_contract_schema_version": contract["schema_version"],
                "controlled_contract_sha256": sha(CONTROLLED_CONFIG),
                "assignment": assignment,
                "study_fingerprint": frozen_fingerprint,
                "wall_time_origin": "dual_phase_first_success",
                "max_pre_entry_wall_seconds": max_pre_entry_wall,
                "max_post_entry_wall_seconds": max_wall,
                "max_total_wall_seconds": max_total_wall,
                "pre_entry_started_utc": None,
                "clock_phase": "pre_entry",
                "first_successful_observed_utc": None,
                "qualified_entry_utc": None,
                "pre_entry_elapsed_seconds": None,
                "post_entry_elapsed_seconds": None,
                "total_wall_elapsed_seconds": None,
                "termination_observed_utc": None,
            }
        )
    elif mode == "support":
        manifest.update(
            {
                "mode": "support_pilot",
                "protocol": contract["environment_protocol"],
                "pilot_protocol": contract["pilot_protocol"],
                "support_contract_schema_version": contract["schema_version"],
                "support_contract_sha256": sha(SUPPORT_CONFIG),
                "assignment": assignment,
                "support_fingerprint": frozen_fingerprint,
                "runtime_policy": contract["runtime_policy"],
                "attempt_bounds": contract["attempt_bounds"],
                "wall_time_origin": "dual_phase_first_success",
                "max_pre_entry_wall_seconds": max_pre_entry_wall,
                "max_post_entry_wall_seconds": max_wall,
                "max_total_wall_seconds": max_total_wall,
                "pre_entry_started_utc": None,
                "clock_phase": "pre_entry",
                "first_successful_observed_utc": None,
                "qualified_entry_utc": None,
                "pre_entry_elapsed_seconds": None,
                "post_entry_elapsed_seconds": None,
                "total_wall_elapsed_seconds": None,
                "termination_observed_utc": None,
                "policy_exhaustions": [],
            }
        )
    reason = "not_started"
    error: str | None = None
    agent_exit_code: int | None = None
    live_capture: LiveCapture | None = None
    cap_monitor_path = run_dir / "cap-monitor.jsonl"
    cap_sample_sequence = 0
    support_selected: dict[str, Any] | None = None
    support_coincident_reasons: list[str] = []
    support_candidates_at_stop: list[dict[str, Any]] = []
    if bounded_trial:
        write_private(cap_monitor_path, "")
    with tempfile.TemporaryDirectory(prefix="shape2b-key-") as secret_dir:
        key_file = Path(secret_dir) / "model_api_key"
        write_private(key_file, read_key(provider) + "\n")
        env["SHAPE_KEY_FILE"] = str(key_file)
        try:
            if build:
                output = compose_agent(
                    project,
                    ["build", "filesystem-decoy-2b", "model-gateway", "attacker-agent"],
                    env,
                )
                write_private(run_dir / "build.log", output.stdout + output.stderr)
            manifest["images"] = {
                name: image_id(image)
                for name, image in {
                    "decoy": DECOY_IMAGE,
                    "gateway": GATEWAY_IMAGE,
                    "agent": AGENT_IMAGE,
                }.items()
            }
            if any(value is None for value in manifest["images"].values()):
                raise RuntimeError("All 2B trial images must be built")
            if bounded_trial and manifest["images"] != frozen_fingerprint.get("images"):
                raise RuntimeError("2B trial images differ from the frozen schedule")
            manifest["agent_image_task_sha256"] = verify_agent_image_task(
                manifest["agent_task_sha256"]
            )
            resolved = compose_agent(project, ["config"], env, timeout=30).stdout
            write_private(run_dir / "compose.resolved.yaml", resolved)
            manifest["resolved_compose_sha256"] = hashlib.sha256(
                resolved.encode()
            ).hexdigest()
            compose_agent(
                project,
                [
                    "up",
                    "-d",
                    "--wait",
                    "--wait-timeout",
                    "30",
                    "--no-build",
                    "filesystem-decoy-2b",
                    "model-gateway",
                ],
                env,
                timeout=60,
            )
            validate_runtime_profile(
                parsed_jsonl(service_events(project, "filesystem-decoy-2b", env)),
                filesystem_profile,
                arm,
            )
            live_capture = LiveCapture(
                COMPOSE,
                project,
                run_dir,
                {
                    "filesystem-decoy-2b": "decoy-live.jsonl",
                    "model-gateway": "gateway-live.jsonl",
                },
                env,
            )
            live_capture.start()
            trial_network = project + "_trial_net"
            egress_network = project + "_egress_net"
            decoy_info = container_info(project, "filesystem-decoy-2b", env)
            gateway_info = container_info(project, "model-gateway", env)
            if decoy_info["networks"] != [trial_network] or gateway_info[
                "networks"
            ] != sorted([trial_network, egress_network]):
                raise RuntimeError(
                    "Decoy or gateway network topology differs from the trial contract"
                )
            if credential_shape(decoy_info) != {
                "real_key_in_environment": False,
                "real_key_file_mounted": False,
                "arm_in_environment": True,
                "placeholder_auth": False,
            } or credential_shape(gateway_info) != {
                "real_key_in_environment": False,
                "real_key_file_mounted": True,
                "arm_in_environment": False,
                "placeholder_auth": False,
            }:
                raise RuntimeError(
                    "Decoy or gateway credential placement differs from the trial contract"
                )
            probe = """
import json, socket, urllib.request
result = {}
for name, url in (("decoy", "http://filesystem-decoy-2b:8082/healthz"),
                  ("gateway", "http://model-gateway:8081/healthz")):
    with urllib.request.urlopen(url, timeout=3) as response:
        result[name] = response.status
try:
    with socket.create_connection(("1.1.1.1", 443), timeout=3):
        result["direct_egress"] = True
except OSError:
    result["direct_egress"] = False
print(json.dumps(result, sort_keys=True))
"""
            observed = json.loads(
                command(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        trial_network,
                        "--read-only",
                        "--cap-drop=ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        "--entrypoint",
                        "python",
                        AGENT_IMAGE,
                        "-c",
                        probe,
                    ],
                    timeout=20,
                ).stdout
            )
            if observed != {"decoy": 200, "gateway": 200, "direct_egress": False}:
                raise RuntimeError(f"2B network preflight failed: {observed}")
            manifest["isolation_preflight"] = observed
            wall_started_utc = datetime.now(timezone.utc)
            started = time.monotonic()
            if dual_phase_trial:
                manifest["pre_entry_started_utc"] = wall_started_utc.isoformat()
            compose_agent(
                project, ["up", "-d", "--no-build", "attacker-agent"], env, timeout=90
            )
            live_capture.add("attacker-agent", "agent-live.log")
            agent_info = container_info(project, "attacker-agent", env)
            if agent_info["networks"] != [trial_network] or credential_shape(
                agent_info
            ) != {
                "real_key_in_environment": False,
                "real_key_file_mounted": False,
                "arm_in_environment": False,
                "placeholder_auth": True,
            }:
                raise RuntimeError(
                    "Attacker network or credential placement differs from the trial contract"
                )
            reason = "agent_exit"
            while True:
                sample_started = time.monotonic()
                state = container_info(project, "attacker-agent", env)["state"]
                gateway_events = parsed_jsonl(
                    service_events(project, "model-gateway", env)
                )
                decoy_events = parsed_jsonl(
                    service_events(project, "filesystem-decoy-2b", env)
                )
                model_ok = any(
                    item.get("event_type") == "model_call" and item.get("status") == 200
                    for item in gateway_events
                )
                rate_limited = any(
                    item.get("event_type")
                    in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"}
                    for item in gateway_events
                )
                connected = any(
                    item.get("event_type") == "ssh_connected" for item in decoy_events
                )
                command_seen = any(
                    item.get("event_type") == "filesystem_interaction"
                    for item in decoy_events
                )
                filesystem_actions = sum(
                    item.get("event_type") == "filesystem_interaction"
                    for item in decoy_events
                )
                agent_tool_calls = count_tool_calls(agent_dir, run_id)
                support_proximity = None
                support_finished_utc = None
                if mode == "support":
                    support_proximity = {
                        **gateway_usage_snapshot(gateway_events),
                        **agent_policy_snapshot(agent_dir, run_id),
                    }
                    # Observe state only after the logs and local counters used
                    # by this sample. If the process settled, refresh the local
                    # snapshot once after all agent writers have stopped.
                    state = container_info(project, "attacker-agent", env)["state"]
                    if not state.get("Running"):
                        support_proximity = {
                            **gateway_usage_snapshot(gateway_events),
                            **agent_policy_snapshot(agent_dir, run_id),
                        }
                        support_finished_utc = container_finished_utc(state)
                # Timestamp the completed observation, not the start of the
                # Docker/log/counter queries whose evidence this sample summarizes.
                sample_observed_utc = datetime.now(timezone.utc)
                if dual_phase_trial:
                    clock = controlled_clock_evidence(
                        decoy_events,
                        pre_entry_started_utc=wall_started_utc,
                        observed_utc=sample_observed_utc,
                        pre_entry_limit_seconds=max_pre_entry_wall,
                    )
                    manifest.update(clock)
                    wall_elapsed = (
                        clock["post_entry_elapsed_seconds"]
                        if clock["clock_phase"] == "post_entry"
                        else clock["pre_entry_elapsed_seconds"]
                    )
                else:
                    clock = None
                    wall_elapsed = max(
                        0.0,
                        (sample_observed_utc - wall_started_utc).total_seconds(),
                    )
                if bounded_trial:
                    cap_sample_sequence += 1
                    sample = {
                        "schema_version": 1,
                        "sequence": cap_sample_sequence,
                        "observed_utc": sample_observed_utc.isoformat(),
                        "elapsed_ms": round((time.monotonic() - started) * 1000),
                        "sample_duration_ms": round(
                            (time.monotonic() - sample_started) * 1000
                        ),
                        "agent_running": bool(state.get("Running")),
                        "filesystem_actions": filesystem_actions,
                        "agent_tool_calls": agent_tool_calls,
                    }
                    if dual_phase_trial:
                        sample.update(
                            {
                                "clock_phase": clock["clock_phase"],
                                "first_successful_observed_utc": clock[
                                    "first_successful_observed_utc"
                                ],
                                "qualified_entry_utc": clock["qualified_entry_utc"],
                                "pre_entry_elapsed_ms": round(
                                    clock["pre_entry_elapsed_seconds"] * 1000
                                ),
                                "post_entry_elapsed_ms": (
                                    round(clock["post_entry_elapsed_seconds"] * 1000)
                                    if clock["post_entry_elapsed_seconds"] is not None
                                    else None
                                ),
                                "total_wall_elapsed_ms": round(
                                    clock["total_wall_elapsed_seconds"] * 1000
                                ),
                            }
                        )
                    if mode == "support":
                        sample.update(
                            {
                                **support_proximity,
                                "agent_finished_utc": (
                                    support_finished_utc.isoformat()
                                    if support_finished_utc is not None
                                    else None
                                ),
                                "agent_exit_code": (
                                    state.get("ExitCode")
                                    if support_finished_utc is not None
                                    else None
                                ),
                            }
                        )
                    append_jsonl(cap_monitor_path, sample)
                if mode == "support":
                    finished_utc = support_finished_utc
                    candidates = support_cap_candidates(
                        decoy_events=decoy_events,
                        gateway_events=gateway_events,
                        agent_dir=agent_dir,
                        run_id=run_id,
                        pre_entry_started_utc=wall_started_utc,
                        observed_utc=sample_observed_utc,
                        max_pre_entry_wall_seconds=max_pre_entry_wall,
                        max_post_entry_wall_seconds=max_wall,
                        max_filesystem_actions=max_filesystem_actions,
                        max_agent_tool_calls=max_agent_tool_calls,
                        max_model_calls=max_model_calls,
                        max_model_tokens=max_model_tokens,
                        monitor_sequence=cap_sample_sequence,
                        agent_finished_utc=finished_utc,
                    )
                    selected = select_support_trigger(candidates)
                    if selected is not None:
                        if support_finished_utc is None:
                            latest_state = container_info(
                                project, "attacker-agent", env
                            )["state"]
                            if not latest_state.get("Running"):
                                # The next immediate sample will bind Docker's
                                # FinishedAt and rerun earliest-trigger selection.
                                continue
                        support_selected, support_coincident_reasons = selected
                        support_candidates_at_stop = candidates
                        reason = support_selected["reason"]
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                        if finished_utc is not None:
                            agent_exit_code = state.get("ExitCode")
                        if reason == "provider_rate_limit":
                            error = "Provider rate limit"
                        elif reason == "model_usage_missing":
                            error = "Gateway provider usage telemetry is missing"
                        break
                    time.sleep(2)
                    continue
                if mode == "connectivity" and model_ok and connected and command_seen:
                    reason = "connectivity_observed"
                    if mode == "controlled":
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                    break
                if rate_limited:
                    reason = "provider_rate_limit"
                    error = "Provider rate limit"
                    if mode == "controlled":
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                    break
                if bounded_trial and filesystem_actions >= max_filesystem_actions:
                    reason = "action_cap"
                    if mode == "controlled":
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                    break
                if agent_tool_calls >= max_agent_tool_calls:
                    reason = "tool_cap"
                    if mode == "controlled":
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                    break
                if any(
                    item.get("event_type") == "cap_reached" for item in gateway_events
                ):
                    reason = "model_cap"
                    if mode == "controlled":
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                    break
                if not state.get("Running"):
                    agent_exit_code = state.get("ExitCode")
                    finished_utc = container_finished_utc(state)
                    if mode == "controlled":
                        finish_clock = controlled_clock_evidence(
                            decoy_events,
                            pre_entry_started_utc=wall_started_utc,
                            observed_utc=finished_utc,
                            pre_entry_limit_seconds=max_pre_entry_wall,
                        )
                        manifest.update(finish_clock)
                        manifest["termination_observed_utc"] = finished_utc.isoformat()
                        if (
                            finish_clock["clock_phase"] == "pre_entry"
                            and finish_clock["pre_entry_elapsed_seconds"]
                            >= max_pre_entry_wall
                        ):
                            reason = "pre_entry_cap"
                        elif (
                            finish_clock["clock_phase"] == "post_entry"
                            and finish_clock["post_entry_elapsed_seconds"] >= max_wall
                        ):
                            reason = "wall_cap"
                    else:
                        finished_elapsed = max(
                            0.0,
                            (finished_utc - wall_started_utc).total_seconds(),
                        )
                        if finished_elapsed >= max_wall:
                            reason = "wall_cap"
                    break
                if mode == "controlled":
                    if (
                        clock["clock_phase"] == "pre_entry"
                        and clock["pre_entry_elapsed_seconds"] >= max_pre_entry_wall
                    ):
                        reason = "pre_entry_cap"
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                        break
                    if (
                        clock["clock_phase"] == "post_entry"
                        and clock["post_entry_elapsed_seconds"] >= max_wall
                    ):
                        reason = "wall_cap"
                        manifest["termination_observed_utc"] = (
                            sample_observed_utc.isoformat()
                        )
                        break
                elif wall_elapsed >= max_wall:
                    reason = "wall_cap"
                    break
                time.sleep(2)
            if reason != "agent_exit":
                compose_agent(
                    project,
                    ["stop", "-t", "5", "attacker-agent"],
                    env,
                    timeout=30,
                    check=False,
                )
            agent_exit_code = container_info(project, "attacker-agent", env)[
                "state"
            ].get("ExitCode")
            manifest["agent_stopped_utc"] = datetime.now(timezone.utc).isoformat()
        except Exception as exc:
            reason = "controller_error"
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if live_capture is not None:
                live_capture.stop()
            for service, filename in (
                ("filesystem-decoy-2b", "decoy-events.jsonl"),
                ("model-gateway", "gateway-events.jsonl"),
                ("attacker-agent", "agent-stdout.log"),
            ):
                try:
                    write_private(
                        run_dir / filename, service_events(project, service, env)
                    )
                except Exception:
                    pass
            compose_agent(
                project, ["down", "--remove-orphans"], env, timeout=90, check=False
            )
    if (
        mode != "support"
        and reason == "agent_exit"
        and (run_dir / "gateway-events.jsonl").exists()
    ):
        gateway_events = parsed_jsonl(
            (run_dir / "gateway-events.jsonl").read_text(encoding="utf-8")
        )
        if any(
            item.get("event_type")
            in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"}
            for item in gateway_events
        ):
            reason = "provider_rate_limit"
            error = "Provider rate limit"
    if bounded_trial and mode != "support" and reason == "agent_exit":
        failure = agent_trial_failure(agent_dir, run_id)
        turn_cap = agent_turn_cap_evidence(agent_dir, run_id)
        if turn_cap is not None and agent_exit_code in {None, 0}:
            reason = "agent_turn_cap"
            manifest["agent_terminal"] = turn_cap
        elif failure is not None or (agent_exit_code not in {None, 0}):
            reason = "agent_failure"
            error = failure or f"Attacker agent exited with code {agent_exit_code}"
    elif mode == "support" and reason == "agent_exit":
        failure = agent_trial_failure(agent_dir, run_id)
        if failure is not None or agent_exit_code not in {None, 0}:
            reason = "agent_failure"
            error = failure or f"Attacker agent exited with code {agent_exit_code}"
            if support_selected is not None:
                support_selected = {
                    **support_selected,
                    "reason": "agent_failure",
                    "observed_count_status": "failed_agent_settlement",
                }
                support_coincident_reasons = ["agent_failure"]
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    if "agent_stopped_utc" not in manifest and agent_exit_code is not None:
        manifest["agent_stopped_utc"] = manifest["finished_utc"]
    manifest["termination_reason"] = reason
    manifest["agent_exit_code"] = agent_exit_code
    observed_agent_tool_calls = count_tool_calls(agent_dir, run_id)
    manifest["observed_agent_tool_calls"] = observed_agent_tool_calls
    if bounded_trial:
        archived_decoy_events = (
            parsed_jsonl((run_dir / "decoy-events.jsonl").read_text(encoding="utf-8"))
            if (run_dir / "decoy-events.jsonl").exists()
            else []
        )
        archived_gateway_events = (
            parsed_jsonl((run_dir / "gateway-events.jsonl").read_text(encoding="utf-8"))
            if (run_dir / "gateway-events.jsonl").exists()
            else []
        )
        monitor_samples = (
            parsed_jsonl(cap_monitor_path.read_text(encoding="utf-8"))
            if cap_monitor_path.exists()
            else []
        )
        manifest["cap_policy"] = contract["cap_policy"]
        if mode == "support" and support_selected is not None:
            selected_exit = (
                _event_utc(support_selected["trigger_utc"], "Support agent exit")
                if support_selected["reason"] in {"agent_exit", "agent_failure"}
                else None
            )
            final_candidates = support_cap_candidates(
                decoy_events=archived_decoy_events,
                gateway_events=archived_gateway_events,
                agent_dir=agent_dir,
                run_id=run_id,
                pre_entry_started_utc=wall_started_utc,
                observed_utc=_event_utc(
                    manifest["termination_observed_utc"],
                    "Support termination observation",
                ),
                max_pre_entry_wall_seconds=max_pre_entry_wall,
                max_post_entry_wall_seconds=max_wall,
                max_filesystem_actions=max_filesystem_actions,
                max_agent_tool_calls=max_agent_tool_calls,
                max_model_calls=max_model_calls,
                max_model_tokens=max_model_tokens,
                monitor_sequence=cap_sample_sequence,
                agent_finished_utc=selected_exit,
            )
            final_selected = select_support_trigger(final_candidates)
            if support_selected["reason"] != "agent_failure":
                if final_selected is None or final_selected[0]["reason"] != reason:
                    reason = "controller_error"
                    manifest["termination_reason"] = reason
                    error = "Support terminal state did not reproduce after archival"
                    manifest["error"] = error
                    support_selected = None
                else:
                    support_selected, support_coincident_reasons = final_selected
            support_candidates_at_stop = final_candidates
        support_snapshot = None
        if mode == "support" and monitor_samples:
            final_sample = monitor_samples[-1]
            support_snapshot = {
                key: final_sample[key]
                for key in (
                    "model_calls",
                    "model_tokens",
                    "agent_decisions",
                    "supervisor_episodes",
                    "executor_episodes",
                    "max_observed_supervisor_turns",
                    "max_observed_executor_turns",
                    "provider_turn_count_status",
                    "policy_exhaustion_count",
                )
            }
        manifest["cap_evidence"] = build_cap_evidence(
            archived_decoy_events,
            observed_agent_tool_calls=observed_agent_tool_calls,
            max_agent_tool_calls=max_agent_tool_calls,
            max_filesystem_actions=max_filesystem_actions,
            monitor_samples=monitor_samples,
            support_snapshot=support_snapshot,
            agent_tool_call_enforcement=(
                "controller_observational_fuse"
                if mode == "support"
                else "observational_watchdog"
            ),
        )
        if mode == "support" and support_selected is not None:
            local_exhaustions = collect_agent_policy_exhaustions(agent_dir, run_id)
            manifest["policy_exhaustions"] = build_support_policy_exhaustions(
                support_candidates_at_stop,
                local_exhaustions,
                selected=support_selected,
                qualified_entry_utc=manifest.get("qualified_entry_utc"),
                observed_utc=manifest["termination_observed_utc"],
            )
            if support_selected["reason"] == reason:
                manifest["termination_evidence"] = build_support_termination_evidence(
                    run_dir,
                    support_selected,
                    support_coincident_reasons,
                    observed_utc=manifest["termination_observed_utc"],
                    settlement_utc=manifest.get("agent_stopped_utc")
                    or manifest["finished_utc"],
                )
    if mode == "connectivity" and reason != "connectivity_observed" and error is None:
        error = "connectivity_not_observed"
    manifest["error"] = error
    inventory = agent_artifact_inventory(agent_dir, run_id)
    write_private(
        run_dir / "agent-artifacts.json",
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
    )
    manifest["artifact_sha256"] = {
        name: sha(run_dir / name)
        for name in (
            "compose.resolved.yaml",
            "decoy-events.jsonl",
            "gateway-events.jsonl",
            "agent-stdout.log",
            "filesystem-profile.json",
            "cap-monitor.jsonl",
            "agent-artifacts.json",
        )
        if (run_dir / name).exists()
    }
    write_private(
        run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    result = {"manifest": manifest, "run_dir": str(run_dir)}
    if bounded_trial:
        try:
            result["score"] = score_events(
                parsed_jsonl(
                    (run_dir / "decoy-events.jsonl").read_text(encoding="utf-8")
                ),
                manifest,
                gateway_events=parsed_jsonl(
                    (run_dir / "gateway-events.jsonl").read_text(encoding="utf-8")
                ),
                agent_trace_events=agent_trace_events(agent_dir, run_id),
            )
        except Exception as exc:
            result["score"] = {
                "schema_version": 1,
                "protocol": manifest["protocol"],
                "scoring_error": f"{type(exc).__name__}: {exc}",
            }
    write_private(
        run_dir / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    return result


def run_connectivity(
    *,
    build: bool = True,
    seed: str = "fixture-seed",
    run_id: str | None = None,
    provider: str = "ollama",
) -> dict[str, Any]:
    return _run_agent(
        "connectivity",
        "B0",
        build=build,
        seed=seed,
        run_id=run_id,
        provider=provider,
    )


def run_pilot(
    arm: str,
    *,
    assignment: dict[str, Any],
    frozen_fingerprint: dict[str, Any],
    run_id: str | None = None,
) -> dict[str, Any]:
    contract = pilot_contract()
    return _run_agent(
        "pilot",
        arm,
        build=False,
        seed=contract["seed"],
        run_id=run_id,
        provider=contract["provider"],
        assignment=assignment,
        frozen_fingerprint=frozen_fingerprint,
    )


def run_controlled(
    arm: str,
    *,
    assignment: dict[str, Any],
    frozen_fingerprint: dict[str, Any],
    run_id: str | None = None,
) -> dict[str, Any]:
    contract = controlled_contract()
    return _run_agent(
        "controlled",
        arm,
        build=False,
        seed=contract["seed"],
        run_id=run_id,
        provider=contract["provider"],
        assignment=assignment,
        frozen_fingerprint=frozen_fingerprint,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode", choices=("deterministic", "connectivity"), default="deterministic"
    )
    parser.add_argument("--arm", choices=("B0", "B1", "B2", "B3"), default="B0")
    parser.add_argument("--seed", default="fixture-seed")
    parser.add_argument("--branching-factor", type=int, default=4)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--provider", choices=("zai", "ollama"), default="ollama")
    parser.add_argument("--run-id", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.mode == "connectivity" and args.arm != "B0":
        parser.error("Fixture connectivity mode uses B0 only")
    result = (
        run_connectivity(
            build=not args.no_build,
            seed=args.seed,
            run_id=args.run_id,
            provider=args.provider,
        )
        if args.mode == "connectivity"
        else run_deterministic(
            args.arm,
            build=not args.no_build,
            seed=args.seed,
            branching_factor=args.branching_factor,
            run_id=args.run_id,
        )
    )
    print(
        json.dumps(
            {
                "run_dir": result["run_dir"],
                "termination_reason": result["manifest"]["termination_reason"],
                "error": result["manifest"]["error"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if result["manifest"]["error"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
