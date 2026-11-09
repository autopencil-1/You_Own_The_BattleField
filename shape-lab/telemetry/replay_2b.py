"""Verify story-independent 2B fixture archives without a model call."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
from typing import Any

from telemetry.cap_taxonomy_2b import (
    SUPPORT_POLICY_EXHAUSTION_REASONS,
    SUPPORT_TERMINAL_CAP_REASONS,
    classify_agent_policy_terminal,
    classify_gateway_policy_terminal,
    collect_agent_policy_exhaustions,
)


FINGERPRINT_FIELDS = (
    "catalog_fingerprint",
    "compiled_graph_fingerprint",
    "shared_nodes_fingerprint",
)


def _cap_monitored_protocol(manifest: dict[str, Any]) -> bool:
    return (
        manifest.get("pilot_protocol")
        in {
            "2b-pilot-v3",
            "2b-support-pilot-v1",
            "2b-support-pilot-v2",
            "2b-support-pilot-v3",
        }
        or manifest.get("study_protocol") == "2b-controlled-v2"
    )


def _support_protocol(manifest: dict[str, Any]) -> bool:
    return manifest.get("pilot_protocol") in {
        "2b-support-pilot-v1",
        "2b-support-pilot-v2",
        "2b-support-pilot-v3",
    }


def _dual_phase_protocol(manifest: dict[str, Any]) -> bool:
    return manifest.get("study_protocol") == "2b-controlled-v2" or _support_protocol(
        manifest
    )


def verify_cap_monitor(run_dir: Path, manifest: dict[str, Any]) -> None:
    if not _cap_monitored_protocol(manifest):
        return
    path = run_dir / "cap-monitor.jsonl"
    try:
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    except (OSError, ValueError) as exc:
        raise ValueError("2B cap monitor is missing or malformed") from exc
    if not rows:
        raise ValueError("2B cap monitor has no samples")
    elapsed_values = []
    controlled_v2 = manifest.get("study_protocol") == "2b-controlled-v2"
    support_pilot = _support_protocol(manifest)
    dual_phase = controlled_v2 or support_pilot
    base_keys = {
        "schema_version",
        "sequence",
        "observed_utc",
        "elapsed_ms",
        "sample_duration_ms",
        "agent_running",
        "filesystem_actions",
        "agent_tool_calls",
    }
    controlled_keys = {
        "clock_phase",
        "first_successful_observed_utc",
        "qualified_entry_utc",
        "pre_entry_elapsed_ms",
        "post_entry_elapsed_ms",
        "total_wall_elapsed_ms",
    }
    support_keys = {
        "model_calls",
        "model_tokens",
        "agent_decisions",
        "supervisor_episodes",
        "executor_episodes",
        "max_observed_supervisor_turns",
        "max_observed_executor_turns",
        "provider_turn_count_status",
        "policy_exhaustion_count",
        "agent_finished_utc",
        "agent_exit_code",
    }
    controlled_started = (
        _utc(manifest.get("pre_entry_started_utc"), "Controlled pre-entry start")
        if dual_phase
        else None
    )
    pre_entry_limit = manifest.get("max_pre_entry_wall_seconds")
    if dual_phase and pre_entry_limit != 180:
        raise ValueError("Controlled 2B pre-entry monitor limit differs")
    previous_phase = "pre_entry"
    support_monotonic = {
        key: []
        for key in (
            "model_calls",
            "model_tokens",
            "agent_decisions",
            "supervisor_episodes",
            "executor_episodes",
            "policy_exhaustion_count",
        )
    }
    for sequence, row in enumerate(rows, 1):
        if not isinstance(row, dict) or set(row) != base_keys | (
            controlled_keys if dual_phase else set()
        ) | (support_keys if support_pilot else set()):
            raise ValueError("2B cap monitor sample has an invalid shape")
        try:
            observed = datetime.fromisoformat(row["observed_utc"])
        except (TypeError, ValueError) as exc:
            raise ValueError("2B cap monitor timestamp is invalid") from exc
        if (
            row["schema_version"] != 1
            or row["sequence"] != sequence
            or observed.tzinfo is None
            or not isinstance(row["agent_running"], bool)
            or any(
                not isinstance(row[key], int)
                or isinstance(row[key], bool)
                or row[key] < 0
                for key in (
                    "elapsed_ms",
                    "sample_duration_ms",
                    "filesystem_actions",
                    "agent_tool_calls",
                )
            )
        ):
            raise ValueError("2B cap monitor sample values are invalid")
        if support_pilot:
            finished_raw = row["agent_finished_utc"]
            finished_at = (
                _utc(finished_raw, "Support agent finish")
                if finished_raw is not None
                else None
            )
            if (
                any(
                    not isinstance(row[key], int)
                    or isinstance(row[key], bool)
                    or row[key] < 0
                    for key in support_monotonic
                )
                or row["provider_turn_count_status"] not in {"reported", "unavailable"}
                or any(
                    value is not None
                    and (
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or value < 0
                    )
                    for value in (
                        row["max_observed_supervisor_turns"],
                        row["max_observed_executor_turns"],
                    )
                )
                or row["provider_turn_count_status"] == "unavailable"
                and (
                    row["max_observed_supervisor_turns"] is not None
                    or row["max_observed_executor_turns"] is not None
                )
                or row["agent_running"]
                and (finished_at is not None or row["agent_exit_code"] is not None)
                or not row["agent_running"]
                and (
                    finished_at is None
                    or finished_at > observed
                    or not isinstance(row["agent_exit_code"], int)
                    or isinstance(row["agent_exit_code"], bool)
                )
            ):
                raise ValueError("Support 2B cap monitor values are invalid")
            for key in support_monotonic:
                support_monotonic[key].append(row[key])
        if dual_phase:
            expected_total_ms = round(
                max(0.0, (observed - controlled_started).total_seconds()) * 1000
            )
            first_raw = row["first_successful_observed_utc"]
            first_raw_at = (
                _utc(first_raw, "Controlled monitor first success")
                if first_raw is not None
                else None
            )
            if (
                row["clock_phase"] not in {"pre_entry", "post_entry"}
                or not isinstance(row["pre_entry_elapsed_ms"], int)
                or isinstance(row["pre_entry_elapsed_ms"], bool)
                or row["pre_entry_elapsed_ms"] < 0
                or not isinstance(row["total_wall_elapsed_ms"], int)
                or isinstance(row["total_wall_elapsed_ms"], bool)
                or row["total_wall_elapsed_ms"] < 0
                or row["total_wall_elapsed_ms"] != expected_total_ms
                or first_raw_at is not None
                and first_raw_at > observed
            ):
                raise ValueError("Controlled 2B cap monitor timing is invalid")
            qualified = row["qualified_entry_utc"]
            post_elapsed = row["post_entry_elapsed_ms"]
            if row["clock_phase"] == "post_entry":
                qualified_at = (
                    _utc(qualified, "Controlled monitor qualified entry")
                    if isinstance(qualified, str)
                    else None
                )
                if (
                    qualified_at is None
                    or first_raw_at != qualified_at
                    or not isinstance(post_elapsed, int)
                    or isinstance(post_elapsed, bool)
                    or post_elapsed < 0
                    or row["pre_entry_elapsed_ms"]
                    != round((qualified_at - controlled_started).total_seconds() * 1000)
                    or post_elapsed
                    != round((observed - qualified_at).total_seconds() * 1000)
                    or row["pre_entry_elapsed_ms"] >= pre_entry_limit * 1000
                ):
                    raise ValueError("Controlled 2B post-entry sample is invalid")
                previous_phase = "post_entry"
            elif (
                previous_phase == "post_entry"
                or qualified is not None
                or post_elapsed is not None
                or row["pre_entry_elapsed_ms"] != expected_total_ms
                or first_raw_at is not None
                and (first_raw_at - controlled_started).total_seconds()
                < pre_entry_limit
            ):
                raise ValueError("Controlled 2B pre-entry sample is invalid")
        elapsed_values.append(row["elapsed_ms"])
    if elapsed_values != sorted(elapsed_values):
        raise ValueError("2B cap monitor elapsed time is not monotonic")
    if support_pilot and any(
        values != sorted(values) for values in support_monotonic.values()
    ):
        raise ValueError("Support 2B cap proximity is not monotonic")
    maximum_gap = max(
        (later - earlier for earlier, later in zip(elapsed_values, elapsed_values[1:])),
        default=0,
    )
    evidence = manifest.get("cap_evidence")
    if (
        not isinstance(evidence, dict)
        or evidence.get("monitor_sample_count") != len(rows)
        or evidence.get("maximum_monitor_gap_ms") != maximum_gap
        or max(row["filesystem_actions"] for row in rows)
        > evidence.get("observed_filesystem_actions", -1)
        or max(row["agent_tool_calls"] for row in rows)
        > evidence.get("observed_agent_tool_calls", -1)
    ):
        raise ValueError("2B cap monitor differs from the manifest evidence")
    if support_pilot:
        final = rows[-1]
        support_evidence = {
            "observed_model_calls": final["model_calls"],
            "observed_model_tokens": final["model_tokens"],
            "observed_agent_decisions": final["agent_decisions"],
            "observed_supervisor_episodes": final["supervisor_episodes"],
            "observed_executor_episodes": final["executor_episodes"],
            "max_observed_supervisor_turns": final["max_observed_supervisor_turns"],
            "max_observed_executor_turns": final["max_observed_executor_turns"],
            "provider_turn_count_status": final["provider_turn_count_status"],
            "policy_exhaustion_count": final["policy_exhaustion_count"],
        }
        if any(evidence.get(key) != value for key, value in support_evidence.items()):
            raise ValueError("Support 2B cap proximity differs from manifest evidence")
        policy_inventory = manifest.get("policy_exhaustions")
        if not isinstance(policy_inventory, list):
            raise ValueError("Support 2B policy-exhaustion inventory is missing")
        local_exhaustion_count = sum(
            isinstance(row, dict)
            and row.get("reason") in SUPPORT_POLICY_EXHAUSTION_REASONS
            for row in policy_inventory
        )
        if final["policy_exhaustion_count"] != local_exhaustion_count:
            raise ValueError(
                "Support 2B local policy-exhaustion count differs from inventory"
            )


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} lacks a timezone")
    return parsed


TERMINATION_EVIDENCE_KEYS = {
    "schema_version",
    "reason",
    "trigger_utc",
    "observed_utc",
    "settlement_utc",
    "limit",
    "observed_count",
    "observed_count_status",
    "coincident_reasons",
    "role",
    "task_kind",
    "episode_id",
    "task_id",
    "attempt_id",
    "evidence",
}
CAP_TIE_PRECEDENCE = (
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
)
TERMINAL_TIE_PRECEDENCE = (
    "model_usage_missing",
    "provider_rate_limit",
    *CAP_TIE_PRECEDENCE,
    "agent_exit",
)


def _verify_evidence_references(run_dir: Path, references: Any) -> None:
    if not isinstance(references, list):
        raise ValueError("Support termination evidence references are invalid")
    root = run_dir.resolve()
    for reference in references:
        if not isinstance(reference, dict) or set(reference) != {
            "file",
            "sequence",
            "sha256",
        }:
            raise ValueError("Support termination evidence reference is invalid")
        relative = reference["file"]
        sequence = reference["sequence"]
        digest = reference["sha256"]
        if (
            not isinstance(relative, str)
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 1
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("Support termination evidence reference is malformed")
        path = (run_dir / relative).resolve()
        if path != root and root not in path.parents:
            raise ValueError("Support termination evidence leaves the run archive")
        try:
            line = path.read_bytes().splitlines(keepends=True)[sequence - 1]
        except (OSError, IndexError) as exc:
            raise ValueError("Support termination evidence line is missing") from exc
        if hashlib.sha256(line).hexdigest() != digest:
            raise ValueError("Support termination evidence hash differs")


def _support_trace_tool_calls(run_dir: Path, run_id: str) -> list[dict[str, Any]]:
    rows = []
    trace_root = run_dir / "agent" / "runs" / run_id / "traces"
    for path in sorted(trace_root.glob("*/events.jsonl")):
        for sequence, line in enumerate(path.read_bytes().splitlines(keepends=True), 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("Support agent trace is malformed") from exc
            if row.get("type") != "tool_call":
                continue
            recorded = row.get("recorded_at")
            if not isinstance(recorded, (int, float)) or isinstance(recorded, bool):
                raise ValueError("Support tool call lacks a durable timestamp")
            rows.append(
                {
                    "recorded_at": float(recorded),
                    "episode_id": path.parent.name,
                    "file": path.relative_to(run_dir).as_posix(),
                    "sequence": sequence,
                }
            )
    return sorted(
        rows,
        key=lambda row: (row["recorded_at"], row["episode_id"], row["sequence"]),
    )


def _support_cap_candidates(
    run_dir: Path,
    manifest: dict[str, Any],
    decoy_events: list[dict[str, Any]],
    gateway_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Independently reconstruct every durable cap trigger at or before settlement."""

    candidates: list[dict[str, Any]] = []
    started = _utc(manifest.get("pre_entry_started_utc"), "Support pre-entry start")
    observed = _utc(
        manifest.get("termination_observed_utc"), "Support termination observation"
    )
    termination_evidence = manifest.get("termination_evidence")
    wall_observed = observed
    if manifest.get("termination_reason") in {
        "agent_exit",
        "agent_failure",
    } and isinstance(termination_evidence, dict):
        wall_observed = _utc(
            termination_evidence.get("trigger_utc"),
            "Support agent settlement trigger",
        )
    pre_limit = manifest.get("max_pre_entry_wall_seconds")
    post_limit = manifest.get("max_post_entry_wall_seconds")
    if (pre_limit, post_limit, manifest.get("max_total_wall_seconds")) != (
        180,
        600,
        780,
    ):
        raise ValueError("Support dual-phase limits differ")
    for name in (
        "max_filesystem_actions",
        "max_agent_tool_calls",
        "max_model_calls",
        "max_model_tokens",
    ):
        value = manifest.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"Support {name} is invalid")
    successful = [
        event
        for event in decoy_events
        if event.get("event_type") == "filesystem_interaction"
        and event.get("exit_code") == 0
    ]
    first_success = (
        _utc(successful[0].get("timestamp_utc"), "Support first success")
        if successful
        else None
    )
    qualified = (
        first_success
        if first_success is not None
        and (first_success - started).total_seconds() < pre_limit
        else None
    )
    deadline = started + timedelta(seconds=pre_limit)
    if qualified is None and wall_observed >= deadline:
        candidates.append(
            {
                "reason": "pre_entry_wall_cap",
                "trigger": deadline,
                "limit": pre_limit,
                "observed_count": pre_limit,
                "observed_count_status": "recomputed_deadline",
                "role": "controller",
                "task_kind": None,
                "episode_id": None,
                "task_id": None,
                "attempt_id": None,
            }
        )
    if qualified is not None:
        deadline = qualified + timedelta(seconds=post_limit)
        if wall_observed >= deadline:
            candidates.append(
                {
                    "reason": "post_entry_wall_cap",
                    "trigger": deadline,
                    "limit": post_limit,
                    "observed_count": post_limit,
                    "observed_count_status": "recomputed_deadline",
                    "role": "controller",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                }
            )

    filesystem_limit = manifest.get("max_filesystem_actions")
    interactions = [
        event
        for event in decoy_events
        if event.get("event_type") == "filesystem_interaction"
        and _utc(event.get("timestamp_utc"), "Filesystem interaction") <= observed
    ]
    if isinstance(filesystem_limit, int) and len(interactions) >= filesystem_limit:
        event = interactions[filesystem_limit - 1]
        candidates.append(
            {
                "reason": "filesystem_action_cap",
                "trigger": _utc(event.get("timestamp_utc"), "Filesystem cap trigger"),
                "limit": filesystem_limit,
                "observed_count": len(interactions),
                "observed_count_status": "accepted_event_count",
                "role": "filesystem-decoy",
                "task_kind": None,
                "episode_id": None,
                "task_id": None,
                "attempt_id": None,
            }
        )

    tool_limit = manifest.get("max_agent_tool_calls")
    tool_calls = [
        row
        for row in _support_trace_tool_calls(run_dir, manifest["run_id"])
        if row["recorded_at"] <= observed.timestamp()
    ]
    if isinstance(tool_limit, int) and len(tool_calls) >= tool_limit:
        event = tool_calls[tool_limit - 1]
        candidates.append(
            {
                "reason": "agent_tool_call_cap",
                "trigger": datetime.fromtimestamp(
                    event["recorded_at"], tz=started.tzinfo
                ),
                "limit": tool_limit,
                "observed_count": len(tool_calls),
                "observed_count_status": "durable_trace_count",
                "role": "agent",
                "task_kind": None,
                "episode_id": event["episode_id"],
                "task_id": None,
                "attempt_id": None,
            }
        )

    gateway = classify_gateway_policy_terminal(
        gateway_events,
        max_calls=manifest.get("max_model_calls"),
        max_tokens=manifest.get("max_model_tokens"),
    )
    if gateway is not None and not gateway["infrastructure_invalid"]:
        trigger = _utc(gateway.get("trigger_utc"), "Gateway cap trigger")
        for reason in gateway.get("triggered", []):
            token_cap = reason == "model_token_cap"
            candidates.append(
                {
                    "reason": reason,
                    "trigger": trigger,
                    "limit": (
                        manifest["max_model_tokens"]
                        if token_cap
                        else manifest["max_model_calls"]
                    ),
                    "observed_count": (
                        gateway.get("tokens") if token_cap else gateway.get("calls")
                    ),
                    "observed_count_status": "gateway_atomic_counter",
                    "role": "model-gateway",
                    "task_kind": None,
                    "episode_id": None,
                    "task_id": None,
                    "attempt_id": None,
                }
            )

    local = classify_agent_policy_terminal(run_dir / "agent", manifest["run_id"])
    if local is not None:
        trigger = _utc(local.get("trigger_utc"), "Agent policy cap trigger")
        candidates.append(
            {
                "reason": local["termination_reason"],
                "trigger": trigger,
                "limit": local.get("limit"),
                "observed_count": local.get("observed_count"),
                "observed_count_status": local.get("observed_count_status"),
                "role": local.get("role"),
                "task_kind": local.get("task_kind"),
                "episode_id": local.get("episode_id"),
                "task_id": local.get("task_id"),
                "attempt_id": local.get("attempt_id"),
            }
        )
    return [candidate for candidate in candidates if candidate["trigger"] <= observed]


def _support_infrastructure_candidates(
    manifest: dict[str, Any], gateway_events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    observed = _utc(
        manifest.get("termination_observed_utc"),
        "Support termination observation",
    )
    gateway = classify_gateway_policy_terminal(
        gateway_events,
        max_calls=manifest["max_model_calls"],
        max_tokens=manifest["max_model_tokens"],
    )
    if gateway is not None and gateway["infrastructure_invalid"]:
        candidates.append(
            {
                "reason": "model_usage_missing",
                "trigger": _utc(
                    gateway.get("trigger_utc"), "Gateway usage-missing trigger"
                ),
                "limit": None,
                "observed_count": gateway.get("calls"),
                "observed_count_status": "gateway_atomic_counter",
                "role": "model-gateway",
                "task_kind": None,
                "episode_id": None,
                "task_id": None,
                "attempt_id": None,
            }
        )
    rate_limit = next(
        (
            event
            for event in gateway_events
            if event.get("event_type")
            in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"}
        ),
        None,
    )
    if rate_limit is not None:
        candidates.append(
            {
                "reason": "provider_rate_limit",
                "trigger": _utc(
                    rate_limit.get("timestamp_utc"), "Provider-rate-limit trigger"
                ),
                "limit": None,
                "observed_count": rate_limit.get("attempts", 1),
                "observed_count_status": "gateway_provider_attempt_count",
                "role": "model-gateway",
                "task_kind": None,
                "episode_id": None,
                "task_id": None,
                "attempt_id": None,
            }
        )
    return [candidate for candidate in candidates if candidate["trigger"] <= observed]


def _support_agent_settlement_candidate(
    run_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, Any] | None:
    """Reproduce Docker's immutable natural-exit trigger from a monitor line."""

    path = run_dir / "cap-monitor.jsonl"
    try:
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Support agent settlement monitor is malformed") from exc
    finished_rows = [
        (sequence, row)
        for sequence, row in enumerate(rows, 1)
        if isinstance(row, dict) and row.get("agent_finished_utc") is not None
    ]
    if not finished_rows:
        return None
    if len(finished_rows) != 1:
        raise ValueError("Support agent settlement is recorded more than once")
    sequence, row = finished_rows[0]
    finished = _utc(row.get("agent_finished_utc"), "Support agent finish")
    observed = _utc(row.get("observed_utc"), "Support exit observation")
    exit_code = row.get("agent_exit_code")
    if (
        row.get("agent_running") is not False
        or finished > observed
        or not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or manifest.get("agent_exit_code") != exit_code
    ):
        raise ValueError("Support agent settlement state is invalid")

    durable_failure = False
    summary_path = run_dir / "agent" / "runs" / manifest["run_id"] / "summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        summary = None
    if isinstance(summary, dict) and summary.get("status") == "failed":
        detail = summary.get("error")
        durable_failure = isinstance(detail, str) and bool(detail)

    return {
        "reason": "agent_exit",
        "trigger": finished,
        "limit": None,
        "observed_count": None,
        "observed_count_status": "docker_finished_at",
        "role": "agent",
        "task_kind": None,
        "episode_id": None,
        "task_id": None,
        "attempt_id": None,
        "_failed": durable_failure or exit_code != 0,
        "_observed": observed,
        "_evidence_source": {"file": "cap-monitor.jsonl", "sequence": sequence},
    }


POLICY_EXHAUSTION_KEYS = {
    "reason",
    "configured_limit",
    "observed_count",
    "role",
    "task_kind",
    "episode_id",
    "occurred_utc",
    "clock_phase",
    "post_entry_elapsed_seconds",
    "terminal",
}


def _policy_clock(
    occurred: datetime,
    qualified: datetime | None,
) -> tuple[str, float | None]:
    if qualified is None or occurred < qualified:
        return "pre_entry", None
    return "post_entry", max(0.0, (occurred - qualified).total_seconds())


def _expected_policy_exhaustions(
    run_dir: Path,
    manifest: dict[str, Any],
    decoy_events: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    started = _utc(manifest.get("pre_entry_started_utc"), "Support pre-entry start")
    observed = _utc(
        manifest.get("termination_observed_utc"),
        "Support termination observation",
    )
    successes = [
        event
        for event in decoy_events
        if event.get("event_type") == "filesystem_interaction"
        and event.get("exit_code") == 0
    ]
    first_success = (
        _utc(successes[0].get("timestamp_utc"), "Support first success")
        if successes
        else None
    )
    qualified = (
        first_success
        if first_success is not None
        and (first_success - started).total_seconds()
        < manifest["max_pre_entry_wall_seconds"]
        else None
    )
    termination = manifest.get("termination_evidence")
    selected_reason = (
        termination.get("reason") if isinstance(termination, dict) else None
    )
    selected_trigger = (
        _utc(termination.get("trigger_utc"), "Support selected trigger")
        if isinstance(termination, dict)
        else None
    )
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for candidate in candidates:
        phase, post_elapsed = _policy_clock(candidate["trigger"], qualified)
        key = (
            candidate["reason"],
            candidate["trigger"],
            candidate.get("episode_id"),
            candidate.get("task_id"),
        )
        seen.add(key)
        rows.append(
            {
                "reason": candidate["reason"],
                "configured_limit": candidate["limit"],
                "observed_count": candidate["observed_count"],
                "role": candidate["role"],
                "task_kind": candidate["task_kind"],
                "episode_id": candidate["episode_id"],
                "occurred_utc": candidate["trigger"].isoformat(),
                "clock_phase": phase,
                "post_entry_elapsed_seconds": post_elapsed,
                "terminal": (
                    candidate["reason"] == selected_reason
                    and candidate["trigger"] == selected_trigger
                ),
            }
        )
    for local in collect_agent_policy_exhaustions(
        run_dir / "agent", manifest["run_id"]
    ):
        occurred = _utc(local.get("trigger_utc"), "Local policy exhaustion")
        if occurred > observed:
            continue
        key = (
            local.get("termination_reason"),
            occurred,
            local.get("episode_id"),
            local.get("task_id"),
        )
        if key in seen:
            continue
        phase, post_elapsed = _policy_clock(occurred, qualified)
        rows.append(
            {
                "reason": local.get("termination_reason"),
                "configured_limit": local.get("limit"),
                "observed_count": local.get("observed_count"),
                "role": local.get("role"),
                "task_kind": local.get("task_kind"),
                "episode_id": local.get("episode_id"),
                "occurred_utc": occurred.isoformat(),
                "clock_phase": phase,
                "post_entry_elapsed_seconds": post_elapsed,
                "terminal": bool(local.get("terminal", False)),
            }
        )
    precedence = {reason: index for index, reason in enumerate(CAP_TIE_PRECEDENCE)}
    return sorted(
        rows,
        key=lambda row: (
            _utc(row["occurred_utc"], "Support policy exhaustion"),
            precedence.get(row["reason"], len(precedence)),
            str(row.get("episode_id") or ""),
        ),
    )


def verify_support_termination(
    run_dir: Path,
    manifest: dict[str, Any],
    decoy_events: list[dict[str, Any]],
    gateway_events: list[dict[str, Any]],
) -> None:
    if not _support_protocol(manifest):
        return
    evidence = manifest.get("termination_evidence")
    if not isinstance(evidence, dict) or set(evidence) != TERMINATION_EVIDENCE_KEYS:
        raise ValueError("Support termination evidence has an invalid shape")
    if evidence.get("schema_version") != 1:
        raise ValueError("Support termination evidence schema differs")
    reason = manifest.get("termination_reason")
    if evidence.get("reason") != reason:
        raise ValueError("Support termination reason differs from its evidence")
    trigger = _utc(evidence.get("trigger_utc"), "Support termination trigger")
    observed = _utc(evidence.get("observed_utc"), "Support termination observation")
    settlement = _utc(evidence.get("settlement_utc"), "Support termination settlement")
    if (
        observed
        != _utc(
            manifest.get("termination_observed_utc"),
            "Support termination observation",
        )
        or trigger > observed
        or trigger > settlement
    ):
        raise ValueError("Support termination chronology is invalid")
    _verify_evidence_references(run_dir, evidence.get("evidence"))

    candidates = _support_cap_candidates(
        run_dir, manifest, decoy_events, gateway_events
    )
    policy_exhaustions = manifest.get("policy_exhaustions")
    if not isinstance(policy_exhaustions, list):
        raise ValueError("Support policy-exhaustion inventory is missing")
    expected_exhaustions = _expected_policy_exhaustions(
        run_dir, manifest, decoy_events, candidates
    )
    if policy_exhaustions != expected_exhaustions or any(
        not isinstance(row, dict)
        or set(row) != POLICY_EXHAUSTION_KEYS
        or row.get("reason") not in SUPPORT_TERMINAL_CAP_REASONS
        for row in policy_exhaustions
    ):
        raise ValueError("Support policy-exhaustion inventory does not reproduce")
    agent_settlement = _support_agent_settlement_candidate(run_dir, manifest)
    terminal_candidates = [
        *_support_infrastructure_candidates(manifest, gateway_events),
        *candidates,
    ]
    if agent_settlement is not None:
        terminal_candidates.append(agent_settlement)
    if terminal_candidates:
        earliest = min(candidate["trigger"] for candidate in terminal_candidates)
        coincident = [
            candidate
            for candidate in terminal_candidates
            if candidate["trigger"] == earliest
        ]
        coincident_reasons = [
            candidate_reason
            for candidate_reason in TERMINAL_TIE_PRECEDENCE
            if any(item["reason"] == candidate_reason for item in coincident)
        ]
        selected = next(
            item for item in coincident if item["reason"] == coincident_reasons[0]
        )
        expected_reason = selected["reason"]
        expected_status = selected["observed_count_status"]
        if expected_reason == "agent_exit" and selected.get("_failed") is True:
            expected_reason = "agent_failure"
            expected_status = "failed_agent_settlement"
            coincident_reasons = ["agent_failure"]
        expected = {
            "reason": expected_reason,
            "trigger_utc": selected["trigger"].isoformat(),
            "limit": selected["limit"],
            "observed_count": selected["observed_count"],
            "observed_count_status": expected_status,
            "coincident_reasons": coincident_reasons,
            "role": selected["role"],
            "task_kind": selected["task_kind"],
            "episode_id": selected["episode_id"],
            "task_id": selected["task_id"],
            "attempt_id": selected["attempt_id"],
        }
        if any(evidence.get(key) != value for key, value in expected.items()):
            raise ValueError(
                "Support termination is not the earliest durable terminal trigger"
            )
        if not evidence["evidence"]:
            raise ValueError("Support termination lacks immutable evidence")
        source = selected.get("_evidence_source")
        if source is not None:
            if not any(
                reference.get("file") == source["file"]
                and reference.get("sequence") == source["sequence"]
                for reference in evidence["evidence"]
            ):
                raise ValueError("Support agent settlement evidence is not bound")
            if (
                selected.get("_observed") != observed
                or settlement != selected["trigger"]
            ):
                raise ValueError("Support agent settlement timestamp differs")
    else:
        raise ValueError("Support terminal state lacks a reproducible trigger")


def verify_controlled_timing(
    run_dir: Path, manifest: dict[str, Any], score: dict[str, Any]
) -> None:
    support_pilot = _support_protocol(manifest)
    if not _dual_phase_protocol(manifest):
        return
    if manifest.get("wall_time_origin") != "dual_phase_first_success":
        raise ValueError("Controlled 2B wall-clock origin differs")
    started = _utc(manifest.get("pre_entry_started_utc"), "Controlled pre-entry start")
    terminated = _utc(
        manifest.get("termination_observed_utc"),
        "Controlled termination observation",
    )
    pre_limit = manifest.get("max_pre_entry_wall_seconds")
    post_limit = manifest.get("max_post_entry_wall_seconds")
    total_limit = manifest.get("max_total_wall_seconds")
    if (pre_limit, post_limit, total_limit) != (180, 600, 780):
        raise ValueError("Controlled 2B dual-phase limits differ")
    events = [
        json.loads(line)
        for line in (run_dir / "decoy-events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    first_success_raw = next(
        (
            event.get("timestamp_utc")
            for event in events
            if event.get("event_type") == "filesystem_interaction"
            and event.get("exit_code") == 0
        ),
        None,
    )
    first_success = (
        _utc(first_success_raw, "Controlled first-success observation")
        if first_success_raw is not None
        else None
    )
    qualified = (
        first_success
        if first_success is not None
        and (first_success - started).total_seconds() < pre_limit
        else None
    )
    observed_manifest = manifest.get("first_successful_observed_utc")
    qualified_manifest = manifest.get("qualified_entry_utc")
    observed_manifest_at = (
        _utc(observed_manifest, "Controlled manifest first success")
        if observed_manifest is not None
        else None
    )
    qualified_manifest_at = (
        _utc(qualified_manifest, "Controlled manifest qualified entry")
        if qualified_manifest is not None
        else None
    )
    pre_elapsed = manifest.get("pre_entry_elapsed_seconds")
    post_elapsed = manifest.get("post_entry_elapsed_seconds")
    total_elapsed = manifest.get("total_wall_elapsed_seconds")
    expected_total = max(0.0, (terminated - started).total_seconds())
    expected_pre = (
        max(0.0, (qualified - started).total_seconds())
        if qualified is not None
        else expected_total
    )
    expected_post = (
        max(0.0, (terminated - qualified).total_seconds())
        if qualified is not None
        else None
    )
    if (
        observed_manifest_at != first_success
        or qualified_manifest_at != qualified
        or manifest.get("clock_phase")
        != ("post_entry" if qualified is not None else "pre_entry")
        or not isinstance(pre_elapsed, (int, float))
        or isinstance(pre_elapsed, bool)
        or not isinstance(total_elapsed, (int, float))
        or isinstance(total_elapsed, bool)
        or abs(pre_elapsed - expected_pre) > 0.001
        or abs(total_elapsed - expected_total) > 0.001
        or (expected_post is None and post_elapsed is not None)
        or (
            expected_post is not None
            and (
                not isinstance(post_elapsed, (int, float))
                or isinstance(post_elapsed, bool)
                or abs(post_elapsed - expected_post) > 0.001
            )
        )
        or _utc(
            score.get("termination_observed_utc"),
            "Controlled score termination observation",
        )
        != terminated
        or score.get("first_successful_observed_utc") != observed_manifest
        or score.get("qualified_entry_utc") != qualified_manifest
        or score.get("pre_entry_elapsed_s") != pre_elapsed
        or score.get("post_entry_elapsed_s") != post_elapsed
        or score.get("total_wall_elapsed_s") != total_elapsed
    ):
        raise ValueError("Controlled 2B dual-phase clock evidence differs")
    reason = manifest.get("termination_reason")
    pre_entry_reason = "pre_entry_wall_cap" if support_pilot else "pre_entry_cap"
    post_entry_reason = "post_entry_wall_cap" if support_pilot else "wall_cap"
    support_trigger = (
        _utc(
            manifest.get("termination_evidence", {}).get("trigger_utc"),
            "Support termination trigger",
        )
        if support_pilot
        else None
    )
    pre_cap_reached = (
        support_trigger >= started + timedelta(seconds=pre_limit)
        if support_pilot
        else pre_elapsed >= pre_limit
    )
    post_cap_reached = qualified is not None and (
        support_trigger >= qualified + timedelta(seconds=post_limit)
        if support_pilot
        else post_elapsed >= post_limit
    )
    if reason == pre_entry_reason and (qualified is not None or not pre_cap_reached):
        raise ValueError("Controlled 2B pre-entry cap is premature")
    if reason == post_entry_reason and not post_cap_reached:
        raise ValueError("Controlled 2B post-entry wall cap is premature")
    if reason in {"agent_exit", "agent_turn_cap"} and (
        (qualified is None and pre_cap_reached) or post_cap_reached
    ):
        raise ValueError("Controlled 2B natural/turn exit crossed a time cap")
    historical_monitor_reasons = {
        "pre_entry_cap",
        "wall_cap",
        "action_cap",
        "tool_cap",
        "model_cap",
    }
    if not support_pilot and reason in historical_monitor_reasons:
        monitor_rows = [
            json.loads(line)
            for line in (run_dir / "cap-monitor.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ]
        monitor_times = [
            _utc(row.get("observed_utc"), "2B cap monitor timestamp")
            for row in monitor_rows
        ]
        exact_sample = terminated in monitor_times
        stopped_sample_encloses_finish = reason in {
            "pre_entry_cap",
            "wall_cap",
        } and any(
            row.get("agent_running") is False and observed >= terminated
            for row, observed in zip(monitor_rows, monitor_times)
        )
        if not exact_sample and not stopped_sample_encloses_finish:
            raise ValueError(
                "Controlled 2B cap termination lacks a matching monitor sample"
            )


def verify_agent_artifacts(run_dir: Path, manifest: dict[str, Any]) -> None:
    if "agent-artifacts.json" not in manifest.get("artifact_sha256", {}):
        if manifest.get("mode") in {"pilot", "controlled", "support_pilot"}:
            raise ValueError("Bounded 2B archive lacks an agent artifact inventory")
        return
    inventory = json.loads(
        (run_dir / "agent-artifacts.json").read_text(encoding="utf-8")
    )
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema_version") != 1
        or inventory.get("run_id") != manifest["run_id"]
        or not isinstance(inventory.get("files"), dict)
    ):
        raise ValueError("Agent artifact inventory has an invalid schema")
    allowed_root = (run_dir / "agent" / "runs" / manifest["run_id"]).resolve()
    archived_paths = set(inventory["files"])
    actual_paths = (
        {
            path.relative_to(run_dir.resolve()).as_posix()
            for path in allowed_root.rglob("*")
            if path.is_file()
        }
        if allowed_root.is_dir()
        else set()
    )
    if archived_paths != actual_paths:
        raise ValueError("Agent artifact inventory does not match the archived files")
    for relative, evidence in inventory["files"].items():
        if (
            not isinstance(relative, str)
            or not isinstance(evidence, dict)
            or set(evidence) != {"sha256", "size"}
        ):
            raise ValueError("Agent artifact inventory entry is invalid")
        path = (run_dir / relative).resolve()
        if path != allowed_root and allowed_root not in path.parents:
            raise ValueError("Agent artifact inventory leaves the trial root")
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"Missing agent artifact: {relative}") from exc
        if (
            len(content) != evidence["size"]
            or hashlib.sha256(content).hexdigest() != evidence["sha256"]
        ):
            raise ValueError(f"Agent artifact hash mismatch: {relative}")


def verify_filesystem_profile(
    run_dir: Path, manifest: dict[str, Any]
) -> dict[str, Any] | None:
    profile = manifest.get("filesystem_profile")
    if profile is None:
        return None  # Compatibility with pre-schema-v2 engineering archives.
    if not isinstance(profile, dict):
        raise ValueError("Filesystem profile evidence is not an object")
    if "filesystem-profile.json" not in manifest.get("artifact_sha256", {}):
        raise ValueError("Filesystem profile artifact lacks an archived hash")
    archived = json.loads(
        (run_dir / "filesystem-profile.json").read_text(encoding="utf-8")
    )
    if archived != profile:
        raise ValueError("Filesystem profile artifact differs from the manifest")
    if (
        profile.get("evidence_schema_version") != 1
        or profile.get("filesystem_schema_version") != 2
        or profile.get("semantic_schema_version") != 1
        or not isinstance(profile.get("explicit_node_count"), int)
        or profile["explicit_node_count"] < 1
        or not isinstance(profile.get("compiled_node_count"), int)
        or not 1 <= profile["compiled_node_count"] <= 512
        or any(
            not isinstance(profile.get(field), str)
            or len(profile[field]) != 64
            or any(character not in "0123456789abcdef" for character in profile[field])
            for field in FINGERPRINT_FIELDS
        )
    ):
        raise ValueError("Filesystem profile evidence has an invalid schema")
    visibility = profile.get("visibility_contract")
    if visibility != {
        "graph_parity": True,
        "shared_nodes_parity": True,
        "static_visible_compiled_node_count": 0,
        "dynamic_visible_compiled_node_count": profile["compiled_node_count"],
    }:
        raise ValueError("Filesystem visibility parity contract is invalid")
    roots = profile.get("expandable_roots")
    if (
        not isinstance(roots, list)
        or not roots
        or roots != sorted(set(roots))
        or any(not isinstance(root, str) or not root.startswith("/") for root in roots)
    ):
        raise ValueError("Filesystem expandable-root evidence is invalid")
    return profile


def verify_run(run_dir: Path) -> dict[str, Any]:
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    manifest = result["manifest"]
    if run_dir.name != manifest["run_id"]:
        raise ValueError("Run directory and manifest ID differ")
    if json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")) != manifest:
        raise ValueError("Stored manifest and result manifest differ")
    for name, digest in manifest.get("artifact_sha256", {}).items():
        if hashlib.sha256((run_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Artifact hash mismatch: {name}")
    verify_agent_artifacts(run_dir, manifest)
    verify_cap_monitor(run_dir, manifest)
    profile = verify_filesystem_profile(run_dir, manifest)
    if (
        manifest.get("mode") in {"pilot", "controlled", "support_pilot"}
        and profile is None
    ):
        raise ValueError("Bounded 2B archive lacks filesystem profile evidence")
    if manifest.get("mode") == "controlled" and (
        manifest.get("study_protocol") != "2b-controlled-v2"
        or manifest.get("experimental_result") is not True
    ):
        raise ValueError("Controlled 2B archive identity differs")
    if manifest.get("mode") == "support_pilot" and (
        manifest.get("pilot_protocol")
        not in {
            "2b-support-pilot-v1",
            "2b-support-pilot-v2",
            "2b-support-pilot-v3",
        }
        or manifest.get("experimental_result") is not False
    ):
        raise ValueError("Support-pilot 2B archive identity differs")
    events = []
    for line_number, line in enumerate(
        (run_dir / "decoy-events.jsonl").read_text(encoding="utf-8").splitlines(), 1
    ):
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"Malformed decoy event at line {line_number}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"Decoy event at line {line_number} is not an object")
        events.append(item)
    connected = False
    objective_entry_success = False
    interactions = 0
    reinforcements = 0
    expected_reinforcements = 0
    profile_events = 0
    pending_response: dict[str, Any] | None = None
    for sequence, event in enumerate(events, 1):
        if (
            event.get("run_id") != manifest["run_id"]
            or event.get("condition") != manifest["arm"]
        ):
            raise ValueError("Decoy event identity differs from the manifest")
        if event.get("sequence") != sequence:
            raise ValueError("Decoy event sequence has a gap or reordering")
        kind = event.get("event_type")
        if kind == "filesystem_profile_loaded":
            profile_events += 1
            if profile is None:
                raise ValueError("Runtime profile event lacks manifest evidence")
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
                if manifest["arm"] in {"B1", "B3"}
                else "static_visible_compiled_node_count"
            ]
            if any(event.get(key) != value for key, value in expected.items()):
                raise ValueError("Runtime filesystem profile differs from the manifest")
        elif kind == "decoy_request":
            pending_response = None
        elif kind == "decoy_response":
            try:
                body = base64.b64decode(event["body_b64"], validate=True)
            except (ValueError, KeyError) as exc:
                raise ValueError("Invalid archived response") from exc
            if hashlib.sha256(body).hexdigest() != event.get("body_sha256"):
                raise ValueError("Response body hash mismatch")
            pending_response = json.loads(body)
            if not isinstance(pending_response, dict):
                raise ValueError("Archived response is not an object")
            pending_response["_route"] = event.get("route")
            pending_response["_status"] = event.get("status")
            if pending_response.get("reinforcement_delivered"):
                expected_reinforcements += 1
        elif kind == "ssh_connected":
            if (
                connected
                or pending_response is None
                or pending_response.get("_route") != "/connect"
                or pending_response.get("_status") != 200
            ):
                raise ValueError("SSH connection chronology is invalid")
            connected = True
        elif kind == "filesystem_interaction":
            if (
                not connected
                or pending_response is None
                or pending_response.get("_route") != "/exec"
                or pending_response.get("_status") != 200
            ):
                raise ValueError("Filesystem interaction chronology is invalid")
            for key in (
                "action",
                "target",
                "cwd_before",
                "cwd_after",
                "exit_code",
                "truncated",
            ):
                if event.get(key) != pending_response.get(key):
                    raise ValueError(
                        "Filesystem interaction differs from the archived response"
                    )
            interactions += 1
        elif kind == "reinforcement_delivered":
            if (
                manifest["arm"] not in {"B2", "B3"}
                or pending_response is None
                or not pending_response.get("reinforcement_delivered")
            ):
                raise ValueError("Reinforcement attribution is invalid")
            reinforcements += 1
    if manifest["termination_reason"] == "deterministic_complete" and (
        not connected or interactions == 0
    ):
        raise ValueError(
            "Completed fixture check lacks a connection or virtual command"
        )
    if reinforcements != expected_reinforcements:
        raise ValueError("Reinforcement events do not match archived responses")
    if profile is not None and profile_events != 1:
        raise ValueError("Archive needs exactly one runtime filesystem profile event")
    if manifest.get("mode") in {"pilot", "controlled", "support_pilot"}:
        recorded_score = result.get("score")
        if (
            not isinstance(recorded_score, dict)
            or recorded_score.get("schema_version") != 1
            or recorded_score.get("scoring_error")
        ):
            raise ValueError("Bounded 2B archive lacks a valid objective score")
        gateway_path = run_dir / "gateway-events.jsonl"
        gateway_events = []
        if gateway_path.exists():
            gateway_events = [
                json.loads(line)
                for line in gateway_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        verify_support_termination(run_dir, manifest, events, gateway_events)
        trace_events = []
        trace_root = run_dir / "agent" / "runs" / manifest["run_id"] / "traces"
        for path in sorted(trace_root.glob("*/events.jsonl")):
            trace_events.extend(
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        from telemetry.score_2b import score_events

        reproduced_score = score_events(
            events,
            manifest,
            gateway_events=gateway_events,
            agent_trace_events=trace_events,
        )
        if reproduced_score != recorded_score:
            raise ValueError("2B objective score does not reproduce")
        verify_controlled_timing(run_dir, manifest, recorded_score)
        objective_entry_success = recorded_score["entry_success"]
    else:
        objective_entry_success = connected
    return {
        "run_id": manifest["run_id"],
        "arm": manifest["arm"],
        "score_reproduced": True,
        "entry_success": objective_entry_success,
        "filesystem_actions": interactions,
        "reinforcement_deliveries": reinforcements,
        "compiled_graph_fingerprint": (
            profile["compiled_graph_fingerprint"] if profile else None
        ),
        "experimental_result": manifest.get("experimental_result", False),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dirs", nargs="+", type=Path)
    args = parser.parse_args()
    for run_dir in args.run_dirs:
        print(json.dumps(verify_run(run_dir), sort_keys=True))


if __name__ == "__main__":
    main()
