"""Freeze and execute the controlled 2B factorial cohort without effect peeking."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import secrets
from typing import Any

from experiment_controller import pilot_2b
from experiment_controller.controlled_2b_contract import (
    ARMS,
    CONFIG,
    LAB,
    STUDIES,
    contract_status,
    load_contract,
    sha256,
    validate_readiness_dependency,
)
from experiment_controller.run_2b import COMPOSE, FIXTURE, TASK, run_controlled, write_private
from telemetry.adjudicate_2b import resolve_annotations
from telemetry.analyze_2b import analyze_controlled, render_analysis_artifacts
from telemetry.annotate_2b import review_packet
from telemetry.replay_2b import verify_run


STUDY_PROTOCOL = "2b-controlled-v2"
STUDY_ID = re.compile(r"2b-study-v2-[0-9]{14}-[0-9a-f]{6}")
RANDOMIZATION_SEED = re.compile(r"[A-Za-z0-9._-]{1,128}")


class StudyIntegrityError(RuntimeError):
    """A non-replaceable controlled-study integrity or containment failure."""


def study_dir(study_id: str) -> Path:
    if not STUDY_ID.fullmatch(study_id):
        raise ValueError("Invalid controlled 2B study ID")
    return STUDIES / study_id


def _pipeline_sources() -> dict[str, Path]:
    paths = {
        "controlled_contract": CONFIG,
        "contract_validator": LAB
        / "experiment_controller"
        / "controlled_2b_contract.py",
        "controlled_scheduler": Path(__file__),
        "runner": LAB / "experiment_controller" / "run_2b.py",
        "scorer": LAB / "telemetry" / "score_2b.py",
        "replay": LAB / "telemetry" / "replay_2b.py",
        "review_projection": LAB / "telemetry" / "annotate_2b.py",
        "adjudication": LAB / "telemetry" / "adjudicate_2b.py",
        "analysis": LAB / "telemetry" / "analyze_2b.py",
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ValueError(
            "Controlled 2B pipeline is incomplete: " + ", ".join(sorted(missing))
        )
    return paths


def fingerprint() -> dict[str, Any]:
    """Fingerprint the complete model-free pipeline and existing trial images."""

    contract = load_contract()
    readiness = validate_readiness_dependency(contract)
    pilot_fingerprint = pilot_2b.fingerprint()
    task = json.loads(TASK.read_text(encoding="utf-8"))
    return {
        "study_protocol": contract["study_protocol"],
        "environment_protocol": contract["environment_protocol"],
        "provider": contract["provider"],
        "agent": task["agent"],
        "task_caps": task["caps_per_trial"],
        "controlled_contract_sha256": sha256(CONFIG),
        "readiness_dependency": readiness,
        "agent_task_sha256": sha256(TASK),
        "fixture_sha256": sha256(FIXTURE),
        "compose_sha256": sha256(COMPOSE),
        "source_sha256": {
            name: sha256(path) for name, path in _pipeline_sources().items()
        },
        "images": pilot_fingerprint["images"],
        "image_source_sha256": pilot_fingerprint["image_source_sha256"],
        "agent_image_task_sha256": pilot_fingerprint["agent_image_task_sha256"],
        "pentestgpt_commit": pilot_fingerprint["pentestgpt_commit"],
        "agent_source_sha256": pilot_fingerprint["agent_source_sha256"],
        "unified_agent_commit": pilot_fingerprint["unified_agent_commit"],
        "claude_code_cli_version": pilot_fingerprint["claude_code_cli_version"],
    }


def _assert_frozen_pipeline(schedule: dict[str, Any]) -> None:
    expected = schedule.get("fingerprint", {}).get("source_sha256")
    observed = {name: sha256(path) for name, path in _pipeline_sources().items()}
    if expected != observed:
        raise StudyIntegrityError(
            "Controlled 2B pipeline source changed after schedule freeze"
        )


def prepare(*, randomization_seed: str | None = None) -> dict[str, Any]:
    """Freeze all forty assignments; this function never executes a run."""

    contract = load_contract()
    frozen = fingerprint()
    randomization_seed = randomization_seed or secrets.token_hex(16)
    if not RANDOMIZATION_SEED.fullmatch(randomization_seed):
        raise ValueError("Invalid controlled 2B randomization seed")
    study_id = (
        "2b-study-v2-"
        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        + "-"
        + secrets.token_hex(3)
    )
    folder = study_dir(study_id)
    folder.mkdir(parents=True, mode=0o700)
    for name in ("review-packets", "annotations", "adjudications"):
        (folder / name).mkdir(mode=0o700)

    rng = random.Random(randomization_seed)
    assignments: list[dict[str, Any]] = []
    arms = contract["design"]["arms"]
    for block in range(1, contract["design"]["balanced_blocks"] + 1):
        order = list(ARMS)
        rng.shuffle(order)
        for arm in order:
            assignments.append(
                {
                    "slot": len(assignments) + 1,
                    "block": block,
                    "arm": arm,
                    "factors": arms[arm],
                }
            )
    schedule = {
        "schema_version": 1,
        "study_id": study_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "randomization_seed": randomization_seed,
        "contract_sha256": sha256(CONFIG),
        "contract": contract,
        "fingerprint": frozen,
        "assignments": assignments,
    }
    schedule_path = folder / "schedule.json"
    write_private(schedule_path, json.dumps(schedule, indent=2, sort_keys=True) + "\n")
    write_private(folder / "schedule.sha256", sha256(schedule_path) + "\n")
    return schedule


def load_schedule(study_id: str) -> dict[str, Any]:
    folder = study_dir(study_id)
    schedule_path = folder / "schedule.json"
    try:
        commitment = (folder / "schedule.sha256").read_text(
            encoding="utf-8"
        ).strip()
    except OSError as exc:
        raise ValueError("Controlled 2B schedule commitment is missing") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", commitment) or sha256(
        schedule_path
    ) != commitment:
        raise ValueError("Controlled 2B schedule differs from its frozen commitment")
    try:
        schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Controlled 2B schedule is missing or malformed") from exc
    if (
        not isinstance(schedule, dict)
        or set(schedule)
        != {
            "schema_version",
            "study_id",
            "created_utc",
            "randomization_seed",
            "contract_sha256",
            "contract",
            "fingerprint",
            "assignments",
        }
        or schedule.get("schema_version") != 1
        or schedule.get("study_id") != study_id
        or schedule.get("contract_sha256") != sha256(CONFIG)
        or schedule.get("contract") != load_contract()
        or not isinstance(schedule.get("fingerprint"), dict)
        or not isinstance(schedule.get("randomization_seed"), str)
        or not RANDOMIZATION_SEED.fullmatch(schedule["randomization_seed"])
    ):
        raise ValueError("Controlled 2B schedule identity or contract differs")

    assignments = schedule.get("assignments")
    contract = schedule["contract"]
    blocks = contract["design"]["balanced_blocks"]
    expected_count = contract["design"]["required_valid_runs"]
    if not isinstance(assignments, list) or len(assignments) != expected_count:
        raise ValueError("Controlled 2B schedule has the wrong assignment count")
    if [row.get("slot") for row in assignments] != list(
        range(1, expected_count + 1)
    ):
        raise ValueError("Controlled 2B schedule has a slot gap or reordering")
    for row in assignments:
        slot = row.get("slot")
        block = row.get("block")
        if (
            not isinstance(slot, int)
            or isinstance(slot, bool)
            or not isinstance(block, int)
            or isinstance(block, bool)
            or block != (slot - 1) // len(ARMS) + 1
        ):
            raise ValueError("Controlled 2B schedule slot-to-block mapping differs")
    for block in range(1, blocks + 1):
        rows = [row for row in assignments if row.get("block") == block]
        if (
            len(rows) != len(ARMS)
            or {row.get("arm") for row in rows} != set(ARMS)
            or any(
                set(row) != {"slot", "block", "arm", "factors"}
                or row.get("factors")
                != contract["design"]["arms"].get(row.get("arm"))
                for row in rows
            )
        ):
            raise ValueError("Controlled 2B schedule block is not balanced")
    return schedule


def assigned_results(study_id: str) -> dict[int, list[dict[str, Any]]]:
    found: dict[int, list[dict[str, Any]]] = {}
    for path in (LAB / "runs").glob("*/result.json"):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        assignment = result.get("manifest", {}).get("assignment", {})
        if assignment.get("study_id") != study_id:
            continue
        slot = assignment.get("slot")
        if (
            not isinstance(slot, int)
            or isinstance(slot, bool)
            or slot < 1
            or slot > 40
        ):
            raise StudyIntegrityError(
                "Controlled result has an invalid or out-of-range assigned slot"
            )
        found.setdefault(slot, []).append(result)
    for rows in found.values():
        rows.sort(key=lambda row: row.get("manifest", {}).get("started_utc", ""))
    return found


def _manifest_matches_fingerprint(
    manifest: dict[str, Any], schedule: dict[str, Any]
) -> bool:
    fingerprint = schedule["fingerprint"]
    contract = schedule["contract"]
    sources = fingerprint.get("source_sha256", {})
    embedded = fingerprint.get("image_source_sha256", {})
    decoy_sources = embedded.get("decoy", {}) if isinstance(embedded, dict) else {}
    agent_sources = embedded.get("agent", {}) if isinstance(embedded, dict) else {}
    task_caps = fingerprint.get("task_caps", {})
    return all(
        (
            manifest.get("protocol") == contract["environment_protocol"],
            manifest.get("controlled_contract_schema_version")
            == contract["schema_version"],
            manifest.get("controlled_contract_sha256")
            == schedule["contract_sha256"],
            manifest.get("experimental_result") is True,
            manifest.get("provider") == contract["provider"],
            manifest.get("model") == contract["agent"]["model"],
            manifest.get("seed") == contract["seed"],
            manifest.get("images") == fingerprint.get("images"),
            manifest.get("agent_task_sha256")
            == fingerprint.get("agent_task_sha256"),
            manifest.get("agent_image_task_sha256")
            == fingerprint.get("agent_image_task_sha256"),
            manifest.get("fixture_sha256") == fingerprint.get("fixture_sha256"),
            manifest.get("controller_sha256") == sources.get("runner"),
            manifest.get("filesystem_engine_sha256")
            == decoy_sources.get("filesystem_decoy_2b/virtual_fs.py"),
            manifest.get("decoy_server_sha256")
            == decoy_sources.get("filesystem_decoy_2b/server.py"),
            manifest.get("ssh_tools_sha256")
            == agent_sources.get("agent_runner/ssh_tools_2b.py"),
            manifest.get("agent_entrypoint_sha256")
            == agent_sources.get("agent_runner/entrypoint_2b.py"),
            manifest.get("pentestgpt_commit")
            == fingerprint.get("pentestgpt_commit"),
            manifest.get("agent_source_sha256")
            == fingerprint.get("agent_source_sha256"),
            manifest.get("unified_agent_commit")
            == fingerprint.get("unified_agent_commit"),
            manifest.get("max_wall_seconds")
            == contract["trial_caps"]["post_entry_wall_seconds"],
            manifest.get("wall_time_origin") == "dual_phase_first_success",
            manifest.get("max_pre_entry_wall_seconds")
            == contract["trial_caps"]["pre_entry_wall_seconds"],
            manifest.get("max_post_entry_wall_seconds")
            == contract["trial_caps"]["post_entry_wall_seconds"],
            manifest.get("max_total_wall_seconds")
            == contract["trial_caps"]["maximum_total_wall_seconds"],
            manifest.get("max_filesystem_actions")
            == contract["trial_caps"]["max_filesystem_actions"],
            manifest.get("retention_horizons_seconds")
            == contract["trial_caps"]["retention_horizons_seconds"],
            manifest.get("max_agent_tool_calls")
            == task_caps.get("max_agent_tool_calls"),
            manifest.get("max_model_calls") == task_caps.get("max_model_calls"),
            manifest.get("max_model_tokens")
            == task_caps.get("max_model_tokens_input_plus_output"),
            manifest.get("cap_policy") == contract["cap_policy"],
        )
    )


def invalid_reason(
    result: dict[str, Any],
    schedule: dict[str, Any],
    assignment: dict[str, Any],
    *,
    replay: bool = True,
) -> str | None:
    manifest = result.get("manifest")
    if not isinstance(manifest, dict):
        return "missing_required_telemetry"
    expected_assignment = {
        "study_id": schedule["study_id"],
        "slot": assignment["slot"],
        "block": assignment["block"],
        "arm": assignment["arm"],
    }
    if (
        manifest.get("mode") != "controlled"
        or manifest.get("study_protocol") != STUDY_PROTOCOL
        or manifest.get("study_fingerprint") != schedule["fingerprint"]
        or manifest.get("assignment") != expected_assignment
        or manifest.get("arm") != assignment["arm"]
        or not isinstance(manifest.get("run_id"), str)
        or not re.fullmatch(r"2b-cont-[a-z0-9-]{1,53}", manifest["run_id"])
        or not _manifest_matches_fingerprint(manifest, schedule)
    ):
        return "source_or_image_drift"
    reason = manifest.get("termination_reason")
    if reason == "provider_rate_limit":
        return "provider_rate_limit"
    if reason == "agent_failure":
        return "agent_failure"
    if reason == "agent_turn_cap":
        policy = schedule["contract"]["termination_policy"]["agent_max_turns"]
        terminal = manifest.get("agent_terminal")
        if (
            not isinstance(terminal, dict)
            or terminal.get("failure_kind") != policy["source_failure_kind"]
            or not isinstance(terminal.get("failure_message"), str)
        ):
            return "agent_failure"
    if reason == "controller_error" or manifest.get("error"):
        return "controller_error"
    declared_outcomes = {"agent_exit", *schedule["contract"]["termination_policy"]["right_censored_reasons"]}
    if reason not in declared_outcomes:
        return "missing_required_telemetry"
    preflight = manifest.get("isolation_preflight")
    if isinstance(preflight, dict) and preflight.get("direct_egress") is True:
        raise StudyIntegrityError(
            f"Direct attacker egress observed in {manifest.get('run_id')}"
        )
    if preflight != {"decoy": 200, "gateway": 200, "direct_egress": False}:
        return "missing_required_telemetry"
    score = result.get("score")
    if not isinstance(score, dict):
        return "missing_required_telemetry"
    if score.get("scoring_error"):
        return "scoring_error"
    if (
        score.get("schema_version") != 1
        or score.get("protocol") != schedule["contract"]["environment_protocol"]
        or score.get("experimental_result") is not True
        or score.get("run_id") != manifest.get("run_id")
        or score.get("arm") != assignment["arm"]
        or score.get("termination_reason") != reason
    ):
        return "missing_required_telemetry"
    entry_success = score.get("entry_success")
    first_success = score.get("first_successful_interaction_utc")
    retention_span = score.get("retention_active_span_s")
    retention_dwell = score.get("retention_dwell_time_s")
    if (
        not isinstance(entry_success, bool)
        or (
            entry_success
            and (
                not isinstance(first_success, str)
                or not isinstance(retention_span, (int, float))
                or isinstance(retention_span, bool)
                or retention_span < 0
                or not isinstance(retention_dwell, (int, float))
                or isinstance(retention_dwell, bool)
                or retention_dwell < retention_span
            )
        )
        or (
            not entry_success
            and any(
                value is not None
                for value in (first_success, retention_span, retention_dwell)
            )
        )
    ):
        return "missing_required_telemetry"
    if (
        reason
        in schedule["contract"]["termination_policy"]["right_censored_reasons"]
        and score.get("right_censored") is not True
    ):
        return "scoring_error"
    caps = schedule["contract"]["trial_caps"]
    pre_limit = caps["pre_entry_wall_seconds"]
    post_limit = caps["post_entry_wall_seconds"]
    pre_started = manifest.get("pre_entry_started_utc")
    termination_observed = manifest.get("termination_observed_utc")
    raw_first_success = manifest.get("first_successful_observed_utc")
    qualified_entry = manifest.get("qualified_entry_utc")
    if not isinstance(pre_started, str) or not isinstance(termination_observed, str):
        return "missing_required_telemetry"
    try:
        pre_started_at = datetime.fromisoformat(
            pre_started.replace("Z", "+00:00")
        )
        termination_at = datetime.fromisoformat(
            termination_observed.replace("Z", "+00:00")
        )
        score_termination_at = datetime.fromisoformat(
            str(score.get("termination_observed_utc")).replace("Z", "+00:00")
        )
        raw_first_success_at = (
            datetime.fromisoformat(raw_first_success.replace("Z", "+00:00"))
            if isinstance(raw_first_success, str)
            else None
        )
        qualified_entry_at = (
            datetime.fromisoformat(qualified_entry.replace("Z", "+00:00"))
            if isinstance(qualified_entry, str)
            else None
        )
    except (AttributeError, ValueError):
        return "missing_required_telemetry"
    total_elapsed = manifest.get("total_wall_elapsed_seconds")
    pre_elapsed = manifest.get("pre_entry_elapsed_seconds")
    post_elapsed = manifest.get("post_entry_elapsed_seconds")
    numeric_elapsed = (pre_elapsed, total_elapsed)
    expected_total = (termination_at - pre_started_at).total_seconds()
    expected_qualified = (
        raw_first_success_at
        if raw_first_success_at is not None
        and (raw_first_success_at - pre_started_at).total_seconds() < pre_limit
        else None
    )
    expected_pre = (
        (expected_qualified - pre_started_at).total_seconds()
        if expected_qualified is not None
        else expected_total
    )
    expected_post = (
        (termination_at - expected_qualified).total_seconds()
        if expected_qualified is not None
        else None
    )
    if (
        pre_started_at.tzinfo is None
        or termination_at.tzinfo is None
        or score_termination_at.tzinfo is None
        or any(
            timestamp is not None and timestamp.tzinfo is None
            for timestamp in (raw_first_success_at, qualified_entry_at)
        )
        or expected_total < 0
        or expected_pre < 0
        or (expected_post is not None and expected_post < 0)
        or score_termination_at != termination_at
        or any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            for value in numeric_elapsed
        )
        or abs(total_elapsed - expected_total) > 0.001
        or abs(pre_elapsed - expected_pre) > 0.001
        or qualified_entry_at != expected_qualified
        or manifest.get("clock_phase")
        != ("post_entry" if expected_qualified is not None else "pre_entry")
        or (
            expected_post is None
            and post_elapsed is not None
        )
        or (
            expected_post is not None
            and (
                not isinstance(post_elapsed, (int, float))
                or isinstance(post_elapsed, bool)
                or abs(post_elapsed - expected_post) > 0.001
            )
        )
        or score.get("first_successful_observed_utc") != raw_first_success
        or score.get("qualified_entry_utc") != qualified_entry
        or score.get("pre_entry_elapsed_s") != pre_elapsed
        or score.get("post_entry_elapsed_s") != post_elapsed
        or score.get("total_wall_elapsed_s") != total_elapsed
        or entry_success is not (expected_qualified is not None)
        or first_success != qualified_entry
        or (
            reason == "pre_entry_cap"
            and (expected_qualified is not None or pre_elapsed < pre_limit)
        )
        or (
            reason == "wall_cap"
            and (expected_qualified is None or post_elapsed < post_limit)
        )
        or (
            reason in {"agent_exit", "agent_turn_cap"}
            and (
                (expected_qualified is None and pre_elapsed >= pre_limit)
                or (expected_qualified is not None and post_elapsed >= post_limit)
            )
        )
    ):
        return "missing_required_telemetry"
    if entry_success:
        try:
            first_success_at = datetime.fromisoformat(
                first_success.replace("Z", "+00:00")
            )
        except ValueError:
            return "missing_required_telemetry"
        if (
            first_success_at.tzinfo is None
            or first_success_at > termination_at
            or abs(
                (termination_at - first_success_at).total_seconds()
                - retention_dwell
            )
            > 0.001
        ):
            return "missing_required_telemetry"
    cap = score.get("cap_conformance")
    if not isinstance(cap, dict) or not isinstance(
        cap.get("monitor_sample_count"), int
    ) or cap.get("monitor_sample_count", 0) < 1:
        return "missing_required_telemetry"
    if cap.get("hard_limit_conformant") is not True:
        raise StudyIntegrityError(
            f"Hard filesystem cap violation in {manifest.get('run_id')}"
        )
    if (
        score.get("total_filesystem_actions")
        != cap.get("observed_filesystem_actions")
        or not isinstance(score.get("filesystem_actions"), int)
        or score["filesystem_actions"] > score["total_filesystem_actions"]
    ):
        return "missing_required_telemetry"
    if manifest.get("confirmed_containment_escape_incident") is True or score.get(
        "confirmed_containment_escape_incident"
    ) is True:
        raise StudyIntegrityError(
            f"Confirmed containment escape in {manifest.get('run_id')}"
        )
    if replay:
        run_id = manifest.get("run_id")
        if not isinstance(run_id, str):
            return "missing_required_telemetry"
        try:
            verify_run(LAB / "runs" / run_id)
        except Exception:
            return "replay_failure"
    return None


def _classify(
    schedule: dict[str, Any], found: dict[int, list[dict[str, Any]]]
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    expected_slots = {row["slot"] for row in schedule["assignments"]}
    if any(
        not isinstance(slot, int)
        or isinstance(slot, bool)
        or slot not in expected_slots
        for slot in found
    ):
        raise StudyIntegrityError("Controlled results contain an unassigned slot")
    valid: dict[int, dict[str, Any]] = {}
    invalid: list[dict[str, Any]] = []
    allowed = set(
        schedule["contract"]["replacement_policy"]["infrastructure_invalid_reasons"]
    )
    for assignment in schedule["assignments"]:
        slot = assignment["slot"]
        for result in found.get(slot, []):
            reason = invalid_reason(result, schedule, assignment)
            if reason is None:
                if slot in valid:
                    raise StudyIntegrityError(
                        f"Controlled slot {slot} has more than one valid run"
                    )
                valid[slot] = result
            else:
                if reason not in allowed:
                    raise StudyIntegrityError(
                        f"Unclassified replacement reason for slot {slot}: {reason}"
                    )
                invalid.append(
                    {
                        "slot": slot,
                        "run_id": result.get("manifest", {}).get("run_id"),
                        "reason": reason,
                    }
                )
    return valid, invalid


def status(study_id: str) -> dict[str, Any]:
    schedule = load_schedule(study_id)
    valid, invalid = _classify(schedule, assigned_results(study_id))
    completed_blocks = []
    for block in range(1, schedule["contract"]["design"]["balanced_blocks"] + 1):
        slots = [
            row["slot"] for row in schedule["assignments"] if row["block"] == block
        ]
        if all(slot in valid for slot in slots):
            completed_blocks.append(block)
    next_slot = next(
        (row["slot"] for row in schedule["assignments"] if row["slot"] not in valid),
        None,
    )
    return {
        "study_id": study_id,
        "scheduled_runs": len(schedule["assignments"]),
        "valid_runs": len(valid),
        "completed_slots": sorted(valid),
        "completed_blocks": completed_blocks,
        "next_slot": next_slot,
        "invalid_attempts": invalid,
        "ready_for_review": len(valid) == len(schedule["assignments"]),
    }


def _complete_results(
    study_id: str,
) -> tuple[dict[str, Any], dict[int, dict[str, Any]], list[dict[str, Any]]]:
    schedule = load_schedule(study_id)
    valid, invalid = _classify(schedule, assigned_results(study_id))
    missing = [
        row["slot"] for row in schedule["assignments"] if row["slot"] not in valid
    ]
    if missing:
        raise ValueError(
            "Controlled 2B schedule is incomplete; missing valid slots: "
            + ", ".join(map(str, missing))
        )
    return schedule, valid, invalid


def _analysis_entered(score: dict[str, Any]) -> bool:
    """Controlled entry requires the first successful filesystem interaction."""

    return (
        score.get("entry_success") is True
        and isinstance(score.get("first_successful_interaction_utc"), str)
        and score.get("retention_dwell_time_s") is not None
    )


def prepare_review_packets(study_id: str) -> dict[str, Any]:
    """Write deterministic arm-blinded packets for every entered valid run."""

    schedule, valid, _ = _complete_results(study_id)
    _assert_frozen_pipeline(schedule)
    folder = study_dir(study_id) / "review-packets"
    if not (folder / "index.json").exists() and (
        any((study_dir(study_id) / "annotations").rglob("*.json"))
        or any((study_dir(study_id) / "adjudications").glob("*.json"))
    ):
        raise StudyIntegrityError(
            "Review annotations exist before the packet set was committed"
        )
    entered_run_ids = []
    nonentered_run_ids = []
    packet_rows = []
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        run_id = result["manifest"]["run_id"]
        if not _analysis_entered(result["score"]):
            nonentered_run_ids.append(run_id)
            continue
        packet = review_packet(LAB / "runs" / run_id)
        if (
            packet.get("run_id") != run_id
            or packet.get("arm_label_included") is not False
        ):
            raise StudyIntegrityError(f"Review packet identity differs for {run_id}")
        rendered = json.dumps(packet, indent=2, sort_keys=True) + "\n"
        output = folder / f"{run_id}.json"
        if output.exists():
            if output.read_text(encoding="utf-8") != rendered:
                raise StudyIntegrityError(
                    f"Existing review packet differs for {run_id}"
                )
        else:
            write_private(output, rendered)
        entered_run_ids.append(run_id)
        packet_rows.append(
            {"run_id": run_id, "file": output.name, "sha256": sha256(output)}
        )
    index = {
        "schema_version": 1,
        "study_protocol": STUDY_PROTOCOL,
        "study_id": study_id,
        "schedule_sha256": sha256(study_dir(study_id) / "schedule.json"),
        "packets": packet_rows,
        "nonentered_run_ids": nonentered_run_ids,
    }
    index_text = json.dumps(index, indent=2, sort_keys=True) + "\n"
    index_path = folder / "index.json"
    commitment_path = folder / "index.sha256"
    if index_path.exists():
        if index_path.read_text(encoding="utf-8") != index_text:
            raise StudyIntegrityError("Existing review packet index differs")
    else:
        write_private(index_path, index_text)
    commitment = sha256(index_path) + "\n"
    if commitment_path.exists():
        if commitment_path.read_text(encoding="utf-8") != commitment:
            raise StudyIntegrityError("Review packet index commitment differs")
    else:
        write_private(commitment_path, commitment)
    return {
        "study_id": study_id,
        "entered_packets": len(entered_run_ids),
        "entered_run_ids": entered_run_ids,
        "nonentered_runs": len(nonentered_run_ids),
        "nonentered_run_ids": nonentered_run_ids,
        "packet_index_sha256": sha256(index_path),
        "ready_for_independent_review": True,
    }


def _verify_review_packets(
    schedule: dict[str, Any], valid: dict[int, dict[str, Any]]
) -> dict[str, Any]:
    _assert_frozen_pipeline(schedule)
    folder = study_dir(schedule["study_id"]) / "review-packets"
    index_path = folder / "index.json"
    commitment_path = folder / "index.sha256"
    try:
        commitment = commitment_path.read_text(encoding="utf-8").strip()
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StudyIntegrityError("Review packet index is missing or malformed") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", commitment) or sha256(
        index_path
    ) != commitment:
        raise StudyIntegrityError("Review packet index differs from its commitment")
    entered = []
    nonentered = []
    expected_files = {"index.json", "index.sha256"}
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        run_id = result["manifest"]["run_id"]
        if not _analysis_entered(result["score"]):
            nonentered.append(run_id)
            if (folder / f"{run_id}.json").exists():
                raise StudyIntegrityError("Non-entered run has a review packet")
            continue
        path = folder / f"{run_id}.json"
        expected_files.add(path.name)
        regenerated = json.dumps(
            review_packet(LAB / "runs" / run_id), indent=2, sort_keys=True
        ) + "\n"
        try:
            observed = path.read_text(encoding="utf-8")
            packet = json.loads(observed)
        except (OSError, json.JSONDecodeError) as exc:
            raise StudyIntegrityError(
                f"Review packet is missing or malformed for {run_id}"
            ) from exc
        if (
            observed != regenerated
            or packet.get("run_id") != run_id
            or packet.get("arm_label_included") is not False
        ):
            raise StudyIntegrityError(f"Review packet differs for {run_id}")
        entered.append(
            {"run_id": run_id, "file": path.name, "sha256": sha256(path)}
        )
    expected_index = {
        "schema_version": 1,
        "study_protocol": STUDY_PROTOCOL,
        "study_id": schedule["study_id"],
        "schedule_sha256": sha256(
            study_dir(schedule["study_id"]) / "schedule.json"
        ),
        "packets": entered,
        "nonentered_run_ids": nonentered,
    }
    if index != expected_index:
        raise StudyIntegrityError("Review packet index content differs")
    actual_files = {path.name for path in folder.iterdir() if path.is_file()}
    if actual_files != expected_files:
        raise StudyIntegrityError("Review packet directory contains unexpected files")
    return index


def _annotation_paths(study_id: str, run_id: str) -> list[Path]:
    root = study_dir(study_id) / "annotations" / run_id
    return sorted(root.glob("*.json")) if root.is_dir() else []


def _adjudication_path(study_id: str, run_id: str) -> Path | None:
    path = study_dir(study_id) / "adjudications" / f"{run_id}.json"
    return path if path.is_file() else None


def review_status(study_id: str) -> dict[str, Any]:
    """Validate two reviews and any required adjudication without revealing arms."""

    schedule, valid, _ = _complete_results(study_id)
    _verify_review_packets(schedule, valid)
    resolved: dict[str, dict[str, Any]] = {}
    shortfalls = []
    nonentered = []
    entered_count = 0
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        run_id = result["manifest"]["run_id"]
        if not _analysis_entered(result["score"]):
            if _annotation_paths(study_id, run_id) or _adjudication_path(
                study_id, run_id
            ) is not None:
                shortfalls.append(
                    {
                        "run_id": run_id,
                        "reason": "nonentered_run_has_unexpected_review_artifacts",
                    }
                )
            nonentered.append(run_id)
            continue
        entered_count += 1
        paths = _annotation_paths(study_id, run_id)
        required = schedule["contract"]["annotation"][
            "reviewers_per_entered_run"
        ]
        if len(paths) != required:
            shortfalls.append(
                {
                    "run_id": run_id,
                    "reason": "requires_exactly_two_annotations",
                    "observed": len(paths),
                }
            )
            continue
        try:
            resolution = resolve_annotations(
                paths,
                adjudication_path=_adjudication_path(study_id, run_id),
                run_dir=LAB / "runs" / run_id,
            )
            disposition = resolution["final_judgments"]["disposition"]
            if disposition == "no_entry" or (
                disposition == "continued_until_censored"
                and result["score"].get("right_censored") is not True
            ):
                raise ValueError(
                    "Resolved disposition is incompatible with objective entry/censoring"
                )
            resolved[run_id] = resolution
        except ValueError as exc:
            shortfalls.append({"run_id": run_id, "reason": str(exc)})
    return {
        "study_id": study_id,
        "entered_runs": entered_count,
        "resolved_runs": len(resolved),
        "nonentered_runs": len(nonentered),
        "shortfalls": shortfalls,
        "ready_for_analysis": not shortfalls,
        "resolved": resolved,
    }


def _analysis_row(
    schedule: dict[str, Any],
    assignment: dict[str, Any],
    result: dict[str, Any],
    judgments: dict[str, Any],
) -> dict[str, Any]:
    manifest = result["manifest"]
    score = result["score"]
    gateway = score.get("gateway_usage")
    if not isinstance(gateway, dict):
        raise StudyIntegrityError(
            f"Controlled score lacks gateway usage: {manifest.get('run_id')}"
        )
    entered = _analysis_entered(score)
    # The controller-selected termination observation is Docker FinishedAt for
    # natural exit or the triggering cap-monitor observation for a censor.
    # Active filesystem span remains a secondary metric, not the event clock.
    observed_time = score.get("retention_dwell_time_s") if entered else None
    if entered and observed_time is None:
        raise StudyIntegrityError(
            f"Entered run lacks an operational event/censor time: {manifest.get('run_id')}"
        )
    return {
        "schema_version": 1,
        "study_protocol": STUDY_PROTOCOL,
        "study_id": schedule["study_id"],
        "schedule_sha256": sha256(
            study_dir(schedule["study_id"]) / "schedule.json"
        ),
        "slot": assignment["slot"],
        "block": assignment["block"],
        "arm": assignment["arm"],
        "run_id": manifest["run_id"],
        "experimental_result": score.get("experimental_result"),
        "entry_success": entered,
        "dwell_time_s": observed_time,
        "termination_reason": score.get("termination_reason"),
        "judgments": judgments,
        "metrics": {
            "filesystem_actions": score.get("filesystem_actions"),
            "exploratory_actions": score.get("exploration_actions"),
            "active_interaction_span_seconds": score.get(
                "retention_active_span_s"
            ),
            "engagement_ratio": score.get("engagement_ratio"),
            "unique_working_directories": score.get("unique_working_directories"),
            "maximum_normalized_path_depth": score.get("max_path_depth"),
            "backtracks": score.get("backtracks"),
            "revisits": score.get("revisits"),
            "model_calls": gateway.get("model_calls"),
            "model_tokens": gateway.get("total_tokens"),
        },
    }


def build_analysis_dataset(study_id: str) -> dict[str, Any]:
    """Build the strict 40-row dataset and hash every source artifact."""

    schedule, valid, invalid = _complete_results(study_id)
    reviews = review_status(study_id)
    if not reviews["ready_for_analysis"]:
        raise ValueError("Controlled 2B reviews or adjudications are incomplete")
    rows = []
    sources = {}
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        run_id = result["manifest"]["run_id"]
        entered = _analysis_entered(result["score"])
        if entered:
            resolution = reviews["resolved"][run_id]
            judgments = resolution["final_judgments"]
        else:
            resolution = None
            judgments = {
                "suspicion": None,
                "disposition": "no_entry",
                "escape_attempt": None,
            }
        rows.append(_analysis_row(schedule, assignment, result, judgments))
        adjudication = _adjudication_path(study_id, run_id)
        packet = study_dir(study_id) / "review-packets" / f"{run_id}.json"
        result_path = LAB / "runs" / run_id / "result.json"
        if not result_path.is_file() or (entered and not packet.is_file()):
            raise StudyIntegrityError(f"Controlled source artifact missing for {run_id}")
        try:
            stored_result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StudyIntegrityError(
                f"Controlled result changed while building dataset: {run_id}"
            ) from exc
        if stored_result != result:
            raise StudyIntegrityError(
                f"Controlled result snapshot differs while building dataset: {run_id}"
            )
        annotations = []
        if resolution is not None:
            for reference in resolution["source_annotations"]:
                path = study_dir(study_id) / "annotations" / run_id / reference["file"]
                if sha256(path) != reference["sha256"]:
                    raise StudyIntegrityError(
                        f"Raw annotation changed while building dataset: {run_id}"
                    )
                annotations.append(reference)
            expected_adjudication = resolution.get("adjudication_sha256")
            if (sha256(adjudication) if adjudication else None) != expected_adjudication:
                raise StudyIntegrityError(
                    f"Adjudication changed while building dataset: {run_id}"
                )
        sources[run_id] = {
            "result_sha256": sha256(result_path),
            "review_packet_sha256": sha256(packet) if entered else None,
            "annotations": annotations,
            "adjudication_sha256": (
                resolution.get("adjudication_sha256") if resolution else None
            ),
            "resolution_status": resolution["status"] if resolution else "no_entry",
        }
    invalid_sources = {}
    for item in invalid:
        run_id = item.get("run_id")
        path = LAB / "runs" / str(run_id) / "result.json"
        if not isinstance(run_id, str) or not path.is_file():
            raise StudyIntegrityError("Infrastructure-invalid attempt lacks an archive")
        invalid_sources[run_id] = {
            "reason": item["reason"],
            "result_sha256": sha256(path),
        }
    return {
        "schema_version": 1,
        "study_protocol": STUDY_PROTOCOL,
        "study_id": study_id,
        "schedule_sha256": sha256(study_dir(study_id) / "schedule.json"),
        "contract_sha256": schedule["contract_sha256"],
        "infrastructure_invalid_attempts": invalid,
        "infrastructure_invalid_sources": invalid_sources,
        "sources": sources,
        "rows": rows,
    }


def freeze_analysis(study_id: str) -> dict[str, Any]:
    """Atomically freeze the row dataset and deterministic production analysis."""

    folder = study_dir(study_id)
    lock_path = folder / "analysis.lock"
    descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    bundle = folder / "analysis"
    stage = folder / f".analysis-{secrets.token_hex(6)}.tmp"
    try:
        if bundle.exists():
            raise FileExistsError("Controlled 2B analysis is already frozen")
        schedule = load_schedule(study_id)
        _assert_frozen_pipeline(schedule)
        dataset = build_analysis_dataset(study_id)
        report = analyze_controlled(
            dataset["rows"],
            schedule=schedule,
            schedule_sha256=dataset["schedule_sha256"],
            contract=schedule["contract"],
        )
        rendered_artifacts = render_analysis_artifacts(report)
        if set(rendered_artifacts) != {
            "arm-summary.csv",
            "factorial-contrasts.csv",
            "retention.svg",
            "limitations-and-verdict.md",
        }:
            raise StudyIntegrityError("Controlled analysis artifact set differs")
        artifact_digests = {
            name: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for name, content in rendered_artifacts.items()
        }
        dataset_text = json.dumps(dataset, indent=2, sort_keys=True) + "\n"
        dataset_digest = hashlib.sha256(dataset_text.encode("utf-8")).hexdigest()
        analysis_digest = schedule["fingerprint"]["source_sha256"]["analysis"]
        envelope = {
            "schema_version": 1,
            "study_protocol": STUDY_PROTOCOL,
            "study_id": study_id,
            "schedule_sha256": dataset["schedule_sha256"],
            "analysis_dataset_sha256": dataset_digest,
            "analysis_code_sha256": analysis_digest,
            "generated_artifacts_sha256": artifact_digests,
            "analysis": report,
        }
        report_text = json.dumps(envelope, indent=2, sort_keys=True) + "\n"
        stage.mkdir(mode=0o700)
        write_private(stage / "analysis-rows.json", dataset_text)
        write_private(stage / "analysis.json", report_text)
        write_private(stage / "analysis-rows.sha256", dataset_digest + "\n")
        for name, content in rendered_artifacts.items():
            write_private(stage / name, content)
        write_private(
            stage / "analysis.sha256",
            hashlib.sha256(report_text.encode("utf-8")).hexdigest() + "\n",
        )
        bundle_manifest = {
            "schema_version": 1,
            "study_protocol": STUDY_PROTOCOL,
            "study_id": study_id,
            "schedule_sha256": dataset["schedule_sha256"],
            "files": {
                "analysis-rows.json": dataset_digest,
                "analysis.json": hashlib.sha256(
                    report_text.encode("utf-8")
                ).hexdigest(),
                **artifact_digests,
            },
        }
        bundle_manifest_text = (
            json.dumps(bundle_manifest, indent=2, sort_keys=True) + "\n"
        )
        write_private(stage / "bundle-manifest.json", bundle_manifest_text)
        write_private(
            stage / "bundle-manifest.sha256",
            hashlib.sha256(bundle_manifest_text.encode("utf-8")).hexdigest()
            + "\n",
        )
        os.replace(stage, bundle)
        return envelope
    finally:
        if stage.is_dir():
            for path in stage.iterdir():
                path.unlink(missing_ok=True)
            stage.rmdir()
        lock_path.unlink(missing_ok=True)


def execute(study_id: str, *, max_new_blocks: int | None = None) -> dict[str, Any]:
    schedule = load_schedule(study_id)
    if fingerprint() != schedule["fingerprint"]:
        raise ValueError("Controlled 2B source or image fingerprint changed after freeze")
    if max_new_blocks is not None and max_new_blocks < 1:
        raise ValueError("max_new_blocks must be positive")
    folder = study_dir(study_id)
    descriptor = os.open(
        folder / "execute.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    os.close(descriptor)
    completed_new_blocks = 0
    try:
        blocks = schedule["contract"]["design"]["balanced_blocks"]
        for block in range(1, blocks + 1):
            assignments = [
                row for row in schedule["assignments"] if row["block"] == block
            ]
            valid, _ = _classify(schedule, assigned_results(study_id))
            if all(row["slot"] in valid for row in assignments):
                continue
            if (
                max_new_blocks is not None
                and completed_new_blocks >= max_new_blocks
            ):
                break
            for assignment in assignments:
                while True:
                    found = assigned_results(study_id)
                    valid, invalid = _classify(schedule, found)
                    if assignment["slot"] in valid:
                        break
                    attempts = [
                        row for row in invalid if row["slot"] == assignment["slot"]
                    ]
                    maximum = schedule["contract"]["replacement_policy"][
                        "maximum_infrastructure_invalid_replacements_per_slot"
                    ]
                    if len(attempts) > maximum:
                        raise RuntimeError(
                            f"Controlled slot {assignment['slot']} exhausted its frozen replacement budget"
                        )
                    run_assignment = {
                        "study_id": study_id,
                        "slot": assignment["slot"],
                        "block": assignment["block"],
                        "arm": assignment["arm"],
                    }
                    result = run_controlled(
                        assignment["arm"],
                        assignment=run_assignment,
                        frozen_fingerprint=schedule["fingerprint"],
                    )
                    reason = invalid_reason(result, schedule, assignment)
                    if reason == "provider_rate_limit":
                        raise RuntimeError(
                            "Provider rate limit exhausted; resume the frozen controlled schedule later"
                        )
            completed_new_blocks += 1
    finally:
        (folder / "execute.lock").unlink(missing_ok=True)
    return status(study_id)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--randomization-seed")
    sub.add_parser("contract-status")
    for action in ("status", "execute", "packets", "review-status", "analyze"):
        item = sub.add_parser(action)
        item.add_argument("--study-id", required=True)
        if action == "execute":
            item.add_argument("--max-new-blocks", type=int)
    args = parser.parse_args()
    if args.action == "contract-status":
        value = contract_status()
    elif args.action == "prepare":
        schedule = prepare(randomization_seed=args.randomization_seed)
        value = {
            "study_id": schedule["study_id"],
            "scheduled_runs": len(schedule["assignments"]),
            "runs_per_arm": schedule["contract"]["design"]["runs_per_arm"],
            "schedule_sha256": sha256(
                study_dir(schedule["study_id"]) / "schedule.json"
            ),
        }
    elif args.action == "status":
        value = status(args.study_id)
    elif args.action == "packets":
        value = prepare_review_packets(args.study_id)
    elif args.action == "review-status":
        value = review_status(args.study_id)
        value.pop("resolved", None)
    elif args.action == "analyze":
        value = freeze_analysis(args.study_id)
    else:
        value = execute(args.study_id, max_new_blocks=args.max_new_blocks)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
