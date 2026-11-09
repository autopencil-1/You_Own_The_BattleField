"""Freeze and execute the effect-blind 2B horizon-support pilot."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Sequence

from experiment_controller import pilot_2b
from experiment_controller.provider_cost_2b import (
    admission_decision,
    estimate_archived_run_cost,
)
from experiment_controller.run_2a import (
    agent_source_sha256,
    pinned_cli_version,
    validate_sources,
)
from experiment_controller.run_2b import (
    AGENT_IMAGE,
    COMPOSE,
    DECOY_IMAGE,
    FIXTURE,
    GATEWAY_IMAGE,
    image_id,
    verify_agent_image_task,
)
from experiment_controller.run_2b_support import run_support_pilot
from experiment_controller.support_pilot_2b_contract import (
    ARMS,
    CONFIG,
    FUTURE_WRAPPER,
    LAB,
    READINESS_CHECKS,
    TASK,
    contract_status,
    load_contract,
    load_freeze,
    sha256,
)
from telemetry.replay_2b import verify_run


PILOTS = LAB / "studies"
PILOT_ID = re.compile(r"2b-support-pilot-v3-[0-9]{14}-[0-9a-f]{6}")
RANDOMIZATION_SEED = re.compile(r"[A-Za-z0-9._-]{1,128}")


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _format_nano_usd(value: int) -> str:
    whole, fractional = divmod(value, 1_000_000_000)
    return f"{whole}.{fractional:09d}"


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)


class _Sha256Sampler:
    """Stable rejection sampler used only to freeze balanced assignments."""

    def __init__(self, seed: str) -> None:
        self._key = hashlib.sha256(
            f"2b-support-pilot-v3:assignment:{seed}".encode("utf-8")
        ).digest()
        self._counter = 0

    def _uint64(self) -> int:
        digest = hashlib.sha256(self._key + self._counter.to_bytes(16, "big")).digest()
        self._counter += 1
        return int.from_bytes(digest[:8], "big")

    def randbelow(self, stop: int) -> int:
        if (
            not isinstance(stop, int)
            or isinstance(stop, bool)
            or not 1 <= stop <= 2**64
        ):
            raise ValueError("Support-pilot sampler bound is invalid")
        limit = 2**64 - (2**64 % stop)
        while True:
            value = self._uint64()
            if value < limit:
                return value % stop

    def shuffle(self, values: list[Any]) -> None:
        for index in range(len(values) - 1, 0, -1):
            other = self.randbelow(index + 1)
            values[index], values[other] = values[other], values[index]


def pilot_dir(pilot_id: str) -> Path:
    if not PILOT_ID.fullmatch(pilot_id):
        raise ValueError("Invalid support-pilot identity")
    return PILOTS / pilot_id


def fingerprint() -> dict[str, Any]:
    """Fingerprint the frozen pipeline and the existing trial images."""

    contract = load_contract()
    freeze = load_freeze()
    pentest_commit, unified_commit = validate_sources()
    maintained_agent_source = agent_source_sha256()
    images = {
        "decoy": image_id(DECOY_IMAGE),
        "gateway": image_id(GATEWAY_IMAGE),
        "agent": image_id(AGENT_IMAGE),
    }
    if any(value is None for value in images.values()):
        raise ValueError("Build all three 2B images before freezing support pilot")
    embedded_task = verify_agent_image_task(sha256(TASK))
    embedded_sources = pilot_2b.verify_image_sources(maintained_agent_source)
    return {
        "schema_version": 1,
        "pilot_protocol": contract["pilot_protocol"],
        "contract_sha256": sha256(CONFIG),
        "agent_task_sha256": sha256(TASK),
        "agent_image_task_sha256": embedded_task,
        "fixture_sha256": sha256(FIXTURE),
        "compose_sha256": sha256(COMPOSE),
        "frozen_input_sha256": contract["frozen_input_sha256"],
        "candidate_status": contract["candidate_status"],
        "runtime_policy": contract["runtime_policy"],
        "trial_caps": contract["trial_caps"],
        "attempt_bounds": contract["attempt_bounds"],
        "transport_bounds": contract["transport_bounds"],
        "container_bounds": contract["container_bounds"],
        "provider_cost_governance": contract["provider_cost_governance"],
        "source_sha256": freeze["frozen_source_sha256"],
        "images": images,
        "image_source_sha256": embedded_sources,
        "pentestgpt_commit": pentest_commit,
        "agent_source_sha256": maintained_agent_source,
        "unified_agent_commit": unified_commit,
        "claude_code_cli_version": pinned_cli_version(),
        "execution": contract["execution"],
    }


def build_schedule(
    *,
    pilot_id: str,
    created_utc: str,
    randomization_seed: str,
    frozen_fingerprint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build, but do not write, a deterministic balanced schedule."""

    pilot_dir(pilot_id)
    if not RANDOMIZATION_SEED.fullmatch(randomization_seed):
        raise ValueError("Invalid support-pilot randomization seed")
    try:
        created = datetime.fromisoformat(created_utc.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Support-pilot creation timestamp is malformed") from exc
    if created.tzinfo is None:
        raise ValueError("Support-pilot creation timestamp lacks a timezone")

    contract = load_contract()
    observed_fingerprint = frozen_fingerprint or fingerprint()
    if not isinstance(observed_fingerprint, dict):
        raise ValueError("Support-pilot preparation fingerprint is invalid")
    sampler = _Sha256Sampler(randomization_seed)
    assignments: list[dict[str, Any]] = []
    for block in range(1, contract["design"]["balanced_blocks"] + 1):
        order = list(ARMS)
        sampler.shuffle(order)
        for arm in order:
            assignments.append(
                {
                    "slot": len(assignments) + 1,
                    "block": block,
                    "arm": arm,
                    "factors": contract["design"]["arms"][arm],
                }
            )
    return {
        "schema_version": 1,
        "pilot_protocol": contract["pilot_protocol"],
        "pilot_id": pilot_id,
        "created_utc": created.isoformat(),
        "randomization_seed": randomization_seed,
        "contract_sha256": sha256(CONFIG),
        "contract": contract,
        "fingerprint": observed_fingerprint,
        "assignments": assignments,
    }


def _write_schedule(*, randomization_seed: str | None = None) -> dict[str, Any]:
    """Freeze the reviewed execution contract without starting a model run."""

    randomization_seed = randomization_seed or secrets.token_hex(16)
    created = datetime.now(timezone.utc)
    pilot_id = (
        "2b-support-pilot-v3-"
        + created.strftime("%Y%m%d%H%M%S")
        + "-"
        + secrets.token_hex(3)
    )
    frozen = fingerprint()
    schedule = build_schedule(
        pilot_id=pilot_id,
        created_utc=created.isoformat(),
        randomization_seed=randomization_seed,
        frozen_fingerprint=frozen,
    )
    folder = pilot_dir(pilot_id)
    folder.mkdir(parents=True, mode=0o700)
    for name in ("review-packets", "annotations", "adjudications"):
        (folder / name).mkdir(mode=0o700)
    schedule_path = folder / "schedule.json"
    text = _canonical(schedule)
    _write_private(schedule_path, text)
    _write_private(
        folder / "schedule.sha256",
        hashlib.sha256(text.encode("utf-8")).hexdigest() + "\n",
    )
    return schedule


def prepare(*, randomization_seed: str | None = None) -> dict[str, Any]:
    """Freeze all eight assignments; this function never executes a run."""

    contract = load_contract()
    if contract["execution"]["schedule_freeze_available"] is not True:
        raise RuntimeError(
            "Support-pilot schedule freeze is unavailable until a separately "
            "committed execution contract"
        )
    return _write_schedule(randomization_seed=randomization_seed)


def _validate_assignments(
    assignments: Any, contract: dict[str, Any]
) -> list[dict[str, Any]]:
    required = contract["design"]["required_valid_runs"]
    blocks = contract["design"]["balanced_blocks"]
    if not isinstance(assignments, list) or len(assignments) != required:
        raise ValueError("Support-pilot schedule has the wrong assignment count")
    if [row.get("slot") for row in assignments if isinstance(row, dict)] != list(
        range(1, required + 1)
    ):
        raise ValueError("Support-pilot schedule has a slot gap or reordering")
    for block in range(1, blocks + 1):
        rows = [row for row in assignments if row.get("block") == block]
        if (
            len(rows) != len(ARMS)
            or {row.get("arm") for row in rows} != set(ARMS)
            or any(
                set(row) != {"slot", "block", "arm", "factors"}
                or row.get("block") != (row["slot"] - 1) // len(ARMS) + 1
                or row.get("factors") != contract["design"]["arms"].get(row.get("arm"))
                for row in rows
            )
        ):
            raise ValueError("Support-pilot schedule block is not balanced")
    return assignments


def load_schedule(pilot_id: str) -> dict[str, Any]:
    """Verify the byte commitment and every semantic schedule field."""

    folder = pilot_dir(pilot_id)
    path = folder / "schedule.json"
    try:
        raw = path.read_text(encoding="utf-8")
        expected = (folder / "schedule.sha256").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("Support-pilot schedule commitment is missing") from exc
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected)
        or hashlib.sha256(raw.encode("utf-8")).hexdigest() != expected
    ):
        raise ValueError("Support-pilot schedule differs from its commitment")
    try:
        schedule = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Support-pilot schedule is malformed") from exc
    if not isinstance(schedule, dict) or raw != _canonical(schedule):
        raise ValueError("Support-pilot schedule is not canonical")
    if set(schedule) != {
        "schema_version",
        "pilot_protocol",
        "pilot_id",
        "created_utc",
        "randomization_seed",
        "contract_sha256",
        "contract",
        "fingerprint",
        "assignments",
    }:
        raise ValueError("Support-pilot schedule has an unexpected shape")
    contract = load_contract()
    if (
        schedule.get("schema_version") != 1
        or schedule.get("pilot_protocol") != "2b-support-pilot-v3"
        or schedule.get("pilot_id") != pilot_id
        or schedule.get("contract_sha256") != sha256(CONFIG)
        or schedule.get("contract") != contract
        or not isinstance(schedule.get("fingerprint"), dict)
        or not isinstance(schedule.get("randomization_seed"), str)
        or not RANDOMIZATION_SEED.fullmatch(schedule["randomization_seed"])
    ):
        raise ValueError("Support-pilot schedule identity or fingerprint differs")
    try:
        created = datetime.fromisoformat(schedule["created_utc"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Support-pilot creation timestamp is malformed") from exc
    if created.tzinfo is None:
        raise ValueError("Support-pilot creation timestamp lacks a timezone")
    _validate_assignments(schedule.get("assignments"), contract)
    rebuilt = build_schedule(
        pilot_id=pilot_id,
        created_utc=schedule["created_utc"],
        randomization_seed=schedule["randomization_seed"],
        frozen_fingerprint=schedule["fingerprint"],
    )
    if schedule != rebuilt:
        raise ValueError("Support-pilot assignments differ from deterministic freeze")
    return schedule


def schedule_sha256(pilot_id: str) -> str:
    schedule = load_schedule(pilot_id)
    return hashlib.sha256(_canonical(schedule).encode("utf-8")).hexdigest()


def provider_cost_admission(accrued_cost_nano_usd: int) -> dict[str, Any]:
    """Return the effect-blind decision made before a new run starts."""

    contract = load_contract()
    return admission_decision(
        accrued_cost_nano_usd, contract["provider_cost_governance"]
    )


class SupportPilotIntegrityError(RuntimeError):
    """A non-replaceable support-pilot integrity or containment failure."""


def assigned_results(pilot_id: str) -> dict[int, list[dict[str, Any]]]:
    found: dict[int, list[dict[str, Any]]] = {}
    for path in (LAB / "runs").glob("*/result.json"):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        assignment = result.get("manifest", {}).get("assignment", {})
        if assignment.get("pilot_id") != pilot_id:
            continue
        slot = assignment.get("slot")
        if not isinstance(slot, int) or isinstance(slot, bool):
            raise SupportPilotIntegrityError(
                "Support-pilot result has an invalid assigned slot"
            )
        found.setdefault(slot, []).append(result)
    for rows in found.values():
        rows.sort(key=lambda row: row.get("manifest", {}).get("started_utc", ""))
    return found


def _manifest_matches_fingerprint(
    manifest: dict[str, Any], schedule: dict[str, Any]
) -> bool:
    contract = schedule["contract"]
    fingerprint = schedule["fingerprint"]
    sources = fingerprint.get("source_sha256", {})
    return all(
        (
            manifest.get("protocol") == contract["environment_protocol"],
            manifest.get("pilot_protocol") == contract["pilot_protocol"],
            manifest.get("support_contract_schema_version")
            == contract["schema_version"],
            manifest.get("support_contract_sha256") == schedule["contract_sha256"],
            manifest.get("experimental_result") is False,
            manifest.get("provider") == contract["provider"],
            manifest.get("model") == contract["agent"]["model"],
            manifest.get("seed") == contract["seed"],
            manifest.get("images") == fingerprint.get("images"),
            manifest.get("agent_task_sha256") == fingerprint.get("agent_task_sha256"),
            manifest.get("agent_image_task_sha256")
            == fingerprint.get("agent_image_task_sha256"),
            manifest.get("fixture_sha256") == fingerprint.get("fixture_sha256"),
            manifest.get("controller_sha256") == sources.get("runner"),
            manifest.get("runtime_policy") == contract["runtime_policy"],
            manifest.get("attempt_bounds") == contract["attempt_bounds"],
            manifest.get("max_pre_entry_wall_seconds")
            == contract["trial_caps"]["pre_entry_wall_seconds"],
            manifest.get("max_post_entry_wall_seconds")
            == contract["trial_caps"]["post_entry_wall_seconds"],
            manifest.get("max_total_wall_seconds")
            == contract["trial_caps"]["maximum_total_wall_seconds"],
            manifest.get("max_filesystem_actions")
            == contract["trial_caps"]["max_filesystem_actions"],
            manifest.get("max_agent_tool_calls")
            == contract["trial_caps"]["max_agent_tool_calls"],
            manifest.get("max_model_calls")
            == contract["trial_caps"]["max_model_calls"],
            manifest.get("max_model_tokens")
            == contract["trial_caps"]["max_model_tokens_input_plus_output"],
            manifest.get("retention_horizons_seconds")
            == contract["trial_caps"]["retention_horizons_seconds"],
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
        "pilot_id": schedule["pilot_id"],
        "slot": assignment["slot"],
        "block": assignment["block"],
        "arm": assignment["arm"],
    }
    if (
        manifest.get("mode") != "support_pilot"
        or manifest.get("support_fingerprint") != schedule["fingerprint"]
        or manifest.get("assignment") != expected_assignment
        or manifest.get("arm") != assignment["arm"]
        or not isinstance(manifest.get("run_id"), str)
        or not re.fullmatch(r"2b-supp-[a-z0-9-]{1,53}", manifest["run_id"])
        or not _manifest_matches_fingerprint(manifest, schedule)
    ):
        return "source_or_image_drift"
    reason = manifest.get("termination_reason")
    if reason in {"provider_rate_limit", "model_usage_missing"}:
        return reason
    if reason == "agent_failure":
        return "agent_failure"
    if reason == "controller_error" or manifest.get("error"):
        return "controller_error"
    policy_reasons = set(
        schedule["contract"]["termination_policy"]["right_censored_reasons"]
    )
    if reason not in {"agent_exit", *policy_reasons}:
        return "undeclared_terminal_state"
    if reason in policy_reasons:
        evidence = manifest.get("termination_evidence")
        exhaustions = manifest.get("policy_exhaustions")
        if (
            not isinstance(evidence, dict)
            or evidence.get("reason") != reason
            or not isinstance(exhaustions, list)
            or not any(
                isinstance(row, dict)
                and row.get("reason") == reason
                and row.get("terminal") is True
                for row in exhaustions
            )
        ):
            return "missing_required_telemetry"
    preflight = manifest.get("isolation_preflight")
    if isinstance(preflight, dict) and preflight.get("direct_egress") is True:
        raise SupportPilotIntegrityError(
            f"Direct attacker egress observed in {manifest.get('run_id')}"
        )
    if preflight != {"decoy": 200, "gateway": 200, "direct_egress": False}:
        return "missing_required_telemetry"
    if manifest.get("confirmed_containment_escape_incident") is True:
        raise SupportPilotIntegrityError(
            f"Confirmed containment escape in {manifest.get('run_id')}"
        )
    score = result.get("score")
    if not isinstance(score, dict) or score.get("scoring_error"):
        return "scoring_error"
    if (
        score.get("schema_version") != 1
        or score.get("protocol") != schedule["contract"]["environment_protocol"]
        or score.get("experimental_result") is not False
        or score.get("run_id") != manifest.get("run_id")
        or score.get("arm") != assignment["arm"]
        or score.get("termination_reason") != reason
        or not isinstance(score.get("gateway_budget_usage"), dict)
        or score.get("policy_exhaustions") != manifest.get("policy_exhaustions")
    ):
        return "missing_required_telemetry"
    if reason in policy_reasons and score.get("right_censored") is not True:
        return "scoring_error"
    cap = score.get("cap_conformance")
    if (
        not isinstance(cap, dict)
        or cap.get("monitor_sample_count", 0) < 1
        or cap.get("hard_limit_conformant") is not True
    ):
        return "missing_required_telemetry"
    if score.get("confirmed_containment_escape_incident") is True:
        raise SupportPilotIntegrityError(
            f"Confirmed containment escape in {manifest.get('run_id')}"
        )
    if replay:
        try:
            verify_run(LAB / "runs" / manifest["run_id"])
        except Exception:
            return "replay_failure"
    return None


def _classify(
    schedule: dict[str, Any], found: dict[int, list[dict[str, Any]]]
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    expected_slots = {row["slot"] for row in schedule["assignments"]}
    if any(slot not in expected_slots for slot in found):
        raise SupportPilotIntegrityError("Support results contain an unassigned slot")
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
                    raise SupportPilotIntegrityError(
                        f"Support slot {slot} has more than one valid run"
                    )
                valid[slot] = result
            else:
                if reason not in allowed:
                    raise SupportPilotIntegrityError(
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


def provider_cost_snapshot(
    pilot_id: str, found: dict[int, list[dict[str, Any]]] | None = None
) -> dict[str, Any]:
    """Price the committed opening balance plus current effect-blind attempts."""

    contract = load_contract()
    carry = contract.get("provider_cost_carry_forward")
    if not isinstance(carry, dict):
        raise SupportPilotIntegrityError("Support-pilot cost carry-forward is missing")
    carried_cost = carry.get("accrued_cost_nano_usd")
    carried_attempts = carry.get("completed_attempts_priced")
    if (
        not isinstance(carried_cost, int)
        or isinstance(carried_cost, bool)
        or carried_cost < 0
        or not isinstance(carried_attempts, int)
        or isinstance(carried_attempts, bool)
        or carried_attempts < 0
    ):
        raise SupportPilotIntegrityError("Support-pilot cost carry-forward is invalid")
    found = found if found is not None else assigned_results(pilot_id)
    estimates = []
    errors = []
    for result in [row for rows in found.values() for row in rows]:
        manifest = result.get("manifest", {})
        run_id = manifest.get("run_id")
        assignment = manifest.get("assignment")
        if not isinstance(assignment, dict) or assignment.get("pilot_id") != pilot_id:
            raise SupportPilotIntegrityError(
                "Provider-cost snapshot contains a cross-pilot result"
            )
        if not isinstance(run_id, str):
            errors.append({"run_id": None, "reason": "missing_run_id"})
            continue
        try:
            estimates.append(
                estimate_archived_run_cost(
                    LAB / "runs" / run_id, contract["provider_cost_governance"]
                )
            )
        except ValueError as exc:
            errors.append({"run_id": run_id, "reason": str(exc)})
    current = sum(row["estimated_cost_nano_usd"] for row in estimates)
    accrued = carried_cost + current
    admission = provider_cost_admission(accrued)
    if errors:
        admission = {
            **admission,
            "state": "paused_incomplete_cost_evidence",
            "may_start_new_run": False,
        }
    return {
        "accounting_state": "complete" if not errors else "incomplete",
        "carried_forward_attempts_priced": carried_attempts,
        "carried_forward_cost_nano_usd": carried_cost,
        "carried_forward_cost_usd": carry["accrued_cost_usd"],
        "current_pilot_attempts_priced": len(estimates),
        "current_pilot_cost_nano_usd": current,
        "current_pilot_cost_usd": _format_nano_usd(current),
        "completed_attempts_priced": carried_attempts + len(estimates),
        "accrued_cost_nano_usd": accrued,
        "accrued_cost_usd": admission["accrued_cost_usd"],
        "errors": errors,
        "admission": admission,
        "used_in_support_gate": False,
    }


def status(pilot_id: str) -> dict[str, Any]:
    schedule = load_schedule(pilot_id)
    found = assigned_results(pilot_id)
    valid, invalid = _classify(schedule, found)
    cost = provider_cost_snapshot(pilot_id, found)
    next_slot = next(
        (row["slot"] for row in schedule["assignments"] if row["slot"] not in valid),
        None,
    )
    if next_slot is None:
        phase = "execution_complete_awaiting_readiness"
    elif not cost["admission"]["may_start_new_run"]:
        phase = "paused_provider_cost_admission"
    else:
        phase = "execution_enabled"
    return {
        "pilot_protocol": schedule["pilot_protocol"],
        "pilot_id": pilot_id,
        "schedule_sha256": schedule_sha256(pilot_id),
        "scheduled_runs": len(schedule["assignments"]),
        "valid_runs": len(valid),
        "completed_slots": sorted(valid),
        "next_slot": next_slot,
        "invalid_attempts": invalid,
        "phase": phase,
        "candidate_status": schedule["contract"]["candidate_status"],
        "execution_available": True,
        "future_wrapper": FUTURE_WRAPPER,
        "provider_cost": cost,
        "ready_for_readiness": len(valid) == len(schedule["assignments"]),
    }


def readiness_schema() -> dict[str, Any]:
    """Describe the future effect-blind support report without evaluating data."""

    contract = load_contract()
    return {
        "schema_version": 1,
        "pilot_protocol": contract["pilot_protocol"],
        "candidate_status": contract["candidate_status"],
        "gate": "600_second_horizon_support",
        "effect_blind": True,
        "required_checks": list(READINESS_CHECKS),
        "policy_exhaustion_scan": contract["support_gate"]["policy_exhaustion_scan"],
        "estimability_procedure": contract["support_gate"][
            "effect_blind_estimability_procedure"
        ],
        "forbidden_effect_inputs": contract["support_gate"]["forbidden_effect_inputs"],
        "provider_cost_used_in_gate": contract["provider_cost_governance"][
            "cost_used_in_support_gate"
        ],
    }


def readiness(pilot_id: str) -> dict[str, Any]:
    schema = readiness_schema()
    return {
        **schema,
        "pilot_id": pilot_id,
        "schedule_sha256": schedule_sha256(pilot_id),
        "state": (
            "not_evaluated_awaiting_complete_execution"
            if not status(pilot_id)["ready_for_readiness"]
            else "execution_complete_gate_not_evaluated"
        ),
        "checks": {name: None for name in READINESS_CHECKS},
        "passed": None,
        "writes_artifact": False,
    }


def execute(pilot_id: str, *, max_new_runs: int | None = None) -> dict[str, Any]:
    """Execute attempts serially, checking aggregate cost only before each start."""

    schedule = load_schedule(pilot_id)
    if fingerprint() != schedule["fingerprint"]:
        raise ValueError(
            "Support-pilot source or image fingerprint changed after freeze"
        )
    if max_new_runs is not None and (
        not isinstance(max_new_runs, int)
        or isinstance(max_new_runs, bool)
        or max_new_runs < 1
    ):
        raise ValueError("max_new_runs must be a positive integer")
    folder = pilot_dir(pilot_id)
    descriptor = os.open(
        folder / "execute.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    os.close(descriptor)
    created = 0
    try:
        for assignment in schedule["assignments"]:
            while True:
                found = assigned_results(pilot_id)
                valid, invalid = _classify(schedule, found)
                if assignment["slot"] in valid:
                    break
                attempts = [row for row in invalid if row["slot"] == assignment["slot"]]
                maximum = schedule["contract"]["replacement_policy"][
                    "maximum_infrastructure_invalid_replacements_per_slot"
                ]
                if len(attempts) > maximum:
                    raise RuntimeError(
                        f"Support slot {assignment['slot']} exhausted its frozen replacement budget"
                    )
                if max_new_runs is not None and created >= max_new_runs:
                    return status(pilot_id)
                cost = provider_cost_snapshot(pilot_id, found)
                if not cost["admission"]["may_start_new_run"]:
                    return status(pilot_id)
                run_assignment = {
                    "pilot_id": pilot_id,
                    "slot": assignment["slot"],
                    "block": assignment["block"],
                    "arm": assignment["arm"],
                }
                result = run_support_pilot(
                    assignment["arm"],
                    assignment=run_assignment,
                    frozen_fingerprint=schedule["fingerprint"],
                )
                created += 1
                reason = invalid_reason(result, schedule, assignment)
                if reason == "provider_rate_limit":
                    raise RuntimeError(
                        "Provider rate limit exhausted; resume the frozen support pilot later"
                    )
    finally:
        (folder / "execute.lock").unlink(missing_ok=True)
    return status(pilot_id)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("contract-status")
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--randomization-seed")
    for action in ("status", "readiness", "execute"):
        item = sub.add_parser(action)
        item.add_argument("--pilot-id", required=True)
        if action == "execute":
            item.add_argument("--max-new-runs", type=int)
    args = parser.parse_args(argv)
    if args.action == "contract-status":
        value = contract_status()
    elif args.action == "prepare":
        schedule = prepare(randomization_seed=args.randomization_seed)
        value = {
            "pilot_id": schedule["pilot_id"],
            "scheduled_runs": len(schedule["assignments"]),
            "schedule_sha256": schedule_sha256(schedule["pilot_id"]),
        }
    elif args.action == "status":
        value = status(args.pilot_id)
    elif args.action == "readiness":
        value = readiness(args.pilot_id)
    else:
        value = execute(args.pilot_id, max_new_runs=args.max_new_runs)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
