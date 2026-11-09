"""Continue frozen v5 assignments as a separate, operator-governed diagnostic.

The parent v5 pilot and its results remain unchanged. This successor reuses
its verified assignment, task, images, runner and caps, but does not impose
the parent's five-hour provider-429 pause. Each attempt requires an explicit
execute call and the unchanged local credit-share reserve. Diagnostic results
never fill a parent v5 slot.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any

from experiment_controller import path_story_pilot_2b_v2 as prior
from experiment_controller import path_story_pilot_2b_zai_v5 as parent
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits
from telemetry.replay_2b_path_story import verify_path_story_bundle


LAB = Path(__file__).resolve().parents[1]
STUDIES = LAB / "studies"
PARENT_PILOT_ID = "2b-path-story-pilot-v5-zai-20261109154540-d08c59"
PILOT_ID = "2b-path-story-pilot-diagnostic-v1-20261109154540-d08c59"
PROTOCOL = "2b-path-story-pilot-diagnostic-v1"
SCHEDULE = STUDIES / PILOT_ID / "schedule.json"


class DiagnosticIntegrityError(RuntimeError):
    """A signed diagnostic input or cost record differs from its evidence."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _utc(value: str) -> datetime:
    return parent._utc(value)


def _folder() -> Path:
    return SCHEDULE.parent


def _parent() -> tuple[dict[str, Any], dict[str, Any]]:
    """Recheck the original freeze and every original attempt, without executing."""
    schedule = parent.load_schedule(PARENT_PILOT_ID)
    state = parent.status(PARENT_PILOT_ID)
    if state.get("pending_run") is not None:
        raise DiagnosticIntegrityError("The parent pilot has an unresolved pending attempt")
    return schedule, state


def prepare() -> dict[str, Any]:
    """Sign the six remaining parent assignments; make no provider request."""
    if SCHEDULE.exists() or SCHEDULE.with_suffix(".sha256").exists():
        return status()
    original, state = _parent()
    if state.get("completed_slots") != [1, 2] or state.get("next_slot") != 3:
        raise DiagnosticIntegrityError("Parent v5 is no longer at the approved continuation point")
    assignments = [dict(row) for row in original["assignments"] if row["slot"] >= 3]
    if len(assignments) != 6 or assignments[0].get("arm") != "B3":
        raise DiagnosticIntegrityError("Parent continuation assignment differs")
    study = {
        "schema_version": 1,
        "pilot_id": PILOT_ID,
        "pilot_protocol": PROTOCOL,
        "parent_pilot_id": PARENT_PILOT_ID,
        "parent_schedule_sha256": _sha(parent._folder(PARENT_PILOT_ID) / "schedule.json"),
        "parent_completed_slots_at_freeze": state["completed_slots"],
        "parent_invalid_attempts_at_freeze": state["invalid_attempts"],
        "contract": original["contract"],
        "assignments": assignments,
        "diagnostic_controller_sha256": _sha(Path(__file__)),
        "execution_policy": {
            "single_explicit_attempt_per_execute": True,
            "five_hour_429_pause": False,
            "operator_stop_is_invalid": True,
            "provider_429_is_invalid": True,
            "infrastructure_invalid_replacement_limit": None,
            "parent_v5_slots_carried_forward": 0,
            "credit_reserve_from_parent_and_diagnostic_attempts": True,
        },
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    prior._write_committed(SCHEDULE, study)
    (_folder() / "admissions").mkdir(mode=0o700, exist_ok=True)
    (_folder() / "operator-stops").mkdir(mode=0o700, exist_ok=True)
    return status()


def _schedule() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    study = prior._read_committed(SCHEDULE)
    original, state = _parent()
    expected_assignments = [dict(row) for row in original["assignments"] if row["slot"] >= 3]
    if (
        study.get("schema_version") != 1
        or study.get("pilot_id") != PILOT_ID
        or study.get("pilot_protocol") != PROTOCOL
        or study.get("parent_pilot_id") != PARENT_PILOT_ID
        or study.get("parent_schedule_sha256") != _sha(parent._folder(PARENT_PILOT_ID) / "schedule.json")
        or study.get("assignments") != expected_assignments
        or study.get("parent_completed_slots_at_freeze") != [1, 2]
        or study.get("parent_invalid_attempts_at_freeze") != state.get("invalid_attempts")
        or study.get("contract") != original["contract"]
        or state.get("completed_slots") != [1, 2]
        or state.get("next_slot") != 3
        or study.get("diagnostic_controller_sha256") != _sha(Path(__file__))
        or study.get("execution_policy") != {
            "single_explicit_attempt_per_execute": True,
            "five_hour_429_pause": False,
            "operator_stop_is_invalid": True,
            "provider_429_is_invalid": True,
            "infrastructure_invalid_replacement_limit": None,
            "parent_v5_slots_carried_forward": 0,
            "credit_reserve_from_parent_and_diagnostic_attempts": True,
        }
    ):
        raise DiagnosticIntegrityError("Frozen diagnostic continuation differs")
    return study, original, state


def _operator_stop(run_id: str, slot: int, manifest: dict[str, Any]) -> bool:
    request_path = _folder() / "operator-stops" / f"{run_id}.request.json"
    if not request_path.exists() and not request_path.with_suffix(".sha256").exists():
        return False
    request = prior._read_committed(request_path)
    if (
        request.get("schema_version") != 1
        or request.get("pilot_id") != PILOT_ID
        or request.get("run_id") != run_id
        or request.get("slot") != slot
        or request.get("actor") != "local_dashboard"
        or request.get("reason") != "operator_stop"
        or request.get("project") != manifest.get("project")
        or not isinstance(request.get("container_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", request["container_id"]) is None
        or _utc(request.get("requested_utc")) < _utc(manifest.get("started_utc"))
        or _utc(request.get("requested_utc")) > _utc(manifest.get("finished_utc"))
    ):
        raise DiagnosticIntegrityError("Operator stop request differs from archived attempt")
    outcome_path = _folder() / "operator-stops" / f"{run_id}.outcome.json"
    if outcome_path.exists() or outcome_path.with_suffix(".sha256").exists():
        outcome = prior._read_committed(outcome_path)
        if (
            outcome.get("schema_version") != 1
            or outcome.get("pilot_id") != PILOT_ID
            or outcome.get("run_id") != run_id
            or outcome.get("slot") != slot
            or outcome.get("request_sha256") != _sha(request_path)
            or outcome.get("state") not in {
                "stop_command_succeeded", "container_already_stopped", "stop_failed"
            }
            or _utc(outcome.get("completed_utc")) < _utc(request["requested_utc"])
            or (outcome.get("state") == "stop_failed") != isinstance(outcome.get("error"), str)
            or (outcome.get("state") == "stop_failed" and outcome.get("docker_exit_code") != 1)
            or (outcome.get("state") == "stop_command_succeeded" and outcome.get("docker_exit_code") != 0)
            or (outcome.get("state") == "container_already_stopped" and outcome.get("docker_exit_code") is not None)
        ):
            raise DiagnosticIntegrityError("Operator stop outcome differs from request")
    return True


def _attempts(study: dict[str, Any], original: dict[str, Any]) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    found = prior._results(PILOT_ID)
    valid: dict[int, dict[str, Any]] = {}
    invalid: list[dict[str, Any]] = []
    priced: list[dict[str, Any]] = []
    assignments = {row["slot"]: row for row in study["assignments"]}
    if set(found) - set(assignments):
        raise DiagnosticIntegrityError("Diagnostic result is outside frozen assignments")
    for slot, assignment in assignments.items():
        for result in found.get(slot, []):
            if slot in valid:
                raise DiagnosticIntegrityError("Diagnostic slot was retried after a valid attempt")
            manifest = result["manifest"]
            run_dir = prior._verify_attempt_artifacts(result)
            expected_assignment = {key: assignment[key] for key in ("slot", "block", "arm", "seed")}
            expected_assignment["pilot_id"] = PILOT_ID
            if (
                manifest.get("assignment") != expected_assignment
                or manifest.get("pilot_protocol") != parent.PROTOCOL
                or manifest.get("provider") != "zai"
                or manifest.get("pilot_fingerprint") != original["fingerprint"]
            ):
                raise DiagnosticIntegrityError("Diagnostic attempt differs from frozen parent assignment")
            if manifest.get("confirmed_containment_escape_incident") is True:
                raise DiagnosticIntegrityError("Confirmed containment escape incident")
            admission_path = _folder() / "admissions" / f"{manifest['run_id']}.json"
            admission = prior._read_committed(admission_path)
            if (
                admission.get("pilot_id") != PILOT_ID
                or admission.get("pilot_protocol") != PROTOCOL
                or admission.get("schedule_sha256") != _sha(SCHEDULE)
                or admission.get("run_id") != manifest["run_id"]
                or admission.get("slot") != slot
                or admission.get("credits", {}).get("may_start_new_run") is not True
                or _utc(admission.get("created_utc")) > _utc(manifest.get("started_utc"))
            ):
                raise DiagnosticIntegrityError("Diagnostic attempt lacks matching admission")
            gateway = [json.loads(line) for line in (run_dir / "gateway-events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            if any(row.get("event_type") == "gateway_error" for row in gateway):
                raise DiagnosticIntegrityError("Unpriced gateway error requires reconciliation")
            credits = estimate_gateway_events_credits(gateway)
            if result.get("provider_credits") != credits or manifest.get("provider_credits") != credits:
                raise DiagnosticIntegrityError("Diagnostic credits differ from gateway usage")
            priced.append({"run_id": manifest["run_id"], "finished_utc": manifest["finished_utc"],
                           "credits": Decimal(credits["estimated_total_credits"])})
            stopped = _operator_stop(manifest["run_id"], slot, manifest)
            reason = None
            if stopped:
                reason = "operator_stop"
            elif any(row.get("event_type") in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"} for row in gateway):
                reason = "provider_rate_limit"
            elif manifest.get("error") or manifest.get("provider_credit_error") or manifest.get("path_story_evidence_error"):
                reason = "controller_error"
            elif not isinstance(manifest.get("provider_settlement"), dict) or manifest["provider_settlement"].get("state") != "complete":
                reason = "missing_required_telemetry"
            elif manifest.get("termination_reason") in {"agent_failure", "controller_error"}:
                reason = manifest["termination_reason"]
            elif manifest.get("termination_reason") not in prior.TERMINAL_REASONS:
                reason = "undeclared_terminal_state"
            else:
                try:
                    if result.get("replay") != verify_path_story_bundle(run_dir):
                        reason = "replay_failure"
                except Exception:
                    reason = "replay_failure"
            if reason is None:
                if slot in valid:
                    raise DiagnosticIntegrityError("Diagnostic slot has two valid attempts")
                valid[slot] = result
            else:
                invalid.append({"slot": slot, "run_id": manifest["run_id"], "reason": reason})
    return valid, invalid, priced


def _credits(parent_state: dict[str, Any], priced: list[dict[str, Any]]) -> dict[str, Any]:
    """Add diagnostic exposure to the fully verified parent's local share."""
    baseline = parent_state.get("credits")
    if not isinstance(baseline, dict) or baseline.get("accounting_kind") != "estimated_from_reported_usage":
        raise DiagnosticIntegrityError("Parent credit accounting is unavailable")
    now = datetime.now(timezone.utc)
    total = Decimal(str(baseline["accrued_total"]))
    rolling = Decimal(str(baseline["accrued_rolling_five_hour"]))
    for row in priced:
        value = row.get("credits")
        if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
            raise DiagnosticIntegrityError("Diagnostic attempt credits are invalid")
        age = now - _utc(row["finished_utc"])
        if age < timedelta(0):
            raise DiagnosticIntegrityError("Diagnostic attempt finish is in the future")
        total += value
        if age < parent.FIVE_HOURS:
            rolling += value
    remaining_total = max(Decimal(0), parent.TOTAL_SHARE - total)
    remaining_rolling = max(Decimal(0), parent.FIVE_HOUR_SHARE - rolling)
    admitted = remaining_total >= parent.MINIMUM_RESERVE and remaining_rolling >= parent.MINIMUM_RESERVE
    return {
        "accounting_kind": "estimated_from_reported_usage",
        "plan_tier": "Max",
        "pilot_total_share": str(parent.TOTAL_SHARE),
        "pilot_five_hour_share": str(parent.FIVE_HOUR_SHARE),
        "minimum_uncommitted_per_new_run": str(parent.MINIMUM_RESERVE),
        "accrued_total": format(total, ".9f"),
        "accrued_rolling_five_hour": format(rolling, ".9f"),
        "remaining_total": format(remaining_total, ".9f"),
        "remaining_rolling_five_hour": format(remaining_rolling, ".9f"),
        "other_subscriber_usage_visible": False,
        "active_run_credit_termination_allowed": False,
        "admitted_by_local_share": admitted,
    }


def status() -> dict[str, Any]:
    study, original, parent_state = _schedule()
    valid, invalid, priced = _attempts(study, original)
    credits = _credits(parent_state, priced)
    pending_path = _folder() / "pending-run.json"
    if pending_path.exists() or pending_path.with_suffix(".sha256").exists():
        pending = prior._read_committed(pending_path)
    else:
        pending = None
    if pending is not None:
        if (
            pending.get("pilot_id") != PILOT_ID
            or pending.get("pilot_protocol") != PROTOCOL
            or pending.get("schedule_sha256") != _sha(SCHEDULE)
            or pending.get("slot") not in {row["slot"] for row in study["assignments"]}
            or not isinstance(pending.get("run_id"), str)
            or prior.RUN_ID.fullmatch(pending["run_id"]) is None
            or pending != prior._read_committed(_folder() / "admissions" / f"{pending['run_id']}.json")
        ):
            raise DiagnosticIntegrityError("Pending diagnostic admission differs")
    next_slot = next((row["slot"] for row in study["assignments"] if row["slot"] not in valid), None)
    if pending:
        phase = "pending_attempt_reconciliation"
    elif next_slot is None:
        phase = "complete"
    elif not credits["admitted_by_local_share"]:
        phase = "paused_credit_share_admission"
    else:
        phase = "ready_for_next_run"
    return {
        "pilot_id": PILOT_ID,
        "pilot_protocol": PROTOCOL,
        "parent_pilot_id": PARENT_PILOT_ID,
        "schedule_sha256": _sha(SCHEDULE),
        "scheduled_runs": len(study["assignments"]),
        "valid_runs": len(valid),
        "completed_slots": sorted(valid),
        "invalid_attempts": invalid,
        "next_slot": next_slot,
        "pending_run": pending,
        "phase": phase,
        "credits": {**credits, "may_start_new_run": phase == "ready_for_next_run"},
        "launch_available": phase == "ready_for_next_run",
        "launch_reason": None if phase == "ready_for_next_run" else phase.replace("_", " "),
        "parent_v5_phase": parent_state["phase"],
        "five_hour_429_pause_override": True,
    }


def execute() -> dict[str, Any]:
    """Start at most one signed diagnostic assignment after credit admission."""
    before = status()
    if before["phase"] != "ready_for_next_run":
        return before
    original = parent.load_schedule(PARENT_PILOT_ID)
    study = prior._read_committed(SCHEDULE)
    assignment = next(row for row in study["assignments"] if row["slot"] == before["next_slot"])
    lock = parent._folder(PARENT_PILOT_ID) / "execute.lock"
    prior._write_new(lock, b"")
    try:
        before = status()
        if before["phase"] != "ready_for_next_run":
            return before
        assignment = next(row for row in study["assignments"] if row["slot"] == before["next_slot"])
        now = datetime.now(timezone.utc)
        run_id = "2b-path-" + now.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        admission = {
            "schema_version": 1, "pilot_id": PILOT_ID, "pilot_protocol": PROTOCOL,
            "parent_pilot_id": PARENT_PILOT_ID,
            "schedule_sha256": before["schedule_sha256"],
            "parent_schedule_sha256": study["parent_schedule_sha256"],
            "run_id": run_id, "slot": assignment["slot"],
            "created_utc": now.isoformat(), "credits": before["credits"],
            "pause_override": "operator_authorized_diagnostic_no_five_hour_429_pause",
        }
        prior._write_committed(_folder() / "admissions" / f"{run_id}.json", admission)
        pending_path = _folder() / "pending-run.json"
        prior._write_committed(pending_path, admission)
        from experiment_controller.run_2b_path_story_pilot_zai_v5 import run_path_story_pilot

        run_path_story_pilot(
            pilot_id=PILOT_ID, slot=assignment["slot"], block=assignment["block"],
            arm=assignment["arm"], seed=assignment["seed"], run_id=run_id,
            frozen_fingerprint=original["fingerprint"], contract=original["contract"],
        )
        _verify_pending_archive(admission)
        pending_path.unlink()
        pending_path.with_suffix(".sha256").unlink()
        return status()
    finally:
        lock.unlink(missing_ok=True)


def _verify_pending_archive(pending: dict[str, Any]) -> None:
    run_id = pending.get("run_id")
    if not isinstance(run_id, str) or prior.RUN_ID.fullmatch(run_id) is None:
        raise DiagnosticIntegrityError("Pending diagnostic run ID is invalid")
    if not (LAB / "runs" / run_id / "result.json").is_file():
        raise DiagnosticIntegrityError("Pending diagnostic attempt has no archived result")
    study, original, _ = _schedule()
    found = prior._results(PILOT_ID)
    if not any(
        row["manifest"].get("run_id") == run_id
        for row in found.get(pending.get("slot"), [])
    ):
        raise DiagnosticIntegrityError("Pending diagnostic archive differs from admission")
    _attempts(study, original)


def reconcile_pending() -> dict[str, Any]:
    pending_path = _folder() / "pending-run.json"
    pending = prior._read_committed(pending_path)
    _verify_pending_archive(pending)
    pending_path.unlink()
    pending_path.with_suffix(".sha256").unlink()
    return status()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "status", "execute", "reconcile-pending"):
        action.add_parser(name)
    args = parser.parse_args()
    value = {
        "prepare": prepare,
        "status": status,
        "execute": execute,
        "reconcile-pending": reconcile_pending,
    }[args.action]()
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
