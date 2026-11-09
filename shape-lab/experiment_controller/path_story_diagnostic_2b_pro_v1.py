"""One B3 diagnostic replacement under a separate Pro credit-share contract.

The frozen v5 and Max diagnostic studies remain unchanged. An exact archived
401 attempt is carried as infrastructure-invalid. Its zero reported usage is
paired with the operator's report of no Charge Type usage; that report is not
misrepresented as an independently verified provider bill. Every execution
requires a new explicit call and uses the existing frozen runner and images.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import re
import secrets
from typing import Any

from experiment_controller import path_story_diagnostic_2b_v1 as previous
from experiment_controller import path_story_pilot_2b_v2 as committed
from experiment_controller import path_story_pilot_2b_zai_v5 as parent
from experiment_controller.run_2b_path_story_pilot_zai_v5 import _gateway_lifecycle
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits
from telemetry.replay_2b_path_story import verify_path_story_bundle


LAB = Path(__file__).resolve().parents[1]
PILOT_ID = "2b-path-story-pilot-diagnostic-v2-pro-20261109154540-d08c59"
PROTOCOL = "2b-path-story-pilot-diagnostic-v2-pro"
PARENT_PILOT_ID = previous.PARENT_PILOT_ID
PREVIOUS_PILOT_ID = previous.PILOT_ID
OLD_401_RUN_ID = "2b-path-20261109182802-55dab3"
SCHEDULE = LAB / "studies" / PILOT_ID / "schedule.json"
RECONCILIATION = SCHEDULE.parent / "auth-401-reconciliation.json"
FIVE_HOURS = timedelta(hours=5)
FIVE_HOUR_SHARE = Decimal(6000)
TOTAL_SHARE = Decimal(15000)
MINIMUM_RESERVE = Decimal(3000)
ATTESTATION = "Operator reported no Charge Type usage for the 2026-11-10 03:28-03:31 KST HTTP 401 attempt"


class ProDiagnosticIntegrityError(RuntimeError):
    """A frozen Pro input, admission, or archive differs from its evidence."""


def _sha(path: Path) -> str:
    return committed._sha(path)


def _utc(value: str) -> datetime:
    return parent._utc(value)


def _folder() -> Path:
    return SCHEDULE.parent


def _parent() -> tuple[dict[str, Any], dict[str, Any]]:
    schedule = parent.load_schedule(PARENT_PILOT_ID)
    state = parent.status(PARENT_PILOT_ID)
    if (state.get("completed_slots") != [1, 2] or state.get("next_slot") != 3
            or state.get("pending_run") is not None):
        raise ProDiagnosticIntegrityError("Parent v5 no longer has the approved B3 continuation")
    return schedule, state


def _pro_contract(original: dict[str, Any]) -> dict[str, Any]:
    contract = deepcopy(original["contract"])
    governance = contract.get("coding_plan_credit_governance")
    if not isinstance(governance, dict) or governance.get("plan_tier") != "Max":
        raise ProDiagnosticIntegrityError("Frozen parent credit governance differs")
    governance.update({
        "plan_tier": "Pro",
        "published_five_hour_credits": 12000,
        "published_weekly_credits": 60000,
        "pilot_five_hour_share_credits": 6000,
        "pilot_total_share_credits": 15000,
        "minimum_uncommitted_credits_per_new_run": 3000,
        "authorization_basis": "user_confirmed_pro_half_five_hour_quarter_weekly_2026-11-10",
        "pilot_total_reset": "none",
    })
    if governance.get("rate_revision") != "zai-glm-5.3-coding-plan-2026-11-09":
        raise ProDiagnosticIntegrityError("Frozen credit rate revision differs")
    return contract


def _old_401_evidence() -> dict[str, Any]:
    """Verify exact rejected request lifecycles and the original invalid result."""
    old_state = previous.status()
    if (old_state.get("completed_slots") != []
            or old_state.get("invalid_attempts") != [{
                "slot": 3, "run_id": OLD_401_RUN_ID, "reason": "controller_error",
            }]
            or old_state.get("pending_run") is not None):
        raise ProDiagnosticIntegrityError("Previous diagnostic attempts differ")
    found = committed._results(PREVIOUS_PILOT_ID)
    if set(found) != {3} or len(found[3]) != 1:
        raise ProDiagnosticIntegrityError("Previous diagnostic archive count differs")
    result = found[3][0]
    run_dir = committed._verify_attempt_artifacts(result)
    manifest = result["manifest"]
    old_schedule = committed._read_committed(previous.SCHEDULE)
    assignment = old_schedule["assignments"][0]
    expected_assignment = {"pilot_id": PREVIOUS_PILOT_ID,
                           **{key: assignment[key] for key in ("slot", "block", "arm", "seed")}}
    settlement = manifest.get("provider_settlement")
    if (
        run_dir.name != OLD_401_RUN_ID
        or manifest.get("run_id") != OLD_401_RUN_ID
        or manifest.get("pilot_id") != PREVIOUS_PILOT_ID
        or manifest.get("assignment") != expected_assignment
        or manifest.get("provider") != "zai"
        or manifest.get("termination_reason") != "controller_error"
        or manifest.get("error") != "Gateway request lifecycle did not settle"
        or manifest.get("confirmed_containment_escape_incident") is True
        or not isinstance(settlement, dict)
        or settlement.get("state") != "incomplete"
        or settlement.get("started_request_count") != 276
        or settlement.get("finished_request_count") != 276
        or settlement.get("provider_completed_request_count") != 0
        or settlement.get("local_rejection_request_count") != 0
        or settlement.get("unaccounted_request_ids") != list(range(1, 277))
        or settlement.get("unmatched_request_ids") != []
        or settlement.get("aborted_request_ids") != []
        or settlement.get("downstream_delivery_failed_ids") != []
        or result.get("replay") != verify_path_story_bundle(run_dir)
        or result["replay"].get("filesystem_actions") != 0
    ):
        raise ProDiagnosticIntegrityError("Previous 401 outcome differs")
    gateway_path = run_dir / "gateway-events.jsonl"
    rows = [json.loads(line) for line in gateway_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 1104 or [row.get("sequence") for row in rows] != list(range(1, 1105)):
        raise ProDiagnosticIntegrityError("Previous 401 gateway sequence differs")
    if any(row.get("run_id") != OLD_401_RUN_ID or row.get("source") != "model-gateway" for row in rows):
        raise ProDiagnosticIntegrityError("Previous 401 gateway identity differs")
    for request_id in range(1, 277):
        events = rows[(request_id - 1) * 4:request_id * 4]
        if [row.get("event_type") for row in events] != [
            "request_started", "model_call", "provider_response_complete", "request_finished",
        ] or any(row.get("request_id") != request_id for row in events):
            raise ProDiagnosticIntegrityError("Previous 401 request lifecycle differs")
        call, completion = events[1:3]
        if (call.get("status") != 401 or call.get("usage") is not None
                or call.get("call_number") != request_id or call.get("attempt_number") != 1
                or completion.get("status") != 401
                or completion.get("call_number") != request_id
                or completion.get("attempt_number") != 1
                or completion.get("usage_recorded") is not False):
            raise ProDiagnosticIntegrityError("Previous 401 response differs")
    lifecycle = _gateway_lifecycle(rows)
    if (lifecycle.get("unaccounted_request_ids") != list(range(1, 277))
            or lifecycle.get("provider_completed_request_count") != 0):
        raise ProDiagnosticIntegrityError("Previous 401 settlement differs")
    credits = estimate_gateway_events_credits(rows)
    if (credits.get("estimated_total_credits") != "0.000000000"
            or manifest.get("provider_credits") != credits
            or result.get("provider_credits") != credits):
        raise ProDiagnosticIntegrityError("Previous 401 reported usage differs")
    return {
        "schema_version": 1,
        "pilot_id": PILOT_ID,
        "pilot_protocol": PROTOCOL,
        "previous_pilot_id": PREVIOUS_PILOT_ID,
        "previous_schedule_sha256": _sha(previous.SCHEDULE),
        "run_id": OLD_401_RUN_ID,
        "slot": 3,
        "classification": "infrastructure_invalid_auth_rejection",
        "gateway_events_sha256": _sha(gateway_path),
        "attempt_manifest_sha256": _sha(run_dir / "attempt-manifest.json"),
        "result_sha256": _sha(run_dir / "result.json"),
        "request_count": 276,
        "provider_http_status": 401,
        "reported_usage_credits": "0.000000000",
        "operator_attested_no_charge": True,
        "operator_attestation": ATTESTATION,
        "provider_charge_independently_verified": False,
        "estimated_carry_forward_credits": "0.000000000",
        "old_archive_modified": False,
        "creates_behavioral_outcome": False,
        "controller_sha256": _sha(Path(__file__)),
    }


def _reconciliation() -> dict[str, Any]:
    recorded = committed._read_committed(RECONCILIATION)
    if recorded != _old_401_evidence():
        raise ProDiagnosticIntegrityError("Pro 401 reconciliation differs from raw evidence")
    return recorded


def prepare() -> dict[str, Any]:
    """Freeze one Pro B3 assignment and old 401 attestation; no model call."""
    if SCHEDULE.exists() or SCHEDULE.with_suffix(".sha256").exists():
        return status()
    expected = _old_401_evidence()
    if RECONCILIATION.exists() or RECONCILIATION.with_suffix(".sha256").exists():
        if committed._read_committed(RECONCILIATION) != expected:
            raise ProDiagnosticIntegrityError("Existing 401 reconciliation differs")
    else:
        committed._write_committed(RECONCILIATION, expected)
    original, state = _parent()
    assignment = dict(original["assignments"][2])
    if assignment.get("slot") != 3 or assignment.get("arm") != "B3":
        raise ProDiagnosticIntegrityError("Parent B3 assignment differs")
    study = {
        "schema_version": 1,
        "pilot_id": PILOT_ID,
        "pilot_protocol": PROTOCOL,
        "parent_pilot_id": PARENT_PILOT_ID,
        "parent_schedule_sha256": _sha(parent._folder(PARENT_PILOT_ID) / "schedule.json"),
        "predecessor_diagnostic_pilot_id": PREVIOUS_PILOT_ID,
        "predecessor_schedule_sha256": _sha(previous.SCHEDULE),
        "reconciliation_sha256": _sha(RECONCILIATION),
        "parent_completed_slots_at_freeze": state["completed_slots"],
        "fingerprint": original["fingerprint"],
        "contract": _pro_contract(original),
        "assignments": [assignment],
        "execution_policy": {
            "one_explicit_attempt_per_execute": True,
            "five_hour_429_pause": False,
            "provider_429_is_invalid": True,
            "operator_stop_is_invalid": True,
            "old_401_is_carried_invalid_only": True,
            "active_run_credit_termination_allowed": False,
            "pro_five_hour_share_credits": 6000,
            "pro_one_time_share_credits": 15000,
            "minimum_uncommitted_credits_per_new_run": 3000,
        },
        "controller_sha256": _sha(Path(__file__)),
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    committed._write_committed(SCHEDULE, study)
    (_folder() / "admissions").mkdir(mode=0o700, exist_ok=True)
    (_folder() / "operator-stops").mkdir(mode=0o700, exist_ok=True)
    return status()


def _schedule() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    study = committed._read_committed(SCHEDULE)
    reconciliation = _reconciliation()
    original, parent_state = _parent()
    assignment = dict(original["assignments"][2])
    if (
        study.get("schema_version") != 1
        or study.get("pilot_id") != PILOT_ID
        or study.get("pilot_protocol") != PROTOCOL
        or study.get("parent_pilot_id") != PARENT_PILOT_ID
        or study.get("parent_schedule_sha256") != _sha(parent._folder(PARENT_PILOT_ID) / "schedule.json")
        or study.get("predecessor_diagnostic_pilot_id") != PREVIOUS_PILOT_ID
        or study.get("predecessor_schedule_sha256") != _sha(previous.SCHEDULE)
        or study.get("reconciliation_sha256") != _sha(RECONCILIATION)
        or study.get("parent_completed_slots_at_freeze") != [1, 2]
        or study.get("fingerprint") != original["fingerprint"]
        or study.get("contract") != _pro_contract(original)
        or study.get("assignments") != [assignment]
        or study.get("execution_policy") != {
            "one_explicit_attempt_per_execute": True,
            "five_hour_429_pause": False,
            "provider_429_is_invalid": True,
            "operator_stop_is_invalid": True,
            "old_401_is_carried_invalid_only": True,
            "active_run_credit_termination_allowed": False,
            "pro_five_hour_share_credits": 6000,
            "pro_one_time_share_credits": 15000,
            "minimum_uncommitted_credits_per_new_run": 3000,
        }
        or study.get("controller_sha256") != _sha(Path(__file__))
        or reconciliation.get("run_id") != OLD_401_RUN_ID
    ):
        raise ProDiagnosticIntegrityError("Frozen Pro B3 schedule differs")
    return study, original, parent_state


def _operator_stop(run_id: str, manifest: dict[str, Any]) -> bool:
    path = _folder() / "operator-stops" / f"{run_id}.request.json"
    if not path.exists() and not path.with_suffix(".sha256").exists():
        return False
    request = committed._read_committed(path)
    if (
        request.get("schema_version") != 1
        or request.get("pilot_id") != PILOT_ID
        or request.get("run_id") != run_id
        or request.get("slot") != 3
        or request.get("actor") != "local_dashboard"
        or request.get("reason") != "operator_stop"
        or request.get("project") != manifest.get("project")
        or not isinstance(request.get("container_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", request["container_id"]) is None
        or _utc(request.get("requested_utc")) < _utc(manifest.get("started_utc"))
        or _utc(request.get("requested_utc")) > _utc(manifest.get("finished_utc"))
    ):
        raise ProDiagnosticIntegrityError("Pro operator stop request differs")
    outcome = _folder() / "operator-stops" / f"{run_id}.outcome.json"
    if outcome.exists() or outcome.with_suffix(".sha256").exists():
        row = committed._read_committed(outcome)
        if (
            row.get("schema_version") != 1
            or row.get("pilot_id") != PILOT_ID
            or row.get("run_id") != run_id
            or row.get("slot") != 3
            or row.get("request_sha256") != _sha(path)
            or row.get("state") not in {
                "stop_command_succeeded", "container_already_stopped", "stop_failed",
            }
            or _utc(row.get("completed_utc")) < _utc(request["requested_utc"])
            or (row.get("state") == "stop_failed") != isinstance(row.get("error"), str)
            or (row.get("state") == "stop_failed" and row.get("docker_exit_code") != 1)
            or (row.get("state") == "stop_command_succeeded" and row.get("docker_exit_code") != 0)
            or (row.get("state") == "container_already_stopped" and row.get("docker_exit_code") is not None)
        ):
            raise ProDiagnosticIntegrityError("Pro operator stop outcome differs")
    return True


def _attempts(study: dict[str, Any]) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]], bool]:
    found = committed._results(PILOT_ID)
    if set(found) - {3}:
        raise ProDiagnosticIntegrityError("Pro result is outside frozen B3 assignment")
    valid: dict[str, Any] | None = None
    invalid: list[dict[str, Any]] = []
    priced: list[dict[str, Any]] = []
    unreconciled_exposure = False
    assignment = study["assignments"][0]
    for result in found.get(3, []):
        if valid is not None:
            raise ProDiagnosticIntegrityError("Pro B3 was retried after a valid attempt")
        manifest = result["manifest"]
        run_dir = committed._verify_attempt_artifacts(result)
        expected_assignment = {"pilot_id": PILOT_ID,
                               **{key: assignment[key] for key in ("slot", "block", "arm", "seed")}}
        if (
            manifest.get("assignment") != expected_assignment
            or manifest.get("pilot_protocol") != parent.PROTOCOL
            or manifest.get("provider") != "zai"
            or manifest.get("pilot_fingerprint") != study["fingerprint"]
            or manifest.get("trial_caps") != study["contract"]["trial_caps"]
            or manifest.get("confirmed_containment_escape_incident") is True
        ):
            raise ProDiagnosticIntegrityError("Pro B3 archive differs from frozen assignment")
        admission = committed._read_committed(_folder() / "admissions" / f"{manifest['run_id']}.json")
        if (
            admission.get("pilot_id") != PILOT_ID
            or admission.get("pilot_protocol") != PROTOCOL
            or admission.get("schedule_sha256") != _sha(SCHEDULE)
            or admission.get("reconciliation_sha256") != _sha(RECONCILIATION)
            or admission.get("run_id") != manifest["run_id"]
            or admission.get("slot") != 3
            or admission.get("credits", {}).get("may_start_new_run") is not True
            or _utc(admission.get("created_utc")) > _utc(manifest.get("started_utc"))
        ):
            raise ProDiagnosticIntegrityError("Pro B3 attempt lacks matching admission")
        gateway = [json.loads(line) for line in (run_dir / "gateway-events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        if any(row.get("event_type") == "gateway_error" for row in gateway):
            unreconciled_exposure = True
        credits = estimate_gateway_events_credits(gateway)
        if result.get("provider_credits") != credits or manifest.get("provider_credits") != credits:
            raise ProDiagnosticIntegrityError("Pro B3 credits differ from gateway usage")
        priced.append({"run_id": manifest["run_id"], "finished_utc": manifest["finished_utc"],
                       "credits": Decimal(credits["estimated_total_credits"])})
        settlement = manifest.get("provider_settlement")
        if not isinstance(settlement, dict) or settlement.get("state") != "complete":
            unreconciled_exposure = True
        reason = None
        if _operator_stop(manifest["run_id"], manifest):
            reason = "operator_stop"
        elif any(row.get("event_type") in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"} for row in gateway):
            reason = "provider_rate_limit"
        elif manifest.get("error") or manifest.get("provider_credit_error") or manifest.get("path_story_evidence_error"):
            reason = "controller_error"
        elif unreconciled_exposure:
            reason = "missing_required_telemetry"
        elif manifest.get("termination_reason") in {"agent_failure", "controller_error"}:
            reason = manifest["termination_reason"]
        elif manifest.get("termination_reason") not in committed.TERMINAL_REASONS:
            reason = "undeclared_terminal_state"
        else:
            try:
                if result.get("replay") != verify_path_story_bundle(run_dir):
                    reason = "replay_failure"
            except Exception:
                reason = "replay_failure"
        if reason is None:
            valid = result
        else:
            invalid.append({"slot": 3, "run_id": manifest["run_id"], "reason": reason})
    return valid, invalid, priced, unreconciled_exposure


def _credits(parent_state: dict[str, Any], priced: list[dict[str, Any]]) -> dict[str, Any]:
    baseline = parent_state.get("credits")
    if not isinstance(baseline, dict) or baseline.get("accounting_kind") != "estimated_from_reported_usage":
        raise ProDiagnosticIntegrityError("Parent provider credit accounting is unavailable")
    now = datetime.now(timezone.utc)
    total = Decimal(str(baseline["accrued_total"]))
    rolling = Decimal(str(baseline["accrued_rolling_five_hour"]))
    for row in priced:
        value = row["credits"]
        if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
            raise ProDiagnosticIntegrityError("Pro attempt credits are invalid")
        age = now - _utc(row["finished_utc"])
        if age < timedelta(0):
            raise ProDiagnosticIntegrityError("Pro attempt finish is in the future")
        total += value
        if age < FIVE_HOURS:
            rolling += value
    remaining_total = max(Decimal(0), TOTAL_SHARE - total)
    remaining_rolling = max(Decimal(0), FIVE_HOUR_SHARE - rolling)
    admitted = remaining_total >= MINIMUM_RESERVE and remaining_rolling >= MINIMUM_RESERVE
    return {
        "accounting_kind": "estimated_from_reported_usage_plus_operator_attested_401_no_charge",
        "plan_tier": "Pro",
        "published_five_hour_credits": "12000",
        "published_weekly_credits": "60000",
        "pilot_five_hour_share": "6000",
        "pilot_total_share": "15000",
        "pilot_total_reset": "none",
        "minimum_uncommitted_per_new_run": "3000",
        "accrued_total": format(total, ".9f"),
        "accrued_rolling_five_hour": format(rolling, ".9f"),
        "remaining_total": format(remaining_total, ".9f"),
        "remaining_rolling_five_hour": format(remaining_rolling, ".9f"),
        "carried_401_reported_credits": "0.000000000",
        "carried_401_charge_basis": "operator_attested_no_Charge_Type_usage",
        "provider_charge_independently_verified": False,
        "other_subscriber_usage_visible": False,
        "active_run_credit_termination_allowed": False,
        "admitted_by_local_share": admitted,
    }


def status() -> dict[str, Any]:
    study, _original, parent_state = _schedule()
    valid, invalid, priced, unreconciled = _attempts(study)
    credits = _credits(parent_state, priced)
    pending_path = _folder() / "pending-run.json"
    pending = (committed._read_committed(pending_path)
               if pending_path.exists() or pending_path.with_suffix(".sha256").exists() else None)
    if pending is not None:
        if (
            pending.get("pilot_id") != PILOT_ID
            or pending.get("pilot_protocol") != PROTOCOL
            or pending.get("schedule_sha256") != _sha(SCHEDULE)
            or pending.get("reconciliation_sha256") != _sha(RECONCILIATION)
            or pending.get("slot") != 3
            or not isinstance(pending.get("run_id"), str)
            or committed.RUN_ID.fullmatch(pending["run_id"]) is None
            or pending != committed._read_committed(_folder() / "admissions" / f"{pending['run_id']}.json")
        ):
            raise ProDiagnosticIntegrityError("Pending Pro B3 admission differs")
    if pending:
        phase = "pending_attempt_reconciliation"
    elif valid is not None:
        phase = "complete"
    elif unreconciled:
        phase = "paused_unreconciled_provider_exposure"
    elif not credits["admitted_by_local_share"]:
        phase = "paused_credit_share_admission"
    else:
        phase = "ready_for_next_run"
    return {
        "pilot_id": PILOT_ID,
        "pilot_protocol": PROTOCOL,
        "parent_pilot_id": PARENT_PILOT_ID,
        "predecessor_diagnostic_pilot_id": PREVIOUS_PILOT_ID,
        "schedule_sha256": _sha(SCHEDULE),
        "reconciled_run_id": OLD_401_RUN_ID,
        "reconciliation_sha256": _sha(RECONCILIATION),
        "carried_invalid_attempts": [{"slot": 3, "run_id": OLD_401_RUN_ID,
                                      "reason": "auth_rejection_401"}],
        "scheduled_runs": 1,
        "valid_runs": int(valid is not None),
        "completed_slots": [3] if valid is not None else [],
        "invalid_attempts": invalid,
        "next_slot": None if valid is not None else 3,
        "pending_run": pending,
        "phase": phase,
        "credits": {**credits, "may_start_new_run": phase == "ready_for_next_run"},
        "launch_available": phase == "ready_for_next_run",
        "launch_reason": None if phase == "ready_for_next_run" else phase.replace("_", " "),
        "five_hour_429_pause_override": True,
        "execution_overlay": "pro_b3_diagnostic_v1",
    }


def execute() -> dict[str, Any]:
    """Start at most one Pro B3 attempt after the signed credit admission."""
    opening = status()
    if opening["phase"] != "ready_for_next_run":
        return opening
    lock = parent._folder(PARENT_PILOT_ID) / "execute.lock"
    committed._write_new(lock, b"")
    try:
        before = status()
        if before["phase"] != "ready_for_next_run":
            return before
        study = committed._read_committed(SCHEDULE)
        assignment = study["assignments"][0]
        now = datetime.now(timezone.utc)
        run_id = "2b-path-" + now.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        admission = {
            "schema_version": 1,
            "pilot_id": PILOT_ID,
            "pilot_protocol": PROTOCOL,
            "parent_pilot_id": PARENT_PILOT_ID,
            "parent_schedule_sha256": study["parent_schedule_sha256"],
            "schedule_sha256": before["schedule_sha256"],
            "reconciliation_sha256": before["reconciliation_sha256"],
            "run_id": run_id,
            "slot": 3,
            "created_utc": now.isoformat(),
            "credits": before["credits"],
            "pause_override": "user_authorized_pro_b3_no_between_run_429_pause",
        }
        committed._write_committed(_folder() / "admissions" / f"{run_id}.json", admission)
        pending_path = _folder() / "pending-run.json"
        committed._write_committed(pending_path, admission)
        from experiment_controller.run_2b_path_story_pilot_zai_v5 import run_path_story_pilot

        run_path_story_pilot(
            pilot_id=PILOT_ID,
            slot=assignment["slot"],
            block=assignment["block"],
            arm=assignment["arm"],
            seed=assignment["seed"],
            run_id=run_id,
            frozen_fingerprint=study["fingerprint"],
            contract=study["contract"],
        )
        _verify_pending_archive(admission)
        pending_path.unlink()
        pending_path.with_suffix(".sha256").unlink()
        return status()
    finally:
        lock.unlink(missing_ok=True)


def _verify_pending_archive(pending: dict[str, Any]) -> None:
    run_id = pending.get("run_id")
    if not isinstance(run_id, str) or committed.RUN_ID.fullmatch(run_id) is None:
        raise ProDiagnosticIntegrityError("Pending Pro run ID is invalid")
    if not (LAB / "runs" / run_id / "result.json").is_file():
        raise ProDiagnosticIntegrityError("Pending Pro attempt has no archived result")
    study, _, _ = _schedule()
    found = committed._results(PILOT_ID)
    if not any(row["manifest"].get("run_id") == run_id for row in found.get(3, [])):
        raise ProDiagnosticIntegrityError("Pending Pro archive differs from admission")
    _attempts(study)


def reconcile_pending() -> dict[str, Any]:
    pending_path = _folder() / "pending-run.json"
    pending = committed._read_committed(pending_path)
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
