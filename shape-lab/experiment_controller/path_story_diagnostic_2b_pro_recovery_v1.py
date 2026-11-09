"""Exact DNS-failure recovery overlay for the frozen Pro B3 diagnostic.

The original schedule, controller, admissions, and run archives stay untouched.
Only the archived 2026-11-09 DNS failure receives a signed reconciliation.
Subsequent attempts still require a separate explicit execute call.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import secrets
import subprocess
from typing import Any

from experiment_controller import path_story_diagnostic_2b_pro_v1 as pro
from experiment_controller import path_story_pilot_2b_v2 as committed
from experiment_controller import path_story_pilot_2b_zai_v5 as parent
from experiment_controller.run_2b_path_story_pilot_zai_v5 import _gateway_lifecycle
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits
from telemetry.replay_2b_path_story import verify_path_story_bundle


PILOT_ID = pro.PILOT_ID
PROTOCOL = pro.PROTOCOL
SCHEDULE = pro.SCHEDULE
DNS_RUN_ID = "2b-path-20261109193436-22dfcb"
FIRST_PRO_RUN_ID = "2b-path-20261109192156-08a4c0"
DNS_RECONCILIATION = SCHEDULE.parent / "dns-gaierror-reconciliation-v1.json"
EXECUTION_OVERLAY = "pro_b3_dns_recovery_v1"
PINS = {
    "schedule_sha256": "1d760bd693e75f2214036dc85c16c8deb9783e0c048546739fb7e0548528ceeb",
    "gateway_events_sha256": "8b28d4a8fdc5587f6f2ba99f00636017cad11a2a086e83482482f8061fb45ef0",
    "attempt_manifest_sha256": "e50836150016cc7f4943bbc0d1af431db15ebfacdecacc50de897a3ad4eaa22a",
    "result_sha256": "a7b209914f788807d2bfda9faa19e979118af0394e5b368d24a24a3fb3982cd1",
    "pending_sha256": "8add23dc0a8cb28d26ab88deb57c6289bebb4dfd8aba09422788d89af28ca542",
    "gateway_image_id": "sha256:7772965fd5df2dde7c5f0948b380e21b1e031a50bc8293461c3a05df7b4bee3e",
    "gateway_server_source_sha256": "dc97c3fc4e6d851e03349bf86ce598f104ad015eab4760c7047d5134698f5c06",
    "gateway_entry_source_sha256": "ea3265f8351ce367333f497a1ef40e75bff7f9459423a451b6e1842e09d1a44a",
}


class DNSRecoveryIntegrityError(RuntimeError):
    """An archived or signed recovery input differs from the exact failure."""


def _sha(path: Path) -> str:
    return committed._sha(path)


def _pending_path() -> Path:
    return SCHEDULE.parent / "pending-run.json"


def _record_exists(path: Path) -> bool:
    return path.exists() or path.with_suffix(".sha256").exists()


def _rows(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "gateway-events.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _expected_dns_reconciliation(study: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recompute the exact exception from independently pinned archive bytes."""
    if study is None:
        study, _, _ = pro._schedule()
    if _sha(SCHEDULE) != PINS["schedule_sha256"]:
        raise DNSRecoveryIntegrityError("Frozen Pro schedule digest differs")
    found = committed._results(PILOT_ID)
    target = next((row for row in found.get(3, [])
                   if row["manifest"].get("run_id") == DNS_RUN_ID), None)
    if target is None:
        raise DNSRecoveryIntegrityError("Pinned DNS run is absent")
    run_dir = committed._verify_attempt_artifacts(target)
    manifest = target["manifest"]
    paths = {
        "gateway_events_sha256": run_dir / "gateway-events.jsonl",
        "attempt_manifest_sha256": run_dir / "attempt-manifest.json",
        "result_sha256": run_dir / "result.json",
    }
    if run_dir.name != DNS_RUN_ID or any(_sha(path) != PINS[key] for key, path in paths.items()):
        raise DNSRecoveryIntegrityError("Pinned DNS archive digest differs")
    source = study.get("fingerprint", {}).get("source_sha256", {})
    if (manifest.get("images", {}).get("gateway") != PINS["gateway_image_id"]
            or study.get("fingerprint", {}).get("images", {}).get("gateway") != PINS["gateway_image_id"]
            or source.get("model_gateway/server.py") != PINS["gateway_server_source_sha256"]
            or source.get("model_gateway/server_path_story_v2.py") != PINS["gateway_entry_source_sha256"]):
        raise DNSRecoveryIntegrityError("Pinned gateway image or source differs")
    expected_assignment = {"pilot_id": PILOT_ID,
                           **{key: study["assignments"][0][key]
                              for key in ("slot", "block", "arm", "seed")}}
    settlement = manifest.get("provider_settlement")
    if (
        manifest.get("run_id") != DNS_RUN_ID
        or manifest.get("pilot_id") != PILOT_ID
        or manifest.get("assignment") != expected_assignment
        or manifest.get("pilot_protocol") != parent.PROTOCOL
        or manifest.get("provider") != "zai"
        or manifest.get("pilot_fingerprint") != study["fingerprint"]
        or manifest.get("trial_caps") != study["contract"]["trial_caps"]
        or manifest.get("termination_reason") != "controller_error"
        or manifest.get("error") != "Gateway request lifecycle did not settle"
        or manifest.get("provider_credit_error") != "ValueError: Gateway error leaves provider usage uncertain"
        or manifest.get("provider_credits") is not None
        or target.get("provider_credits") is not None
        or manifest.get("confirmed_containment_escape_incident") is True
        or manifest.get("path_story_evidence_error") is not None
        or manifest.get("agent_exit_code") != 0
        or not isinstance(settlement, dict)
        or settlement.get("state") != "incomplete"
        or settlement.get("started_request_count") != 25
        or settlement.get("finished_request_count") != 25
        or settlement.get("provider_completed_request_count") != 24
        or settlement.get("local_rejection_request_count") != 0
        or settlement.get("unaccounted_request_ids") != [25]
        or settlement.get("unmatched_request_ids") != []
        or settlement.get("aborted_request_ids") != []
        or settlement.get("downstream_delivery_failed_ids") != []
        or target.get("replay") != verify_path_story_bundle(run_dir)
    ):
        raise DNSRecoveryIntegrityError("DNS attempt outcome differs")
    admission_path = SCHEDULE.parent / "admissions" / f"{DNS_RUN_ID}.json"
    admission = committed._read_committed(admission_path)
    if (_sha(admission_path) != PINS["pending_sha256"]
            or admission.get("run_id") != DNS_RUN_ID
            or admission.get("pilot_id") != PILOT_ID
            or admission.get("schedule_sha256") != PINS["schedule_sha256"]
            or admission.get("reconciliation_sha256") != _sha(pro.RECONCILIATION)
            or admission.get("slot") != 3
            or admission.get("credits", {}).get("may_start_new_run") is not True
            or pro._utc(admission.get("created_utc")) > pro._utc(manifest.get("started_utc"))):
        raise DNSRecoveryIntegrityError("Pinned DNS admission differs")
    rows = _rows(run_dir)
    if (len(rows) != 99 or [row.get("sequence") for row in rows] != list(range(1, 100))
            or any(row.get("run_id") != DNS_RUN_ID or row.get("source") != "model-gateway"
                   or row.get("provider") != "zai" for row in rows)):
        raise DNSRecoveryIntegrityError("DNS gateway sequence differs")
    for request_id in range(1, 25):
        request = rows[(request_id - 1) * 4:request_id * 4]
        if ([row.get("event_type") for row in request] != [
                "request_started", "model_call", "provider_response_complete", "request_finished"]
                or any(row.get("request_id") != request_id for row in request)):
            raise DNSRecoveryIntegrityError("Completed request lifecycle differs")
        call, completion = request[1:3]
        if (call.get("status") != 200 or not isinstance(call.get("usage"), dict)
                or call.get("call_number") != request_id or call.get("attempt_number") != 1
                or completion.get("status") != 200
                or completion.get("call_number") != request_id
                or completion.get("attempt_number") != 1
                or completion.get("usage_recorded") is not True):
            raise DNSRecoveryIntegrityError("Completed provider response differs")
    final = rows[96:]
    if ([row.get("event_type") for row in final] != [
            "request_started", "gateway_error", "request_finished"]
            or any(row.get("request_id") != 25 for row in final)
            or final[1].get("error_type") != "gaierror"
            or final[1].get("call_number") != 25
            or final[1].get("attempt_number") != 1):
        raise DNSRecoveryIntegrityError("DNS failure lifecycle differs")
    lifecycle = _gateway_lifecycle(rows)
    if (lifecycle.get("unaccounted_request_ids") != [25]
            or lifecycle.get("provider_completed_request_count") != 24):
        raise DNSRecoveryIntegrityError("Recomputed gateway settlement differs")
    credits = estimate_gateway_events_credits(rows)
    if (credits.get("model_calls") != 24
            or credits.get("estimated_total_credits") != "79.807400000"
            or credits.get("total_tokens") != 545843):
        raise DNSRecoveryIntegrityError("Completed-call credit estimate differs")
    return {
        "schema_version": 1,
        "execution_overlay": EXECUTION_OVERLAY,
        "pilot_id": PILOT_ID,
        "pilot_protocol": PROTOCOL,
        "schedule_sha256": PINS["schedule_sha256"],
        "frozen_controller_sha256": _sha(Path(pro.__file__)),
        "recovery_controller_sha256": _sha(Path(__file__)),
        "run_id": DNS_RUN_ID,
        "slot": 3,
        "classification": "infrastructure_invalid_dns_resolution_failure",
        "gateway_events_sha256": PINS["gateway_events_sha256"],
        "attempt_manifest_sha256": PINS["attempt_manifest_sha256"],
        "result_sha256": PINS["result_sha256"],
        "admission_sha256": PINS["pending_sha256"],
        "gateway_image_id": PINS["gateway_image_id"],
        "gateway_server_source_sha256": PINS["gateway_server_source_sha256"],
        "gateway_entry_source_sha256": PINS["gateway_entry_source_sha256"],
        "gateway_image_source_verified_at_reconciliation": True,
        "successful_provider_calls_with_reported_usage": 24,
        "reported_usage_credit_estimate": credits["estimated_total_credits"],
        "credit_estimate": credits,
        "dns_failure_request_id": 25,
        "dns_failure_error_type": "gaierror",
        "dns_failure_provider_response_recorded": False,
        "dns_failure_zero_charge_basis": "inferred_from_dns_resolution_error_before_connection_not_provider_bill",
        "provider_charge_independently_verified": False,
        "original_provider_settlement_state": "incomplete",
        "old_archive_modified": False,
        "creates_behavioral_outcome": False,
    }


def _reconciliation(study: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if not _record_exists(DNS_RECONCILIATION):
        return None
    record = committed._read_committed(DNS_RECONCILIATION)
    if record != _expected_dns_reconciliation(study):
        raise DNSRecoveryIntegrityError("Signed DNS reconciliation differs from archive")
    return record


def verify_reconciled_exposure(run_id: str, sha256: str) -> bool:
    """Dashboard bypasses its incomplete-settlement guard for this exact record."""
    if run_id != DNS_RUN_ID or not isinstance(sha256, str):
        return False
    record = _reconciliation()
    return record is not None and sha256 == _sha(DNS_RECONCILIATION)


def _attempts(study: dict[str, Any]) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]], bool, dict[str, Any] | None]:
    found = committed._results(PILOT_ID)
    if set(found) - {3}:
        raise DNSRecoveryIntegrityError("Result is outside frozen B3 assignment")
    valid = None
    invalid: list[dict[str, Any]] = []
    priced: list[dict[str, Any]] = []
    unreconciled = False
    expected_assignment = {"pilot_id": PILOT_ID,
                           **{key: study["assignments"][0][key]
                              for key in ("slot", "block", "arm", "seed")}}
    signed_dns = _reconciliation(study)
    for result in found.get(3, []):
        if valid is not None:
            raise DNSRecoveryIntegrityError("B3 was retried after a valid outcome")
        manifest = result["manifest"]
        run_dir = committed._verify_attempt_artifacts(result)
        run_id = manifest["run_id"]
        if (manifest.get("assignment") != expected_assignment
                or manifest.get("pilot_protocol") != parent.PROTOCOL
                or manifest.get("provider") != "zai"
                or manifest.get("pilot_fingerprint") != study["fingerprint"]
                or manifest.get("trial_caps") != study["contract"]["trial_caps"]
                or manifest.get("confirmed_containment_escape_incident") is True):
            raise DNSRecoveryIntegrityError("Attempt differs from frozen B3 assignment")
        admission = committed._read_committed(SCHEDULE.parent / "admissions" / f"{run_id}.json")
        if (admission.get("pilot_id") != PILOT_ID
                or admission.get("pilot_protocol") != PROTOCOL
                or admission.get("schedule_sha256") != _sha(SCHEDULE)
                or admission.get("reconciliation_sha256") != _sha(pro.RECONCILIATION)
                or admission.get("run_id") != run_id
                or admission.get("slot") != 3
                or admission.get("credits", {}).get("may_start_new_run") is not True
                or pro._utc(admission.get("created_utc")) > pro._utc(manifest.get("started_utc"))):
            raise DNSRecoveryIntegrityError("Attempt lacks matching signed admission")
        if run_id not in {FIRST_PRO_RUN_ID, DNS_RUN_ID} and (
                signed_dns is None
                or admission.get("execution_overlay") != EXECUTION_OVERLAY
                or admission.get("dns_reconciliation_sha256") != _sha(DNS_RECONCILIATION)):
            raise DNSRecoveryIntegrityError("Post-recovery admission lacks DNS overlay identity")
        rows = _rows(run_dir)
        credits = estimate_gateway_events_credits(rows)
        is_dns = run_id == DNS_RUN_ID
        settled = isinstance(manifest.get("provider_settlement"), dict) and manifest["provider_settlement"].get("state") == "complete"
        if is_dns:
            # Exact archive is checked even while its signed recovery record is absent.
            if signed_dns is None:
                _expected_dns_reconciliation(study)
            settled = signed_dns is not None
            reason = "dns_resolution_failure"
        elif result.get("provider_credits") != credits or manifest.get("provider_credits") != credits:
            unreconciled = True
            reason = "unreconciled_provider_usage"
        elif pro._operator_stop(run_id, manifest):
            reason = "operator_stop"
        elif any(row.get("event_type") in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"} for row in rows):
            reason = "provider_rate_limit"
        elif manifest.get("error") or manifest.get("provider_credit_error") or manifest.get("path_story_evidence_error"):
            reason = "controller_error"
        elif not settled or any(row.get("event_type") == "gateway_error" for row in rows):
            reason = "missing_required_telemetry"
        elif manifest.get("termination_reason") in {"agent_failure", "controller_error"}:
            reason = manifest["termination_reason"]
        elif manifest.get("termination_reason") not in committed.TERMINAL_REASONS:
            reason = "undeclared_terminal_state"
        else:
            try:
                reason = None if result.get("replay") == verify_path_story_bundle(run_dir) else "replay_failure"
            except Exception:
                reason = "replay_failure"
        priced.append({"run_id": run_id, "finished_utc": manifest["finished_utc"],
                       "credits": Decimal(credits["estimated_total_credits"])})
        if not settled:
            unreconciled = True
        if reason is None:
            valid = result
        else:
            invalid.append({"slot": 3, "run_id": run_id, "reason": reason})
    return valid, invalid, priced, unreconciled, signed_dns


def _pending() -> dict[str, Any] | None:
    path = _pending_path()
    if not _record_exists(path):
        return None
    if not path.exists() and path.with_suffix(".sha256").exists():
        # A crash after unlinking the JSON but before its sidecar must remain
        # recoverable only for this already signed, exact DNS admission.
        if _reconciliation() is None:
            raise DNSRecoveryIntegrityError("Partial pending record lacks signed DNS recovery")
        digest = path.with_suffix(".sha256").read_text(encoding="utf-8").strip()
        admission_path = SCHEDULE.parent / "admissions" / f"{DNS_RUN_ID}.json"
        if digest != PINS["pending_sha256"] or _sha(admission_path) != digest:
            raise DNSRecoveryIntegrityError("Partial pending digest differs")
        pending = committed._read_committed(admission_path)
    else:
        pending = committed._read_committed(path)
    if (pending.get("pilot_id") != PILOT_ID
            or pending.get("pilot_protocol") != PROTOCOL
            or pending.get("schedule_sha256") != _sha(SCHEDULE)
            or pending.get("reconciliation_sha256") != _sha(pro.RECONCILIATION)
            or pending.get("slot") != 3
            or not isinstance(pending.get("run_id"), str)
            or committed.RUN_ID.fullmatch(pending["run_id"]) is None
            or pending != committed._read_committed(SCHEDULE.parent / "admissions" / f"{pending['run_id']}.json")):
        raise DNSRecoveryIntegrityError("Pending admission differs")
    return pending


def status() -> dict[str, Any]:
    study, _, parent_state = pro._schedule()
    if _sha(SCHEDULE) != PINS["schedule_sha256"]:
        raise DNSRecoveryIntegrityError("Frozen schedule digest differs")
    valid, invalid, priced, unreconciled, signed_dns = _attempts(study)
    credits = pro._credits(parent_state, priced)
    pending = _pending()
    if pending is not None:
        phase = "pending_attempt_reconciliation"
    elif unreconciled:
        phase = "paused_unreconciled_provider_exposure"
    elif valid is not None:
        phase = "complete"
    elif not credits["admitted_by_local_share"]:
        phase = "paused_credit_share_admission"
    else:
        phase = "ready_for_next_run"
    return {
        "pilot_id": PILOT_ID, "pilot_protocol": PROTOCOL,
        "parent_pilot_id": pro.PARENT_PILOT_ID,
        "predecessor_diagnostic_pilot_id": pro.PREVIOUS_PILOT_ID,
        "schedule_sha256": _sha(SCHEDULE),
        "reconciled_run_id": pro.OLD_401_RUN_ID,
        "reconciliation_sha256": _sha(pro.RECONCILIATION),
        "reconciled_incomplete_run_id": DNS_RUN_ID if signed_dns is not None else None,
        "dns_reconciliation_sha256": _sha(DNS_RECONCILIATION) if signed_dns is not None else None,
        "carried_invalid_attempts": [{"slot": 3, "run_id": pro.OLD_401_RUN_ID,
                                      "reason": "auth_rejection_401"}],
        "scheduled_runs": 1, "valid_runs": int(valid is not None),
        "completed_slots": [3] if valid is not None else [],
        "invalid_attempts": invalid, "next_slot": None if valid is not None else 3,
        "pending_run": pending, "phase": phase,
        "credits": {**credits, "may_start_new_run": phase == "ready_for_next_run",
                    "dns_reconciled_usage_credits": "79.807400000" if signed_dns else None,
                    "dns_zero_charge_basis": signed_dns.get("dns_failure_zero_charge_basis") if signed_dns else None},
        "launch_available": phase == "ready_for_next_run",
        "launch_reason": None if phase == "ready_for_next_run" else phase.replace("_", " "),
        "five_hour_429_pause_override": True,
        "execution_overlay": EXECUTION_OVERLAY,
    }


def _no_active_run() -> None:
    """The reconciliation may not release an actively running attempt."""
    if (parent._folder(pro.PARENT_PILOT_ID) / "execute.lock").exists():
        raise DNSRecoveryIntegrityError("Parent execution lock is still held")
    jobs = pro.LAB / "runs" / ".dashboard-jobs"
    for path in jobs.glob("2b-diag-*/status.json"):
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise DNSRecoveryIntegrityError("Dashboard job state is unreadable") from exc
        if job.get("run_id") == DNS_RUN_ID and job.get("status") in {"queued", "running"}:
            raise DNSRecoveryIntegrityError("DNS attempt worker is still active")
    manifest = json.loads((pro.LAB / "runs" / DNS_RUN_ID / "attempt-manifest.json").read_text(encoding="utf-8"))
    project = manifest.get("project")
    if project != "shape" + DNS_RUN_ID.lower():
        raise DNSRecoveryIntegrityError("DNS attempt project differs")
    query = subprocess.run(["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
                            "--format", "{{.ID}}"], check=True, capture_output=True, text=True,
                           timeout=15)
    if query.stdout.strip():
        raise DNSRecoveryIntegrityError("DNS attempt containers are still running")


def _verify_gateway_image_source() -> None:
    """Bind the recorded gateway source to the content-addressed runtime image."""
    paths = ["/app/model_gateway/server.py", "/app/model_gateway/server_path_story_v2.py"]
    query = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sha256sum",
         PINS["gateway_image_id"], *paths],
        check=True, capture_output=True, text=True, timeout=30,
    )
    expected = [PINS["gateway_server_source_sha256"], PINS["gateway_entry_source_sha256"]]
    if query.stdout.splitlines() != [f"{digest}  {path}" for digest, path in zip(expected, paths)]:
        raise DNSRecoveryIntegrityError("Pinned gateway image source differs")


def reconcile_dns() -> dict[str, Any]:
    """Sign one archived failure and clear only its matching pending admission."""
    pending = _pending()
    if pending is None:
        if _reconciliation() is None:
            raise DNSRecoveryIntegrityError("DNS admission is neither pending nor reconciled")
        return status()
    pending_digest = (_sha(_pending_path()) if _pending_path().exists()
                      else _pending_path().with_suffix(".sha256").read_text(encoding="utf-8").strip())
    if pending.get("run_id") != DNS_RUN_ID or pending_digest != PINS["pending_sha256"]:
        raise DNSRecoveryIntegrityError("Pending run is not the pinned DNS failure")
    expected = _expected_dns_reconciliation()
    _no_active_run()
    _verify_gateway_image_source()
    if _record_exists(DNS_RECONCILIATION):
        if _reconciliation() != expected:
            raise DNSRecoveryIntegrityError("Existing DNS reconciliation differs")
    else:
        committed._write_committed(DNS_RECONCILIATION, expected)
    # An interruption after the signed write is recoverable on a later call.
    _reconciliation()
    _pending_path().unlink(missing_ok=True)
    _pending_path().with_suffix(".sha256").unlink(missing_ok=True)
    return status()


def _verify_pending_archive(pending: dict[str, Any]) -> None:
    run_id = pending["run_id"]
    if not (pro.LAB / "runs" / run_id / "result.json").is_file():
        raise DNSRecoveryIntegrityError("Pending attempt has no archived result")
    study, _, _ = pro._schedule()
    found = committed._results(PILOT_ID)
    if not any(row["manifest"].get("run_id") == run_id for row in found.get(3, [])):
        raise DNSRecoveryIntegrityError("Pending archive differs from admission")
    _, _, _, unreconciled, _ = _attempts(study)
    if unreconciled:
        raise DNSRecoveryIntegrityError("Pending archive has unresolved provider exposure")


def reconcile_pending() -> dict[str, Any]:
    pending = _pending()
    if pending is None:
        return status()
    if pending["run_id"] == DNS_RUN_ID:
        return reconcile_dns()
    _verify_pending_archive(pending)
    _pending_path().unlink()
    _pending_path().with_suffix(".sha256").unlink()
    return status()


def execute() -> dict[str, Any]:
    """Run one B3 attempt with the original signed assignment and Pro shares."""
    opening = status()
    if opening["phase"] != "ready_for_next_run":
        return opening
    lock = parent._folder(pro.PARENT_PILOT_ID) / "execute.lock"
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
            "schema_version": 1, "pilot_id": PILOT_ID, "pilot_protocol": PROTOCOL,
            "parent_pilot_id": pro.PARENT_PILOT_ID,
            "parent_schedule_sha256": study["parent_schedule_sha256"],
            "schedule_sha256": before["schedule_sha256"],
            "reconciliation_sha256": before["reconciliation_sha256"],
            "dns_reconciliation_sha256": before["dns_reconciliation_sha256"],
            "execution_overlay": EXECUTION_OVERLAY,
            "run_id": run_id, "slot": 3, "created_utc": now.isoformat(),
            "credits": before["credits"],
            "pause_override": "user_authorized_pro_b3_no_between_run_429_pause",
        }
        committed._write_committed(SCHEDULE.parent / "admissions" / f"{run_id}.json", admission)
        committed._write_committed(_pending_path(), admission)
        from experiment_controller.run_2b_path_story_pilot_zai_v5 import run_path_story_pilot
        run_path_story_pilot(
            pilot_id=PILOT_ID, slot=assignment["slot"], block=assignment["block"],
            arm=assignment["arm"], seed=assignment["seed"], run_id=run_id,
            frozen_fingerprint=study["fingerprint"], contract=study["contract"],
        )
        _verify_pending_archive(admission)
        _pending_path().unlink()
        _pending_path().with_suffix(".sha256").unlink()
        return status()
    finally:
        lock.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("status", "reconcile-dns", "reconcile-pending", "execute"):
        actions.add_parser(name)
    args = parser.parse_args()
    result = {"status": status, "reconcile-dns": reconcile_dns,
              "reconcile-pending": reconcile_pending, "execute": execute}[args.action]()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
