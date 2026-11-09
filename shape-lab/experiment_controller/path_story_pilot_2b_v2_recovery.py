"""Pinned cost reconciliation and serial resume for one path-story v2 attempt.

The slot-3 archive and frozen pilot sources remain unchanged. Its final
upstream response was fully received and logged with provider usage, but the
gateway never finished sending that response to the stopped attacker process.
The attempt stays infrastructure-invalid; only its provider cost is added to
the admission ledger by this separately committed execution overlay.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
from typing import Any

from experiment_controller import path_story_pilot_2b_v2 as pilot
from experiment_controller.provider_cost_2b import (
    _format_nano_usd,
    _usd_to_nano,
    admission_decision,
    estimate_gateway_events_cost,
)
from telemetry.replay_2b_path_story import verify_path_story_bundle


PILOT_ID = "2b-path-story-pilot-v2-20261109090930-389179"
RUN_ID = "2b-path-20261109093304-8a1b1d"
SLOT = 3
SCHEDULE_SHA256 = "c6949a7cc22ee08df88b22add45284b7e1e30c1c7dbe2976fe0588c887bf4ba1"
GATEWAY_SHA256 = "0dd7ab5f1491d2f7da4facff9ab307b47099556d282664126459ae8c7757272c"
MANIFEST_SHA256 = "04951913095cdfaf29da485397bbbe24bd632f093b1970a5cba9a30724330cf4"
RESULT_SHA256 = "11c29da3017f9536df47bfb8b708667fedb6236da72fb5b3a19fbb8f22c9c921"
EXPECTED_COST_NANO_USD = 9_785_370_680
RECONCILIATION = pilot.pilot_dir(PILOT_ID) / "cost-reconciliation-slot3.json"


def _expected() -> dict[str, Any]:
    """Prove the exact archived upstream responses are fully priceable."""
    schedule = pilot.load_schedule(PILOT_ID)
    if pilot._sha(pilot.pilot_dir(PILOT_ID) / "schedule.json") != SCHEDULE_SHA256:
        raise pilot.PilotIntegrityError("Recovery schedule commitment differs")
    for relative, digest in schedule["fingerprint"]["source_sha256"].items():
        if pilot._sha(pilot.LAB / relative) != digest:
            raise pilot.PilotIntegrityError(f"Frozen pilot source changed: {relative}")
    assignment = schedule["assignments"][SLOT - 1]
    if assignment["slot"] != SLOT or assignment["arm"] != "B0":
        raise pilot.PilotIntegrityError("Recovery slot assignment differs")
    run_dir = pilot.LAB / "runs" / RUN_ID
    gateway_path = run_dir / "gateway-events.jsonl"
    manifest_path = run_dir / "attempt-manifest.json"
    result_path = run_dir / "result.json"
    for path, digest in (
        (gateway_path, GATEWAY_SHA256),
        (manifest_path, MANIFEST_SHA256),
        (result_path, RESULT_SHA256),
    ):
        if pilot._sha(path) != digest:
            raise pilot.PilotIntegrityError(f"Recovery archive changed: {path.name}")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if pilot._verify_attempt_artifacts(result) != run_dir:
        raise pilot.PilotIntegrityError("Recovery attempt artifacts differ")
    if verify_path_story_bundle(run_dir) != result.get("replay"):
        raise pilot.PilotIntegrityError("Recovery path-story replay differs")
    manifest = result["manifest"]
    settlement = manifest.get("provider_settlement")
    if (
        manifest.get("run_id") != RUN_ID
        or manifest.get("assignment") != {
            "pilot_id": PILOT_ID,
            **{key: assignment[key] for key in ("slot", "block", "arm", "seed")},
        }
        or pilot._invalid_reason(result, schedule, assignment) != "controller_error"
        or manifest.get("termination_reason") != "controller_error"
        or not isinstance(settlement, dict)
        or settlement.get("state") != "incomplete"
        or settlement.get("started_request_count") != 193
        or settlement.get("finished_request_count") != 192
        or settlement.get("unmatched_request_ids") != [193]
        or settlement.get("aborted_request_ids") != []
        or settlement.get("max_wait_seconds") != 190
        or manifest.get("provider_cost_error") is not None
    ):
        raise pilot.PilotIntegrityError("Invalid attempt or settlement classification changed")
    rows = [
        json.loads(line)
        for line in gateway_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(rows) != 578 or [row.get("sequence") for row in rows] != list(range(1, 579)):
        raise pilot.PilotIntegrityError("Gateway event journal shape differs")
    if any(row.get("run_id") != RUN_ID or row.get("source") != "model-gateway" for row in rows):
        raise pilot.PilotIntegrityError("Gateway event identity differs")
    for request_id in range(1, 194):
        events = [row for row in rows if row.get("request_id") == request_id]
        expected_types = ["request_started", "model_call"]
        if request_id < 193:
            expected_types.append("request_finished")
        if [row.get("event_type") for row in events] != expected_types:
            raise pilot.PilotIntegrityError(f"Gateway request {request_id} lifecycle differs")
        call = events[1]
        if (
            call.get("status") != 200
            or call.get("call_number") != request_id
            or call.get("attempt_number") != 1
            or not isinstance(call.get("usage"), dict)
        ):
            raise pilot.PilotIntegrityError(f"Gateway request {request_id} usage is incomplete")
    if any(row.get("event_type") not in {
        "request_started", "model_call", "request_finished"
    } for row in rows):
        raise pilot.PilotIntegrityError("Gateway journal has unaccounted events")
    estimate = estimate_gateway_events_cost(
        rows, schedule["contract"]["provider_cost_governance"]
    )
    if (
        estimate["model_calls"] != 193
        or estimate["estimated_cost_nano_usd"] != EXPECTED_COST_NANO_USD
        or manifest.get("provider_cost") != estimate
    ):
        raise pilot.PilotIntegrityError("Reconciled provider usage or cost differs")
    return {
        "schema_version": 1,
        "pilot_id": PILOT_ID,
        "pilot_protocol": pilot.PROTOCOL,
        "schedule_sha256": SCHEDULE_SHA256,
        "run_id": RUN_ID,
        "slot": SLOT,
        "classification": "infrastructure_invalid_controller_error",
        "raw_gateway_sha256": GATEWAY_SHA256,
        "manifest_sha256": MANIFEST_SHA256,
        "result_sha256": RESULT_SHA256,
        "upstream_responses_with_usage": 193,
        "downstream_finishes": 192,
        "last_response_request_id": 193,
        "last_response_condition": "upstream_complete_downstream_finish_missing",
        "cost_evidence": estimate,
        "archive_modified": False,
        "creates_trial_attempt": False,
        "creates_censored_outcome": False,
        "recovery_source_sha256": pilot._sha(Path(__file__)),
    }


def freeze_reconciliation() -> dict[str, Any]:
    expected = _expected()
    if RECONCILIATION.exists():
        if pilot._read_committed(RECONCILIATION) != expected:
            raise pilot.PilotIntegrityError("Existing cost reconciliation differs")
    else:
        pilot._write_committed(RECONCILIATION, expected)
    return expected


def load_reconciliation() -> dict[str, Any]:
    recorded = pilot._read_committed(RECONCILIATION)
    if recorded != _expected():
        raise pilot.PilotIntegrityError("Cost reconciliation differs from raw evidence")
    return recorded


def funding_snapshot(found: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    reconciliation = load_reconciliation()
    base = pilot._cost_snapshot(PILOT_ID, found)
    matching = [row for row in base["errors"] if row.get("run_id") == RUN_ID]
    if matching != [{"run_id": RUN_ID, "reason": "Provider settlement is incomplete"}]:
        raise pilot.PilotIntegrityError("Reconciled attempt is absent from cost errors")
    errors = [row for row in base["errors"] if row.get("run_id") != RUN_ID]
    accrued = _usd_to_nano(base["accrued_usd"], "accrued cost") + EXPECTED_COST_NANO_USD
    authorized = _usd_to_nano(base["authorized_usd"], "authorization")
    admission = admission_decision(accrued, {
        "pilot_authorization_usd": _format_nano_usd(authorized),
        "minimum_uncommitted_reserve_per_new_run_usd": "10.000000000",
    })
    if errors:
        admission["state"] = "paused_incomplete_cost_evidence"
        admission["may_start_new_run"] = False
    return {
        **base,
        "accounting_state": "complete" if not errors else "incomplete",
        "state": admission["state"],
        "may_start_new_run": admission["may_start_new_run"],
        "accrued_usd": _format_nano_usd(accrued),
        "accrued_over_authorization_usd": _format_nano_usd(max(0, accrued - authorized)),
        "remaining_usd": admission["remaining_authorization_usd"],
        "attempts_priced": base["attempts_priced"] + 1,
        "errors": errors,
        "evidence": [*base["evidence"], {
            "run_id": RUN_ID,
            "gateway_events_sha256": GATEWAY_SHA256,
            "estimated_cost_nano_usd": EXPECTED_COST_NANO_USD,
            "estimated_cost_usd": _format_nano_usd(EXPECTED_COST_NANO_USD),
            "reconciliation_sha256": pilot._sha(RECONCILIATION),
        }],
        "reconciliation_sha256": pilot._sha(RECONCILIATION),
        "reconciled_run_id": RUN_ID,
    }


def status() -> dict[str, Any]:
    original = pilot.status(PILOT_ID)
    funding = funding_snapshot(pilot._results(PILOT_ID))
    original["funding"] = funding
    if original["pending_run"] is not None:
        phase = "pending_attempt_reconciliation"
    elif original["provider_rate_limit_pause"] is not None:
        phase = "paused_provider_rate_limit"
        funding["state"] = "paused_provider_rate_limit"
        funding["may_start_new_run"] = False
    elif original["next_slot"] is None:
        phase = "execution_complete_awaiting_annotation"
    elif funding["may_start_new_run"]:
        phase = "execution_enabled"
    else:
        phase = "paused_provider_cost_admission"
    original["phase"] = phase
    original["execution_overlay"] = "slot3_cost_reconciliation_v1"
    return original


def execute(*, max_new_runs: int | None = None) -> dict[str, Any]:
    """Resume only through the committed overlay and between-run admission."""
    schedule = pilot.load_schedule(PILOT_ID)
    load_reconciliation()
    if max_new_runs is not None and (type(max_new_runs) is not int or max_new_runs < 1):
        raise ValueError("max_new_runs must be a positive integer")
    opening = status()
    if opening["pending_run"] is not None:
        raise pilot.PilotIntegrityError("Pending attempt must be reconciled first")
    if opening["provider_rate_limit_pause"] is not None or not opening["funding"]["may_start_new_run"]:
        return opening
    if pilot.fingerprint() != schedule["fingerprint"]:
        raise pilot.PilotIntegrityError("Frozen source or image fingerprint changed")
    from experiment_controller.run_2b_path_story_pilot_v2 import run_path_story_pilot

    folder = pilot.pilot_dir(PILOT_ID)
    descriptor = os.open(folder / "execute.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    created = 0
    try:
        for assignment in schedule["assignments"]:
            while True:
                observed = status()
                if assignment["slot"] in observed["completed_slots"]:
                    break
                if observed["pending_run"] is not None:
                    raise pilot.PilotIntegrityError("Pending attempt must be reconciled first")
                if max_new_runs is not None and created >= max_new_runs:
                    return observed
                if not observed["funding"]["may_start_new_run"]:
                    return observed
                run_id = (
                    "2b-path-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                    + "-" + secrets.token_hex(3)
                )
                pilot._write_pending(PILOT_ID, assignment, run_id)
                result = run_path_story_pilot(
                    pilot_id=PILOT_ID,
                    slot=assignment["slot"],
                    block=assignment["block"],
                    arm=assignment["arm"],
                    seed=assignment["seed"],
                    run_id=run_id,
                    frozen_fingerprint=schedule["fingerprint"],
                    contract=schedule["contract"],
                )
                created += 1
                reason = pilot._invalid_reason(result, schedule, assignment)
                pilot.reconcile_pending(PILOT_ID)
                if reason == "provider_rate_limit":
                    return status()
    finally:
        (folder / "execute.lock").unlink(missing_ok=True)
    return status()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("freeze")
    actions.add_parser("status")
    execution = actions.add_parser("execute")
    execution.add_argument("--max-new-runs", type=int)
    args = parser.parse_args()
    value = (
        freeze_reconciliation() if args.action == "freeze"
        else status() if args.action == "status"
        else execute(max_new_runs=args.max_new_runs)
    )
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
