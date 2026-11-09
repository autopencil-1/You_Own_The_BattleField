"""Immutable slot-4 cost closeout for the paused path-story v2 pilot.

The second wall-cap attempt with an unfinished downstream reply stays invalid.
Its completed upstream usage is priced once. This module deliberately exposes
no execution command while the recurring closeout failure is investigated.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from experiment_controller import path_story_pilot_2b_v2 as pilot
from experiment_controller import path_story_pilot_2b_v2_recovery as slot3
from experiment_controller.provider_cost_2b import (
    _format_nano_usd,
    _usd_to_nano,
    estimate_gateway_events_cost,
)
from telemetry.replay_2b_path_story import verify_path_story_bundle


PILOT_ID = slot3.PILOT_ID
RUN_ID = "2b-path-20261109100724-a577f5"
SLOT = 4
SCHEDULE_SHA256 = slot3.SCHEDULE_SHA256
GATEWAY_SHA256 = "67a1d3eed9f54f3e8b8fabecfa2e354e8eaafd8a03d4784423a90846952a06c1"
MANIFEST_SHA256 = "be649e188e10a9ea085960c412bd02d2c7594125f311f1f20d736fccdda4b1ce"
RESULT_SHA256 = "9fb6063c5aa89756b6470314be78fc76071085875d0399f515799712c68ab26e"
EXPECTED_COST_NANO_USD = 8_913_747_080
EXPECTED_CUMULATIVE_NANO_USD = 46_339_601_000
RECONCILIATION = pilot.pilot_dir(PILOT_ID) / "cost-reconciliation-slot4.json"


def _expected() -> dict[str, Any]:
    """Recompute cost only from the exact archived upstream responses."""
    prior = slot3.load_reconciliation()
    schedule = pilot.load_schedule(PILOT_ID)
    if pilot._sha(pilot.pilot_dir(PILOT_ID) / "schedule.json") != SCHEDULE_SHA256:
        raise pilot.PilotIntegrityError("Closeout schedule commitment differs")
    for relative, digest in schedule["fingerprint"]["source_sha256"].items():
        if pilot._sha(pilot.LAB / relative) != digest:
            raise pilot.PilotIntegrityError(f"Frozen pilot source changed: {relative}")
    assignment = schedule["assignments"][SLOT - 1]
    if assignment["slot"] != SLOT or assignment["arm"] != "B3":
        raise pilot.PilotIntegrityError("Closeout slot assignment differs")
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
            raise pilot.PilotIntegrityError(f"Closeout archive changed: {path.name}")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if pilot._verify_attempt_artifacts(result) != run_dir:
        raise pilot.PilotIntegrityError("Closeout attempt artifacts differ")
    if verify_path_story_bundle(run_dir) != result.get("replay"):
        raise pilot.PilotIntegrityError("Closeout path-story replay differs")
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
        or settlement.get("started_request_count") != 132
        or settlement.get("finished_request_count") != 131
        or settlement.get("unmatched_request_ids") != [132]
        or settlement.get("aborted_request_ids") != []
        or settlement.get("max_wait_seconds") != 190
        or manifest.get("provider_cost_error") is not None
    ):
        raise pilot.PilotIntegrityError("Closeout attempt or settlement differs")
    rows = [
        json.loads(line)
        for line in gateway_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(rows) != 395 or [row.get("sequence") for row in rows] != list(range(1, 396)):
        raise pilot.PilotIntegrityError("Closeout gateway journal shape differs")
    if any(row.get("run_id") != RUN_ID or row.get("source") != "model-gateway" for row in rows):
        raise pilot.PilotIntegrityError("Closeout gateway event identity differs")
    for request_id in range(1, 133):
        events = [row for row in rows if row.get("request_id") == request_id]
        expected_types = ["request_started", "model_call"]
        if request_id < 132:
            expected_types.append("request_finished")
        if [row.get("event_type") for row in events] != expected_types:
            raise pilot.PilotIntegrityError(f"Closeout request {request_id} lifecycle differs")
        call = events[1]
        if (
            call.get("status") != 200
            or call.get("call_number") != request_id
            or call.get("attempt_number") != 1
            or not isinstance(call.get("usage"), dict)
        ):
            raise pilot.PilotIntegrityError(f"Closeout request {request_id} usage differs")
    if any(row.get("event_type") not in {
        "request_started", "model_call", "request_finished"
    } for row in rows):
        raise pilot.PilotIntegrityError("Closeout journal has unaccounted events")
    estimate = estimate_gateway_events_cost(
        rows, schedule["contract"]["provider_cost_governance"]
    )
    if (
        estimate["model_calls"] != 132
        or estimate["estimated_cost_nano_usd"] != EXPECTED_COST_NANO_USD
        or manifest.get("provider_cost") != estimate
    ):
        raise pilot.PilotIntegrityError("Closeout provider usage or cost differs")
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
        "upstream_responses_with_usage": 132,
        "downstream_finishes": 131,
        "last_response_request_id": 132,
        "last_response_condition": "upstream_complete_downstream_finish_missing",
        "cost_evidence": estimate,
        "prior_reconciliation_sha256": pilot._sha(slot3.RECONCILIATION),
        "prior_run_id": prior["run_id"],
        "archive_modified": False,
        "creates_trial_attempt": False,
        "creates_censored_outcome": False,
        "recovery_source_sha256": pilot._sha(Path(__file__)),
    }


def freeze_reconciliation() -> dict[str, Any]:
    expected = _expected()
    if RECONCILIATION.exists():
        if pilot._read_committed(RECONCILIATION) != expected:
            raise pilot.PilotIntegrityError("Existing closeout reconciliation differs")
    else:
        pilot._write_committed(RECONCILIATION, expected)
    return expected


def load_reconciliation() -> dict[str, Any]:
    recorded = pilot._read_committed(RECONCILIATION)
    if recorded != _expected():
        raise pilot.PilotIntegrityError("Closeout reconciliation differs from raw evidence")
    return recorded


def funding_snapshot(found: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    load_reconciliation()
    base = slot3.funding_snapshot(found)
    matching = [row for row in base["errors"] if row.get("run_id") == RUN_ID]
    if matching != [{"run_id": RUN_ID, "reason": "Provider settlement is incomplete"}]:
        raise pilot.PilotIntegrityError("Closeout attempt is absent from cost errors")
    errors = [row for row in base["errors"] if row.get("run_id") != RUN_ID]
    accrued = _usd_to_nano(base["accrued_usd"], "accrued cost") + EXPECTED_COST_NANO_USD
    authorized = _usd_to_nano(base["authorized_usd"], "authorization")
    if accrued != EXPECTED_CUMULATIVE_NANO_USD or authorized != 100_000_000_000:
        raise pilot.PilotIntegrityError("Closeout cumulative authorization or cost differs")
    remaining = max(0, authorized - accrued)
    return {
        **base,
        "accounting_state": "complete" if not errors else "incomplete",
        "state": "paused_repeated_gateway_closeout",
        "may_start_new_run": False,
        "accrued_usd": _format_nano_usd(accrued),
        "accrued_over_authorization_usd": _format_nano_usd(max(0, accrued - authorized)),
        "remaining_usd": _format_nano_usd(remaining),
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
    original = slot3.status()
    original["funding"] = funding_snapshot(pilot._results(PILOT_ID))
    original["phase"] = "paused_repeated_gateway_closeout"
    original["execution_available"] = False
    original["execution_overlay"] = "slot4_cost_closeout_v1"
    return original


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("freeze")
    actions.add_parser("status")
    args = parser.parse_args()
    value = freeze_reconciliation() if args.action == "freeze" else status()
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
