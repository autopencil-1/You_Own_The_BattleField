"""Evidence preserving cost reconciliation and serial resume for controlled v3.

The frozen schedule and invalid run archive remain byte for byte unchanged.
Only the exact archived gateway stderr contamination identified below is
excluded from provider usage accounting. The attempt remains invalid.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
from typing import Any

from experiment_controller import controlled_2b_v3 as study
from experiment_controller.controlled_2b_v3_contract import LAB, sha256
from experiment_controller.provider_cost_2b import (
    _format_nano_usd,
    estimate_gateway_events_cost,
)
from experiment_controller.run_2b_controlled_v3 import run_controlled_v3, write_private


STUDY_ID = "2b-study-v3-20261106131028-e43a20"
RUN_ID = "2b-cont-20261106144106-59c56c"
RAW_GATEWAY_SHA256 = "232fc48981550cc1dbdc5677ad44ccc30f46bf987b529d449abae9ac6ffde4c8"
SCHEDULE_SHA256 = "219909085a5ecb6a67fddbe5dced63381759b59877066af11d17622ad0143d5b"
RECONCILIATION = study.study_dir(STUDY_ID) / "cost-reconciliation.json"


def _expected() -> dict[str, Any]:
    schedule = study.load_schedule(STUDY_ID)
    if sha256(study.study_dir(STUDY_ID) / "schedule.json") != SCHEDULE_SHA256:
        raise study.StudyIntegrityError("Recovery schedule commitment differs")
    if sha256(study.SOURCE_FILES["scheduler"]) != schedule["fingerprint"]["v3_source_sha256"]["scheduler"]:
        raise study.StudyIntegrityError("Frozen scheduler changed")
    if sha256(study.SOURCE_FILES["runner"]) != schedule["fingerprint"]["v3_source_sha256"]["runner"]:
        raise study.StudyIntegrityError("Frozen runner changed")
    run_dir = LAB / "runs" / RUN_ID
    gateway = run_dir / "gateway-events.jsonl"
    manifest_path = run_dir / "manifest.json"
    result_path = run_dir / "result.json"
    if sha256(gateway) != RAW_GATEWAY_SHA256:
        raise study.StudyIntegrityError("Raw gateway archive changed")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if (
        manifest.get("run_id") != RUN_ID
        or manifest.get("assignment") != {
            "study_id": STUDY_ID, "slot": 9, "block": 3, "arm": "B1"
        }
        or manifest.get("artifact_sha256", {}).get("gateway-events.jsonl") != RAW_GATEWAY_SHA256
        or result.get("manifest") != manifest
        or study.invalid_reason(result, schedule, schedule["assignments"][8]) != "replay_failure"
    ):
        raise study.StudyIntegrityError("Invalid slot-9 archive classification changed")
    lines = gateway.read_text(encoding="utf-8").splitlines()
    if len(lines) != 142 or lines[121] != "----------------------------------------":
        raise study.StudyIntegrityError("Gateway stderr boundary differs")
    if "BrokenPipeError: [Errno 32] Broken pipe" not in lines[121:]:
        raise study.StudyIntegrityError("Gateway stderr diagnosis differs")
    rows = [json.loads(line) for line in lines[:121]]
    if (
        any(line.startswith("{") for line in lines[121:])
        or [row.get("sequence") for row in rows] != list(range(1, 122))
        or any(row.get("run_id") != RUN_ID or row.get("event_type") != "model_call" or row.get("status") != 200 for row in rows)
    ):
        raise study.StudyIntegrityError("Gateway event prefix is incomplete")
    governance = {"rate_card": schedule["contract"]["provider_cost_review"]["rate_card"]}
    estimate = estimate_gateway_events_cost(rows, governance)
    if estimate["estimated_cost_nano_usd"] != 6_212_324_560:
        raise study.StudyIntegrityError("Reconciled provider cost differs")
    return {
        "schema_version": 1,
        "study_id": STUDY_ID,
        "schedule_sha256": SCHEDULE_SHA256,
        "run_id": RUN_ID,
        "slot": 9,
        "classification": "infrastructure_invalid_replay_failure",
        "raw_gateway_sha256": RAW_GATEWAY_SHA256,
        "manifest_sha256": sha256(manifest_path),
        "result_sha256": sha256(result_path),
        "gateway_json_event_lines": 121,
        "gateway_stderr_lines": 21,
        "stderr_diagnosis": "docker_logs_merged_gateway_broken_pipe_traceback",
        "cost_evidence": estimate,
        "archive_modified": False,
        "creates_trial_attempt": False,
        "creates_censored_outcome": False,
        "recovery_source_sha256": sha256(Path(__file__)),
    }


def freeze_reconciliation() -> dict[str, Any]:
    expected = _expected()
    if RECONCILIATION.exists():
        if study._committed(RECONCILIATION) != expected:
            raise study.StudyIntegrityError("Existing reconciliation differs")
    else:
        study._write_committed(RECONCILIATION, expected)
    return expected


def load_reconciliation() -> dict[str, Any]:
    recorded = study._committed(RECONCILIATION)
    if recorded != _expected():
        raise study.StudyIntegrityError("Cost reconciliation differs from raw evidence")
    return recorded


def funding_snapshot(found: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    reconciliation = load_reconciliation()
    base = study.funding_snapshot(STUDY_ID, found)
    matching = [row for row in base["errors"] if row.get("run_id") == RUN_ID]
    if len(matching) != 1:
        raise study.StudyIntegrityError("Reconciled run is missing from cost errors")
    errors = [row for row in base["errors"] if row.get("run_id") != RUN_ID]
    accrued = (
        study._usd_to_nano(base["accrued_usd"], "accrued cost")
        + reconciliation["cost_evidence"]["estimated_cost_nano_usd"]
    )
    authorized = study._usd_to_nano(base["authorized_usd"], "authorization")
    remaining = max(0, authorized - accrued)
    admitted = not errors and remaining >= study.RESERVE_NANO_USD
    return {
        **base,
        "accounting_state": "complete" if not errors else "incomplete",
        "accrued_usd": _format_nano_usd(accrued),
        "remaining_usd": _format_nano_usd(remaining),
        "attempts_priced": base["attempts_priced"] + 1,
        "errors": errors,
        "may_start_new_run": admitted,
        "state": "admitted" if admitted else "paused_incomplete_cost_evidence" if errors else "paused_insufficient_reserve",
        "reconciliation_sha256": sha256(RECONCILIATION),
        "reconciled_run_id": RUN_ID,
    }


def status() -> dict[str, Any]:
    original = study.status(STUDY_ID)
    found = study._results(STUDY_ID)
    funding = funding_snapshot(found)
    original["funding"] = funding
    if original["pending_run"] is None:
        original["phase"] = (
            "execution_complete_awaiting_annotation"
            if original["next_slot"] is None
            else "execution_enabled" if funding["may_start_new_run"]
            else "paused_provider_cost_admission"
        )
    original["execution_overlay"] = "slot9_cost_reconciliation_v1"
    return original


def execute(*, max_new_runs: int | None = None) -> dict[str, Any]:
    schedule = study.load_schedule(STUDY_ID)
    load_reconciliation()
    if study.fingerprint() != schedule["fingerprint"]:
        raise study.StudyIntegrityError("Frozen source or image fingerprint changed")
    if max_new_runs is not None and (not isinstance(max_new_runs, int) or isinstance(max_new_runs, bool) or max_new_runs < 1):
        raise ValueError("max_new_runs must be positive")
    folder = study.study_dir(STUDY_ID)
    lock = folder / "execute.lock"
    pending = folder / "pending-run.json"
    if pending.exists():
        raise study.StudyIntegrityError("A prior run needs archive reconciliation")
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    created = 0
    try:
        for row in schedule["assignments"]:
            while True:
                found = study._results(STUDY_ID)
                valid, invalid = study._classified(schedule, found)
                if row["slot"] in valid:
                    break
                attempts = [item for item in invalid if item["slot"] == row["slot"]]
                maximum = schedule["contract"]["replacement_policy"]["maximum_infrastructure_invalid_replacements_per_slot"]
                if len(attempts) > maximum:
                    raise study.StudyIntegrityError(f"Slot {row['slot']} exceeded its replacement allowance")
                if max_new_runs is not None and created >= max_new_runs:
                    return status()
                if not funding_snapshot(found)["may_start_new_run"]:
                    return status()
                assignment = {"study_id": STUDY_ID, **{key: row[key] for key in ("slot", "block", "arm")}}
                run_id = "2b-cont-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
                write_private(pending, study._canonical({
                    "study_id": STUDY_ID,
                    "slot": row["slot"],
                    "run_id": run_id,
                    "schedule_sha256": SCHEDULE_SHA256,
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                }))
                result = run_controlled_v3(row["arm"], assignment=assignment, frozen_fingerprint=schedule["fingerprint"], run_id=run_id)
                pending.unlink()
                created += 1
                if study.invalid_reason(result, schedule, row) == "provider_rate_limit":
                    raise RuntimeError("Provider rate limit; resume the frozen slot later")
    finally:
        lock.unlink(missing_ok=True)
    return status()


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("freeze")
    sub.add_parser("status")
    item = sub.add_parser("execute")
    item.add_argument("--max-new-runs", type=int)
    args = parser.parse_args()
    value = freeze_reconciliation() if args.action == "freeze" else status() if args.action == "status" else execute(max_new_runs=args.max_new_runs)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
