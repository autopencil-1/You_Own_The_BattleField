"""Read-only status for the frozen v3 Z.ai path-story pilot archive.

Historical Docker image IDs are checked against the committed preflight and
run manifests. Current image tags are deliberately never inspected: rebuilding
images cannot change what the archived trial used. This module has no command
to prepare, execute, reconcile, or alter a pilot.
"""

from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from experiment_controller import path_story_pilot_2b_v2 as prior
from experiment_controller import path_story_pilot_2b_zai_execution as frozen
from experiment_controller.run_2b_path_story_pilot_zai import _gateway_lifecycle
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits
from telemetry.replay_2b_path_story import verify_path_story_bundle


LAB = Path(__file__).resolve().parents[1]
PILOT_ID = "2b-path-story-pilot-v3-zai-20261109124716-3c0485"
SCHEDULE_SHA256 = "32af55e9b613d25d80ea8e3c386f5d0cf1be85a86e87b95e2fd35edb660bf9c5"
STUDY = LAB / "studies" / PILOT_ID
REPORT = LAB / "runs" / "path-story-zai-candidate-20261109122935-0e4fe8" / "report.json"


class ArchiveIntegrityError(RuntimeError):
    """Historical evidence differs from the frozen commitment."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _gateway_rows(path: Path, run_id: str) -> list[dict[str, Any]]:
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveIntegrityError("Gateway journal is missing or malformed") from exc
    if any(
        not isinstance(row, dict)
        or row.get("run_id") != run_id
        or row.get("source") != "model-gateway"
        or row.get("provider") != "zai"
        for row in rows
    ):
        raise ArchiveIntegrityError("Gateway journal identity differs")
    return rows


def archive_status() -> dict[str, Any]:
    """Verify committed files and replay every archived v3 Z.ai attempt."""
    try:
        schedule = prior._read_committed(STUDY / "schedule.json")
    except Exception as exc:
        raise ArchiveIntegrityError("Committed schedule cannot be read") from exc
    if _sha(STUDY / "schedule.json") != SCHEDULE_SHA256:
        raise ArchiveIntegrityError("Frozen schedule SHA-256 differs")
    contract = schedule.get("contract")
    assignments = schedule.get("assignments")
    if (
        schedule.get("schema_version") != 1
        or schedule.get("pilot_id") != PILOT_ID
        or schedule.get("pilot_protocol") != frozen.PROTOCOL
        or not isinstance(contract, dict)
        or contract.get("pilot_protocol") != frozen.PROTOCOL
        or not isinstance(assignments, list)
        or len(assignments) != 8
        or assignments != prior.assignments(contract, schedule.get("randomization_seed", ""))
        or {arm: sum(row.get("arm") == arm for row in assignments)
            for arm in prior.ARMS} != {arm: 2 for arm in prior.ARMS}
    ):
        raise ArchiveIntegrityError("Frozen assignment semantics differ")
    fingerprint = schedule.get("fingerprint")
    if not isinstance(fingerprint, dict):
        raise ArchiveIntegrityError("Schedule fingerprint is missing")
    images = fingerprint.get("images")
    if (
        not isinstance(images, dict)
        or set(images) != {"agent", "decoy", "gateway"}
        or any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
               for value in images.values())
    ):
        raise ArchiveIntegrityError("Historical Docker image IDs are malformed")
    if _sha(REPORT) != schedule.get("source_model_free_report_sha256"):
        raise ArchiveIntegrityError("Committed model-free preflight report differs")
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    preflights = report.get("preflights")
    if (
        report.get("candidate_protocol") != "2b-path-story-pilot-v3-zai-candidate"
        or report.get("model_calls") != 0
        or not isinstance(preflights, list)
        or len(preflights) != 2
        or [(row.get("arm"), row.get("status"), row.get("model_calls"), row.get("agent_started"))
            for row in preflights]
        != [("B0", "passed", 0, False), ("B3", "passed", 0, False)]
        or any(row.get("images") != images for row in preflights)
    ):
        raise ArchiveIntegrityError("Historical Docker preflight differs")

    # The frozen classifier reads only archived results; it does not call
    # load_schedule(), whose execution gate inspects current Docker tags.
    valid, invalid, _ = frozen._attempts(schedule)
    found = prior._results(PILOT_ID)
    attempts: list[dict[str, Any]] = []
    total_credits = Decimal(0)
    for assignment in assignments:
        slot = assignment["slot"]
        for result in found.get(slot, []):
            manifest = result.get("manifest")
            if not isinstance(manifest, dict):
                raise ArchiveIntegrityError("Archived result lacks a manifest")
            run_id = manifest.get("run_id")
            if not isinstance(run_id, str) or prior.RUN_ID.fullmatch(run_id) is None:
                raise ArchiveIntegrityError("Archived run ID is invalid")
            run_dir = prior._verify_attempt_artifacts(result)
            if (
                manifest.get("pilot_fingerprint") != fingerprint
                or manifest.get("images") != images
                or manifest.get("compose_sha256") != fingerprint.get("compose_sha256")
                or manifest.get("agent_task_sha256") != fingerprint.get("agent_task_sha256")
                or manifest.get("fixture_sha256") != fingerprint.get("fixture_sha256")
            ):
                raise ArchiveIntegrityError("Run provenance differs from the schedule")
            replay = verify_path_story_bundle(run_dir)
            if result.get("replay") != replay or manifest.get("replay") != replay:
                raise ArchiveIntegrityError("Archived replay differs")
            rows = _gateway_rows(run_dir / "gateway-events.jsonl", run_id)
            lifecycle = _gateway_lifecycle(rows)
            settlement = manifest.get("provider_settlement")
            compared = (
                "started_request_count", "finished_request_count",
                "provider_completed_request_count", "local_rejection_request_count",
                "downstream_delivery_failed_ids", "aborted_request_ids",
                "unaccounted_request_ids", "unmatched_request_ids",
            )
            if (
                not isinstance(settlement, dict)
                or settlement.get("state") != "complete"
                or any(settlement.get(key) != lifecycle[key] for key in compared)
                or lifecycle["unaccounted_request_ids"]
                or lifecycle["unmatched_request_ids"]
                or lifecycle["aborted_request_ids"]
            ):
                raise ArchiveIntegrityError("Gateway settlement differs from journal")
            credits = estimate_gateway_events_credits(rows)
            if result.get("provider_credits") != credits or manifest.get("provider_credits") != credits:
                raise ArchiveIntegrityError("Archived credits differ from provider usage")
            total_credits += Decimal(credits["estimated_total_credits"])
            classification = "valid" if slot in valid and valid[slot] == result else next(
                (row["reason"] for row in invalid if row["run_id"] == run_id), None
            )
            if classification is None:
                raise ArchiveIntegrityError("Archived attempt has no classification")
            attempts.append({
                "run_id": run_id,
                "slot": slot,
                "arm": assignment["arm"],
                "classification": classification,
                "artifact_count": len(manifest["artifact_sha256"]),
                "replay_verified": True,
                "filesystem_actions": replay.get("filesystem_actions"),
                "materialized_nodes": replay.get("materialized_nodes"),
                "gateway_lifecycle": lifecycle,
                "estimated_credits": credits["estimated_total_credits"],
                "historical_image_ids_match_schedule": True,
            })
    next_slot = next((row["slot"] for row in assignments if row["slot"] not in valid), None)
    pending_path = STUDY / "pending-run.json"
    pending = prior._read_committed(pending_path) if pending_path.exists() else None
    return {
        "archive_protocol": "2b-path-story-pilot-v3-zai-read-only-archive",
        "pilot_id": PILOT_ID,
        "schedule_sha256": SCHEDULE_SHA256,
        "schedule_verified": True,
        "model_free_report_sha256": _sha(REPORT),
        "historical_image_ids": images,
        "current_docker_tags_checked": False,
        "completed_slots": sorted(valid),
        "valid_runs": len(valid),
        "invalid_attempts": invalid,
        "attempts": attempts,
        "next_slot": next_slot,
        "pending_run": pending,
        "estimated_total_credits": format(total_credits, ".9f"),
        "execution_available": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(archive_status(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
