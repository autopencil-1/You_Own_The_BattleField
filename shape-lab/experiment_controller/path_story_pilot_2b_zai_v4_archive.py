"""Read-only evidence status for the frozen three-attempt v4 Z.ai archive.

This pins the v4 schedule and the first three result archives. It compares
historical image and source IDs recorded at preflight and at run time, without
inspecting current Docker tags. It has no execution or mutation command.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from experiment_controller import path_story_pilot_2b_v2 as prior
from experiment_controller import path_story_pilot_2b_zai_archive as predecessor
from experiment_controller import path_story_pilot_2b_zai_v4 as frozen
from experiment_controller.run_2b_path_story_pilot_zai_v4 import _gateway_lifecycle
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits
from telemetry.replay_2b_path_story import verify_path_story_bundle


LAB = Path(__file__).resolve().parents[1]
PILOT_ID = "2b-path-story-pilot-v4-zai-20261109150154-7a81b0"
SCHEDULE_SHA256 = "6fad5f55435dabc6e839ac541751cc7e9353f3ee7d98727d78a14e228ceef9b8"
STUDY = LAB / "studies" / PILOT_ID
REPORT = LAB / "runs" / "path-story-zai-v4-preflight-r2-20261109" / "report.json"
RUN_HASHES = {
    "2b-path-20261109150216-16d7a7": {
        "attempt_manifest": "5d25b29e36a31fac9e0e23c965172296f9bed7f79ecc211cba29ffc8e0eb54f9",
        "gateway_events": "915b5c650907e50ad55d50a10c3cf157cb1ce5f906f3e5c44d9a637e4bdeb907",
        "result": "40e5b2833ef1fa5f1bce8ef39434a0d4829cf5a8ac03907b5f269dd844530c54",
    },
    "2b-path-20261109151433-6dd657": {
        "attempt_manifest": "6b14c7126ed8be41a8bcc03f84ef7c197cfb4f7faac369163a0201874f28b276",
        "gateway_events": "2c021a44f42fc05e3cbb211282093b8888bc5132052013c06bd7a550e0c8eebc",
        "result": "76d35377c44ce5aa917425fb43b145f976a3ac28f70a1bf341c88e4c11f87476",
    },
    "2b-path-20261109152656-9f0b8f": {
        "attempt_manifest": "dea9b2404567539a11abe4963d621e331e54aad8d7d6e77d09e9f9fb3b715fdc",
        "gateway_events": "00270647263ca80d8d4836a7d664337777a83b3f7af669df9f8d5b8a826ba44b",
        "result": "d2960ff03efe2b3bb7b1d1bd6ddae2b0fa4a09ad542b05aa7142361e408fb14d",
    },
}


class ArchiveIntegrityError(RuntimeError):
    """A pinned v4 schedule or attempt differs from its evidence."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _usage_credits(rows: list[dict[str, Any]], governance: dict[str, Any]) -> str:
    """Calculate credits directly from journal usage and frozen multipliers."""
    total = Decimal(0)
    for row in rows:
        if row.get("event_type") != "model_call" or row.get("status") != 200:
            continue
        usage = row.get("usage")
        if not isinstance(usage, dict):
            raise ArchiveIntegrityError("Successful model response lacks usage")
        values = {}
        for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"):
            value = usage.get(key, 0)
            if type(value) is not int or value < 0:
                raise ArchiveIntegrityError("Model usage is malformed")
            values[key] = value
        try:
            observed = datetime.fromisoformat(row["timestamp_utc"].replace("Z", "+00:00"))
        except (KeyError, AttributeError, ValueError) as exc:
            raise ArchiveIntegrityError("Model timestamp is malformed") from exc
        if observed.tzinfo is None:
            raise ArchiveIntegrityError("Model timestamp has no timezone")
        utc = observed.astimezone(timezone.utc)
        amount = (
            Decimal(values["input_tokens"] + values["cache_creation_input_tokens"])
            * Decimal(governance["input_multiplier"])
            + Decimal(values["cache_read_input_tokens"])
            * Decimal(governance["cached_input_multiplier"])
            + Decimal(values["output_tokens"])
            * Decimal(governance["output_multiplier"])
        ) / Decimal(governance["tokens_per_credit_unit"])
        peak = (
            utc.weekday() in governance["peak_weekdays_utc"]
            and governance["peak_start_hour_utc"] <= utc.hour < governance["peak_end_hour_utc"]
        )
        total += amount if peak else amount * Decimal(governance["off_peak_multiplier"])
    return format(total, ".9f")


def archive_status() -> dict[str, Any]:
    try:
        schedule = prior._read_committed(STUDY / "schedule.json")
        report = prior._read_committed(REPORT)
    except Exception as exc:
        raise ArchiveIntegrityError("Committed v4 schedule or preflight report is unavailable") from exc
    if _sha(STUDY / "schedule.json") != SCHEDULE_SHA256:
        raise ArchiveIntegrityError("Frozen v4 schedule SHA-256 differs")
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
        or {arm: sum(row.get("arm") == arm for row in assignments) for arm in prior.ARMS}
        != {arm: 2 for arm in prior.ARMS}
        or schedule.get("contract_sha256") != schedule.get("fingerprint", {}).get("contract_sha256")
    ):
        raise ArchiveIntegrityError("Frozen v4 assignment semantics differ")
    fingerprint = schedule["fingerprint"]
    images = fingerprint.get("images")
    if (
        not isinstance(images, dict)
        or set(images) != {"agent", "decoy", "gateway"}
        or any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
               for value in images.values())
    ):
        raise ArchiveIntegrityError("Historical v4 image IDs are malformed")
    source_hashes = fingerprint.get("source_sha256")
    if (
        not isinstance(source_hashes, dict)
        or not source_hashes
        or any(not isinstance(name, str) or not isinstance(digest, str)
               or not re.fullmatch(r"[0-9a-f]{64}", digest)
               for name, digest in source_hashes.items())
        or _sha(REPORT) != schedule.get("source_model_free_report_sha256")
        or report.get("source_sha256") != source_hashes
        or report.get("agent_source_sha256") != fingerprint.get("agent_source_sha256")
        or report.get("task_sha256") != fingerprint.get("agent_task_sha256")
        or report.get("fixture_sha256") != fingerprint.get("fixture_sha256")
        or report.get("candidate_protocol") != "2b-path-story-pilot-v4-zai-preflight"
        or report.get("model_calls") != 0
    ):
        raise ArchiveIntegrityError("Historical v4 source/preflight evidence differs")
    preflights = report.get("preflights")
    if (
        not isinstance(preflights, list)
        or len(preflights) != 2
        or [(row.get("arm"), row.get("status"), row.get("model_calls"), row.get("agent_started"))
            for row in preflights]
        != [("B0", "passed", 0, False), ("B3", "passed", 0, False)]
        or any(row.get("images") != images for row in preflights)
    ):
        raise ArchiveIntegrityError("Historical v4 image preflight differs")

    v3 = predecessor.archive_status()
    if len(v3["attempts"]) != 1 or v3["attempts"][0]["classification"] != "controller_error":
        raise ArchiveIntegrityError("Predecessor v3 attempt set differs")
    carry = contract.get("predecessor_v3_context")
    prior_run = LAB / "runs" / v3["attempts"][0]["run_id"]
    expected_carry = {
        "pilot_id": v3["pilot_id"],
        "schedule_sha256": v3["schedule_sha256"],
        "invalid_run_id": prior_run.name,
        "attempt_manifest_sha256": _sha(prior_run / "attempt-manifest.json"),
        "gateway_events_sha256": _sha(prior_run / "gateway-events.jsonl"),
        "estimated_credits": v3["estimated_total_credits"],
        "valid_slots_carried_forward": [],
    }
    if (
        not isinstance(carry, dict)
        or carry != expected_carry
        or report.get("predecessor_v3_context") != carry
        or v3["estimated_total_credits"] != "100.809835000"
    ):
        raise ArchiveIntegrityError("Predecessor v3 credit carry differs")

    found = prior._results(PILOT_ID)
    if set(found) != {1, 2, 3} or any(len(found[slot]) != 1 for slot in (1, 2, 3)):
        raise ArchiveIntegrityError("V4 three-attempt archive differs")
    valid, invalid, _ = frozen._attempts(schedule)
    if (
        sorted(valid) != [1, 2]
        or invalid != [{
            "slot": 3,
            "run_id": "2b-path-20261109152656-9f0b8f",
            "reason": "controller_error",
        }]
    ):
        raise ArchiveIntegrityError("V4 three-attempt classification differs")
    attempts: list[dict[str, Any]] = []
    v4_total = Decimal(0)
    for slot in (1, 2, 3):
        result = found[slot][0]
        manifest = result.get("manifest")
        if not isinstance(manifest, dict):
            raise ArchiveIntegrityError("V4 result lacks an attempt manifest")
        run_id = manifest.get("run_id")
        if run_id not in RUN_HASHES:
            raise ArchiveIntegrityError("V4 run ID differs")
        run_dir = prior._verify_attempt_artifacts(result)
        hashes = {
            "attempt_manifest": _sha(run_dir / "attempt-manifest.json"),
            "gateway_events": _sha(run_dir / "gateway-events.jsonl"),
            "result": _sha(run_dir / "result.json"),
        }
        if hashes != RUN_HASHES[run_id]:
            raise ArchiveIntegrityError("Pinned v4 result or journal SHA-256 differs")
        assignment = assignments[slot - 1]
        if (
            manifest.get("assignment") != {
                "pilot_id": PILOT_ID,
                **{key: assignment[key] for key in ("slot", "block", "arm", "seed")},
            }
            or manifest.get("pilot_protocol") != frozen.PROTOCOL
            or manifest.get("provider") != "zai"
            or manifest.get("pilot_fingerprint") != fingerprint
            or manifest.get("images") != images
            or manifest.get("compose_sha256") != fingerprint.get("compose_sha256")
            or manifest.get("agent_task_sha256") != fingerprint.get("agent_task_sha256")
            or manifest.get("fixture_sha256") != fingerprint.get("fixture_sha256")
        ):
            raise ArchiveIntegrityError("V4 run provenance differs from schedule")
        replay = verify_path_story_bundle(run_dir)
        if result.get("replay") != replay or manifest.get("replay") != replay:
            raise ArchiveIntegrityError("V4 replay differs")
        try:
            gateway = [json.loads(line) for line in (run_dir / "gateway-events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ArchiveIntegrityError("V4 gateway journal is malformed") from exc
        if any(not isinstance(row, dict) or row.get("run_id") != run_id
               or row.get("source") != "model-gateway" or row.get("provider") != "zai"
               for row in gateway):
            raise ArchiveIntegrityError("V4 gateway journal identity differs")
        lifecycle = _gateway_lifecycle(gateway)
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
            or lifecycle["aborted_request_ids"]
            or lifecycle["unaccounted_request_ids"]
            or lifecycle["unmatched_request_ids"]
        ):
            raise ArchiveIntegrityError("V4 gateway settlement differs from journal")
        credits = estimate_gateway_events_credits(gateway)
        manual_credits = _usage_credits(gateway, contract["coding_plan_credit_governance"])
        if (
            credits["estimated_total_credits"] != manual_credits
            or result.get("provider_credits") != credits
            or manifest.get("provider_credits") != credits
        ):
            raise ArchiveIntegrityError("V4 credits differ from provider usage")
        v4_total += Decimal(manual_credits)
        classification = "valid" if slot in valid else invalid[0]["reason"]
        attempts.append({
            "run_id": run_id,
            "slot": slot,
            "arm": assignment["arm"],
            "classification": classification,
            "hashes_sha256": hashes,
            "artifact_count": len(manifest["artifact_sha256"]),
            "replay_verified": True,
            "filesystem_actions": replay.get("filesystem_actions"),
            "materialized_nodes": replay.get("materialized_nodes"),
            "gateway_lifecycle": lifecycle,
            "estimated_credits": manual_credits,
            "historical_image_ids_match_schedule": True,
        })
    pending_path = STUDY / "pending-run.json"
    pending = prior._read_committed(pending_path) if pending_path.exists() else None
    if pending is not None:
        raise ArchiveIntegrityError("V4 archive has an unclosed pending run")
    return {
        "archive_protocol": "2b-path-story-pilot-v4-zai-three-attempt-read-only-archive",
        "pilot_id": PILOT_ID,
        "schedule_sha256": SCHEDULE_SHA256,
        "schedule_verified": True,
        "model_free_report_sha256": _sha(REPORT),
        "historical_image_ids": images,
        "source_fingerprint_sha256": hashlib.sha256(
            json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "current_docker_tags_checked": False,
        "predecessor_v3": expected_carry,
        "completed_slots": sorted(valid),
        "valid_runs": len(valid),
        "invalid_attempts": invalid,
        "attempts": attempts,
        "next_slot": 3,
        "pending_run": None,
        "estimated_v4_credits": format(v4_total, ".9f"),
        "estimated_total_including_v3_carry": format(
            v4_total + Decimal(v3["estimated_total_credits"]), ".9f"
        ),
        "execution_available": False,
    }


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(archive_status(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
