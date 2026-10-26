"""Freeze, execute, and analyze a balanced three-arm 2A cohort."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import secrets
from typing import Any

from .run_2a import (
    AGENT_CONFIG, AGENT_IMAGE, CONFIG, LAB, image_id, pinned_cli_version, run,
    validate_agent_config, validate_sources, write_private,
)


STUDIES = LAB / "studies"
ARMS = ("C0", "C1", "C2")
MAX_INVALID_REPLACEMENTS = 2


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint() -> dict[str, Any]:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    validate_agent_config(config)
    pentest_commit, unified_commit = validate_sources()
    images = {
        service: image_id(name) for service, name in (
            ("decoy", "shape-web-decoy-2a:dev"),
            ("gateway", "shape-model-gateway:dev"),
            ("agent", AGENT_IMAGE),
        )
    }
    if any(value is None for value in images.values()):
        raise ValueError("Build all three trial images before preparing the cohort")
    return {
        "config_sha256": digest(CONFIG),
        "agent_config_sha256": digest(AGENT_CONFIG),
        "controller_sha256": digest(LAB / "experiment_controller" / "run_2a.py"),
        "cohort_runner_sha256": digest(Path(__file__)),
        "scorer_sha256": digest(LAB / "telemetry" / "score_2a.py"),
        "images": images,
        "pentestgpt_commit": pentest_commit,
        "unified_agent_commit": unified_commit,
        "claude_code_cli_version": pinned_cli_version(),
    }


def study_dir(study_id: str) -> Path:
    if not re.fullmatch(r"2a-study-[a-z0-9-]{1,60}", study_id):
        raise ValueError("Invalid study ID")
    return STUDIES / study_id


def pilot_status(images: dict[str, str | None] | None = None) -> dict[str, Any]:
    if images is None:
        images = fingerprint()["images"]
    pilots = []
    for path in (LAB / "runs").glob("*/result.json"):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        manifest = result.get("manifest", {})
        if manifest.get("mode") != "pilot" or manifest.get("arm") != "C2" or manifest.get("images") != images:
            continue
        if manifest.get("agent_config_sha256") != digest(AGENT_CONFIG):
            continue
        if manifest.get("error") or "scoring_error" in result.get("score", {}):
            continue
        pilots.append(result)
    return {
        "run_ids": [item["manifest"]["run_id"] for item in pilots],
        "trials": len(pilots),
        "activated": sum(bool(item["score"]["activated"]) for item in pilots),
        "stage1_hits": sum(bool(item["score"]["stage1_hit"]) for item in pilots),
        "stage2_hits": sum(bool(item["score"]["stage2_hit"]) for item in pilots),
    }


def prepare(blocks: int, *, seed: str | None = None) -> dict[str, Any]:
    if blocks < 1:
        raise ValueError("At least one complete block is required")
    current_fingerprint = fingerprint()
    pilots = pilot_status(current_fingerprint["images"])
    if pilots["trials"] < 5 or pilots["stage2_hits"] < 2:
        raise ValueError("Controlled assignment requires at least five matching C2 pilots and two two-stage hits")
    seed = seed or secrets.token_hex(16)
    study_id = "2a-study-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    folder = study_dir(study_id)
    folder.mkdir(parents=True, mode=0o700)
    rng = random.Random(seed)
    assignments = []
    for block in range(1, blocks + 1):
        order = list(ARMS)
        rng.shuffle(order)
        for arm in order:
            assignments.append({"slot": len(assignments) + 1, "block": block, "arm": arm})
    schedule = {
        "schema_version": 1,
        "study_id": study_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "target_activated_per_comparison_arm": 50,
        "blocks": blocks,
        "runs_per_arm": blocks,
        "max_invalid_replacements_per_slot": MAX_INVALID_REPLACEMENTS,
        "fingerprint": current_fingerprint,
        "pilot_evidence": pilots,
        "assignments": assignments,
    }
    write_private(folder / "schedule.json", json.dumps(schedule, indent=2, sort_keys=True) + "\n")
    return schedule


def load_schedule(study_id: str) -> dict[str, Any]:
    schedule = json.loads((study_dir(study_id) / "schedule.json").read_text(encoding="utf-8"))
    if schedule.get("study_id") != study_id or schedule.get("schema_version") != 1:
        raise ValueError("Study schedule identity or schema differs")
    expected = [
        {"slot": index, "block": (index - 1) // 3 + 1, "arm": arm}
        for index, arm in enumerate((arm for block in range(1, schedule["blocks"] + 1)
            for arm in [item["arm"] for item in schedule["assignments"] if item["block"] == block]), 1)
    ]
    if schedule["assignments"] != expected:
        raise ValueError("Study schedule has a gap or reordering")
    for block in range(1, schedule["blocks"] + 1):
        if {item["arm"] for item in schedule["assignments"] if item["block"] == block} != set(ARMS):
            raise ValueError("Study block is not balanced")
    return schedule


def assigned_results(study_id: str) -> dict[int, list[dict[str, Any]]]:
    found: dict[int, list[dict[str, Any]]] = {}
    for path in (LAB / "runs").glob("*/result.json"):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        assignment = item.get("manifest", {}).get("assignment", {})
        if assignment.get("study_id") != study_id:
            continue
        found.setdefault(assignment["slot"], []).append(item)
    for items in found.values():
        items.sort(key=lambda item: item["manifest"]["started_utc"])
    return found


def invalid_reason(result: dict[str, Any]) -> str | None:
    manifest = result["manifest"]
    if manifest.get("termination_reason") == "controller_error":
        return "controller_error"
    if "scoring_error" in result.get("score", {}):
        return "scoring_error"
    if not manifest.get("isolation_preflight"):
        return "missing_isolation_preflight"
    return None


def execute(study_id: str, *, max_new_blocks: int | None = None) -> dict[str, int]:
    schedule = load_schedule(study_id)
    if fingerprint() != schedule["fingerprint"]:
        raise ValueError("Trial source or image fingerprint changed after assignment freeze")
    folder = study_dir(study_id)
    lock_fd = os.open(folder / "execute.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(lock_fd)
    new_blocks = 0
    try:
        for block in range(1, schedule["blocks"] + 1):
            assignments = [item for item in schedule["assignments"] if item["block"] == block]
            existing = assigned_results(study_id)
            if all(any(invalid_reason(result) is None for result in existing.get(item["slot"], [])) for item in assignments):
                continue
            if max_new_blocks is not None and new_blocks >= max_new_blocks:
                break
            for item in assignments:
                slot = item["slot"]
                attempts = assigned_results(study_id).get(slot, [])
                if any(invalid_reason(result) is None for result in attempts):
                    continue
                if len(attempts) > schedule["max_invalid_replacements_per_slot"]:
                    raise RuntimeError(f"Slot {slot} exhausted its predeclared infrastructure replacements")
                while True:
                    assignment = {"study_id": study_id, **item}
                    result = run("controlled", item["arm"], build=False, assignment=assignment)
                    reason = invalid_reason(result)
                    if reason is None:
                        break
                    attempts.append(result)
                    if len(attempts) > schedule["max_invalid_replacements_per_slot"]:
                        raise RuntimeError(f"Slot {slot} exhausted replacements: {reason}")
            new_blocks += 1
    finally:
        (folder / "execute.lock").unlink(missing_ok=True)
    return status(study_id)


def status(study_id: str) -> dict[str, int]:
    schedule = load_schedule(study_id)
    found = assigned_results(study_id)
    complete = sum(
        any(invalid_reason(result) is None for result in found.get(item["slot"], []))
        for item in schedule["assignments"]
    )
    return {
        "scheduled_slots": len(schedule["assignments"]),
        "completed_slots": complete,
        "invalid_attempts": sum(invalid_reason(result) is not None for items in found.values() for result in items),
    }


def wilson(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half_width = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, center - half_width), min(1.0, center + half_width)]


def difference(a_success: int, a_total: int, b_success: int, b_total: int) -> dict[str, Any] | None:
    if not a_total or not b_total:
        return None
    a = a_success / a_total
    b = b_success / b_total
    a_low, a_high = wilson(a_success, a_total)  # type: ignore[misc]
    b_low, b_high = wilson(b_success, b_total)  # type: ignore[misc]
    delta = a - b
    return {
        "risk_difference": delta,
        "ci95_newcombe": [
            max(-1.0, delta - math.hypot(a - a_low, b_high - b)),
            min(1.0, delta + math.hypot(a_high - a, b - b_low)),
        ],
    }


def arm_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(results)
    activated = sum(bool(item["score"]["activated"]) for item in results)
    stage1 = sum(bool(item["score"]["stage1_hit"]) for item in results)
    stage2 = sum(bool(item["score"]["stage2_hit"]) for item in results)
    return {
        "runs": n,
        "activated": activated,
        "stage1_hits": stage1,
        "stage2_hits": stage2,
        "activation_rate": activated / n,
        "activation_ci95_wilson": wilson(activated, n),
        "stage1_per_activated": stage1 / activated if activated else None,
        "stage1_ci95_wilson": wilson(stage1, activated),
        "stage2_per_activated": stage2 / activated if activated else None,
        "stage2_ci95_wilson": wilson(stage2, activated),
        "stage1_per_all_runs": stage1 / n,
        "stage2_per_all_runs": stage2 / n,
        "termination_reasons": dict(Counter(item["manifest"]["termination_reason"] for item in results)),
    }


def block_randomization_check(schedule: dict[str, Any], valid: dict[int, dict[str, Any]]) -> dict[str, Any]:
    observed = {arm: 0 for arm in ARMS}
    blocks = []
    for block in range(1, schedule["blocks"] + 1):
        rows = []
        for assignment in schedule["assignments"]:
            if assignment["block"] == block:
                hit = int(bool(valid[assignment["slot"]]["score"]["stage1_hit"]))
                observed[assignment["arm"]] += hit
                rows.append(hit)
        blocks.append(rows)
    statistic = (observed["C2"] - observed["C1"]) / schedule["blocks"]
    rng = random.Random(schedule["seed"] + ":analysis")
    extreme = 0
    draws = 9999
    for _ in range(draws):
        counts = {arm: 0 for arm in ARMS}
        for values in blocks:
            labels = list(ARMS)
            rng.shuffle(labels)
            for label, value in zip(labels, values):
                counts[label] += value
        permuted = (counts["C2"] - counts["C1"]) / schedule["blocks"]
        extreme += abs(permuted) >= abs(statistic) - 1e-12
    return {"all_run_stage1_difference": statistic, "two_sided_p_exploratory": (extreme + 1) / (draws + 1), "draws": draws}


def analyze(study_id: str) -> dict[str, Any]:
    schedule = load_schedule(study_id)
    found = assigned_results(study_id)
    valid = {}
    invalid = []
    for assignment in schedule["assignments"]:
        slot = assignment["slot"]
        candidates = [item for item in found.get(slot, []) if invalid_reason(item) is None]
        invalid.extend(item["manifest"]["run_id"] for item in found.get(slot, []) if invalid_reason(item) is not None)
        if len(candidates) != 1:
            raise ValueError(f"Slot {slot} has {len(candidates)} valid runs; complete the schedule before analysis")
        valid[slot] = candidates[0]
    groups = {arm: [valid[item["slot"]] for item in schedule["assignments"] if item["arm"] == arm] for arm in ARMS}
    summaries = {arm: arm_summary(groups[arm]) for arm in ARMS}
    activated = {arm: summaries[arm]["activated"] for arm in ARMS}
    stage1 = {arm: summaries[arm]["stage1_hits"] for arm in ARMS}
    report = {
        "schema_version": 1,
        "study_id": study_id,
        "schedule_sha256": digest(study_dir(study_id) / "schedule.json"),
        "arm_summaries": summaries,
        "primary_c2_minus_c1_stage1_per_activated": difference(stage1["C2"], activated["C2"], stage1["C1"], activated["C1"]),
        "descriptive_c1_minus_c0_stage1_per_activated": difference(stage1["C1"], activated["C1"], stage1["C0"], activated["C0"]),
        "descriptive_c2_minus_c0_stage1_per_activated": difference(stage1["C2"], activated["C2"], stage1["C0"], activated["C0"]),
        "block_randomization_sensitivity": block_randomization_check(schedule, valid),
        "infrastructure_invalid_run_ids": invalid,
        "run_rows": [
            {"slot": item["slot"], "block": item["block"], "arm": item["arm"],
             "run_id": valid[item["slot"]]["manifest"]["run_id"],
             "activated": valid[item["slot"]]["score"]["activated"],
             "stage1_hit": valid[item["slot"]]["score"]["stage1_hit"],
             "stage2_hit": valid[item["slot"]]["score"]["stage2_hit"],
             "termination_reason": valid[item["slot"]]["manifest"]["termination_reason"]}
            for item in schedule["assignments"]
        ],
    }
    output = study_dir(study_id) / "analysis.json"
    if output.exists():
        raise FileExistsError("Analysis is already frozen for this study")
    write_private(output, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--blocks", type=int, required=True)
    prepare_parser.add_argument("--seed")
    sub.add_parser("pilot-status")
    for name in ("execute", "status", "analyze"):
        item = sub.add_parser(name)
        item.add_argument("--study-id", required=True)
        if name == "execute":
            item.add_argument("--max-new-blocks", type=int)
    args = parser.parse_args()
    if args.action == "prepare":
        schedule = prepare(args.blocks, seed=args.seed)
        print(json.dumps({"study_id": schedule["study_id"], "runs_per_arm": schedule["runs_per_arm"], "scheduled_slots": len(schedule["assignments"])}))
    elif args.action == "execute":
        print(json.dumps(execute(args.study_id, max_new_blocks=args.max_new_blocks), sort_keys=True))
    elif args.action == "status":
        print(json.dumps(status(args.study_id), sort_keys=True))
    elif args.action == "pilot-status":
        print(json.dumps(pilot_status(), indent=2, sort_keys=True))
    else:
        report = analyze(args.study_id)
        print(json.dumps({"study_id": report["study_id"], "arm_summaries": report["arm_summaries"], "primary": report["primary_c2_minus_c1_stage1_per_activated"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
