"""Review and freeze the effect-blind 2B horizon-support readiness gate.

This post-execution evaluator is intentionally separate from the frozen
support-pilot scheduler.  It consumes the committed schedule and immutable run
archives without changing the execution pipeline that produced them.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from experiment_controller import support_pilot_2b
from experiment_controller.support_pilot_2b_contract import (
    ARMS,
    LAB,
    READINESS_CHECKS,
)
from telemetry.adjudicate_2b import resolve_annotations
from telemetry.annotate_2b import review_packet
from telemetry.replay_2b import verify_run


EVALUATOR = Path(__file__).resolve()
PILOT_PROTOCOL = "2b-support-pilot-v3"
TAU_SECONDS = 600


class SupportReadinessIntegrityError(RuntimeError):
    """The committed review or execution evidence is inconsistent."""


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def _complete_results(
    pilot_id: str,
) -> tuple[dict[str, Any], dict[int, dict[str, Any]], list[dict[str, Any]]]:
    schedule = support_pilot_2b.load_schedule(pilot_id)
    found = support_pilot_2b.assigned_results(pilot_id)
    valid, invalid = support_pilot_2b._classify(schedule, found)
    missing = [
        row["slot"] for row in schedule["assignments"] if row["slot"] not in valid
    ]
    if missing:
        raise ValueError(
            "Support-pilot execution is incomplete; missing valid slots: "
            + ", ".join(map(str, missing))
        )
    return schedule, valid, invalid


def _analysis_entered(score: dict[str, Any]) -> bool:
    return (
        score.get("entry_success") is True
        and isinstance(score.get("first_successful_interaction_utc"), str)
        and isinstance(score.get("retention_dwell_time_s"), (int, float))
        and not isinstance(score.get("retention_dwell_time_s"), bool)
    )


def prepare_review_packets(pilot_id: str) -> dict[str, Any]:
    """Commit deterministic arm-blinded packets for every entered valid run."""

    schedule, valid, _ = _complete_results(pilot_id)
    root = support_pilot_2b.pilot_dir(pilot_id)
    folder = root / "review-packets"
    if not (folder / "index.json").exists() and (
        any((root / "annotations").rglob("*.json"))
        or any((root / "adjudications").glob("*.json"))
    ):
        raise SupportReadinessIntegrityError(
            "Review annotations exist before the packet set was committed"
        )

    packet_rows: list[dict[str, str]] = []
    entered_run_ids: list[str] = []
    nonentered_run_ids: list[str] = []
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        run_id = result["manifest"]["run_id"]
        if not _analysis_entered(result["score"]):
            nonentered_run_ids.append(run_id)
            continue
        packet = review_packet(LAB / "runs" / run_id)
        if packet.get("run_id") != run_id or packet.get("arm_label_included") is not False:
            raise SupportReadinessIntegrityError(
                f"Review packet identity differs for {run_id}"
            )
        output = folder / f"{run_id}.json"
        rendered = _canonical(packet)
        if output.exists():
            if output.read_text(encoding="utf-8") != rendered:
                raise SupportReadinessIntegrityError(
                    f"Existing review packet differs for {run_id}"
                )
        else:
            _write_private(output, rendered)
        entered_run_ids.append(run_id)
        packet_rows.append(
            {"run_id": run_id, "file": output.name, "sha256": _sha256(output)}
        )

    index = {
        "schema_version": 1,
        "pilot_protocol": PILOT_PROTOCOL,
        "pilot_id": pilot_id,
        "schedule_sha256": support_pilot_2b.schedule_sha256(pilot_id),
        "packets": packet_rows,
        "nonentered_run_ids": nonentered_run_ids,
    }
    index_path = folder / "index.json"
    commitment_path = folder / "index.sha256"
    rendered = _canonical(index)
    if index_path.exists():
        if index_path.read_text(encoding="utf-8") != rendered:
            raise SupportReadinessIntegrityError(
                "Existing review packet index differs"
            )
    else:
        _write_private(index_path, rendered)
    commitment = _sha256(index_path) + "\n"
    if commitment_path.exists():
        if commitment_path.read_text(encoding="utf-8") != commitment:
            raise SupportReadinessIntegrityError(
                "Review packet index commitment differs"
            )
    else:
        _write_private(commitment_path, commitment)
    return {
        "pilot_id": pilot_id,
        "entered_packets": len(entered_run_ids),
        "entered_run_ids": entered_run_ids,
        "nonentered_runs": len(nonentered_run_ids),
        "nonentered_run_ids": nonentered_run_ids,
        "packet_index_sha256": _sha256(index_path),
        "ready_for_independent_review": True,
    }


def _verify_review_packets(
    schedule: dict[str, Any], valid: dict[int, dict[str, Any]]
) -> dict[str, Any]:
    pilot_id = schedule["pilot_id"]
    folder = support_pilot_2b.pilot_dir(pilot_id) / "review-packets"
    index_path = folder / "index.json"
    commitment_path = folder / "index.sha256"
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        commitment = commitment_path.read_text(encoding="utf-8").strip()
    except (OSError, json.JSONDecodeError) as exc:
        raise SupportReadinessIntegrityError(
            "Review packet index is missing or malformed"
        ) from exc
    if not re.fullmatch(r"[0-9a-f]{64}", commitment) or _sha256(
        index_path
    ) != commitment:
        raise SupportReadinessIntegrityError(
            "Review packet index differs from its commitment"
        )

    entered: list[dict[str, str]] = []
    nonentered: list[str] = []
    expected_files = {"index.json", "index.sha256"}
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        run_id = result["manifest"]["run_id"]
        path = folder / f"{run_id}.json"
        if not _analysis_entered(result["score"]):
            nonentered.append(run_id)
            if path.exists():
                raise SupportReadinessIntegrityError(
                    "Non-entered run has a review packet"
                )
            continue
        expected_files.add(path.name)
        regenerated = _canonical(review_packet(LAB / "runs" / run_id))
        try:
            observed = path.read_text(encoding="utf-8")
            packet = json.loads(observed)
        except (OSError, json.JSONDecodeError) as exc:
            raise SupportReadinessIntegrityError(
                f"Review packet is missing or malformed for {run_id}"
            ) from exc
        if (
            observed != regenerated
            or packet.get("run_id") != run_id
            or packet.get("arm_label_included") is not False
        ):
            raise SupportReadinessIntegrityError(
                f"Review packet differs for {run_id}"
            )
        entered.append(
            {"run_id": run_id, "file": path.name, "sha256": _sha256(path)}
        )
    expected_index = {
        "schema_version": 1,
        "pilot_protocol": PILOT_PROTOCOL,
        "pilot_id": pilot_id,
        "schedule_sha256": support_pilot_2b.schedule_sha256(pilot_id),
        "packets": entered,
        "nonentered_run_ids": nonentered,
    }
    if index != expected_index:
        raise SupportReadinessIntegrityError("Review packet index content differs")
    actual_files = {path.name for path in folder.iterdir() if path.is_file()}
    if actual_files != expected_files:
        raise SupportReadinessIntegrityError(
            "Review packet directory contains unexpected files"
        )
    return index


def _annotation_paths(pilot_id: str, run_id: str) -> list[Path]:
    root = support_pilot_2b.pilot_dir(pilot_id) / "annotations" / run_id
    return sorted(root.glob("*.json")) if root.is_dir() else []


def _adjudication_path(pilot_id: str, run_id: str) -> Path | None:
    path = support_pilot_2b.pilot_dir(pilot_id) / "adjudications" / f"{run_id}.json"
    return path if path.is_file() else None


def review_status(pilot_id: str) -> dict[str, Any]:
    """Validate exactly two blinded reviews and all required adjudications."""

    schedule, valid, _ = _complete_results(pilot_id)
    _verify_review_packets(schedule, valid)
    resolved: dict[str, dict[str, Any]] = {}
    shortfalls: list[dict[str, Any]] = []
    nonentered: list[str] = []
    entered_count = 0
    required = schedule["contract"]["annotation"]["reviewers_per_entered_run"]
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        run_id = result["manifest"]["run_id"]
        if not _analysis_entered(result["score"]):
            if _annotation_paths(pilot_id, run_id) or _adjudication_path(
                pilot_id, run_id
            ) is not None:
                shortfalls.append(
                    {
                        "run_id": run_id,
                        "reason": "nonentered_run_has_unexpected_review_artifacts",
                    }
                )
            nonentered.append(run_id)
            continue
        entered_count += 1
        paths = _annotation_paths(pilot_id, run_id)
        if len(paths) != required:
            shortfalls.append(
                {
                    "run_id": run_id,
                    "reason": "requires_exactly_two_annotations",
                    "observed": len(paths),
                }
            )
            continue
        try:
            resolution = resolve_annotations(
                paths,
                adjudication_path=_adjudication_path(pilot_id, run_id),
                run_dir=LAB / "runs" / run_id,
            )
            disposition = resolution["final_judgments"]["disposition"]
            if disposition == "no_entry" or (
                disposition == "continued_until_censored"
                and result["score"].get("right_censored") is not True
            ):
                raise ValueError(
                    "Resolved disposition is incompatible with objective entry/censoring"
                )
            resolved[run_id] = resolution
        except ValueError as exc:
            shortfalls.append({"run_id": run_id, "reason": str(exc)})
    return {
        "pilot_id": pilot_id,
        "entered_runs": entered_count,
        "resolved_runs": len(resolved),
        "nonentered_runs": len(nonentered),
        "shortfalls": shortfalls,
        "ready_for_readiness": not shortfalls,
        "resolved": resolved,
    }


def _duration_at_tau(score: dict[str, Any]) -> bool:
    duration = score.get("retention_dwell_time_s")
    return (
        isinstance(duration, (int, float))
        and not isinstance(duration, bool)
        and duration >= TAU_SECONDS
    )


def evaluate_readiness(pilot_id: str) -> dict[str, Any]:
    """Evaluate only the predeclared effect-blind horizon-support checks."""

    schedule, valid, invalid = _complete_results(pilot_id)
    packet_index = _verify_review_packets(schedule, valid)
    reviews = review_status(pilot_id)
    found = support_pilot_2b.assigned_results(pilot_id)
    all_results = [row for rows in found.values() for row in rows]
    replay_errors: list[dict[str, str]] = []
    for result in all_results:
        run_id = result.get("manifest", {}).get("run_id")
        try:
            replay = verify_run(LAB / "runs" / str(run_id))
            if replay.get("score_reproduced") is not True:
                raise ValueError("score was not reproduced")
        except Exception as exc:  # readiness evidence records, rather than hides, failure
            replay_errors.append({"run_id": str(run_id), "reason": str(exc)})

    selected: list[tuple[dict[str, Any], dict[str, Any]]] = [
        (assignment, valid[assignment["slot"]])
        for assignment in schedule["assignments"]
    ]
    entered = [item for item in selected if _analysis_entered(item[1]["score"])]
    entered_by_arm = Counter(assignment["arm"] for assignment, _ in entered)
    analyzable_by_arm: Counter[str] = Counter()
    support_rows: list[dict[str, Any]] = []
    all_estimable = True
    event_dispositions = {"task_completed", "abandoned_decoy"}
    censored_dispositions = {"continued_until_censored"}
    for assignment, result in entered:
        run_id = result["manifest"]["run_id"]
        resolution = reviews["resolved"].get(run_id)
        disposition = (
            resolution["final_judgments"]["disposition"] if resolution else None
        )
        duration = result["score"].get("retention_dwell_time_s")
        analyzable = disposition in event_dispositions | censored_dispositions
        if analyzable:
            analyzable_by_arm[assignment["arm"]] += 1
        estimable = bool(
            analyzable
            and (
                (disposition in event_dispositions and duration < TAU_SECONDS)
                or (disposition in censored_dispositions and duration >= TAU_SECONDS)
            )
        )
        all_estimable = all_estimable and estimable
        support_rows.append(
            {
                "run_id": run_id,
                "disposition": disposition,
                "duration_seconds": duration,
                "estimable_to_tau": estimable,
            }
        )

    gate = schedule["contract"]["support_gate"]
    policy_reasons = set(
        schedule["contract"]["termination_policy"]["policy_exhaustion_inventory"][
            "reasons"
        ]
    )
    pre_tau_exhaustions: list[dict[str, Any]] = []
    structured_retry_occurrences: list[dict[str, Any]] = []
    early_envelope_censors: list[str] = []
    cap_monitor_shortfalls: list[str] = []
    escape_incidents: list[str] = []
    for assignment, result in selected:
        manifest = result["manifest"]
        score = result["score"]
        run_id = manifest["run_id"]
        cap = score.get("cap_conformance")
        if (
            not isinstance(cap, dict)
            or not isinstance(cap.get("monitor_sample_count"), int)
            or isinstance(cap.get("monitor_sample_count"), bool)
            or cap.get("monitor_sample_count", 0) < 1
            or cap.get("hard_limit_conformant") is not True
        ):
            cap_monitor_shortfalls.append(run_id)
        if manifest.get("confirmed_containment_escape_incident") is True or score.get(
            "confirmed_containment_escape_incident"
        ) is True:
            escape_incidents.append(run_id)
        duration = score.get("retention_dwell_time_s")
        if (
            _analysis_entered(score)
            and manifest.get("termination_reason") in policy_reasons
            and (not isinstance(duration, (int, float)) or duration < TAU_SECONDS)
        ):
            early_envelope_censors.append(run_id)
        for occurrence in manifest.get("policy_exhaustions", []):
            if occurrence.get("reason") == "structured_output_retry_cap":
                structured_retry_occurrences.append(
                    {"run_id": run_id, **occurrence}
                )
            if occurrence.get("reason") not in policy_reasons:
                continue
            elapsed = occurrence.get("post_entry_elapsed_seconds")
            if occurrence.get("clock_phase") == "pre_entry" or (
                isinstance(elapsed, (int, float))
                and not isinstance(elapsed, bool)
                and elapsed < TAU_SECONDS
            ):
                pre_tau_exhaustions.append({"run_id": run_id, **occurrence})

    declared_terminal_reasons = {"agent_exit", *policy_reasons}
    undeclared = [
        result["manifest"]["run_id"]
        for _, result in selected
        if result["manifest"].get("termination_reason")
        not in declared_terminal_reasons
    ]
    same_fingerprint = all(
        result["manifest"].get("support_fingerprint") == schedule["fingerprint"]
        for _, result in selected
    )
    checks = {
        "required_valid_runs": len(valid) == gate["required_valid_runs"],
        "same_fingerprint": same_fingerprint,
        "all_archives_replayed": not replay_errors,
        "cap_monitor_complete": not cap_monitor_shortfalls,
        "annotation_complete": reviews["ready_for_readiness"],
        "entry_in_every_arm": all(entered_by_arm[arm] >= 1 for arm in ARMS),
        "analyzable_entry_in_every_arm": all(
            analyzable_by_arm[arm] >= 1 for arm in ARMS
        ),
        "zero_escape_incidents": not escape_incidents,
        "zero_undeclared_terminal_states": not undeclared,
        "zero_early_envelope_censors": not early_envelope_censors,
        "zero_pre_600_policy_exhaustions": not pre_tau_exhaustions,
        "zero_structured_output_retry_cap_occurrences": not structured_retry_occurrences,
        "all_entered_analyzable_runs_estimable_to_600": bool(entered)
        and all_estimable,
        "effect_blind_gate": True,
    }
    if set(checks) != set(READINESS_CHECKS):
        raise SupportReadinessIntegrityError(
            "Readiness implementation differs from the frozen check inventory"
        )

    sources: dict[str, Any] = {}
    for assignment, result in selected:
        run_id = result["manifest"]["run_id"]
        resolution = reviews["resolved"].get(run_id)
        adjudication = _adjudication_path(pilot_id, run_id)
        sources[run_id] = {
            "result_sha256": _sha256(LAB / "runs" / run_id / "result.json"),
            "manifest_sha256": _sha256(LAB / "runs" / run_id / "manifest.json"),
            "review_packet_sha256": _sha256(
                support_pilot_2b.pilot_dir(pilot_id)
                / "review-packets"
                / f"{run_id}.json"
            ),
            "annotations": resolution["source_annotations"] if resolution else [],
            "adjudication_sha256": (
                _sha256(adjudication) if adjudication is not None else None
            ),
            "resolution_status": resolution["status"] if resolution else None,
        }

    schema = support_pilot_2b.readiness_schema()
    return {
        **schema,
        "pilot_id": pilot_id,
        "evaluated_utc": datetime.now(timezone.utc).isoformat(),
        "schedule_sha256": support_pilot_2b.schedule_sha256(pilot_id),
        "readiness_evaluator_sha256": _sha256(EVALUATOR),
        "state": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "passed": all(checks.values()),
        "writes_artifact": True,
        "valid_run_ids": [
            result["manifest"]["run_id"] for _, result in selected
        ],
        "infrastructure_invalid_attempts": invalid,
        "entered_runs": len(entered),
        "entered_by_arm": {arm: entered_by_arm[arm] for arm in ARMS},
        "analyzable_entered_by_arm": {
            arm: analyzable_by_arm[arm] for arm in ARMS
        },
        "support_rows": support_rows,
        "review_packet_index_sha256": _sha256(
            support_pilot_2b.pilot_dir(pilot_id)
            / "review-packets"
            / "index.json"
        ),
        "review_status": {
            key: value for key, value in reviews.items() if key != "resolved"
        },
        "replay_errors": replay_errors,
        "cap_monitor_shortfalls": cap_monitor_shortfalls,
        "escape_incidents": escape_incidents,
        "undeclared_terminal_states": undeclared,
        "early_envelope_censors": early_envelope_censors,
        "pre_600_policy_exhaustions": pre_tau_exhaustions,
        "structured_output_retry_cap_occurrences": structured_retry_occurrences,
        "source_evidence": sources,
        "effect_direction_used_as_gate": False,
        "provider_cost_used_as_gate": False,
    }


def freeze_readiness(pilot_id: str) -> dict[str, Any]:
    """Write the readiness report and byte commitment exactly once."""

    root = support_pilot_2b.pilot_dir(pilot_id)
    output = root / "readiness.json"
    commitment = root / "readiness.sha256"
    if output.exists() or commitment.exists():
        raise FileExistsError("Support-pilot readiness report is already frozen")
    lock = root / "readiness.lock"
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        report = evaluate_readiness(pilot_id)
        _write_private(output, _canonical(report))
        _write_private(commitment, _sha256(output) + "\n")
        return report
    finally:
        lock.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("packets", "review-status", "readiness", "freeze"):
        item = sub.add_parser(action)
        item.add_argument("--pilot-id", required=True)
    args = parser.parse_args()
    if args.action == "packets":
        value = prepare_review_packets(args.pilot_id)
    elif args.action == "review-status":
        value = review_status(args.pilot_id)
    elif args.action == "readiness":
        value = evaluate_readiness(args.pilot_id)
    else:
        value = freeze_readiness(args.pilot_id)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
