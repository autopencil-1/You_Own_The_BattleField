"""Commit and verify blinded review packets for the frozen controlled-v3 cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiment_controller import controlled_2b_v3 as study
from experiment_controller.controlled_2b_v3_contract import LAB, sha256
from experiment_controller.run_2b_controlled_v3 import write_private
from telemetry.annotate_2b import HIDDEN_KEYS
from telemetry.annotate_2b_controlled_v3 import review_packet


PROJECTION = LAB / "telemetry" / "annotate_2b_controlled_v3.py"
TRACE_PROJECTION = LAB / "telemetry" / "annotate_2b.py"


def _render(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _assert_no_arm_keys(value: Any) -> None:
    if isinstance(value, dict):
        if any(str(key).lower() in HIDDEN_KEYS for key in value):
            raise study.StudyIntegrityError("Review packet contains an arm or assignment key")
        for child in value.values():
            _assert_no_arm_keys(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_arm_keys(child)


def _cohort(study_id: str) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
    schedule = study.load_schedule(study_id)
    if study_id != "2b-study-v3-20261106131028-e43a20":
        raise ValueError("Review projection is bound to the frozen controlled-v3 study")
    if (study.study_dir(study_id) / "pending-run.json").exists():
        raise study.StudyIntegrityError("Review packets require settled execution")
    for name, path in study.SOURCE_FILES.items():
        if sha256(path) != schedule["fingerprint"]["v3_source_sha256"][name]:
            raise study.StudyIntegrityError(f"Frozen {name} source changed")
    if sha256(TRACE_PROJECTION) != schedule["contract"]["frozen_input_sha256"]["review_projection"]:
        raise study.StudyIntegrityError("Frozen trace projection changed")
    valid, invalid = study._classified(schedule, study._results(study_id))
    if len(valid) != 40 or len(invalid) != 2:
        raise study.StudyIntegrityError("Controlled-v3 review population differs")
    return schedule, valid


def _packet_rows(
    schedule: dict[str, Any], valid: dict[int, dict[str, Any]], *, write: bool
) -> tuple[list[dict[str, Any]], list[str]]:
    folder = study.study_dir(schedule["study_id"]) / "review-packets"
    packets: list[dict[str, Any]] = []
    nonentered: list[str] = []
    for assignment in schedule["assignments"]:
        result = valid[assignment["slot"]]
        score = result["score"]
        run_id = result["manifest"]["run_id"]
        entered = (
            score.get("entry_success") is True
            and isinstance(score.get("first_successful_interaction_utc"), str)
            and score.get("retention_dwell_time_s") is not None
        )
        if not entered:
            nonentered.append(run_id)
            if (folder / f"{run_id}.json").exists():
                raise study.StudyIntegrityError("Nonentered run has a review packet")
            continue
        archive = LAB / "runs" / run_id
        packet = review_packet(archive)
        if (
            packet.get("run_id") != run_id
            or packet.get("arm_label_included") is not False
            or packet.get("archive_replay", {}).get("entry_success") is not True
        ):
            raise study.StudyIntegrityError("Review packet identity or replay differs")
        _assert_no_arm_keys(packet)
        rendered = _render(packet)
        path = folder / f"{run_id}.json"
        if path.exists():
            if path.read_text(encoding="utf-8") != rendered:
                raise study.StudyIntegrityError(f"Existing review packet changed: {run_id}")
        elif write:
            write_private(path, rendered)
        else:
            raise study.StudyIntegrityError(f"Review packet is missing: {run_id}")
        packets.append({
            "run_id": run_id,
            "file": path.name,
            "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "result_sha256": sha256(archive / "result.json"),
        })
    return packets, nonentered


def _index(schedule: dict[str, Any], packets: list[dict[str, Any]], nonentered: list[str]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "study_protocol": "2b-controlled-v3",
        "study_id": schedule["study_id"],
        "schedule_sha256": sha256(study.study_dir(schedule["study_id"]) / "schedule.json"),
        "contract_sha256": schedule["contract_sha256"],
        "projection_sha256": sha256(PROJECTION),
        "review_controller_sha256": sha256(Path(__file__)),
        "trace_projection_sha256": sha256(TRACE_PROJECTION),
        "v3_replay_sha256": schedule["fingerprint"]["v3_source_sha256"]["replay"],
        "packets": packets,
        "nonentered_run_ids": nonentered,
    }


def prepare(study_id: str) -> dict[str, Any]:
    schedule, valid = _cohort(study_id)
    folder = study.study_dir(study_id) / "review-packets"
    if not (folder / "index.json").exists() and (
        any((study.study_dir(study_id) / "annotations").rglob("*.json"))
        or any((study.study_dir(study_id) / "adjudications").glob("*.json"))
    ):
        raise study.StudyIntegrityError("Annotations predate the packet commitment")
    packets, nonentered = _packet_rows(schedule, valid, write=True)
    expected = _index(schedule, packets, nonentered)
    index_path = folder / "index.json"
    commitment_path = folder / "index.sha256"
    rendered = _render(expected)
    if index_path.exists():
        if index_path.read_text(encoding="utf-8") != rendered:
            raise study.StudyIntegrityError("Review packet index differs")
    else:
        write_private(index_path, rendered)
    commitment = sha256(index_path) + "\n"
    if commitment_path.exists():
        if commitment_path.read_text(encoding="utf-8") != commitment:
            raise study.StudyIntegrityError("Review packet commitment differs")
    else:
        write_private(commitment_path, commitment)
    return verify(study_id)


def verify(study_id: str) -> dict[str, Any]:
    schedule, valid = _cohort(study_id)
    folder = study.study_dir(study_id) / "review-packets"
    index_path = folder / "index.json"
    commitment_path = folder / "index.sha256"
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        commitment = commitment_path.read_text(encoding="utf-8").strip()
    except (OSError, json.JSONDecodeError) as exc:
        raise study.StudyIntegrityError("Review packet index is missing or malformed") from exc
    if commitment != sha256(index_path):
        raise study.StudyIntegrityError("Review packet index commitment differs")
    packets, nonentered = _packet_rows(schedule, valid, write=False)
    if index != _index(schedule, packets, nonentered):
        raise study.StudyIntegrityError("Review packet index content differs")
    expected_files = {"index.json", "index.sha256", *(row["file"] for row in packets)}
    if {path.name for path in folder.iterdir() if path.is_file()} != expected_files:
        raise study.StudyIntegrityError("Review packet directory has unexpected files")
    return {
        "study_id": study_id,
        "schedule_sha256": index["schedule_sha256"],
        "packet_index_sha256": sha256(index_path),
        "entered_packets": len(packets),
        "nonentered_runs": len(nonentered),
        "ready_for_independent_review": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("--study-id", required=True)
    args = parser.parse_args()
    value = prepare(args.study_id) if args.action == "prepare" else verify(args.study_id)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
