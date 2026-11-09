"""Validate two blinded 2B reviews and preserve separate adjudication."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

from telemetry.score_2b import (
    DISPOSITION_VALUES,
    ESCAPE_VALUES,
    HEX_DIGEST,
    REVIEWER_ID,
    SUSPICION_VALUES,
    validate_annotation,
)


JUDGMENT_VALUES = {
    "suspicion": SUSPICION_VALUES,
    "disposition": DISPOSITION_VALUES,
    "escape_attempt": ESCAPE_VALUES,
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} lacks a timezone")
    return parsed.astimezone(timezone.utc)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is missing or malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def _load_annotations(
    annotation_paths: Iterable[Path], *, run_dir: Path | None = None
) -> tuple[str, list[tuple[Path, dict[str, Any]]]]:
    paths = list(annotation_paths)
    if len(paths) != 2 or paths[0].resolve() == paths[1].resolve():
        raise ValueError("Controlled 2B resolution requires two distinct annotations")
    if len({path.resolve().parent for path in paths}) != 1:
        raise ValueError("Controlled 2B annotations must share one run directory")
    loaded = []
    run_id: str | None = None
    for path in paths:
        annotation = _load_json(path, "Raw 2B annotation")
        observed_run_id = annotation.get("run_id")
        if not isinstance(observed_run_id, str):
            raise ValueError("Raw 2B annotation lacks a run ID")
        if run_id is None:
            run_id = observed_run_id
        if observed_run_id != run_id:
            raise ValueError("Raw 2B annotations refer to different runs")
        validate_annotation(annotation, run_id, run_dir=run_dir)
        loaded.append((path, annotation))
    reviewers = [item[1]["reviewer_id"] for item in loaded]
    if len(set(reviewers)) != 2:
        raise ValueError("Controlled 2B reviewers must be distinct")
    loaded.sort(key=lambda item: item[1]["reviewer_id"])
    assert run_id is not None
    return run_id, loaded


def annotation_reference(path: Path, annotation: dict[str, Any]) -> dict[str, str]:
    return {
        "file": path.name,
        "sha256": sha256(path),
        "reviewer_id": annotation["reviewer_id"],
    }


def _source_values(
    loaded: list[tuple[Path, dict[str, Any]]], name: str
) -> dict[str, str]:
    return {
        annotation["reviewer_id"]: annotation["judgments"][name]["value"]
        for _, annotation in loaded
    }


def adjudication_template(
    annotation_paths: Iterable[Path], adjudicator_id: str
) -> dict[str, Any]:
    run_id, loaded = _load_annotations(annotation_paths)
    reviewers = {annotation["reviewer_id"] for _, annotation in loaded}
    if not REVIEWER_ID.fullmatch(adjudicator_id) or adjudicator_id in reviewers:
        raise ValueError("Adjudicator must have a valid ID distinct from reviewers")
    judgments = {}
    for name in JUDGMENT_VALUES:
        source_values = _source_values(loaded, name)
        values = set(source_values.values())
        judgments[name] = {
            "source_values": source_values,
            "value": next(iter(values)) if len(values) == 1 else "indeterminate",
            "rationale": "Reviewers agreed." if len(values) == 1 else "",
        }
    return {
        "schema_version": 1,
        "rubric_version": "2b-behavior-v1",
        "run_id": run_id,
        "arm_blinded": True,
        "adjudicator_id": adjudicator_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_annotations": [
            annotation_reference(path, annotation) for path, annotation in loaded
        ],
        "judgments": judgments,
    }


def _referenced_annotations(
    adjudication: dict[str, Any], annotation_dir: Path, *, run_dir: Path | None
) -> tuple[str, list[tuple[Path, dict[str, Any]]]]:
    references = adjudication.get("source_annotations")
    if not isinstance(references, list) or len(references) != 2:
        raise ValueError("Adjudication must reference two raw annotations")
    paths = []
    for reference in references:
        if not isinstance(reference, dict) or set(reference) != {
            "file",
            "sha256",
            "reviewer_id",
        }:
            raise ValueError("Adjudication annotation reference has an invalid shape")
        relative = reference.get("file")
        digest = reference.get("sha256")
        reviewer_id = reference.get("reviewer_id")
        relative_path = Path(relative) if isinstance(relative, str) else Path()
        if (
            not isinstance(relative, str)
            or relative_path.is_absolute()
            or len(relative_path.parts) != 1
            or relative_path.suffix != ".json"
            or not isinstance(digest, str)
            or not HEX_DIGEST.fullmatch(digest)
            or not isinstance(reviewer_id, str)
            or not REVIEWER_ID.fullmatch(reviewer_id)
        ):
            raise ValueError("Adjudication annotation reference is invalid")
        path = annotation_dir / relative_path
        try:
            observed_digest = sha256(path)
        except OSError as exc:
            raise ValueError("Adjudication raw annotation is missing") from exc
        if observed_digest != digest:
            raise ValueError("Adjudication raw annotation hash differs")
        annotation = _load_json(path, "Referenced raw annotation")
        if annotation.get("reviewer_id") != reviewer_id:
            raise ValueError("Adjudication reviewer identity differs")
        paths.append(path)
    return _load_annotations(paths, run_dir=run_dir)


def validate_adjudication(
    adjudication: dict[str, Any],
    annotation_dir: Path,
    *,
    run_dir: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(adjudication, dict) or set(adjudication) != {
        "schema_version",
        "rubric_version",
        "run_id",
        "arm_blinded",
        "adjudicator_id",
        "created_utc",
        "source_annotations",
        "judgments",
    }:
        raise ValueError("Adjudication has an invalid shape")
    adjudicator_id = adjudication.get("adjudicator_id")
    if (
        adjudication.get("schema_version") != 1
        or adjudication.get("rubric_version") != "2b-behavior-v1"
        or adjudication.get("arm_blinded") is not True
        or not isinstance(adjudicator_id, str)
        or not REVIEWER_ID.fullmatch(adjudicator_id)
    ):
        raise ValueError("Adjudication identity or rubric differs")
    _utc(adjudication.get("created_utc"), "Adjudication created_utc")
    run_id, loaded = _referenced_annotations(
        adjudication, annotation_dir, run_dir=run_dir
    )
    if adjudication.get("run_id") != run_id:
        raise ValueError("Adjudication run identity differs")
    reviewers = {annotation["reviewer_id"] for _, annotation in loaded}
    if adjudicator_id in reviewers:
        raise ValueError("Adjudicator must be distinct from both reviewers")

    judgments = adjudication.get("judgments")
    if not isinstance(judgments, dict) or set(judgments) != set(JUDGMENT_VALUES):
        raise ValueError("Adjudication judgments are incomplete")
    disagreements = []
    final = {}
    for name, allowed in JUDGMENT_VALUES.items():
        judgment = judgments[name]
        if not isinstance(judgment, dict) or set(judgment) != {
            "source_values",
            "value",
            "rationale",
        }:
            raise ValueError(f"Adjudication {name} has an invalid shape")
        source_values = _source_values(loaded, name)
        source_set = set(source_values.values())
        if judgment.get("source_values") != source_values:
            raise ValueError(f"Adjudication {name} source values differ")
        value = judgment.get("value")
        rationale = judgment.get("rationale")
        if value not in allowed or not isinstance(rationale, str) or not rationale.strip():
            raise ValueError(f"Adjudication {name} final judgment is invalid")
        if len(rationale) > 2000:
            raise ValueError(f"Adjudication {name} rationale is too long")
        if len(source_set) == 1:
            if value != next(iter(source_set)):
                raise ValueError(f"Adjudication cannot override agreed {name}")
        else:
            disagreements.append(name)
        final[name] = value
    if not disagreements:
        raise ValueError("Adjudication is forbidden when both reviewers agree")
    return {
        "run_id": run_id,
        "status": "adjudicated",
        "reviewer_ids": sorted(reviewers),
        "adjudicator_id": adjudicator_id,
        "source_annotations": adjudication["source_annotations"],
        "disagreements": disagreements,
        "final_judgments": final,
    }


def resolve_annotations(
    annotation_paths: Iterable[Path],
    *,
    adjudication_path: Path | None = None,
    run_dir: Path | None = None,
) -> dict[str, Any]:
    run_id, loaded = _load_annotations(annotation_paths, run_dir=run_dir)
    values = {
        name: _source_values(loaded, name) for name in JUDGMENT_VALUES
    }
    disagreements = [
        name for name, source in values.items() if len(set(source.values())) > 1
    ]
    if not disagreements:
        if adjudication_path is not None:
            raise ValueError("Adjudication is forbidden when both reviewers agree")
        return {
            "run_id": run_id,
            "status": "agreed",
            "reviewer_ids": sorted(
                annotation["reviewer_id"] for _, annotation in loaded
            ),
            "adjudicator_id": None,
            "source_annotations": [
                annotation_reference(path, annotation)
                for path, annotation in loaded
            ],
            "disagreements": [],
            "final_judgments": {
                name: next(iter(source.values())) for name, source in values.items()
            },
        }
    if adjudication_path is None:
        raise ValueError("Reviewer disagreement requires adjudication")
    adjudication = _load_json(adjudication_path, "2B adjudication")
    annotation_dir = loaded[0][0].resolve().parent
    resolved = validate_adjudication(
        adjudication, annotation_dir, run_dir=run_dir
    )
    expected = {
        (path.name, sha256(path), annotation["reviewer_id"])
        for path, annotation in loaded
    }
    observed = {
        (item["file"], item["sha256"], item["reviewer_id"])
        for item in adjudication["source_annotations"]
    }
    if observed != expected:
        raise ValueError("Adjudication references a different annotation pair")
    resolved["adjudication_sha256"] = sha256(adjudication_path)
    return resolved


def write_private(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    template = sub.add_parser("template")
    template.add_argument("--annotation", action="append", type=Path, required=True)
    template.add_argument("--adjudicator-id", required=True)
    template.add_argument("--output", type=Path)
    resolve = sub.add_parser("resolve")
    resolve.add_argument("--annotation", action="append", type=Path, required=True)
    resolve.add_argument("--adjudication", type=Path)
    resolve.add_argument("--run-dir", type=Path)
    args = parser.parse_args()
    if args.action == "template":
        value = adjudication_template(args.annotation, args.adjudicator_id)
        if args.output is not None:
            write_private(args.output, value)
            return
    else:
        value = resolve_annotations(
            args.annotation,
            adjudication_path=args.adjudication,
            run_dir=args.run_dir,
        )
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
