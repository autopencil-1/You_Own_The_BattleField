"""Seal and verify the completed 2B horizon-support evidence bundle."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from experiment_controller import support_pilot_2b
from experiment_controller.provider_cost_2b import estimate_archived_run_cost
from experiment_controller.support_pilot_2b_contract import CONFIG, LAB
from telemetry.replay_2b import verify_run


PILOT_PROTOCOL = "2b-support-pilot-v3"
CONTRACT_NAMES = (
    "exp_2b_support_pilot_v1_candidate",
    "exp_2b_support_pilot_v1",
    "exp_2b_support_pilot_v2",
    "exp_2b_support_pilot_v3",
)
BUNDLE_FILES = (
    "evidence-manifest.json",
    "replay-verification.json",
    "cost-ledger.json",
)


class SupportCloseoutIntegrityError(RuntimeError):
    """The immutable support-pilot evidence differs from its commitment."""


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SupportCloseoutIntegrityError(f"{label} is missing or malformed") from exc
    if not isinstance(value, dict):
        raise SupportCloseoutIntegrityError(f"{label} is not an object")
    return value


def _commitment(path: Path, commitment_path: Path, label: str) -> str:
    try:
        expected = commitment_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SupportCloseoutIntegrityError(f"{label} commitment is missing") from exc
    observed = _sha256(path)
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or observed != expected:
        raise SupportCloseoutIntegrityError(f"{label} differs from its commitment")
    return observed


def _load_readiness(pilot_id: str) -> tuple[dict[str, Any], str]:
    root = support_pilot_2b.pilot_dir(pilot_id)
    path = root / "readiness.json"
    digest = _commitment(path, root / "readiness.sha256", "Readiness report")
    readiness = _json(path, "Readiness report")
    checks = readiness.get("checks")
    if (
        readiness.get("pilot_id") != pilot_id
        or readiness.get("pilot_protocol") != PILOT_PROTOCOL
        or readiness.get("passed") is not True
        or not isinstance(checks, dict)
        or not checks
        or not all(value is True for value in checks.values())
        or readiness.get("schedule_sha256")
        != support_pilot_2b.schedule_sha256(pilot_id)
    ):
        raise SupportCloseoutIntegrityError("Readiness report is not a passing gate")
    evaluator = Path(__file__).with_name("support_readiness_2b.py")
    if readiness.get("readiness_evaluator_sha256") != _sha256(evaluator):
        raise SupportCloseoutIntegrityError(
            "Readiness evaluator differs from the frozen report"
        )
    return readiness, digest


def _complete_results(
    pilot_id: str,
) -> tuple[
    dict[str, Any],
    dict[int, list[dict[str, Any]]],
    dict[int, dict[str, Any]],
    list[dict[str, Any]],
]:
    schedule = support_pilot_2b.load_schedule(pilot_id)
    found = support_pilot_2b.assigned_results(pilot_id)
    valid, invalid = support_pilot_2b._classify(schedule, found)
    if len(valid) != len(schedule["assignments"]):
        raise SupportCloseoutIntegrityError("Support-pilot execution is incomplete")
    return schedule, found, valid, invalid


def _ordered_attempts(
    schedule: dict[str, Any],
    found: dict[int, list[dict[str, Any]]],
    valid: dict[int, dict[str, Any]],
    invalid: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    invalid_by_id = {row["run_id"]: row["reason"] for row in invalid}
    rows: list[dict[str, Any]] = []
    for assignment in schedule["assignments"]:
        slot = assignment["slot"]
        valid_id = valid[slot]["manifest"]["run_id"]
        for attempt_index, result in enumerate(found.get(slot, []), 1):
            manifest = result["manifest"]
            run_id = manifest["run_id"]
            classification = (
                "valid" if run_id == valid_id else "infrastructure_invalid"
            )
            reason = None if classification == "valid" else invalid_by_id.get(run_id)
            if classification == "infrastructure_invalid" and reason is None:
                raise SupportCloseoutIntegrityError(
                    f"Attempt classification is missing for {run_id}"
                )
            rows.append(
                {
                    "slot": slot,
                    "block": assignment["block"],
                    "arm": assignment["arm"],
                    "attempt_index": attempt_index,
                    "run_id": run_id,
                    "started_utc": manifest.get("started_utc"),
                    "classification": classification,
                    "invalid_reason": reason,
                    "result": result,
                }
            )
    return rows


def _archive_evidence(row: dict[str, Any]) -> dict[str, Any]:
    run_id = row["run_id"]
    run_dir = LAB / "runs" / run_id
    manifest = row["result"]["manifest"]
    artifacts = manifest.get("artifact_sha256")
    if not isinstance(artifacts, dict) or not artifacts:
        raise SupportCloseoutIntegrityError(f"Archive inventory is missing for {run_id}")
    for name, expected in artifacts.items():
        path = run_dir / name
        if not isinstance(expected, str) or _sha256(path) != expected:
            raise SupportCloseoutIntegrityError(
                f"Archived artifact differs for {run_id}: {name}"
            )
    return {
        "slot": row["slot"],
        "block": row["block"],
        "arm": row["arm"],
        "attempt_index": row["attempt_index"],
        "run_id": run_id,
        "started_utc": row["started_utc"],
        "classification": row["classification"],
        "invalid_reason": row["invalid_reason"],
        "result_sha256": _sha256(run_dir / "result.json"),
        "manifest_sha256": _sha256(run_dir / "manifest.json"),
        "artifact_sha256": dict(sorted(artifacts.items())),
    }


def _contract_commitments() -> list[dict[str, Any]]:
    folder = LAB / "config"
    rows = []
    for name in CONTRACT_NAMES:
        config = folder / f"{name}.json"
        commitment = folder / f"{name}.sha256"
        rows.append(
            {
                "name": name,
                "file": config.relative_to(LAB).as_posix(),
                "commitment_file": commitment.relative_to(LAB).as_posix(),
                "sha256": _commitment(config, commitment, name),
            }
        )
    if rows[-1]["sha256"] != _sha256(CONFIG):
        raise SupportCloseoutIntegrityError("Active execution contract differs")
    return rows


def _review_evidence(pilot_id: str, readiness: dict[str, Any]) -> dict[str, Any]:
    root = support_pilot_2b.pilot_dir(pilot_id)
    packet_root = root / "review-packets"
    packet_index_sha = _commitment(
        packet_root / "index.json",
        packet_root / "index.sha256",
        "Review-packet index",
    )
    if readiness.get("review_packet_index_sha256") != packet_index_sha:
        raise SupportCloseoutIntegrityError(
            "Readiness report references another review-packet index"
        )
    annotations = [
        {
            "file": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
        }
        for path in sorted((root / "annotations").rglob("*.json"))
    ]
    adjudications = [
        {
            "file": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
        }
        for path in sorted((root / "adjudications").glob("*.json"))
    ]
    return {
        "packet_index_sha256": packet_index_sha,
        "packet_index_commitment_sha256": _sha256(packet_root / "index.sha256"),
        "annotations": annotations,
        "adjudications": adjudications,
    }


def _replay_document(
    pilot_id: str,
    schedule_sha256: str,
    attempts: list[dict[str, Any]],
    created_utc: str,
) -> dict[str, Any]:
    rows = []
    for attempt in attempts:
        replay = verify_run(LAB / "runs" / attempt["run_id"])
        rows.append(
            {
                "slot": attempt["slot"],
                "attempt_index": attempt["attempt_index"],
                "classification": attempt["classification"],
                "invalid_reason": attempt["invalid_reason"],
                "result_sha256": _sha256(
                    LAB / "runs" / attempt["run_id"] / "result.json"
                ),
                "replay": replay,
            }
        )
    return {
        "schema_version": 1,
        "pilot_protocol": PILOT_PROTOCOL,
        "pilot_id": pilot_id,
        "created_utc": created_utc,
        "schedule_sha256": schedule_sha256,
        "replay_source_sha256": _sha256(LAB / "telemetry" / "replay_2b.py"),
        "attempts_verified": len(rows),
        "all_scores_reproduced": all(
            row["replay"].get("score_reproduced") is True for row in rows
        ),
        "attempts": rows,
    }


def _cost_document(
    pilot_id: str,
    schedule: dict[str, Any],
    attempts: list[dict[str, Any]],
    created_utc: str,
) -> dict[str, Any]:
    governance = schedule["contract"]["provider_cost_governance"]
    carry = schedule["contract"]["provider_cost_carry_forward"]
    estimates = []
    for attempt in attempts:
        run_id = attempt["run_id"]
        estimate = estimate_archived_run_cost(LAB / "runs" / run_id, governance)
        estimates.append(
            {
                "slot": attempt["slot"],
                "attempt_index": attempt["attempt_index"],
                "classification": attempt["classification"],
                "invalid_reason": attempt["invalid_reason"],
                "manifest_sha256": _sha256(LAB / "runs" / run_id / "manifest.json"),
                "gateway_events_sha256": _sha256(
                    LAB / "runs" / run_id / "gateway-events.jsonl"
                ),
                **estimate,
            }
        )
    snapshot = support_pilot_2b.provider_cost_snapshot(pilot_id)
    current = sum(row["estimated_cost_nano_usd"] for row in estimates)
    if (
        snapshot.get("accounting_state") != "complete"
        or snapshot.get("errors")
        or snapshot.get("current_pilot_attempts_priced") != len(estimates)
        or snapshot.get("current_pilot_cost_nano_usd") != current
        or snapshot.get("carried_forward_cost_nano_usd")
        != carry["accrued_cost_nano_usd"]
    ):
        raise SupportCloseoutIntegrityError(
            "Provider-cost ledger does not reproduce the controller snapshot"
        )
    return {
        "schema_version": 1,
        "pilot_protocol": PILOT_PROTOCOL,
        "pilot_id": pilot_id,
        "created_utc": created_utc,
        "schedule_sha256": support_pilot_2b.schedule_sha256(pilot_id),
        "accounting_source_sha256": _sha256(
            LAB / "experiment_controller" / "provider_cost_2b.py"
        ),
        "governance": governance,
        "carried_forward": carry,
        "current_pilot_attempts": estimates,
        "snapshot": snapshot,
        "cost_used_in_support_gate": False,
    }


def build_closeout_documents(
    pilot_id: str, *, created_utc: str | None = None
) -> dict[str, dict[str, Any]]:
    """Recompute every closeout document without writing an artifact."""

    created_utc = created_utc or datetime.now(timezone.utc).isoformat()
    schedule, found, valid, invalid = _complete_results(pilot_id)
    readiness, readiness_sha = _load_readiness(pilot_id)
    attempts = _ordered_attempts(schedule, found, valid, invalid)
    schedule_sha = support_pilot_2b.schedule_sha256(pilot_id)
    root = support_pilot_2b.pilot_dir(pilot_id)
    evidence = {
        "schema_version": 1,
        "pilot_protocol": PILOT_PROTOCOL,
        "pilot_id": pilot_id,
        "created_utc": created_utc,
        "bundle_kind": "post_execution_support_pilot_closeout",
        "archive_policy": "hash_references_only_no_archive_copies",
        "schedule": {
            "file": "schedule.json",
            "sha256": _commitment(
                root / "schedule.json", root / "schedule.sha256", "Schedule"
            ),
            "commitment_file_sha256": _sha256(root / "schedule.sha256"),
        },
        "contracts": _contract_commitments(),
        "readiness": {
            "file": "readiness.json",
            "sha256": readiness_sha,
            "commitment_file_sha256": _sha256(root / "readiness.sha256"),
            "passed": readiness["passed"],
        },
        "review_evidence": _review_evidence(pilot_id, readiness),
        "attempts": [_archive_evidence(row) for row in attempts],
    }
    replay = _replay_document(pilot_id, schedule_sha, attempts, created_utc)
    cost = _cost_document(pilot_id, schedule, attempts, created_utc)
    return {
        "evidence-manifest.json": evidence,
        "replay-verification.json": replay,
        "cost-ledger.json": cost,
    }


def closeout_summary(documents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence = documents["evidence-manifest.json"]
    replay = documents["replay-verification.json"]
    cost = documents["cost-ledger.json"]
    attempts = evidence["attempts"]
    snapshot = cost["snapshot"]
    return {
        "pilot_id": evidence["pilot_id"],
        "attempts_preserved": len(attempts),
        "valid_attempts": sum(row["classification"] == "valid" for row in attempts),
        "infrastructure_invalid_attempts": sum(
            row["classification"] == "infrastructure_invalid" for row in attempts
        ),
        "all_scores_reproduced": replay["all_scores_reproduced"],
        "completed_attempts_priced": snapshot["completed_attempts_priced"],
        "accrued_cost_usd": snapshot["accrued_cost_usd"],
        "remaining_authorization_usd": snapshot["admission"][
            "remaining_authorization_usd"
        ],
        "admission_state": snapshot["admission"]["state"],
    }


def seal_closeout(pilot_id: str) -> dict[str, Any]:
    """Write the closeout documents and final bundle commitment exactly once."""

    root = support_pilot_2b.pilot_dir(pilot_id)
    folder = root / "closeout"
    if folder.exists():
        raise FileExistsError("Support-pilot closeout bundle already exists")
    lock = root / "closeout.lock"
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        documents = build_closeout_documents(pilot_id)
        folder.mkdir(mode=0o700)
        for name in BUNDLE_FILES:
            _write_private(folder / name, _canonical(documents[name]))
        manifest = {
            "schema_version": 1,
            "pilot_protocol": PILOT_PROTOCOL,
            "pilot_id": pilot_id,
            "created_utc": documents["evidence-manifest.json"]["created_utc"],
            "bundle_kind": "post_execution_support_pilot_closeout",
            "files": [
                {
                    "file": name,
                    "sha256": _sha256(folder / name),
                    "size_bytes": (folder / name).stat().st_size,
                }
                for name in BUNDLE_FILES
            ],
            "external_commitments": {
                "schedule_sha256": support_pilot_2b.schedule_sha256(pilot_id),
                "execution_contract_sha256": _sha256(CONFIG),
                "readiness_sha256": _sha256(root / "readiness.json"),
            },
            "archive_policy": "hash_references_only_no_archive_copies",
        }
        _write_private(folder / "bundle-manifest.json", _canonical(manifest))
        _write_private(
            folder / "bundle-manifest.sha256",
            _sha256(folder / "bundle-manifest.json") + "\n",
        )
        return {
            **closeout_summary(documents),
            "bundle_manifest_sha256": _sha256(folder / "bundle-manifest.json"),
            "bundle_files": list(BUNDLE_FILES),
            "sealed": True,
        }
    finally:
        lock.unlink(missing_ok=True)


def verify_closeout(pilot_id: str) -> dict[str, Any]:
    """Re-hash sources, re-run replay, and reproduce cost from the sealed bundle."""

    root = support_pilot_2b.pilot_dir(pilot_id)
    folder = root / "closeout"
    manifest_path = folder / "bundle-manifest.json"
    bundle_sha = _commitment(
        manifest_path,
        folder / "bundle-manifest.sha256",
        "Closeout bundle manifest",
    )
    manifest = _json(manifest_path, "Closeout bundle manifest")
    expected_files = set(BUNDLE_FILES)
    rows = manifest.get("files")
    expected_external = {
        "schedule_sha256": support_pilot_2b.schedule_sha256(pilot_id),
        "execution_contract_sha256": _sha256(CONFIG),
        "readiness_sha256": _sha256(root / "readiness.json"),
    }
    if (
        manifest.get("schema_version") != 1
        or manifest.get("pilot_id") != pilot_id
        or manifest.get("pilot_protocol") != PILOT_PROTOCOL
        or manifest.get("bundle_kind")
        != "post_execution_support_pilot_closeout"
        or manifest.get("archive_policy")
        != "hash_references_only_no_archive_copies"
        or manifest.get("external_commitments") != expected_external
        or not isinstance(rows, list)
        or {row.get("file") for row in rows if isinstance(row, dict)}
        != expected_files
    ):
        raise SupportCloseoutIntegrityError("Closeout bundle manifest is invalid")
    for row in rows:
        path = folder / row["file"]
        if _sha256(path) != row.get("sha256") or path.stat().st_size != row.get(
            "size_bytes"
        ):
            raise SupportCloseoutIntegrityError(
                f"Closeout bundle file differs: {row['file']}"
            )

    stored = {name: _json(folder / name, name) for name in BUNDLE_FILES}
    created_utc = stored["evidence-manifest.json"].get("created_utc")
    rebuilt = build_closeout_documents(pilot_id, created_utc=created_utc)
    if stored != rebuilt:
        raise SupportCloseoutIntegrityError(
            "Sealed closeout documents do not reproduce from source evidence"
        )
    return {
        **closeout_summary(stored),
        "bundle_manifest_sha256": bundle_sha,
        "source_evidence_reverified": True,
        "sealed": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("preview", "seal", "verify"):
        item = sub.add_parser(action)
        item.add_argument("--pilot-id", required=True)
    args = parser.parse_args()
    if args.action == "preview":
        value = {**closeout_summary(build_closeout_documents(args.pilot_id)), "sealed": False}
    elif args.action == "seal":
        value = seal_closeout(args.pilot_id)
    else:
        value = verify_closeout(args.pilot_id)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
