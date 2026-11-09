"""Stop one admitted diagnostic 2B attacker without killing its controller.

The runner owns provider settlement and archival. This adapter only requests
that its exact attacker container stop, and keeps an independent committed
operator record outside the runner's signed run directory.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Iterator

from experiment_controller import path_story_pilot_2b_v2 as committed

from .core import JOBS, utc_now


class StopConflict(ValueError):
    """The requested stop is not safe or the diagnostic evidence is incomplete."""


def _diagnostic_paths() -> tuple[str, Path]:
    from experiment_controller import path_story_diagnostic_2b_v1 as diagnostic

    return diagnostic.PILOT_ID, diagnostic.SCHEDULE


def _pro_paths() -> tuple[str, Path]:
    from experiment_controller import path_story_diagnostic_2b_pro_v1 as diagnostic

    return diagnostic.PILOT_ID, diagnostic.SCHEDULE


def _known_paths() -> tuple[tuple[str, Path], tuple[str, Path]]:
    return _diagnostic_paths(), _pro_paths()


def _pilot_paths(run_id: str, pilot_id: str | None = None) -> tuple[str, Path] | None:
    """Resolve a run to one allowlisted diagnostic study, never by a caller path."""
    choices = _known_paths()
    if pilot_id is not None:
        return next((row for row in choices if row[0] == pilot_id), None)
    found = [row for row in choices if (
        (row[1].parent / "admissions" / f"{run_id}.json").exists()
        or (row[1].parent / "admissions" / f"{run_id}.sha256").exists()
    )]
    if len(found) > 1:
        raise StopConflict("Run has more than one diagnostic study admission")
    return found[0] if found else None


def _allowed_slot(pilot_id: str, slot: object) -> bool:
    if not isinstance(slot, int) or isinstance(slot, bool):
        return False
    if pilot_id == _diagnostic_paths()[0]:
        return slot in range(3, 9)
    if pilot_id == _pro_paths()[0]:
        return slot == 3
    return False


def _read_committed(path: Path) -> dict[str, Any]:
    try:
        return committed._read_committed(path)
    except (OSError, ValueError, RuntimeError) as exc:
        raise StopConflict(f"Diagnostic committed record is unavailable: {path.name}") from exc


def _committed_sha(record: dict[str, Any]) -> str:
    return hashlib.sha256(committed._canonical(record)).hexdigest()


def _request_path(schedule_path: Path, run_id: str) -> Path:
    return schedule_path.parent / "operator-stops" / f"{run_id}.request.json"


def _outcome_path(schedule_path: Path, run_id: str) -> Path:
    return schedule_path.parent / "operator-stops" / f"{run_id}.outcome.json"


def _failure_path(schedule_path: Path, run_id: str, sequence: int) -> Path:
    return schedule_path.parent / "operator-stops" / f"{run_id}.failure-{sequence:04d}.json"


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or re.fullmatch(r"2b-path-[0-9]{14}-[0-9a-f]{6}", run_id) is None:
        raise StopConflict("Invalid diagnostic run ID")


def _validate_request(record: dict[str, Any], run_id: str, pilot_id: str) -> None:
    stamp = record.get("requested_utc")
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise StopConflict("Operator-stop request time is invalid") from exc
    if parsed.tzinfo is None:
        raise StopConflict("Operator-stop request time lacks a timezone")
    slot = record.get("slot")
    if (record.get("schema_version") != 1 or record.get("pilot_id") != pilot_id
            or record.get("run_id") != run_id or record.get("actor") != "local_dashboard"
            or record.get("reason") != "operator_stop"
            or not _allowed_slot(pilot_id, slot)
            or record.get("project") != "shape" + run_id.lower()
            or not isinstance(record.get("container_id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["container_id"]) is None):
        raise StopConflict("Operator-stop request identity differs")


def stop_requested(run_id: str, pilot_id: str | None = None) -> bool:
    """Return true only for a valid, hash-committed operator request."""
    _validate_run_id(run_id)
    selected = _pilot_paths(run_id, pilot_id)
    if selected is None:
        return False
    fixed_pilot_id, schedule_path = selected
    path = _request_path(schedule_path, run_id)
    if not path.exists() and not path.with_suffix(".sha256").exists():
        return False
    record = _read_committed(path)
    _validate_request(record, run_id, fixed_pilot_id)
    admission = _read_committed(schedule_path.parent / "admissions" / f"{run_id}.json")
    schedule = _read_committed(schedule_path)
    from experiment_controller import path_story_diagnostic_2b_v1 as diagnostic

    if (admission.get("pilot_id") != fixed_pilot_id
            or admission.get("run_id") != run_id
            or admission.get("slot") != record["slot"]
            or admission.get("parent_pilot_id") != diagnostic.PARENT_PILOT_ID
            or schedule.get("pilot_id") != fixed_pilot_id
            or admission.get("schedule_sha256") != _committed_sha(schedule)):
        raise StopConflict("Operator-stop request admission differs")
    return True


def _failures(schedule_path: Path, run_id: str, pilot_id: str,
              request: dict[str, Any]) -> list[dict[str, Any]]:
    folder = schedule_path.parent / "operator-stops"
    pattern = re.compile(re.escape(run_id) + r"\.failure-([0-9]{4})\.(json|sha256)")
    indices: set[int] = set()
    for path in folder.glob(f"{run_id}.failure-*"):
        matched = pattern.fullmatch(path.name)
        if matched is None:
            raise StopConflict("Operator-stop failure record name is invalid")
        indices.add(int(matched[1]))
    if indices != set(range(1, len(indices) + 1)):
        raise StopConflict("Operator-stop failure records are not contiguous")
    request_sha = _committed_sha(request)
    rows = []
    for sequence in sorted(indices):
        row = _read_committed(_failure_path(schedule_path, run_id, sequence))
        completed = row.get("completed_utc")
        try:
            completed_at = datetime.fromisoformat(completed.replace("Z", "+00:00"))
            requested_at = datetime.fromisoformat(request["requested_utc"].replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise StopConflict("Operator-stop failure record time is invalid") from exc
        if (row.get("schema_version") != 1 or row.get("pilot_id") != pilot_id
                or row.get("run_id") != run_id or row.get("slot") != request["slot"]
                or row.get("sequence") != sequence or row.get("request_sha256") != request_sha
                or row.get("state") != "stop_failed" or not isinstance(row.get("error"), str)
                or completed_at.tzinfo is None or completed_at < requested_at):
            raise StopConflict("Operator-stop failure record differs")
        rows.append(row)
    return rows


def stop_retry_available(run_id: str, pilot_id: str | None = None) -> bool:
    """Expose a retry only after a signed stop failure while a run is pending."""
    if not stop_requested(run_id, pilot_id):
        return False
    selected = _pilot_paths(run_id, pilot_id)
    if selected is None:
        return False
    fixed_pilot_id, schedule_path = selected
    outcome = _outcome_path(schedule_path, run_id)
    if outcome.exists() or outcome.with_suffix(".sha256").exists():
        _read_committed(outcome)
        return False
    request = _read_committed(_request_path(schedule_path, run_id))
    failures = _failures(schedule_path, run_id, fixed_pilot_id, request)
    pending_path = schedule_path.parent / "pending-run.json"
    if not pending_path.exists() and not pending_path.with_suffix(".sha256").exists():
        return False
    pending = _read_committed(pending_path)
    if pending.get("run_id") != run_id or pending.get("pilot_id") != fixed_pilot_id:
        raise StopConflict("Operator-stop pending run differs")
    return bool(failures)


@contextmanager
def _stop_lock() -> Iterator[None]:
    JOBS.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(JOBS / "diagnostic-stop.lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise StopConflict("Another diagnostic stop request is in progress") from exc
        yield
    finally:
        os.close(descriptor)


def _docker(arguments: list[str], *, timeout: int = 15) -> str:
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StopConflict("Docker did not complete the scoped stop command") from exc
    if result.returncode:
        raise StopConflict(f"Docker scoped stop command exited {result.returncode}")
    try:
        return result.stdout.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as exc:
        raise StopConflict("Docker scoped stop output was not UTF-8") from exc


def _attacker_container(project: str, run_id: str, expected_image: str,
                        *, require_running: bool = True,
                        allow_missing: bool = False) -> tuple[str, bool] | None:
    output = _docker([
        "docker", "ps", "--all", "--no-trunc", "--quiet",
        "--filter", f"label=com.docker.compose.project={project}",
        "--filter", "label=com.docker.compose.service=attacker-agent",
    ])
    identifiers = output.splitlines() if output else []
    if not identifiers and allow_missing:
        return None
    if len(identifiers) != 1 or re.fullmatch(r"[0-9a-f]{64}", identifiers[0]) is None:
        raise StopConflict("Expected exactly one diagnostic attacker container")
    identifier = identifiers[0]
    try:
        rows = json.loads(_docker(["docker", "inspect", identifier]))
        info = rows[0]
        labels = info["Config"]["Labels"]
        environment = info["Config"]["Env"]
        running = info["State"]["Running"]
        image = info["Image"]
    except (AttributeError, KeyError, IndexError, TypeError, ValueError) as exc:
        raise StopConflict("Attacker container inspection is incomplete") from exc
    if not isinstance(labels, dict) or not isinstance(environment, list):
        raise StopConflict("Attacker container labels or environment are incomplete")
    run_ids = [value.partition("=")[2] for value in environment
               if isinstance(value, str) and value.startswith("SHAPE_RUN_ID=")]
    if (info.get("Id") != identifier or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != "attacker-agent"
            or run_ids != [run_id] or image != expected_image
            or not isinstance(running, bool) or (require_running and not running)):
        raise StopConflict("Attacker container identity or running state differs")
    return identifier, running


def _admitted_context(run_id: str, pilot_id: str | None = None) -> tuple[str, Path, int, str]:
    selected = _pilot_paths(run_id, pilot_id)
    if selected is None:
        raise StopConflict("Run has no allowlisted diagnostic admission")
    pilot_id, schedule_path = selected
    schedule = _read_committed(schedule_path)
    from experiment_controller import path_story_diagnostic_2b_v1 as diagnostic

    if (schedule.get("pilot_id") != pilot_id
            or schedule.get("parent_pilot_id") != diagnostic.PARENT_PILOT_ID):
        raise StopConflict("Diagnostic schedule identity differs")
    parent_path = schedule_path.parent.parent / diagnostic.PARENT_PILOT_ID / "schedule.json"
    parent_schedule = _read_committed(parent_path)
    parent_hash = _committed_sha(parent_schedule)
    if (schedule.get("parent_schedule_sha256") != parent_hash
            or parent_schedule.get("pilot_id") != diagnostic.PARENT_PILOT_ID):
        raise StopConflict("Diagnostic parent schedule differs")
    fingerprint = parent_schedule.get("fingerprint")
    if pilot_id == _pro_paths()[0]:
        parent_assignments = parent_schedule.get("assignments")
        parent_b3 = ([row for row in parent_assignments
                      if isinstance(row, dict) and row.get("slot") == 3]
                     if isinstance(parent_assignments, list) else [])
        if (schedule.get("fingerprint") != fingerprint
                or len(parent_b3) != 1 or parent_b3[0].get("arm") != "B3"
                or schedule.get("assignments") != parent_b3):
            raise StopConflict("Pro diagnostic B3 assignment or fingerprint differs from parent")
    images = fingerprint.get("images") if isinstance(fingerprint, dict) else None
    expected_image = images.get("agent") if isinstance(images, dict) else None
    if not isinstance(expected_image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image) is None:
        raise StopConflict("Diagnostic schedule lacks a frozen agent image")
    folder = schedule_path.parent
    admission = _read_committed(folder / "admissions" / f"{run_id}.json")
    pending = _read_committed(folder / "pending-run.json")
    schedule_hash = _committed_sha(schedule)
    slot = admission.get("slot")
    assignments = schedule.get("assignments")
    if (not _allowed_slot(pilot_id, slot)
            or admission.get("pilot_id") != pilot_id or admission.get("run_id") != run_id
            or admission.get("parent_pilot_id") != diagnostic.PARENT_PILOT_ID
            or admission.get("parent_schedule_sha256") != parent_hash
            or admission.get("schedule_sha256") != schedule_hash
            or (schedule.get("pilot_protocol") is not None
                and admission.get("pilot_protocol") != schedule.get("pilot_protocol"))
            or pending != admission
            or not isinstance(assignments, list)
            or sum(isinstance(row, dict) and row.get("slot") == slot for row in assignments) != 1):
        raise StopConflict("Diagnostic admission or pending run differs")
    return pilot_id, schedule_path, slot, expected_image


def request_stop(run_id: str) -> dict[str, Any]:
    """Hash-commit operator intent, then stop only the verified attacker container."""
    _validate_run_id(run_id)
    requested_utc = utc_now()
    with _stop_lock():
        selected = _pilot_paths(run_id)
        if selected is None:
            raise StopConflict("Run has no allowlisted diagnostic admission")
        pilot_id, schedule_path = selected
        request_path = _request_path(schedule_path, run_id)
        outcome_path = _outcome_path(schedule_path, run_id)
        project = "shape" + run_id.lower()
        existing_request = stop_requested(run_id, pilot_id)
        if existing_request:
            request = _read_committed(request_path)
            request_sha = _committed_sha(request)
            failures = _failures(schedule_path, run_id, pilot_id, request)
            if outcome_path.exists() or outcome_path.with_suffix(".sha256").exists():
                outcome = _read_committed(outcome_path)
                completed = outcome.get("completed_utc")
                try:
                    completed_at = datetime.fromisoformat(completed.replace("Z", "+00:00"))
                    requested_at = datetime.fromisoformat(request["requested_utc"].replace("Z", "+00:00"))
                except (AttributeError, TypeError, ValueError) as exc:
                    raise StopConflict("Operator-stop outcome time is invalid") from exc
                if (outcome.get("schema_version") != 1 or outcome.get("pilot_id") != pilot_id
                        or outcome.get("run_id") != run_id or outcome.get("slot") != request["slot"]
                        or outcome.get("request_sha256") != request_sha
                        or outcome.get("state") not in {
                            "stop_command_succeeded", "container_already_stopped"}
                        or completed_at.tzinfo is None or completed_at < requested_at):
                    raise StopConflict("Operator-stop outcome differs from request")
                return {"run_id": run_id, "pilot_id": pilot_id,
                        "stop_requested": True, "state": outcome.get("state"),
                        "retry_available": False, "repeated": True}
            try:
                _, _, slot, expected_image = _admitted_context(run_id, pilot_id)
            except StopConflict:
                # The runner may already have archived and cleared pending.
                if (schedule_path.parent.parent.parent / "runs" / run_id / "result.json").is_file():
                    return {"run_id": run_id, "pilot_id": pilot_id,
                            "stop_requested": True, "state": "request_recorded",
                            "retry_available": False, "repeated": True}
                raise
            observed = _attacker_container(
                project, run_id, expected_image, require_running=False, allow_missing=True)
            if observed is None:
                identifier, running = request["container_id"], False
            else:
                identifier, running = observed
            if identifier != request["container_id"] or slot != request["slot"]:
                raise StopConflict("Attacker container changed after operator-stop request")
        else:
            failures = []
            pilot_id, schedule_path, slot, expected_image = _admitted_context(run_id, pilot_id)
            identifier, running = _attacker_container(project, run_id, expected_image)
            if (schedule_path.parent.parent.parent / "runs" / run_id / "result.json").exists():
                raise StopConflict("Diagnostic attempt was already archived")
            request = {
                "schema_version": 1, "pilot_id": pilot_id, "run_id": run_id,
                "slot": slot, "requested_utc": requested_utc, "actor": "local_dashboard",
                "reason": "operator_stop", "project": project,
                "container_id": identifier,
            }
            committed._write_committed(request_path, request)
        state = "stop_command_succeeded" if running else "container_already_stopped"
        error = None
        if running:
            try:
                _docker(["docker", "stop", "--time", "5", identifier], timeout=20)
            except StopConflict as exc:
                state = "stop_failed"
                error = str(exc)
        if state == "stop_failed":
            sequence = len(failures) + 1
            failure = {
                "schema_version": 1, "pilot_id": pilot_id, "run_id": run_id,
                "slot": slot, "sequence": sequence,
                "request_sha256": _committed_sha(request),
                "completed_utc": utc_now(), "state": state,
                "docker_exit_code": 1, "error": error,
            }
            committed._write_committed(_failure_path(schedule_path, run_id, sequence), failure)
            return {"run_id": run_id, "pilot_id": pilot_id, "stop_requested": True,
                    "state": state, "error": error, "retry_available": True,
                    "repeated": existing_request}
        outcome = {
            "schema_version": 1, "pilot_id": pilot_id, "run_id": run_id,
            "slot": slot, "request_sha256": _committed_sha(request),
            "completed_utc": utc_now(), "state": state,
            "docker_exit_code": 0 if running else None,
            "error": error,
        }
        committed._write_committed(outcome_path, outcome)
        return {"run_id": run_id, "pilot_id": pilot_id, "stop_requested": True,
                "state": state, "error": error, "retry_available": False,
                "repeated": existing_request}
