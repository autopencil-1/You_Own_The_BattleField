"""Detached dashboard worker for one diagnostic 2B continuation attempt."""

from __future__ import annotations

import fcntl
import os
import sys
import threading
import traceback
from typing import Any

from .core import JOBS, LAB, RUN_ID_RE, job_status, private_json, read_json, utc_now
from .diagnostic_pilot_2b import _controller


def _admitted_run(request: dict[str, Any]) -> dict[str, Any] | None:
    from experiment_controller import path_story_pilot_2b_v2 as prior

    pilot_id = request.get("pilot_id")
    folder = LAB / "studies" / str(pilot_id)
    baseline = set(request.get("baseline_admissions") or [])
    paths = [folder / "pending-run.json"]
    admissions = folder / "admissions"
    if admissions.is_dir():
        paths.extend(path for path in admissions.glob("*.json") if path.name not in baseline)
    found: dict[str, dict[str, Any]] = {}
    for path in paths:
        if not path.exists():
            continue
        try:
            admission = prior._read_committed(path)
        except (OSError, ValueError, RuntimeError):
            continue
        run_id = admission.get("run_id")
        if (not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id)
                or admission.get("pilot_id") != pilot_id
                or admission.get("schedule_sha256") != request.get("schedule_sha256")
                or admission.get("slot") != request.get("slot")
                or run_id + ".json" in baseline):
            continue
        found[run_id] = admission
    return next(iter(found.values())) if len(found) == 1 else None


def main(job_id: str) -> int:
    if not RUN_ID_RE.fullmatch(job_id) or not job_id.startswith("2b-diag-"):
        return 2
    folder = JOBS / job_id
    request = read_json(folder / "request.json") or {}
    controller = _controller()
    if request.get("kind") != "path_story_diagnostic_v1" or request.get("pilot_id") != controller.PILOT_ID:
        return 2
    descriptor = os.open(JOBS / "active.lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            current = job_status(job_id) or {}
            current.update({"status": "failed", "error": "Another worker holds the trial lock",
                            "finished_utc": utc_now(), "pid": os.getpid()})
            private_json(folder / "status.json", current)
            return 1
        current = job_status(job_id) or {}
        current.update({"status": "running", "started_utc": utc_now(), "pid": os.getpid()})
        private_json(folder / "status.json", current)
        outcome: dict[str, Any] = {}

        def execute_one() -> None:
            try:
                outcome["controller_status"] = controller.execute()
            except Exception as exc:
                traceback.print_exc()
                outcome["error"] = f"{type(exc).__name__}: {exc}"

        thread = threading.Thread(target=execute_one, name="shape-2b-diagnostic-execute")
        thread.start()
        while thread.is_alive():
            admission = _admitted_run(request)
            if admission and not current.get("run_id"):
                current.update({"run_id": admission["run_id"], "slot": admission.get("slot")})
                private_json(folder / "status.json", current)
            thread.join(timeout=0.25)
        if not current.get("run_id"):
            admission = _admitted_run(request)
            if admission:
                current.update({"run_id": admission["run_id"], "slot": admission.get("slot")})
        result = outcome.get("controller_status")
        if outcome.get("error"):
            current.update({"status": "failed", "error": outcome["error"]})
        elif isinstance(result, dict) and current.get("run_id"):
            current.update({"status": "complete", "pilot_phase": result.get("phase"), "error": None})
        else:
            phase = result.get("phase") if isinstance(result, dict) else "unknown"
            current.update({"status": "not_admitted", "pilot_phase": phase,
                            "run_id": None, "error": result.get("launch_reason") if isinstance(result, dict)
                            else "Controller did not admit a new attempt"})
        current["finished_utc"] = utc_now()
        private_json(folder / "status.json", current)
        return 0 if current["status"] == "complete" else 1
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
