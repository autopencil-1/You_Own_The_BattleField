"""Detached dashboard worker that owns one controller invocation."""

from __future__ import annotations

import fcntl
import os
import sys
import traceback

from .core import RunRequest, JOBS, job_status, private_json, utc_now


def main(run_id: str) -> int:
    folder = JOBS / run_id
    request = RunRequest.model_validate_json((folder / "request.json").read_text(encoding="utf-8"))
    lock_path = JOBS / "active.lock"
    descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            status = job_status(run_id) or {}
            status.update({"status": "failed", "error": "Another worker holds the trial lock",
                           "finished_utc": utc_now(), "pid": os.getpid()})
            private_json(folder / "status.json", status)
            return 1
        status = job_status(run_id) or {}
        status.update({"status": "running", "started_utc": utc_now(), "pid": os.getpid()})
        private_json(folder / "status.json", status)
        try:
            if request.experiment == "2A":
                from experiment_controller.run_2a import run
                result = run(request.mode, request.arm, build=request.build, run_id=run_id)
            else:
                if request.mode == "deterministic":
                    from experiment_controller.run_2b import run_deterministic
                    result = run_deterministic(request.arm, build=request.build, seed=request.seed,
                                               branching_factor=request.branching_factor, run_id=run_id)
                else:
                    from experiment_controller.run_2b import run_connectivity
                    result = run_connectivity(build=request.build, seed=request.seed, run_id=run_id)
            manifest = result["manifest"]
            error = manifest.get("error")
            if request.experiment == "2A" and "scoring_error" in result.get("score", {}):
                error = result["score"]["scoring_error"]
            status.update({"status": "failed" if error else "complete",
                           "error": error, "termination_reason": manifest.get("termination_reason"),
                           "finished_utc": utc_now()})
            private_json(folder / "status.json", status)
            return 1 if error else 0
        except Exception as exc:
            traceback.print_exc()
            status.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}",
                           "finished_utc": utc_now()})
            private_json(folder / "status.json", status)
            return 1
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
