"""Launch one allowlisted SHAPE run from the local operator console."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import secrets
import subprocess
import sys
import threading
from typing import Any

from .core import RunRequest, JOBS, RUNS, job_status, private_json, utc_now


_launch_lock = threading.Lock()


def _active_job() -> str | None:
    if not JOBS.is_dir():
        return None
    for folder in JOBS.iterdir():
        if not folder.is_dir():
            continue
        status = job_status(folder.name) or {}
        if status.get("status") in {"queued", "running"}:
            pid = status.get("pid")
            if isinstance(pid, int):
                try:
                    os.kill(pid, 0)
                    return folder.name
                except ProcessLookupError:
                    pass
            elif status.get("status") == "queued":
                try:
                    created = datetime.fromisoformat(str(status["created_utc"]).replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - created).total_seconds() < 30:
                        return folder.name
                except (KeyError, ValueError):
                    pass
            status.update({"status": "failed", "error": "Worker exited before completing the run",
                           "finished_utc": utc_now()})
            private_json(folder / "status.json", status)
    return None


def launch_run(request: RunRequest) -> dict[str, Any]:
    with _launch_lock:
        active = _active_job()
        if active:
            raise RuntimeError(f"Another dashboard run is active: {active}")
        if request.mode != "deterministic":
            from experiment_controller.run_2a import read_key
            read_key()
        prefix = ("2a" if request.experiment == "2A" else "2b") + "-" + request.mode[:4]
        run_id = f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"
        folder = JOBS / run_id
        folder.mkdir(parents=True, mode=0o700)
        private_json(folder / "request.json", request.model_dump())
        private_json(folder / "status.json", {
            "run_id": run_id, "experiment": request.experiment, "mode": request.mode,
            "arm": request.arm, "status": "queued", "created_utc": utc_now(),
            "max_wall_seconds": (240 if request.mode == "connectivity" else
                                 1200 if request.mode == "pilot" else None),
            "pid": None, "error": None,
        })
        descriptor = os.open(folder / "worker.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("SHAPE_", "COMPOSE_", "ANTHROPIC_"))
                   and key not in {"ZAI_API_KEY", "DOCKER_HOST", "DOCKER_CONTEXT"}}
            try:
                subprocess.Popen([sys.executable, "-m", "dashboard.worker", run_id],
                                 cwd=RUNS.parent, env=env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            except Exception as exc:
                status = job_status(run_id) or {}
                status.update({"status": "failed", "error": f"Worker launch failed: {type(exc).__name__}",
                               "finished_utc": utc_now()})
                private_json(folder / "status.json", status)
                raise
        return {"job_id": run_id, "run_id": run_id, "status": "queued"}
