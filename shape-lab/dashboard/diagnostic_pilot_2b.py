"""Dashboard admission for the separately recorded 2B diagnostic continuation."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import secrets
import subprocess
import sys
from typing import Any

from . import jobs
from .core import JOBS, RUNS, key_configured, private_json, read_json, utc_now


def _controller():
    from experiment_controller import path_story_diagnostic_2b_v1

    return path_story_diagnostic_2b_v1


def _unreconciled_provider_exposure(current: dict[str, Any]) -> str | None:
    """Pause dashboard starts when an archived attempt lacks complete settlement.

    The frozen controller estimates credits only from reported successful usage.
    A provider 401 has no usage report, so its zero estimate cannot authorize
    another unattended run while settlement remains incomplete.
    """
    attempts = current.get("invalid_attempts")
    if not isinstance(attempts, list):
        return "Diagnostic attempt ledger is unavailable"
    for attempt in attempts:
        run_id = attempt.get("run_id") if isinstance(attempt, dict) else None
        if not isinstance(run_id, str) or not run_id.startswith("2b-path-"):
            return "Diagnostic attempt identity differs"
        manifest = read_json(RUNS / run_id / "attempt-manifest.json")
        settlement = manifest.get("provider_settlement") if isinstance(manifest, dict) else None
        if not isinstance(settlement, dict) or settlement.get("state") != "complete":
            return f"Run {run_id} has incomplete provider settlement; reconcile credentials and cost before another attempt"
    return None


def public_status() -> dict[str, Any]:
    """Read admission without revealing a future arm or seed."""
    controller = _controller()
    if not controller.SCHEDULE.is_file():
        return {
            "pilot_id": controller.PILOT_ID,
            "pilot_protocol": controller.PROTOCOL,
            "phase": "not_prepared",
            "launch_available": False,
            "launch_reason": "Diagnostic schedule has not been prepared",
            "pending_run": None,
        }
    current = controller.status()
    if not isinstance(current, dict) or current.get("pilot_id") != controller.PILOT_ID:
        raise RuntimeError("Diagnostic controller status differs")
    current = dict(current)
    reason = current.get("launch_reason")
    exposure = _unreconciled_provider_exposure(current)
    if exposure:
        reason = exposure
        current["controller_phase"] = current.get("phase")
        current["phase"] = "paused_unreconciled_provider_exposure"
    if not key_configured("zai"):
        reason = "Z.AI key is not configured in the root .env"
    current["launch_available"] = bool(current.get("launch_available")) and not reason
    current["launch_reason"] = reason
    pending = current.get("pending_run")
    if isinstance(pending, dict) and isinstance(pending.get("run_id"), str):
        from .diagnostic_stop_2b import stop_requested, stop_retry_available

        pending = dict(pending)
        pending["stop_requested"] = stop_requested(pending["run_id"], controller.PILOT_ID)
        pending["stop_retry_available"] = (stop_retry_available(pending["run_id"], controller.PILOT_ID)
                                           if pending["stop_requested"] else False)
        current["pending_run"] = pending
    return current


def launch_next(current: dict[str, Any]) -> dict[str, Any]:
    """Queue exactly one controller-admitted attempt per dashboard action."""
    controller = _controller()
    if current.get("pilot_id") != controller.PILOT_ID or not current.get("launch_available"):
        raise RuntimeError(str(current.get("launch_reason") or "Diagnostic launch is unavailable"))
    from experiment_controller.run_2a import read_key

    read_key("zai")
    with jobs._launch_lock:
        active = jobs._active_job()
        if active:
            raise RuntimeError(f"Another dashboard run is active: {active}")
        # Admission is rechecked after the local queue lock to narrow stale-status races.
        admitted = public_status()
        if not admitted.get("launch_available") or admitted.get("next_slot") != current.get("next_slot"):
            raise RuntimeError(str(admitted.get("launch_reason") or "Diagnostic assignment changed"))
        job_id = "2b-diag-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        folder = JOBS / job_id
        folder.mkdir(parents=True, mode=0o700)
        admissions = RUNS.parent / "studies" / controller.PILOT_ID / "admissions"
        baseline = sorted(path.name for path in admissions.glob("*.json")) if admissions.is_dir() else []
        private_json(folder / "request.json", {
            "kind": "path_story_diagnostic_v1",
            "pilot_id": controller.PILOT_ID,
            "schedule_sha256": admitted["schedule_sha256"],
            "slot": admitted.get("next_slot"),
            "baseline_admissions": baseline,
        })
        private_json(folder / "status.json", {
            "job_id": job_id,
            "run_id": None,
            "pilot_id": controller.PILOT_ID,
            "slot": admitted.get("next_slot"),
            "status": "queued",
            "created_utc": utc_now(),
            "pid": None,
            "error": None,
        })
        descriptor = os.open(folder / "worker.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("SHAPE_", "COMPOSE_", "ANTHROPIC_"))
                   and key not in {"ZAI_API_KEY", "OLLAMA_API_KEY", "DOCKER_HOST", "DOCKER_CONTEXT"}}
            try:
                subprocess.Popen([sys.executable, "-m", "dashboard.diagnostic_pilot_2b_worker", job_id],
                                 cwd=RUNS.parent, env=env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            except Exception as exc:
                private_json(folder / "status.json", {
                    "job_id": job_id, "run_id": None, "pilot_id": controller.PILOT_ID,
                    "status": "failed", "error": f"Worker launch failed: {type(exc).__name__}",
                    "finished_utc": utc_now(),
                })
                raise
    return {"job_id": job_id, "status": "queued", "pilot_id": controller.PILOT_ID,
            "next_slot": admitted.get("next_slot")}
