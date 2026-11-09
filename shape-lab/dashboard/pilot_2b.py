"""Local dashboard adapter for one frozen 2B path-story pilot assignment."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import secrets
import subprocess
import sys
from typing import Any

from . import jobs
from .core import JOBS, RUNS, key_configured, private_json, utc_now


PILOT_ID = "2b-path-story-pilot-v5-zai-20261109154540-d08c59"


def _reason(phase: str, credits: dict[str, Any]) -> str | None:
    if phase == "ready_for_next_run":
        return None
    if phase == "paused_provider_rate_limit":
        until = credits.get("rate_limit_pause_until_utc")
        return f"Provider rate-limit pause until {until}" if until else "Provider rate-limit pause"
    if phase == "paused_credit_share_admission":
        return "The pilot's estimated credit share is below its per-run reserve"
    if phase == "pending_attempt_reconciliation":
        return "An admitted attempt must finish or be reconciled before another starts"
    if phase == "complete":
        return "All scheduled assignments are complete"
    return f"Pilot is not ready: {phase}"


def public_status() -> dict[str, Any]:
    """Use the controller's read-only checks; disclose no future assignment."""
    from experiment_controller.path_story_pilot_2b_zai_v5 import status

    current = status(PILOT_ID)
    credits = current.get("credits") if isinstance(current.get("credits"), dict) else {}
    phase = str(current.get("phase") or "unknown")
    reason = _reason(phase, credits)
    if reason is None and not key_configured("zai"):
        reason = "Z.AI key is not configured in the root .env"
    return {
        "pilot_id": PILOT_ID,
        "pilot_protocol": current.get("pilot_protocol"),
        "schedule_sha256": current.get("schedule_sha256"),
        "scheduled_runs": current.get("scheduled_runs"),
        "valid_runs": current.get("valid_runs"),
        "completed_slots": current.get("completed_slots"),
        "invalid_attempts": current.get("invalid_attempts"),
        "next_slot": current.get("next_slot"),
        "pending_run": current.get("pending_run"),
        "phase": phase,
        "credits": credits,
        "launch_available": reason is None,
        "launch_reason": reason,
    }


def launch_next(current: dict[str, Any]) -> dict[str, Any]:
    """Queue one detached worker; the controller makes final admission."""
    if current.get("pilot_id") != PILOT_ID or not current.get("launch_available"):
        raise RuntimeError(str(current.get("launch_reason") or "Pilot launch is unavailable"))
    from experiment_controller.run_2a import read_key

    read_key("zai")
    with jobs._launch_lock:
        active = jobs._active_job()
        if active:
            raise RuntimeError(f"Another dashboard run is active: {active}")
        job_id = "2b-pilo-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        folder = JOBS / job_id
        folder.mkdir(parents=True, mode=0o700)
        admissions = RUNS.parent / "studies" / PILOT_ID / "admissions"
        baseline = sorted(path.name for path in admissions.glob("*.json")) if admissions.is_dir() else []
        private_json(folder / "request.json", {
            "kind": "path_story_pilot_v5", "pilot_id": PILOT_ID,
            "schedule_sha256": current["schedule_sha256"],
            "slot": current.get("next_slot"),
            "baseline_admissions": baseline,
        })
        private_json(folder / "status.json", {
            "job_id": job_id, "run_id": None, "pilot_id": PILOT_ID,
            "slot": current.get("next_slot"), "status": "queued", "created_utc": utc_now(),
            "pid": None, "error": None,
        })
        descriptor = os.open(folder / "worker.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("SHAPE_", "COMPOSE_", "ANTHROPIC_"))
                   and key not in {"ZAI_API_KEY", "OLLAMA_API_KEY", "DOCKER_HOST", "DOCKER_CONTEXT"}}
            try:
                subprocess.Popen([sys.executable, "-m", "dashboard.pilot_2b_worker", job_id],
                                 cwd=RUNS.parent, env=env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            except Exception as exc:
                status = {"job_id": job_id, "run_id": None, "pilot_id": PILOT_ID,
                          "status": "failed", "error": f"Worker launch failed: {type(exc).__name__}",
                          "finished_utc": utc_now()}
                private_json(folder / "status.json", status)
                raise
    return {"job_id": job_id, "status": "queued", "pilot_id": PILOT_ID,
            "next_slot": current.get("next_slot")}
