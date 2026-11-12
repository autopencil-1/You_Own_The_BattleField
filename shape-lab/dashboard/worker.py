"""Detached dashboard worker that owns one controller invocation."""

from __future__ import annotations

import fcntl
import os
import sys
import tomllib
import traceback
from typing import Any

from .core import RunRequest, JOBS, archive_error, job_status, private_json, utc_now


def checked_out_sources() -> tuple[str, str | None]:
    """Report the PentestGPT and UnifiedAgent revisions on disk without a frozen-commit gate.

    The run uses whatever PentestGPT is checked out; the manifest records the
    actual revisions so the operator can judge the outcome.
    """
    from experiment_controller.run_2a import REPO, command
    agent = REPO / "PentestGPT"
    commit = command(["git", "-C", str(agent), "rev-parse", "HEAD"]).stdout.strip()
    project = tomllib.loads((agent / "pentestgpt_agent" / "pyproject.toml").read_text(encoding="utf-8"))
    source = project.get("tool", {}).get("uv", {}).get("sources", {}).get("unified-agent")
    unified = source.get("rev") if isinstance(source, dict) else None
    return commit, unified if isinstance(unified, str) else None


def run_2a_on_checkout(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Run 2A without requiring the frozen PentestGPT commit.

    run_2a.py is hash-pinned as a frozen source by the 2B path-story pilots, so
    its gate is swapped here for this one invocation instead of being edited.
    """
    from experiment_controller import run_2a
    frozen_gate = run_2a.validate_sources
    run_2a.validate_sources = checked_out_sources
    try:
        return run_2a.run(*args, **kwargs)
    finally:
        run_2a.validate_sources = frozen_gate


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
                result = run_2a_on_checkout(request.mode, request.arm, build=request.build,
                                            run_id=run_id, provider=request.provider)
            else:
                if request.mode == "deterministic":
                    from experiment_controller.run_2b import run_deterministic
                    result = run_deterministic(request.arm, build=request.build, seed=request.seed,
                                               branching_factor=request.branching_factor, run_id=run_id)
                else:
                    from experiment_controller.run_2b import run_connectivity
                    result = run_connectivity(build=request.build, seed=request.seed, run_id=run_id,
                                              provider=request.provider)
            manifest = result["manifest"]
            error = archive_error(manifest)
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
