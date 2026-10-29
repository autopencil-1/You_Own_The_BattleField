"""Run catalog, validated fixture launch requests, and live event projection."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


LAB = Path(__file__).resolve().parents[1]
RUNS = LAB / "runs"
JOBS = RUNS / ".dashboard-jobs"
UI_DIST = LAB / "dashboard_ui" / "dist"
RUN_ID_RE = re.compile(r"2[ab]-[a-z0-9-]{1,75}$")
SEED_RE = re.compile(r"[A-Za-z0-9._-]{1,128}$")
ARMS = {"2A": ("C0", "C1", "C2"), "2B": ("B0", "B1", "B2", "B3")}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run_path(run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid run ID")
    path = RUNS / run_id
    if not path.is_dir() or path.is_symlink() or path.resolve().parent != RUNS.resolve():
        raise FileNotFoundError(run_id)
    return path


def private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return None
    return value if isinstance(value, dict) else None


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    experiment: str
    mode: str = "deterministic"
    arm: str
    build: bool = False
    seed: str = "fixture-seed"
    branching_factor: int = Field(default=4, ge=1, le=15)

    @model_validator(mode="after")
    def validate_run(self) -> "RunRequest":
        if self.experiment not in ARMS or self.arm not in ARMS[self.experiment]:
            raise ValueError("Experiment and arm do not match")
        allowed = {"2A": {"deterministic", "connectivity", "pilot"},
                   "2B": {"deterministic", "connectivity"}}
        if self.mode not in allowed[self.experiment]:
            raise ValueError("Mode is unavailable for this experiment")
        if self.experiment == "2A" and self.mode == "pilot" and self.arm != "C2":
            raise ValueError("The 2A pilot uses C2 only")
        if self.experiment == "2B" and self.mode == "connectivity" and self.arm != "B0":
            raise ValueError("The 2B connectivity fixture uses B0 only")
        if not SEED_RE.fullmatch(self.seed):
            raise ValueError("Invalid seed")
        if self.experiment == "2A" and (self.seed != "fixture-seed" or self.branching_factor != 4):
            raise ValueError("2A does not use the 2B seed or branching factor")
        if self.experiment == "2B" and self.mode == "connectivity" and self.branching_factor != 4:
            raise ValueError("The 2B connectivity fixture uses branching factor 4")
        return self


def key_configured() -> bool:
    """Report only whether the root .env contains a nonempty Z.AI key."""
    path = LAB.parent / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines:
        name, separator, value = line.removeprefix("export ").partition("=")
        if separator and name.strip() == "ZAI_API_KEY":
            return bool(value.strip().strip("\"'"))
    return False


def capabilities() -> dict[str, Any]:
    agent_2a = read_json(LAB / "config" / "agent_2a_task.json") or {}
    agent_2b = read_json(LAB / "config" / "agent_2b_task.json") or {}
    return {
        "schema_version": 1,
        "experiments": [
            {"id": "2A", "name": "OBEY", "arms": list(ARMS["2A"]),
             "launch_modes": ["deterministic", "connectivity", "pilot"],
             "agent": agent_2a.get("agent"), "pilot_caps": agent_2a.get("caps_per_trial")},
            {"id": "2B", "name": "EXPLORE", "arms": list(ARMS["2B"]),
             "launch_modes": ["deterministic", "connectivity"],
             "agent": agent_2b.get("agent"), "fixture_caps": {"wall_seconds": 240, "max_agent_tool_calls": 20,
                                                                  "max_model_calls": 8, "max_model_tokens_input_plus_output": 100000}},
        ],
        "credential_configured": key_configured(),
        "agent_settings_source": "config/agent_2a_task.json and config/agent_2b_task.json",
    }


def job_path(run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid run ID")
    return JOBS / run_id / "status.json"


def job_status(run_id: str) -> dict[str, Any] | None:
    return read_json(job_path(run_id))


def list_runs(limit: int = 80) -> list[dict[str, Any]]:
    RUNS.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows = []
    for path in RUNS.iterdir():
        if not path.is_dir() or path.is_symlink() or not RUN_ID_RE.fullmatch(path.name):
            continue
        manifest = read_json(path / "manifest.json") or {}
        job = job_status(path.name) or {}
        rows.append({
            "run_id": path.name,
            "experiment": "2A" if path.name.startswith("2a-") else "2B",
            "mode": manifest.get("mode") or job.get("mode") or "unknown",
            "arm": manifest.get("arm") or job.get("arm"),
            "status": job.get("status") or ("complete" if (path / "result.json").exists() else "archived"),
            "started_utc": manifest.get("started_utc") or job.get("created_utc"),
            "finished_utc": manifest.get("finished_utc"),
            "termination_reason": manifest.get("termination_reason"),
            "experimental_result": bool(manifest.get("experimental_result", False)),
        })
    rows.sort(key=lambda item: item["started_utc"] or "", reverse=True)
    return rows[:limit]


def _jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (FileNotFoundError, OSError):
        return []
    records = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            if number == len(lines):
                continue
            records.append((number, {"event_type": "telemetry_gap", "error": "invalid_json"}))
            continue
        if isinstance(value, dict):
            records.append((number, value))
    return records


def _compact(value: object, maximum: int = 12000) -> object:
    if isinstance(value, str):
        return value[:maximum] + ("\n[display truncated]" if len(value) > maximum else "")
    if isinstance(value, dict):
        return {str(key): _compact(item, maximum) for key, item in value.items()}
    if isinstance(value, list):
        return [_compact(item, maximum) for item in value[:100]]
    return value


def _project(source: str, row: dict[str, Any], *, episode_id: str | None = None,
             role: str | None = None) -> dict[str, Any]:
    kind = str(row.get("event_type") or row.get("type") or "unknown")
    occurred = row.get("timestamp_utc")
    if not isinstance(occurred, str):
        stamp = row.get("recorded_at")
        occurred = datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") if isinstance(stamp, (int, float)) else utc_now()
    detail = {key: value for key, value in row.items()
              if key not in {"body_b64", "body_sha256", "timestamp_utc", "recorded_at", "sequence", "run_id", "condition", "experiment", "source", "elapsed_ms"}}
    if source == "decoy" and isinstance(row.get("body_b64"), str):
        try:
            body = base64.b64decode(row["body_b64"], validate=True)
            detail["response_text"] = _compact(body.decode("utf-8", errors="replace"))
            detail["body_sha256"] = row.get("body_sha256")
            detail["body_hash_verified"] = hashlib.sha256(body).hexdigest() == row.get("body_sha256")
        except ValueError:
            detail["response_text"] = "[invalid archived response]"
            detail["body_hash_verified"] = False
    return {"source": source, "kind": kind, "occurred_utc": occurred,
            "source_sequence": row.get("sequence"), "episode_id": episode_id,
            "role": role, "call_id": row.get("call_id"), "detail": _compact(detail)}


class Collector:
    def __init__(self) -> None:
        self.lock = threading.RLock()

    def collect(self, run_id: str) -> list[dict[str, Any]]:
        path = run_path(run_id)
        index = path / "monitor-events.jsonl"
        with self.lock:
            existing = [row for _, row in _jsonl(index) if "event_id" in row]
            seen = {row.get("source_key") for row in existing}
            fresh: list[dict[str, Any]] = []

            for source in ("decoy", "gateway"):
                for filename in (f"{source}-live.jsonl", f"{source}-events.jsonl"):
                    for line, row in _jsonl(path / filename):
                        if row.get("run_id") != run_id and row.get("event_type") != "telemetry_gap":
                            continue
                        sequence = row.get("sequence")
                        key = f"{source}:{sequence}" if isinstance(sequence, int) else f"{source}:{filename}:{line}"
                        if key in seen:
                            continue
                        seen.add(key)
                        fresh.append({"source_key": key, "raw_ref": {"file": filename, "line": line},
                                      **_project(source, row)})

            traces = path / "agent" / "runs" / run_id / "traces"
            if traces.is_dir():
                for episode in sorted(traces.iterdir()):
                    if not episode.is_dir():
                        continue
                    role = (read_json(episode / "input.json") or {}).get("role")
                    for line, row in _jsonl(episode / "events.jsonl"):
                        sequence = row.get("sequence")
                        key = f"agent:{episode.name}:{sequence}" if isinstance(sequence, int) else f"agent:{episode.name}:{line}"
                        if key in seen:
                            continue
                        seen.add(key)
                        fresh.append({"source_key": key,
                                      "raw_ref": {"file": f"agent/runs/{run_id}/traces/{episode.name}/events.jsonl", "line": line},
                                      **_project("agent", row, episode_id=episode.name, role=role)})

            for filename in ("agent-live.log", "agent-stdout.log"):
                try:
                    lines = (path / filename).read_text(encoding="utf-8", errors="replace").splitlines()
                except (FileNotFoundError, OSError):
                    continue
                for line, value in enumerate(lines, 1):
                    if not value.startswith("AGENT_STARTED="):
                        continue
                    stamp = value.partition("=")[2].strip()
                    try:
                        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    key = "agent-runtime:started"
                    if key in seen:
                        continue
                    seen.add(key)
                    fresh.append({"source_key": key, "raw_ref": {"file": filename, "line": line},
                                  "source": "controller", "kind": "agent_started",
                                  "occurred_utc": stamp, "source_sequence": None,
                                  "episode_id": None, "role": None, "call_id": None,
                                  "detail": {"message": "Agent process started"}})

            if fresh:
                fresh.sort(key=lambda item: (item["occurred_utc"], item["source_key"]))
                descriptor = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    for item in fresh:
                        item["event_id"] = len(existing) + 1
                        item["run_id"] = run_id
                        item["experiment"] = "2A" if run_id.startswith("2a-") else "2B"
                        item["observed_utc"] = utc_now()
                        stream.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
                        existing.append(item)
                    stream.flush()
                    os.fsync(stream.fileno())
            return existing


collector = Collector()


def run_snapshot(run_id: str) -> dict[str, Any]:
    path = run_path(run_id)
    events = collector.collect(run_id)
    manifest = read_json(path / "manifest.json") or {}
    job = job_status(run_id) or {}
    agent_started = next((item["occurred_utc"] for item in events if item["kind"] == "agent_started"), None)
    return {
        "run_id": run_id, "experiment": "2A" if run_id.startswith("2a-") else "2B",
        "mode": manifest.get("mode") or job.get("mode"),
        "arm": manifest.get("arm") or job.get("arm"),
        "status": job.get("status") or ("complete" if (path / "result.json").exists() else "archived"),
        "started_utc": manifest.get("started_utc") or job.get("created_utc"),
        "agent_started_utc": agent_started,
        "finished_utc": manifest.get("finished_utc"),
        "termination_reason": manifest.get("termination_reason"),
        "error": manifest.get("error") or job.get("error"),
        "max_wall_seconds": manifest.get("max_wall_seconds") or job.get("max_wall_seconds"),
        "experimental_result": bool(manifest.get("experimental_result", False)),
        "event_count": len(events),
        "score": (read_json(path / "result.json") or {}).get("score"),
        "job": job,
    }


def provisional_snapshot(run_id: str) -> dict[str, Any] | None:
    job = job_status(run_id)
    if job is None:
        return None
    return {
        "run_id": run_id, "experiment": job.get("experiment"),
        "mode": job.get("mode"), "arm": job.get("arm"),
        "status": job.get("status"), "started_utc": job.get("created_utc"),
        "agent_started_utc": None, "finished_utc": job.get("finished_utc"),
        "termination_reason": job.get("termination_reason"),
        "error": job.get("error"), "max_wall_seconds": job.get("max_wall_seconds"),
        "experimental_result": False,
        "event_count": 0, "score": None, "job": job,
    }
