"""Run catalog, validated fixture launch requests, and live event projection."""

from __future__ import annotations

import base64
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import threading
from typing import Any, Iterator
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


LAB = Path(__file__).resolve().parents[1]
RUNS = LAB / "runs"
JOBS = RUNS / ".dashboard-jobs"
STUDIES = LAB / "studies"
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


def _path_story(run_id: str) -> bool:
    return run_id.startswith("2b-path-") and RUN_ID_RE.fullmatch(run_id) is not None


def monitor_index_path(run_id: str) -> Path:
    """Keep derived UI state outside controller-signed run archives."""
    if RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError("Invalid run ID")
    return RUNS / ".dashboard-monitor" / run_id / "events.jsonl"


def _controller_manifest(path: Path) -> dict[str, Any]:
    if not _path_story(path.name):
        return read_json(path / "manifest.json") or {}
    attempt = read_json(path / "attempt-manifest.json") or {}
    if attempt.get("run_id") != path.name or not str(attempt.get("pilot_protocol", "")).startswith(
        "2b-path-story-pilot-"
    ):
        return {}
    return attempt


def _manifest_name(path: Path) -> str:
    return "attempt-manifest.json" if _path_story(path.name) else "manifest.json"


def _pending_path_story() -> dict[str, dict[str, Any]]:
    """Read admitted pilot assignments for runs that have not archived yet."""
    if not STUDIES.is_dir():
        return {}
    pending: dict[str, dict[str, Any]] = {}
    for folder in STUDIES.iterdir():
        if not folder.is_dir() or folder.is_symlink() or not folder.name.startswith("2b-path-story-pilot-"):
            continue
        admission = read_json(folder / "pending-run.json") or {}
        run_id = admission.get("run_id")
        if not isinstance(run_id, str) or not _path_story(run_id) or admission.get("pilot_id") != folder.name:
            continue
        schedule = read_json(folder / "schedule.json") or {}
        assignments = schedule.get("assignments")
        slot = admission.get("slot")
        if not isinstance(assignments, list) or not isinstance(slot, int) or isinstance(slot, bool):
            continue
        assignment = next((row for row in assignments if isinstance(row, dict) and row.get("slot") == slot), None)
        if assignment is None:
            continue
        contract = schedule.get("contract") if isinstance(schedule.get("contract"), dict) else {}
        pending[run_id] = {
            "pilot_id": folder.name,
            "pilot_protocol": schedule.get("pilot_protocol"),
            "slot": slot,
            "block": assignment.get("block"),
            "arm": assignment.get("arm"),
            "provider": contract.get("provider"),
            "started_utc": admission.get("created_utc"),
            "trial_caps": contract.get("trial_caps") if isinstance(contract.get("trial_caps"), dict) else {},
        }
    return pending


def _last_complete_jsonl(path: Path) -> dict[str, Any] | None:
    """Read one live monitor sample without loading its growing journal."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 65536))
            lines = stream.read().splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and isinstance(value.get("observed_utc"), str):
            return value
    return None


def _path_story_progress(path: Path, manifest: dict[str, Any], pending: dict[str, Any]) -> dict[str, Any] | None:
    if not _path_story(path.name):
        return None
    sample = _last_complete_jsonl(path / "cap-monitor.jsonl")
    clock = manifest.get("clock") if isinstance(manifest.get("clock"), dict) else {}
    caps = manifest.get("trial_caps") if isinstance(manifest.get("trial_caps"), dict) else pending.get("trial_caps", {})
    replay = manifest.get("replay") if isinstance(manifest.get("replay"), dict) else {}
    if not sample and not clock:
        return None
    sample = sample or {}
    return {
        "phase": clock.get("clock_phase") or sample.get("clock_phase"),
        "observed_utc": sample.get("observed_utc"),
        "pre_entry_elapsed_seconds": clock.get("pre_entry_elapsed_seconds", sample.get("pre_entry_elapsed_seconds")),
        "post_entry_elapsed_seconds": clock.get("post_entry_elapsed_seconds", sample.get("post_entry_elapsed_seconds")),
        "pre_entry_wall_seconds": caps.get("pre_entry_wall_seconds"),
        "post_entry_wall_seconds": caps.get("post_entry_wall_seconds"),
        "qualified_entry_utc": clock.get("qualified_entry_utc") or sample.get("qualified_entry_utc"),
        "filesystem_actions": replay.get("filesystem_actions", sample.get("filesystem_actions")),
        "materialized_nodes": replay.get("materialized_nodes"),
        "agent_tool_calls": sample.get("agent_tool_calls"),
        "model_calls": sample.get("model_calls"),
        "model_tokens": sample.get("model_tokens"),
        "selected_reason": manifest.get("termination_reason") or sample.get("selected_reason"),
    }


def _path_story_artifacts_match(path: Path, manifest: dict[str, Any]) -> bool:
    """Verify the complete signed file set without writing to the run archive."""
    artifacts = manifest.get("artifact_sha256")
    if not isinstance(artifacts, dict) or not artifacts:
        return False
    found: set[str] = set()
    try:
        for item in path.rglob("*"):
            if item.is_symlink():
                return False
            if not item.is_file():
                continue
            name = item.relative_to(path).as_posix()
            if name in {"attempt-manifest.json", "result.json"}:
                continue
            expected = artifacts.get(name)
            if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                return False
            digest = hashlib.sha256()
            with item.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                return False
            found.add(name)
    except OSError:
        return False
    return found == set(artifacts)


def _path_story_archive_complete(path: Path, manifest: dict[str, Any], result: dict[str, Any]) -> bool:
    """Require committed records and signed artifacts before calling an attempt reviewable."""
    settlement = manifest.get("provider_settlement")
    replay = manifest.get("replay")
    return (
        isinstance(manifest.get("finished_utc"), str)
        and isinstance(settlement, dict) and settlement.get("state") == "complete"
        and isinstance(replay, dict)
        and isinstance(result.get("score"), dict)
        and result.get("manifest") == manifest
        and result.get("replay") == replay
        and _path_story_artifacts_match(path, manifest)
    )


def _path_story_classification(manifest: dict[str, Any], result: dict[str, Any],
                               admission: dict[str, Any], archive_complete: bool) -> str | None:
    if not manifest:
        return None
    if (manifest.get("termination_reason") in {"provider_rate_limit", "agent_failure", "controller_error"}
            or manifest.get("error") or manifest.get("provider_credit_error")
            or manifest.get("path_story_evidence_error")
            or isinstance(manifest.get("provider_settlement"), dict)
            and manifest["provider_settlement"].get("state") != "complete"):
        return "infrastructure_invalid"
    if archive_complete:
        return "controller_review"
    return None if admission and not result else "infrastructure_invalid"


def _path_story_status(manifest: dict[str, Any], result: dict[str, Any],
                       admission: dict[str, Any], progress: dict[str, Any] | None,
                       archive_complete: bool) -> str:
    if _path_story_error(manifest):
        return "failed"
    if archive_complete:
        return "complete"
    if manifest and result:
        return "failed"
    if manifest or result:
        return "running" if admission else "failed"
    return "running" if progress or admission else "archived"


def _path_story_error(manifest: dict[str, Any]) -> str | None:
    for key in ("error", "provider_credit_error", "path_story_evidence_error"):
        value = manifest.get(key)
        if isinstance(value, str) and value:
            return value
    if manifest.get("termination_reason") == "provider_rate_limit":
        return "Provider rate limit; this attempt is infrastructure-invalid"
    if manifest.get("termination_reason") in {"agent_failure", "controller_error"}:
        return str(manifest["termination_reason"]).replace("_", " ")
    settlement = manifest.get("provider_settlement")
    if isinstance(settlement, dict) and settlement.get("state") != "complete":
        return "Provider settlement is incomplete"
    return None


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    experiment: str
    provider: Literal["zai", "ollama"] = "ollama"
    mode: str = "deterministic"
    arm: str
    build: bool = False
    seed: str = "fixture-seed"
    branching_factor: int = Field(default=4, ge=1, le=15)

    @model_validator(mode="after")
    def validate_run(self) -> "RunRequest":
        if self.experiment not in ARMS or self.arm not in ARMS[self.experiment]:
            raise ValueError("Experiment and arm do not match")
        allowed = {"2A": {"deterministic", "connectivity", "engineering", "pilot"},
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


def key_configured(provider: str = "ollama") -> bool:
    """Report only whether the root .env contains the selected provider key."""
    from model_gateway.providers import provider_spec
    key_name = provider_spec(provider)["key_name"]
    path = LAB.parent / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines:
        name, separator, value = line.removeprefix("export ").partition("=")
        if separator and name.strip() == key_name:
            return bool(value.strip().strip("\"'"))
    return False


def capabilities() -> dict[str, Any]:
    agent_2a = read_json(LAB / "config" / "agent_2a_task.json") or {}
    agent_2b = read_json(LAB / "config" / "agent_2b_task.json") or {}
    return {
        "schema_version": 1,
        "experiments": [
            {"id": "2A", "name": "OBEY", "arms": list(ARMS["2A"]),
             "launch_modes": ["deterministic", "connectivity", "engineering", "pilot"],
             "decoy_protocol": "session-v2",
             "agent": agent_2a.get("agent"), "pilot_caps": agent_2a.get("caps_per_trial")},
            {"id": "2B", "name": "EXPLORE", "arms": list(ARMS["2B"]),
             "launch_modes": ["deterministic", "connectivity"],
             "agent": agent_2b.get("agent"), "fixture_caps": {
                 "wall_seconds": (agent_2b.get("caps_per_trial") or {}).get("wall_seconds"), "max_agent_tool_calls": 20, "max_model_calls": 8,
                 "max_model_tokens_input_plus_output": (agent_2b.get("caps_per_trial") or {}).get("max_model_tokens_input_plus_output"),
             }},
        ],
        "credential_configured": key_configured(),
        "provider_credentials": {name: key_configured(name) for name in ("zai", "ollama")},
        "agent_settings_source": "config/agent_2a_task.json and config/agent_2b_task.json",
    }


def job_path(run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid run ID")
    return JOBS / run_id / "status.json"


def job_status(run_id: str) -> dict[str, Any] | None:
    return read_json(job_path(run_id))


def archive_error(manifest: dict[str, Any]) -> str | None:
    error = manifest.get("error")
    if isinstance(error, str) and error:
        return error
    code = manifest.get("agent_exit_code")
    if manifest.get("termination_reason") == "agent_exit" and isinstance(code, int) and code != 0:
        return f"Attacker agent exited with code {code}"
    return None


def archived_provider(manifest: dict[str, Any], job: dict[str, Any]) -> str | None:
    mode = manifest.get("mode") or job.get("mode")
    if not mode or str(mode).startswith("deterministic"):
        return None
    return manifest.get("provider") or job.get("provider") or "zai"  # Legacy agent archives used Z.AI.


def list_runs(limit: int = 80) -> list[dict[str, Any]]:
    RUNS.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows = []
    pending = _pending_path_story()
    found: set[str] = set()
    for path in RUNS.iterdir():
        if not path.is_dir() or path.is_symlink() or not RUN_ID_RE.fullmatch(path.name):
            continue
        found.add(path.name)
        path_story = _path_story(path.name)
        manifest = _controller_manifest(path)
        decoy = (read_json(path / "manifest.json") or {}) if path_story else {}
        admission = pending.get(path.name, {}) if path_story else {}
        job = job_status(path.name) or {}
        error = (_path_story_error(manifest) if path_story else archive_error(manifest)) or job.get("error")
        progress = _path_story_progress(path, manifest, admission) if path_story else None
        result = (read_json(path / "result.json") or {}) if path_story else {}
        archive_complete = _path_story_archive_complete(path, manifest, result) if path_story else False
        status = _path_story_status(manifest, result, admission, progress, archive_complete) if path_story else (
                      "failed" if error else job.get("status") or ("complete" if (path / "result.json").exists() else "archived"))
        rows.append({
            "run_id": path.name,
            "experiment": "2A" if path.name.startswith("2a-") else "2B",
            "mode": manifest.get("mode") or ("path_story_pilot" if path_story else job.get("mode") or "unknown"),
            "arm": manifest.get("arm") or admission.get("arm") or decoy.get("arm") or job.get("arm"),
            "provider": manifest.get("provider") or admission.get("provider") if path_story else archived_provider(manifest, job),
            "decoy_protocol": (manifest.get("environment_protocol") or "filesystem-path-story-v1") if path_story else manifest.get("decoy_protocol") or job.get("decoy_protocol") or ("text-only" if path.name.startswith("2a-") else None),
            "status": status,
            "started_utc": manifest.get("started_utc") or admission.get("started_utc") or job.get("created_utc"),
            "finished_utc": manifest.get("finished_utc"),
            "termination_reason": manifest.get("termination_reason") or (progress or {}).get("selected_reason"),
            "experimental_result": bool(manifest.get("experimental_result", False)),
            "pilot_id": manifest.get("pilot_id") or admission.get("pilot_id"),
            "pilot_protocol": manifest.get("pilot_protocol") or admission.get("pilot_protocol"),
            "slot": manifest.get("slot") or admission.get("slot"),
            "block": manifest.get("block") or admission.get("block"),
            "attempt_classification": _path_story_classification(manifest, result, admission, archive_complete) if path_story else None,
        })
    for run_id, admission in pending.items():
        if run_id in found or (RUNS / run_id).exists():
            continue
        rows.append({
            "run_id": run_id, "experiment": "2B", "mode": "path_story_pilot",
            "arm": admission.get("arm"), "provider": admission.get("provider"),
            "decoy_protocol": "filesystem-path-story-v1", "status": "queued",
            "started_utc": admission.get("started_utc"), "finished_utc": None,
            "termination_reason": None, "experimental_result": False,
            "pilot_id": admission.get("pilot_id"), "pilot_protocol": admission.get("pilot_protocol"),
            "slot": admission.get("slot"), "block": admission.get("block"),
            "attempt_classification": None,
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


_SESSION_SECRET_RE = re.compile(r"(?i)\b[0-9a-f]{32}\b")
_PUBLIC_EPISODE_RE = re.compile(r"trace-[0-9a-f]{20}\Z")


def _public_episode_id(name: str) -> str:
    """Give a trace a stable identifier that cannot match a session secret."""
    return f"trace-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:20]}"


def _redact_session(value: object) -> object:
    """Keep session-v2 secrets in the private archive, never the monitor API."""
    if isinstance(value, str):
        return _SESSION_SECRET_RE.sub("[redacted]", value)
    if isinstance(value, dict):
        return {key: _redact_session(item) for key, item in value.items()
                if key != "body_b64"}
    if isinstance(value, list):
        return [_redact_session(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_session(item) for item in value]
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


def _sqlite_read_uri(database: Path, run_id: str, run_dir: Path) -> str:
    # SQLite mode=ro may still create WAL/SHM beside the database. Frozen 2B
    # archives cannot gain files, and completed 2A runs should stay untouched.
    immutable = bool(_controller_manifest(run_dir).get("finished_utc")) or (run_dir / "result.json").is_file()
    return database.as_uri() + ("?mode=ro&immutable=1" if immutable else "?mode=ro")


@contextmanager
def _state_connection(database: Path, run_id: str, run_dir: Path) -> Iterator[sqlite3.Connection]:
    """Read committed WAL rows without writing into a finalized run archive."""
    uri = _sqlite_read_uri(database, run_id, run_dir)
    wal = database.with_name(database.name + "-wal")
    if "immutable=1" in uri and wal.exists():
        if wal.is_symlink() or not wal.is_file() or wal.resolve().parent != database.parent.resolve():
            raise sqlite3.DatabaseError("Agent WAL is not a regular archive file")
        with tempfile.TemporaryDirectory(prefix="shape-dashboard-sqlite-") as temporary:
            copy = Path(temporary) / database.name
            shutil.copyfile(database, copy)
            shutil.copyfile(wal, copy.with_name(wal.name))
            with closing(sqlite3.connect(copy.as_uri() + "?mode=ro", uri=True, timeout=0.1)) as connection:
                yield connection
        return
    with closing(sqlite3.connect(uri, uri=True, timeout=0.1)) as connection:
        yield connection


def _state_rows(path: Path, run_id: str) -> list[dict[str, Any]]:
    """Read only committed PentestGPT transitions from the live trial database."""
    database = path / "agent" / "runs" / run_id / "state.sqlite3"
    if not database.is_file() or database.is_symlink():
        return []
    try:
        with _state_connection(database, run_id, path) as connection:
            connection.row_factory = sqlite3.Row
            tasks = {row["task_id"]: dict(row) for row in connection.execute(
                "SELECT task_id, kind, target, objective, done_when FROM tasks WHERE run_id = ?", (run_id,))}
            transitions = [dict(row) for row in connection.execute(
                "SELECT revision, kind, task_id, attempt_id, detail, created_at "
                "FROM transitions WHERE run_id = ? ORDER BY revision", (run_id,))]
    except (sqlite3.Error, OSError):
        return []  # The agent may still be creating its database or committing a transition.
    projected = []
    reference = f"agent/runs/{run_id}/state.sqlite3"
    for row in transitions:
        try:
            detail = json.loads(row["detail"])
        except (TypeError, ValueError):
            detail = {"unparsed_detail": str(row["detail"])}
        if not isinstance(detail, dict):
            detail = {"value": detail}
        kind = row["kind"]
        task_id = row["task_id"]
        selected_task = tasks.get(task_id or detail.get("next_task_id"))
        projected.append({
            "source_key": f"state:{row['revision']}",
            "raw_ref": {"file": reference, "revision": row["revision"]},
            "source": "agent", "kind": "state_transition",
            "occurred_utc": datetime.fromtimestamp(row["created_at"], timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "source_sequence": row["revision"], "episode_id": None,
            "role": "supervisor" if kind == "plan_committed" else "executor" if kind.startswith("attempt_") else None,
            "call_id": None,
            "detail": _compact({"transition": kind, "revision": row["revision"],
                                "task_id": task_id, "attempt_id": row["attempt_id"],
                                "task": selected_task, **detail}),
        })
    return projected


def _outcome_detail(manifest: dict[str, Any], events: list[dict[str, Any]],
                    summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Explain the observed termination while retaining the controller's raw reason."""
    reason = manifest.get("termination_reason")
    code = manifest.get("agent_exit_code")
    gateway = [item for item in events if item.get("source") == "gateway"]
    cap = next((item.get("detail", {}) for item in reversed(gateway) if item.get("kind") == "cap_reached"), None)
    provider_limit = any(item.get("kind") in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"}
                         for item in gateway)
    cap_rejection = any(item.get("source") == "agent" and item.get("kind") in {"assistant_text", "turn_completed"}
                        and "trial_cap_reached" in json.dumps(item.get("detail", {})) for item in events)
    cause = reason or "unknown"
    label = str(reason or "Unknown termination").replace("_", " ")
    if reason == "provider_rate_limit" or provider_limit and code not in (None, 0):
        cause, label = "provider_rate_limit", "Provider rate limit"
    elif cap and (reason == "model_cap" or reason == "agent_exit" and isinstance(code, int) and code != 0 and cap_rejection):
        tokens, token_limit = cap.get("tokens"), manifest.get("max_model_tokens")
        calls, call_limit = cap.get("calls"), manifest.get("max_model_calls")
        if cap.get("usage_missing"):
            cause, label = "model_usage_missing", "Model usage missing at trial cap"
        elif isinstance(tokens, int) and isinstance(token_limit, int) and tokens >= token_limit:
            cause, label = "model_token_cap", f"Model token cap reached ({tokens:,}/{token_limit:,})"
        elif isinstance(calls, int) and isinstance(call_limit, int) and calls >= call_limit:
            cause, label = "model_call_cap", f"Model call cap reached ({calls}/{call_limit})"
        else:
            cause, label = "model_cap", "Model trial cap reached"
    elif reason == "agent_exit" and isinstance(code, int) and code != 0:
        agent_error = (summary or {}).get("error")
        if isinstance(agent_error, str) and agent_error.startswith("supervisor_contract:") and "without TurnCompleted" in agent_error:
            cause, label = "supervisor_stream_incomplete", "Supervisor stream ended without a terminal event"
        else:
            cause, label = "agent_error", f"Agent exited with code {code}"
    return {"cause": cause, "label": label, "termination_reason": reason,
            "agent_exit_code": code, "controller_error": manifest.get("error"),
            "cap": cap, "tasks": (summary or {}).get("tasks", []),
            "agent_status": (summary or {}).get("status")}


class Collector:
    def __init__(self) -> None:
        self.lock = threading.RLock()

    def collect(self, run_id: str) -> list[dict[str, Any]]:
        path = run_path(run_id)
        session_v2 = (read_json(path / "manifest.json") or {}).get("decoy_protocol") == "session-v2"
        index = monitor_index_path(run_id)
        with self.lock:
            existing = [row for _, row in _jsonl(index) if "event_id" in row]
            seen = {row.get("source_key") for row in existing}
            fresh: list[dict[str, Any]] = []

            for source in ("decoy", "gateway"):
                for filename in (f"{source}-live.jsonl", f"{source}-events.jsonl"):
                    for line, row in _jsonl(path / filename):
                        if row.get("run_id") != run_id and row.get("event_type") != "telemetry_gap":
                            continue
                        if _path_story(run_id) and row.get("event_type") == "filesystem_materialized":
                            continue  # The verified inventory has its own paginated view.
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
                    if not episode.is_dir() or episode.is_symlink():
                        continue
                    role = (read_json(episode / "input.json") or {}).get("role")
                    episode_id = _public_episode_id(episode.name) if session_v2 else episode.name
                    for line, row in _jsonl(episode / "events.jsonl"):
                        if row.get("type") == "raw_event" and row.get("kind") == "system:thinking_tokens":
                            continue  # Repeated omitted-token notices add no observable agent action.
                        sequence = row.get("sequence")
                        key = f"agent:{episode_id}:{sequence}" if isinstance(sequence, int) else f"agent:{episode_id}:{line}"
                        if key in seen:
                            continue
                        seen.add(key)
                        fresh.append({"source_key": key,
                                      "raw_ref": {"file": f"agent/runs/{run_id}/traces/{episode_id}/events.jsonl", "line": line},
                                      **_project("agent", row, episode_id=episode_id, role=role)})

            for item in _state_rows(path, run_id):
                if item["source_key"] in seen:
                    continue
                seen.add(item["source_key"])
                fresh.append(item)

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

            manifest = _controller_manifest(path)
            finished = manifest.get("finished_utc")
            if isinstance(finished, str) and "controller:outcome" not in seen:
                summary = read_json(path / "agent" / "runs" / run_id / "summary.json")
                fresh.append({"source_key": "controller:outcome", "raw_ref": {"file": _manifest_name(path)},
                              "source": "controller", "kind": "run_outcome",
                              "occurred_utc": finished, "source_sequence": None,
                              "episode_id": None, "role": None, "call_id": None,
                              "detail": _compact(_outcome_detail(manifest, existing + fresh, summary))})
                seen.add("controller:outcome")

            if fresh:
                fresh.sort(key=lambda item: (item["occurred_utc"], item["source_key"]))
                index.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if index.parent.is_symlink():
                    raise RuntimeError("Dashboard monitor cache is a symlink")
                descriptor = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    for item in fresh:
                        if session_v2:
                            item = _redact_session(item)
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


def raw_event_record(run_id: str, event_id: int) -> dict[str, Any]:
    """Fetch one authoritative source record without exposing arbitrary run files."""
    if event_id < 1:
        raise FileNotFoundError(event_id)
    path = run_path(run_id)
    session_v2 = (read_json(path / "manifest.json") or {}).get("decoy_protocol") == "session-v2"
    manifest_name = _manifest_name(path)

    def visible(record: dict[str, Any]) -> dict[str, Any]:
        return _redact_session(record) if session_v2 else record

    event = next((item for item in collector.collect(run_id) if item["event_id"] == event_id), None)
    reference = event.get("raw_ref") if event else None
    if not isinstance(reference, dict) or not isinstance(reference.get("file"), str):
        raise FileNotFoundError(event_id)
    relative = reference["file"]
    trace_pattern = rf"agent/runs/{re.escape(run_id)}/traces/[A-Za-z0-9._-]+/events\.jsonl"
    state_name = f"agent/runs/{run_id}/state.sqlite3"
    summary_name = f"agent/runs/{run_id}/summary.json"
    line_files = {"decoy-live.jsonl", "decoy-events.jsonl", "gateway-live.jsonl",
                  "gateway-events.jsonl", "agent-live.log", "agent-stdout.log"}
    if Path(relative).is_absolute() or ".." in Path(relative).parts or not (
        relative in line_files | {manifest_name, state_name, summary_name}
        or re.fullmatch(trace_pattern, relative)
    ):
        raise FileNotFoundError(event_id)
    if relative == "attempt-manifest.json" and event.get("kind") != "run_outcome":
        raise FileNotFoundError(event_id)
    source = path / relative
    if session_v2 and re.fullmatch(trace_pattern, relative):
        public_episode = Path(relative).parent.name
        if _PUBLIC_EPISODE_RE.fullmatch(public_episode):
            trace_root = path / "agent" / "runs" / run_id / "traces"
            matches = [candidate / "events.jsonl" for candidate in trace_root.iterdir()
                       if candidate.is_dir() and not candidate.is_symlink()
                       and _public_episode_id(candidate.name) == public_episode] if trace_root.is_dir() else []
            if len(matches) != 1:
                raise FileNotFoundError(event_id)
            source = matches[0]
    if not source.is_file() or not source.resolve().is_relative_to(path.resolve()) or any(
        parent.is_symlink() for parent in (source, *source.parents) if parent != path and parent.is_relative_to(path)
    ):
        raise FileNotFoundError(event_id)
    if relative == state_name:
        revision = reference.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise FileNotFoundError(event_id)
        try:
            with _state_connection(source, run_id, path) as connection:
                connection.row_factory = sqlite3.Row
                record = connection.execute(
                    "SELECT revision, kind, task_id, attempt_id, detail, created_at "
                    "FROM transitions WHERE run_id = ? AND revision = ?", (run_id, revision)).fetchone()
        except (sqlite3.Error, OSError) as exc:
            raise FileNotFoundError(event_id) from exc
        if record is None:
            raise FileNotFoundError(event_id)
        result = dict(record)
        try:
            result["detail"] = json.loads(result["detail"])
        except (TypeError, ValueError):
            pass
        return visible({"raw_ref": reference, "record": result})
    if relative in {manifest_name, summary_name}:
        record = read_json(source)
        if record is None:
            raise FileNotFoundError(event_id)
        if relative == manifest_name and event.get("kind") == "run_outcome":
            summary_path = path / summary_name
            if summary_path.is_file() and summary_path.resolve().is_relative_to(path.resolve()) and not any(
                parent.is_symlink() for parent in (summary_path, *summary_path.parents)
                if parent != path and parent.is_relative_to(path)
            ):
                record = {"manifest": record, "agent_summary": read_json(summary_path)}
        return visible({"raw_ref": reference, "record": record})
    line_number = reference.get("line")
    if not isinstance(line_number, int) or isinstance(line_number, bool) or line_number < 1:
        raise FileNotFoundError(event_id)
    try:
        with source.open(encoding="utf-8", errors="replace") as stream:
            line = next((text for index, text in enumerate(stream, 1) if index == line_number), None)
    except OSError as exc:
        raise FileNotFoundError(event_id) from exc
    if line is None:
        raise FileNotFoundError(event_id)
    try:
        record = json.loads(line) if source.suffix == ".jsonl" else line.rstrip("\n")
    except ValueError:
        record = line.rstrip("\n")
    return visible({"raw_ref": reference, "record": record})


def run_snapshot(run_id: str) -> dict[str, Any]:
    path = run_path(run_id)
    events = collector.collect(run_id)
    if _path_story(run_id):
        manifest = _controller_manifest(path)
        decoy = read_json(path / "manifest.json") or {}
        admission = _pending_path_story().get(run_id, {})
        progress = _path_story_progress(path, manifest, admission)
        result = read_json(path / "result.json") or {}
        error = _path_story_error(manifest)
        archive_complete = _path_story_archive_complete(path, manifest, result)
        if not error and manifest and result and not archive_complete:
            error = "Archived evidence is incomplete or differs from its signed manifest"
        classification = _path_story_classification(manifest, result, admission, archive_complete)
        status = _path_story_status(manifest, result, admission, progress, archive_complete)
        credits = manifest.get("provider_credits") if isinstance(manifest.get("provider_credits"), dict) else {}
        settlement = manifest.get("provider_settlement") if isinstance(manifest.get("provider_settlement"), dict) else {}
        caps = manifest.get("trial_caps") if isinstance(manifest.get("trial_caps"), dict) else admission.get("trial_caps", {})
        outcome = next((item["detail"] for item in events if item["kind"] == "run_outcome"), None)
        return {
            "run_id": run_id, "experiment": "2B", "mode": manifest.get("mode") or "path_story_pilot",
            "arm": manifest.get("arm") or admission.get("arm") or decoy.get("arm"),
            "provider": manifest.get("provider") or admission.get("provider"),
            "decoy_protocol": manifest.get("environment_protocol") or "filesystem-path-story-v1",
            "status": status, "started_utc": manifest.get("started_utc") or admission.get("started_utc"),
            "agent_started_utc": next((item["occurred_utc"] for item in events if item["kind"] == "agent_started"), None),
            "finished_utc": manifest.get("finished_utc"),
            "termination_reason": manifest.get("termination_reason") or (progress or {}).get("selected_reason"),
            "error": error, "diagnosed_cause": outcome.get("cause") if outcome else None,
            "max_wall_seconds": caps.get("maximum_total_wall_seconds"),
            "experimental_result": bool(manifest.get("experimental_result", False)),
            "event_count": len(events), "score": result.get("score"), "job": {},
            "pilot_id": manifest.get("pilot_id") or admission.get("pilot_id"),
            "pilot_protocol": manifest.get("pilot_protocol") or admission.get("pilot_protocol"),
            "slot": manifest.get("slot") or admission.get("slot"),
            "block": manifest.get("block") or admission.get("block"),
            "attempt_classification": classification,
            "provider_credits_estimated": credits.get("estimated_total_credits"),
            "provider_settlement_state": settlement.get("state"),
            "progress": progress,
        }
    manifest = read_json(path / "manifest.json") or {}
    job = job_status(run_id) or {}
    error = archive_error(manifest) or job.get("error")
    outcome = next((item["detail"] for item in events if item["kind"] == "run_outcome"), None)
    agent_summary = read_json(path / "agent" / "runs" / run_id / "summary.json") or {}
    agent_error = agent_summary.get("error")
    stream_incomplete = (isinstance(agent_error, str) and
                         agent_error.startswith("supervisor_contract:") and
                         "without TurnCompleted" in agent_error)
    if stream_incomplete and isinstance(error, str) and error.startswith("Attacker agent exited with code "):
        error = agent_error[:500]
    if isinstance(error, str) and error.startswith("Attacker agent exited with code ") and outcome and outcome.get("cause") not in {"agent_error", "agent_exit"}:
        error = outcome.get("label") or error
    agent_started = next((item["occurred_utc"] for item in events if item["kind"] == "agent_started"), None)
    return {
        "run_id": run_id, "experiment": "2A" if run_id.startswith("2a-") else "2B",
        "mode": manifest.get("mode") or job.get("mode"),
        "arm": manifest.get("arm") or job.get("arm"),
        "provider": archived_provider(manifest, job),
        "decoy_protocol": manifest.get("decoy_protocol") or job.get("decoy_protocol") or ("text-only" if run_id.startswith("2a-") else None),
        "status": "failed" if error else job.get("status") or ("complete" if (path / "result.json").exists() else "archived"),
        "started_utc": manifest.get("started_utc") or job.get("created_utc"),
        "agent_started_utc": agent_started,
        "finished_utc": manifest.get("finished_utc"),
        "termination_reason": manifest.get("termination_reason"),
        "error": _redact_session(error) if manifest.get("decoy_protocol") == "session-v2" else error,
        "diagnosed_cause": "supervisor_stream_incomplete" if stream_incomplete else outcome.get("cause") if outcome else None,
        "max_wall_seconds": manifest.get("max_wall_seconds") or job.get("max_wall_seconds"),
        "experimental_result": bool(manifest.get("experimental_result", False)),
        "event_count": len(events),
        "score": (read_json(path / "result.json") or {}).get("score"),
        "job": job,
    }


def materialization_page(run_id: str, *, after: int = 0, limit: int = 100) -> dict[str, Any]:
    """Page hash-checked generated paths without flooding the live event feed."""
    if after < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid materialization range")
    if not _path_story(run_id):
        raise FileNotFoundError(run_id)
    try:
        path = run_path(run_id)
    except FileNotFoundError:
        if run_id in _pending_path_story():
            return {"items": [], "total": 0, "has_more": False, "next_after": after,
                    "verified": False, "available": False}
        raise
    manifest = _controller_manifest(path)
    if not manifest:
        return {"items": [], "total": 0, "has_more": False, "next_after": after,
                "verified": False, "available": False}
    inventory_path = path / "materialization-inventory.json"
    artifacts = manifest.get("artifact_sha256") if isinstance(manifest.get("artifact_sha256"), dict) else {}
    expected = artifacts.get(inventory_path.name)
    if (not inventory_path.is_file() or inventory_path.is_symlink() or not isinstance(expected, str)
            or hashlib.sha256(inventory_path.read_bytes()).hexdigest() != expected):
        raise ValueError("Materialization archive hash differs")
    inventory = read_json(inventory_path) or {}
    items = inventory.get("items")
    replay = manifest.get("replay") if isinstance(manifest.get("replay"), dict) else {}
    if (not isinstance(items, list) or replay.get("materialized_nodes") != len(items)
            or any(not isinstance(item, dict) or not isinstance(item.get("path"), str)
                   or not isinstance(item.get("inventory_index"), int) for item in items)):
        raise ValueError("Materialization inventory differs from replay")
    selected = items[after:after + limit]
    next_after = after + len(selected)
    return {"items": selected, "total": len(items), "has_more": next_after < len(items),
            "next_after": next_after, "verified": True, "available": True}


def provisional_snapshot(run_id: str) -> dict[str, Any] | None:
    job = job_status(run_id)
    if job is None:
        admission = _pending_path_story().get(run_id) if _path_story(run_id) else None
        if admission is None:
            return None
        caps = admission.get("trial_caps", {})
        return {
            "run_id": run_id, "experiment": "2B", "mode": "path_story_pilot",
            "arm": admission.get("arm"), "provider": admission.get("provider"),
            "decoy_protocol": "filesystem-path-story-v1", "status": "queued",
            "started_utc": admission.get("started_utc"), "agent_started_utc": None,
            "finished_utc": None, "termination_reason": None, "error": None,
            "max_wall_seconds": caps.get("maximum_total_wall_seconds"),
            "experimental_result": False, "event_count": 0, "score": None, "job": {},
            "pilot_id": admission.get("pilot_id"), "pilot_protocol": admission.get("pilot_protocol"),
            "slot": admission.get("slot"), "block": admission.get("block"),
            "attempt_classification": None, "provider_credits_estimated": None,
            "provider_settlement_state": None, "progress": None,
        }
    return {
        "run_id": run_id, "experiment": job.get("experiment"),
        "mode": job.get("mode"), "arm": job.get("arm"), "provider": job.get("provider"),
        "decoy_protocol": job.get("decoy_protocol"),
        "status": job.get("status"), "started_utc": job.get("created_utc"),
        "agent_started_utc": None, "finished_utc": job.get("finished_utc"),
        "termination_reason": job.get("termination_reason"),
        "error": job.get("error"), "max_wall_seconds": job.get("max_wall_seconds"),
        "experimental_result": False,
        "event_count": 0, "score": None, "job": job,
    }
