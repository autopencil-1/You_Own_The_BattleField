"""Run a deterministic decoy check or a bounded PentestGPT connectivity trial."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid
from typing import Any

from telemetry.score_2a import load_events, score_events


LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parent
COMPOSE = LAB / "compose.yaml"
CONFIG = LAB / "config" / "exp_2a_pilot.json"
EXPECTED_PENTESTGPT_COMMIT = "e8b1bb77d1ac00329675cec3b060aba971ec1ac8"
EXPECTED_UNIFIED_COMMIT = "acff8eeadf93e367d4a1578d3a2739cbc9d3ace5"
EXPECTED_CLAUDE_CLI_VERSION = "2.1.206"
CLAUDE_CLI = "/opt/pentestgpt_agent/.venv/lib/python3.12/site-packages/claude_agent_sdk/_bundled/claude"


def command(args: list[str], *, env: dict[str, str] | None = None, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=REPO, env=env, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(args)}\n{result.stderr[-2000:]}")
    return result


def compose(project: str, args: list[str], env: dict[str, str], *, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    return command(["docker", "compose", "--profile", "agent", "-p", project, "-f", str(COMPOSE), *args], env=env, timeout=timeout, check=check)


def write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def read_key() -> str:
    for line in (REPO / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("export "):
            line = line[7:]
        name, separator, value = line.partition("=")
        if separator and name.strip() == "ZAI_API_KEY":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            if value:
                return value
    raise ValueError("ZAI_API_KEY is absent from the repository .env")


def validate_sources() -> tuple[str, str]:
    commit = command(["git", "-C", str(REPO / "PentestGPT"), "rev-parse", "HEAD"]).stdout.strip()
    if commit != EXPECTED_PENTESTGPT_COMMIT:
        raise ValueError("PentestGPT checkout differs from the frozen commit")
    project = (REPO / "PentestGPT" / "pentestgpt_agent" / "pyproject.toml").read_text(encoding="utf-8")
    lock = (REPO / "PentestGPT" / "pentestgpt_agent" / "uv.lock").read_text(encoding="utf-8")
    if EXPECTED_UNIFIED_COMMIT not in project or EXPECTED_UNIFIED_COMMIT not in lock:
        raise ValueError("UnifiedAgent dependency differs from the frozen commit")
    return commit, EXPECTED_UNIFIED_COMMIT


def count_tool_calls(agent_dir: Path, run_id: str) -> int:
    count = 0
    for path in (agent_dir / "runs" / run_id / "traces").glob("*/events.jsonl"):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # A writer may be completing its final line.
            if event.get("type") == "tool_call":
                count += 1
    return count


def service_events(project: str, service: str, env: dict[str, str]) -> str:
    return compose(project, ["logs", "--no-color", "--no-log-prefix", service], env, timeout=30, check=False).stdout


def container_state(project: str, service: str, env: dict[str, str]) -> dict[str, Any] | None:
    identifier = compose(project, ["ps", "-a", "-q", service], env, timeout=30, check=False).stdout.strip()
    if not identifier:
        return None
    output = command(["docker", "inspect", identifier, "--format", "{{json .State}}"], timeout=30, check=False)
    return json.loads(output.stdout) if output.returncode == 0 else None


def parsed_jsonl(text: str) -> list[dict[str, Any]]:
    events = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def image_id(name: str) -> str | None:
    result = command(["docker", "image", "inspect", name, "--format", "{{.Id}}"], check=False, timeout=30)
    return result.stdout.strip() or None


def pinned_cli_version() -> str:
    output = command([
        "docker", "run", "--rm", "--entrypoint", CLAUDE_CLI,
        "shape-pentestgpt-agent:dev", "--version",
    ], timeout=30).stdout.strip()
    version = output.split(" ", 1)[0]
    if version != EXPECTED_CLAUDE_CLI_VERSION:
        raise ValueError(f"Claude Code CLI version differs from the frozen version: {version}")
    return version


def run(mode: str, arm: str, *, build: bool = True) -> dict[str, Any]:
    if mode not in {"deterministic", "connectivity", "pilot"}:
        raise ValueError("Invalid mode")
    if mode in {"deterministic", "pilot"} and arm != "C2":
        raise ValueError(f"The {mode} mode exercises C2 only")
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    pentest_commit, unified_commit = validate_sources()
    run_id = "2a-" + mode[:4] + "-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
    if not re.fullmatch(r"[a-z0-9-]{1,63}", run_id):
        raise ValueError("Invalid run ID")
    project = "shape" + run_id
    run_dir = LAB / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    agent_dir = run_dir / "agent"
    agent_dir.mkdir(mode=0o700)
    caps = config["caps_per_trial"]
    smoke = mode == "connectivity"
    max_wall = 240 if smoke else caps["wall_seconds"]
    max_tools = 20 if smoke else caps["max_agent_tool_calls"]
    max_model_calls = 8 if smoke else caps["max_model_calls"]
    max_model_tokens = 100000 if smoke else caps["max_model_tokens_input_plus_output"]
    env = dict(os.environ)
    env.update({
        "SHAPE_RUN_ID": run_id,
        "SHAPE_ARM": arm,
        "SHAPE_SMOKE": "1" if smoke else "0",
        "SHAPE_RUN_DIR": str(run_dir.resolve()),
        "LAB_UID": str(os.getuid()),
        "LAB_GID": str(os.getgid()),
        "SHAPE_MAX_MODEL_CALLS": str(max_model_calls),
        "SHAPE_MAX_MODEL_TOKENS": str(max_model_tokens),
    })
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "mode": mode,
        "arm": arm,
        "project": project,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "config_sha256": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
        "pentestgpt_commit": pentest_commit,
        "unified_agent_commit": unified_commit,
        "model": config["agent"]["model"],
        "target": config["task"]["target"],
        "max_wall_seconds": max_wall,
        "max_agent_tool_calls": max_tools,
        "max_model_calls": max_model_calls,
        "max_model_tokens": max_model_tokens,
    }
    reason = "not_started"
    error: str | None = None
    agent_exit_code: int | None = None
    started = 0.0
    with tempfile.TemporaryDirectory(prefix="shape2a-key-") as secret_dir:
        key_file = Path(secret_dir) / "zai_api_key"
        if mode != "deterministic":
            write_private(key_file, read_key() + "\n")
            env["SHAPE_KEY_FILE"] = str(key_file)
        try:
            if build:
                services = ["web-decoy-2a"] if mode == "deterministic" else ["web-decoy-2a", "model-gateway", "attacker-agent"]
                result = compose(project, ["build", *services], env)
                write_private(run_dir / "build.log", result.stdout + result.stderr)
            manifest["images"] = {name: image_id(image) for name, image in {
                "decoy": "shape-web-decoy-2a:dev",
                "gateway": "shape-model-gateway:dev",
                "agent": "shape-pentestgpt-agent:dev",
            }.items()}
            if mode != "deterministic":
                manifest["claude_code_cli_version"] = pinned_cli_version()
            resolved_compose = compose(project, ["config"], env, timeout=30).stdout
            write_private(run_dir / "compose.resolved.yaml", resolved_compose)
            manifest["resolved_compose_sha256"] = hashlib.sha256(resolved_compose.encode()).hexdigest()
            write_private(run_dir / "trial-config.json", CONFIG.read_text(encoding="utf-8"))
            write_private(run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            if mode == "deterministic":
                compose(project, ["up", "-d", "--wait", "--wait-timeout", "30", "--no-build", "web-decoy-2a"], env, timeout=60)
                network = project + "_trial_net"
                client = command([
                    "docker", "run", "--rm", "--network", network,
                    "--mount", f"type=bind,src={LAB / 'tests'},dst=/smoke,readonly",
                    "--entrypoint", "python", "shape-web-decoy-2a:dev", "/smoke/docker_smoke_2a.py",
                ], timeout=60)
                write_private(run_dir / "client.log", client.stdout + client.stderr)
                reason = "deterministic_complete"
            else:
                compose(project, ["up", "-d", "--wait", "--wait-timeout", "30", "--no-build", "web-decoy-2a", "model-gateway"], env, timeout=60)
                started = time.monotonic()
                compose(project, ["up", "-d", "--no-build", "attacker-agent"], env, timeout=90)
                reason = "agent_exit"
                while True:
                    wall = time.monotonic() - started
                    tools = count_tool_calls(agent_dir, run_id)
                    state = container_state(project, "attacker-agent", env)
                    if state and not state.get("Running"):
                        agent_exit_code = state.get("ExitCode")
                        break
                    if tools >= max_tools:
                        reason = "tool_cap"
                        break
                    if wall >= max_wall:
                        reason = "wall_cap"
                        break
                    gateway_events = parsed_jsonl(service_events(project, "model-gateway", env))
                    if any(event.get("event_type") == "cap_reached" for event in gateway_events):
                        reason = "model_cap"
                        break
                    if smoke:
                        model_ok = any(event.get("event_type") == "model_call" and event.get("status") == 200 for event in gateway_events)
                        decoy_events = parsed_jsonl(service_events(project, "web-decoy-2a", env))
                        target_seen = any(event.get("event_type") == "decoy_request" for event in decoy_events)
                        if model_ok and target_seen:
                            reason = "connectivity_observed"
                            break
                    time.sleep(2)
                if reason != "agent_exit":
                    compose(project, ["stop", "-t", "5", "attacker-agent"], env, timeout=30, check=False)
                state = container_state(project, "attacker-agent", env)
                agent_exit_code = state.get("ExitCode") if state else None
        except Exception as exc:
            reason = "controller_error"
            error = f"{type(exc).__name__}: {exc}"
        finally:
            for service, filename in [
                ("web-decoy-2a", "decoy-events.jsonl"),
                ("model-gateway", "gateway-events.jsonl"),
                ("attacker-agent", "agent-stdout.log"),
            ]:
                try:
                    write_private(run_dir / filename, service_events(project, service, env))
                except Exception:
                    pass
            compose(project, ["down", "--remove-orphans"], env, timeout=90, check=False)
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["termination_reason"] = reason
    manifest["agent_exit_code"] = agent_exit_code
    manifest["error"] = error
    manifest["observed_agent_tool_calls"] = count_tool_calls(agent_dir, run_id)
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        score = score_events(load_events(run_dir / "decoy-events.jsonl"), run_id, arm)
    except Exception as exc:
        score = {"scoring_error": f"{type(exc).__name__}: {exc}"}
    if mode == "connectivity" and reason != "connectivity_observed" and error is None:
        error = "connectivity_not_observed"
        manifest["error"] = error
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {"manifest": manifest, "score": score, "run_dir": str(run_dir)}
    write_private(run_dir / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["deterministic", "connectivity", "pilot"], required=True)
    parser.add_argument("--arm", choices=["C0", "C1", "C2"], default="C2")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    result = run(args.mode, args.arm, build=not args.no_build)
    print(json.dumps({
        "run_dir": result["run_dir"],
        "termination_reason": result["manifest"]["termination_reason"],
        "error": result["manifest"]["error"],
        "score": result["score"],
    }, indent=2, sort_keys=True))
    if result["manifest"]["error"] or "scoring_error" in result["score"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
