"""Run the model-free path-story Docker B0–B3 integration matrix.

Only the filesystem decoy is started through Compose. A disposable attacker
image process calls its registered SSH tools directly; neither PentestGPT nor
the model gateway is started. The exact decoy journal is archived and replayed.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import posixpath
import secrets
import subprocess
import time
from typing import Any

from experiment_controller.path_story_evidence_2b import archive_path_story_run
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from telemetry.replay_2b_path_story import (
    verify_path_story_bundle,
    verify_path_story_pair,
)


LAB = Path(__file__).resolve().parents[1]
CONFIG = LAB / "config" / "exp_2b_path_story_matrix_v1.json"
FIXTURE = LAB / "config" / "exp_2b_path_story_v1.json"
TASK = LAB / "config" / "agent_2b_task.json"
PROBE = LAB / "tests" / "path_story_matrix_probe_2b.py"
COMPOSE = (LAB / "compose_2b.yaml", LAB / "compose_2b_path_story.yaml")
DECOY_IMAGE = "shape-filesystem-decoy-2b:path-story-v1"
ATTACKER_IMAGE = "shape-2b-attacker:path-story-v1"
TARGET = "ssh://lab@filesystem-decoy-2b"
ARMS = ("B0", "B1", "B2", "B3")
MAX_COMMANDS = 50
MATRIX_VERSION = "path-story-docker-matrix-v1"


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_matrix_config(path: Path = CONFIG) -> dict[str, Any]:
    """Validate the frozen, identical command assignment for all four arms."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Matrix config must be a JSON object")
    if raw.get("schema_version") != 1 or raw.get("matrix_protocol") != "2b-path-story-model-free-matrix-v1":
        raise ValueError("Unsupported frozen matrix protocol")
    if raw.get("arms") != list(ARMS):
        raise ValueError("Matrix must assign B0, B1, B2, B3 exactly once")
    if raw.get("fixture_path") != "config/exp_2b_path_story_v1.json":
        raise ValueError("Matrix fixture path differs")
    if raw.get("task_path") != "config/agent_2b_task.json":
        raise ValueError("Matrix task path differs")
    if raw.get("fixture_sha256") != _sha(FIXTURE.read_bytes()):
        raise ValueError("Frozen fixture hash differs")
    if raw.get("task_sha256") != _sha(TASK.read_bytes()):
        raise ValueError("Frozen PentestGPT task hash differs")
    commands = raw.get("command_plan")
    prefix_length = raw.get("common_prefix_length")
    seed = raw.get("seed")
    if raw.get("target") != TARGET:
        raise ValueError("Matrix target differs from the authorized lab target")
    if type(raw.get("max_commands")) is not int or raw["max_commands"] != MAX_COMMANDS:
        raise ValueError("Matrix command cap must be exactly 50")
    if (
        not isinstance(seed, str)
        or not seed
        or len(seed) > 128
        or "\n" in seed
        or "\r" in seed
    ):
        raise ValueError("Matrix seed must be a nonempty single line")
    if (
        not isinstance(commands, list)
        or len(commands) != MAX_COMMANDS
        or any(
            not isinstance(command, str)
            or not command.strip()
            or len(command) > 512
            or "\x00" in command
            for command in commands
        )
    ):
        raise ValueError("Matrix command plan must contain 50 bounded commands")
    if type(prefix_length) is not int or prefix_length != 5:
        raise ValueError("Matrix common-prefix length is invalid")
    _, filesystem = load_path_story_fixture(FIXTURE, seed, dynamic=True)
    if raw.get("expected_catalog_fingerprint") != filesystem.catalog.fingerprint:
        raise ValueError("Frozen catalog fingerprint differs")
    frontier = raw.get("expected_frontier_path")
    if (
        raw.get("expected_frontier_action") != MAX_COMMANDS
        or not isinstance(frontier, str)
        or not frontier.startswith("/")
        or posixpath.normpath(frontier) != frontier
        or commands[-1] != f"ls {frontier}"
    ):
        raise ValueError("Frozen action-50 frontier assignment differs")
    return raw


def _command(
    args: list[str], *, env: dict[str, str] | None = None, timeout: int = 600,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        args, cwd=LAB, env=env, capture_output=True, timeout=timeout
    )
    if check and result.returncode:
        detail = result.stderr[-2000:].decode("utf-8", "replace")
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(args)}\n{detail}"
        )
    return result


def _compose(
    project: str, args: list[str], env: dict[str, str], *,
    timeout: int = 600, check: bool = True, profile_agent: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    prefix = ["docker", "compose", "-p", project]
    if profile_agent:
        prefix.extend(("--profile", "agent"))
    for file in COMPOSE:
        prefix.extend(("-f", str(file)))
    return _command(prefix + args, env=env, timeout=timeout, check=check)


def _single_line(result: subprocess.CompletedProcess[bytes], label: str) -> str:
    value = result.stdout.decode("utf-8", "strict").strip()
    if not value or "\n" in value:
        raise RuntimeError(f"{label} is missing or ambiguous")
    return value


def _wait_healthy(container_id: str, *, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = _single_line(
            _command(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_id],
                timeout=15,
            ),
            "decoy health",
        )
        if state == "healthy":
            return
        if state == "unhealthy":
            raise RuntimeError("Path-story decoy became unhealthy")
        time.sleep(1)
    raise RuntimeError("Path-story decoy health timed out")


def _preflight(project: str, env: dict[str, str], decoy_image_id: str) -> dict[str, Any]:
    container_id = _single_line(
        _compose(project, ["ps", "-q", "filesystem-decoy-2b"], env, timeout=30),
        "decoy container ID",
    )
    _wait_healthy(container_id)
    network = project + "_trial_net"
    internal = _single_line(
        _command(
            ["docker", "network", "inspect", network, "--format", "{{json .Internal}}"],
            timeout=30,
        ),
        "trial-network internal flag",
    )
    if internal != "true":
        raise RuntimeError("Trial network is not internal")
    container = json.loads(
        _single_line(
            _command(
                [
                    "docker", "inspect", container_id, "--format",
                    "{{json .NetworkSettings.Networks}}",
                ],
                timeout=30,
            ),
            "decoy networks",
        )
    )
    if sorted(container) != [network]:
        raise RuntimeError("Decoy joined an unexpected network")
    ports = json.loads(
        _single_line(
            _command(
                [
                    "docker", "inspect", container_id, "--format",
                    "{{json .NetworkSettings.Ports}}",
                ],
                timeout=30,
            ),
            "decoy ports",
        )
    )
    if any(value is not None for value in ports.values()):
        raise RuntimeError("Decoy published a host port")
    image = _single_line(
        _command(
            ["docker", "inspect", container_id, "--format", "{{.Config.Image}}"],
            timeout=30,
        ),
        "decoy image",
    )
    if image != DECOY_IMAGE:
        raise RuntimeError("Unexpected decoy image")
    actual_image_id = _single_line(
        _command(
            ["docker", "inspect", container_id, "--format", "{{.Image}}"], timeout=30
        ),
        "decoy image ID",
    )
    if actual_image_id != decoy_image_id:
        raise RuntimeError("Decoy container does not use the freshly built image")
    members = _command(
        [
            "docker", "ps", "-aq", "--no-trunc", "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        timeout=30,
    ).stdout.decode("utf-8", "strict").splitlines()
    if members != [container_id]:
        raise RuntimeError("A gateway, agent, or other project container was started")
    return {
        "container_id": container_id,
        "network": network,
        "internal_network": True,
        "no_host_ports": True,
        "only_decoy_service_started": True,
    }


def _response_pairs(events: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    request: dict[str, Any] | None = None
    for event in events:
        kind = event.get("event_type")
        if kind == "decoy_request":
            if request is not None:
                raise ValueError("A decoy request lacks a response")
            request = event
        elif kind == "response_write_failed":
            raise ValueError("Matrix contains a failed response write")
        elif kind == "decoy_response":
            if request is None:
                raise ValueError("Decoy response lacks a request")
            pairs.append((request, event))
            request = None
    if request is not None:
        raise ValueError("Matrix ends with an unanswered request")
    return pairs


def _prompt(body: dict[str, Any], cwd_key: str) -> str:
    identity = body["identity"]
    return f"{identity['username']}@{identity['hostname']}:{body[cwd_key]}$ "


def validate_tool_observation(
    event_bytes: bytes, report: dict[str, Any], config: dict[str, Any],
    *, arm: str, run_id: str,
) -> dict[str, Any]:
    """Link every attacker-image tool string to the delivered decoy bytes."""
    events = [json.loads(line) for line in event_bytes.splitlines()]
    if not events or events[0].get("event_type") != "path_story_profile_loaded":
        raise ValueError("Matrix journal lacks path-story profile evidence")
    pairs = _response_pairs(events)
    if len(pairs) != MAX_COMMANDS + 1:
        raise ValueError("Matrix did not deliver one connect and 50 shell actions")
    if (
        report.get("run_id") != run_id
        or report.get("arm") != arm
        or report.get("target") != TARGET
        or report.get("registry_spec") != "ssh_tools_2b_path_story:REGISTRY"
        or report.get("status") != "complete"
        or report.get("completed_actions") != MAX_COMMANDS
    ):
        raise ValueError("Tool report identity or adapter differs")
    executions = report.get("actions")
    if not isinstance(executions, list) or len(executions) != MAX_COMMANDS:
        raise ValueError("Tool report lacks 50 executions")
    commands = config["command_plan"]
    if len(commands) != MAX_COMMANDS:
        raise ValueError("Matrix command plan changed")
    for index, (request, response) in enumerate(pairs):
        if response.get("status") != 200:
            raise ValueError(f"Matrix response {index} was not delivered successfully")
        request_body = json.loads(base64.b64decode(request["request_body_b64"], validate=True))
        body = json.loads(base64.b64decode(response["body_b64"], validate=True))
        if index == 0:
            if request.get("route") != "/connect" or request_body != {"target": TARGET}:
                raise ValueError("Matrix connection request differs")
            expected = body["output"] + _prompt(body, "cwd")
            connection = report.get("connection")
            if (
                not isinstance(connection, dict)
                or connection.get("tool") != "ssh_connect"
                or connection.get("arguments") != {"target": TARGET}
                or connection.get("response") != expected
                or not body.get("new_connection")
            ):
                raise ValueError("Attacker-image connection output differs")
        else:
            command = commands[index - 1]
            if request.get("route") != "/exec" or request_body != {"command": command}:
                raise ValueError(f"Matrix command {index} differs")
            expected = body["output"]
            if body["exit_code"]:
                expected += f"[exit code {body['exit_code']}]\n"
            expected += _prompt(body, "cwd_after")
            action = executions[index - 1]
            if (
                not isinstance(action, dict)
                or action.get("sequence") != index
                or action.get("tool") != "ssh_exec"
                or action.get("arguments") != {"command": command}
                or action.get("response") != expected
            ):
                raise ValueError(f"Attacker-image tool output differs at action {index}")
            if index == MAX_COMMANDS:
                if body.get("target") != config["expected_frontier_path"]:
                    raise ValueError("Action 50 did not reach the frozen frontier path")
                if arm in {"B1", "B3"} and body["exit_code"] != 0:
                    raise ValueError("Dynamic frontier failed at action 50")
                if arm in {"B0", "B2"} and body["exit_code"] == 0:
                    raise ValueError("Static frontier unexpectedly existed")
    materializations = [
        event for event in events if event.get("event_type") == "filesystem_materialized"
    ]
    last_response_sequence = pairs[-1][1]["sequence"]
    horizon_nodes = sum(
        event.get("response_sequence") == last_response_sequence
        for event in materializations
    )
    reinforcements = [
        event for event in events if event.get("event_type") == "reinforcement_delivered"
    ]
    reinforcement_count = len(reinforcements)
    if arm in {"B0", "B2"} and materializations:
        raise ValueError("Static arm materialized generated nodes")
    if arm in {"B1", "B3"} and horizon_nodes == 0:
        raise ValueError("Dynamic arm did not reveal fresh structure at action 50")
    if arm in {"B0", "B1"} and reinforcement_count:
        raise ValueError("Control-text arm delivered reinforcement")
    if arm in {"B2", "B3"} and reinforcement_count == 0:
        raise ValueError("Reinforcement arm did not deliver reinforcement")
    if arm in {"B2", "B3"} and reinforcements[0].get("command_count") != 6:
        raise ValueError("First reinforcement was not delivered at action 6")
    if sum(event.get("event_type") == "filesystem_interaction" for event in events) != MAX_COMMANDS:
        raise ValueError("Matrix does not have exactly 50 filesystem interactions")
    return {
        "actions": MAX_COMMANDS,
        "response_count": len(pairs),
        "materialized_nodes": len(materializations),
        "new_nodes_at_action_50": horizon_nodes,
        "reinforcement_events": reinforcement_count,
    }


def _capture_events(project: str, env: dict[str, str], run_dir: Path) -> bytes:
    logs = _compose(
        project,
        ["logs", "--no-color", "--no-log-prefix", "filesystem-decoy-2b"],
        env,
        timeout=30,
    )
    if logs.stderr:
        _write_private(run_dir / "docker-logs-stderr.txt", logs.stderr)
        raise RuntimeError("Docker logs emitted stderr; journal completeness is uncertain")
    if not logs.stdout or not logs.stdout.endswith(b"\n"):
        raise RuntimeError("Decoy journal is empty or ends with an incomplete line")
    _write_private(run_dir / "decoy-events.jsonl", logs.stdout)
    return logs.stdout


def _run_arm(
    output_dir: Path, inputs_dir: Path, config: dict[str, Any], arm: str,
    project_base: str, images: dict[str, str],
) -> dict[str, Any]:
    project = f"{project_base}-{arm.lower()}"
    run_id = f"{project}-run"
    run_dir = output_dir / arm
    run_dir.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(
        {
            "SHAPE_RUN_ID": run_id,
            "SHAPE_ARM": arm,
            "SHAPE_2B_SEED": config["seed"],
            "SHAPE_2B_MAX_COMMANDS": str(MAX_COMMANDS),
            "SHAPE_2B_REINFORCEMENT_EVERY": "3",
        }
    )
    probe_name = f"{project}-probe"
    captured = False
    failure: BaseException | None = None
    cleanup_error: BaseException | None = None
    result: dict[str, Any] | None = None
    try:
        _compose(project, ["up", "-d", "--no-deps", "filesystem-decoy-2b"], env, timeout=90)
        preflight = _preflight(project, env, images[DECOY_IMAGE])
        probe = _command(
            [
                "docker", "run", "--rm", "--name", probe_name,
                "--network", preflight["network"],
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--read-only", "--cap-drop=ALL",
                "--security-opt", "no-new-privileges:true",
                "--mount", f"type=bind,src={inputs_dir},dst=/smoke,readonly",
                "--env", "SHAPE_2B_DECOY_URL=http://filesystem-decoy-2b:8082",
                "--env", f"SHAPE_2B_TARGET={TARGET}",
                "--entrypoint", "python", images[ATTACKER_IMAGE],
                "/smoke/path_story_matrix_probe_2b.py",
                "--config", "/smoke/exp_2b_path_story_matrix_v1.json",
                "--arm", arm,
                "--run-id", run_id,
            ],
            timeout=180,
            check=False,
        )
        if probe.stdout:
            _write_private(run_dir / "tool-report.json", probe.stdout)
        if probe.stderr:
            _write_private(run_dir / "tool-probe-stderr.txt", probe.stderr)
        if probe.returncode:
            raise RuntimeError(f"Attacker-image tool probe exited {probe.returncode}")
        if probe.stderr:
            raise RuntimeError("Attacker-image tool probe emitted stderr")
        if not probe.stdout.endswith(b"\n") or len(probe.stdout.splitlines()) != 1:
            raise ValueError("Tool probe did not emit one JSON report")
        tool_report = json.loads(probe.stdout)
        if tool_report.get("config_sha256") != _sha((inputs_dir / CONFIG.name).read_bytes()):
            raise ValueError("Probe read a different matrix config")
        events = _capture_events(project, env, run_dir)
        captured = True
        observation = validate_tool_observation(
            events, tool_report, config, arm=arm, run_id=run_id
        )
        manifest = archive_path_story_run(
            run_dir,
            fixture_path=FIXTURE,
            seed=config["seed"],
            arm=arm,
            run_id=run_id,
            event_path=run_dir / "decoy-events.jsonl",
            max_commands=MAX_COMMANDS,
        )
        replay = verify_path_story_bundle(run_dir)
        if replay["filesystem_actions"] != MAX_COMMANDS:
            raise ValueError("Replay did not verify exactly 50 actions")
        if replay["materialized_nodes"] != observation["materialized_nodes"]:
            raise ValueError("Replay materialization count differs from live journal")
        result = {
            "arm": arm,
            "run_id": run_id,
            "project": project,
            "run_dir": str(run_dir),
            "preflight": preflight,
            "observation": observation,
            "manifest_sha256": _sha((run_dir / "manifest.json").read_bytes()),
            "event_sha256": _sha(events),
            "tool_report_sha256": _sha(probe.stdout),
            "replay": replay,
            "archive_version": manifest["evidence_version"],
        }
    except BaseException as exc:
        failure = exc
    finally:
        if not captured:
            try:
                _capture_events(project, env, run_dir)
            except BaseException as exc:
                if failure is None:
                    failure = exc
        _command(["docker", "rm", "-f", probe_name], timeout=30, check=False)
        try:
            _compose(project, ["down", "--remove-orphans"], env, timeout=90)
        except BaseException as exc:
            cleanup_error = exc
    if failure is not None or cleanup_error is not None:
        detail = {
            "arm": arm,
            "run_id": run_id,
            "project": project,
            "error": f"{type(failure).__name__}: {failure}" if failure else None,
            "cleanup_error": f"{type(cleanup_error).__name__}: {cleanup_error}" if cleanup_error else None,
        }
        _write_private(run_dir / "failure.json", _json_bytes(detail))
        raise RuntimeError(f"Matrix {arm} failed; see {run_dir / 'failure.json'}") from (failure or cleanup_error)
    assert result is not None
    return result


def execute_matrix(output_dir: Path, config_path: Path = CONFIG) -> dict[str, Any]:
    """Build images, run each isolated arm, archive/replay, and compare pairs."""
    config_path = Path(config_path).resolve()
    config = load_matrix_config(config_path)
    output_dir = Path(output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("Matrix output directory must be empty")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.is_symlink():
        raise ValueError("Matrix output directory must not be a symlink")
    inputs_dir = output_dir / "inputs"
    inputs_dir.mkdir(mode=0o700)
    config_bytes = config_path.read_bytes()
    probe_bytes = PROBE.read_bytes()
    _write_private(inputs_dir / CONFIG.name, config_bytes)
    _write_private(inputs_dir / PROBE.name, probe_bytes)
    started = datetime.now(timezone.utc).isoformat()
    project_base = (
        "shape-path-matrix-"
        + datetime.now(timezone.utc).strftime("%y%m%d%H%M%S")
        + "-"
        + secrets.token_hex(3)
    )
    env = os.environ.copy()
    env.update(
        {
            "SHAPE_RUN_ID": project_base + "-build",
            "SHAPE_ARM": "B0",
            "SHAPE_2B_SEED": config["seed"],
            "SHAPE_2B_MAX_COMMANDS": str(MAX_COMMANDS),
        }
    )
    completed: dict[str, dict[str, Any]] = {}
    try:
        build = _compose(
            project_base + "-build",
            ["build", "filesystem-decoy-2b", "attacker-agent"],
            env,
            timeout=1200,
            profile_agent=True,
            check=False,
        )
        _write_private(output_dir / "build.log", build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(f"Path-story image build exited {build.returncode}")
        images = {
            name: _single_line(
                _command(["docker", "image", "inspect", "--format", "{{.Id}}", name], timeout=30),
                f"{name} image ID",
            )
            for name in (DECOY_IMAGE, ATTACKER_IMAGE)
        }
        for arm in ARMS:
            completed[arm] = _run_arm(output_dir, inputs_dir, config, arm, project_base, images)
        common = config["command_plan"][: config["common_prefix_length"]]
        pair_unreinforced = verify_path_story_pair(output_dir / "B0", output_dir / "B1", common)
        pair_reinforced = verify_path_story_pair(output_dir / "B2", output_dir / "B3", common)
        if pair_unreinforced["shared_prefix_sha256"] != pair_reinforced["shared_prefix_sha256"]:
            raise ValueError("The four arms differ in the frozen common response prefix")
        commitments = {
            (
                row["replay"]["seed_sha256"],
                row["replay"]["fixture_sha256"],
                row["replay"]["catalog_fingerprint"],
                row["replay"]["shared_nodes_fingerprint"],
            )
            for row in completed.values()
        }
        if len(commitments) != 1:
            raise ValueError("Matrix arms do not share seed, fixture, and story commitments")
        report = {
            "matrix_version": MATRIX_VERSION,
            "status": "passed",
            "started_utc": started,
            "completed_utc": datetime.now(timezone.utc).isoformat(),
            "config_sha256": _sha(config_bytes),
            "probe_sha256": _sha(probe_bytes),
            "orchestrator_sha256": _sha(Path(__file__).read_bytes()),
            "compose_sha256": {path.name: _sha(path.read_bytes()) for path in COMPOSE},
            "fixture_sha256": _sha(FIXTURE.read_bytes()),
            "seed_sha256": _sha(config["seed"].encode("utf-8")),
            "target": TARGET,
            "max_commands_per_arm": MAX_COMMANDS,
            "common_prefix_commands": common,
            "common_prefix_sha256": pair_unreinforced["shared_prefix_sha256"],
            "images": images,
            "arms": completed,
            "pairs": {
                "B0_B1": pair_unreinforced,
                "B2_B3": pair_reinforced,
            },
            "funding": {
                "state": "not_applicable_model_free",
                "model_gateway_started": False,
                "agent_process_started": False,
                "provider_calls_from_matrix": 0,
                "provider_authorization_consumed_usd": "0.000000000",
            },
        }
        _write_private(output_dir / "matrix-report.json", _json_bytes(report))
        return report
    except BaseException as exc:
        _write_private(
            output_dir / "matrix-failure.json",
            _json_bytes(
                {
                    "matrix_version": MATRIX_VERSION,
                    "status": "failed",
                    "started_utc": started,
                    "failed_utc": datetime.now(timezone.utc).isoformat(),
                    "completed_arms": list(completed),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            ),
        )
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()
    report = execute_matrix(args.output_dir, args.config)
    print(
        json.dumps(
            {
                "status": report["status"],
                "output_dir": str(Path(args.output_dir).resolve()),
                "report": str((Path(args.output_dir).resolve() / "matrix-report.json")),
                "arms": list(report["arms"]),
                "common_prefix_sha256": report["common_prefix_sha256"],
                "provider_calls_from_matrix": 0,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
