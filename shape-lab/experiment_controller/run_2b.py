"""Run a model-free, isolated 2B fixture check and archive its evidence."""

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

from .run_2a import count_tool_calls, parsed_jsonl, read_key, validate_sources
from .live_capture import LiveCapture


LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parent
COMPOSE = LAB / "compose_2b.yaml"
FIXTURE = LAB / "config" / "exp_2b_engine_fixture.json"
TASK = LAB / "config" / "agent_2b_task.json"
DECOY_IMAGE = "shape-filesystem-decoy-2b:dev"
AGENT_IMAGE = "shape-2b-attacker:dev"
GATEWAY_IMAGE = "shape-model-gateway:dev"


def command(args: list[str], *, env: dict[str, str] | None = None,
            timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=LAB, env=env, text=True,
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(args)}\n{result.stderr[-2000:]}")
    return result


def compose(project: str, args: list[str], env: dict[str, str], *,
            timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    return command(["docker", "compose", "-p", project, "-f", str(COMPOSE), *args],
                   env=env, timeout=timeout, check=check)


def compose_agent(project: str, args: list[str], env: dict[str, str], *,
                  timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    return command(["docker", "compose", "--profile", "agent", "-p", project,
                    "-f", str(COMPOSE), *args], env=env, timeout=timeout, check=check)


def write_private(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(value)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def image_id(name: str = DECOY_IMAGE) -> str | None:
    result = command(["docker", "image", "inspect", name,
                      "--format", "{{.Id}}"], timeout=30, check=False)
    return result.stdout.strip() or None


def service_events(project: str, service: str, env: dict[str, str]) -> str:
    return compose_agent(project, ["logs", "--no-color", "--no-log-prefix", service],
                         env, timeout=30, check=False).stdout


def container_info(project: str, service: str, env: dict[str, str]) -> dict[str, Any]:
    identifier = compose_agent(project, ["ps", "-a", "-q", service], env,
                               timeout=30).stdout.strip()
    if not identifier:
        raise RuntimeError(f"Missing {service} container")
    output = command(["docker", "inspect", identifier,
                      "--format", "{{json .State}}\n{{json .NetworkSettings.Networks}}\n{{json .Config.Env}}\n{{json .Mounts}}"],
                     timeout=30).stdout.splitlines()
    return {"state": json.loads(output[0]), "networks": sorted(json.loads(output[1])),
            "environment": json.loads(output[2]), "mounts": json.loads(output[3])}


def credential_shape(info: dict[str, Any]) -> dict[str, bool]:
    names = {item.partition("=")[0] for item in info["environment"]}
    mounts = {item["Destination"] for item in info["mounts"]}
    return {"real_key_in_environment": "ZAI_API_KEY" in names,
            "real_key_file_mounted": "/run/secrets/zai_api_key" in mounts,
            "arm_in_environment": "SHAPE_ARM" in names,
            "placeholder_auth": "ANTHROPIC_AUTH_TOKEN=shape-lab-placeholder" in info["environment"]}


def run_deterministic(arm: str, *, build: bool = True, seed: str = "fixture-seed",
                      branching_factor: int = 4, run_id: str | None = None) -> dict[str, Any]:
    if arm not in {"B0", "B1", "B2", "B3"}:
        raise ValueError("Unknown 2B arm")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", seed):
        raise ValueError("Invalid seed")
    if not 1 <= branching_factor <= 15:
        raise ValueError("Invalid branching factor")
    run_id = run_id or "2b-dete-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
    if not re.fullmatch(r"2b-dete-[a-z0-9-]{1,53}", run_id):
        raise ValueError("Invalid run ID")
    project = "shape" + run_id
    run_dir = LAB / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    env = dict(os.environ)
    env.update({"SHAPE_RUN_ID": run_id, "SHAPE_ARM": arm, "SHAPE_2B_SEED": seed,
                "SHAPE_2B_BRANCHING": str(branching_factor),
                "SHAPE_RUN_DIR": str(run_dir.resolve()),
                "LAB_UID": str(os.getuid()), "LAB_GID": str(os.getgid())})
    manifest: dict[str, Any] = {
        "schema_version": 1, "run_id": run_id, "mode": "deterministic_fixture",
        "arm": arm, "seed": seed, "branching_factor": branching_factor,
        "project": project,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "fixture_sha256": sha(FIXTURE),
        "agent_task_sha256": sha(TASK),
        "filesystem_engine_sha256": sha(LAB / "filesystem_decoy_2b" / "virtual_fs.py"),
        "decoy_server_sha256": sha(LAB / "filesystem_decoy_2b" / "server.py"),
        "ssh_tools_sha256": sha(LAB / "agent_runner" / "ssh_tools_2b.py"),
        "compose_source_sha256": sha(COMPOSE),
        "experimental_result": False,
    }
    error: str | None = None
    reason = "not_started"
    live_capture: LiveCapture | None = None
    try:
        if build:
            output = compose_agent(project, ["build", "filesystem-decoy-2b", "attacker-agent"], env)
            write_private(run_dir / "build.log", output.stdout + output.stderr)
        manifest["decoy_image_id"] = image_id()
        manifest["agent_image_id"] = image_id(AGENT_IMAGE)
        if manifest["decoy_image_id"] is None or manifest["agent_image_id"] is None:
            raise RuntimeError("2B decoy and attacker images must be built")
        resolved = compose(project, ["config"], env, timeout=30).stdout
        write_private(run_dir / "compose.resolved.yaml", resolved)
        manifest["resolved_compose_sha256"] = hashlib.sha256(resolved.encode()).hexdigest()
        compose(project, ["up", "-d", "--wait", "--wait-timeout", "30", "--no-build",
                          "filesystem-decoy-2b"], env, timeout=60)
        live_capture = LiveCapture(COMPOSE, project, run_dir,
                                   {"filesystem-decoy-2b": "decoy-live.jsonl"}, env)
        live_capture.start()
        network = project + "_trial_net"
        network_state = command(["docker", "network", "inspect", network,
                                 "--format", "{{json .Internal}}"], timeout=30).stdout.strip()
        if network_state != "true":
            raise RuntimeError("Trial network is not internal")
        identifier = compose(project, ["ps", "-q", "filesystem-decoy-2b"], env,
                             timeout=30).stdout.strip()
        inspection = command(["docker", "inspect", identifier,
                              "--format", "{{json .NetworkSettings.Networks}}\n{{json .NetworkSettings.Ports}}"],
                             timeout=30).stdout.splitlines()
        if sorted(json.loads(inspection[0])) != [network]:
            raise RuntimeError("2B decoy joined an unexpected network")
        ports = json.loads(inspection[1])
        if any(value is not None for value in ports.values()):
            raise RuntimeError("2B decoy published a host port")
        manifest["isolation_preflight"] = {"internal_network": True, "no_host_ports": True}
        client = command([
            "docker", "run", "--rm", "--network", network,
            "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
            "--mount", f"type=bind,src={LAB / 'tests'},dst=/smoke,readonly",
            "--env", f"SHAPE_SMOKE_ARM={arm}",
            "--entrypoint", "python", DECOY_IMAGE, "/smoke/docker_smoke_2b.py",
        ], timeout=60)
        write_private(run_dir / "client.log", client.stdout + client.stderr)
        tool_probe = """
import socket
from ssh_tools_2b import ssh_connect, ssh_exec
assert "Already connected" in ssh_connect("ssh://lab@filesystem-decoy-2b")
assert "/home/lab/README.txt" in ssh_exec("file /home/lab/README.txt")
assert "command not found" in ssh_exec("uname -a")
try:
    with socket.create_connection(("1.1.1.1", 443), timeout=3):
        raise AssertionError("attacker image has direct external egress")
except OSError:
    pass
print("SSH_TOOL_TRANSPORT=passed")
"""
        tool_client = command([
            "docker", "run", "--rm", "--network", network,
            "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
            "--entrypoint", "python", AGENT_IMAGE, "-c", tool_probe,
        ], timeout=60)
        write_private(run_dir / "tool-client.log", tool_client.stdout + tool_client.stderr)
        reason = "deterministic_complete"
    except Exception as exc:
        reason = "controller_error"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if live_capture is not None:
            live_capture.stop()
        try:
            logs = compose(project, ["logs", "--no-color", "--no-log-prefix",
                                     "filesystem-decoy-2b"], env, timeout=30,
                           check=False).stdout
            write_private(run_dir / "decoy-events.jsonl", logs)
        except Exception:
            pass
        compose(project, ["down", "--remove-orphans"], env, timeout=90, check=False)
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["termination_reason"] = reason
    manifest["error"] = error
    manifest["artifact_sha256"] = {
        name: sha(run_dir / name) for name in ("compose.resolved.yaml", "client.log",
                                               "tool-client.log", "decoy-events.jsonl")
        if (run_dir / name).exists()
    }
    write_private(run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    result = {"manifest": manifest, "run_dir": str(run_dir)}
    write_private(run_dir / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def run_connectivity(*, build: bool = True, seed: str = "fixture-seed",
                     run_id: str | None = None) -> dict[str, Any]:
    """Bounded real-agent check of the tool seam; not an experiment outcome."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", seed):
        raise ValueError("Invalid seed")
    pentest_commit, unified_commit = validate_sources()
    run_id = run_id or "2b-conn-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
    if not re.fullmatch(r"2b-conn-[a-z0-9-]{1,53}", run_id):
        raise ValueError("Invalid run ID")
    project = "shape" + run_id
    run_dir = LAB / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    agent_dir = run_dir / "agent"
    agent_dir.mkdir(mode=0o700)
    env = dict(os.environ)
    env.update({
        "SHAPE_RUN_ID": run_id,
        "SHAPE_ARM": "B0",
        "SHAPE_2B_SEED": seed,
        "SHAPE_RUN_DIR": str(run_dir.resolve()),
        "SHAPE_2B_ALLOW_FIXTURE_MODEL": "1",
        "SHAPE_2B_SMOKE": "1",
        "SHAPE_MAX_MODEL_CALLS": "8",
        "SHAPE_MAX_MODEL_TOKENS": "100000",
        "LAB_UID": str(os.getuid()),
        "LAB_GID": str(os.getgid()),
    })
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "mode": "connectivity_fixture",
        "arm": "B0",
        "seed": seed,
        "project": project,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "fixture_sha256": sha(FIXTURE),
        "agent_task_sha256": sha(TASK),
        "filesystem_engine_sha256": sha(LAB / "filesystem_decoy_2b" / "virtual_fs.py"),
        "decoy_server_sha256": sha(LAB / "filesystem_decoy_2b" / "server.py"),
        "ssh_tools_sha256": sha(LAB / "agent_runner" / "ssh_tools_2b.py"),
        "agent_entrypoint_sha256": sha(LAB / "agent_runner" / "entrypoint_2b.py"),
        "controller_sha256": sha(Path(__file__)),
        "pentestgpt_commit": pentest_commit,
        "unified_agent_commit": unified_commit,
        "max_wall_seconds": 240,
        "max_agent_tool_calls": 20,
        "max_model_calls": 8,
        "max_model_tokens": 100000,
        "experimental_result": False,
    }
    reason = "not_started"
    error: str | None = None
    agent_exit_code: int | None = None
    live_capture: LiveCapture | None = None
    with tempfile.TemporaryDirectory(prefix="shape2b-key-") as secret_dir:
        key_file = Path(secret_dir) / "zai_api_key"
        write_private(key_file, read_key() + "\n")
        env["SHAPE_KEY_FILE"] = str(key_file)
        try:
            if build:
                output = compose_agent(project, ["build", "filesystem-decoy-2b",
                                                 "model-gateway", "attacker-agent"], env)
                write_private(run_dir / "build.log", output.stdout + output.stderr)
            manifest["images"] = {name: image_id(image) for name, image in {
                "decoy": DECOY_IMAGE, "gateway": GATEWAY_IMAGE,
                "agent": AGENT_IMAGE,
            }.items()}
            if any(value is None for value in manifest["images"].values()):
                raise RuntimeError("All 2B trial images must be built")
            resolved = compose_agent(project, ["config"], env, timeout=30).stdout
            write_private(run_dir / "compose.resolved.yaml", resolved)
            manifest["resolved_compose_sha256"] = hashlib.sha256(resolved.encode()).hexdigest()
            compose_agent(project, ["up", "-d", "--wait", "--wait-timeout", "30",
                                    "--no-build", "filesystem-decoy-2b", "model-gateway"],
                          env, timeout=60)
            live_capture = LiveCapture(COMPOSE, project, run_dir,
                                       {"filesystem-decoy-2b": "decoy-live.jsonl",
                                        "model-gateway": "gateway-live.jsonl"}, env)
            live_capture.start()
            trial_network = project + "_trial_net"
            egress_network = project + "_egress_net"
            decoy_info = container_info(project, "filesystem-decoy-2b", env)
            gateway_info = container_info(project, "model-gateway", env)
            if decoy_info["networks"] != [trial_network] or gateway_info["networks"] != sorted([trial_network, egress_network]):
                raise RuntimeError("Decoy or gateway network topology differs from the trial contract")
            if credential_shape(decoy_info) != {
                "real_key_in_environment": False, "real_key_file_mounted": False,
                "arm_in_environment": True, "placeholder_auth": False,
            } or credential_shape(gateway_info) != {
                "real_key_in_environment": False, "real_key_file_mounted": True,
                "arm_in_environment": False, "placeholder_auth": False,
            }:
                raise RuntimeError("Decoy or gateway credential placement differs from the trial contract")
            probe = """
import json, socket, urllib.request
result = {}
for name, url in (("decoy", "http://filesystem-decoy-2b:8082/healthz"),
                  ("gateway", "http://model-gateway:8081/healthz")):
    with urllib.request.urlopen(url, timeout=3) as response:
        result[name] = response.status
try:
    with socket.create_connection(("1.1.1.1", 443), timeout=3):
        result["direct_egress"] = True
except OSError:
    result["direct_egress"] = False
print(json.dumps(result, sort_keys=True))
"""
            observed = json.loads(command([
                "docker", "run", "--rm", "--network", trial_network,
                "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
                "--entrypoint", "python", AGENT_IMAGE, "-c", probe,
            ], timeout=20).stdout)
            if observed != {"decoy": 200, "gateway": 200, "direct_egress": False}:
                raise RuntimeError(f"2B network preflight failed: {observed}")
            manifest["isolation_preflight"] = observed
            started = time.monotonic()
            compose_agent(project, ["up", "-d", "--no-build", "attacker-agent"],
                          env, timeout=90)
            live_capture.add("attacker-agent", "agent-live.log")
            agent_info = container_info(project, "attacker-agent", env)
            if agent_info["networks"] != [trial_network] or credential_shape(agent_info) != {
                "real_key_in_environment": False, "real_key_file_mounted": False,
                "arm_in_environment": False, "placeholder_auth": True,
            }:
                raise RuntimeError("Attacker network or credential placement differs from the trial contract")
            reason = "agent_exit"
            while True:
                state = container_info(project, "attacker-agent", env)["state"]
                gateway_events = parsed_jsonl(service_events(project, "model-gateway", env))
                decoy_events = parsed_jsonl(service_events(project, "filesystem-decoy-2b", env))
                model_ok = any(item.get("event_type") == "model_call" and item.get("status") == 200
                               for item in gateway_events)
                connected = any(item.get("event_type") == "ssh_connected" for item in decoy_events)
                command_seen = any(item.get("event_type") == "filesystem_interaction" for item in decoy_events)
                if model_ok and connected and command_seen:
                    reason = "connectivity_observed"
                    break
                if not state.get("Running"):
                    agent_exit_code = state.get("ExitCode")
                    break
                if count_tool_calls(agent_dir, run_id) >= 20:
                    reason = "tool_cap"
                    break
                if time.monotonic() - started >= 240:
                    reason = "wall_cap"
                    break
                if any(item.get("event_type") == "cap_reached" for item in gateway_events):
                    reason = "model_cap"
                    break
                time.sleep(2)
            if reason != "agent_exit":
                compose_agent(project, ["stop", "-t", "5", "attacker-agent"],
                              env, timeout=30, check=False)
            agent_exit_code = container_info(project, "attacker-agent", env)["state"].get("ExitCode")
        except Exception as exc:
            reason = "controller_error"
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if live_capture is not None:
                live_capture.stop()
            for service, filename in (("filesystem-decoy-2b", "decoy-events.jsonl"),
                                      ("model-gateway", "gateway-events.jsonl"),
                                      ("attacker-agent", "agent-stdout.log")):
                try:
                    write_private(run_dir / filename, service_events(project, service, env))
                except Exception:
                    pass
            compose_agent(project, ["down", "--remove-orphans"], env, timeout=90, check=False)
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["termination_reason"] = reason
    manifest["agent_exit_code"] = agent_exit_code
    manifest["observed_agent_tool_calls"] = count_tool_calls(agent_dir, run_id)
    if reason != "connectivity_observed" and error is None:
        error = "connectivity_not_observed"
    manifest["error"] = error
    manifest["artifact_sha256"] = {
        name: sha(run_dir / name) for name in ("decoy-events.jsonl", "gateway-events.jsonl",
                                               "agent-stdout.log") if (run_dir / name).exists()
    }
    write_private(run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    result = {"manifest": manifest, "run_dir": str(run_dir)}
    write_private(run_dir / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("deterministic", "connectivity"),
                        default="deterministic")
    parser.add_argument("--arm", choices=("B0", "B1", "B2", "B3"), default="B0")
    parser.add_argument("--seed", default="fixture-seed")
    parser.add_argument("--branching-factor", type=int, default=4)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--run-id", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.mode == "connectivity" and args.arm != "B0":
        parser.error("Fixture connectivity mode uses B0 only")
    result = (run_connectivity(build=not args.no_build, seed=args.seed, run_id=args.run_id)
              if args.mode == "connectivity" else
              run_deterministic(args.arm, build=not args.no_build, seed=args.seed,
                                branching_factor=args.branching_factor, run_id=args.run_id))
    print(json.dumps({"run_dir": result["run_dir"],
                      "termination_reason": result["manifest"]["termination_reason"],
                      "error": result["manifest"]["error"]}, indent=2, sort_keys=True))
    if result["manifest"]["error"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
