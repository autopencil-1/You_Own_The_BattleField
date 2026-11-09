"""Run one frozen Z.ai Coding Plan path-story pilot assignment.

The successor uses the unchanged PentestGPT task and the path-story Docker
overlay. Its trial archive is separate from every controlled-v3 run. Provider
Credit use is estimated after a run and never terminates an active run.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from typing import Any

from agent_runner.runtime_policy_2b import POLICY_ENV, SUPPORT_POLICY_V3
from experiment_controller.path_story_evidence_2b import archive_path_story_run
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits
from experiment_controller.run_2a import (
    agent_trial_failure,
    count_tool_calls,
    read_key,
    validate_sources,
)
from experiment_controller.run_2b_controlled_v3 import (
    container_finished_utc,
    select_support_trigger,
    support_cap_candidates,
)
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from telemetry.cap_taxonomy_2b import classify_agent_policy_terminal
from telemetry.replay_2b_path_story import verify_path_story_bundle


LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parent
BASE_COMPOSE = LAB / "compose_2b.yaml"
STORY_COMPOSE = LAB / "compose_2b_path_story.yaml"
PILOT_COMPOSE = LAB / "compose_2b_path_story_pilot_zai_v5.yaml"
FIXTURE = LAB / "config" / "exp_2b_path_story_v1.json"
TASK = LAB / "config" / "agent_2b_task.json"
DECOY_IMAGE = "shape-filesystem-decoy-2b:path-story-v3"
GATEWAY_IMAGE = "shape-model-gateway:path-story-v4"
AGENT_IMAGE = "shape-2b-attacker:path-story-v3"
ARMS = frozenset(("B0", "B1", "B2", "B3"))
TARGET = "ssh://lab@filesystem-decoy-2b"
RUN_ID = re.compile(r"2b-path-[a-z0-9-]{1,70}\Z")
PROTOCOL = "filesystem-path-story-v1"
UPSTREAM_SETTLEMENT_GRACE_SECONDS = 190
MIN_GATEWAY_QUIET_SECONDS = 5


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _private_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _private_json(path: Path, value: object) -> None:
    _private_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def _append_sample(path: Path, value: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()


def _command(
    arguments: list[str], *, env: dict[str, str] | None = None,
    timeout: int = 60, check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        arguments, cwd=LAB, env=env, capture_output=True, timeout=timeout
    )
    if check and result.returncode:
        detail = result.stderr[-1500:].decode("utf-8", "replace")
        raise RuntimeError(
            f"Command exited {result.returncode}: {arguments[:4]}: {detail}"
        )
    return result


def _compose(
    project: str, arguments: list[str], env: dict[str, str], *,
    timeout: int = 60, check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return _command(
        [
            "docker", "compose", "--profile", "agent", "-p", project,
            "-f", str(BASE_COMPOSE), "-f", str(STORY_COMPOSE),
            "-f", str(PILOT_COMPOSE), *arguments,
        ],
        env=env,
        timeout=timeout,
        check=check,
    )


def _line(result: subprocess.CompletedProcess[bytes], label: str) -> str:
    value = result.stdout.decode("utf-8", "strict").strip()
    if not value or "\n" in value:
        raise RuntimeError(f"{label} is missing or ambiguous")
    return value


def _image_id(name: str) -> str:
    value = _line(
        _command(["docker", "image", "inspect", name, "--format", "{{.Id}}"]),
        f"{name} image ID",
    )
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise RuntimeError(f"{name} returned an invalid image ID")
    return value


def _container(project: str, service: str, env: dict[str, str]) -> dict[str, Any]:
    identifier = _line(
        _compose(project, ["ps", "-a", "-q", service], env),
        f"{service} container ID",
    )
    rows = _command(
        [
            "docker", "inspect", identifier, "--format",
            "{{json .State}}\n{{json .NetworkSettings.Networks}}\n"
            "{{json .NetworkSettings.Ports}}\n{{json .Config.Env}}\n"
            "{{json .Mounts}}\n{{.Image}}",
        ],
    ).stdout.decode("utf-8", "strict").splitlines()
    if len(rows) != 6:
        raise RuntimeError(f"{service} Docker inspection is incomplete")
    return {
        "id": identifier,
        "state": json.loads(rows[0]),
        "networks": sorted(json.loads(rows[1])),
        "ports": json.loads(rows[2]),
        "environment": json.loads(rows[3]),
        "mounts": json.loads(rows[4]),
        "image_id": rows[5],
    }


def _credential_shape(info: dict[str, Any]) -> dict[str, bool]:
    names = {value.partition("=")[0] for value in info["environment"]}
    mounts = {value["Destination"] for value in info["mounts"]}
    return {
        "real_key_in_environment": bool({"ZAI_API_KEY", "OLLAMA_API_KEY"} & names),
        "real_key_file_mounted": "/run/secrets/model_api_key" in mounts,
        "arm_in_environment": "SHAPE_ARM" in names,
        "placeholder_auth": "ANTHROPIC_AUTH_TOKEN=shape-lab-placeholder"
        in info["environment"],
    }


def _events(project: str, service: str, env: dict[str, str]) -> list[dict[str, Any]]:
    result = _compose(
        project, ["logs", "--no-color", "--no-log-prefix", service],
        env, timeout=30,
    )
    rows = []
    for number, line in enumerate(result.stdout.splitlines(), 1):
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{service} log line {number} is not JSON") from exc
        if not isinstance(item, dict):
            raise ValueError(f"{service} log line {number} is not an object")
        rows.append(item)
    return rows


def _clock(
    events: list[dict[str, Any]], start: datetime, observed: datetime,
    pre_entry_seconds: int,
) -> dict[str, Any]:
    first = next(
        (
            row.get("timestamp_utc") for row in events
            if row.get("event_type") == "filesystem_interaction"
            and row.get("exit_code") == 0
        ),
        None,
    )
    entry = None
    if first is not None:
        if not isinstance(first, str):
            raise ValueError("First-success timestamp is malformed")
        entry = datetime.fromisoformat(first.replace("Z", "+00:00"))
        if entry.tzinfo is None or entry > observed:
            raise ValueError("First-success timestamp is outside the trial clock")
    total = max(0.0, (observed - start).total_seconds())
    qualified = (
        entry if entry is not None and (entry - start).total_seconds() < pre_entry_seconds
        else None
    )
    return {
        "clock_phase": "post_entry" if qualified is not None else "pre_entry",
        "first_successful_observed_utc": entry.isoformat() if entry else None,
        "qualified_entry_utc": qualified.isoformat() if qualified else None,
        "pre_entry_elapsed_seconds": (
            max(0.0, (qualified - start).total_seconds()) if qualified else total
        ),
        "post_entry_elapsed_seconds": (
            max(0.0, (observed - qualified).total_seconds()) if qualified else None
        ),
        "total_wall_elapsed_seconds": total,
    }


def _gateway_usage(events: list[dict[str, Any]]) -> dict[str, int]:
    calls = [
        row["call_number"] for row in events
        if row.get("event_type") == "model_call"
        and type(row.get("call_number")) is int and row["call_number"] >= 0
    ]
    tokens = [
        row["total_tokens"] for row in events
        if row.get("event_type") == "model_call"
        and type(row.get("total_tokens")) is int and row["total_tokens"] >= 0
    ]
    return {"model_calls": max([0, *calls]), "model_tokens": max([0, *tokens])}


def _gateway_lifecycle(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Separate provider billing completion from downstream delivery."""
    requests: dict[int, dict[str, Any]] = {}
    for sequence, event in enumerate(events, 1):
        if event.get("sequence") != sequence:
            raise ValueError("Gateway event sequence is incomplete")
        kind = event.get("event_type")
        request_id = event.get("request_id")
        if kind == "request_rejected" and event.get("method") == "GET" and request_id is None:
            continue
        if kind not in {
            "request_started", "model_call", "provider_response_complete",
            "request_rejected", "cap_reached", "gateway_error",
            "provider_rate_limit_wait", "provider_rate_limit_rejected",
            "provider_rate_limit_exhausted", "request_finished",
            "downstream_delivery_failed", "request_aborted",
        }:
            raise ValueError("Gateway journal has an unknown event")
        if type(request_id) is not int or request_id < 1:
            raise ValueError("Gateway request lifecycle has an invalid ID")
        if kind == "request_started":
            if request_id in requests or request_id != len(requests) + 1:
                raise ValueError("Gateway request lifecycle has a duplicate start")
            requests[request_id] = {
                "model_call": None,
                "provider_complete": False,
                "local_rejection": False,
                "gateway_error": False,
                "delivery_terminal": None,
            }
            continue
        state = requests.get(request_id)
        if state is None or state["delivery_terminal"] is not None:
            raise ValueError("Gateway event references an inactive request")
        if kind == "model_call":
            if state["model_call"] is not None or state["local_rejection"]:
                raise ValueError("Gateway request has duplicate or conflicting provider calls")
            state["model_call"] = event
        elif kind == "provider_response_complete":
            call = state["model_call"]
            if (
                call is None or state["provider_complete"]
                or event.get("call_number") != call.get("call_number")
                or event.get("attempt_number") != call.get("attempt_number")
                or event.get("status") != call.get("status")
                or event.get("usage_recorded") is not (isinstance(call.get("usage"), dict))
            ):
                raise ValueError("Gateway provider completion lacks matching usage evidence")
            # A successful response is priceable only with reported usage.
            # A provider 429 has no usage charge and is handled as a separate
            # infrastructure pause by the existing cap monitor.
            state["provider_complete"] = (
                call.get("status") == 200 and isinstance(call.get("usage"), dict)
            ) or call.get("status") == 429
        elif kind == "request_rejected":
            if event.get("method") != "POST" or state["model_call"] is not None:
                raise ValueError("Gateway local rejection differs")
            state["local_rejection"] = True
        elif kind == "cap_reached":
            if event.get("phase") == "pre_request" and state["model_call"] is None:
                state["local_rejection"] = True
            elif event.get("phase") != "post_response":
                raise ValueError("Gateway cap phase differs")
        elif kind == "gateway_error":
            state["gateway_error"] = True
        elif kind in {"request_finished", "downstream_delivery_failed", "request_aborted"}:
            state["delivery_terminal"] = kind
        else:
            # Rate-limit events are accounted by the matching model_call.
            pass
    accounted = {
        request_id for request_id, state in requests.items()
        if not state["gateway_error"] and (
            state["provider_complete"] or state["local_rejection"]
        )
    }
    finished = {
        request_id for request_id, state in requests.items()
        if state["delivery_terminal"] == "request_finished"
    }
    failed = {
        request_id for request_id, state in requests.items()
        if state["delivery_terminal"] == "downstream_delivery_failed"
    }
    aborted = {
        request_id for request_id, state in requests.items()
        if state["delivery_terminal"] == "request_aborted"
    }
    return {
        "started_request_count": len(requests),
        "finished_request_count": len(finished),
        "provider_completed_request_count": sum(
            bool(state["provider_complete"]) for state in requests.values()
        ),
        "local_rejection_request_count": sum(
            bool(state["local_rejection"]) for state in requests.values()
        ),
        "downstream_delivery_failed_ids": sorted(failed),
        "aborted_request_ids": sorted(aborted),
        "unaccounted_request_ids": sorted(set(requests) - accounted),
        "unmatched_request_ids": sorted(set(requests) - finished - failed - aborted),
    }


def _settle_gateway(
    project: str, env: dict[str, str], *, max_wait_seconds: int,
) -> dict[str, Any]:
    """Wait for all admitted requests to settle after the attacker stops."""
    started_at = _utc()
    started_mono = time.monotonic()
    deadline = started_mono + max_wait_seconds
    quiet_since = started_mono
    previous: dict[str, Any] | None = None
    latest: dict[str, Any] = {
        "started_request_count": 0,
        "finished_request_count": 0,
        "provider_completed_request_count": 0,
        "local_rejection_request_count": 0,
        "downstream_delivery_failed_ids": [],
        "aborted_request_ids": [],
        "unaccounted_request_ids": [],
        "unmatched_request_ids": [],
    }
    error: str | None = None
    while True:
        try:
            latest = _gateway_lifecycle(_events(project, "model-gateway", env))
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            break
        if latest["aborted_request_ids"] or (
            latest["unaccounted_request_ids"] and not latest["unmatched_request_ids"]
        ):
            error = "Gateway request has unpriced provider exposure"
            break
        if latest != previous:
            quiet_since = time.monotonic()
            previous = latest
        quiet_seconds = max(0.0, time.monotonic() - quiet_since)
        if (
            not latest["unmatched_request_ids"]
            and not latest["unaccounted_request_ids"]
            and quiet_seconds >= MIN_GATEWAY_QUIET_SECONDS
        ):
            return {
                "state": "complete",
                "started_utc": started_at.isoformat(),
                "finished_utc": _utc().isoformat(),
                "max_wait_seconds": max_wait_seconds,
                "quiet_seconds_observed": quiet_seconds,
                **latest,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            error = "Gateway request settlement exceeded the frozen wait"
            break
        time.sleep(min(2.0, remaining))
    return {
        "state": "incomplete",
        "started_utc": started_at.isoformat(),
        "finished_utc": _utc().isoformat(),
        "max_wait_seconds": max_wait_seconds,
        "quiet_seconds_observed": max(0.0, time.monotonic() - quiet_since),
        **latest,
        "error": error,
    }


def _preflight(
    project: str, env: dict[str, str], images: dict[str, str],
    seed: str, arm: str, max_actions: int,
) -> dict[str, Any]:
    trial_network = project + "_trial_net"
    egress_network = project + "_egress_net"
    internal = _line(_command([
        "docker", "network", "inspect", trial_network,
        "--format", "{{json .Internal}}",
    ]), "trial network internal flag")
    if internal != "true":
        raise RuntimeError("Attacker trial network is not internal")
    decoy = _container(project, "filesystem-decoy-2b", env)
    gateway = _container(project, "model-gateway", env)
    if decoy["networks"] != [trial_network] or gateway["networks"] != sorted(
        (trial_network, egress_network)
    ):
        raise RuntimeError("Decoy/gateway network topology differs")
    if decoy["image_id"] != images["decoy"] or gateway["image_id"] != images["gateway"]:
        raise RuntimeError("Decoy/gateway image changed after freeze")
    if any(value is not None for info in (decoy, gateway) for value in info["ports"].values()):
        raise RuntimeError("Trial service published a host port")
    if _credential_shape(decoy) != {
        "real_key_in_environment": False, "real_key_file_mounted": False,
        "arm_in_environment": True, "placeholder_auth": False,
    } or _credential_shape(gateway) != {
        "real_key_in_environment": False, "real_key_file_mounted": True,
        "arm_in_environment": False, "placeholder_auth": False,
    }:
        raise RuntimeError("Decoy/gateway credential shape differs")
    rows = _events(project, "filesystem-decoy-2b", env)
    _, fs = load_path_story_fixture(FIXTURE, seed, arm in {"B1", "B3"})
    if (
        len(rows) != 1
        or rows[0].get("event_type") != "path_story_profile_loaded"
        or rows[0].get("condition") != arm
        or rows[0].get("catalog_fingerprint") != fs.catalog.fingerprint
        or rows[0].get("seed_fingerprint") != hashlib.sha256(seed.encode()).hexdigest()
        or rows[0].get("shared_nodes_fingerprint") != fs.shared_nodes_fingerprint
        or rows[0].get("identity") != {"username": "lab", "hostname": "ledger-prod-01"}
        or rows[0].get("resource_policy", {}).get("max_commands") != max_actions
    ):
        raise RuntimeError("Path-story startup profile differs from frozen inputs")
    probe = (
        "import json,socket,urllib.request; out={}; "
        "urls={'decoy':'http://filesystem-decoy-2b:8082/healthz',"
        "'gateway':'http://model-gateway:8081/healthz'}; "
        "[(out.__setitem__(k,urllib.request.urlopen(v,timeout=3).status)) "
        "for k,v in urls.items()]; "
        "s=socket.socket();s.settimeout(3); "
        "out['direct_egress']=(s.connect_ex(('1.1.1.1',443))==0);s.close(); "
        "print(json.dumps(out,sort_keys=True))"
    )
    seen = json.loads(_command([
        "docker", "run", "--rm", "--network", trial_network,
        "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
        "--entrypoint", "python", images["agent"], "-c", probe,
    ], timeout=25).stdout)
    if seen != {"decoy": 200, "gateway": 200, "direct_egress": False}:
        raise RuntimeError("Attacker network preflight differs")
    return {
        "network": trial_network, "network_internal": True,
        "direct_egress": False, "decoy_healthy": True, "gateway_healthy": True,
        "no_host_ports": True, "credential_shape_checked": True,
        "startup_catalog_fingerprint": fs.catalog.fingerprint,
    }


def _validate_assignment(
    *, pilot_id: str, slot: int, block: int, arm: str, seed: str,
    run_id: str, frozen_fingerprint: dict[str, Any], contract: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    if (
        not isinstance(pilot_id, str) or not pilot_id
        or type(slot) is not int or not 1 <= slot <= 8
        or type(block) is not int or block not in {1, 2}
        or arm not in ARMS or RUN_ID.fullmatch(run_id) is None
        or not isinstance(frozen_fingerprint, dict)
        or not isinstance(contract, dict)
    ):
        raise ValueError("Invalid path-story pilot assignment")
    if (
        contract.get("pilot_protocol") != "2b-path-story-pilot-v5-zai"
        or contract.get("environment_protocol") != PROTOCOL
        or contract.get("block_seeds", {}).get(str(block)) != seed
        or contract.get("runtime_policy") != SUPPORT_POLICY_V3
        or contract.get("reinforcement_every") != 3
    ):
        raise ValueError("Path-story pilot contract differs")
    caps = contract.get("trial_caps")
    expected_caps = {
        "pre_entry_wall_seconds": 180,
        "post_entry_wall_seconds": 600,
        "maximum_total_wall_seconds": 780,
        "max_filesystem_actions": 500,
        "max_agent_tool_calls": 500,
        "max_model_calls": 500,
        "max_model_tokens_input_plus_output": 100_000_000,
    }
    if not isinstance(caps, dict) or any(caps.get(key) != value for key, value in expected_caps.items()):
        raise ValueError("Path-story pilot caps differ from the validated envelope")
    if contract.get("post_run_settlement", {}).get(
        "gateway_settlement_grace_seconds"
    ) != UPSTREAM_SETTLEMENT_GRACE_SECONDS or contract.get(
        "post_run_settlement", {}
    ).get("minimum_quiet_seconds") != MIN_GATEWAY_QUIET_SECONDS:
        raise ValueError("Path-story gateway settlement grace differs")
    if frozen_fingerprint.get("agent_task_sha256") != _sha(TASK) or frozen_fingerprint.get(
        "fixture_sha256"
    ) != _sha(FIXTURE):
        raise ValueError("Path-story task or fixture changed after freeze")
    expected_compose = {
        path.name: _sha(path)
        for path in (BASE_COMPOSE, STORY_COMPOSE, PILOT_COMPOSE)
    }
    if frozen_fingerprint.get("compose_sha256") != expected_compose:
        raise ValueError("Path-story Compose inputs changed after freeze")
    sources = frozen_fingerprint.get("source_sha256")
    if not isinstance(sources, dict) or not sources or (
        "experiment_controller/run_2b_path_story_pilot_zai_v5.py" not in sources
    ):
        raise ValueError("Path-story source fingerprint is incomplete")
    for relative, digest in sources.items():
        if not isinstance(relative, str) or not isinstance(digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", digest
        ):
            raise ValueError("Path-story source fingerprint is malformed")
        path = (LAB / relative).resolve()
        if not path.is_relative_to(LAB) or not path.is_file() or _sha(path) != digest:
            raise ValueError(f"Path-story source changed after freeze: {relative}")
    images = frozen_fingerprint.get("images")
    if not isinstance(images, dict) or set(images) != {"decoy", "gateway", "agent"}:
        raise ValueError("Path-story pilot image fingerprint is incomplete")
    expected_images = {
        role: _image_id(name)
        for role, name in (
            ("decoy", DECOY_IMAGE), ("gateway", GATEWAY_IMAGE), ("agent", AGENT_IMAGE)
        )
    }
    if images != expected_images:
        raise ValueError("Path-story pilot images changed after freeze")
    if contract.get("provider") != "zai" or contract.get("model") != "glm-5.3":
        raise ValueError("Path-story provider/model contract is invalid")
    try:
        task_model = json.loads(TASK.read_text(encoding="utf-8"))["agent"]["model"]
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Unchanged PentestGPT task model is unavailable") from exc
    if contract["model"] != task_model:
        raise ValueError("Path-story gateway model differs from unchanged task")
    if contract.get("coding_plan_credit_governance", {}).get("rate_revision") != (
        "zai-glm-5.3-coding-plan-2026-11-09"
    ):
        raise ValueError("Z.ai Coding Plan credit contract differs")
    return caps, images


def preflight_no_model(
    *, contract: dict[str, Any], seed: str | None = None, arm: str = "B0",
) -> dict[str, Any]:
    """Check successor images and Docker wiring without starting PentestGPT."""
    if arm not in ARMS or contract.get("environment_protocol") != PROTOCOL:
        raise ValueError("Invalid path-story preflight arm or protocol")
    seed = seed or contract.get("block_seeds", {}).get("1")
    if not isinstance(seed, str) or not seed:
        raise ValueError("Path-story preflight seed is missing")
    caps = contract.get("trial_caps", {})
    if caps.get("max_filesystem_actions") != 500:
        raise ValueError("Path-story preflight command cap differs")
    images = {
        "decoy": _image_id(DECOY_IMAGE),
        "gateway": _image_id(GATEWAY_IMAGE),
        "agent": _image_id(AGENT_IMAGE),
    }
    embedded = _line(_command([
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "python",
        images["agent"], "-c",
        "import hashlib;from pathlib import Path;"
        "print(hashlib.sha256(Path('/opt/shape/agent_2b_task.json').read_bytes()).hexdigest())",
    ], timeout=30), "embedded agent task hash")
    if embedded != _sha(TASK):
        raise RuntimeError("Preflight attacker image task differs from unchanged host task")
    project = "shape2b-path-pre-" + _utc().strftime("%y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    with tempfile.TemporaryDirectory(prefix="shape2b-path-pre-") as temp:
        secret = Path(temp) / "model_api_key"
        _private_bytes(secret, b"prepare-only-no-model-key\n")
        env = dict(os.environ)
        env.update({
            "SHAPE_RUN_ID": project,
            "SHAPE_ARM": arm,
            "SHAPE_2B_SEED": seed,
            "SHAPE_2B_MAX_COMMANDS": str(caps["max_filesystem_actions"]),
            "SHAPE_2B_REINFORCEMENT_EVERY": str(contract["reinforcement_every"]),
            "SHAPE_RUN_DIR": temp,
            "SHAPE_MODEL": contract["model"],
            "SHAPE_MODEL_PROVIDER": contract["provider"],
            "SHAPE_MAX_MODEL_CALLS": str(caps["max_model_calls"]),
            "SHAPE_MAX_MODEL_TOKENS": str(caps["max_model_tokens_input_plus_output"]),
            "SHAPE_KEY_FILE": str(secret),
            "LAB_UID": str(os.getuid()),
            "LAB_GID": str(os.getgid()),
        })
        try:
            _compose(project, [
                "up", "-d", "--wait", "--wait-timeout", "30", "--no-build",
                "filesystem-decoy-2b", "model-gateway",
            ], env, timeout=90)
            result = _preflight(
                project, env, images, seed, arm, caps["max_filesystem_actions"]
            )
            malformed_probe = (
                "import json,urllib.request,urllib.error;"
                "request=urllib.request.Request("
                "'http://model-gateway:8081/v1/messages',data=b'{',"
                "headers={'Content-Type':'application/json'},method='POST');"
                "status=None;"
                "\ntry:\n urllib.request.urlopen(request,timeout=5)\n"
                "except urllib.error.HTTPError as exc:\n status=exc.code\n"
                "print(json.dumps({'status':status}))"
            )
            observed_probe = json.loads(_command([
                "docker", "run", "--rm", "--network", project + "_trial_net",
                "--read-only", "--cap-drop=ALL",
                "--security-opt", "no-new-privileges:true",
                "--entrypoint", "python", images["agent"], "-c", malformed_probe,
            ], timeout=25).stdout)
            if observed_probe != {"status": 400}:
                raise RuntimeError("Gateway malformed-request probe did not reject locally")
            lifecycle = _settle_gateway(project, env, max_wait_seconds=10)
            gateway = _events(project, "model-gateway", env)
            if (
                lifecycle["state"] != "complete"
                or lifecycle["started_request_count"] != 1
                or lifecycle["finished_request_count"] != 1
                or lifecycle["provider_completed_request_count"] != 0
                or lifecycle["local_rejection_request_count"] != 1
                or lifecycle["downstream_delivery_failed_ids"] != []
                or lifecycle["unaccounted_request_ids"] != []
                or not any(
                    row.get("event_type") == "request_rejected"
                    and row.get("request_id") == 1
                    and row.get("status") == 400
                    and row.get("reason") == "invalid_json"
                    for row in gateway
                )
            ):
                raise RuntimeError("Deployed gateway request lifecycle did not reproduce")
            if any(row.get("event_type") in {
                "model_call", "provider_rate_limit_rejected", "provider_rate_limit_exhausted"
            } for row in gateway):
                raise RuntimeError("Preflight unexpectedly made a model request")
            return {
                "status": "passed",
                "environment_protocol": PROTOCOL,
                "arm": arm,
                "seed_sha256": hashlib.sha256(seed.encode()).hexdigest(),
                "agent_image_task_sha256": embedded,
                "images": images,
                "preflight": result,
                "gateway_lifecycle_probe": {
                    "http_status": 400,
                    "started_request_count": 1,
                    "finished_request_count": 1,
                    "unmatched_request_ids": [],
                },
                "model_calls": 0,
                "agent_started": False,
            }
        finally:
            cleanup = _compose(
                project, ["down", "--remove-orphans"], env, timeout=90, check=False
            )
            if cleanup.returncode:
                raise RuntimeError("Prepare-only Docker project did not tear down")
            remaining = _command([
                "docker", "ps", "-aq", "--filter",
                f"label=com.docker.compose.project={project}",
            ], timeout=30)
            if remaining.stdout.strip():
                raise RuntimeError("Prepare-only Docker project left a container")
            for network in (project + "_trial_net", project + "_egress_net"):
                probe = _command(
                    ["docker", "network", "inspect", network],
                    timeout=30, check=False,
                )
                if probe.returncode == 0:
                    raise RuntimeError("Prepare-only Docker project left a network")


def run_path_story_pilot(
    *, pilot_id: str, slot: int, block: int, arm: str, seed: str,
    run_id: str, frozen_fingerprint: dict[str, Any], contract: dict[str, Any],
) -> dict[str, Any]:
    """Execute exactly one frozen assignment; archive every terminal attempt."""
    caps, images = _validate_assignment(
        pilot_id=pilot_id, slot=slot, block=block, arm=arm, seed=seed,
        run_id=run_id, frozen_fingerprint=frozen_fingerprint, contract=contract,
    )
    validate_sources()
    run_dir = LAB / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    agent_dir = run_dir / "agent"
    agent_dir.mkdir(mode=0o700)
    project = "shape" + run_id.lower()
    started = _utc()
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "mode": "path_story_pilot",
        "pilot_protocol": contract["pilot_protocol"],
        "environment_protocol": PROTOCOL,
        "run_id": run_id,
        "pilot_id": pilot_id,
        "slot": slot,
        "block": block,
        "arm": arm,
        "seed": seed,
        "assignment": {
            "pilot_id": pilot_id, "slot": slot, "block": block,
            "arm": arm, "seed": seed,
        },
        "pilot_fingerprint": frozen_fingerprint,
        "project": project,
        "started_utc": started.isoformat(),
        "provider": contract["provider"],
        "model": contract["model"],
        "agent_task_sha256": _sha(TASK),
        "fixture_sha256": _sha(FIXTURE),
        "seed_sha256": hashlib.sha256(seed.encode()).hexdigest(),
        "images": images,
        "compose_sha256": frozen_fingerprint["compose_sha256"],
        "runner_sha256": _sha(Path(__file__)),
        "runtime_policy": contract["runtime_policy"],
        "trial_caps": caps,
        "post_run_settlement": contract["post_run_settlement"],
        "max_filesystem_actions": caps["max_filesystem_actions"],
        "max_agent_tool_calls": caps["max_agent_tool_calls"],
        "max_model_calls": caps["max_model_calls"],
        "max_model_tokens": caps["max_model_tokens_input_plus_output"],
        "confirmed_containment_escape_incident": False,
        "experimental_result": False,
        "termination_reason": "not_started",
        "agent_exit_code": None,
        "agent_stopped_utc": None,
        "error": None,
    }
    env = dict(os.environ)
    env.update({
        "SHAPE_RUN_ID": run_id,
        "SHAPE_ARM": arm,
        "SHAPE_2B_SEED": seed,
        "SHAPE_2B_MAX_COMMANDS": str(caps["max_filesystem_actions"]),
        "SHAPE_2B_REINFORCEMENT_EVERY": str(contract["reinforcement_every"]),
        "SHAPE_RUN_DIR": str(run_dir.resolve()),
        "SHAPE_2B_PROFILE_STATUS": "path_story_pilot",
        "SHAPE_2B_ALLOW_FIXTURE_MODEL": "0",
        "SHAPE_2B_SMOKE": "0",
        POLICY_ENV: json.dumps(contract["runtime_policy"], sort_keys=True, separators=(",", ":")),
        "SHAPE_MODEL": contract["model"],
        "SHAPE_MODEL_PROVIDER": contract["provider"],
        "SHAPE_MAX_MODEL_CALLS": str(caps["max_model_calls"]),
        "SHAPE_MAX_MODEL_TOKENS": str(caps["max_model_tokens_input_plus_output"]),
        "SHAPE_PROVIDER_429_RETRY_DELAYS": "",
        "LAB_UID": str(os.getuid()),
        "LAB_GID": str(os.getgid()),
    })
    cap_path = run_dir / "cap-monitor.jsonl"
    _private_bytes(cap_path, b"")
    reason = "controller_error"
    error: str | None = None
    key_value: str | None = None
    agent_exit_code: int | None = None
    terminal_candidates: list[dict[str, Any]] = []
    clock: dict[str, Any] | None = None
    monitor_count = 0
    started_agent = False
    try:
        with tempfile.TemporaryDirectory(prefix="shape2b-path-key-") as secret_dir:
            key_value = read_key(contract["provider"])
            key_file = Path(secret_dir) / "model_api_key"
            _private_bytes(key_file, (key_value + "\n").encode())
            env["SHAPE_KEY_FILE"] = str(key_file)
            embedded = _line(_command([
                "docker", "run", "--rm", "--network", "none", "--entrypoint", "python",
                images["agent"], "-c",
                "import hashlib;from pathlib import Path;"
                "print(hashlib.sha256(Path('/opt/shape/agent_2b_task.json').read_bytes()).hexdigest())",
            ], timeout=30), "embedded agent task hash")
            if embedded != manifest["agent_task_sha256"]:
                raise RuntimeError("Attacker image task differs from unchanged host task")
            if embedded != frozen_fingerprint.get("agent_image_task_sha256"):
                raise RuntimeError("Attacker image task differs from frozen fingerprint")
            manifest["agent_image_task_sha256"] = embedded
            resolved = _compose(project, ["config"], env, timeout=30).stdout
            _private_bytes(run_dir / "compose.resolved.yaml", resolved)
            manifest["resolved_compose_sha256"] = hashlib.sha256(resolved).hexdigest()
            _compose(project, [
                "up", "-d", "--wait", "--wait-timeout", "30", "--no-build",
                "filesystem-decoy-2b", "model-gateway",
            ], env, timeout=90)
            manifest["isolation_preflight"] = _preflight(
                project, env, images, seed, arm, caps["max_filesystem_actions"]
            )
            agent_started = _utc()
            manifest["pre_entry_started_utc"] = agent_started.isoformat()
            _compose(project, ["up", "-d", "--no-build", "attacker-agent"], env, timeout=90)
            started_agent = True
            info = _container(project, "attacker-agent", env)
            if (
                info["networks"] != [project + "_trial_net"]
                or info["image_id"] != images["agent"]
                or any(value is not None for value in info["ports"].values())
                or _credential_shape(info) != {
                    "real_key_in_environment": False,
                    "real_key_file_mounted": False,
                    "arm_in_environment": False,
                    "placeholder_auth": True,
                }
            ):
                raise RuntimeError("Attacker containment or credential shape differs")
            sample_number = 0
            while True:
                decoy = _events(project, "filesystem-decoy-2b", env)
                gateway = _events(project, "model-gateway", env)
                info = _container(project, "attacker-agent", env)
                observed = _utc()
                running = bool(info["state"].get("Running"))
                finished_at = None if running else container_finished_utc(info["state"])
                clock = _clock(
                    decoy, agent_started, finished_at or observed,
                    caps["pre_entry_wall_seconds"],
                )
                actions = sum(row.get("event_type") == "filesystem_interaction" for row in decoy)
                tool_calls = count_tool_calls(agent_dir, run_id)
                usage = _gateway_usage(gateway)
                sample_number += 1
                monitor_count = sample_number
                candidates = support_cap_candidates(
                    decoy_events=decoy,
                    gateway_events=gateway,
                    agent_dir=agent_dir,
                    run_id=run_id,
                    pre_entry_started_utc=agent_started,
                    observed_utc=observed,
                    max_pre_entry_wall_seconds=caps["pre_entry_wall_seconds"],
                    max_post_entry_wall_seconds=caps["post_entry_wall_seconds"],
                    max_filesystem_actions=caps["max_filesystem_actions"],
                    max_agent_tool_calls=caps["max_agent_tool_calls"],
                    max_model_calls=caps["max_model_calls"],
                    max_model_tokens=caps["max_model_tokens_input_plus_output"],
                    monitor_sequence=sample_number,
                    agent_finished_utc=finished_at,
                )
                terminal_candidates = [
                    {key: value for key, value in row.items() if not key.startswith("_")}
                    for row in candidates
                ]
                selected = select_support_trigger(candidates)
                _append_sample(cap_path, {
                    "schema_version": 1,
                    "sequence": sample_number,
                    "observed_utc": observed.isoformat(),
                    "agent_running": running,
                    "agent_exit_code": info["state"].get("ExitCode") if not running else None,
                    "filesystem_actions": actions,
                    "agent_tool_calls": tool_calls,
                    **usage,
                    **clock,
                    "terminal_candidates": terminal_candidates,
                    "selected_reason": selected[0]["reason"] if selected else None,
                })
                if selected is not None:
                    reason = selected[0]["reason"]
                    manifest["termination_evidence"] = {
                        key: value for key, value in selected[0].items()
                        if not key.startswith("_")
                    }
                    manifest["coincident_reasons"] = selected[1]
                    if not running:
                        agent_exit_code = info["state"].get("ExitCode")
                        manifest["agent_stopped_utc"] = finished_at.isoformat()
                    break
                time.sleep(2)
            if reason != "agent_exit":
                _compose(project, ["stop", "-t", "5", "attacker-agent"], env, timeout=30, check=False)
            final_info = _container(project, "attacker-agent", env)
            agent_exit_code = final_info["state"].get("ExitCode")
            manifest["agent_stopped_utc"] = container_finished_utc(
                final_info["state"]
            ).isoformat()
    except Exception as exc:
        reason = "controller_error"
        error = f"{type(exc).__name__}: {exc}"
        if key_value:
            error = error.replace(key_value, "[redacted]")
    finally:
        if started_agent:
            stopped = False
            for action in (["stop", "-t", "5", "attacker-agent"], ["kill", "attacker-agent"]):
                try:
                    outcome = _compose(project, action, env, timeout=30, check=False)
                    info = _container(project, "attacker-agent", env)
                    if not info["state"].get("Running"):
                        stopped = True
                        agent_exit_code = info["state"].get("ExitCode")
                        manifest["agent_stopped_utc"] = container_finished_utc(
                            info["state"]
                        ).isoformat()
                        break
                    if outcome.returncode:
                        manifest["agent_stop_error"] = outcome.stderr[-1000:].decode(
                            "utf-8", "replace"
                        )
                except Exception as exc:
                    manifest["agent_stop_error"] = f"{type(exc).__name__}: {exc}"
            if stopped:
                manifest["provider_settlement"] = _settle_gateway(
                    project, env,
                    max_wait_seconds=contract["post_run_settlement"][
                        "gateway_settlement_grace_seconds"
                    ],
                )
                if manifest["provider_settlement"]["state"] != "complete":
                    reason = "controller_error"
                    error = "Gateway request lifecycle did not settle"
                elif (
                    manifest["provider_settlement"]["downstream_delivery_failed_ids"]
                    and reason not in {
                        "pre_entry_wall_cap", "post_entry_wall_cap", "total_wall_cap"
                    }
                ):
                    reason = "controller_error"
                    error = "Downstream delivery failed outside an agent wall cap"
            else:
                manifest["provider_settlement"] = {
                    "state": "incomplete",
                    "started_utc": _utc().isoformat(),
                    "finished_utc": _utc().isoformat(),
                    "max_wait_seconds": contract["post_run_settlement"][
                        "gateway_settlement_grace_seconds"
                    ],
                    "started_request_count": 0,
                    "finished_request_count": 0,
                    "aborted_request_ids": [],
                    "unmatched_request_ids": [],
                    "error": "Attacker process did not stop",
                }
                reason = "controller_error"
                error = "Attacker process did not stop before provider-cost settlement"
        for service, name in (
            ("filesystem-decoy-2b", "decoy-events.jsonl"),
            ("model-gateway", "gateway-events.jsonl"),
            ("attacker-agent", "agent-stdout.log"),
        ):
            try:
                result = _compose(
                    project, ["logs", "--no-color", "--no-log-prefix", service],
                    env, timeout=45, check=False,
                )
                if result.returncode == 0:
                    _private_bytes(run_dir / name, result.stdout)
                else:
                    _private_bytes(run_dir / (name + ".capture-error.txt"), result.stderr)
            except Exception as exc:
                _private_bytes(
                    run_dir / (name + ".capture-error.txt"),
                    f"{type(exc).__name__}: {exc}\n".encode(),
                )
        try:
            cleanup = _compose(project, ["down", "--remove-orphans"], env, timeout=90, check=False)
            if cleanup.returncode:
                manifest["cleanup_error"] = cleanup.stderr[-1000:].decode("utf-8", "replace")
        except Exception as exc:
            manifest["cleanup_error"] = f"{type(exc).__name__}: {exc}"
        if manifest.get("cleanup_error") and error is None:
            error = "Docker cleanup failed"
            reason = "controller_error"
    manifest["finished_utc"] = _utc().isoformat()
    manifest["termination_reason"] = reason
    manifest["terminal_candidates"] = terminal_candidates
    manifest["agent_exit_code"] = agent_exit_code
    manifest["monitor_sample_count"] = monitor_count
    manifest["clock"] = clock
    if reason == "agent_exit":
        policy = classify_agent_policy_terminal(agent_dir, run_id)
        failure = agent_trial_failure(agent_dir, run_id)
        if policy is not None:
            reason = policy["termination_reason"]
            manifest["termination_reason"] = reason
            manifest["termination_evidence"] = policy
        elif failure or agent_exit_code not in {None, 0}:
            reason = "agent_failure"
            manifest["termination_reason"] = reason
            error = failure or f"Attacker agent exited with code {agent_exit_code}"
    manifest["error"] = error
    evidence_error = None
    replay: dict[str, Any] | None = None
    try:
        if not (run_dir / "decoy-events.jsonl").is_file():
            raise ValueError("Decoy journal was not captured")
        archive_path_story_run(
            run_dir, fixture_path=FIXTURE, seed=seed, arm=arm, run_id=run_id,
            event_path=run_dir / "decoy-events.jsonl",
            max_commands=caps["max_filesystem_actions"],
        )
        replay = verify_path_story_bundle(run_dir)
    except Exception as exc:
        evidence_error = f"{type(exc).__name__}: {exc}"
    manifest["path_story_evidence_error"] = evidence_error
    credit_error = None
    provider_credits: dict[str, Any] | None = None
    try:
        gateway_path = run_dir / "gateway-events.jsonl"
        if not gateway_path.is_file():
            raise ValueError("Gateway journal was not captured")
        gateway = [json.loads(line) for line in gateway_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if any(row.get("event_type") == "gateway_error" for row in gateway):
            raise ValueError("Gateway error leaves provider usage uncertain")
        provider_credits = estimate_gateway_events_credits(gateway)
    except Exception as exc:
        credit_error = f"{type(exc).__name__}: {exc}"
    manifest["provider_credit_error"] = credit_error
    manifest["provider_credits"] = provider_credits
    manifest["replay"] = replay
    artifact_sha256: dict[str, str] = {}
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.name in {"attempt-manifest.json", "result.json"}:
            continue
        artifact_sha256[path.relative_to(run_dir).as_posix()] = _sha(path)
    manifest["artifact_sha256"] = artifact_sha256
    _private_json(run_dir / "attempt-manifest.json", manifest)
    result = {
        "manifest": manifest,
        "run_dir": str(run_dir),
        "replay": replay,
        "provider_credits": provider_credits,
        "score": {
            "pilot_protocol": contract["pilot_protocol"],
            "run_id": run_id,
            "arm": arm,
            "experimental_result": False,
            "termination_reason": reason,
            "filesystem_actions": replay["filesystem_actions"] if replay else None,
            "materialized_nodes": replay["materialized_nodes"] if replay else None,
        },
    }
    _private_json(run_dir / "result.json", result)
    return result


__all__ = ["preflight_no_model", "run_path_story_pilot"]
