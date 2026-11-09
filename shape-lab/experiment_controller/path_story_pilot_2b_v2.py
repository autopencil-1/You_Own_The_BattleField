"""Freeze and govern the successor path-story behavioral pilot.

Preparation builds and fingerprints images, then commits a balanced eight-slot
schedule with zero provider authorization. No model run starts until a separate
user-approved funding tranche is recorded with authorize. Active runs are never
stopped for ordinary provider spend; admission is checked between attempts.
"""

from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import subprocess
from typing import Any

from agent_runner.runtime_policy_2b import SUPPORT_POLICY_V3
from experiment_controller.provider_cost_2b import (
    _format_nano_usd,
    _usd_to_nano,
    admission_decision,
    estimate_gateway_events_cost,
)
from experiment_controller.run_2a import agent_source_sha256, validate_sources
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server_path_story import StorySession
from filesystem_decoy_2b.virtual_fs import NodeKind
from telemetry.replay_2b_path_story import verify_path_story_bundle


LAB = Path(__file__).resolve().parents[1]
CONFIG = LAB / "config" / "exp_2b_path_story_pilot_v2.json"
FIXTURE = LAB / "config" / "exp_2b_path_story_v1.json"
TASK = LAB / "config" / "agent_2b_task.json"
MATRIX_CONFIG = LAB / "config" / "exp_2b_path_story_matrix_v1.json"
BASE_COMPOSE = LAB / "compose_2b.yaml"
OVERLAY_COMPOSE = LAB / "compose_2b_path_story.yaml"
PILOT_COMPOSE = LAB / "compose_2b_path_story_pilot.yaml"
STUDIES = LAB / "studies"
PROTOCOL = "2b-path-story-pilot-v2"
ENVIRONMENT = "filesystem-path-story-v1"
PILOT_ID = re.compile(r"2b-path-story-pilot-v2-[0-9]{14}-[0-9a-f]{6}\Z")
RUN_ID = re.compile(r"2b-path-[0-9]{14}-[0-9a-f]{6}\Z")
SEED = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
ARMS = ("B0", "B1", "B2", "B3")
RESERVE_NANO_USD = 10_000_000_000
AUTHORIZATION_CEILING_NANO_USD = 100_000_000_000
IMAGES = {
    "decoy": "shape-filesystem-decoy-2b:path-story-v1",
    "gateway": "shape-model-gateway:path-story-v1",
    "agent": "shape-2b-attacker:path-story-v1",
}
SOURCE_FILES = {
    name: LAB / name for name in (
        "experiment_controller/path_story_pilot_2b_v2.py",
        "experiment_controller/run_2b_path_story_pilot_v2.py",
        "experiment_controller/provider_cost_2b.py",
        "experiment_controller/run_2a.py",
        "experiment_controller/run_2b.py",
        "experiment_controller/run_2b_controlled_v3.py",
        "experiment_controller/path_story_evidence_2b.py",
        "telemetry/replay_2b_path_story.py",
        "telemetry/review_2b_path_story_pilot_v2.py",
        "telemetry/cap_taxonomy_2b.py",
        "filesystem_decoy_2b/server_path_story.py",
        "filesystem_decoy_2b/path_story_fs.py",
        "filesystem_decoy_2b/semantic_v2.py",
        "filesystem_decoy_2b/virtual_fs.py",
        "filesystem_decoy_2b/server.py",
        "agent_runner/ssh_tools_2b_path_story.py",
        "agent_runner/ssh_tools_2b.py",
        "agent_runner/entrypoint_2b_path_story.py",
        "agent_runner/runtime_policy_2b.py",
        "model_gateway/server.py",
        "model_gateway/server_path_story.py",
        "model_gateway/Dockerfile_path_story",
        "compose_2b.yaml",
        "compose_2b_path_story.yaml",
        "compose_2b_path_story_pilot.yaml",
        "model_gateway/providers.py",
    )
}
TERMINAL_REASONS = {
    "agent_exit",
    "agent_turn_cap",
    "total_wall_cap",
    "pre_entry_wall_cap",
    "post_entry_wall_cap",
    "filesystem_action_cap",
    "agent_tool_call_cap",
    "model_call_cap",
    "model_token_cap",
    "agent_decision_cap",
    "supervisor_turn_cap",
    "executor_turn_cap",
    "task_attempt_cap",
    "supervisor_attempt_cap",
    "structured_output_retry_cap",
}


class PilotIntegrityError(RuntimeError):
    """A committed assignment, archive, or funding record differs."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_new(path: Path, content: bytes) -> None:
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


def _write_committed(path: Path, value: dict[str, Any]) -> None:
    raw = _canonical(value)
    _write_new(path, raw)
    _write_new(path.with_suffix(".sha256"), (hashlib.sha256(raw).hexdigest() + "\n").encode())


def _read_committed(path: Path) -> dict[str, Any]:
    if path.is_symlink() or path.with_suffix(".sha256").is_symlink():
        raise PilotIntegrityError(f"Committed artifact is a symlink: {path}")
    try:
        raw = path.read_bytes()
        expected = path.with_suffix(".sha256").read_text(encoding="utf-8").strip()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PilotIntegrityError(f"Missing or malformed committed artifact: {path}") from exc
    if (
        not isinstance(value, dict)
        or raw != _canonical(value)
        or expected != hashlib.sha256(raw).hexdigest()
    ):
        raise PilotIntegrityError(f"Committed artifact differs: {path}")
    return value


def pilot_dir(pilot_id: str) -> Path:
    if PILOT_ID.fullmatch(pilot_id) is None:
        raise ValueError("Invalid path-story pilot ID")
    return STUDIES / pilot_id


def load_contract() -> dict[str, Any]:
    """Validate the versioned successor contract without reading task text."""
    raw = json.loads(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Path-story pilot contract must be an object")
    if (
        raw.get("schema_version") != 1
        or raw.get("pilot_protocol") != PROTOCOL
        or raw.get("environment_protocol") != ENVIRONMENT
        or raw.get("target") != "ssh://lab@filesystem-decoy-2b"
        or raw.get("status") != "schedule_freeze_available_execution_requires_authorization"
        or raw.get("task_path") != "config/agent_2b_task.json"
        or raw.get("task_sha256") != _sha(TASK)
        or raw.get("fixture_path") != "config/exp_2b_path_story_v1.json"
        or raw.get("fixture_sha256") != _sha(FIXTURE)
        or raw.get("provider") != "ollama"
        or raw.get("model") != "glm-5.3"
        or raw.get("agent") != {"backend": "claude", "effort": "max", "model": "glm-5.3"}
        or raw.get("reinforcement_every") != 3
        or raw.get("runtime_policy") != SUPPORT_POLICY_V3
    ):
        raise ValueError("Path-story pilot fixed identity differs")
    gate = raw.get("model_free_gate")
    if not isinstance(gate, dict) or gate.get("matrix_config_sha256") != _sha(MATRIX_CONFIG):
        raise ValueError("Model-free matrix config commitment differs")
    report_path = LAB / str(gate.get("matrix_report_path", ""))
    matrix_report = json.loads(report_path.read_text(encoding="utf-8"))
    if (
        gate.get("matrix_report_path") != "runs/path-story-matrix-v1-20261109-01/matrix-report.json"
        or gate.get("matrix_report_sha256") != _sha(report_path)
        or matrix_report.get("status") != "passed"
        or matrix_report.get("compose_sha256", {}).get(OVERLAY_COMPOSE.name)
        != _sha(OVERLAY_COMPOSE)
        or matrix_report.get("compose_sha256", {}).get(BASE_COMPOSE.name)
        != _sha(BASE_COMPOSE)
    ):
        raise ValueError("Passing model-free matrix report commitment differs")
    for seed in raw.get("block_seeds", {}).values():
        if not isinstance(seed, str) or SEED.fullmatch(seed) is None:
            raise ValueError("Pilot block seed is invalid")
    if raw.get("block_seeds") != {
        "1": "path-story-pilot-v1-block-01",
        "2": "path-story-pilot-v1-block-02",
    }:
        raise ValueError("Pilot block seeds differ")
    _, fs = load_path_story_fixture(FIXTURE, raw["block_seeds"]["1"], True)
    if raw.get("catalog_fingerprint") != fs.catalog.fingerprint:
        raise ValueError("Path-story catalog fingerprint differs")
    design = raw.get("design")
    expected_arms = {
        "B0": {"structure": False, "reinforcement": False},
        "B1": {"structure": True, "reinforcement": False},
        "B2": {"structure": False, "reinforcement": True},
        "B3": {"structure": True, "reinforcement": True},
    }
    if (
        not isinstance(design, dict)
        or design.get("arms") != expected_arms
        or design.get("balanced_blocks") != 2
        or design.get("required_valid_runs") != 8
        or design.get("runs_per_arm") != 2
        or design.get("runs_are_serial") is not True
        or design.get("freeze_all_assignments_before_execution") is not True
    ):
        raise ValueError("Pilot factorial design differs")
    caps = raw.get("trial_caps")
    if not isinstance(caps, dict) or caps != {
        "pre_entry_wall_seconds": 180,
        "post_entry_wall_seconds": 600,
        "maximum_total_wall_seconds": 780,
        "max_filesystem_actions": 500,
        "max_agent_tool_calls": 500,
        "max_model_calls": 500,
        "max_model_tokens_input_plus_output": 100000000,
        "retention_horizons_seconds": [60, 180, 300, 600],
    }:
        raise ValueError("Pilot runtime envelope differs")
    if raw.get("post_run_settlement") != {
        "gateway_settlement_grace_seconds": 190,
        "minimum_quiet_seconds": 5,
        "excluded_from_behavioral_clocks": True,
        "new_model_requests_allowed": False,
    }:
        raise ValueError("Pilot post-run settlement policy differs")
    replacement = raw.get("replacement_policy")
    if (
        not isinstance(replacement, dict)
        or replacement.get("maximum_infrastructure_invalid_replacements_per_slot") != 2
        or replacement.get("replace_behavioral_outcomes") is not False
        or replacement.get("retry_same_frozen_slot_arm_and_seed") is not True
    ):
        raise ValueError("Pilot replacement policy differs")
    governance = raw.get("provider_cost_governance")
    if (
        not isinstance(governance, dict)
        or governance.get("prepare_opens_zero_authorization") is not True
        or governance.get("authorization_requires_separate_user_approved_tranche") is not True
        or governance.get("minimum_uncommitted_reserve_per_new_run_usd") != "10.000000000"
        or governance.get("maximum_total_authorization_usd") != "100.000000000"
        or governance.get("authorization_semantics") != "between_run_tranche"
        or governance.get("active_run_overage_possible") is not True
        or governance.get("admission_between_runs_only") is not True
        or governance.get("active_run_cost_termination") is not False
        or governance.get("cost_enters_behavioral_outcome") is not False
    ):
        raise ValueError("Pilot provider-cost governance differs")
    rates = governance.get("rate_card")
    if not isinstance(rates, dict) or any(
        rates.get(key) != value
        for key, value in {
            "provider": "ollama",
            "model": "glm-5.3",
            "revision": "ollama-glm-5.3-2026-11-09",
            "input_usd_per_million_tokens": "1.40",
            "cached_input_usd_per_million_tokens": "0.26",
            "output_usd_per_million_tokens": "4.40",
            "cache_creation_input_rate_class": "input",
        }.items()
    ):
        raise ValueError("Pilot frozen rate card differs")
    return raw


class _Sha256Sampler:
    """Stable rejection sampler for the two complete assignment blocks."""

    def __init__(self, seed: str) -> None:
        if SEED.fullmatch(seed) is None:
            raise ValueError("Invalid assignment randomization seed")
        self.key = hashlib.sha256((PROTOCOL + ":assignment:" + seed).encode()).digest()
        self.counter = 0

    def randbelow(self, stop: int) -> int:
        if type(stop) is not int or stop < 1:
            raise ValueError("Invalid sampler bound")
        limit = 2**64 - (2**64 % stop)
        while True:
            digest = hashlib.sha256(self.key + self.counter.to_bytes(16, "big")).digest()
            self.counter += 1
            value = int.from_bytes(digest[:8], "big")
            if value < limit:
                return value % stop

    def shuffle(self, values: list[str]) -> None:
        for index in range(len(values) - 1, 0, -1):
            other = self.randbelow(index + 1)
            values[index], values[other] = values[other], values[index]


def assignments(contract: dict[str, Any], randomization_seed: str) -> list[dict[str, Any]]:
    sampler = _Sha256Sampler(randomization_seed)
    rows: list[dict[str, Any]] = []
    for block in (1, 2):
        order = list(ARMS)
        sampler.shuffle(order)
        for arm in order:
            rows.append({
                "slot": len(rows) + 1,
                "block": block,
                "arm": arm,
                "seed": contract["block_seeds"][str(block)],
                "factors": contract["design"]["arms"][arm],
            })
    return rows


def build_schedule(
    *, pilot_id: str, created_utc: str, randomization_seed: str,
    frozen_fingerprint: dict[str, Any], contract: dict[str, Any] | None = None,
    seed_horizon_evidence: dict[str, Any] | None = None,
    model_free_preflight: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    pilot_dir(pilot_id)
    contract = contract or load_contract()
    try:
        created = datetime.fromisoformat(created_utc.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Pilot creation time is invalid") from exc
    if created.tzinfo is None:
        raise ValueError("Pilot creation time needs a timezone")
    if not isinstance(frozen_fingerprint, dict):
        raise ValueError("Pilot fingerprint must be an object")
    return {
        "schema_version": 1,
        "pilot_protocol": PROTOCOL,
        "pilot_id": pilot_id,
        "created_utc": created.isoformat(),
        "randomization_seed": randomization_seed,
        "contract_sha256": _sha(CONFIG),
        "contract": contract,
        "fingerprint": frozen_fingerprint,
        "execution_policy": {
            "runs_serial": True,
            "admission_between_runs_only": True,
            "minimum_uncommitted_reserve_usd": "10.000000000",
            "maximum_total_authorization_usd": "100.000000000",
            "active_run_cost_termination_allowed": False,
            "cost_enters_behavioral_outcome": False,
        },
        "seed_horizon_evidence": seed_horizon_evidence or {},
        "model_free_preflight": model_free_preflight or [],
        "assignments": assignments(contract, randomization_seed),
    }


def _seed_horizon(seed: str) -> dict[str, Any]:
    """Verify 500 successful directory observations and an unopened frontier."""
    _, dynamic = load_path_story_fixture(FIXTURE, seed, True)
    _, static = load_path_story_fixture(FIXTURE, seed, False)
    if dynamic.shared_nodes_fingerprint != static.shared_nodes_fingerprint:
        raise ValueError("Static and dynamic authored bases differ for pilot seed")
    session = StorySession(dynamic)
    session.connect()
    queue = deque(sorted(dynamic.spec.expandable_roots))
    selected: list[str] = []
    visited: set[str] = set()
    last_children = 0
    while queue and len(selected) < 500:
        path = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        node = dynamic.node(path)
        if node is None:
            raise ValueError("Generated path vanished during seed preflight")
        if node.metadata.kind is not NodeKind.DIRECTORY:
            continue
        result = session.execute(f"ls {path}")
        if result.exit_code or result.truncated:
            raise ValueError("Seed horizon listing failed or truncated")
        selected.append(path)
        children = dynamic.children(path)
        last_children = len(children)
        for name in children:
            child = posixpath.join(path, name)
            child_node = dynamic.node(child)
            if child_node is not None and child_node.metadata.kind is NodeKind.DIRECTORY:
                queue.append(child)
    if len(selected) != 500 or not queue or last_children < 1:
        raise ValueError("Pilot seed exhausted its 500-action structural horizon")
    return {
        "seed_sha256": hashlib.sha256(seed.encode("utf-8")).hexdigest(),
        "catalog_fingerprint": dynamic.catalog.fingerprint,
        "shared_nodes_fingerprint": dynamic.shared_nodes_fingerprint,
        "successful_distinct_directory_listings": len(selected),
        "unopened_directory_frontier": len(queue),
        "last_action_children": last_children,
        "selected_paths_sha256": hashlib.sha256(
            "\n".join(selected).encode("utf-8")
        ).hexdigest(),
    }


def _docker(args: list[str], *, timeout: int = 1200) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, cwd=LAB, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = result.stderr[-3000:].decode("utf-8", "replace")
        raise RuntimeError(f"Docker command failed ({result.returncode}): {detail}")
    return result


def build_images() -> bytes:
    """Build the three frozen images without starting services or models."""
    args = [
        "docker", "compose", "--profile", "agent",
        "-f", str(BASE_COMPOSE), "-f", str(OVERLAY_COMPOSE),
        "-f", str(PILOT_COMPOSE),
        "build", "filesystem-decoy-2b", "model-gateway", "attacker-agent",
    ]
    result = _docker(args)
    return result.stdout + result.stderr


def _image_id(tag: str) -> str:
    output = _docker(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"], timeout=30
    ).stdout.decode("utf-8", "strict").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", output):
        raise ValueError(f"Image ID for {tag} is missing or malformed")
    return output


def _embedded_task_sha256(agent_image_id: str) -> str:
    script = (
        "import hashlib; from pathlib import Path; "
        "print(hashlib.sha256(Path('/opt/shape/agent_2b_task.json').read_bytes()).hexdigest())"
    )
    digest = _docker(
        [
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
            "--entrypoint", "python", agent_image_id, "-c", script,
        ],
        timeout=30,
    ).stdout.decode("utf-8", "strict").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Attacker image embedded task digest is malformed")
    return digest


def fingerprint() -> dict[str, Any]:
    """Bind task, source tree, images, and passing model-free gate."""
    contract = load_contract()
    pentest_commit, unified_commit = validate_sources()
    images = {role: _image_id(tag) for role, tag in IMAGES.items()}
    embedded_task = _embedded_task_sha256(images["agent"])
    if embedded_task != _sha(TASK):
        raise ValueError("Built attacker image does not contain the unchanged task")
    sources = {name: _sha(path) for name, path in SOURCE_FILES.items()}
    return {
        "schema_version": 1,
        "pilot_protocol": PROTOCOL,
        "contract_sha256": _sha(CONFIG),
        "agent_task_sha256": _sha(TASK),
        "agent_image_task_sha256": embedded_task,
        "fixture_sha256": _sha(FIXTURE),
        "catalog_fingerprint": contract["catalog_fingerprint"],
        "matrix_report_sha256": contract["model_free_gate"]["matrix_report_sha256"],
        "compose_sha256": {
            BASE_COMPOSE.name: _sha(BASE_COMPOSE),
            OVERLAY_COMPOSE.name: _sha(OVERLAY_COMPOSE),
            PILOT_COMPOSE.name: _sha(PILOT_COMPOSE),
        },
        "source_sha256": sources,
        "agent_source_sha256": agent_source_sha256(),
        "pentestgpt_commit": pentest_commit,
        "unified_agent_commit": unified_commit,
        "images": images,
        "runtime_policy": contract["runtime_policy"],
        "trial_caps": contract["trial_caps"],
    }


def prepare(*, randomization_seed: str | None = None) -> dict[str, Any]:
    """Freeze eight assignments with zero authorization and no model calls."""
    contract = load_contract()
    randomization_seed = randomization_seed or secrets.token_hex(16)
    if SEED.fullmatch(randomization_seed) is None:
        raise ValueError("Invalid assignment randomization seed")
    build_log = build_images()
    frozen = fingerprint()
    horizons = {
        block: _seed_horizon(seed)
        for block, seed in contract["block_seeds"].items()
    }
    from experiment_controller.run_2b_path_story_pilot_v2 import preflight_no_model

    preflights = [
        preflight_no_model(
            contract=contract, seed=contract["block_seeds"]["1"], arm="B0"
        ),
        preflight_no_model(
            contract=contract, seed=contract["block_seeds"]["2"], arm="B3"
        ),
    ]
    if any(row.get("model_calls") != 0 or row.get("agent_started") is not False
           or row.get("status") != "passed" for row in preflights):
        raise ValueError("Model-free successor Docker preflight did not pass")
    now = datetime.now(timezone.utc)
    pilot_id = (
        "2b-path-story-pilot-v2-" + now.strftime("%Y%m%d%H%M%S")
        + "-" + secrets.token_hex(3)
    )
    schedule = build_schedule(
        pilot_id=pilot_id,
        created_utc=now.isoformat(),
        randomization_seed=randomization_seed,
        frozen_fingerprint=frozen,
        contract=contract,
        seed_horizon_evidence=horizons,
        model_free_preflight=preflights,
    )
    folder = pilot_dir(pilot_id)
    folder.mkdir(parents=True, mode=0o700)
    _write_new(folder / "build.log", build_log)
    for name in ("review-packets", "annotations", "adjudications", "funding-tranches"):
        (folder / name).mkdir(mode=0o700)
    _write_committed(folder / "schedule.json", schedule)
    funding = {
        "schema_version": 1,
        "pilot_protocol": PROTOCOL,
        "pilot_id": pilot_id,
        "schedule_sha256": _sha(folder / "schedule.json"),
        "opening_authorization_nano_usd": 0,
        "opening_authorization_usd": "0.000000000",
        "tranches": [],
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    _write_committed(folder / "funding.json", funding)
    return schedule


def load_schedule(pilot_id: str) -> dict[str, Any]:
    folder = pilot_dir(pilot_id)
    schedule = _read_committed(folder / "schedule.json")
    contract = load_contract()
    seed = schedule.get("randomization_seed")
    expected_policy = {
        "runs_serial": True,
        "admission_between_runs_only": True,
        "minimum_uncommitted_reserve_usd": "10.000000000",
        "maximum_total_authorization_usd": "100.000000000",
        "active_run_cost_termination_allowed": False,
        "cost_enters_behavioral_outcome": False,
    }
    if (
        schedule.get("schema_version") != 1
        or schedule.get("pilot_protocol") != PROTOCOL
        or schedule.get("pilot_id") != pilot_id
        or schedule.get("contract_sha256") != _sha(CONFIG)
        or schedule.get("contract") != contract
        or not isinstance(seed, str)
        or SEED.fullmatch(seed) is None
        or schedule.get("assignments") != assignments(contract, seed)
        or schedule.get("execution_policy") != expected_policy
        or not isinstance(schedule.get("fingerprint"), dict)
        or schedule["fingerprint"].get("agent_task_sha256") != _sha(TASK)
        or schedule["fingerprint"].get("fixture_sha256") != _sha(FIXTURE)
        or not isinstance(schedule.get("seed_horizon_evidence"), dict)
        or set(schedule["seed_horizon_evidence"]) != {"1", "2"}
        or any(
            not isinstance(row, dict)
            or row.get("successful_distinct_directory_listings") != 500
            or type(row.get("unopened_directory_frontier")) is not int
            or row["unopened_directory_frontier"] < 1
            or type(row.get("last_action_children")) is not int
            or row["last_action_children"] < 1
            or row.get("seed_sha256") != hashlib.sha256(
                contract["block_seeds"][block].encode("utf-8")
            ).hexdigest()
            or row.get("catalog_fingerprint") != contract["catalog_fingerprint"]
            for block, row in schedule["seed_horizon_evidence"].items()
        )
        or not isinstance(schedule.get("model_free_preflight"), list)
        or len(schedule["model_free_preflight"]) != 2
        or [(row.get("arm"), row.get("seed_sha256")) for row in schedule["model_free_preflight"]]
        != [
            ("B0", hashlib.sha256(contract["block_seeds"]["1"].encode()).hexdigest()),
            ("B3", hashlib.sha256(contract["block_seeds"]["2"].encode()).hexdigest()),
        ]
        or any(
            row.get("status") != "passed"
            or row.get("model_calls") != 0
            or row.get("agent_started") is not False
            or row.get("images") != schedule["fingerprint"].get("images")
            for row in schedule["model_free_preflight"]
        )
    ):
        raise PilotIntegrityError("Frozen path-story schedule semantics differ")
    return schedule


def schedule_sha256(pilot_id: str) -> str:
    load_schedule(pilot_id)
    return _sha(pilot_dir(pilot_id) / "schedule.json")


def _funding_base(pilot_id: str) -> dict[str, Any]:
    value = _read_committed(pilot_dir(pilot_id) / "funding.json")
    if value != {
        "schema_version": 1,
        "pilot_protocol": PROTOCOL,
        "pilot_id": pilot_id,
        "schedule_sha256": schedule_sha256(pilot_id),
        "opening_authorization_nano_usd": 0,
        "opening_authorization_usd": "0.000000000",
        "tranches": [],
        "created_utc": value.get("created_utc"),
    }:
        raise PilotIntegrityError("Opening funding ledger differs")
    try:
        created = datetime.fromisoformat(value["created_utc"])
    except (TypeError, ValueError) as exc:
        raise PilotIntegrityError("Opening funding timestamp differs") from exc
    if created.tzinfo is None:
        raise PilotIntegrityError("Opening funding timestamp is not timezone aware")
    return value


def _tranches(pilot_id: str) -> list[dict[str, Any]]:
    base = _funding_base(pilot_id)
    folder = pilot_dir(pilot_id) / "funding-tranches"
    names = sorted(path.name for path in folder.iterdir())
    expected_names: list[str] = []
    count = sum(name.endswith(".json") for name in names)
    for sequence in range(1, count + 1):
        stem = f"{sequence:04d}"
        expected_names.extend((stem + ".json", stem + ".sha256"))
    if names != sorted(expected_names):
        raise PilotIntegrityError("Funding tranche file sequence differs")
    rows: list[dict[str, Any]] = []
    previous_sha = _sha(pilot_dir(pilot_id) / "funding.json")
    for sequence in range(1, count + 1):
        path = folder / f"{sequence:04d}.json"
        row = _read_committed(path)
        amount = row.get("amount_nano_usd")
        if (
            row.get("schema_version") != 1
            or row.get("pilot_id") != pilot_id
            or row.get("schedule_sha256") != base["schedule_sha256"]
            or row.get("sequence") != sequence
            or row.get("prior_sha256") != previous_sha
            or type(amount) is not int
            or amount <= 0
            or row.get("amount_usd") != _format_nano_usd(amount)
            or row.get("authorization_basis") != "user_approved_tranche"
        ):
            raise PilotIntegrityError("Funding tranche semantics differ")
        rows.append(row)
        previous_sha = _sha(path)
    if sum(row["amount_nano_usd"] for row in rows) > AUTHORIZATION_CEILING_NANO_USD:
        raise PilotIntegrityError("Pilot funding exceeds the $100 authorization ceiling")
    return rows


def authorize(pilot_id: str, amount_usd: str) -> dict[str, Any]:
    """Append one explicit authorization; never start a run."""
    load_schedule(pilot_id)
    amount = _usd_to_nano(amount_usd, "authorization tranche")
    if amount <= 0:
        raise ValueError("Authorization tranche must be positive")
    folder = pilot_dir(pilot_id)
    if (folder / "execute.lock").exists() or (folder / "pending-run.json").exists():
        raise PilotIntegrityError("Cannot change funding during an attempt")
    rows = _tranches(pilot_id)
    if sum(row["amount_nano_usd"] for row in rows) + amount > AUTHORIZATION_CEILING_NANO_USD:
        raise ValueError("Authorization would exceed the $100 pilot ceiling")
    sequence = len(rows) + 1
    previous = (
        _sha(folder / "funding.json") if not rows
        else _sha(folder / "funding-tranches" / f"{sequence - 1:04d}.json")
    )
    record = {
        "schema_version": 1,
        "pilot_id": pilot_id,
        "schedule_sha256": schedule_sha256(pilot_id),
        "sequence": sequence,
        "prior_sha256": previous,
        "authorized_utc": datetime.now(timezone.utc).isoformat(),
        "amount_nano_usd": amount,
        "amount_usd": _format_nano_usd(amount),
        "authorization_basis": "user_approved_tranche",
    }
    _write_committed(folder / "funding-tranches" / f"{sequence:04d}.json", record)
    return status(pilot_id)


def _results(pilot_id: str) -> dict[int, list[dict[str, Any]]]:
    """Find only completed attempts assigned to this successor pilot."""
    found: dict[int, list[dict[str, Any]]] = {}
    for path in sorted((LAB / "runs").glob("2b-path-*/result.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PilotIntegrityError(f"Malformed run result: {path}") from exc
        if not isinstance(value, dict):
            raise PilotIntegrityError(f"Run result is not an object: {path}")
        manifest = value.get("manifest")
        if not isinstance(manifest, dict):
            continue
        assignment = manifest.get("assignment")
        if not isinstance(assignment, dict) or assignment.get("pilot_id") != pilot_id:
            continue
        run_id = manifest.get("run_id")
        slot = assignment.get("slot")
        if (
            not isinstance(run_id, str)
            or RUN_ID.fullmatch(run_id) is None
            or path.parent.name != run_id
            or type(slot) is not int
            or not 1 <= slot <= 8
        ):
            raise PilotIntegrityError("Path-story result identity or slot differs")
        found.setdefault(slot, []).append(value)
    for rows in found.values():
        rows.sort(key=lambda value: value["manifest"].get("started_utc", ""))
    return found


def _verify_attempt_artifacts(
    result: dict[str, Any], *, require_gateway: bool = True
) -> Path:
    """Bind the result and every archived file to the attempt manifest."""
    manifest = result.get("manifest")
    if not isinstance(manifest, dict):
        raise PilotIntegrityError("Attempt result lacks a manifest")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise PilotIntegrityError("Attempt run identity is invalid")
    run_dir = LAB / "runs" / run_id
    if run_dir.is_symlink() or not run_dir.is_dir():
        raise PilotIntegrityError("Attempt run directory is missing or unsafe")
    try:
        stored_result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
        stored_manifest = json.loads(
            (run_dir / "attempt-manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PilotIntegrityError("Attempt result or manifest is missing or malformed") from exc
    if (
        stored_result != result
        or stored_manifest != manifest
        or result.get("run_dir") != str(run_dir)
    ):
        raise PilotIntegrityError("Attempt result and manifest differ")
    hashes = manifest.get("artifact_sha256")
    if not isinstance(hashes, dict):
        raise PilotIntegrityError("Attempt artifact inventory is missing")
    if require_gateway and "gateway-events.jsonl" not in hashes:
        raise PilotIntegrityError("Attempt artifact inventory lacks gateway evidence")
    actual: set[str] = set()
    for path in run_dir.rglob("*"):
        if path.is_symlink():
            raise PilotIntegrityError("Attempt archive contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(run_dir).as_posix()
        if relative in {"attempt-manifest.json", "result.json"}:
            continue
        actual.add(relative)
    if set(hashes) != actual:
        raise PilotIntegrityError("Attempt artifact inventory is incomplete")
    for relative, digest in hashes.items():
        path = run_dir / relative
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not path.is_file()
            or path.is_symlink()
            or _sha(path) != digest
        ):
            raise PilotIntegrityError(f"Attempt artifact differs: {relative}")
    return run_dir


def _invalid_reason(
    result: dict[str, Any], schedule: dict[str, Any],
    assignment: dict[str, Any], *, replay: bool = True,
) -> str | None:
    manifest = result.get("manifest")
    if not isinstance(manifest, dict):
        return "missing_required_telemetry"
    run_dir = _verify_attempt_artifacts(result, require_gateway=False)
    expected_assignment = {
        "pilot_id": schedule["pilot_id"],
        "slot": assignment["slot"],
        "block": assignment["block"],
        "arm": assignment["arm"],
        "seed": assignment["seed"],
    }
    frozen = schedule["fingerprint"]
    if (
        manifest.get("assignment") != expected_assignment
        or manifest.get("pilot_protocol") != PROTOCOL
        or manifest.get("environment_protocol") != ENVIRONMENT
        or manifest.get("mode") != "path_story_pilot"
        or manifest.get("arm") != assignment["arm"]
        or manifest.get("seed") != assignment["seed"]
        or manifest.get("pilot_fingerprint") != frozen
        or manifest.get("agent_task_sha256") != frozen["agent_task_sha256"]
        or manifest.get("fixture_sha256") != frozen["fixture_sha256"]
        or manifest.get("images") != frozen["images"]
        or manifest.get("compose_sha256") != frozen["compose_sha256"]
    ):
        return "source_or_image_drift"
    if "gateway-events.jsonl" not in manifest["artifact_sha256"]:
        return "missing_required_telemetry"
    if manifest.get("confirmed_containment_escape_incident") is True:
        raise PilotIntegrityError("Confirmed containment escape incident")
    reason = manifest.get("termination_reason")
    allowed_invalid = set(
        schedule["contract"]["replacement_policy"]["infrastructure_invalid_reasons"]
    )
    if reason in allowed_invalid:
        return reason
    if reason not in TERMINAL_REASONS:
        return "undeclared_terminal_state"
    if manifest.get("error") or manifest.get("path_story_evidence_error"):
        return "controller_error"
    if manifest.get("provider_cost_error"):
        return "model_usage_missing"
    settlement = manifest.get("provider_settlement")
    if not isinstance(settlement, dict) or settlement.get("state") != "complete":
        return "missing_required_telemetry"
    score = result.get("score")
    if (
        not isinstance(score, dict)
        or score.get("pilot_protocol") != PROTOCOL
        or score.get("run_id") != manifest.get("run_id")
        or score.get("arm") != assignment["arm"]
        or score.get("termination_reason") != reason
        or score.get("experimental_result") is not False
    ):
        return "missing_required_telemetry"
    if replay:
        try:
            checked = verify_path_story_bundle(run_dir)
        except Exception:
            return "replay_failure"
        if result.get("replay") != checked:
            return "replay_failure"
    elif not isinstance(result.get("replay"), dict):
        return "replay_failure"
    return None


def _classify(
    schedule: dict[str, Any], found: dict[int, list[dict[str, Any]]],
    *, replay: bool = True,
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    expected_slots = {row["slot"] for row in schedule["assignments"]}
    if set(found) - expected_slots:
        raise PilotIntegrityError("Run result has an unassigned pilot slot")
    valid: dict[int, dict[str, Any]] = {}
    invalid: list[dict[str, Any]] = []
    allowed_invalid = set(
        schedule["contract"]["replacement_policy"]["infrastructure_invalid_reasons"]
    )
    for assignment in schedule["assignments"]:
        slot = assignment["slot"]
        for result in found.get(slot, []):
            reason = _invalid_reason(result, schedule, assignment, replay=replay)
            run_id = result["manifest"]["run_id"]
            if reason is None:
                if slot in valid:
                    raise PilotIntegrityError(f"Slot {slot} has two valid runs")
                valid[slot] = result
            else:
                if reason not in allowed_invalid:
                    raise PilotIntegrityError(f"Unreplaceable pilot violation: {reason}")
                invalid.append({"slot": slot, "run_id": run_id, "reason": reason})
        attempts = [row for row in invalid if row["slot"] == slot]
        maximum = schedule["contract"]["replacement_policy"][
            "maximum_infrastructure_invalid_replacements_per_slot"
        ]
        if len(attempts) > maximum:
            raise PilotIntegrityError(f"Slot {slot} exhausted replacement budget")
    return valid, invalid


def _reconcile_gateway_requests(
    events: list[dict[str, Any]], settlement: dict[str, Any]
) -> None:
    """Independently prove each started upstream request has one terminal event."""
    started: set[int] = set()
    finished: set[int] = set()
    for sequence, row in enumerate(events, 1):
        if row.get("sequence") != sequence:
            raise ValueError("Gateway journal event sequence differs")
        kind = row.get("event_type")
        request_event = (
            kind in {"model_call", "gateway_error", "cap_reached", "request_rejected"}
            or isinstance(kind, str) and kind.startswith("provider_rate_limit_")
        )
        # The gateway journals a rejected GET without entering do_POST. It
        # cannot contact the provider and therefore has no request lifecycle.
        rejected_get = kind == "request_rejected" and row.get("method") == "GET"
        if request_event and not rejected_get and "request_id" not in row:
            raise ValueError("Gateway request event lacks request ID")
        if "request_id" in row and kind not in {
            "request_started", "request_finished", "request_aborted"
        }:
            request_id = row["request_id"]
            if type(request_id) is not int or request_id not in started or request_id in finished:
                raise ValueError("Gateway event lacks an active request start")
        if kind not in {"request_started", "request_finished", "request_aborted"}:
            continue
        request_id = row.get("request_id")
        if type(request_id) is not int or request_id < 1:
            raise ValueError("Gateway request lifecycle has an invalid request ID")
        if kind == "request_started":
            if request_id in started or request_id in finished:
                raise ValueError("Gateway request lifecycle has a duplicate start")
            started.add(request_id)
        elif kind == "request_finished":
            if request_id not in started or request_id in finished:
                raise ValueError("Gateway request lifecycle has a missing or duplicate finish")
            finished.add(request_id)
        else:
            raise ValueError("Gateway request lifecycle contains an aborted request")
    if started != finished:
        raise ValueError("Gateway request lifecycle is unsettled")
    if (
        settlement.get("started_request_count") != len(started)
        or settlement.get("finished_request_count") != len(finished)
        or settlement.get("aborted_request_ids") != []
        or settlement.get("unmatched_request_ids") != []
    ):
        raise ValueError("Provider settlement manifest differs from gateway journal")


def _cost_snapshot(
    pilot_id: str, found: dict[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    contract = load_contract()
    tranches = _tranches(pilot_id)
    authorized = sum(row["amount_nano_usd"] for row in tranches)
    accrued = 0
    priced = 0
    errors: list[dict[str, str]] = []
    evidence: list[dict[str, Any]] = []
    for slot in sorted(found):
        for result in found[slot]:
            run_id = result["manifest"]["run_id"]
            try:
                run_dir = _verify_attempt_artifacts(result)
                settlement = result["manifest"].get("provider_settlement")
                if (
                    not isinstance(settlement, dict)
                    or settlement.get("state") != "complete"
                    or settlement.get("unmatched_request_ids") != []
                    or settlement.get("aborted_request_ids") != []
                    or settlement.get("max_wait_seconds") != 190
                    or not isinstance(settlement.get("quiet_seconds_observed"), (int, float))
                    or isinstance(settlement.get("quiet_seconds_observed"), bool)
                    or settlement["quiet_seconds_observed"] < 5
                    or type(settlement.get("started_request_count")) is not int
                    or type(settlement.get("finished_request_count")) is not int
                    or settlement["started_request_count"]
                    != settlement["finished_request_count"]
                ):
                    raise ValueError("Provider settlement is incomplete")
                path = run_dir / "gateway-events.jsonl"
                lines = path.read_text(encoding="utf-8").splitlines()
                events = [json.loads(line) for line in lines if line.strip()]
                if any(not isinstance(row, dict) for row in events):
                    raise ValueError("Gateway journal has a non-object row")
                _reconcile_gateway_requests(events, settlement)
                if any(row.get("event_type") == "gateway_error" for row in events):
                    raise ValueError(
                        "Gateway transport error has unpriced provider exposure"
                    )
                estimate = estimate_gateway_events_cost(
                    events, contract["provider_cost_governance"]
                )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError, PilotIntegrityError) as exc:
                errors.append({"run_id": run_id, "reason": str(exc)})
                continue
            accrued += estimate["estimated_cost_nano_usd"]
            priced += 1
            evidence.append({
                "run_id": run_id,
                "gateway_events_sha256": _sha(path),
                "estimated_cost_nano_usd": estimate["estimated_cost_nano_usd"],
                "estimated_cost_usd": estimate["estimated_cost_usd"],
            })
    governance = {
        "pilot_authorization_usd": _format_nano_usd(authorized),
        "minimum_uncommitted_reserve_per_new_run_usd": "10.000000000",
    }
    admission = admission_decision(accrued, governance)
    if errors:
        admission["state"] = "paused_incomplete_cost_evidence"
        admission["may_start_new_run"] = False
    elif not tranches:
        admission["state"] = "awaiting_authorization"
        admission["may_start_new_run"] = False
    return {
        "accounting_state": "complete" if not errors else "incomplete",
        "state": admission["state"],
        "may_start_new_run": admission["may_start_new_run"],
        "authorized_usd": _format_nano_usd(authorized),
        "authorization_ceiling_usd": "100.000000000",
        "accrued_usd": _format_nano_usd(accrued),
        "accrued_over_authorization_usd": _format_nano_usd(max(0, accrued - authorized)),
        "remaining_usd": admission["remaining_authorization_usd"],
        "required_reserve_usd": "10.000000000",
        "attempts_priced": priced,
        "errors": errors,
        "evidence": evidence,
        "tranches": tranches,
        "active_run_termination_allowed": False,
        "creates_trial_attempt": False,
        "creates_censored_outcome": False,
    }


def _pending(pilot_id: str) -> dict[str, Any] | None:
    path = pilot_dir(pilot_id) / "pending-run.json"
    if not path.exists() and not path.with_suffix(".sha256").exists():
        return None
    return _read_committed(path)


def _rate_limit_pause(pilot_id: str) -> dict[str, Any] | None:
    path = pilot_dir(pilot_id) / "provider-rate-limit-pause.json"
    if not path.exists() and not path.with_suffix(".sha256").exists():
        return None
    value = _read_committed(path)
    if (
        value.get("pilot_id") != pilot_id
        or value.get("schedule_sha256") != schedule_sha256(pilot_id)
        or not isinstance(value.get("run_id"), str)
        or RUN_ID.fullmatch(value["run_id"]) is None
    ):
        raise PilotIntegrityError("Provider rate-limit pause identity differs")
    return value


def _record_rate_limit_pause(pilot_id: str, run_id: str) -> None:
    existing = _rate_limit_pause(pilot_id)
    if existing is not None:
        if existing.get("run_id") == run_id:
            return
        raise PilotIntegrityError("Provider rate-limit pause is already active")
    _write_committed(
        pilot_dir(pilot_id) / "provider-rate-limit-pause.json",
        {
            "schema_version": 1,
            "pilot_id": pilot_id,
            "schedule_sha256": schedule_sha256(pilot_id),
            "run_id": run_id,
            "paused_utc": datetime.now(timezone.utc).isoformat(),
            "reason": "provider_rate_limit",
        },
    )


def resume_rate_limit(pilot_id: str) -> dict[str, Any]:
    """Archive a provider pause after its external cause has been resolved."""
    pause = _rate_limit_pause(pilot_id)
    if pause is None:
        return status(pilot_id)
    folder = pilot_dir(pilot_id)
    if (folder / "execute.lock").exists() or _pending(pilot_id) is not None:
        raise PilotIntegrityError("Cannot resume while a pilot attempt is active")
    history = folder / "provider-rate-limit-history"
    history.mkdir(mode=0o700, exist_ok=True)
    source = folder / "provider-rate-limit-pause.json"
    target = history / f"{pause['run_id']}.json"
    if target.exists() or target.with_suffix(".sha256").exists():
        raise PilotIntegrityError("Provider rate-limit pause was already archived")
    os.replace(source, target)
    os.replace(source.with_suffix(".sha256"), target.with_suffix(".sha256"))
    return status(pilot_id)


def status(pilot_id: str) -> dict[str, Any]:
    schedule = load_schedule(pilot_id)
    found = _results(pilot_id)
    valid, invalid = _classify(schedule, found)
    cost = _cost_snapshot(pilot_id, found)
    pending = _pending(pilot_id)
    rate_pause = _rate_limit_pause(pilot_id)
    next_slot = next(
        (row["slot"] for row in schedule["assignments"] if row["slot"] not in valid),
        None,
    )
    if pending is not None:
        phase = "pending_attempt_reconciliation"
    elif rate_pause is not None:
        phase = "paused_provider_rate_limit"
    elif next_slot is None:
        phase = "execution_complete_awaiting_annotation"
    elif cost["state"] == "awaiting_authorization":
        phase = "awaiting_authorization"
    elif cost["may_start_new_run"]:
        phase = "execution_enabled"
    else:
        phase = "paused_provider_cost_admission"
    if rate_pause is not None:
        cost["state"] = "paused_provider_rate_limit"
        cost["may_start_new_run"] = False
    return {
        "pilot_id": pilot_id,
        "pilot_protocol": PROTOCOL,
        "phase": phase,
        "schedule_sha256": schedule_sha256(pilot_id),
        "scheduled_runs": 8,
        "valid_runs": len(valid),
        "completed_slots": sorted(valid),
        "invalid_attempts": invalid,
        "next_slot": next_slot,
        "pending_run": pending,
        "provider_rate_limit_pause": rate_pause,
        "funding": cost,
        "ready_for_review": next_slot is None,
    }


def _write_pending(pilot_id: str, assignment: dict[str, Any], run_id: str) -> None:
    path = pilot_dir(pilot_id) / "pending-run.json"
    if path.exists() or path.with_suffix(".sha256").exists():
        raise PilotIntegrityError("Another path-story attempt is pending")
    record = {
        "schema_version": 1,
        "pilot_id": pilot_id,
        "schedule_sha256": schedule_sha256(pilot_id),
        "assignment": assignment,
        "run_id": run_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    _write_committed(path, record)


def reconcile_pending(pilot_id: str) -> dict[str, Any]:
    """Clear a completed attempt pointer after validating its frozen identity."""
    schedule = load_schedule(pilot_id)
    pending = _pending(pilot_id)
    if pending is None:
        return status(pilot_id)
    if pending.get("pilot_id") != pilot_id or pending.get("schedule_sha256") != schedule_sha256(pilot_id):
        raise PilotIntegrityError("Pending attempt identity differs")
    assignment = pending.get("assignment")
    if assignment not in schedule["assignments"]:
        raise PilotIntegrityError("Pending attempt assignment differs")
    found = _results(pilot_id)
    matches = [
        row for row in found.get(assignment["slot"], [])
        if row["manifest"].get("run_id") == pending.get("run_id")
    ]
    if len(matches) != 1:
        raise PilotIntegrityError("Pending attempt lacks exactly one completed result")
    reason = _invalid_reason(matches[0], schedule, assignment)
    folder = pilot_dir(pilot_id)
    pending_path = folder / "pending-run.json"
    archive = folder / "pending-history"
    archive.mkdir(mode=0o700, exist_ok=True)
    target = archive / f"{pending['run_id']}.json"
    if target.exists() or target.with_suffix(".sha256").exists():
        raise PilotIntegrityError("Pending attempt was already reconciled")
    if reason == "provider_rate_limit":
        _record_rate_limit_pause(pilot_id, pending["run_id"])
    os.replace(pending_path, target)
    os.replace(pending_path.with_suffix(".sha256"), target.with_suffix(".sha256"))
    return status(pilot_id)


def execute(pilot_id: str, *, max_new_runs: int | None = None) -> dict[str, Any]:
    """Run frozen slots only after explicit funding, checking cost between runs."""
    schedule = load_schedule(pilot_id)
    if max_new_runs is not None and (type(max_new_runs) is not int or max_new_runs < 1):
        raise ValueError("max_new_runs must be a positive integer")
    # This check precedes image inspection, key access, Docker starts and the
    # runner import. A prepared zero-funded schedule has no model side effect.
    if not _tranches(pilot_id):
        raise PilotIntegrityError("Pilot awaits an explicit provider authorization tranche")
    opening = status(pilot_id)
    if opening["pending_run"] is not None:
        raise PilotIntegrityError("Pending attempt must be reconciled first")
    if opening["provider_rate_limit_pause"] is not None:
        return opening
    if not opening["funding"]["may_start_new_run"]:
        return opening
    if fingerprint() != schedule["fingerprint"]:
        raise PilotIntegrityError("Pilot source or image fingerprint changed after freeze")
    from experiment_controller.run_2b_path_story_pilot_v2 import run_path_story_pilot

    folder = pilot_dir(pilot_id)
    descriptor = os.open(folder / "execute.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    created = 0
    try:
        for assignment in schedule["assignments"]:
            while True:
                observed = status(pilot_id)
                if assignment["slot"] in observed["completed_slots"]:
                    break
                if observed["pending_run"] is not None:
                    raise PilotIntegrityError("Pending attempt must be reconciled first")
                if max_new_runs is not None and created >= max_new_runs:
                    return observed
                if not observed["funding"]["may_start_new_run"]:
                    return observed
                run_id = (
                    "2b-path-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                    + "-" + secrets.token_hex(3)
                )
                _write_pending(pilot_id, assignment, run_id)
                result = run_path_story_pilot(
                    pilot_id=pilot_id,
                    slot=assignment["slot"],
                    block=assignment["block"],
                    arm=assignment["arm"],
                    seed=assignment["seed"],
                    run_id=run_id,
                    frozen_fingerprint=schedule["fingerprint"],
                    contract=schedule["contract"],
                )
                created += 1
                reason = _invalid_reason(result, schedule, assignment)
                reconcile_pending(pilot_id)
                if reason == "provider_rate_limit":
                    return status(pilot_id)
    finally:
        (folder / "execute.lock").unlink(missing_ok=True)
    return status(pilot_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--randomization-seed")
    for name in ("status", "execute", "reconcile"):
        command = sub.add_parser(name)
        command.add_argument("--pilot-id", required=True)
        if name == "execute":
            command.add_argument("--max-new-runs", type=int)
    authorize_parser = sub.add_parser("authorize")
    authorize_parser.add_argument("--pilot-id", required=True)
    authorize_parser.add_argument("--amount-usd", required=True)
    resume_parser = sub.add_parser("resume-rate-limit")
    resume_parser.add_argument("--pilot-id", required=True)
    args = parser.parse_args()
    if args.action == "prepare":
        value = prepare(randomization_seed=args.randomization_seed)
        output = {
            "pilot_id": value["pilot_id"],
            "pilot_protocol": PROTOCOL,
            "scheduled_runs": len(value["assignments"]),
            "schedule_sha256": schedule_sha256(value["pilot_id"]),
            "funding_state": "awaiting_authorization",
            "model_calls": 0,
        }
    elif args.action == "status":
        output = status(args.pilot_id)
    elif args.action == "execute":
        output = execute(args.pilot_id, max_new_runs=args.max_new_runs)
    elif args.action == "reconcile":
        output = reconcile_pending(args.pilot_id)
    elif args.action == "resume-rate-limit":
        output = resume_rate_limit(args.pilot_id)
    else:
        output = authorize(args.pilot_id, args.amount_usd)
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
