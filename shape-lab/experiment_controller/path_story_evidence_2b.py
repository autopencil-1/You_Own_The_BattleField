"""Archive one model-free path-story 2B journal under a versioned contract.

This successor helper does not modify or interpret controlled-v3 archives. It
copies the exact fixture, task, source and event bytes needed for later replay.
The trial seed is stored privately; public evidence carries its commitment.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
from typing import Any, Iterable

from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server import ARMS
from filesystem_decoy_2b.virtual_fs import MAX_SEARCH_DEPTH, MAX_SEARCH_NODES


LAB = Path(__file__).resolve().parents[1]
EVIDENCE_VERSION = "path-story-evidence-v1"
TARGET = "ssh://lab@filesystem-decoy-2b"
TASK = LAB / "config" / "agent_2b_task.json"
SOURCE_FILES = {
    "source/semantic_v2.py": LAB / "filesystem_decoy_2b" / "semantic_v2.py",
    "source/path_story_fs.py": LAB / "filesystem_decoy_2b" / "path_story_fs.py",
    "source/server_path_story.py": LAB / "filesystem_decoy_2b" / "server_path_story.py",
    "source/virtual_fs.py": LAB / "filesystem_decoy_2b" / "virtual_fs.py",
    "source/server.py": LAB / "filesystem_decoy_2b" / "server.py",
    "source/ssh_tools_2b_path_story.py": LAB / "agent_runner" / "ssh_tools_2b_path_story.py",
    "source/ssh_tools_2b.py": LAB / "agent_runner" / "ssh_tools_2b.py",
    "source/entrypoint_2b_path_story.py": LAB / "agent_runner" / "entrypoint_2b_path_story.py",
    "source/runtime_policy_2b.py": LAB / "agent_runner" / "runtime_policy_2b.py",
    "source/path_story_evidence_2b.py": LAB / "experiment_controller" / "path_story_evidence_2b.py",
    "source/replay_2b_path_story.py": LAB / "telemetry" / "replay_2b_path_story.py",
}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _private_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _event_bytes(
    *, event_lines: Iterable[str] | None, event_path: Path | None
) -> bytes:
    if (event_lines is None) == (event_path is None):
        raise ValueError("Supply exactly one of event_lines or event_path")
    if event_path is not None:
        content = event_path.read_bytes()
    else:
        values = list(event_lines or ())
        if not values or any(not isinstance(line, str) for line in values):
            raise ValueError("Event lines must be nonempty UTF-8 strings")
        content = "".join(line if line.endswith("\n") else line + "\n" for line in values).encode(
            "utf-8"
        )
    if not content or not content.endswith(b"\n") or b"\r" in content:
        raise ValueError("Decoy journal must be nonempty newline-delimited UTF-8")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decoy journal is not UTF-8") from exc
    return content


def _events(content: bytes, *, run_id: str, arm: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sequence, line in enumerate(content.splitlines(), 1):
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Malformed decoy event at line {sequence}") from exc
        if (
            not isinstance(row, dict)
            or row.get("sequence") != sequence
            or row.get("run_id") != run_id
            or row.get("condition") != arm
            or row.get("experiment") != "2B"
        ):
            raise ValueError(f"Decoy event {sequence} identity or order differs")
        rows.append(row)
    if not rows or rows[0].get("event_type") != "path_story_profile_loaded":
        raise ValueError("Decoy journal lacks its first profile event")
    if sum(row.get("event_type") == "path_story_profile_loaded" for row in rows) != 1:
        raise ValueError("Decoy journal must contain exactly one profile event")
    return rows


def _expected_resource_policy(fs: Any, max_commands: int, reinforcement_every: int) -> dict[str, int]:
    limits = fs.catalog.limits
    return {
        "max_depth": limits.max_depth,
        "max_path_chars": limits.max_path_chars,
        "max_content_bytes": limits.max_content_bytes,
        "max_cached_nodes": limits.max_cached_nodes,
        "max_children": limits.max_children,
        "max_search_depth": MAX_SEARCH_DEPTH,
        "max_search_nodes": MAX_SEARCH_NODES,
        "max_output_chars": fs.max_output_chars,
        "max_commands": max_commands,
        "reinforcement_every": reinforcement_every,
    }


def _inventory(events: list[dict[str, Any]]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    preceding_response: dict[str, Any] | None = None
    for event in events:
        kind = event.get("event_type")
        if kind == "decoy_response":
            try:
                body = base64.b64decode(event["body_b64"], validate=True)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("Archived response has invalid bytes") from exc
            if sha256_bytes(body) != event.get("body_sha256"):
                raise ValueError("Archived response hash differs")
            preceding_response = event
        elif kind == "filesystem_materialized":
            required = (
                "inventory_index",
                "response_sequence",
                "response_sha256",
                "path",
                "node_sha256",
            )
            if (
                event.get("evidence_version") != EVIDENCE_VERSION
                or any(key not in event for key in required)
                or not isinstance(event["inventory_index"], int)
                or isinstance(event["inventory_index"], bool)
                or event["inventory_index"] != len(items) + 1
                or not isinstance(event["response_sequence"], int)
                or isinstance(event["response_sequence"], bool)
                or preceding_response is None
                or event["response_sequence"] != preceding_response["sequence"]
                or preceding_response.get("status") != 200
                or preceding_response.get("route") != "/exec"
                or event["response_sha256"] != preceding_response["body_sha256"]
                or not isinstance(event["path"], str)
                or not event["path"].startswith("/")
                or posixpath.normpath(event["path"]) != event["path"]
                or event["path"] in seen_paths
                or not isinstance(event["node_sha256"], str)
                or not _HEX.fullmatch(event["node_sha256"])
            ):
                raise ValueError("Materialization event is malformed or unlinked")
            path = event["path"]
            seen_paths.add(path)
            items.append({key: event[key] for key in required})
        elif kind != "filesystem_materialized":
            preceding_response = None
    return {"evidence_version": EVIDENCE_VERSION, "items": items}


def archive_path_story_run(
    run_dir: Path,
    *,
    fixture_path: Path,
    seed: str,
    arm: str,
    run_id: str,
    event_lines: Iterable[str] | None = None,
    event_path: Path | None = None,
    max_commands: int = 50,
) -> dict[str, Any]:
    """Write a replayable, private successor evidence bundle without model calls."""
    run_dir = Path(run_dir)
    fixture_path = Path(fixture_path)
    if not _RUN_ID.fullmatch(run_id) or arm not in ARMS:
        raise ValueError("Invalid path-story run identity")
    if not isinstance(seed, str) or not seed or len(seed) > 128:
        raise ValueError("Invalid path-story seed")
    if (
        not isinstance(max_commands, int)
        or isinstance(max_commands, bool)
        or not 1 <= max_commands <= 500
    ):
        raise ValueError("Invalid command cap")
    if (run_dir / "manifest.json").exists():
        raise ValueError("Path-story archive is already finalized")
    fixture_bytes = fixture_path.read_bytes()
    source_bytes = {name: path.read_bytes() for name, path in SOURCE_FILES.items()}
    source_sha256 = {name: sha256_bytes(content) for name, content in source_bytes.items()}
    generator_fingerprint = source_sha256["source/path_story_fs.py"]
    generator_code_fingerprint = sha256_bytes(
        _canonical(
            {
                "path_story_fs.py": generator_fingerprint,
                "semantic_v2.py": source_sha256["source/semantic_v2.py"],
            }
        )
    )
    _, fs = load_path_story_fixture(fixture_path, seed, dynamic=ARMS[arm][0])
    _, static_fs = load_path_story_fixture(fixture_path, seed, dynamic=False)
    _, dynamic_fs = load_path_story_fixture(fixture_path, seed, dynamic=True)
    if static_fs.shared_nodes_fingerprint != dynamic_fs.shared_nodes_fingerprint:
        raise ValueError("Static and dynamic authored bases differ")
    content = _event_bytes(event_lines=event_lines, event_path=event_path)
    events = _events(content, run_id=run_id, arm=arm)
    startup = events[0]
    observed_policy = startup.get("resource_policy")
    if not isinstance(observed_policy, dict):
        raise ValueError("Startup event lacks resource policy")
    reinforcement_every = observed_policy.get("reinforcement_every")
    if (
        not isinstance(reinforcement_every, int)
        or isinstance(reinforcement_every, bool)
        or not 1 <= reinforcement_every <= 50
    ):
        raise ValueError("Invalid reinforcement frequency")
    resource_policy = _expected_resource_policy(fs, max_commands, reinforcement_every)
    expected_startup = {
        "evidence_version": EVIDENCE_VERSION,
        **fs.profile_evidence(),
        "generator_fingerprint": generator_fingerprint,
        "generator_code_fingerprint": generator_code_fingerprint,
        "identity": {"username": fs.spec.username, "hostname": fs.spec.hostname},
        "resource_policy": resource_policy,
    }
    if any(startup.get(key) != value for key, value in expected_startup.items()):
        raise ValueError("Runtime path-story profile differs from archived inputs")
    inventory = _inventory(events)
    if inventory["items"] and not ARMS[arm][0]:
        raise ValueError("Static arm cannot materialize generated nodes")
    for item in inventory["items"]:
        path = item["path"]
        if path in fs.spec.nodes or fs.node_fingerprint(path) != item["node_sha256"]:
            raise ValueError("Materialized node differs from archived fixture and seed")
    profile = {
        **expected_startup,
        "expandable_roots": sorted(fs.spec.expandable_roots),
        "visibility_contract": {
            "generated_visible": ARMS[arm][0],
            "authored_base_parity": True,
        },
    }
    task_bytes = TASK.read_bytes()
    artifacts: dict[str, bytes] = {
        "fixture.json": fixture_bytes,
        "seed.txt": (seed + "\n").encode("utf-8"),
        "task.json": task_bytes,
        "decoy-events.jsonl": content,
        "filesystem-profile-v2.json": _json_bytes(profile),
        "materialization-inventory.json": _json_bytes(inventory),
        **source_bytes,
    }
    manifest = {
        "evidence_version": EVIDENCE_VERSION,
        "run_id": run_id,
        "arm": arm,
        "target": TARGET,
        "max_commands": max_commands,
        "seed_sha256": sha256_bytes(seed.encode("utf-8")),
        "fixture_sha256": sha256_bytes(fixture_bytes),
        "task_sha256": sha256_bytes(task_bytes),
        "catalog_fingerprint": fs.catalog.fingerprint,
        "generator_version": fs.catalog.generator_version,
        "generator_fingerprint": generator_fingerprint,
        "generator_code_fingerprint": generator_code_fingerprint,
        "shared_nodes_fingerprint": fs.shared_nodes_fingerprint,
        "identity": profile["identity"],
        "resource_policy": resource_policy,
        "source_sha256": source_sha256,
        "event_count": len(events),
        "response_count": sum(row.get("event_type") == "decoy_response" for row in events),
        "materialization_count": len(inventory["items"]),
        "artifact_sha256": {
            name: sha256_bytes(contents) for name, contents in sorted(artifacts.items())
        },
    }
    if run_dir.is_symlink():
        raise ValueError("Run archive directory must not be a symlink")
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    same_event_destination = (
        event_path is not None
        and event_path.resolve() == (run_dir / "decoy-events.jsonl").resolve()
    )
    for name in artifacts:
        destination = run_dir / name
        if destination.exists() and not (name == "decoy-events.jsonl" and same_event_destination):
            raise ValueError(f"Archive artifact already exists: {name}")
    for name, data in artifacts.items():
        destination = run_dir / name
        if name == "decoy-events.jsonl" and same_event_destination:
            if destination.read_bytes() != data:
                raise ValueError("Event source changed during archival")
            os.chmod(destination, 0o600)
            continue
        _private_write(destination, data)
    _private_write(run_dir / "manifest.json", _json_bytes(manifest))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--seed-file", required=True, type=Path)
    parser.add_argument("--arm", required=True, choices=tuple(ARMS))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--max-commands", type=int, default=50)
    args = parser.parse_args()
    seed = args.seed_file.read_text(encoding="utf-8").rstrip("\n")
    result = archive_path_story_run(
        args.run_dir,
        fixture_path=args.fixture,
        seed=seed,
        arm=args.arm,
        run_id=args.run_id,
        event_path=args.events,
        max_commands=args.max_commands,
    )
    print(
        json.dumps(
            {
                "run_id": result["run_id"],
                "arm": result["arm"],
                "evidence_version": result["evidence_version"],
                "materialization_count": result["materialization_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
