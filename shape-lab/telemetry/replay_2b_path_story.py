"""Replay versioned path-story 2B evidence without a model or live service.

The verifier regenerates delivered response bytes and first-delivered lazy
materializations from the archived fixture and seed.  It does not interpret
the frozen controlled-v3 compiled-graph contract.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server import ARMS, MAX_REQUEST_BYTES
from filesystem_decoy_2b.server_path_story import StorySession
from filesystem_decoy_2b.virtual_fs import MAX_SEARCH_DEPTH, MAX_SEARCH_NODES


EVIDENCE_VERSION = "path-story-evidence-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LAB = Path(__file__).resolve().parents[1]
_SOURCES = {
    "source/semantic_v2.py": _LAB / "filesystem_decoy_2b" / "semantic_v2.py",
    "source/path_story_fs.py": _LAB / "filesystem_decoy_2b" / "path_story_fs.py",
    "source/server_path_story.py": _LAB / "filesystem_decoy_2b" / "server_path_story.py",
    "source/virtual_fs.py": _LAB / "filesystem_decoy_2b" / "virtual_fs.py",
    "source/server.py": _LAB / "filesystem_decoy_2b" / "server.py",
    "source/ssh_tools_2b_path_story.py": _LAB / "agent_runner" / "ssh_tools_2b_path_story.py",
    "source/ssh_tools_2b.py": _LAB / "agent_runner" / "ssh_tools_2b.py",
    "source/entrypoint_2b_path_story.py": _LAB / "agent_runner" / "entrypoint_2b_path_story.py",
    "source/runtime_policy_2b.py": _LAB / "agent_runner" / "runtime_policy_2b.py",
    "source/path_story_evidence_2b.py": _LAB / "experiment_controller" / "path_story_evidence_2b.py",
    "source/replay_2b_path_story.py": _LAB / "telemetry" / "replay_2b_path_story.py",
}
_REQUIRED_ARTIFACTS = frozenset(
    {
        "fixture.json",
        "seed.txt",
        "task.json",
        "decoy-events.jsonl",
        "filesystem-profile-v2.json",
        "materialization-inventory.json",
        *_SOURCES,
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is missing or malformed") from exc


def _decoded(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"{label} is invalid base64") from exc


def _source_hashes(run_dir: Path, artifacts: dict[str, str]) -> dict[str, str]:
    hashes = {}
    for name, local_path in _SOURCES.items():
        digest = artifacts[name]
        # The archived byte copy is sufficient evidence of the producing
        # implementation.  Replay uses the installed version of this frozen
        # evidence protocol and rejects a source mismatch rather than running
        # archived code.
        if not local_path.is_file() or _sha256(local_path.read_bytes()) != digest:
            raise ValueError(f"Current replay source differs from archive: {name}")
        hashes[name] = digest
    return hashes


def _validate_archive(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    manifest = _read_json(run_dir / "manifest.json", "Path-story manifest")
    if manifest.get("evidence_version") != EVIDENCE_VERSION:
        raise ValueError("Unsupported path-story evidence version")
    run_id = manifest.get("run_id")
    arm = manifest.get("arm")
    max_commands = manifest.get("max_commands")
    if (
        not isinstance(run_id, str)
        or re.fullmatch(r"[A-Za-z0-9._-]{1,80}", run_id) is None
        or arm not in ARMS
        or not isinstance(max_commands, int)
        or isinstance(max_commands, bool)
        or not 1 <= max_commands <= 500
    ):
        raise ValueError("Path-story manifest identity or command cap is invalid")
    artifacts = _object(manifest.get("artifact_sha256"), "Artifact hash map")
    if not _REQUIRED_ARTIFACTS <= artifacts.keys():
        raise ValueError("Path-story archive lacks required artifacts")
    for name, digest in artifacts.items():
        if (
            not isinstance(name, str)
            or not name
            or name.startswith("/")
            or ".." in Path(name).parts
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise ValueError("Path-story artifact hash map is invalid")
        artifact = run_dir / name
        if (
            not artifact.is_file()
            or artifact.is_symlink()
            or not artifact.resolve().is_relative_to(run_dir.resolve())
        ):
            raise ValueError(f"Path-story artifact is missing or unsafe: {name}")
        if _sha256(artifact.read_bytes()) != digest:
            raise ValueError(f"Path-story artifact hash mismatch: {name}")
    source_hashes = _source_hashes(run_dir, artifacts)
    if manifest.get("source_sha256") != source_hashes:
        raise ValueError("Manifest source inventory differs")
    if _sha256((run_dir / "fixture.json").read_bytes()) != manifest.get("fixture_sha256"):
        raise ValueError("Fixture commitment differs")
    seed_bytes = (run_dir / "seed.txt").read_bytes()
    if not seed_bytes.endswith(b"\n") or seed_bytes.count(b"\n") != 1:
        raise ValueError("Seed artifact is malformed")
    try:
        seed = seed_bytes[:-1].decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Seed artifact is not UTF-8") from exc
    if not seed or _sha256(seed.encode("utf-8")) != manifest.get("seed_sha256"):
        raise ValueError("Seed commitment differs")
    expected_generator = source_hashes["source/path_story_fs.py"]
    expected_code = _sha256(
        _canonical_bytes(
            {
                "path_story_fs.py": expected_generator,
                "semantic_v2.py": source_hashes["source/semantic_v2.py"],
            }
        )
    )
    if (
        manifest.get("generator_fingerprint") != expected_generator
        or manifest.get("generator_code_fingerprint") != expected_code
    ):
        raise ValueError("Generator source commitment differs")
    profile = _read_json(run_dir / "filesystem-profile-v2.json", "Filesystem profile")
    fixture = _read_json(run_dir / "fixture.json", "Archived fixture")
    if _sha256((run_dir / "task.json").read_bytes()) != manifest.get("task_sha256"):
        raise ValueError("Task commitment differs")
    return manifest, profile, seed, fixture


def _profile_expectations(
    run_dir: Path, manifest: dict[str, Any], profile: dict[str, Any], seed: str
) -> tuple[dict[str, Any], Any, StorySession]:
    raw, fs = load_path_story_fixture(
        run_dir / "fixture.json", seed, ARMS[manifest["arm"]][0]
    )
    _, counterpart = load_path_story_fixture(
        run_dir / "fixture.json", seed, not ARMS[manifest["arm"]][0]
    )
    if fs.shared_nodes_fingerprint != counterpart.shared_nodes_fingerprint:
        raise ValueError("Authored-base parity differs between structure arms")
    if not ARMS[manifest["arm"]][0] and any(
        path not in fs.spec.nodes for root in fs.spec.expandable_roots
        for path in (f"{root}/{name}" for name in fs.children(root))
    ):
        raise ValueError("Static structure exposes a generated path")
    policy = {
        "max_depth": fs.catalog.limits.max_depth,
        "max_path_chars": fs.catalog.limits.max_path_chars,
        "max_content_bytes": fs.catalog.limits.max_content_bytes,
        "max_cached_nodes": fs.catalog.limits.max_cached_nodes,
        "max_children": fs.catalog.limits.max_children,
        "max_search_depth": MAX_SEARCH_DEPTH,
        "max_search_nodes": MAX_SEARCH_NODES,
        "max_output_chars": fs.max_output_chars,
        "max_commands": manifest["max_commands"],
        "reinforcement_every": profile.get("resource_policy", {}).get(
            "reinforcement_every"
        ),
    }
    every = policy["reinforcement_every"]
    if not isinstance(every, int) or isinstance(every, bool) or not 1 <= every <= 50:
        raise ValueError("Invalid reinforcement frequency")
    evidence = fs.profile_evidence()
    expected_profile = {
        "evidence_version": EVIDENCE_VERSION,
        **evidence,
        "identity": {"username": fs.spec.username, "hostname": fs.spec.hostname},
        "resource_policy": policy,
        "expandable_roots": sorted(fs.spec.expandable_roots),
        "visibility_contract": {
            "generated_visible": ARMS[manifest["arm"]][0],
            "authored_base_parity": True,
        },
    }
    if profile != expected_profile:
        raise ValueError("Filesystem profile does not regenerate")
    for key in (
        "catalog_fingerprint",
        "generator_version",
        "generator_fingerprint",
        "generator_code_fingerprint",
        "shared_nodes_fingerprint",
        "resource_policy",
    ):
        if manifest.get(key) != expected_profile[key]:
            raise ValueError(f"Manifest profile commitment differs: {key}")
    if manifest.get("identity") != expected_profile["identity"]:
        raise ValueError("Manifest host identity differs")
    if manifest.get("target") != "ssh://lab@filesystem-decoy-2b":
        raise ValueError("Path-story target differs from the pinned task")
    if (run_dir / "task.json").read_bytes() != (
        Path(__file__).resolve().parents[1] / "config" / "agent_2b_task.json"
    ).read_bytes():
        raise ValueError("Archived PentestGPT task differs from the pinned task")
    return raw, fs, StorySession(fs)


def _events(run_dir: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        lines = (run_dir / "decoy-events.jsonl").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("Decoy journal is missing or unreadable") from exc
    events = []
    last_elapsed = -1
    for sequence, line in enumerate(lines, 1):
        try:
            event = _object(json.loads(line), "Decoy event")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Decoy event {sequence} is malformed") from exc
        if (
            type(event.get("sequence")) is not int
            or event["sequence"] != sequence
            or event.get("run_id") != manifest["run_id"]
            or event.get("condition") != manifest["arm"]
            or event.get("experiment") != "2B"
            or event.get("source") != "filesystem-decoy-2b"
            or not isinstance(event.get("elapsed_ms"), int)
            or isinstance(event["elapsed_ms"], bool)
            or event["elapsed_ms"] < 0
            or event["elapsed_ms"] < last_elapsed
        ):
            raise ValueError("Decoy event sequence or identity differs")
        last_elapsed = event["elapsed_ms"]
        try:
            if datetime.fromisoformat(event["timestamp_utc"].replace("Z", "+00:00")).tzinfo is None:
                raise ValueError
        except (KeyError, AttributeError, ValueError) as exc:
            raise ValueError("Decoy event timestamp is invalid") from exc
        events.append(event)
    if not events or events[0].get("event_type") != "path_story_profile_loaded":
        raise ValueError("Path-story startup profile event is missing")
    return events


@dataclass
class _Response:
    status: int
    payload: dict[str, Any]
    command: str | None
    new_connection: bool
    capture_active: bool


class _Simulator:
    def __init__(
        self, session: StorySession, fs: Any, manifest: dict[str, Any], raw: dict[str, Any]
    ) -> None:
        self.session = session
        self.fs = fs
        self.manifest = manifest
        self.raw = raw
        self.command_count = 0
        self.qualifying_count = 0
        self.reinforcement_every = manifest["resource_policy"]["reinforcement_every"]
        self.snapshot: tuple[Any, ...] | None = None

    def predict(self, request: dict[str, Any]) -> _Response:
        route = request.get("route")
        if not isinstance(route, str) or not route.startswith("/") or len(route) > 256:
            raise ValueError("Invalid journaled request route")
        self.snapshot = (
            self.session.connected,
            self.session.cwd,
            self.session.previous_cwd,
            self.command_count,
            self.qualifying_count,
        )
        length = request.get("content_length")
        if length is not None and type(length) is not int:
            raise ValueError("Request Content-Length evidence is invalid")
        bounded = isinstance(length, int) and not isinstance(length, bool) and 0 <= length <= MAX_REQUEST_BYTES
        if bounded:
            body = _decoded(request.get("request_body_b64"), "Request body")
            if len(body) > length:
                raise ValueError("Request byte count exceeds Content-Length")
        else:
            if "request_body_b64" in request:
                raise ValueError("Rejected request unexpectedly archives body bytes")
            body = b""
        if route not in {"/connect", "/exec"}:
            return _Response(404, {"error": "not_found"}, None, False, False)
        if not bounded:
            return _Response(413, {"error": "request_size"}, None, False, False)
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            return _Response(400, {"error": "invalid_json"}, None, False, False)
        if not isinstance(data, dict):
            return _Response(400, {"error": "invalid_request"}, None, False, False)
        if route == "/connect":
            if set(data) != {"target"} or data["target"] != self.manifest["target"]:
                return _Response(400, {"error": "target_not_allowed"}, None, False, False)
            first = not self.session.connected
            banner = self.session.connect()
            payload = {
                "output": banner,
                "cwd": self.session.cwd,
                "connected": True,
                "new_connection": first,
            }
            return _Response(200, self._present(payload), None, first, False)
        if set(data) != {"command"} or not isinstance(data["command"], str):
            return _Response(400, {"error": "invalid_command"}, None, False, False)
        if not self.session.connected:
            return _Response(409, {"error": "connection_required"}, None, False, False)
        if self.command_count >= self.manifest["max_commands"]:
            return _Response(429, {"error": "command_cap_reached"}, None, False, False)
        self.fs.begin_materialization_capture()
        result = self.session.execute(data["command"])
        self.command_count += 1
        output = result.output
        output_truncated = result.truncated
        reinforced = False
        if result.exit_code == 0 and result.action in {"ls", "cat", "head"}:
            self.qualifying_count += 1
            if (
                ARMS[self.manifest["arm"]][1]
                and self.qualifying_count % self.reinforcement_every == 0
            ):
                note = (
                    ("\n" if output and not output.endswith("\n") else "")
                    + self.raw.get("reinforcement_text", "")
                    + "\n"
                )
                if len(output) + len(note) <= self.fs.max_output_chars:
                    output += note
                    reinforced = True
        if len(output) > self.fs.max_output_chars:
            marker = "\n[virtual output truncated]\n"
            output = output[: self.fs.max_output_chars - len(marker)] + marker
            output_truncated = True
        payload = {
            "output": output,
            "exit_code": result.exit_code,
            "action": result.action,
            "target": result.target,
            "cwd_before": result.cwd_before,
            "cwd_after": result.cwd_after,
            "truncated": output_truncated,
            "reinforcement_delivered": reinforced,
        }
        return _Response(200, self._present(payload), data["command"], False, True)

    def _present(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload["identity"] = {
            "username": self.fs.spec.username,
            "hostname": self.fs.spec.hostname,
        }
        if payload.get("truncated") and isinstance(payload.get("output"), str):
            payload["output"] = payload["output"].replace(
                "[virtual output truncated]", "[output truncated]"
            )
        return payload

    def rollback(self) -> None:
        if self.snapshot is None:
            raise ValueError("No request state is available for rollback")
        (
            self.session.connected,
            self.session.cwd,
            self.session.previous_cwd,
            self.command_count,
            self.qualifying_count,
        ) = self.snapshot
        self.fs.discard_materialization_capture()
        self.snapshot = None

    def accepted(self) -> None:
        self.snapshot = None


def _compare_fields(event: dict[str, Any], fields: dict[str, Any], label: str) -> None:
    for key, value in fields.items():
        if event.get(key) != value:
            raise ValueError(f"{label} differs: {key}")


def _verified_responses(
    events: list[dict[str, Any]], manifest: dict[str, Any], profile: dict[str, Any],
    session: StorySession, fs: Any, raw: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    startup_fields = {
        key: profile[key]
        for key in (
            "evidence_version", "filesystem_schema_version", "semantic_schema_version",
            "generator_version", "generator_fingerprint", "generator_code_fingerprint",
            "catalog_fingerprint", "seed_fingerprint", "shared_nodes_fingerprint",
            "explicit_node_count", "identity", "resource_policy",
        )
    }
    _compare_fields(events[0], startup_fields, "Runtime profile")
    simulator = _Simulator(session, fs, manifest, raw)
    responses: list[dict[str, Any]] = []
    materializations: list[dict[str, Any]] = []
    position = 1
    while position < len(events):
        request = events[position]
        if request.get("event_type") != "decoy_request":
            raise ValueError("Decoy request chronology is invalid")
        predicted = simulator.predict(request)
        position += 1
        if position >= len(events):
            raise ValueError("Decoy request lacks a terminal event")
        event = events[position]
        if event.get("event_type") == "response_write_failed":
            if event.get("route") != request.get("route") or not isinstance(event.get("error_type"), str):
                raise ValueError("Response write-failure event differs")
            simulator.rollback()
            position += 1
            continue
        if event.get("event_type") != "decoy_response":
            raise ValueError("Decoy request lacks a response")
        body = _decoded(event.get("body_b64"), "Response body")
        expected_body = _canonical_bytes(predicted.payload)
        if (
            event.get("route") != request.get("route")
            or event.get("status") != predicted.status
            or event.get("body_sha256") != _sha256(body)
            or body != expected_body
        ):
            raise ValueError("Delivered response does not reproduce byte for byte")
        response_sha = _sha256(body)
        response_sequence = event["sequence"]
        responses.append({
            "route": request["route"],
            "request_body_b64": request.get("request_body_b64"),
            "status": predicted.status,
            "body": body,
        })
        position += 1
        expected_items = (
            fs.commit_materialization_capture(
                response_sequence=response_sequence, response_sha256=response_sha
            )
            if predicted.capture_active
            else ()
        )
        for item in expected_items:
            if position >= len(events) or events[position].get("event_type") != "filesystem_materialized":
                raise ValueError("Committed materialization event is missing")
            row = events[position]
            _compare_fields(row, {"evidence_version": EVIDENCE_VERSION, **item}, "Materialization")
            materializations.append(dict(item))
            position += 1
        if position < len(events) and events[position].get("event_type") == "filesystem_materialized":
            raise ValueError("Unexpected materialization event")
        if predicted.new_connection:
            if position >= len(events) or events[position].get("event_type") != "ssh_connected":
                raise ValueError("SSH connection event is missing")
            _compare_fields(
                events[position],
                {"target": manifest["target"], "cwd": session.cwd},
                "SSH connection",
            )
            position += 1
        if predicted.command is not None:
            if position >= len(events) or events[position].get("event_type") != "filesystem_interaction":
                raise ValueError("Filesystem interaction event is missing")
            interaction = events[position]
            _compare_fields(
                interaction,
                {
                    "command": predicted.command,
                    **{
                        key: predicted.payload[key]
                        for key in (
                            "action", "target", "cwd_before", "cwd_after",
                            "exit_code", "truncated",
                        )
                    },
                },
                "Filesystem interaction",
            )
            position += 1
            if predicted.payload["reinforcement_delivered"]:
                if position >= len(events) or events[position].get("event_type") != "reinforcement_delivered":
                    raise ValueError("Reinforcement event is missing")
                _compare_fields(
                    events[position],
                    {
                        "command_count": simulator.command_count,
                        "response_sha256": _sha256(predicted.payload["output"].encode()),
                    },
                    "Reinforcement",
                )
                position += 1
        simulator.accepted()
    return responses, materializations, simulator.command_count


def verify_path_story_bundle(run_dir: str | Path) -> dict[str, Any]:
    """Fail closed if any archived byte or generated observation differs."""
    run_dir = Path(run_dir)
    manifest, profile, seed, _ = _validate_archive(run_dir)
    raw, fs, session = _profile_expectations(run_dir, manifest, profile, seed)
    events = _events(run_dir, manifest)
    if manifest.get("event_count") != len(events):
        raise ValueError("Manifest event count differs")
    responses, observed, actions = _verified_responses(
        events, manifest, profile, session, fs, raw
    )
    if (
        manifest.get("response_count") != len(responses)
        or manifest.get("materialization_count") != len(observed)
    ):
        raise ValueError("Manifest response or materialization count differs")
    inventory = _read_json(
        run_dir / "materialization-inventory.json", "Materialization inventory"
    )
    if inventory != {"evidence_version": EVIDENCE_VERSION, "items": observed}:
        raise ValueError("Final materialization inventory differs")
    if list(fs.committed_inventory()) != observed:
        raise ValueError("Materialization inventory does not match replay state")
    if not ARMS[manifest["arm"]][0] and observed:
        raise ValueError("Static structure materialized generated nodes")
    return {
        "run_id": manifest["run_id"],
        "arm": manifest["arm"],
        "responses": len(responses),
        "filesystem_actions": actions,
        "materialized_nodes": len(observed),
        "catalog_fingerprint": profile["catalog_fingerprint"],
        "shared_nodes_fingerprint": profile["shared_nodes_fingerprint"],
        "seed_sha256": manifest["seed_sha256"],
        "fixture_sha256": manifest["fixture_sha256"],
    }


def verify_path_story_pair(
    static_dir: str | Path, dynamic_dir: str | Path, common_commands: list[str] | tuple[str, ...]
) -> dict[str, Any]:
    """Compare an assigned static/dynamic pair's common pre-expansion prefix."""
    static_dir = Path(static_dir)
    dynamic_dir = Path(dynamic_dir)
    left = verify_path_story_bundle(static_dir)
    right = verify_path_story_bundle(dynamic_dir)
    if (left["arm"], right["arm"]) not in {("B0", "B1"), ("B2", "B3")}:
        raise ValueError("Pair must share the text arm and differ in structure")
    for key in ("seed_sha256", "fixture_sha256", "catalog_fingerprint", "shared_nodes_fingerprint"):
        if left[key] != right[key]:
            raise ValueError(f"Paired-arm commitment differs: {key}")
    expected = list(common_commands)
    if not expected or any(not isinstance(command, str) for command in expected):
        raise ValueError("Common prefix needs at least one command")

    def prefix(run_dir: Path) -> list[bytes]:
        manifest, _, _, _ = _validate_archive(run_dir)
        events = _events(run_dir, manifest)
        delivered: list[tuple[str, dict[str, Any], bytes]] = []
        request: dict[str, Any] | None = None
        for event in events[1:]:
            if event["event_type"] == "decoy_request":
                request = event
            elif event["event_type"] == "decoy_response":
                if request is None:
                    raise ValueError("Response lacks request")
                delivered.append((request["route"], request, _decoded(event["body_b64"], "Response body")))
                request = None
        if len(delivered) < len(expected) + 1 or delivered[0][0] != "/connect":
            raise ValueError("Paired run lacks the common connection prefix")
        if not json.loads(delivered[0][2]).get("new_connection"):
            raise ValueError("Paired prefix did not open a new connection")
        bodies = [delivered[0][2]]
        for index, command in enumerate(expected, 1):
            route, req, body = delivered[index]
            payload = json.loads(_decoded(req.get("request_body_b64"), "Request body"))
            if route != "/exec" or payload != {"command": command}:
                raise ValueError("Paired common command prefix differs")
            bodies.append(body)
        return bodies

    left_bodies = prefix(static_dir)
    right_bodies = prefix(dynamic_dir)
    if left_bodies != right_bodies:
        raise ValueError("Paired common response bytes differ")
    return {
        "static_run_id": left["run_id"],
        "dynamic_run_id": right["run_id"],
        "common_commands": expected,
        "shared_prefix_sha256": _sha256(b"\x00".join(left_bodies)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dirs", nargs="+", type=Path)
    args = parser.parse_args()
    for run_dir in args.run_dirs:
        print(json.dumps(verify_path_story_bundle(run_dir), sort_keys=True))


if __name__ == "__main__":
    main()
