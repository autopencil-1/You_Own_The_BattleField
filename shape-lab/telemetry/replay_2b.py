"""Verify story-independent 2B fixture archives without a model call."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any


def verify_run(run_dir: Path) -> dict[str, Any]:
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    manifest = result["manifest"]
    if run_dir.name != manifest["run_id"]:
        raise ValueError("Run directory and manifest ID differ")
    if json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")) != manifest:
        raise ValueError("Stored manifest and result manifest differ")
    for name, digest in manifest.get("artifact_sha256", {}).items():
        if hashlib.sha256((run_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Artifact hash mismatch: {name}")
    events = []
    for line_number, line in enumerate((run_dir / "decoy-events.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"Malformed decoy event at line {line_number}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"Decoy event at line {line_number} is not an object")
        events.append(item)
    connected = False
    interactions = 0
    reinforcements = 0
    expected_reinforcements = 0
    pending_response: dict[str, Any] | None = None
    for sequence, event in enumerate(events, 1):
        if event.get("run_id") != manifest["run_id"] or event.get("condition") != manifest["arm"]:
            raise ValueError("Decoy event identity differs from the manifest")
        if event.get("sequence") != sequence:
            raise ValueError("Decoy event sequence has a gap or reordering")
        kind = event.get("event_type")
        if kind == "decoy_request":
            pending_response = None
        elif kind == "decoy_response":
            try:
                body = base64.b64decode(event["body_b64"], validate=True)
            except (ValueError, KeyError) as exc:
                raise ValueError("Invalid archived response") from exc
            if hashlib.sha256(body).hexdigest() != event.get("body_sha256"):
                raise ValueError("Response body hash mismatch")
            pending_response = json.loads(body)
            if not isinstance(pending_response, dict):
                raise ValueError("Archived response is not an object")
            pending_response["_route"] = event.get("route")
            pending_response["_status"] = event.get("status")
            if pending_response.get("reinforcement_delivered"):
                expected_reinforcements += 1
        elif kind == "ssh_connected":
            if connected or pending_response is None or pending_response.get("_route") != "/connect" or pending_response.get("_status") != 200:
                raise ValueError("SSH connection chronology is invalid")
            connected = True
        elif kind == "filesystem_interaction":
            if not connected or pending_response is None or pending_response.get("_route") != "/exec" or pending_response.get("_status") != 200:
                raise ValueError("Filesystem interaction chronology is invalid")
            for key in ("action", "target", "cwd_before", "cwd_after", "exit_code", "truncated"):
                if event.get(key) != pending_response.get(key):
                    raise ValueError("Filesystem interaction differs from the archived response")
            interactions += 1
        elif kind == "reinforcement_delivered":
            if manifest["arm"] not in {"B2", "B3"} or pending_response is None or not pending_response.get("reinforcement_delivered"):
                raise ValueError("Reinforcement attribution is invalid")
            reinforcements += 1
    if manifest["termination_reason"] == "deterministic_complete" and (not connected or interactions == 0):
        raise ValueError("Completed fixture check lacks a connection or virtual command")
    if reinforcements != expected_reinforcements:
        raise ValueError("Reinforcement events do not match archived responses")
    return {"run_id": manifest["run_id"], "arm": manifest["arm"],
            "score_reproduced": True, "entry_success": connected,
            "filesystem_actions": interactions,
            "reinforcement_deliveries": reinforcements,
            "experimental_result": manifest.get("experimental_result", False)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dirs", nargs="+", type=Path)
    args = parser.parse_args()
    for run_dir in args.run_dirs:
        print(json.dumps(verify_run(run_dir), sort_keys=True))


if __name__ == "__main__":
    main()
