"""Run a frozen 2B command plan through the attacker image's registered SSH tools.

This script is mounted into a disposable attacker-image container with its
entrypoint overridden to Python. It never starts PentestGPT, an MCP server, or
a model client. Stdout is one JSON report with the exact tool response strings.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from unified_agent.tools import resolve_registry


PROBE_VERSION = "path-story-matrix-probe-v1"
REGISTRY_SPEC = "ssh_tools_2b_path_story:REGISTRY"
TARGET = "ssh://lab@filesystem-decoy-2b"
ACTION_COUNT = 50
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")
_PROMPT = re.compile(
    r"(?P<username>[a-z_][a-z0-9_-]{0,31})@"
    r"(?P<hostname>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):"
    r"(?P<cwd>/[A-Za-z0-9._/-]{0,255})\$ \Z"
)


class ProbeError(ValueError):
    """The frozen plan or registered tool contract is unsuitable for this probe."""


def _load_plan(path: Path) -> tuple[str, list[str], str]:
    raw = path.read_bytes()
    config = json.loads(raw)
    if not isinstance(config, dict):
        raise ProbeError("matrix config must be a JSON object")
    target = config.get("target")
    if target != TARGET or os.environ.get("SHAPE_2B_TARGET", TARGET) != target:
        raise ProbeError("matrix target differs from the registered lab target")
    if config.get("max_commands") != ACTION_COUNT:
        raise ProbeError("matrix command cap must be 50")
    plan = config.get("command_plan")
    if not isinstance(plan, list) or len(plan) != ACTION_COUNT:
        raise ProbeError(f"command_plan must contain exactly {ACTION_COUNT} commands")
    if any(
        not isinstance(command, str)
        or not command.strip()
        or len(command) > 512
        or "\x00" in command
        for command in plan
    ):
        raise ProbeError("command_plan contains an invalid command")
    return target, plan, hashlib.sha256(raw).hexdigest()


def _registered_tools() -> tuple[Any, Any]:
    registry = resolve_registry(REGISTRY_SPEC)
    if registry.server_name != "shape_ssh":
        raise ProbeError("unexpected registered SSH server name")
    entries = {entry.name: entry for entry in registry.tools}
    if set(entries) != {"ssh_connect", "ssh_exec"}:
        raise ProbeError("unexpected registered SSH tool set")
    for name, argument in (("ssh_connect", "target"), ("ssh_exec", "command")):
        parameters = list(inspect.signature(entries[name].fn).parameters.values())
        if (
            len(parameters) != 1
            or parameters[0].name != argument
            or parameters[0].kind != inspect.Parameter.POSITIONAL_OR_KEYWORD
            or parameters[0].default is not inspect.Parameter.empty
        ):
            raise ProbeError(f"unexpected {name} argument contract")
    return entries["ssh_connect"].fn, entries["ssh_exec"].fn


def _check_response(value: Any, identity: tuple[str, str] | None) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ProbeError("registered SSH tool did not return text")
    prompt = _PROMPT.search(value)
    if prompt is None:
        raise ProbeError("registered SSH tool response lacks a valid shell prompt")
    observed = (prompt.group("username"), prompt.group("hostname"))
    if identity is not None and observed != identity:
        raise ProbeError("registered SSH identity changed within one session")
    return observed


def run(config_path: Path, arm: str, run_id: str) -> dict[str, Any]:
    if arm not in {"B0", "B1", "B2", "B3"} or _RUN_ID.fullmatch(run_id) is None:
        raise ProbeError("invalid matrix run identity")
    target, plan, config_sha256 = _load_plan(config_path)
    connect, execute = _registered_tools()
    report: dict[str, Any] = {
        "probe_version": PROBE_VERSION,
        "status": "running",
        "arm": arm,
        "run_id": run_id,
        "config_sha256": config_sha256,
        "registry_spec": REGISTRY_SPEC,
        "target": target,
        "connection": None,
        "actions": [],
    }
    try:
        connection_response = connect(target=target)
        identity = _check_response(connection_response, None)
        report["connection"] = {
            "tool": "ssh_connect",
            "arguments": {"target": target},
            "response": connection_response,
        }
        report["identity"] = {"username": identity[0], "hostname": identity[1]}
        for sequence, command in enumerate(plan, start=1):
            response = execute(command=command)
            _check_response(response, identity)
            report["actions"].append(
                {
                    "sequence": sequence,
                    "tool": "ssh_exec",
                    "arguments": {"command": command},
                    "response": response,
                }
            )
    except Exception as exc:
        report["status"] = "failed"
        report["completed_actions"] = len(report["actions"])
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return report
    report["status"] = "complete"
    report["completed_actions"] = ACTION_COUNT
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--arm", required=True, choices=("B0", "B1", "B2", "B3"))
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        report = run(args.config, args.arm, args.run_id)
    except Exception as exc:
        print(f"matrix probe setup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
