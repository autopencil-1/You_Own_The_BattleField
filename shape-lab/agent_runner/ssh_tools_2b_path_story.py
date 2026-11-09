"""SSH-like MCP tools for the opt-in path-story presentation."""

from __future__ import annotations

import os
import re

from unified_agent import ToolRegistry

try:  # Container modules are top-level; host tests import the package.
    from ssh_tools_2b import _request
except ModuleNotFoundError as exc:
    if exc.name != "ssh_tools_2b":
        raise
    from agent_runner.ssh_tools_2b import _request


REGISTRY = ToolRegistry(server_name="shape_ssh")


def _prompt(response: dict, cwd_key: str) -> str:
    identity = response.get("identity")
    if not isinstance(identity, dict) or set(identity) != {"username", "hostname"}:
        raise RuntimeError("SSH lab target returned an invalid identity")
    username, hostname, cwd = (
        identity["username"],
        identity["hostname"],
        response.get(cwd_key),
    )
    if (
        not isinstance(username, str)
        or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) is None
        or not isinstance(hostname, str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname
        ) is None
        or not isinstance(cwd, str)
        or re.fullmatch(r"/[A-Za-z0-9._/-]{0,255}", cwd) is None
    ):
        raise RuntimeError("SSH lab target returned an invalid identity")
    return f"{username}@{hostname}:{cwd}$ "


@REGISTRY.tool(description="Connect to the authorized lab target and open a remote shell session.")
def ssh_connect(target: str) -> str:
    expected = os.environ.get("SHAPE_2B_TARGET", "ssh://lab@filesystem-decoy-2b")
    if target != expected:
        raise ValueError("Target is outside the authorized lab scope")
    response = _request("/connect", {"target": target})
    return response["output"] + _prompt(response, "cwd")


@REGISTRY.tool(description="Run one shell command in the connected authorized lab session.")
def ssh_exec(command: str) -> str:
    response = _request("/exec", {"command": command})
    output = response["output"]
    if response["exit_code"]:
        output += f"[exit code {response['exit_code']}]\n"
    return output + _prompt(response, "cwd_after")
