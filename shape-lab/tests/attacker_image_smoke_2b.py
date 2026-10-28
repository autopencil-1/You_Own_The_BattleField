"""Check the 2B image and MCP tool registration without model or network access."""

import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess

from unified_agent import SandboxPolicy, UnifiedAgent
from ssh_tools_2b import REGISTRY


task = json.loads(Path("/opt/shape/agent_2b_task.json").read_text(encoding="utf-8"))
assert set(task) == {"schema_version", "agent", "task", "caps_per_trial"}
assert set(Path("/opt/shape").iterdir()) == {
    Path("/opt/shape/entrypoint_2b.py"),
    Path("/opt/shape/ssh_tools_2b.py"),
    Path("/opt/shape/agent_2b_task.json"),
}
assert task["task"]["target"] == "ssh://lab@filesystem-decoy-2b"
assert "ZAI_API_KEY" not in os.environ
assert not any(shutil.which(name) for name in ("git", "uv", "ssh"))
assert importlib.metadata.version("pentestgpt-agent") == "0.1.0"
assert importlib.metadata.version("unified-agent") == "0.3.0"
assert {tool.name for tool in REGISTRY.tools} == {"ssh_connect", "ssh_exec"}
agent = UnifiedAgent("claude", workspace="/tmp/shape2b-smoke", model="glm-5.3-flash",
                     sandbox=SandboxPolicy.FULL_ACCESS, tools="ssh_tools_2b:REGISTRY")
agent._prepare()
assert agent._tool_server is not None
assert agent._tool_server.server_name == "shape_ssh"
cli = "/opt/pentestgpt_agent/.venv/lib/python3.12/site-packages/claude_agent_sdk/_bundled/claude"
version = subprocess.run([cli, "--version"], capture_output=True, text=True,
                         timeout=15, check=True).stdout.split(" ", 1)[0]
assert version == "2.1.206", version
print(json.dumps({"image_smoke": "passed", "arm_blind": True,
                  "tools": sorted(tool.name for tool in REGISTRY.tools),
                  "cli_version": version}, sort_keys=True))
