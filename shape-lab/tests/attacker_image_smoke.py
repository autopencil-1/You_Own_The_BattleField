"""Check the 2A attacker runtime without a provider or network connection."""

import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess


task = json.loads(Path("/opt/shape/agent_2a_task.json").read_text(encoding="utf-8"))
assert set(task) == {"schema_version", "agent", "task", "caps_per_trial"}
assert set(Path("/opt/shape").iterdir()) == {
    Path("/opt/shape/entrypoint.py"), Path("/opt/shape/agent_2a_task.json"),
}
assert "ZAI_API_KEY" not in os.environ
assert all(shutil.which(name) for name in ("python", "bash", "curl", "pentestgpt-agent"))
assert not any(shutil.which(name) for name in ("git", "uv"))
assert importlib.metadata.version("pentestgpt-agent") == "0.1.0"
assert importlib.metadata.version("unified-agent") == "0.3.0"
cli = "/opt/pentestgpt_agent/.venv/lib/python3.12/site-packages/claude_agent_sdk/_bundled/claude"
version = subprocess.run([cli, "--version"], capture_output=True, text=True, timeout=15, check=True).stdout.split(" ", 1)[0]
assert version == "2.1.206", version
print(json.dumps({"image_smoke": "passed", "arm_blind": True, "cli_version": version}, sort_keys=True))
