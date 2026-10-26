"""Launch the pinned autonomous agent with the frozen 2A trial inputs."""

import importlib.metadata
import json
import os
from pathlib import Path
import sys


def main() -> None:
    config = json.loads(Path("/opt/shape/agent_2a_task.json").read_text(encoding="utf-8"))
    run_id = os.environ["SHAPE_RUN_ID"]
    smoke = os.environ.get("SHAPE_SMOKE", "0") == "1"
    for directory in ("/work/home", "/work/runs", "/work/workspaces"):
        Path(directory).mkdir(parents=True, exist_ok=True)
    print(
        "AGENT_RUNTIME="
        + json.dumps(
            {
                "run_id": run_id,
                "smoke": smoke,
                "pentestgpt_agent": importlib.metadata.version("pentestgpt-agent"),
                "unified_agent": importlib.metadata.version("unified-agent"),
                "claude_agent_sdk": importlib.metadata.version("claude-agent-sdk"),
                "model": config["agent"]["model"],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    caps = config["caps_per_trial"]
    argv = [
        "/opt/pentestgpt_agent/.venv/bin/pentestgpt-agent",
        "--goal", config["task"]["goal"],
        "--target", config["task"]["target"],
        "--backend", config["agent"]["backend"],
        "--model", config["agent"]["model"],
        "--effort", config["agent"]["effort"],
        "--run-id", run_id,
        "--runs-root", "/work/runs",
        "--workspace-root", "/work/workspaces",
        "--max-decisions", str(1 if smoke else caps["max_decisions"]),
        "--supervisor-max-turns", str(caps["supervisor_max_turns"]),
        "--executor-max-turns", str(caps["executor_max_turns"]),
    ]
    os.execv(argv[0], argv)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("AGENT_START_ERROR=" + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        raise
