"""Run the same pinned PentestGPT task with path-story SSH presentation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path

from pentestgpt_agent.agents import (
    EXECUTOR_INSTRUCTIONS,
    SUPERVISOR_INSTRUCTIONS,
    Executor,
    Supervisor,
)
from pentestgpt_agent.policy import ExecutorTurnPolicy
from pentestgpt_agent.trace import EpisodeRunner, TraceStore
from pentestgpt_agent.trial import TrialConfig, _provider_environment, run_trial
from unified_agent import SandboxPolicy, UnifiedAgent

try:  # Container entrypoint is a top-level module; tests import the package.
    from runtime_policy_2b import load_runtime_policy
except ModuleNotFoundError as exc:
    if exc.name != "runtime_policy_2b":
        raise
    from agent_runner.runtime_policy_2b import load_runtime_policy


def _build_roles_2b(
    trial: TrialConfig, traces: TraceStore
) -> tuple[Supervisor, Executor]:
    role_root = trial.workspace_root / trial.run_id
    provider_environment = _provider_environment(trial.backend)
    supervisor = Supervisor(
        EpisodeRunner(
            UnifiedAgent(
                trial.backend,
                workspace=role_root / "supervisor",
                model=trial.model,
                effort=trial.effort,
                sandbox=SandboxPolicy.READ_ONLY,
                instructions=SUPERVISOR_INSTRUCTIONS,
                extra_env=provider_environment,
            ),
            traces,
        ),
        max_turns=trial.supervisor_max_turns,
    )
    executor = Executor(
        EpisodeRunner(
            UnifiedAgent(
                trial.backend,
                workspace=role_root / "executor",
                model=trial.model,
                effort=trial.effort,
                sandbox=SandboxPolicy.FULL_ACCESS,
                instructions=EXECUTOR_INSTRUCTIONS,
                extra_env=provider_environment,
                tools="ssh_tools_2b_path_story:REGISTRY",
            ),
            traces,
        ),
        max_turns=trial.executor_max_turns,
        turn_policy=trial.executor_turn_policy,
    )
    return supervisor, executor


def main() -> None:
    config = json.loads(
        Path("/opt/shape/agent_2b_task.json").read_text(encoding="utf-8")
    )
    if (
        os.environ.get("SHAPE_2B_PROFILE_STATUS") == "fixture"
        and os.environ.get("SHAPE_2B_ALLOW_FIXTURE_MODEL") != "1"
    ):
        raise RuntimeError(
            "Fixture profile is restricted to explicit connectivity checks"
        )
    run_id = os.environ["SHAPE_RUN_ID"]
    runtime_policy = load_runtime_policy(config, os.environ)
    for directory in ("/work/home", "/work/runs", "/work/workspaces"):
        Path(directory).mkdir(parents=True, exist_ok=True)
    print(
        "AGENT_RUNTIME="
        + json.dumps(
            {
                "run_id": run_id,
                "pentestgpt_agent": importlib.metadata.version("pentestgpt-agent"),
                "unified_agent": importlib.metadata.version("unified-agent"),
                "model": config["agent"]["model"],
                "tool_adapter": "shape_ssh_mcp_host_v1",
                "runtime_policy": runtime_policy.evidence(),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    trial = TrialConfig(
        run_id=run_id,
        goal=config["task"]["goal"],
        targets=(config["task"]["target"],),
        backend=config["agent"]["backend"],
        model=config["agent"]["model"],
        effort=config["agent"]["effort"],
        runs_root=Path("/work/runs"),
        workspace_root=Path("/work/workspaces"),
        max_decisions=(
            1
            if os.environ.get("SHAPE_2B_SMOKE") == "1"
            else runtime_policy.max_decisions
        ),
        max_supervisor_attempts=runtime_policy.max_supervisor_attempts,
        max_attempts_per_task=runtime_policy.max_attempts_per_task,
        supervisor_max_turns=runtime_policy.supervisor_max_turns,
        executor_max_turns=runtime_policy.executor_max_turns,
        executor_turn_policy=ExecutorTurnPolicy(runtime_policy.executor_turn_policy),
    )
    traces = TraceStore(trial.runs_root)
    supervisor, executor = _build_roles_2b(trial, traces)
    print(
        "AGENT_STARTED="
        + datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        flush=True,
    )
    summary = asyncio.run(run_trial(trial, supervisor=supervisor, executor=executor))
    print("TRIAL_RESULT=" + json.dumps(summary, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
