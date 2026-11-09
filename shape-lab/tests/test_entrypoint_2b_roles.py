"""The 2B planner must never receive the imitated SSH tool registry."""

from pathlib import Path
import unittest

try:
    from agent_runner import entrypoint_2b
    from pentestgpt_agent.policy import ExecutorTurnPolicy
    from pentestgpt_agent.trace import TraceStore
    from pentestgpt_agent.trial import TrialConfig
    from unified_agent import SandboxPolicy
except ModuleNotFoundError as exc:
    if exc.name not in {"pentestgpt_agent", "unified_agent"}:
        raise
    raise unittest.SkipTest(
        "2B role wiring requires the attacker image's agent runtime"
    ) from exc


def test_2b_roles_isolate_supervisor_and_preserve_executor_tools(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class CapturedAgent:
        def __init__(self, backend: object, **options: object) -> None:
            self.backend = backend
            self.instructions = options["instructions"]
            self.sandbox = options["sandbox"]
            self.tools = options.get("tools")
            self.effort = options["effort"]

    monkeypatch.setattr(entrypoint_2b, "UnifiedAgent", CapturedAgent)
    trial = TrialConfig(
        run_id="2b-test-run",
        goal="Assess the authorized fixture.",
        targets=("shape-ssh://ssh-decoy-2b:22",),
        backend="claude",
        model="glm-5.3",
        runs_root=tmp_path / "runs",
        workspace_root=tmp_path / "workspaces",
        effort="max",
        executor_turn_policy=ExecutorTurnPolicy.FULL_DECLARED_CEILING,
    )

    supervisor, executor = entrypoint_2b._build_roles_2b(
        trial, TraceStore(trial.runs_root)
    )

    assert supervisor.runner.agent.sandbox is SandboxPolicy.READ_ONLY
    assert supervisor.runner.agent.tools is None
    assert executor.runner.agent.sandbox is SandboxPolicy.FULL_ACCESS
    assert executor.runner.agent.tools == "ssh_tools_2b:REGISTRY"
    assert executor.turn_policy is ExecutorTurnPolicy.FULL_DECLARED_CEILING
