"""Parse an arm-blind, versioned 2B runtime envelope without changing the task."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Mapping


POLICY_ENV = "SHAPE_2B_RUNTIME_POLICY_JSON"
SUPPORT_POLICY = {
    "schema_version": 1,
    "name": "horizon-support-v1",
    "max_decisions": 25,
    "supervisor_max_turns": 4,
    "executor_max_turns": 12,
    "executor_turn_policy": "full_declared_ceiling",
}


@dataclass(frozen=True)
class RuntimePolicy:
    schema_version: int
    name: str
    max_decisions: int
    supervisor_max_turns: int
    executor_max_turns: int
    executor_turn_policy: str

    def evidence(self) -> dict[str, Any]:
        value = asdict(self)
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return {**value, "sha256": hashlib.sha256(canonical).hexdigest()}


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= maximum
    ):
        raise ValueError(f"2B runtime policy {label} is invalid")
    return value


def load_runtime_policy(
    task: dict[str, Any],
    environ: Mapping[str, str],
) -> RuntimePolicy:
    """Use exact task defaults unless a supported experiment overlay is supplied."""

    caps = task.get("caps_per_trial")
    if not isinstance(caps, dict):
        raise ValueError("2B task caps are missing")
    raw = environ.get(POLICY_ENV)
    if raw in {None, ""}:
        return RuntimePolicy(
            schema_version=1,
            name="task-default-v1",
            max_decisions=_positive_int(caps.get("max_decisions"), "max_decisions", 1_000),
            supervisor_max_turns=_positive_int(
                caps.get("supervisor_max_turns"), "supervisor_max_turns", 100
            ),
            executor_max_turns=_positive_int(
                caps.get("executor_max_turns"), "executor_max_turns", 100
            ),
            executor_turn_policy="task_kind_defaults",
        )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("2B runtime policy JSON is malformed") from exc
    if not isinstance(value, dict) or value != SUPPORT_POLICY:
        raise ValueError("2B runtime policy is not the frozen support candidate")
    if (
        value["supervisor_max_turns"] != caps.get("supervisor_max_turns")
        or value["executor_max_turns"] != caps.get("executor_max_turns")
    ):
        raise ValueError("2B support policy changes the task role-turn ceilings")
    return RuntimePolicy(
        schema_version=value["schema_version"],
        name=value["name"],
        max_decisions=_positive_int(value["max_decisions"], "max_decisions", 1_000),
        supervisor_max_turns=_positive_int(
            value["supervisor_max_turns"], "supervisor_max_turns", 100
        ),
        executor_max_turns=_positive_int(
            value["executor_max_turns"], "executor_max_turns", 100
        ),
        executor_turn_policy=value["executor_turn_policy"],
    )
