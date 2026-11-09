"""The support runtime policy is explicit and leaves task defaults intact."""

from __future__ import annotations

import copy
import json
import unittest

from agent_runner.runtime_policy_2b import (
    POLICY_ENV,
    SUPPORT_POLICY,
    SUPPORT_POLICY_V2,
    SUPPORT_POLICY_V3,
    load_runtime_policy,
)


TASK = {
    "caps_per_trial": {
        "max_decisions": 20,
        "supervisor_max_turns": 4,
        "executor_max_turns": 12,
    }
}


class RuntimePolicy2BTests(unittest.TestCase):
    def test_absent_overlay_reproduces_task_defaults(self) -> None:
        policy = load_runtime_policy(TASK, {})
        self.assertEqual(policy.name, "task-default-v1")
        self.assertEqual(policy.max_decisions, 20)
        self.assertEqual(policy.max_supervisor_attempts, 2)
        self.assertEqual(policy.max_attempts_per_task, 2)
        self.assertEqual(policy.supervisor_max_turns, 4)
        self.assertEqual(policy.executor_max_turns, 12)
        self.assertEqual(policy.executor_turn_policy, "task_kind_defaults")
        self.assertRegex(policy.evidence()["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(load_runtime_policy(TASK, {POLICY_ENV: ""}), policy)

    def test_support_overlay_uses_full_existing_executor_ceiling(self) -> None:
        task_before = copy.deepcopy(TASK)
        policy = load_runtime_policy(
            TASK,
            {POLICY_ENV: json.dumps(SUPPORT_POLICY)},
        )
        self.assertEqual(policy.name, "horizon-support-v1")
        self.assertEqual(policy.max_decisions, 25)
        self.assertEqual(policy.executor_max_turns, 12)
        self.assertEqual(policy.executor_turn_policy, "full_declared_ceiling")
        self.assertEqual(TASK, task_before)

    def test_v3_overlay_moves_all_agent_administrative_bounds_behind_outer_fuses(
        self,
    ) -> None:
        task_before = copy.deepcopy(TASK)
        policy = load_runtime_policy(
            TASK,
            {POLICY_ENV: json.dumps(SUPPORT_POLICY_V3)},
        )
        self.assertEqual(policy.name, "horizon-support-v3")
        self.assertEqual(policy.max_decisions, 500)
        self.assertEqual(policy.max_supervisor_attempts, 500)
        self.assertEqual(policy.max_attempts_per_task, 500)
        self.assertEqual(policy.supervisor_max_turns, 500)
        self.assertEqual(policy.executor_max_turns, 500)
        self.assertEqual(policy.executor_turn_policy, "full_declared_ceiling")
        self.assertEqual(TASK, task_before)

    def test_unknown_or_role_ceiling_changing_overlay_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "not the frozen"):
            load_runtime_policy(TASK, {POLICY_ENV: '{"name":"other"}'})
        changed = {**SUPPORT_POLICY, "executor_max_turns": 13}
        with self.assertRaisesRegex(ValueError, "not the frozen"):
            load_runtime_policy(TASK, {POLICY_ENV: json.dumps(changed)})

    def test_v2_overlay_expands_only_the_versioned_runtime_opportunity(self) -> None:
        task_before = copy.deepcopy(TASK)
        policy = load_runtime_policy(
            TASK,
            {POLICY_ENV: json.dumps(SUPPORT_POLICY_V2)},
        )
        self.assertEqual(policy.name, "horizon-support-v2")
        self.assertEqual(policy.max_decisions, 25)
        self.assertEqual(policy.supervisor_max_turns, 4)
        self.assertEqual(policy.executor_max_turns, 500)
        self.assertEqual(policy.executor_turn_policy, "full_declared_ceiling")
        self.assertEqual(TASK, task_before)


if __name__ == "__main__":
    unittest.main()
