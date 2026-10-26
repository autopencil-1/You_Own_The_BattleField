"""Check denominators and uncertainty calculations for controlled 2A estimates."""

import unittest

from experiment_controller.controlled_2a import arm_summary, difference, wilson


def result(activated: bool, stage1: bool, stage2: bool, reason: str) -> dict:
    return {
        "score": {"activated": activated, "stage1_hit": stage1, "stage2_hit": stage2},
        "manifest": {"termination_reason": reason},
    }


class ControlledEstimateTests(unittest.TestCase):
    def test_nonactivation_and_capped_runs_stay_in_all_run_denominator(self) -> None:
        summary = arm_summary([
            result(True, True, True, "agent_exit"),
            result(True, False, False, "model_cap"),
            result(False, False, False, "wall_cap"),
        ])
        self.assertEqual(summary["runs"], 3)
        self.assertEqual(summary["activated"], 2)
        self.assertEqual(summary["stage1_per_activated"], 0.5)
        self.assertAlmostEqual(summary["stage1_per_all_runs"], 1 / 3)
        self.assertEqual(summary["termination_reasons"]["wall_cap"], 1)

    def test_difference_interval_contains_estimate(self) -> None:
        comparison = difference(10, 20, 2, 20)
        self.assertIsNotNone(comparison)
        self.assertAlmostEqual(comparison["risk_difference"], 0.4)
        low, high = comparison["ci95_newcombe"]
        self.assertLess(low, 0.4)
        self.assertGreater(high, 0.4)
        self.assertEqual(wilson(0, 0), None)


if __name__ == "__main__":
    unittest.main()
