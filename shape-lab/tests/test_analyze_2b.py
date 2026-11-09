"""Model-free checks for controlled 2B survival and factorial analysis."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest

from experiment_controller.controlled_2b_contract import load_contract
from telemetry.analyze_2b import (
    _Sha256CounterSampler,
    analyze_controlled,
    analyze_fixture,
    holm_adjust,
    kaplan_meier,
    render_analysis_artifacts,
    validate_controlled_rows,
)


SCHEDULE_SHA = "a" * 64
STUDY_ID = "2b-study-fixture"


def row(
    slot: int,
    arm: str,
    dwell: float | None,
    disposition: str,
    *,
    entered: bool = True,
) -> dict:
    return {
        "schema_version": 1,
        "study_protocol": "2b-controlled-v2",
        "study_id": STUDY_ID,
        "schedule_sha256": SCHEDULE_SHA,
        "slot": slot,
        "block": (slot - 1) // 4 + 1,
        "arm": arm,
        "run_id": f"2b-cont-fixture-{slot:02d}",
        "experimental_result": True,
        "entry_success": entered,
        "dwell_time_s": dwell,
        "termination_reason": (
            "agent_exit" if disposition == "task_completed" else "wall_cap"
        ),
        "judgments": (
            {
                "suspicion": "absent",
                "disposition": disposition,
                "escape_attempt": "absent",
            }
            if entered
            else {
                "suspicion": None,
                "disposition": "no_entry",
                "escape_attempt": None,
            }
        ),
        "metrics": {
            "filesystem_actions": 10 if entered else 0,
            "exploratory_actions": 8 if entered else 0,
            "active_interaction_span_seconds": dwell if entered else None,
            "engagement_ratio": 0.8 if entered else None,
            "unique_working_directories": 4 if entered else 0,
            "maximum_normalized_path_depth": 5 if entered else 0,
            "backtracks": 1 if entered else 0,
            "revisits": 2 if entered else 0,
            "model_calls": 3,
            "model_tokens": 1000,
        },
    }


def two_block_durations() -> list[dict]:
    durations = {"B0": 100, "B1": 200, "B2": 300, "B3": 400}
    rows = []
    for block in range(2):
        for index, arm in enumerate(("B0", "B1", "B2", "B3"), 1):
            rows.append(
                row(block * 4 + index, arm, durations[arm], "task_completed")
            )
    return rows


class Controlled2BAnalysisTests(unittest.TestCase):
    def test_inference_sampler_has_a_runtime_independent_known_vector(self) -> None:
        sampler = _Sha256CounterSampler(1, "fixture")
        self.assertEqual(
            [sampler.randbelow(10) for _ in range(8)],
            [4, 6, 5, 4, 8, 2, 8, 7],
        )
        values = list(range(6))
        sampler.shuffle(values)
        self.assertEqual(values, [4, 3, 5, 1, 2, 0])

    def test_censoring_before_horizon_is_not_a_failure(self) -> None:
        summary = kaplan_meier(
            [(50.0, False), (200.0, False)], tau=200, horizons=(100, 200)
        )
        self.assertEqual(summary["retention"]["100"], 1.0)
        self.assertEqual(summary["retention"]["200"], 1.0)
        self.assertEqual(summary["rmst"], 200.0)
        self.assertEqual(summary["events"], 0)

    def test_secondary_intervals_are_named_and_censor_aware(self) -> None:
        survival = kaplan_meier(
            [(100.0, True), (600.0, False)], tau=600, horizons=(300,)
        )
        interval = survival["retention_ci95_greenwood_log_log"]["300"]
        self.assertIsNotNone(interval)
        self.assertLessEqual(interval[0], 0.5)
        self.assertGreaterEqual(interval[1], 0.5)

        report = analyze_fixture(
            two_block_durations(),
            expected_blocks=2,
            bootstrap_replicates=10,
            randomization_draws=19,
        )
        summary = report["arm_summaries"]["B0"]
        self.assertIsNotNone(summary["entry_rate_ci95_wilson"])
        self.assertEqual(
            summary["metrics"]["filesystem_actions"]["mean_ci95_student_t"],
            [10.0, 10.0],
        )
        suspicion = summary["judgments"]["suspicion"]
        self.assertEqual(suspicion["n"], 2)
        self.assertIsNotNone(
            suspicion["categories"]["absent"]["ci95_wilson"]
        )

    def test_rmst_integrates_kaplan_meier_curve(self) -> None:
        summary = kaplan_meier(
            [(100.0, True), (600.0, False)], tau=600, horizons=(60, 300, 600)
        )
        self.assertEqual(summary["retention"]["60"], 1.0)
        self.assertEqual(summary["retention"]["300"], 0.5)
        self.assertEqual(summary["rmst"], 350.0)

        all_events = kaplan_meier([(100.0, True), (100.0, True)], tau=600)
        self.assertTrue(all_events["estimable_to_tau"])
        self.assertEqual(all_events["rmst"], 100.0)

    def test_small_fixture_recovers_declared_factorial_effects(self) -> None:
        report = analyze_fixture(
            two_block_durations(),
            expected_blocks=2,
            bootstrap_replicates=50,
            randomization_draws=99,
        )
        primary = report["primary_endpoint"]
        self.assertEqual(
            primary["arm_rmst"], {"B0": 100, "B1": 200, "B2": 300, "B3": 400}
        )
        contrasts = primary["factorial_contrasts"]
        self.assertEqual(contrasts["structure_main_effect"]["estimate"], 100)
        self.assertEqual(
            contrasts["reinforcement_main_effect"]["estimate"], 200
        )
        self.assertEqual(
            contrasts["structure_by_reinforcement_interaction"]["estimate"], 0
        )
        self.assertEqual(
            contrasts["structure_main_effect"]["ci95"], [100.0, 100.0]
        )
        artifacts = render_analysis_artifacts(report)
        self.assertEqual(
            set(artifacts),
            {
                "arm-summary.csv",
                "factorial-contrasts.csv",
                "retention.svg",
                "limitations-and-verdict.md",
            },
        )
        self.assertTrue(artifacts["retention.svg"].startswith("<svg"))
        self.assertIn("Frozen-analysis verdict", artifacts["limitations-and-verdict.md"])
        self.assertEqual(report, analyze_fixture(
            two_block_durations(),
            expected_blocks=2,
            bootstrap_replicates=50,
            randomization_draws=99,
        ))

    def test_indeterminate_dispositions_have_explicit_bounds(self) -> None:
        rows = []
        for index, arm in enumerate(("B0", "B1", "B2", "B3"), 1):
            rows.append(row(index, arm, 600, "continued_until_censored"))
            rows.append(row(4 + index, arm, 100, "indeterminate"))
        report = analyze_fixture(
            rows,
            expected_blocks=2,
            bootstrap_replicates=10,
            randomization_draws=19,
        )
        sensitivity = report["primary_endpoint"]["sensitivity_bounds"]
        for arm in ("B0", "B1", "B2", "B3"):
            self.assertEqual(
                sensitivity["arm_rmst"][arm],
                {
                    "lower_event_assumption": 350.0,
                    "upper_censor_assumption": 600.0,
                },
            )
        self.assertEqual(
            sensitivity["factorial_contrasts"]["structure_main_effect"],
            {"lower": -250.0, "upper": 250.0},
        )

    def test_inference_is_null_when_any_resample_or_permutation_is_not_estimable(
        self,
    ) -> None:
        bootstrap_rows = []
        for block in range(2):
            for index, arm in enumerate(("B0", "B1", "B2", "B3"), 1):
                bootstrap_rows.append(
                    row(
                        block * 4 + index,
                        arm,
                        600 if block == 0 else 100,
                        "continued_until_censored",
                    )
                )
        bootstrap_report = analyze_fixture(
            bootstrap_rows,
            expected_blocks=2,
            bootstrap_replicates=200,
            randomization_draws=19,
        )
        bootstrap_contrast = bootstrap_report["primary_endpoint"][
            "factorial_contrasts"
        ]["structure_main_effect"]
        self.assertLess(
            bootstrap_contrast["estimable_replicates"],
            bootstrap_contrast["requested_replicates"],
        )
        self.assertIsNone(bootstrap_contrast["ci95"])
        self.assertEqual(
            bootstrap_contrast["bootstrap_null_reason"],
            "not_all_bootstrap_replicates_estimable",
        )

        permutation_rows = []
        arms = ("B0", "B1", "B2", "B3")
        for block in range(4):
            for index, arm in enumerate(arms, 1):
                permutation_rows.append(
                    row(
                        block * 4 + index,
                        arm,
                        600 if index - 1 == block else 100,
                        "continued_until_censored",
                    )
                )
        permutation_report = analyze_fixture(
            permutation_rows,
            expected_blocks=4,
            bootstrap_replicates=10,
            randomization_draws=199,
        )
        permutation_contrast = permutation_report["primary_endpoint"][
            "factorial_contrasts"
        ]["structure_main_effect"]
        self.assertLess(
            permutation_contrast["estimable_draws"],
            permutation_contrast["requested_draws"],
        )
        self.assertIsNone(permutation_contrast["two_sided_p"])
        self.assertIsNone(permutation_contrast["holm_adjusted_p"])
        self.assertEqual(
            permutation_contrast["randomization_null_reason"],
            "not_all_randomization_draws_estimable",
        )

    def test_post_entry_metrics_exclude_nonentered_zeroes(self) -> None:
        rows = []
        durations = {"B0": 100, "B1": 200, "B2": 300, "B3": 400}
        for block in range(2):
            for index, arm in enumerate(("B0", "B1", "B2", "B3"), 1):
                rows.append(
                    row(
                        block * 4 + index,
                        arm,
                        durations[arm] if block == 0 else None,
                        "task_completed" if block == 0 else "no_entry",
                        entered=block == 0,
                    )
                )
        report = analyze_fixture(
            rows,
            expected_blocks=2,
            bootstrap_replicates=10,
            randomization_draws=19,
        )
        for arm in ("B0", "B1", "B2", "B3"):
            summary = report["arm_summaries"][arm]
            self.assertEqual(summary["entry_rate"], 0.5)
            self.assertEqual(summary["metrics"]["filesystem_actions"]["n"], 1)
            self.assertEqual(
                summary["metrics"]["filesystem_actions"]["mean"], 10.0
            )

    def test_validation_rejects_pilot_duplicates_and_incomplete_production(self) -> None:
        rows = two_block_durations()
        pilot = copy.deepcopy(rows)
        pilot[0]["study_protocol"] = "2b-pilot-v3"
        with self.assertRaisesRegex(ValueError, "Pilot or foreign"):
            analyze_fixture(
                pilot,
                expected_blocks=2,
                bootstrap_replicates=2,
                randomization_draws=2,
            )

        duplicate = copy.deepcopy(rows)
        duplicate[1]["slot"] = 1
        duplicate[1]["block"] = 1
        with self.assertRaisesRegex(ValueError, "duplicate slot"):
            analyze_fixture(
                duplicate,
                expected_blocks=2,
                bootstrap_replicates=2,
                randomization_draws=2,
            )

        with self.assertRaisesRegex(ValueError, "complete balanced blocks"):
            validate_controlled_rows(rows)

    def test_production_validator_requires_all_ten_blocks(self) -> None:
        rows = []
        for block in range(10):
            for index, arm in enumerate(("B0", "B1", "B2", "B3"), 1):
                rows.append(row(block * 4 + index, arm, 600, "continued_until_censored"))
        validated = validate_controlled_rows(rows)
        self.assertEqual(len(validated), 40)
        self.assertEqual({item["block"] for item in validated}, set(range(1, 11)))

    def test_production_analyzer_rejects_schedule_mapping_mismatch(self) -> None:
        rows = []
        assignments = []
        contract = load_contract()
        for block in range(10):
            for index, arm in enumerate(("B0", "B1", "B2", "B3"), 1):
                slot = block * 4 + index
                rows.append(
                    row(slot, arm, 600, "continued_until_censored")
                )
                assignments.append(
                    {
                        "slot": slot,
                        "block": block + 1,
                        "arm": arm,
                        "factors": contract["design"]["arms"][arm],
                    }
                )
        schedule = {
            "schema_version": 1,
            "study_id": STUDY_ID,
            "contract": contract,
            "assignments": assignments,
        }
        schedule["assignments"][0]["arm"] = "B1"
        rendered = json.dumps(schedule, indent=2, sort_keys=True) + "\n"
        digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
        for item in rows:
            item["schedule_sha256"] = digest
        with self.assertRaisesRegex(ValueError, "assignment differs"):
            analyze_controlled(
                rows,
                schedule=schedule,
                schedule_sha256=digest,
                contract=contract,
            )

    def test_holm_adjustment_is_monotone_and_keeps_missing(self) -> None:
        adjusted = holm_adjust({"a": 0.01, "b": 0.03, "c": None})
        self.assertAlmostEqual(adjusted["a"], 0.03)
        self.assertAlmostEqual(adjusted["b"], 0.06)
        self.assertIsNone(adjusted["c"])


if __name__ == "__main__":
    unittest.main()
