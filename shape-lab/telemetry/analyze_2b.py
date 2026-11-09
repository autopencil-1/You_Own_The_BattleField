"""Censoring-aware factorial analysis for the controlled 2B study.

The production entry point, :func:`analyze_controlled`, always validates the
complete 40-run cohort against the committed ``2b-controlled-v2`` contract.
``analyze_fixture`` is deliberately separate and exists only for small,
model-free test cohorts.
"""

from __future__ import annotations

from collections import Counter
import csv
import hashlib
from html import escape
import io
import json
import math
import re
from statistics import median, stdev
from typing import Any, Iterable, Sequence

from experiment_controller.controlled_2b_contract import ARMS, load_contract


STUDY_PROTOCOL = "2b-controlled-v2"
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
STUDY_ID = re.compile(r"2b-study-[a-z0-9-]{1,64}")
RUN_ID = re.compile(r"2b-cont-[a-z0-9-]{1,56}")
DISPOSITIONS = {
    "continued_until_censored",
    "task_completed",
    "abandoned_decoy",
    "no_entry",
    "indeterminate",
}
SUSPICION = {"present", "absent", "indeterminate"}
ESCAPE = {"present", "absent", "indeterminate"}
JUDGMENT_CATEGORIES = {
    "suspicion": ("present", "absent", "indeterminate"),
    "disposition": (
        "continued_until_censored",
        "task_completed",
        "abandoned_decoy",
        "indeterminate",
    ),
    "escape_attempt": ("present", "absent", "indeterminate"),
}
ROW_KEYS = {
    "schema_version",
    "study_protocol",
    "study_id",
    "schedule_sha256",
    "slot",
    "block",
    "arm",
    "run_id",
    "experimental_result",
    "entry_success",
    "dwell_time_s",
    "termination_reason",
    "judgments",
    "metrics",
}
JUDGMENT_KEYS = {"suspicion", "disposition", "escape_attempt"}
METRIC_KEYS = {
    "filesystem_actions",
    "exploratory_actions",
    "active_interaction_span_seconds",
    "engagement_ratio",
    "unique_working_directories",
    "maximum_normalized_path_depth",
    "backtracks",
    "revisits",
    "model_calls",
    "model_tokens",
}
INTEGER_METRICS = {
    "filesystem_actions",
    "exploratory_actions",
    "unique_working_directories",
    "maximum_normalized_path_depth",
    "backtracks",
    "revisits",
    "model_calls",
    "model_tokens",
}
CONTRAST_COEFFICIENTS = {
    "structure_main_effect": {"B0": -0.5, "B1": 0.5, "B2": -0.5, "B3": 0.5},
    "reinforcement_main_effect": {
        "B0": -0.5,
        "B1": -0.5,
        "B2": 0.5,
        "B3": 0.5,
    },
    "structure_by_reinforcement_interaction": {
        "B0": 1.0,
        "B1": -1.0,
        "B2": -1.0,
        "B3": 1.0,
    },
}
T_CRITICAL_975 = (
    0.0,
    12.706,
    4.303,
    3.182,
    2.776,
    2.571,
    2.447,
    2.365,
    2.306,
    2.262,
    2.228,
    2.201,
    2.179,
    2.160,
    2.145,
    2.131,
    2.120,
    2.110,
    2.101,
    2.093,
    2.086,
    2.080,
    2.074,
    2.069,
    2.064,
    2.060,
    2.056,
    2.052,
    2.048,
    2.045,
    2.042,
)


def _nonnegative_number(value: Any, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError(f"{label} must be a finite nonnegative number")


def _validate_metric(name: str, value: Any) -> None:
    if value is None:
        return
    _nonnegative_number(value, f"2B metric {name}")
    if name in INTEGER_METRICS and (
        not isinstance(value, int) or isinstance(value, bool)
    ):
        raise ValueError(f"2B metric {name} must be an integer or null")


def _validate_rows(
    rows: Sequence[dict[str, Any]],
    *,
    expected_blocks: int,
    expected_protocol: str = STUDY_PROTOCOL,
) -> list[dict[str, Any]]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise ValueError("Controlled 2B analysis rows must be a sequence")
    if expected_blocks < 1 or len(rows) != expected_blocks * len(ARMS):
        raise ValueError("Controlled 2B analysis requires complete balanced blocks")

    normalized = list(rows)
    study_ids: set[str] = set()
    schedule_hashes: set[str] = set()
    slots: set[int] = set()
    run_ids: set[str] = set()
    for row in normalized:
        if not isinstance(row, dict) or set(row) != ROW_KEYS:
            raise ValueError("Controlled 2B analysis row has an invalid shape")
        if row.get("schema_version") != 1:
            raise ValueError("Controlled 2B analysis row schema differs")
        if row.get("study_protocol") != expected_protocol:
            raise ValueError("Pilot or foreign-protocol row cannot enter controlled analysis")
        study_id = row.get("study_id")
        digest = row.get("schedule_sha256")
        run_id = row.get("run_id")
        if not isinstance(study_id, str) or not STUDY_ID.fullmatch(study_id):
            raise ValueError("Controlled 2B study identity is invalid")
        if not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest):
            raise ValueError("Controlled 2B schedule digest is invalid")
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise ValueError("Controlled 2B run identity is invalid")
        study_ids.add(study_id)
        schedule_hashes.add(digest)
        if run_id in run_ids:
            raise ValueError("Controlled 2B analysis contains a duplicate run")
        run_ids.add(run_id)

        slot = row.get("slot")
        block = row.get("block")
        arm = row.get("arm")
        if (
            not isinstance(slot, int)
            or isinstance(slot, bool)
            or slot < 1
            or slot > expected_blocks * len(ARMS)
            or not isinstance(block, int)
            or isinstance(block, bool)
            or block != (slot - 1) // len(ARMS) + 1
            or arm not in ARMS
        ):
            raise ValueError("Controlled 2B slot, block, or arm is invalid")
        if slot in slots:
            raise ValueError("Controlled 2B analysis contains a duplicate slot")
        slots.add(slot)
        if row.get("experimental_result") is not True:
            raise ValueError("Engineering or pilot row cannot enter controlled analysis")

        entered = row.get("entry_success")
        dwell = row.get("dwell_time_s")
        reason = row.get("termination_reason")
        if not isinstance(entered, bool) or not isinstance(reason, str) or not reason:
            raise ValueError("Controlled 2B entry or termination value is invalid")
        _nonnegative_number(dwell, "Controlled 2B dwell_time_s", nullable=not entered)
        if entered and dwell is None:
            raise ValueError("Entered controlled run lacks dwell time")
        if not entered and dwell is not None:
            raise ValueError("Non-entered controlled run has post-entry dwell time")

        judgments = row.get("judgments")
        if not isinstance(judgments, dict) or set(judgments) != JUDGMENT_KEYS:
            raise ValueError("Controlled 2B final judgments are incomplete")
        disposition = judgments.get("disposition")
        if disposition not in DISPOSITIONS:
            raise ValueError("Controlled 2B disposition is invalid")
        if entered:
            if (
                judgments.get("suspicion") not in SUSPICION
                or judgments.get("escape_attempt") not in ESCAPE
                or disposition == "no_entry"
            ):
                raise ValueError("Entered controlled run lacks adjudicated judgments")
        elif judgments != {
            "suspicion": None,
            "disposition": "no_entry",
            "escape_attempt": None,
        }:
            raise ValueError("Non-entered controlled run has incompatible judgments")

        metrics = row.get("metrics")
        if not isinstance(metrics, dict) or set(metrics) != METRIC_KEYS:
            raise ValueError("Controlled 2B metric row is incomplete")
        for name, value in metrics.items():
            _validate_metric(name, value)

    if len(study_ids) != 1 or len(schedule_hashes) != 1:
        raise ValueError("Controlled 2B rows mix studies or schedules")
    if slots != set(range(1, expected_blocks * len(ARMS) + 1)):
        raise ValueError("Controlled 2B schedule has a slot gap")
    for block in range(1, expected_blocks + 1):
        block_rows = [row for row in normalized if row["block"] == block]
        if len(block_rows) != len(ARMS) or {row["arm"] for row in block_rows} != set(
            ARMS
        ):
            raise ValueError("Controlled 2B analysis block is not balanced")
    return sorted(normalized, key=lambda row: row["slot"])


def validate_controlled_rows(
    rows: Sequence[dict[str, Any]], contract: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Validate the exact production cohort; no incomplete-study override exists."""

    contract = contract or load_contract()
    if contract.get("study_protocol") != STUDY_PROTOCOL:
        raise ValueError("Controlled 2B analysis contract identity differs")
    blocks = contract.get("design", {}).get("balanced_blocks")
    required = contract.get("design", {}).get("required_valid_runs")
    if blocks != 10 or required != 40:
        raise ValueError("Controlled 2B production cohort size differs")
    validated = _validate_rows(rows, expected_blocks=blocks)
    if len(validated) != required:
        raise ValueError("Controlled 2B production cohort is incomplete")
    return validated


def _validate_schedule_binding(
    rows: Sequence[dict[str, Any]],
    *,
    schedule: dict[str, Any],
    schedule_sha256: str,
    contract: dict[str, Any],
) -> None:
    if not isinstance(schedule, dict) or schedule.get("schema_version") != 1:
        raise ValueError("Controlled 2B committed schedule is invalid")
    if not isinstance(schedule_sha256, str) or not HEX_DIGEST.fullmatch(
        schedule_sha256
    ):
        raise ValueError("Controlled 2B committed schedule digest is invalid")
    rendered = json.dumps(schedule, indent=2, sort_keys=True) + "\n"
    if hashlib.sha256(rendered.encode("utf-8")).hexdigest() != schedule_sha256:
        raise ValueError("Controlled 2B schedule object differs from its commitment")
    if schedule.get("contract") != contract:
        raise ValueError("Controlled 2B schedule embeds a different contract")
    if schedule.get("study_id") != rows[0]["study_id"] or any(
        row["schedule_sha256"] != schedule_sha256 for row in rows
    ):
        raise ValueError("Controlled 2B rows are bound to another schedule")
    assignments = schedule.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != len(rows):
        raise ValueError("Controlled 2B schedule assignment count differs")
    expected = {
        item.get("slot"): (item.get("block"), item.get("arm"))
        for item in assignments
        if isinstance(item, dict)
    }
    if len(expected) != len(rows) or any(
        expected.get(row["slot"]) != (row["block"], row["arm"]) for row in rows
    ):
        raise ValueError("Controlled 2B row assignment differs from frozen schedule")


def _observations(
    rows: Iterable[dict[str, Any]],
    *,
    indeterminate: str = "exclude",
) -> list[tuple[float, bool]]:
    if indeterminate not in {"exclude", "event", "censor"}:
        raise ValueError("Invalid indeterminate sensitivity policy")
    observations: list[tuple[float, bool]] = []
    for row in rows:
        if not row["entry_success"]:
            continue
        disposition = row["judgments"]["disposition"]
        if disposition == "indeterminate" and indeterminate == "exclude":
            continue
        if disposition in {"task_completed", "abandoned_decoy"}:
            event = True
        elif disposition == "continued_until_censored":
            event = False
        elif disposition == "indeterminate":
            event = indeterminate == "event"
        else:
            raise ValueError("Entered run has no analyzable disposition")
        observations.append((float(row["dwell_time_s"]), event))
    return observations


def _greenwood_log_log_interval(
    survival: float, greenwood_sum: float
) -> list[float] | None:
    """Return the pointwise 95% log-minus-log Greenwood interval."""

    if survival <= 0.0:
        return [0.0, 0.0]
    if survival >= 1.0:
        return [1.0, 1.0]
    if not math.isfinite(greenwood_sum) or greenwood_sum < 0:
        return None
    standard_error = math.sqrt(greenwood_sum) / abs(math.log(survival))
    transformed = math.log(-math.log(survival))
    lower = math.exp(-math.exp(transformed + 1.959963984540054 * standard_error))
    upper = math.exp(-math.exp(transformed - 1.959963984540054 * standard_error))
    return [max(0.0, lower), min(1.0, upper)]


def kaplan_meier(
    observations: Sequence[tuple[float, bool]],
    *,
    tau: float,
    horizons: Sequence[float] = (),
) -> dict[str, Any]:
    """Return a nonparametric survival curve, horizon estimates, and RMST.

    Censoring reduces later risk sets but never acts as a disengagement event.
    Values beyond the last observation are reported only if follow-up reaches
    the requested horizon or the survival curve has already reached zero.
    """

    _nonnegative_number(tau, "RMST tau")
    if tau <= 0:
        raise ValueError("RMST tau must be positive")
    clean: list[tuple[float, bool]] = []
    for duration, event in observations:
        _nonnegative_number(duration, "Survival duration")
        if not isinstance(event, bool):
            raise ValueError("Survival event indicator must be boolean")
        clean.append((float(duration), event))
    requested = sorted(set(float(value) for value in horizons))
    if any(value < 0 or value > tau for value in requested):
        raise ValueError("Retention horizon lies outside the RMST interval")
    if not clean:
        return {
            "observations": 0,
            "events": 0,
            "censored": 0,
            "curve": [],
            "retention": {str(int(value)): None for value in requested},
            "retention_ci95_greenwood_log_log": {
                str(int(value)): None for value in requested
            },
            "rmst": None,
            "estimable_to_tau": False,
            "max_followup": None,
        }

    event_times = sorted(
        {duration for duration, event in clean if event and duration <= tau}
    )
    survival = 1.0
    previous = 0.0
    area = 0.0
    curve: list[dict[str, Any]] = []
    survival_steps: list[tuple[float, float, float]] = []
    greenwood_sum = 0.0
    for timestamp in event_times:
        area += survival * max(0.0, timestamp - previous)
        at_risk = sum(duration >= timestamp for duration, _ in clean)
        events = sum(
            duration == timestamp and event for duration, event in clean
        )
        if at_risk <= 0 or events <= 0 or events > at_risk:
            raise ValueError("Survival risk set is inconsistent")
        survival *= 1.0 - events / at_risk
        if events < at_risk:
            greenwood_sum += events / (at_risk * (at_risk - events))
        else:
            greenwood_sum = math.inf
        curve.append(
            {
                "time": timestamp,
                "at_risk": at_risk,
                "events": events,
                "survival": survival,
                "greenwood_sum": greenwood_sum,
            }
        )
        survival_steps.append((timestamp, survival, greenwood_sum))
        previous = timestamp

    max_followup = max(duration for duration, _ in clean)
    estimable_to_tau = max_followup >= tau or survival <= 0.0
    rmst = None
    if estimable_to_tau:
        rmst = area + survival * max(0.0, tau - previous)

    retention: dict[str, float | None] = {}
    retention_intervals: dict[str, list[float] | None] = {}
    for horizon in requested:
        value = 1.0
        horizon_greenwood = 0.0
        for timestamp, step_survival, step_greenwood in survival_steps:
            if timestamp <= horizon:
                value = step_survival
                horizon_greenwood = step_greenwood
            else:
                break
        key = str(int(horizon))
        estimable = max_followup >= horizon or value <= 0.0
        retention[key] = value if estimable else None
        retention_intervals[key] = (
            _greenwood_log_log_interval(value, horizon_greenwood)
            if estimable
            else None
        )
    return {
        "observations": len(clean),
        "events": sum(event for _, event in clean),
        "censored": sum(not event for _, event in clean),
        "curve": curve,
        "retention": retention,
        "retention_ci95_greenwood_log_log": retention_intervals,
        "rmst": rmst,
        "estimable_to_tau": estimable_to_tau,
        "max_followup": max_followup,
    }


def _arm_primary(
    rows: Sequence[dict[str, Any]],
    *,
    tau: float,
    horizons: Sequence[float],
    indeterminate: str = "exclude",
) -> dict[str, dict[str, Any]]:
    return {
        arm: kaplan_meier(
            _observations(
                [row for row in rows if row["arm"] == arm],
                indeterminate=indeterminate,
            ),
            tau=tau,
            horizons=horizons,
        )
        for arm in ARMS
    }


def factorial_contrasts(
    arm_values: dict[str, float | None]
) -> dict[str, float | None]:
    if set(arm_values) != set(ARMS):
        raise ValueError("Factorial contrast requires all four arms")
    result: dict[str, float | None] = {}
    for name, coefficients in CONTRAST_COEFFICIENTS.items():
        if any(arm_values[arm] is None for arm in ARMS):
            result[name] = None
        else:
            result[name] = sum(
                coefficients[arm] * float(arm_values[arm])  # type: ignore[arg-type]
                for arm in ARMS
            )
    return result


def _percentile(values: Sequence[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _analysis_seed(schedule_sha256: str) -> int:
    if not HEX_DIGEST.fullmatch(schedule_sha256):
        raise ValueError("Controlled 2B schedule digest is invalid")
    return int(
        hashlib.sha256(f"{schedule_sha256}:analysis".encode("utf-8")).hexdigest(),
        16,
    )


class _Sha256CounterSampler:
    """Runtime-independent pseudo-random sampler for frozen inference draws."""

    def __init__(self, seed: int, domain: str) -> None:
        self._key = seed.to_bytes(32, "big") + domain.encode("ascii")
        self._counter = 0

    def _uint64(self) -> int:
        digest = hashlib.sha256(
            self._key + self._counter.to_bytes(16, "big")
        ).digest()
        self._counter += 1
        return int.from_bytes(digest[:8], "big")

    def randbelow(self, stop: int) -> int:
        if not isinstance(stop, int) or isinstance(stop, bool) or stop < 1:
            raise ValueError("Sampler bound must be a positive integer")
        width = 1 << 64
        limit = width - width % stop
        while True:
            value = self._uint64()
            if value < limit:
                return value % stop

    def choices(self, values: Sequence[Any], count: int) -> list[Any]:
        if not values:
            raise ValueError("Cannot sample an empty sequence")
        return [values[self.randbelow(len(values))] for _ in range(count)]

    def shuffle(self, values: list[Any]) -> None:
        for index in range(len(values) - 1, 0, -1):
            other = self.randbelow(index + 1)
            values[index], values[other] = values[other], values[index]


def _bootstrap(
    rows: Sequence[dict[str, Any]],
    *,
    tau: float,
    horizons: Sequence[float],
    replicates: int,
    schedule_sha256: str,
    observed: dict[str, float | None],
) -> dict[str, Any]:
    if replicates < 1:
        raise ValueError("Block bootstrap requires at least one replicate")
    blocks = sorted({row["block"] for row in rows})
    by_block = {
        block: [row for row in rows if row["block"] == block] for block in blocks
    }
    rng = _Sha256CounterSampler(
        _analysis_seed(schedule_sha256), f"{STUDY_PROTOCOL}:block-bootstrap"
    )
    samples = {name: [] for name in CONTRAST_COEFFICIENTS}
    for _ in range(replicates):
        sampled: list[dict[str, Any]] = []
        for block in rng.choices(blocks, len(blocks)):
            sampled.extend(by_block[block])
        primary = _arm_primary(sampled, tau=tau, horizons=horizons)
        values = factorial_contrasts(
            {arm: primary[arm]["rmst"] for arm in ARMS}
        )
        for name, value in values.items():
            if value is not None:
                samples[name].append(value)
    result = {}
    for name, values in samples.items():
        if observed[name] is None:
            status = "not_estimable"
            reason = "observed_contrast_not_estimable"
        elif len(values) != replicates:
            status = "not_estimable"
            reason = "not_all_bootstrap_replicates_estimable"
        else:
            status = "complete"
            reason = None
        result[name] = {
            "ci95": (
                [_percentile(values, 0.025), _percentile(values, 0.975)]
                if status == "complete"
                else None
            ),
            "estimable_replicates": len(values),
            "requested_replicates": replicates,
            "bootstrap_status": status,
            "bootstrap_null_reason": reason,
        }
    return result


def holm_adjust(p_values: dict[str, float | None]) -> dict[str, float | None]:
    """Holm-adjust a fixed family, retaining nulls for non-estimable tests."""

    family_size = len(p_values)
    observed = sorted(
        ((name, value) for name, value in p_values.items() if value is not None),
        key=lambda item: item[1],
    )
    adjusted: dict[str, float | None] = {name: None for name in p_values}
    previous = 0.0
    for index, (name, value) in enumerate(observed):
        if not 0 <= value <= 1:
            raise ValueError("P-value lies outside [0, 1]")
        candidate = min(1.0, (family_size - index) * value)
        previous = max(previous, candidate)
        adjusted[name] = previous
    return adjusted


def _randomization_tests(
    rows: Sequence[dict[str, Any]],
    *,
    tau: float,
    horizons: Sequence[float],
    draws: int,
    schedule_sha256: str,
    observed: dict[str, float | None],
) -> dict[str, Any]:
    if draws < 1:
        raise ValueError("Randomization test requires at least one draw")
    blocks = sorted({row["block"] for row in rows})
    by_block = {
        block: sorted(
            [row for row in rows if row["block"] == block],
            key=lambda row: row["slot"],
        )
        for block in blocks
    }
    rng = _Sha256CounterSampler(
        _analysis_seed(schedule_sha256), f"{STUDY_PROTOCOL}:randomization"
    )
    extreme = {name: 0 for name in CONTRAST_COEFFICIENTS}
    estimable = {name: 0 for name in CONTRAST_COEFFICIENTS}
    for _ in range(draws):
        permuted: list[dict[str, Any]] = []
        for block in blocks:
            labels = list(ARMS)
            rng.shuffle(labels)
            for row, arm in zip(by_block[block], labels):
                permuted.append({**row, "arm": arm})
        primary = _arm_primary(permuted, tau=tau, horizons=horizons)
        values = factorial_contrasts(
            {arm: primary[arm]["rmst"] for arm in ARMS}
        )
        for name, value in values.items():
            if value is None or observed[name] is None:
                continue
            estimable[name] += 1
            extreme[name] += abs(value) >= abs(observed[name]) - 1e-12
    raw: dict[str, float | None] = {}
    reasons: dict[str, str | None] = {}
    for name in CONTRAST_COEFFICIENTS:
        if observed[name] is None:
            raw[name] = None
            reasons[name] = "observed_contrast_not_estimable"
        elif estimable[name] != draws:
            raw[name] = None
            reasons[name] = "not_all_randomization_draws_estimable"
        else:
            raw[name] = (extreme[name] + 1) / (draws + 1)
            reasons[name] = None
    adjusted = holm_adjust(raw)
    return {
        name: {
            "two_sided_p": raw[name],
            "holm_adjusted_p": adjusted[name],
            "estimable_draws": estimable[name],
            "requested_draws": draws,
            "randomization_status": (
                "complete" if reasons[name] is None else "not_estimable"
            ),
            "randomization_null_reason": reasons[name],
        }
        for name in CONTRAST_COEFFICIENTS
    }


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if (
        not isinstance(successes, int)
        or isinstance(successes, bool)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or successes < 0
        or total < 0
        or successes > total
    ):
        raise ValueError("Wilson interval counts are invalid")
    if total == 0:
        return None
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    half_width = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / total
            + z * z / (4 * total * total)
        )
        / denominator
    )
    return [max(0.0, center - half_width), min(1.0, center + half_width)]


def _t_critical_975(degrees_freedom: int) -> float:
    if degrees_freedom < 1:
        raise ValueError("Student t interval needs positive degrees of freedom")
    if degrees_freedom < len(T_CRITICAL_975):
        return T_CRITICAL_975[degrees_freedom]
    if degrees_freedom <= 40:
        return 2.021
    if degrees_freedom <= 60:
        return 2.000
    if degrees_freedom <= 120:
        return 1.980
    return 1.959963984540054


def _numeric_summary(values: Sequence[Any]) -> dict[str, Any]:
    observed = [float(value) for value in values if value is not None]
    if not observed:
        return {
            "n": 0,
            "missing": len(values),
            "mean": None,
            "mean_ci95_student_t": None,
            "median": None,
            "minimum": None,
            "maximum": None,
        }
    mean = sum(observed) / len(observed)
    interval = None
    if len(observed) >= 2:
        margin = (
            _t_critical_975(len(observed) - 1)
            * stdev(observed)
            / math.sqrt(len(observed))
        )
        interval = [mean - margin, mean + margin]
    return {
        "n": len(observed),
        "missing": len(values) - len(observed),
        "mean": mean,
        "mean_ci95_student_t": interval,
        "median": median(observed),
        "minimum": min(observed),
        "maximum": max(observed),
    }


def _judgment_summary(
    rows: Sequence[dict[str, Any]], name: str
) -> dict[str, Any]:
    values = [
        row["judgments"][name]
        for row in rows
        if row["judgments"][name] is not None
    ]
    counts = Counter(values)
    total = len(values)
    return {
        "n": total,
        "categories": {
            value: {
                "count": counts[value],
                "proportion": counts[value] / total if total else None,
                "ci95_wilson": wilson_interval(counts[value], total),
            }
            for value in JUDGMENT_CATEGORIES[name]
        },
    }


def _arm_summaries(
    rows: Sequence[dict[str, Any]],
    primary: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    summaries: dict[str, Any] = {}
    for arm in ARMS:
        arm_rows = [row for row in rows if row["arm"] == arm]
        entered = [row for row in arm_rows if row["entry_success"]]
        summaries[arm] = {
            "runs": len(arm_rows),
            "entered": len(entered),
            "entry_rate": len(entered) / len(arm_rows),
            "entry_rate_ci95_wilson": wilson_interval(
                len(entered), len(arm_rows)
            ),
            "primary": primary[arm],
            "termination_reasons": dict(
                sorted(Counter(row["termination_reason"] for row in arm_rows).items())
            ),
            "judgments": {
                name: _judgment_summary(entered, name)
                for name in sorted(JUDGMENT_KEYS)
            },
            "metrics": {
                name: _numeric_summary([row["metrics"][name] for row in entered])
                for name in sorted(METRIC_KEYS)
            },
        }
    return summaries


def _sensitivity_bounds(
    rows: Sequence[dict[str, Any]],
    *,
    tau: float,
    horizons: Sequence[float],
) -> dict[str, Any]:
    lower_primary = _arm_primary(
        rows, tau=tau, horizons=horizons, indeterminate="event"
    )
    upper_primary = _arm_primary(
        rows, tau=tau, horizons=horizons, indeterminate="censor"
    )
    arm_bounds = {
        arm: {
            "lower_event_assumption": lower_primary[arm]["rmst"],
            "upper_censor_assumption": upper_primary[arm]["rmst"],
        }
        for arm in ARMS
    }
    contrast_bounds: dict[str, Any] = {}
    for name, coefficients in CONTRAST_COEFFICIENTS.items():
        if any(
            arm_bounds[arm]["lower_event_assumption"] is None
            or arm_bounds[arm]["upper_censor_assumption"] is None
            for arm in ARMS
        ):
            contrast_bounds[name] = {"lower": None, "upper": None}
            continue
        lower = 0.0
        upper = 0.0
        for arm, coefficient in coefficients.items():
            arm_low = float(arm_bounds[arm]["lower_event_assumption"])
            arm_high = float(arm_bounds[arm]["upper_censor_assumption"])
            lower += coefficient * (arm_low if coefficient >= 0 else arm_high)
            upper += coefficient * (arm_high if coefficient >= 0 else arm_low)
        contrast_bounds[name] = {"lower": lower, "upper": upper}
    return {
        "indeterminate_assumptions": {
            "lower": "all indeterminate dispositions are disengagement events at observed dwell",
            "upper": "all indeterminate dispositions are censored at observed dwell",
        },
        "arm_rmst": arm_bounds,
        "factorial_contrasts": contrast_bounds,
    }


def _analyze(
    rows: Sequence[dict[str, Any]],
    *,
    tau: float,
    horizons: Sequence[float],
    bootstrap_replicates: int,
    randomization_draws: int,
) -> dict[str, Any]:
    schedule_sha256 = rows[0]["schedule_sha256"]
    primary = _arm_primary(rows, tau=tau, horizons=horizons)
    arm_values = {arm: primary[arm]["rmst"] for arm in ARMS}
    estimates = factorial_contrasts(arm_values)
    bootstrap = _bootstrap(
        rows,
        tau=tau,
        horizons=horizons,
        replicates=bootstrap_replicates,
        schedule_sha256=schedule_sha256,
        observed=estimates,
    )
    tests = _randomization_tests(
        rows,
        tau=tau,
        horizons=horizons,
        draws=randomization_draws,
        schedule_sha256=schedule_sha256,
        observed=estimates,
    )
    contrasts = {
        name: {
            "estimate": estimates[name],
            **bootstrap[name],
            **tests[name],
        }
        for name in CONTRAST_COEFFICIENTS
    }
    return {
        "schema_version": 1,
        "study_protocol": STUDY_PROTOCOL,
        "study_id": rows[0]["study_id"],
        "schedule_sha256": schedule_sha256,
        "row_count": len(rows),
        "blocks": len({row["block"] for row in rows}),
        "primary_endpoint": {
            "name": "restricted_mean_time_to_disengagement_seconds",
            "tau_seconds": tau,
            "time_origin": "first_successful_filesystem_interaction",
            "arm_rmst": arm_values,
            "factorial_contrasts": contrasts,
            "sensitivity_bounds": _sensitivity_bounds(
                rows, tau=tau, horizons=horizons
            ),
        },
        "arm_summaries": _arm_summaries(rows, primary),
        "analysis_parameters": {
            "retention_horizons_seconds": list(horizons),
            "bootstrap_replicates": bootstrap_replicates,
            "randomization_test_draws": randomization_draws,
            "analysis_seed_sha256": hashlib.sha256(
                f"{schedule_sha256}:analysis".encode("utf-8")
            ).hexdigest(),
            "sampler": "sha256_counter_uint64_rejection_fisher_yates_v1",
            "multiplicity_adjustment": "holm",
            "positive_direction": "greater_retention",
            "confidence_level": 0.95,
            "retention_interval_method": "pointwise_greenwood_log_minus_log",
            "numeric_mean_interval_method": "student_t",
            "proportion_interval_method": "wilson",
            "post_entry_metrics_only": True,
        },
    }


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return format(value, ".12g")
    return str(value)


def _arm_summary_csv(report: dict[str, Any]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(
        [
            "arm",
            "runs",
            "entered",
            "entry_rate",
            "entry_ci95_lower",
            "entry_ci95_upper",
            "rmst_seconds",
            "rmst_estimable_to_tau",
            "events",
            "censored",
            "retention_60",
            "retention_180",
            "retention_300",
            "retention_600",
        ]
    )
    for arm in ARMS:
        summary = report["arm_summaries"][arm]
        primary = summary["primary"]
        interval = summary["entry_rate_ci95_wilson"] or [None, None]
        retention = primary["retention"]
        writer.writerow(
            [
                arm,
                summary["runs"],
                summary["entered"],
                _csv_value(summary["entry_rate"]),
                _csv_value(interval[0]),
                _csv_value(interval[1]),
                _csv_value(primary["rmst"]),
                str(primary["estimable_to_tau"]).lower(),
                primary["events"],
                primary["censored"],
                *(
                    _csv_value(retention.get(str(horizon)))
                    for horizon in (60, 180, 300, 600)
                ),
            ]
        )
    return stream.getvalue()


def _factorial_contrasts_csv(report: dict[str, Any]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(
        [
            "contrast",
            "estimate_seconds",
            "ci95_lower",
            "ci95_upper",
            "two_sided_p",
            "holm_adjusted_p",
            "bootstrap_status",
            "randomization_status",
        ]
    )
    contrasts = report["primary_endpoint"]["factorial_contrasts"]
    for name in CONTRAST_COEFFICIENTS:
        value = contrasts[name]
        interval = value["ci95"] or [None, None]
        writer.writerow(
            [
                name,
                _csv_value(value["estimate"]),
                _csv_value(interval[0]),
                _csv_value(interval[1]),
                _csv_value(value["two_sided_p"]),
                _csv_value(value["holm_adjusted_p"]),
                value["bootstrap_status"],
                value["randomization_status"],
            ]
        )
    return stream.getvalue()


def _retention_svg(report: dict[str, Any]) -> str:
    width, height = 800, 480
    left, right, top, bottom = 76, 24, 42, 64
    plot_width = width - left - right
    plot_height = height - top - bottom
    tau = float(report["primary_endpoint"]["tau_seconds"])
    colors = {"B0": "#3b82f6", "B1": "#16a34a", "B2": "#ea580c", "B3": "#9333ea"}
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="400" y="25" text-anchor="middle" font-family="sans-serif" font-size="17">Controlled 2B post-entry retention</text>',
        f'<line x1="{left}" y1="{top + plot_height}" x2="{left + plot_width}" y2="{top + plot_height}" stroke="#111"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_height}" stroke="#111"/>',
    ]
    for horizon in (0, 60, 180, 300, 600):
        x = left + plot_width * min(float(horizon), tau) / tau
        lines.extend(
            [
                f'<line x1="{x:.2f}" y1="{top}" x2="{x:.2f}" y2="{top + plot_height}" stroke="#e5e7eb"/>',
                f'<text x="{x:.2f}" y="{top + plot_height + 24}" text-anchor="middle" font-family="sans-serif" font-size="12">{horizon}</text>',
            ]
        )
    for proportion in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = top + plot_height * (1.0 - proportion)
        lines.extend(
            [
                f'<line x1="{left}" y1="{y:.2f}" x2="{left + plot_width}" y2="{y:.2f}" stroke="#e5e7eb"/>',
                f'<text x="{left - 10}" y="{y + 4:.2f}" text-anchor="end" font-family="sans-serif" font-size="12">{proportion:.2f}</text>',
            ]
        )
    for index, arm in enumerate(ARMS):
        primary = report["arm_summaries"][arm]["primary"]
        path = [f"M {left:.2f} {top:.2f}"]
        survival = 1.0
        for step in primary["curve"]:
            x = left + plot_width * min(float(step["time"]), tau) / tau
            y_before = top + plot_height * (1.0 - survival)
            survival = float(step["survival"])
            y_after = top + plot_height * (1.0 - survival)
            path.extend([f"H {x:.2f}", f"V {y_after:.2f}"])
        followup = primary.get("max_followup")
        if followup is not None:
            x = left + plot_width * min(float(followup), tau) / tau
            path.append(f"H {x:.2f}")
        color = colors[arm]
        lines.append(
            f'<path d="{escape(" ".join(path))}" fill="none" stroke="{color}" stroke-width="2.5"/>'
        )
        legend_x = left + plot_width - 130
        legend_y = top + 18 + index * 22
        lines.extend(
            [
                f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x + 25}" y2="{legend_y}" stroke="{color}" stroke-width="3"/>',
                f'<text x="{legend_x + 33}" y="{legend_y + 4}" font-family="sans-serif" font-size="12">{arm}</text>',
            ]
        )
    lines.extend(
        [
            f'<text x="{left + plot_width / 2:.2f}" y="{height - 14}" text-anchor="middle" font-family="sans-serif" font-size="13">Seconds since first successful filesystem interaction</text>',
            f'<text x="18" y="{top + plot_height / 2:.2f}" text-anchor="middle" font-family="sans-serif" font-size="13" transform="rotate(-90 18 {top + plot_height / 2:.2f})">Retention probability</text>',
            "</svg>",
        ]
    )
    return "\n".join(lines) + "\n"


def _limitations_markdown(report: dict[str, Any]) -> str:
    summaries = report["arm_summaries"]
    entered = sum(summaries[arm]["entered"] for arm in ARMS)
    contrasts = report["primary_endpoint"]["factorial_contrasts"]
    fully_estimable = all(
        value["estimate"] is not None
        and value["ci95"] is not None
        and value["holm_adjusted_p"] is not None
        for value in contrasts.values()
    )
    significant = [
        name
        for name, value in contrasts.items()
        if value["holm_adjusted_p"] is not None
        and value["holm_adjusted_p"] < 0.05
    ]
    if not fully_estimable:
        verdict = (
            "The complete confirmatory family was not estimable under the frozen "
            "censoring rules; no confirmatory effect verdict is supported."
        )
    elif significant:
        verdict = (
            "At least one predeclared factorial contrast crossed the Holm-adjusted "
            "0.05 threshold: " + ", ".join(significant) + "."
        )
    else:
        verdict = (
            "No predeclared factorial contrast crossed the Holm-adjusted 0.05 "
            "threshold. This is not evidence that the effects are zero."
        )
    return (
        "# Controlled 2B limitations and verdict\n\n"
        f"Study `{report['study_id']}` contains {report['row_count']} valid assigned "
        f"runs in {report['blocks']} complete blocks; {entered} runs reached the "
        "first successful filesystem interaction.\n\n"
        "## Frozen-analysis verdict\n\n"
        f"{verdict}\n\n"
        "## Interpretation limits\n\n"
        "- The post-entry RMST is conditional on successful entry; non-entry is "
        "reported separately and is not a zero-retention observation.\n"
        "- Results apply to the pinned PentestGPT version, model, provider, task, "
        "fixture, adapter, and caps, not to general-purpose agents as a class.\n"
        "- Review packets hide explicit arm fields, but reviewers may infer an arm "
        "from filesystem content; perfect blinding is not claimed.\n"
        "- Administrative censoring and indeterminate dispositions are reported; "
        "the latter receive the frozen best/worst-case sensitivity analysis.\n"
        "- Completion and abandonment time use the controller/Docker-observed "
        "termination instant, not a timestamp inferred from reviewer judgment.\n"
        "- An annotated escape attempt is not a confirmed containment incident.\n"
    )


def render_analysis_artifacts(report: dict[str, Any]) -> dict[str, str]:
    """Render deterministic human-readable artifacts from a validated report."""

    return {
        "arm-summary.csv": _arm_summary_csv(report),
        "factorial-contrasts.csv": _factorial_contrasts_csv(report),
        "retention.svg": _retention_svg(report),
        "limitations-and-verdict.md": _limitations_markdown(report),
    }


def analyze_controlled(
    rows: Sequence[dict[str, Any]],
    *,
    schedule: dict[str, Any],
    schedule_sha256: str,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze rows bound to the complete committed production schedule."""

    contract = contract or load_contract()
    validated = validate_controlled_rows(rows, contract)
    _validate_schedule_binding(
        validated,
        schedule=schedule,
        schedule_sha256=schedule_sha256,
        contract=contract,
    )
    analysis = contract["analysis"]
    uncertainty = analysis["uncertainty"]
    return _analyze(
        validated,
        tau=float(analysis["primary_endpoint"]["tau_seconds"]),
        horizons=contract["trial_caps"]["retention_horizons_seconds"],
        bootstrap_replicates=uncertainty["block_bootstrap_replicates"],
        randomization_draws=uncertainty["randomization_test_draws"],
    )


def analyze_fixture(
    rows: Sequence[dict[str, Any]],
    *,
    expected_blocks: int,
    tau: float = 600,
    horizons: Sequence[float] = (60, 180, 300, 600),
    bootstrap_replicates: int = 100,
    randomization_draws: int = 199,
) -> dict[str, Any]:
    """Analyze an explicitly small model-free fixture; never use for a study."""

    validated = _validate_rows(rows, expected_blocks=expected_blocks)
    return _analyze(
        validated,
        tau=tau,
        horizons=horizons,
        bootstrap_replicates=bootstrap_replicates,
        randomization_draws=randomization_draws,
    )
