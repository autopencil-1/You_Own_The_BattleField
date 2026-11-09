"""Validate the non-executable controlled-2B-v3 pre-execution freeze."""

from __future__ import annotations

from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from experiment_controller import controlled_2b_contract as controlled_v2
from experiment_controller import support_pilot_2b
from experiment_controller.support_closeout_2b import verify_closeout


LAB = Path(__file__).resolve().parents[1]
CONFIG = LAB / "config" / "exp_2b_controlled_v3.json"
COMMITMENT = LAB / "config" / "exp_2b_controlled_v3.sha256"
TASK = LAB / "config" / "agent_2b_task.json"
FIXTURE = LAB / "config" / "exp_2b_engine_fixture.json"
V2_CONFIG = LAB / "config" / "exp_2b_controlled_v2.json"
SUPPORT_CONFIG = LAB / "config" / "exp_2b_support_pilot_v3.json"
PILOT_ID = "2b-support-pilot-v3-20261106055726-49c7fa"
PILOT_DIR = LAB / "studies" / PILOT_ID
CLOSEOUT = PILOT_DIR / "closeout"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is missing or malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def _committed(path: Path, commitment: Path, label: str) -> str:
    try:
        expected = commitment.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"{label} commitment is missing") from exc
    observed = sha256(path)
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or observed != expected:
        raise ValueError(f"{label} differs from its commitment")
    return observed


def _format_nano_usd(value: int) -> str:
    whole, fractional = divmod(value, 1_000_000_000)
    return f"{whole}.{fractional:09d}"


def _frozen_source_hashes() -> dict[str, str]:
    return {
        "agent_task": sha256(TASK),
        "filesystem_fixture": sha256(FIXTURE),
        "controlled_v2_contract": sha256(V2_CONFIG),
        "support_v3_execution_contract": sha256(SUPPORT_CONFIG),
        "support_v3_schedule": sha256(PILOT_DIR / "schedule.json"),
        "support_v3_readiness": sha256(PILOT_DIR / "readiness.json"),
        "support_v3_closeout_bundle": sha256(CLOSEOUT / "bundle-manifest.json"),
        "support_v3_closeout_evidence": sha256(
            CLOSEOUT / "evidence-manifest.json"
        ),
        "support_v3_replay_verification": sha256(
            CLOSEOUT / "replay-verification.json"
        ),
        "support_v3_cost_ledger": sha256(CLOSEOUT / "cost-ledger.json"),
        "runtime_policy": sha256(LAB / "agent_runner" / "runtime_policy_2b.py"),
        "cap_taxonomy": sha256(LAB / "telemetry" / "cap_taxonomy_2b.py"),
        "scorer": sha256(LAB / "telemetry" / "score_2b.py"),
        "replay": sha256(LAB / "telemetry" / "replay_2b.py"),
        "review_projection": sha256(LAB / "telemetry" / "annotate_2b.py"),
        "adjudication": sha256(LAB / "telemetry" / "adjudicate_2b.py"),
        "analysis": sha256(LAB / "telemetry" / "analyze_2b.py"),
        "readiness_evaluator": sha256(
            LAB / "experiment_controller" / "support_readiness_2b.py"
        ),
        "closeout_verifier": sha256(
            LAB / "experiment_controller" / "support_closeout_2b.py"
        ),
    }


def _readiness_dependency(readiness: dict[str, Any]) -> dict[str, Any]:
    schedule_sha = _committed(
        PILOT_DIR / "schedule.json", PILOT_DIR / "schedule.sha256", "Support schedule"
    )
    readiness_sha = _committed(
        PILOT_DIR / "readiness.json",
        PILOT_DIR / "readiness.sha256",
        "Support readiness",
    )
    checks = readiness.get("checks")
    required = readiness.get("required_checks")
    if (
        readiness.get("pilot_id") != PILOT_ID
        or readiness.get("pilot_protocol") != "2b-support-pilot-v3"
        or readiness.get("passed") is not True
        or readiness.get("schedule_sha256") != schedule_sha
        or not isinstance(checks, dict)
        or not isinstance(required, list)
        or set(checks) != set(required)
        or not all(checks.get(name) is True for name in required)
    ):
        raise ValueError("Controlled-v3 support readiness dependency did not pass")
    return {
        "pilot_id": PILOT_ID,
        "schedule_sha256": schedule_sha,
        "readiness_sha256": readiness_sha,
        "require_passed": True,
        "required_checks": required,
    }


def _closeout_dependency() -> dict[str, Any]:
    verified = verify_closeout(PILOT_ID)
    expected = {
        "attempts_preserved": 9,
        "valid_attempts": 8,
        "infrastructure_invalid_attempts": 1,
        "all_scores_reproduced": True,
    }
    if any(verified.get(key) != value for key, value in expected.items()):
        raise ValueError("Controlled-v3 support closeout population differs")
    return {
        "pilot_id": PILOT_ID,
        "bundle_manifest_sha256": sha256(CLOSEOUT / "bundle-manifest.json"),
        "evidence_manifest_sha256": sha256(CLOSEOUT / "evidence-manifest.json"),
        "replay_verification_sha256": sha256(
            CLOSEOUT / "replay-verification.json"
        ),
        "cost_ledger_sha256": sha256(CLOSEOUT / "cost-ledger.json"),
        **expected,
    }


def _pre_entry_bound_basis(readiness: dict[str, Any]) -> dict[str, Any]:
    run_ids = readiness.get("valid_run_ids")
    if not isinstance(run_ids, list) or len(run_ids) != 8:
        raise ValueError("Support readiness valid-run population differs")
    observed = []
    for run_id in run_ids:
        if not isinstance(run_id, str):
            raise ValueError("Support readiness run identity differs")
        result = _json(LAB / "runs" / run_id / "result.json", "Support result")
        manifest = result.get("manifest")
        score = result.get("score")
        if (
            not isinstance(manifest, dict)
            or not isinstance(score, dict)
            or manifest.get("run_id") != run_id
            or manifest.get("assignment", {}).get("pilot_id") != PILOT_ID
            or score.get("entry_success") is not True
        ):
            raise ValueError("Support pre-entry evidence differs")
        value = score.get("pre_entry_elapsed_s")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError("Support pre-entry elapsed time is missing")
        observed.append(value)
    observed_max = max(observed)
    if abs(observed_max - 57.369347) > 0.000001 or observed_max >= 180:
        raise ValueError("Support pre-entry confirmation differs")
    v2 = controlled_v2.validate_pre_entry_bound_basis(controlled_v2.load_contract())
    return {
        "source_contract": "2b-controlled-v2",
        "source_contract_sha256": sha256(V2_CONFIG),
        "source_pilot_id": v2["pilot_id"],
        "source_observed_max_seconds": v2["observed_max_seconds"],
        "source_rule": v2["rule"],
        "pre_entry_wall_seconds": v2["pre_entry_wall_seconds"],
        "support_confirmation": {
            "pilot_id": PILOT_ID,
            "entered_runs": len(observed),
            "observed_max_pre_entry_seconds": observed_max,
            "all_below_bound": all(value < 180 for value in observed),
        },
    }


def _provider_cost_review(cost: dict[str, Any]) -> dict[str, Any]:
    current = cost.get("current_pilot_attempts")
    if not isinstance(current, list) or len(current) != 9:
        raise ValueError("Support cost-ledger population differs")
    valid = [row for row in current if row.get("classification") == "valid"]
    invalid = [
        row for row in current if row.get("classification") == "infrastructure_invalid"
    ]
    if len(valid) != 8 or len(invalid) != 1:
        raise ValueError("Support cost-ledger classifications differ")
    valid_cost = sum(row["estimated_cost_nano_usd"] for row in valid)
    invalid_cost = sum(row["estimated_cost_nano_usd"] for row in invalid)
    max_cost = max(row["estimated_cost_nano_usd"] for row in current)
    if (
        valid_cost != 74_685_878_880
        or invalid_cost != 5_676_999_440
        or max_cost != 12_789_088_840
    ):
        raise ValueError("Support cost evidence differs")
    return {
        "status": "authorization_required_before_execution_overlay",
        "basis_pilot_id": PILOT_ID,
        "basis_closeout_bundle_sha256": sha256(CLOSEOUT / "bundle-manifest.json"),
        "rate_card": cost["governance"]["rate_card"],
        "observed_valid_attempts": len(valid),
        "observed_invalid_attempts": len(invalid),
        "observed_valid_cost_usd": _format_nano_usd(valid_cost),
        "observed_invalid_cost_usd": _format_nano_usd(invalid_cost),
        "observed_current_pilot_cost_usd": _format_nano_usd(
            valid_cost + invalid_cost
        ),
        "observed_max_attempt_cost_usd": _format_nano_usd(max_cost),
        "projected_40_valid_at_observed_mean_usd": _format_nano_usd(
            (valid_cost // len(valid)) * 40
        ),
        "illustrative_120_attempts_at_observed_max_usd": _format_nano_usd(
            max_cost * 120
        ),
        "main_study_authorization_usd": None,
        "minimum_uncommitted_reserve_per_new_run_usd": None,
        "active_run_cost_termination": False,
        "cost_must_remain_outside_outcome_analysis": True,
        "admission_must_be_effect_blind": True,
    }


def expected_contract() -> dict[str, Any]:
    """Reconstruct the exact pre-execution freeze from committed evidence."""

    v2 = controlled_v2.load_contract()
    schedule = support_pilot_2b.load_schedule(PILOT_ID)
    support = schedule["contract"]
    readiness = _json(PILOT_DIR / "readiness.json", "Support readiness")
    cost = _json(CLOSEOUT / "cost-ledger.json", "Support cost ledger")
    closeout = _closeout_dependency()
    return {
        "schema_version": 3,
        "study_protocol": "2b-controlled-v3",
        "contract_kind": "pre_execution_freeze",
        "status": "scientific_contract_frozen_resource_review_required",
        "supersedes_contract_sha256": sha256(V2_CONFIG),
        "supersession_reason": (
            "validated_600_second_horizon_requires_support_v3_execution_envelope"
        ),
        "environment_protocol": v2["environment_protocol"],
        "profile": v2["profile"],
        "provider": v2["provider"],
        "agent": deepcopy(v2["agent"]),
        "seed": v2["seed"],
        "branching_factor": v2["branching_factor"],
        "reinforcement_every": v2["reinforcement_every"],
        "frozen_input_sha256": _frozen_source_hashes(),
        "readiness_dependency": _readiness_dependency(readiness),
        "closeout_dependency": closeout,
        "pre_entry_bound_basis": _pre_entry_bound_basis(readiness),
        "design": deepcopy(v2["design"]),
        "runtime_policy": deepcopy(support["runtime_policy"]),
        "attempt_bounds": deepcopy(support["attempt_bounds"]),
        "trial_caps": deepcopy(support["trial_caps"]),
        "cap_policy": deepcopy(support["cap_policy"]),
        "termination_policy": deepcopy(support["termination_policy"]),
        "replacement_policy": deepcopy(support["replacement_policy"]),
        "annotation": deepcopy(v2["annotation"]),
        "analysis": deepcopy(v2["analysis"]),
        "provider_cost_review": _provider_cost_review(cost),
        "execution": {
            "available": False,
            "schedule_freeze_available": False,
            "prepare_makes_model_calls": False,
            "reason": (
                "main_study_resource_authorization_and_v3_execution_overlay_not_frozen"
            ),
            "future_scheduler": "experiment_controller.controlled_2b_v3",
            "future_runner": (
                "experiment_controller.run_2b_controlled_v3.run_controlled_v3"
            ),
            "runs_must_be_serial": True,
            "frozen_schedule_order_required": True,
            "task_unchanged": True,
        },
    }


def load_contract() -> dict[str, Any]:
    """Validate the byte commitment and every derived scientific setting."""

    _committed(CONFIG, COMMITMENT, "Controlled-v3 contract")
    contract = _json(CONFIG, "Controlled-v3 contract")
    expected = expected_contract()
    if contract != expected:
        raise ValueError("Controlled-v3 contract differs from committed evidence")
    return contract


def contract_status() -> dict[str, Any]:
    contract = load_contract()
    return {
        "study_protocol": contract["study_protocol"],
        "status": contract["status"],
        "contract_sha256": sha256(CONFIG),
        "supersedes_contract_sha256": contract["supersedes_contract_sha256"],
        "task_unchanged": True,
        "required_valid_runs": contract["design"]["required_valid_runs"],
        "readiness_dependency": contract["readiness_dependency"],
        "closeout_dependency": contract["closeout_dependency"],
        "provider_cost_review": contract["provider_cost_review"],
        "schedule_freeze_available": False,
        "execution_available": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("expected", "status"))
    args = parser.parse_args()
    value = expected_contract() if args.action == "expected" else contract_status()
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
