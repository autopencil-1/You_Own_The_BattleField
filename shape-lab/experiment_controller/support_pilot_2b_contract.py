"""Execution freeze for the approved 2B horizon-support-v3 pilot."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from agent_runner.runtime_policy_2b import SUPPORT_POLICY_V3
from experiment_controller import support_pilot_2b_candidate_contract as candidate
from experiment_controller.provider_cost_2b import estimate_archived_run_cost


LAB = candidate.LAB
CONFIG = LAB / "config" / "exp_2b_support_pilot_v3.json"
COMMITMENT = LAB / "config" / "exp_2b_support_pilot_v3.sha256"
PREVIOUS_EXECUTION_CONFIG = LAB / "config" / "exp_2b_support_pilot_v2.json"
PREVIOUS_EXECUTION_COMMITMENT = LAB / "config" / "exp_2b_support_pilot_v2.sha256"
PREVIOUS_PILOT_ID = "2b-support-pilot-v2-20261106050510-2cf465"
PREVIOUS_PILOT_DIR = LAB / "studies" / PREVIOUS_PILOT_ID
PREVIOUS_SCHEDULE = PREVIOUS_PILOT_DIR / "schedule.json"
PREVIOUS_SCHEDULE_COMMITMENT = PREVIOUS_PILOT_DIR / "schedule.sha256"
PREVIOUS_RUN_IDS = (
    "2b-supp-20261106050724-85cba5",
    "2b-supp-20261106051918-0fe4df",
)
INTEGRITY_INCIDENT = (
    PREVIOUS_PILOT_DIR
    / "diagnostics"
    / "2b-supp-20261106050724-85cba5-integrity-incident.json"
)
TASK = candidate.TASK
FIXTURE = candidate.FIXTURE
ARMS = candidate.ARMS
READINESS_CHECKS = candidate.READINESS_CHECKS
FUTURE_WRAPPER = candidate.FUTURE_WRAPPER

TRIAL_CAPS_V3 = {
    "max_filesystem_actions": 500,
    "max_agent_tool_calls": 500,
    "max_model_calls": 500,
    "max_model_tokens_input_plus_output": 100000000,
    "pre_entry_wall_seconds": 180,
    "post_entry_wall_seconds": 600,
    "maximum_total_wall_seconds": 780,
    "retention_horizons_seconds": [60, 180, 300, 600],
}
ATTEMPT_BOUNDS_V3 = {
    "claude_retry_count": 0,
    "gateway_429_retry_count": 0,
    "max_attempts_per_task": 500,
    "max_supervisor_attempts": 500,
    "structured_output_retry_count": None,
    "structured_output_retry_count_status": "provider_managed_not_exposed",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is missing or malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _pipeline_sources() -> dict[str, Path]:
    return {
        "base_candidate_contract": candidate.CONFIG,
        "base_candidate_loader": Path(candidate.__file__).resolve(),
        "execution_contract_loader": Path(__file__).resolve(),
        "scheduler": Path(__file__).with_name("support_pilot_2b.py"),
        "runner_wrapper": Path(__file__).with_name("run_2b_support.py"),
        "runner": Path(__file__).with_name("run_2b.py"),
        "runtime_policy": LAB / "agent_runner" / "runtime_policy_2b.py",
        "agent_entrypoint": LAB / "agent_runner" / "entrypoint_2b.py",
        "provider_cost_accounting": Path(__file__).with_name("provider_cost_2b.py"),
        "cap_taxonomy": LAB / "telemetry" / "cap_taxonomy_2b.py",
        "scorer": LAB / "telemetry" / "score_2b.py",
        "replay": LAB / "telemetry" / "replay_2b.py",
        "review_projection": LAB / "telemetry" / "annotate_2b.py",
        "adjudication": LAB / "telemetry" / "adjudicate_2b.py",
    }


def _predecessor_evidence() -> dict[str, str]:
    paths = {
        "superseded_execution_contract": PREVIOUS_EXECUTION_CONFIG,
        "superseded_execution_commitment": PREVIOUS_EXECUTION_COMMITMENT,
        "superseded_schedule": PREVIOUS_SCHEDULE,
        "superseded_schedule_commitment": PREVIOUS_SCHEDULE_COMMITMENT,
        "first_run_manifest": LAB / "runs" / PREVIOUS_RUN_IDS[0] / "manifest.json",
        "first_run_result": LAB / "runs" / PREVIOUS_RUN_IDS[0] / "result.json",
        "first_run_gateway": LAB
        / "runs"
        / PREVIOUS_RUN_IDS[0]
        / "gateway-events.jsonl",
        "second_run_manifest": LAB / "runs" / PREVIOUS_RUN_IDS[1] / "manifest.json",
        "second_run_result": LAB / "runs" / PREVIOUS_RUN_IDS[1] / "result.json",
        "second_run_gateway": LAB
        / "runs"
        / PREVIOUS_RUN_IDS[1]
        / "gateway-events.jsonl",
        "first_run_integrity_incident": INTEGRITY_INCIDENT,
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ValueError(
            "Support-v3 predecessor evidence is incomplete: "
            + ", ".join(sorted(missing))
        )
    return {name: sha256(path) for name, path in paths.items()}


def _cost_carry_forward(governance: dict[str, Any]) -> dict[str, Any]:
    evidence = []
    for run_id in PREVIOUS_RUN_IDS:
        run_dir = LAB / "runs" / run_id
        estimate = estimate_archived_run_cost(run_dir, governance)
        evidence.append(
            {
                "run_id": run_id,
                "manifest_sha256": sha256(run_dir / "manifest.json"),
                "gateway_events_sha256": sha256(run_dir / "gateway-events.jsonl"),
                "estimated_cost_nano_usd": estimate["estimated_cost_nano_usd"],
                "estimated_cost_usd": estimate["estimated_cost_usd"],
            }
        )
    total = sum(row["estimated_cost_nano_usd"] for row in evidence)
    whole, fractional = divmod(total, 1_000_000_000)
    return {
        "schema_version": 1,
        "accounting_rule": "committed_baseline_plus_current_pilot_archives",
        "source_pilot_id": PREVIOUS_PILOT_ID,
        "source_schedule_sha256": sha256(PREVIOUS_SCHEDULE),
        "rate_card_revision": governance["rate_card"]["revision"],
        "ordered_run_ids": list(PREVIOUS_RUN_IDS),
        "completed_attempts_priced": len(evidence),
        "accrued_cost_nano_usd": total,
        "accrued_cost_usd": f"{whole}.{fractional:09d}",
        "evidence": evidence,
    }


def _validate_commitment() -> str:
    try:
        expected = COMMITMENT.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("Support-v3 execution commitment is missing") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256(CONFIG) != expected:
        raise ValueError("Support-v3 contract differs from its frozen commitment")
    return expected


def load_freeze() -> dict[str, Any]:
    """Validate the v3 envelope, predecessor evidence, cost, and pipeline."""

    _validate_commitment()
    freeze = _json(CONFIG, "Support-v3 execution contract")
    if set(freeze) != {
        "schema_version",
        "pilot_protocol",
        "contract_kind",
        "status",
        "base_candidate_sha256",
        "supersedes_execution_contract_sha256",
        "supersession_reason",
        "predecessor_evidence_sha256",
        "runtime_policy",
        "attempt_bounds",
        "trial_caps",
        "resource_review",
        "provider_cost_carry_forward",
        "frozen_source_sha256",
        "execution",
    }:
        raise ValueError("Support-v3 contract has an unexpected shape")
    reviewed = candidate.load_contract()
    expected_carry = _cost_carry_forward(reviewed["provider_cost_governance"])
    if (
        freeze.get("schema_version") != 3
        or freeze.get("pilot_protocol") != "2b-support-pilot-v3"
        or freeze.get("contract_kind") != "execution_freeze"
        or freeze.get("status") != "execution_enabled_not_readiness_passed"
        or freeze.get("base_candidate_sha256") != sha256(candidate.CONFIG)
        or freeze.get("supersedes_execution_contract_sha256")
        != sha256(PREVIOUS_EXECUTION_CONFIG)
        or freeze.get("supersession_reason")
        != "v2_external_stop_inventory_bug_and_pre_600_attempt_exhaustion"
        or freeze.get("predecessor_evidence_sha256") != _predecessor_evidence()
        or freeze.get("runtime_policy") != SUPPORT_POLICY_V3
        or freeze.get("attempt_bounds") != ATTEMPT_BOUNDS_V3
        or freeze.get("trial_caps") != TRIAL_CAPS_V3
        or freeze.get("provider_cost_carry_forward") != expected_carry
    ):
        raise ValueError("Support-v3 identity, envelope, or cost basis differs")
    if freeze.get("resource_review") != {
        "approved": True,
        "basis": "v2_two_attempt_observed_cost_and_600_second_completion",
        "v2_observed_attempts": 2,
        "v2_observed_cost_usd": "10.684347160",
        "v2_both_reached_post_entry_seconds": 600,
        "pilot_authorization_usd": "100.00",
        "opening_remaining_authorization_usd": "89.315652840",
        "minimum_uncommitted_reserve_per_new_run_usd": "15.00",
        "active_run_cost_termination": False,
    }:
        raise ValueError("Support-v3 resource review differs")
    sources = _pipeline_sources()
    missing = [name for name, path in sources.items() if not path.is_file()]
    if missing:
        raise ValueError(
            "Support-v3 pipeline is incomplete: " + ", ".join(sorted(missing))
        )
    if freeze.get("frozen_source_sha256") != {
        name: sha256(path) for name, path in sources.items()
    }:
        raise ValueError("Support-v3 pipeline differs from its freeze")
    if freeze.get("execution") != {
        "available": True,
        "schedule_freeze_available": True,
        "prepare_makes_model_calls": False,
        "runs_are_serial": True,
        "frozen_schedule_order_required": True,
        "provider_cost_admission_required_before_every_attempt": True,
        "active_run_cost_termination": False,
        "superseded_v1_attempt_is_excluded": True,
        "superseded_v2_attempts_are_excluded": True,
    }:
        raise ValueError("Support-v3 execution boundary differs")
    return freeze


def load_contract() -> dict[str, Any]:
    """Return the immutable base design with the approved v3 envelope."""

    reviewed = candidate.load_contract()
    freeze = load_freeze()
    contract = deepcopy(reviewed)
    contract["schema_version"] = 3
    contract["pilot_protocol"] = "2b-support-pilot-v3"
    contract["predecessor_protocol"] = "2b-support-pilot-v2"
    contract["candidate_status"] = freeze["status"]
    contract["runtime_policy"] = deepcopy(SUPPORT_POLICY_V3)
    contract["attempt_bounds"] = deepcopy(ATTEMPT_BOUNDS_V3)
    contract["trial_caps"] = deepcopy(TRIAL_CAPS_V3)
    contract["provider_cost_carry_forward"] = deepcopy(
        freeze["provider_cost_carry_forward"]
    )
    contract["execution"] = {
        "future_wrapper": FUTURE_WRAPPER,
        "available": True,
        "schedule_freeze_available": True,
        "prepare_makes_model_calls": False,
        "resource_review_complete": True,
        "provider_cost_admission_required_before_every_attempt": True,
        "active_run_cost_termination": False,
        "execution_order": "serial_frozen_schedule_order",
        "superseded_v1_attempt_is_excluded": True,
        "superseded_v2_attempts_are_excluded": True,
    }
    contract["execution_freeze"] = {
        "schema_version": freeze["schema_version"],
        "base_candidate_sha256": freeze["base_candidate_sha256"],
        "supersedes_execution_contract_sha256": freeze[
            "supersedes_execution_contract_sha256"
        ],
        "supersession_reason": freeze["supersession_reason"],
        "predecessor_evidence_sha256": freeze["predecessor_evidence_sha256"],
        "execution_contract_sha256": sha256(CONFIG),
        "frozen_source_sha256": freeze["frozen_source_sha256"],
        "resource_review": freeze["resource_review"],
        "provider_cost_carry_forward": freeze["provider_cost_carry_forward"],
    }
    return contract


def contract_status() -> dict[str, Any]:
    contract = load_contract()
    return {
        "pilot_protocol": contract["pilot_protocol"],
        "status": contract["candidate_status"],
        "contract_sha256": sha256(CONFIG),
        "base_candidate_sha256": contract["execution_freeze"]["base_candidate_sha256"],
        "supersedes_execution_contract_sha256": contract["execution_freeze"][
            "supersedes_execution_contract_sha256"
        ],
        "agent_task_sha256": sha256(TASK),
        "task_unchanged": True,
        "resource_review_complete": True,
        "schedule_freeze_available": True,
        "execution_available": True,
        "readiness_passed": False,
        "required_valid_runs": contract["design"]["required_valid_runs"],
        "runtime_policy": contract["runtime_policy"],
        "attempt_bounds": contract["attempt_bounds"],
        "trial_caps": contract["trial_caps"],
        "provider_cost_governance": contract["provider_cost_governance"],
        "provider_cost_carry_forward": contract["provider_cost_carry_forward"],
    }


__all__ = [
    "ARMS",
    "ATTEMPT_BOUNDS_V3",
    "COMMITMENT",
    "CONFIG",
    "FIXTURE",
    "FUTURE_WRAPPER",
    "LAB",
    "READINESS_CHECKS",
    "TASK",
    "TRIAL_CAPS_V3",
    "contract_status",
    "load_contract",
    "load_freeze",
    "sha256",
]
