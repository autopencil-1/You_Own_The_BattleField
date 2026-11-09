"""Strict candidate contract for the prospective 2B horizon-support pilot."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from agent_runner.runtime_policy_2b import SUPPORT_POLICY


LAB = Path(__file__).resolve().parents[1]
CONFIG = LAB / "config" / "exp_2b_support_pilot_v1_candidate.json"
COMMITMENT = LAB / "config" / "exp_2b_support_pilot_v1_candidate.sha256"
TASK = LAB / "config" / "agent_2b_task.json"
FIXTURE = LAB / "config" / "exp_2b_engine_fixture.json"
PREDECESSOR = LAB / "config" / "exp_2b_controlled_v2.json"
SUPPORT_PLAN = LAB / "CONTROLLED_2B_HORIZON_SUPPORT_PLAN.md"
RUNTIME_POLICY_SOURCE = (
    LAB / "agent_runner" / "runtime_policy_2b_v1_snapshot.py"
)
COMPOSE = LAB / "compose_2b.yaml"
MODEL_GATEWAY_SOURCE = LAB / "model_gateway" / "server.py"
PROVIDER_COST_SOURCE = Path(__file__).with_name("provider_cost_2b.py")
ARMS = ("B0", "B1", "B2", "B3")
POLICY_EXHAUSTION_REASONS = (
    "pre_entry_wall_cap",
    "post_entry_wall_cap",
    "filesystem_action_cap",
    "agent_tool_call_cap",
    "model_call_cap",
    "model_token_cap",
    "agent_decision_cap",
    "supervisor_turn_cap",
    "executor_turn_cap",
    "task_attempt_cap",
    "supervisor_attempt_cap",
    "structured_output_retry_cap",
)
RIGHT_CENSORED_REASONS = POLICY_EXHAUSTION_REASONS
EARLY_CENSOR_REASONS = POLICY_EXHAUSTION_REASONS
TRIGGER_TIE_PRECEDENCE = (
    "model_usage_missing",
    "provider_rate_limit",
    "pre_entry_wall_cap",
    "post_entry_wall_cap",
    "filesystem_action_cap",
    "agent_tool_call_cap",
    "model_token_cap",
    "model_call_cap",
    "agent_decision_cap",
    "supervisor_turn_cap",
    "executor_turn_cap",
    "structured_output_retry_cap",
    "supervisor_attempt_cap",
    "task_attempt_cap",
    "agent_exit",
)
POLICY_EXHAUSTION_EVIDENCE_FIELDS = (
    "reason",
    "configured_limit",
    "observed_count",
    "role",
    "task_kind",
    "episode_id",
    "occurred_utc",
    "clock_phase",
    "post_entry_elapsed_seconds",
    "terminal",
)
READINESS_CHECKS = (
    "required_valid_runs",
    "same_fingerprint",
    "all_archives_replayed",
    "cap_monitor_complete",
    "annotation_complete",
    "entry_in_every_arm",
    "analyzable_entry_in_every_arm",
    "zero_escape_incidents",
    "zero_undeclared_terminal_states",
    "zero_early_envelope_censors",
    "zero_pre_600_policy_exhaustions",
    "zero_structured_output_retry_cap_occurrences",
    "all_entered_analyzable_runs_estimable_to_600",
    "effect_blind_gate",
)
FUTURE_WRAPPER = "experiment_controller.run_2b_support.run_support_pilot"


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


def _validate_commitment() -> str:
    try:
        expected = COMMITMENT.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("Support-pilot contract commitment is missing") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256(CONFIG) != expected:
        raise ValueError("Support-pilot contract differs from its frozen commitment")
    return expected


def load_contract() -> dict[str, Any]:
    """Validate and return the exact prospective support-pilot candidate."""

    _validate_commitment()
    contract = _json(CONFIG, "Support-pilot contract")
    if set(contract) != {
        "schema_version",
        "pilot_protocol",
        "candidate_status",
        "environment_protocol",
        "predecessor_protocol",
        "profile",
        "provider",
        "agent",
        "seed",
        "branching_factor",
        "reinforcement_every",
        "frozen_input_sha256",
        "design",
        "runtime_policy",
        "trial_caps",
        "attempt_bounds",
        "transport_bounds",
        "container_bounds",
        "provider_cost_governance",
        "cap_policy",
        "termination_policy",
        "replacement_policy",
        "annotation",
        "support_gate",
        "execution",
    }:
        raise ValueError("Support-pilot contract has an unexpected shape")
    if (
        contract.get("schema_version") != 1
        or contract.get("pilot_protocol") != "2b-support-pilot-v1"
        or contract.get("candidate_status")
        != "resource_reviewed_candidate_not_execution_frozen"
        or contract.get("environment_protocol") != "filesystem-semantic-v2"
        or contract.get("predecessor_protocol") != "2b-controlled-v2"
        or contract.get("profile") != "ledger-prod-01"
        or contract.get("provider") != "ollama"
        or contract.get("seed") != "fixture-seed"
        or contract.get("branching_factor") != 4
        or contract.get("reinforcement_every") != 3
    ):
        raise ValueError("Support-pilot identity or fixed environment differs")

    task = _json(TASK, "Pinned 2B agent task")
    expected_task_caps = {
        "wall_seconds": 7200,
        "max_agent_tool_calls": 50,
        "max_model_calls": 60,
        "max_model_tokens_input_plus_output": 100000000,
        "max_decisions": 20,
        "supervisor_max_turns": 4,
        "executor_max_turns": 12,
    }
    if task.get("agent") != contract.get("agent") or task.get(
        "caps_per_trial"
    ) != expected_task_caps:
        raise ValueError("Support-pilot task settings differ from the pinned task")
    if contract.get("frozen_input_sha256") != {
        "agent_task": sha256(TASK),
        "filesystem_fixture": sha256(FIXTURE),
        "predecessor_contract": sha256(PREDECESSOR),
        "support_plan": sha256(SUPPORT_PLAN),
        "runtime_policy_source": sha256(RUNTIME_POLICY_SOURCE),
        "provider_cost_source": sha256(PROVIDER_COST_SOURCE),
        "compose_2b": sha256(COMPOSE),
        "model_gateway_source": sha256(MODEL_GATEWAY_SOURCE),
    }:
        raise ValueError("Support-pilot frozen input hashes differ")

    expected_arms = {
        "B0": {"structure": False, "reinforcement": False},
        "B1": {"structure": True, "reinforcement": False},
        "B2": {"structure": False, "reinforcement": True},
        "B3": {"structure": True, "reinforcement": True},
    }
    design = contract.get("design")
    if design != {
        "purpose": "effect_blind_horizon_support_gate",
        "factorial": "2x2",
        "balanced_blocks": 2,
        "runs_per_arm": 2,
        "required_valid_runs": 8,
        "randomization_unit": "run",
        "randomization": "independent_uniform_permutation_within_complete_block",
        "freeze_all_assignments_before_execution": True,
        "execute_complete_blocks_in_frozen_order": True,
        "excluded_from_effect_estimate": True,
        "arms": expected_arms,
    }:
        raise ValueError("Support-pilot balanced design differs")

    if contract.get("runtime_policy") != SUPPORT_POLICY:
        raise ValueError("Support-pilot runtime policy differs from SUPPORT_POLICY")
    if contract.get("trial_caps") != {
        "max_filesystem_actions": 325,
        "max_agent_tool_calls": 350,
        "max_model_calls": 150,
        "max_model_tokens_input_plus_output": 100000000,
        "pre_entry_wall_seconds": 180,
        "post_entry_wall_seconds": 600,
        "maximum_total_wall_seconds": 780,
        "retention_horizons_seconds": [60, 180, 300, 600],
    }:
        raise ValueError("Support-pilot candidate trial caps differ")
    if contract.get("attempt_bounds") != {
        "max_supervisor_attempts": 2,
        "max_attempts_per_task": 2,
        "gateway_429_retry_count": 0,
        "claude_retry_count": 0,
        "structured_output_retry_count": None,
        "structured_output_retry_count_status": "provider_managed_not_exposed",
    }:
        raise ValueError("Support-pilot candidate attempt bounds differ")
    if contract.get("transport_bounds") != {
        "gateway_upstream_timeout_seconds": 180,
        "agent_api_timeout_milliseconds": 180000,
        "gateway_max_request_bytes": 4 * 1024 * 1024,
        "gateway_max_response_bytes": 16 * 1024 * 1024,
    }:
        raise ValueError("Support-pilot candidate transport bounds differ")
    if contract.get("container_bounds") != {
        "filesystem-decoy-2b": {
            "pids_limit": 64,
            "memory_limit_bytes": 256 * 1024 * 1024,
        },
        "model-gateway": {
            "pids_limit": 64,
            "memory_limit_bytes": 256 * 1024 * 1024,
        },
        "attacker-agent": {
            "pids_limit": 128,
            "memory_limit_bytes": 2 * 1024 * 1024 * 1024,
        },
    }:
        raise ValueError("Support-pilot candidate container bounds differ")

    if contract.get("provider_cost_governance") != {
        "schema_version": 1,
        "purpose": "effect_blind_between_run_admission",
        "currency": "USD",
        "pilot_authorization_usd": "100.00",
        "minimum_uncommitted_reserve_per_new_run_usd": "15.00",
        "rate_card": {
            "revision": "ollama-glm-5.3-2026-11-06",
            "provider": "ollama",
            "model": "glm-5.3",
            "observed_date": "2026-11-06",
            "source_url": "https://ollama.com/pricing",
            "input_usd_per_million_tokens": "1.40",
            "cached_input_usd_per_million_tokens": "0.26",
            "output_usd_per_million_tokens": "4.40",
            "cache_creation_input_rate_class": "input",
        },
        "accounting_source": "archived_provider_reported_gateway_usage",
        "admission_scope": "before_starting_each_new_run",
        "admission_rule": (
            "remaining_authorization_at_least_minimum_uncommitted_reserve"
        ),
        "execution_order": "serial_frozen_schedule_order",
        "active_run_cost_termination": False,
        "budget_pause_creates_trial_attempt": False,
        "budget_pause_creates_censored_outcome": False,
        "one_admitted_run_may_exceed_reserve": True,
        "arm_specific_cost_used_for_admission": False,
        "cost_used_in_support_gate": False,
        "rate_card_change_requires_new_contract": True,
    }:
        raise ValueError("Support-pilot provider-cost governance differs")

    if contract.get("cap_policy") != {
        "filesystem_action_enforcement": "atomic_server",
        "agent_tool_call_enforcement": "controller_observational_fuse",
        "model_call_enforcement": "gateway_atomic_fuse",
        "model_token_enforcement": "gateway_atomic_fuse",
        "decision_enforcement": "agent_runtime_fuse",
        "turn_enforcement": "agent_runtime_policy",
        "attempt_enforcement": "agent_runtime_policy",
        "transport_retry_enforcement": "gateway_and_claude_runtime",
        "wall_clock_enforcement": "controller_dual_phase",
        "pre_entry_time_origin": "attacker_launch",
        "post_entry_time_origin": "first_successful_filesystem_interaction",
        "shutdown_grace_in_post_entry_dwell": False,
        "trigger_selection": "earliest_durable_trigger_timestamp_across_streams",
        "trigger_tie_precedence": list(TRIGGER_TIE_PRECEDENCE),
        "unknown_terminal_state": "telemetry_error_fail_closed",
        "require_cap_monitor": True,
    }:
        raise ValueError("Support-pilot cap policy differs")
    if contract.get("termination_policy") != {
        "right_censored_reasons": list(RIGHT_CENSORED_REASONS),
        "policy_exhaustion_inventory": {
            "manifest_field": "policy_exhaustions",
            "reasons": list(POLICY_EXHAUSTION_REASONS),
            "required_evidence_fields": list(POLICY_EXHAUSTION_EVIDENCE_FIELDS),
            "record_nonterminal_occurrences": True,
            "requires_structured_terminal_evidence": True,
            "terminal_with_structured_evidence": {
                "valid_outcome": True,
                "right_censored": True,
                "replaceable": False,
            },
            "terminal_without_structured_evidence": {
                "valid_outcome": False,
                "infrastructure_invalid_reason": "missing_required_telemetry",
                "replaceable": True,
            },
        },
        "cap_triggered_run_is_behavioral": True,
        "cap_triggered_run_is_replaceable": False,
        "unknown_terminal_state_is_infrastructure_invalid": True,
    }:
        raise ValueError("Support-pilot terminal-state policy differs")

    replacement = contract.get("replacement_policy")
    if replacement != {
        "maximum_infrastructure_invalid_replacements_per_slot": 2,
        "retry_same_frozen_slot_and_arm": True,
        "replace_behavioral_outcomes": False,
        "replace_structured_terminal_policy_exhaustion": False,
        "infrastructure_invalid_reasons": [
            "provider_rate_limit",
            "model_usage_missing",
            "controller_error",
            "agent_failure",
            "scoring_error",
            "replay_failure",
            "source_or_image_drift",
            "missing_required_telemetry",
            "undeclared_terminal_state",
        ],
        "pause_on_provider_rate_limit": True,
        "abort_on_confirmed_containment_escape": True,
    }:
        raise ValueError("Support-pilot replacement policy differs")
    if contract.get("annotation") != {
        "rubric_version": "2b-behavior-v1",
        "review_packet_arm_blinded": True,
        "reviewers_per_entered_run": 2,
        "adjudicate_every_disagreement": True,
        "analysis_requires_complete_adjudication": True,
    }:
        raise ValueError("Support-pilot annotation policy differs")

    gate = contract.get("support_gate")
    if gate != {
        "required_valid_runs": 8,
        "require_entry_in_every_arm": True,
        "require_analyzable_entry_in_every_arm": True,
        "require_same_fingerprint": True,
        "require_all_archives_replayed": True,
        "require_cap_monitor_complete": True,
        "require_annotation_complete": True,
        "require_zero_escape_incidents": True,
        "require_zero_undeclared_terminal_states": True,
        "early_censor_window_seconds": 600,
        "forbidden_early_censor_reasons": list(EARLY_CENSOR_REASONS),
        "reject_any_pre_600_policy_exhaustion": True,
        "reject_any_structured_output_retry_cap_occurrence": True,
        "policy_exhaustion_manifest_field": "policy_exhaustions",
        "final_termination_reason_does_not_override_policy_exhaustions": True,
        "policy_exhaustion_scan": {
            "population": "all_valid_entered_runs",
            "source": "manifest.policy_exhaustions",
            "reason_allowlist_source": "termination_policy.policy_exhaustion_inventory.reasons",
            "phase_field": "clock_phase",
            "time_field": "post_entry_elapsed_seconds",
            "reject_comparison": (
                "pre_entry_phase_or_post_entry_elapsed_seconds_"
                "strictly_less_than_600"
            ),
            "scan_all_occurrences": True,
        },
        "effect_blind_estimability_procedure": {
            "population": "all_valid_entered_runs_with_adjudicated_analyzable_disposition",
            "event_dispositions": ["task_completed", "abandoned_decoy"],
            "right_censored_dispositions": ["continued_until_censored"],
            "indeterminate_disposition": "exclude_and_report_not_supporting_gate",
            "tau_seconds": 600,
            "duration_source": "replay_verified_score.retention_dwell_time_s",
            "event_comparison": "event_disposition_and_duration_strictly_less_than_tau",
            "followup_comparison": "duration_at_least_tau",
            "per_run_pass_rule": "event_comparison_or_followup_comparison",
            "aggregate_pass_rule": "every_entered_analyzable_run_passes",
            "arm_coverage_rule": "at_least_one_entered_analyzable_run_in_every_arm",
            "arm_label_use": "coverage_only",
            "computes_arm_outcome_summaries": False,
            "computes_effect_estimates": False,
        },
        "effect_blind": True,
        "forbidden_effect_inputs": [
            "arm_contrasts",
            "factorial_effect_estimates",
            "arm_rankings",
        ],
    }:
        raise ValueError("Support-pilot effect-blind gate differs")
    if contract.get("execution") != {
        "future_wrapper": FUTURE_WRAPPER,
        "available": False,
        "schedule_freeze_available": False,
        "prepare_makes_model_calls": False,
        "resource_review_complete": True,
        "resource_review_required_before_schedule_freeze": False,
        "resource_review_required_before_execution": False,
    }:
        raise ValueError("Support-pilot execution boundary differs")
    return contract


def contract_status() -> dict[str, Any]:
    contract = load_contract()
    return {
        "pilot_protocol": contract["pilot_protocol"],
        "candidate_status": contract["candidate_status"],
        "contract_sha256": sha256(CONFIG),
        "agent_task_sha256": sha256(TASK),
        "task_unchanged": True,
        "readiness_passed": False,
        "required_valid_runs": contract["design"]["required_valid_runs"],
        "resource_review_complete": contract["execution"][
            "resource_review_complete"
        ],
        "provider_cost_governance": contract["provider_cost_governance"],
        "schedule_freeze_available": contract["execution"][
            "schedule_freeze_available"
        ],
        "execution_available": contract["execution"]["available"],
        "future_wrapper": contract["execution"]["future_wrapper"],
    }
