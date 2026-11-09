"""Effect-blind provider-cost accounting for the 2B support pilot.

Cost is an admission concern between runs, not an in-run termination signal.
The functions in this module deliberately have no process-control capability.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
from typing import Any, Iterable


NANO_USD_PER_USD = 1_000_000_000
TOKENS_PER_MILLION = 1_000_000
USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)


def _nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _usd_to_nano(value: Any, label: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a decimal string")
    try:
        nano = Decimal(value) * NANO_USD_PER_USD
    except InvalidOperation as exc:
        raise ValueError(f"{label} is not a decimal amount") from exc
    if nano < 0 or nano != nano.to_integral_value():
        raise ValueError(f"{label} must be a non-negative exact nano-USD amount")
    return int(nano)


def _rate_to_nano_per_token(value: Any, label: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a decimal string")
    try:
        rate = Decimal(value)
        nano_per_token = rate * NANO_USD_PER_USD / TOKENS_PER_MILLION
    except InvalidOperation as exc:
        raise ValueError(f"{label} is not a decimal rate") from exc
    if rate < 0 or nano_per_token != nano_per_token.to_integral_value():
        raise ValueError(f"{label} must resolve to an exact nano-USD/token rate")
    return int(nano_per_token)


def _format_nano_usd(value: int) -> str:
    whole, fractional = divmod(value, NANO_USD_PER_USD)
    return f"{whole}.{fractional:09d}"


def gateway_usage(events: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Aggregate successful, provider-reported usage without arm information."""

    usage = {field: 0 for field in USAGE_FIELDS}
    model_calls = 0
    for event in events:
        if event.get("event_type") != "model_call" or event.get("status") != 200:
            continue
        model_calls += 1
        reported = event.get("usage")
        if not isinstance(reported, dict):
            raise ValueError("Successful model call lacks provider usage")
        for field in USAGE_FIELDS:
            usage[field] += _nonnegative_int(
                reported.get(field, 0), f"provider usage {field}"
            )
    return {
        "model_calls": model_calls,
        **usage,
        "total_tokens": sum(usage.values()),
    }


def estimate_usage_cost(
    usage: dict[str, Any], governance: dict[str, Any]
) -> dict[str, Any]:
    """Apply the contract's frozen rate card to one aggregate usage record."""

    rate_card = governance.get("rate_card")
    if not isinstance(rate_card, dict):
        raise ValueError("Provider-cost governance lacks a rate card")
    normalized = {
        field: _nonnegative_int(usage.get(field, 0), field)
        for field in USAGE_FIELDS
    }
    input_rate_tokens = (
        normalized["input_tokens"] + normalized["cache_creation_input_tokens"]
    )
    cached_rate_tokens = normalized["cache_read_input_tokens"]
    output_rate_tokens = normalized["output_tokens"]
    input_nano = _rate_to_nano_per_token(
        rate_card.get("input_usd_per_million_tokens"), "input rate"
    )
    cached_nano = _rate_to_nano_per_token(
        rate_card.get("cached_input_usd_per_million_tokens"),
        "cached-input rate",
    )
    output_nano = _rate_to_nano_per_token(
        rate_card.get("output_usd_per_million_tokens"), "output rate"
    )
    cost_nano = (
        input_rate_tokens * input_nano
        + cached_rate_tokens * cached_nano
        + output_rate_tokens * output_nano
    )
    return {
        "rate_card_revision": rate_card.get("revision"),
        "model_calls": _nonnegative_int(usage.get("model_calls", 0), "model_calls"),
        **normalized,
        "total_tokens": sum(normalized.values()),
        "input_rate_tokens": input_rate_tokens,
        "cached_input_rate_tokens": cached_rate_tokens,
        "output_rate_tokens": output_rate_tokens,
        "estimated_cost_nano_usd": cost_nano,
        "estimated_cost_usd": _format_nano_usd(cost_nano),
    }


def estimate_gateway_events_cost(
    events: Iterable[dict[str, Any]], governance: dict[str, Any]
) -> dict[str, Any]:
    return estimate_usage_cost(gateway_usage(events), governance)


def estimate_archived_run_cost(
    run_dir: Path, governance: dict[str, Any]
) -> dict[str, Any]:
    """Read a completed archive and return aggregate, effect-blind cost evidence."""

    manifest_path = run_dir / "manifest.json"
    gateway_path = run_dir / "gateway-events.jsonl"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        rows = [
            json.loads(line)
            for line in gateway_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Completed run lacks readable provider-cost evidence") from exc
    if not isinstance(manifest, dict) or manifest.get("mode") != "support_pilot":
        raise ValueError("Provider-cost accounting requires a support-pilot archive")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("Gateway cost evidence must contain JSON objects")
    estimate = estimate_gateway_events_cost(rows, governance)
    return {
        "run_id": manifest.get("run_id"),
        "evidence_file": "gateway-events.jsonl",
        **estimate,
    }


def admission_decision(
    accrued_cost_nano_usd: int, governance: dict[str, Any]
) -> dict[str, Any]:
    """Decide whether another run may start; never controls an active run."""

    accrued = _nonnegative_int(accrued_cost_nano_usd, "accrued_cost_nano_usd")
    authorization = _usd_to_nano(
        governance.get("pilot_authorization_usd"), "pilot authorization"
    )
    reserve = _usd_to_nano(
        governance.get("minimum_uncommitted_reserve_per_new_run_usd"),
        "minimum uncommitted reserve",
    )
    remaining = max(0, authorization - accrued)
    admitted = remaining >= reserve
    return {
        "state": "admitted" if admitted else "paused_insufficient_reserve",
        "may_start_new_run": admitted,
        "accrued_cost_nano_usd": accrued,
        "accrued_cost_usd": _format_nano_usd(accrued),
        "authorization_nano_usd": authorization,
        "authorization_usd": _format_nano_usd(authorization),
        "remaining_authorization_nano_usd": remaining,
        "remaining_authorization_usd": _format_nano_usd(remaining),
        "required_reserve_nano_usd": reserve,
        "required_reserve_usd": _format_nano_usd(reserve),
        "active_run_termination_allowed": False,
        "creates_trial_attempt": False,
        "creates_censored_outcome": False,
    }


__all__ = [
    "admission_decision",
    "estimate_archived_run_cost",
    "estimate_gateway_events_cost",
    "estimate_usage_cost",
    "gateway_usage",
]
