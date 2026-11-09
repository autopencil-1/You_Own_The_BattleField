"""Effect-blind estimates of Z.ai Coding Plan credits from gateway usage.

These are estimates from the published GLM-5.3 multipliers, not a claim about
the subscriber's live balance or the provider's final charge. No function in
this module can start or stop an agent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable


INPUT_MULTIPLIER = Decimal("6.9")
CACHED_INPUT_MULTIPLIER = Decimal("1.7")
OUTPUT_MULTIPLIER = Decimal("24")
OFF_PEAK_MULTIPLIER = Decimal("0.5")
CREDIT_DIVISOR = Decimal("10000")
USAGE_FIELDS = (
    "input_tokens", "cache_creation_input_tokens",
    "cache_read_input_tokens", "output_tokens",
)


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Model-call timestamp is missing")
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Model-call timestamp is invalid") from exc
    if observed.tzinfo is None:
        raise ValueError("Model-call timestamp needs a timezone")
    return observed.astimezone(timezone.utc)


def is_peak(observed: datetime) -> bool:
    """Published Mon–Fri 14:00–18:00 Singapore time, expressed in UTC."""
    utc = observed.astimezone(timezone.utc)
    return utc.weekday() < 5 and 6 <= utc.hour < 10


def estimate_gateway_events_credits(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    totals = {field: 0 for field in USAGE_FIELDS}
    calls = 0
    peak_calls = 0
    off_peak_calls = 0
    peak_credits = Decimal(0)
    off_peak_credits = Decimal(0)
    for event in events:
        if event.get("event_type") != "model_call":
            continue
        if event.get("provider") != "zai" or event.get("model") != "glm-5.3":
            raise ValueError("Z.ai credit evidence has another provider or model")
        status = event.get("status")
        if type(status) is not int:
            raise ValueError("Model-call HTTP status is invalid")
        if status != 200:
            continue
        if event.get("path") != "/v1/messages":
            raise ValueError("Successful model call has an unexpected route")
        if event.get("served_model") != "glm-5.3":
            raise ValueError("Z.ai served model differs from the frozen model")
        usage = event.get("usage")
        if not isinstance(usage, dict):
            raise ValueError("Successful Z.ai response lacks reported usage")
        values = {
            field: _nonnegative_int(usage.get(field, 0), field)
            for field in USAGE_FIELDS
        }
        observed = _timestamp(event.get("timestamp_utc"))
        raw = (
            (values["input_tokens"] + values["cache_creation_input_tokens"])
            * INPUT_MULTIPLIER
            + values["cache_read_input_tokens"] * CACHED_INPUT_MULTIPLIER
            + values["output_tokens"] * OUTPUT_MULTIPLIER
        ) / CREDIT_DIVISOR
        for field, value in values.items():
            totals[field] += value
        calls += 1
        if is_peak(observed):
            peak_calls += 1
            peak_credits += raw
        else:
            off_peak_calls += 1
            off_peak_credits += raw * OFF_PEAK_MULTIPLIER
    return {
        "accounting_kind": "published_multiplier_estimate_not_live_balance",
        "rate_revision": "zai-glm-5.3-coding-plan-2026-11-09",
        "source_url": "https://docs.z.ai/devpack/overview",
        "model_calls": calls,
        "peak_model_calls": peak_calls,
        "off_peak_model_calls": off_peak_calls,
        **totals,
        "total_tokens": sum(totals.values()),
        "estimated_peak_credits": format(peak_credits, ".9f"),
        "estimated_off_peak_credits": format(off_peak_credits, ".9f"),
        "estimated_total_credits": format(peak_credits + off_peak_credits, ".9f"),
        "live_plan_balance_known": False,
    }


__all__ = ["estimate_gateway_events_credits", "is_peak"]
