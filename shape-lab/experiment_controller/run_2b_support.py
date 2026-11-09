"""Execution wrapper for one frozen 2B horizon-support assignment."""

from __future__ import annotations

from typing import Any

from .run_2b import _run_agent
from .support_pilot_2b_contract import load_contract


def run_support_pilot(
    arm: str,
    *,
    assignment: dict[str, Any],
    frozen_fingerprint: dict[str, Any],
    run_id: str | None = None,
) -> dict[str, Any]:
    """Run one assignment under the execution-enabled support contract."""

    contract = load_contract()
    if contract["execution"]["available"] is not True:
        raise RuntimeError(
            "2b-support-pilot-v3 execution is unavailable until a separately "
            "committed execution contract and schedule"
        )
    return _run_agent(
        "support",
        arm,
        build=False,
        seed=contract["seed"],
        run_id=run_id,
        provider=contract["provider"],
        assignment=assignment,
        frozen_fingerprint=frozen_fingerprint,
    )


__all__ = ["run_support_pilot"]
