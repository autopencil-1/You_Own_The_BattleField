"""Frozen controlled-v3 assignments and between-run resource admission."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import secrets
from typing import Any

from experiment_controller import support_pilot_2b
from experiment_controller.controlled_2b_v3_contract import CONFIG, LAB, load_contract, sha256
from experiment_controller.provider_cost_2b import (
    _format_nano_usd,
    _usd_to_nano,
    estimate_gateway_events_cost,
)
from experiment_controller.run_2b_controlled_v3 import run_controlled_v3, write_private
from telemetry.replay_2b_controlled_v3 import verify_run


STUDIES = LAB / "studies"
PROTOCOL = "2b-controlled-v3"
ID = re.compile(r"2b-study-v3-[0-9]{14}-[0-9a-f]{6}")
SEED = re.compile(r"[A-Za-z0-9._-]{1,128}")
ARMS = ("B0", "B1", "B2", "B3")
RESERVE_NANO_USD = 15_000_000_000
INITIAL_NANO_USD = 600_000_000_000
SOURCE_FILES = {
    "scheduler": Path(__file__),
    "runner": LAB / "experiment_controller" / "run_2b_controlled_v3.py",
    "scorer": LAB / "telemetry" / "score_2b_controlled_v3.py",
    "replay": LAB / "telemetry" / "replay_2b_controlled_v3.py",
    "cost": LAB / "experiment_controller" / "provider_cost_2b.py",
}


class StudyIntegrityError(RuntimeError):
    """A nonreplaceable violation of the frozen controlled study."""


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def study_dir(study_id: str) -> Path:
    if not ID.fullmatch(study_id):
        raise ValueError("Invalid controlled-v3 study ID")
    return STUDIES / study_id


def fingerprint() -> dict[str, Any]:
    """Bind the validated image population and the new execution sources."""
    contract = load_contract()
    support = support_pilot_2b.fingerprint()
    return {
        "study_protocol": PROTOCOL,
        "contract_sha256": sha256(CONFIG),
        "agent_task_sha256": support["agent_task_sha256"],
        "agent_image_task_sha256": support["agent_image_task_sha256"],
        "fixture_sha256": support["fixture_sha256"],
        "compose_sha256": support["compose_sha256"],
        "images": support["images"],
        "image_source_sha256": support["image_source_sha256"],
        "pentestgpt_commit": support["pentestgpt_commit"],
        "agent_source_sha256": support["agent_source_sha256"],
        "unified_agent_commit": support["unified_agent_commit"],
        "claude_code_cli_version": support["claude_code_cli_version"],
        "support_source_sha256": support["source_sha256"],
        "v3_source_sha256": {key: sha256(path) for key, path in SOURCE_FILES.items()},
        "runtime_policy": contract["runtime_policy"],
        "attempt_bounds": contract["attempt_bounds"],
        "trial_caps": contract["trial_caps"],
        "cap_policy": contract["cap_policy"],
    }


def _assignments(contract: dict[str, Any], seed: str) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rows = []
    for block in range(1, contract["design"]["balanced_blocks"] + 1):
        order = list(ARMS)
        rng.shuffle(order)
        for arm in order:
            rows.append({
                "slot": len(rows) + 1,
                "block": block,
                "arm": arm,
                "factors": contract["design"]["arms"][arm],
            })
    return rows


def _committed(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        expected = path.with_suffix(".sha256").read_text(encoding="utf-8").strip()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise StudyIntegrityError(f"Missing or malformed commitment: {path.name}") from exc
    if (
        not isinstance(value, dict)
        or raw != _canonical(value)
        or expected != hashlib.sha256(raw.encode("utf-8")).hexdigest()
    ):
        raise StudyIntegrityError(f"Committed artifact changed: {path.name}")
    return value


def _write_committed(path: Path, value: dict[str, Any]) -> None:
    raw = _canonical(value)
    commitment = hashlib.sha256(raw.encode()).hexdigest() + "\n"
    if not path.exists():
        write_private(path, raw)
        write_private(path.with_suffix(".sha256"), commitment)
        return
    old = _committed(path)
    history = path.parent / "funding-history"
    history.mkdir(mode=0o700, exist_ok=True)
    prior = history / f"funding-{len(old['tranches']):04d}.json"
    if prior.exists():
        if _committed(prior) != old:
            raise StudyIntegrityError("Prior funding history differs")
    else:
        write_private(prior, _canonical(old))
        write_private(prior.with_suffix(".sha256"), sha256(path) + "\n")
    suffix = secrets.token_hex(8)
    next_path = path.with_name(path.name + "." + suffix)
    next_commit = path.with_name(path.stem + "." + suffix + ".sha256")
    write_private(next_path, raw)
    write_private(next_commit, commitment)
    os.replace(next_path, path)
    os.replace(next_commit, path.with_suffix(".sha256"))


def prepare(*, randomization_seed: str | None = None) -> dict[str, Any]:
    """Freeze forty assignments and the first approved resource tranche."""
    contract = load_contract()
    randomization_seed = randomization_seed or secrets.token_hex(16)
    if not SEED.fullmatch(randomization_seed):
        raise ValueError("Invalid randomization seed")
    study_id = (
        "2b-study-v3-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        + "-" + secrets.token_hex(3)
    )
    schedule = {
        "schema_version": 1,
        "study_protocol": PROTOCOL,
        "study_id": study_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "randomization_seed": randomization_seed,
        "contract_sha256": sha256(CONFIG),
        "contract": contract,
        "fingerprint": fingerprint(),
        "execution_policy": {
            "runs_serial": True,
            "admission_between_runs_only": True,
            "minimum_uncommitted_reserve_usd": "15.000000000",
            "active_run_cost_termination_allowed": False,
            "cost_enters_outcome_analysis": False,
        },
        "assignments": _assignments(contract, randomization_seed),
    }
    folder = study_dir(study_id)
    folder.mkdir(parents=True, mode=0o700)
    for name in ("review-packets", "annotations", "adjudications"):
        (folder / name).mkdir(mode=0o700)
    _write_committed(folder / "schedule.json", schedule)
    funding = {
        "schema_version": 1,
        "study_id": study_id,
        "schedule_sha256": sha256(folder / "schedule.json"),
        "tranches": [{
            "sequence": 1,
            "authorized_utc": datetime.now(timezone.utc).isoformat(),
            "amount_nano_usd": INITIAL_NANO_USD,
            "amount_usd": _format_nano_usd(INITIAL_NANO_USD),
            "authorization_basis": "user_approved_initial_tranche",
        }],
    }
    _write_committed(folder / "funding.json", funding)
    return schedule


def load_schedule(study_id: str) -> dict[str, Any]:
    schedule = _committed(study_dir(study_id) / "schedule.json")
    contract = load_contract()
    seed = schedule.get("randomization_seed")
    if (
        schedule.get("study_id") != study_id
        or schedule.get("study_protocol") != PROTOCOL
        or schedule.get("contract_sha256") != sha256(CONFIG)
        or schedule.get("contract") != contract
        or not isinstance(seed, str)
        or not SEED.fullmatch(seed)
        or schedule.get("assignments") != _assignments(contract, seed)
        or len(schedule["assignments"]) != 40
        or schedule.get("execution_policy") != {
            "runs_serial": True,
            "admission_between_runs_only": True,
            "minimum_uncommitted_reserve_usd": "15.000000000",
            "active_run_cost_termination_allowed": False,
            "cost_enters_outcome_analysis": False,
        }
    ):
        raise StudyIntegrityError("Controlled-v3 schedule semantics differ")
    return schedule


def _results(study_id: str) -> dict[int, list[dict[str, Any]]]:
    found: dict[int, list[dict[str, Any]]] = {}
    for path in (LAB / "runs").glob("*/result.json"):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
            assignment = result.get("manifest", {}).get("assignment", {})
        except (OSError, json.JSONDecodeError, AttributeError):
            continue
        if assignment.get("study_id") != study_id:
            continue
        slot = assignment.get("slot")
        if not isinstance(slot, int) or isinstance(slot, bool) or not 1 <= slot <= 40:
            raise StudyIntegrityError("Controlled-v3 archive has an invalid slot")
        found.setdefault(slot, []).append(result)
    for rows in found.values():
        rows.sort(key=lambda row: row.get("manifest", {}).get("started_utc", ""))
    for path in (LAB / "runs").glob("*/manifest.json"):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if manifest.get("assignment", {}).get("study_id") == study_id and not (path.parent / "result.json").exists():
            raise StudyIntegrityError(f"Unsettled controlled-v3 archive: {path.parent.name}")
    return found


def invalid_reason(result: dict[str, Any], schedule: dict[str, Any], row: dict[str, Any]) -> str | None:
    manifest = result.get("manifest", {})
    expected = {key: row[key] for key in ("slot", "block", "arm")}
    expected["study_id"] = schedule["study_id"]
    fp = schedule["fingerprint"]
    if (
        manifest.get("mode") != "controlled"
        or manifest.get("study_protocol") != PROTOCOL
        or manifest.get("experimental_result") is not True
        or manifest.get("assignment") != expected
        or manifest.get("study_fingerprint") != fp
        or manifest.get("arm") != row["arm"]
        or manifest.get("controlled_contract_sha256") != schedule["contract_sha256"]
        or manifest.get("controller_sha256") != fp["v3_source_sha256"]["runner"]
        or manifest.get("images") != fp["images"]
        or manifest.get("agent_task_sha256") != fp["agent_task_sha256"]
        or manifest.get("max_pre_entry_wall_seconds") != 180
        or manifest.get("max_post_entry_wall_seconds") != 600
        or manifest.get("max_filesystem_actions") != schedule["contract"]["trial_caps"]["max_filesystem_actions"]
    ):
        return "source_or_image_drift"
    if manifest.get("confirmed_containment_escape_incident") is True:
        raise StudyIntegrityError("Confirmed containment escape")
    reason = manifest.get("termination_reason")
    if reason in {"provider_rate_limit", "model_usage_missing", "controller_error", "agent_failure"}:
        return reason
    if reason not in {"agent_exit", *schedule["contract"]["termination_policy"]["right_censored_reasons"]}:
        return "undeclared_terminal_state"
    score = result.get("score")
    if not isinstance(score, dict) or score.get("scoring_error"):
        return "scoring_error"
    if score.get("experimental_result") is not True or score.get("entry_success") not in {True, False}:
        return "missing_required_telemetry"
    try:
        verify_run(LAB / "runs" / manifest["run_id"])
    except Exception:
        return "replay_failure"
    return None


def _classified(schedule: dict[str, Any], found: dict[int, list[dict[str, Any]]]) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    valid = {}
    invalid = []
    allowed = set(schedule["contract"]["replacement_policy"]["infrastructure_invalid_reasons"])
    for row in schedule["assignments"]:
        for result in found.get(row["slot"], []):
            reason = invalid_reason(result, schedule, row)
            if reason is None:
                if row["slot"] in valid:
                    raise StudyIntegrityError("Multiple valid runs for one slot")
                valid[row["slot"]] = result
            elif reason in allowed:
                invalid.append({"slot": row["slot"], "run_id": result.get("manifest", {}).get("run_id"), "reason": reason})
            else:
                raise StudyIntegrityError(f"Unclassified invalid reason: {reason}")
    return valid, invalid


def funding_snapshot(study_id: str, found: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    funding = _committed(study_dir(study_id) / "funding.json")
    schedule = load_schedule(study_id)
    if funding.get("study_id") != study_id or funding.get("schedule_sha256") != sha256(study_dir(study_id) / "schedule.json"):
        raise StudyIntegrityError("Funding ledger is bound to another schedule")
    tranches = funding.get("tranches")
    if not isinstance(tranches, list) or not tranches or any(
        row.get("sequence") != index or row.get("amount_nano_usd", 0) <= 0
        or row.get("amount_usd") != _format_nano_usd(row["amount_nano_usd"])
        for index, row in enumerate(tranches, 1)
    ):
        raise StudyIntegrityError("Funding tranches are invalid")
    authorized = sum(row["amount_nano_usd"] for row in tranches)
    governance = {"rate_card": schedule["contract"]["provider_cost_review"]["rate_card"]}
    estimates = []
    errors = []
    for result in [item for rows in found.values() for item in rows]:
        run_id = result.get("manifest", {}).get("run_id")
        try:
            path = LAB / "runs" / run_id / "gateway-events.jsonl"
            events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            estimates.append({"run_id": run_id, **estimate_gateway_events_cost(events, governance)})
        except (OSError, ValueError, TypeError) as exc:
            errors.append({"run_id": run_id, "reason": str(exc)})
    accrued = sum(row["estimated_cost_nano_usd"] for row in estimates)
    remaining = max(0, authorized - accrued)
    admitted = not errors and remaining >= RESERVE_NANO_USD
    return {
        "accounting_state": "complete" if not errors else "incomplete",
        "authorized_usd": _format_nano_usd(authorized),
        "accrued_usd": _format_nano_usd(accrued),
        "remaining_usd": _format_nano_usd(remaining),
        "required_reserve_usd": _format_nano_usd(RESERVE_NANO_USD),
        "tranches": tranches,
        "attempts_priced": len(estimates),
        "errors": errors,
        "may_start_new_run": admitted,
        "state": "admitted" if admitted else "paused_incomplete_cost_evidence" if errors else "paused_insufficient_reserve",
        "active_run_termination_allowed": False,
        "creates_trial_attempt": False,
        "creates_censored_outcome": False,
    }


def add_tranche(study_id: str, amount_usd: str) -> dict[str, Any]:
    """Record a later authorization without altering the scientific schedule."""
    amount = _usd_to_nano(amount_usd, "new authorization tranche")
    if amount <= 0:
        raise ValueError("New authorization tranche must be positive")
    folder = study_dir(study_id)
    load_schedule(study_id)
    if (folder / "execute.lock").exists():
        raise StudyIntegrityError("Cannot replenish funding while a run is active")
    funding = _committed(folder / "funding.json")
    funding_snapshot(study_id, _results(study_id))
    tranches = funding["tranches"]
    tranches.append({
        "sequence": len(tranches) + 1,
        "authorized_utc": datetime.now(timezone.utc).isoformat(),
        "amount_nano_usd": amount,
        "amount_usd": _format_nano_usd(amount),
        "authorization_basis": "user_approved_replenishment",
        "previous_ledger_sha256": sha256(folder / "funding.json"),
    })
    _write_committed(folder / "funding.json", funding)
    return funding_snapshot(study_id, _results(study_id))


def status(study_id: str) -> dict[str, Any]:
    schedule = load_schedule(study_id)
    found = _results(study_id)
    valid, invalid = _classified(schedule, found)
    next_slot = next((row["slot"] for row in schedule["assignments"] if row["slot"] not in valid), None)
    funding = funding_snapshot(study_id, found)
    pending = study_dir(study_id) / "pending-run.json"
    return {
        "study_id": study_id,
        "study_protocol": PROTOCOL,
        "schedule_sha256": sha256(study_dir(study_id) / "schedule.json"),
        "scheduled_runs": 40,
        "valid_runs": len(valid),
        "completed_slots": sorted(valid),
        "invalid_attempts": invalid,
        "next_slot": next_slot,
        "phase": "pending_attempt_reconciliation" if pending.exists() else "execution_complete_awaiting_annotation" if next_slot is None else "execution_enabled" if funding["may_start_new_run"] else "paused_provider_cost_admission",
        "pending_run": json.loads(pending.read_text(encoding="utf-8")) if pending.exists() else None,
        "funding": funding,
    }


def execute(study_id: str, *, max_new_runs: int | None = None) -> dict[str, Any]:
    schedule = load_schedule(study_id)
    if fingerprint() != schedule["fingerprint"]:
        raise StudyIntegrityError("Controlled-v3 source or image fingerprint changed")
    if max_new_runs is not None and (not isinstance(max_new_runs, int) or isinstance(max_new_runs, bool) or max_new_runs < 1):
        raise ValueError("max_new_runs must be positive")
    lock = study_dir(study_id) / "execute.lock"
    pending = study_dir(study_id) / "pending-run.json"
    if pending.exists():
        raise StudyIntegrityError("A prior run needs archive and cost reconciliation")
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    created = 0
    try:
        for row in schedule["assignments"]:
            while True:
                found = _results(study_id)
                valid, invalid = _classified(schedule, found)
                if row["slot"] in valid:
                    break
                attempts = [item for item in invalid if item["slot"] == row["slot"]]
                maximum = schedule["contract"]["replacement_policy"]["maximum_infrastructure_invalid_replacements_per_slot"]
                if len(attempts) > maximum:
                    raise StudyIntegrityError(f"Slot {row['slot']} exceeded its replacement allowance")
                if max_new_runs is not None and created >= max_new_runs:
                    return status(study_id)
                if not funding_snapshot(study_id, found)["may_start_new_run"]:
                    return status(study_id)
                assignment = {"study_id": study_id, **{key: row[key] for key in ("slot", "block", "arm")}}
                run_id = "2b-cont-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
                write_private(pending, _canonical({
                    "study_id": study_id,
                    "slot": row["slot"],
                    "run_id": run_id,
                    "schedule_sha256": sha256(study_dir(study_id) / "schedule.json"),
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                }))
                result = run_controlled_v3(row["arm"], assignment=assignment, frozen_fingerprint=schedule["fingerprint"], run_id=run_id)
                pending.unlink()
                created += 1
                reason = invalid_reason(result, schedule, row)
                if reason == "provider_rate_limit":
                    raise RuntimeError("Provider rate limit; resume the frozen slot later")
    finally:
        lock.unlink(missing_ok=True)
    return status(study_id)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--randomization-seed")
    for action in ("status", "execute", "authorize"):
        item = sub.add_parser(action)
        item.add_argument("--study-id", required=True)
        if action == "execute":
            item.add_argument("--max-new-runs", type=int)
        if action == "authorize":
            item.add_argument("--amount-usd", required=True)
    args = parser.parse_args()
    if args.action == "prepare":
        schedule = prepare(randomization_seed=args.randomization_seed)
        value = status(schedule["study_id"])
    elif args.action == "status":
        value = status(args.study_id)
    elif args.action == "authorize":
        value = add_tranche(args.study_id, args.amount_usd)
    else:
        value = execute(args.study_id, max_new_runs=args.max_new_runs)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
