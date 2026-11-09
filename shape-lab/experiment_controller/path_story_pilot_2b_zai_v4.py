"""Freeze and run the versioned Z.ai transcript-recovery pilot serially.

The prior Z.ai invalid attempt also counts against the user's 14,000 rolling
5-hour and 35,000 one-time shares. Admission is between attempts; a provider
429 pauses replacement attempts and never becomes a behavioral outcome.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
from typing import Any

from experiment_controller import path_story_pilot_2b_v2 as prior
from experiment_controller import path_story_pilot_2b_zai as candidate
from experiment_controller.run_2a import agent_source_sha256, validate_sources
from experiment_controller.zai_coding_credits_2b import estimate_gateway_events_credits
from telemetry.replay_2b_path_story import verify_path_story_bundle


LAB = Path(__file__).resolve().parents[1]
CONFIG = LAB / "config" / "exp_2b_path_story_pilot_v4_zai.json"
REPORT = LAB / "runs" / "path-story-zai-v4-preflight-r2-20261109" / "report.json"
V4_COMPOSE = LAB / "compose_2b_path_story_pilot_zai_v4.yaml"
V4_RUNNER = LAB / "experiment_controller" / "run_2b_path_story_pilot_zai_v4.py"
PRIOR_SCHEDULE = LAB / "studies" / "2b-path-story-pilot-v3-zai-20261109124716-3c0485" / "schedule.json"
PRIOR_RUN = LAB / "runs" / "2b-path-20261109124816-55aca0"
PRIOR_PILOT_ID = "2b-path-story-pilot-v3-zai-20261109124716-3c0485"
STUDIES = LAB / "studies"
PROTOCOL = "2b-path-story-pilot-v4-zai"
PILOT_ID = re.compile(r"2b-path-story-pilot-v4-zai-[0-9]{14}-[0-9a-f]{6}\Z")
IMAGES = {
    "decoy": "shape-filesystem-decoy-2b:path-story-v2",
    "gateway": "shape-model-gateway:path-story-v3",
    "agent": "shape-2b-attacker:path-story-v2",
}
SOURCE_FILES = {
    **{name: path for name, path in prior.SOURCE_FILES.items()
       if name not in {
           "experiment_controller/path_story_pilot_2b_v2.py",
           "experiment_controller/run_2b_path_story_pilot_v2.py",
           "model_gateway/Dockerfile_path_story",
           "compose_2b_path_story_pilot.yaml",
       }},
    "experiment_controller/path_story_pilot_2b_zai_v4.py": Path(__file__),
    "experiment_controller/run_2b_path_story_pilot_zai_v4.py": V4_RUNNER,
    "experiment_controller/zai_coding_credits_2b.py": candidate.CREDITS,
    "experiment_controller/path_story_pilot_2b_zai.py": Path(candidate.__file__),
    "model_gateway/server_path_story_v2.py": candidate.gateway_candidate.GATEWAY_SERVER,
    "model_gateway/Dockerfile_path_story_v2": candidate.gateway_candidate.GATEWAY_DOCKERFILE,
    "compose_2b_path_story_pilot_zai_v4.yaml": V4_COMPOSE,
}
FIVE_HOURS = timedelta(hours=5)
RATE_LIMIT_PAUSE = timedelta(hours=5)
MINIMUM_RESERVE = Decimal(7500)
FIVE_HOUR_SHARE = Decimal(14000)
TOTAL_SHARE = Decimal(35000)


class PilotIntegrityError(RuntimeError):
    """A frozen schedule, archived attempt, or credit record differs."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise PilotIntegrityError("Timestamp is malformed") from exc
    if result.tzinfo is None:
        raise PilotIntegrityError("Timestamp needs a timezone")
    return result.astimezone(timezone.utc)


def _folder(pilot_id: str) -> Path:
    if PILOT_ID.fullmatch(pilot_id) is None:
        raise ValueError("Invalid Z.ai pilot ID")
    return STUDIES / pilot_id


def _prior_context() -> dict[str, Any]:
    if _sha(PRIOR_SCHEDULE) != "32af55e9b613d25d80ea8e3c386f5d0cf1be85a86e87b95e2fd35edb660bf9c5":
        raise PilotIntegrityError("Prior Z.ai schedule differs")
    prior_results = prior._results(PRIOR_PILOT_ID)
    if set(prior_results) != {1} or len(prior_results[1]) != 1 or prior_results[1][0][
        "manifest"
    ].get("run_id") != PRIOR_RUN.name:
        raise PilotIntegrityError("Prior Z.ai pilot has another unaccounted attempt")
    manifest_path = PRIOR_RUN / "attempt-manifest.json"
    gateway_path = PRIOR_RUN / "gateway-events.jsonl"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    gateway = [json.loads(line) for line in gateway_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    credits = estimate_gateway_events_credits(gateway)
    if (
        manifest.get("pilot_id") != PRIOR_PILOT_ID
        or manifest.get("run_id") != PRIOR_RUN.name
        or manifest.get("provider") != "zai"
        or manifest.get("termination_reason") != "agent_failure"
        or manifest.get("error") != "provider: episode stream ended without TurnCompleted"
        or manifest.get("provider_credits") != credits
        or credits["estimated_total_credits"] != "100.809835000"
    ):
        raise PilotIntegrityError("Prior Z.ai invalid attempt differs")
    return {
        "pilot_id": PRIOR_PILOT_ID,
        "schedule_sha256": _sha(PRIOR_SCHEDULE),
        "invalid_run_id": PRIOR_RUN.name,
        "attempt_manifest_sha256": _sha(manifest_path),
        "gateway_events_sha256": _sha(gateway_path),
        "estimated_credits": credits["estimated_total_credits"],
        "valid_slots_carried_forward": [],
    }


def docker_check() -> dict[str, Any]:
    """Build successor images and prove B0/B3 wiring with a dummy key."""
    if REPORT.exists():
        raise PilotIntegrityError("Versioned preflight report already exists")
    contract = json.loads(CONFIG.read_text(encoding="utf-8"))
    if (
        contract.get("pilot_protocol") != PROTOCOL
        or contract.get("provider") != "zai"
        or contract.get("model") != "glm-5.3"
        or contract.get("task_sha256") != _sha(candidate.TASK)
        or contract.get("fixture_sha256") != _sha(candidate.FIXTURE)
        or contract.get("predecessor_v3_context") != _prior_context()
    ):
        raise PilotIntegrityError("V4 preflight inputs differ")
    command = [
        "docker", "compose", "--profile", "agent",
        "-f", str(candidate.BASE_COMPOSE),
        "-f", str(candidate.STORY_COMPOSE),
        "-f", str(V4_COMPOSE),
        "build", "filesystem-decoy-2b", "model-gateway", "attacker-agent",
    ]
    build = subprocess.run(command, cwd=LAB, capture_output=True, timeout=1200)
    if build.returncode:
        raise PilotIntegrityError(
            "V4 image build failed: " + build.stderr[-2000:].decode("utf-8", "replace")
        )
    from experiment_controller.run_2b_path_story_pilot_zai_v4 import preflight_no_model

    preflights = [
        preflight_no_model(contract=contract, seed=contract["block_seeds"]["1"], arm="B0"),
        preflight_no_model(contract=contract, seed=contract["block_seeds"]["2"], arm="B3"),
    ]
    if any(
        row.get("status") != "passed" or row.get("model_calls") != 0
        or row.get("agent_started") is not False for row in preflights
    ):
        raise PilotIntegrityError("V4 dummy-key preflight failed")
    report = {
        "schema_version": 1,
        "candidate_protocol": "2b-path-story-pilot-v4-zai-preflight",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "task_sha256": _sha(candidate.TASK),
        "fixture_sha256": _sha(candidate.FIXTURE),
        "source_sha256": {name: _sha(path) for name, path in SOURCE_FILES.items()},
        "agent_source_sha256": agent_source_sha256(),
        "predecessor_v3_context": _prior_context(),
        "preflights": preflights,
        "model_calls": 0,
    }
    REPORT.parent.mkdir(parents=True, mode=0o700, exist_ok=False)
    prior._write_committed(REPORT, report)
    (REPORT.parent / "build.log").write_bytes(build.stdout + build.stderr)
    contract["zai_model_free_preflight"]["report_sha256"] = _sha(REPORT)
    CONFIG.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def load_contract() -> dict[str, Any]:
    baseline = json.loads(
        (LAB / "config" / "exp_2b_path_story_pilot_v3_zai_active.json").read_text(encoding="utf-8")
    )
    if (
        baseline.get("pilot_protocol") != "2b-path-story-pilot-v3-zai"
        or baseline.get("task_sha256") != _sha(candidate.TASK)
        or baseline.get("fixture_sha256") != _sha(candidate.FIXTURE)
        or baseline.get("coding_plan_credit_governance", {}).get("pilot_total_share_credits") != 35000
    ):
        raise PilotIntegrityError("Prior Z.ai contract baseline differs")
    active = json.loads(CONFIG.read_text(encoding="utf-8"))
    expected = dict(baseline)
    expected["pilot_protocol"] = PROTOCOL
    expected["contract_kind"] = "fresh_eight_slot_zai_coding_plan_pilot_v4"
    expected["status"] = "schedule_freeze_available_after_v4_preflight"
    expected["predecessor_v3_context"] = _prior_context()
    expected["zai_model_free_preflight"] = {
        "report_path": REPORT.relative_to(LAB).as_posix(),
        "report_sha256": _sha(REPORT),
    }
    expected["execution"] = dict(baseline["execution"])
    expected["execution"]["cohort_enrollment_decision"] = "fresh_eight_after_versioned_agent_recovery"
    if active != expected:
        raise PilotIntegrityError("Z.ai execution contract differs")
    report = prior._read_committed(REPORT)
    if (
        report.get("candidate_protocol") != "2b-path-story-pilot-v4-zai-preflight"
        or report.get("task_sha256") != _sha(candidate.TASK)
        or report.get("fixture_sha256") != _sha(candidate.FIXTURE)
        or report.get("source_sha256")
        != {name: _sha(path) for name, path in SOURCE_FILES.items()}
        or report.get("agent_source_sha256") != agent_source_sha256()
        or report.get("predecessor_v3_context") != _prior_context()
        or report.get("model_calls") != 0
        or [(row.get("arm"), row.get("status"), row.get("model_calls"))
            for row in report.get("preflights", [])]
        != [("B0", "passed", 0), ("B3", "passed", 0)]
    ):
        raise PilotIntegrityError("Z.ai dummy-key preflight report differs")
    return active


def load_schedule(pilot_id: str) -> dict[str, Any]:
    schedule = prior._read_committed(_folder(pilot_id) / "schedule.json")
    contract = load_contract()
    if (
        schedule.get("pilot_id") != pilot_id
        or schedule.get("pilot_protocol") != PROTOCOL
        or schedule.get("contract_sha256") != _sha(CONFIG)
        or schedule.get("contract") != contract
        or schedule.get("assignments")
        != prior.assignments(contract, schedule.get("randomization_seed", ""))
        or len(schedule["assignments"]) != 8
    ):
        raise PilotIntegrityError("Frozen Z.ai schedule differs")
    frozen = schedule.get("fingerprint")
    if not isinstance(frozen, dict):
        raise PilotIntegrityError("Z.ai fingerprint is missing")
    for relative, digest in frozen.get("source_sha256", {}).items():
        if relative not in SOURCE_FILES or _sha(SOURCE_FILES[relative]) != digest:
            raise PilotIntegrityError(f"Frozen source differs: {relative}")
    if set(frozen.get("source_sha256", {})) != set(SOURCE_FILES):
        raise PilotIntegrityError("Frozen source inventory differs")
    if frozen.get("compose_sha256") != {
        path.name: _sha(path)
        for path in (candidate.BASE_COMPOSE, candidate.STORY_COMPOSE, V4_COMPOSE)
    }:
        raise PilotIntegrityError("Frozen Compose source differs")
    if frozen.get("agent_task_sha256") != _sha(candidate.TASK) or frozen.get(
        "fixture_sha256"
    ) != _sha(candidate.FIXTURE):
        raise PilotIntegrityError("Frozen task or fixture differs")
    if frozen.get("agent_source_sha256") != agent_source_sha256():
        raise PilotIntegrityError("Frozen PentestGPT agent source differs")
    if frozen.get("images") != {
        role: prior._image_id(tag) for role, tag in IMAGES.items()
    }:
        raise PilotIntegrityError("Frozen Docker image differs")
    return schedule


def prepare(*, randomization_seed: str | None = None) -> dict[str, Any]:
    """Freeze a fresh balanced schedule; make no provider request."""
    contract = load_contract()
    seed = randomization_seed or secrets.token_hex(16)
    if prior.SEED.fullmatch(seed) is None:
        raise ValueError("Invalid randomization seed")
    pentest_commit, unified_commit = validate_sources()
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    images = {role: prior._image_id(tag) for role, tag in IMAGES.items()}
    if images != report["preflights"][0]["images"] or images != report["preflights"][1]["images"]:
        raise PilotIntegrityError("Docker images changed since dummy-key preflight")
    embedded_task = prior._embedded_task_sha256(images["agent"])
    if embedded_task != _sha(candidate.TASK):
        raise PilotIntegrityError("Agent image task differs")
    now = datetime.now(timezone.utc)
    pilot_id = "2b-path-story-pilot-v4-zai-" + now.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    fingerprint = {
        "schema_version": 1,
        "pilot_protocol": PROTOCOL,
        "contract_sha256": _sha(CONFIG),
        "agent_task_sha256": _sha(candidate.TASK),
        "agent_image_task_sha256": embedded_task,
        "fixture_sha256": _sha(candidate.FIXTURE),
        "catalog_fingerprint": contract["catalog_fingerprint"],
        "matrix_report_sha256": contract["model_free_gate"]["matrix_report_sha256"],
        "compose_sha256": {path.name: _sha(path) for path in (
            candidate.BASE_COMPOSE, candidate.STORY_COMPOSE, V4_COMPOSE,
        )},
        "source_sha256": {name: _sha(path) for name, path in SOURCE_FILES.items()},
        "agent_source_sha256": agent_source_sha256(),
        "pentestgpt_commit": pentest_commit,
        "unified_agent_commit": unified_commit,
        "images": images,
        "runtime_policy": contract["runtime_policy"],
        "trial_caps": contract["trial_caps"],
    }
    schedule = {
        "schema_version": 1,
        "pilot_protocol": PROTOCOL,
        "pilot_id": pilot_id,
        "created_utc": now.isoformat(),
        "randomization_seed": seed,
        "randomization_algorithm": "v2_sha256_balanced_block_sampler",
        "contract_sha256": _sha(CONFIG),
        "contract": contract,
        "fingerprint": fingerprint,
        "source_model_free_report_sha256": _sha(REPORT),
        "assignments": prior.assignments(contract, seed),
    }
    folder = _folder(pilot_id)
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    (folder / "admissions").mkdir(mode=0o700)
    prior._write_committed(folder / "schedule.json", schedule)
    return status(pilot_id)


def _attempts(schedule: dict[str, Any]) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    found = prior._results(schedule["pilot_id"])
    valid: dict[int, dict[str, Any]] = {}
    invalid: list[dict[str, Any]] = []
    priced: list[dict[str, Any]] = []
    for assignment in schedule["assignments"]:
        slot = assignment["slot"]
        for result in found.get(slot, []):
            manifest = result["manifest"]
            run_dir = prior._verify_attempt_artifacts(result)
            expected_assignment = {key: assignment[key] for key in ("slot", "block", "arm", "seed")}
            expected_assignment["pilot_id"] = schedule["pilot_id"]
            if (
                manifest.get("assignment") != expected_assignment
                or manifest.get("pilot_protocol") != PROTOCOL
                or manifest.get("provider") != "zai"
                or manifest.get("pilot_fingerprint") != schedule["fingerprint"]
            ):
                raise PilotIntegrityError("Archived Z.ai attempt differs from its assignment")
            if manifest.get("confirmed_containment_escape_incident") is True:
                raise PilotIntegrityError("Confirmed containment escape incident")
            gateway = [json.loads(line) for line in (run_dir / "gateway-events.jsonl").read_text().splitlines() if line.strip()]
            if any(row.get("event_type") == "gateway_error" for row in gateway):
                raise PilotIntegrityError("Unpriced gateway error requires reconciliation")
            credits = estimate_gateway_events_credits(gateway)
            if result.get("provider_credits") != credits or manifest.get("provider_credits") != credits:
                raise PilotIntegrityError("Archived Z.ai credits differ from gateway usage")
            priced.append({"run_id": manifest["run_id"], "finished_utc": manifest["finished_utc"],
                           "credits": Decimal(credits["estimated_total_credits"])})
            reason = None
            if any(row.get("event_type") in {"provider_rate_limit_rejected", "provider_rate_limit_exhausted"} for row in gateway):
                reason = "provider_rate_limit"
            elif manifest.get("error") or manifest.get("provider_credit_error") or manifest.get("path_story_evidence_error"):
                reason = "controller_error"
            elif manifest.get("provider_settlement", {}).get("state") != "complete":
                reason = "missing_required_telemetry"
            elif manifest.get("termination_reason") in {"agent_failure", "controller_error"}:
                reason = manifest["termination_reason"]
            elif manifest.get("termination_reason") not in prior.TERMINAL_REASONS:
                reason = "undeclared_terminal_state"
            else:
                try:
                    if result.get("replay") != verify_path_story_bundle(run_dir):
                        reason = "replay_failure"
                except Exception:
                    reason = "replay_failure"
            if reason is None:
                if slot in valid:
                    raise PilotIntegrityError("Slot has two valid runs")
                valid[slot] = result
            else:
                if reason not in schedule["contract"]["replacement_policy"]["infrastructure_invalid_reasons"]:
                    raise PilotIntegrityError("Unreplaceable Z.ai infrastructure violation")
                invalid.append({"slot": slot, "run_id": manifest["run_id"], "reason": reason})
        if sum(row["slot"] == slot for row in invalid) > 2:
            raise PilotIntegrityError("Slot exhausted its replacement allowance")
    return valid, invalid, priced


def credit_admission(priced: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    """Count every valid or invalid priced attempt, with no outcome fields."""
    total = Decimal(0)
    five_hour = Decimal(0)
    for row in priced:
        credits = row.get("credits")
        if not isinstance(credits, Decimal) or not credits.is_finite() or credits < 0:
            raise PilotIntegrityError("Attempt credit estimate is invalid")
        age = now - _utc(row.get("finished_utc"))
        if age < timedelta(0):
            raise PilotIntegrityError("Attempt finish time is in the future")
        total += credits
        if age < FIVE_HOURS:
            five_hour += credits
    remaining_total = max(Decimal(0), TOTAL_SHARE - total)
    remaining_five_hour = max(Decimal(0), FIVE_HOUR_SHARE - five_hour)
    return {
        "accounting_kind": "estimated_from_reported_usage",
        "plan_tier": "Max",
        "pilot_total_share": str(TOTAL_SHARE),
        "pilot_five_hour_share": str(FIVE_HOUR_SHARE),
        "minimum_uncommitted_per_new_run": str(MINIMUM_RESERVE),
        "accrued_total": format(total, ".9f"),
        "accrued_rolling_five_hour": format(five_hour, ".9f"),
        "remaining_total": format(remaining_total, ".9f"),
        "remaining_rolling_five_hour": format(remaining_five_hour, ".9f"),
        "other_subscriber_usage_visible": False,
        "active_run_credit_termination_allowed": False,
        "admitted_by_local_share": (
            remaining_total >= MINIMUM_RESERVE
            and remaining_five_hour >= MINIMUM_RESERVE
        ),
    }


def status(pilot_id: str) -> dict[str, Any]:
    schedule = load_schedule(pilot_id)
    valid, invalid, priced = _attempts(schedule)
    previous = _prior_context()
    previous_manifest = json.loads((PRIOR_RUN / "attempt-manifest.json").read_text(encoding="utf-8"))
    priced.insert(0, {
        "run_id": previous["invalid_run_id"],
        "finished_utc": previous_manifest["finished_utc"],
        "credits": Decimal(previous["estimated_credits"]),
    })
    now = datetime.now(timezone.utc)
    credits = credit_admission(priced, now)
    next_slot = next((row["slot"] for row in schedule["assignments"] if row["slot"] not in valid), None)
    folder = _folder(pilot_id)
    pending_path = folder / "pending-run.json"
    pending = prior._read_committed(pending_path) if pending_path.exists() else None
    rate_limited = [row for row in invalid if row["reason"] == "provider_rate_limit"]
    last_limit = max((_utc(row["finished_utc"]) for row in priced if any(
        bad["run_id"] == row["run_id"] for bad in rate_limited
    )), default=None)
    limit_pause_until = last_limit + RATE_LIMIT_PAUSE if last_limit else None
    admitted = credits["admitted_by_local_share"]
    if pending:
        phase = "pending_attempt_reconciliation"
    elif next_slot is None:
        phase = "complete"
    elif limit_pause_until and now < limit_pause_until:
        phase = "paused_provider_rate_limit"
    elif not admitted:
        phase = "paused_credit_share_admission"
    else:
        phase = "ready_for_next_run"
    return {
        "pilot_id": pilot_id,
        "pilot_protocol": PROTOCOL,
        "schedule_sha256": _sha(folder / "schedule.json"),
        "scheduled_runs": 8,
        "valid_runs": len(valid),
        "completed_slots": sorted(valid),
        "invalid_attempts": invalid,
        "predecessor_invalid_attempt": {
            "run_id": previous["invalid_run_id"],
            "estimated_credits": previous["estimated_credits"],
            "behavioral_slots_carried_forward": 0,
        },
        "next_slot": next_slot,
        "pending_run": pending,
        "phase": phase,
        "credits": {
            **credits,
            "may_start_new_run": phase == "ready_for_next_run",
            "rate_limit_pause_until_utc": limit_pause_until.isoformat() if limit_pause_until else None,
        },
    }


def execute(pilot_id: str) -> dict[str, Any]:
    """Start at most one assignment after the effect-blind credit check."""
    before = status(pilot_id)
    if before["phase"] != "ready_for_next_run":
        return before
    schedule = load_schedule(pilot_id)
    assignment = schedule["assignments"][before["next_slot"] - 1]
    folder = _folder(pilot_id)
    lock = folder / "execute.lock"
    prior._write_new(lock, b"")
    try:
        before = status(pilot_id)
        if before["phase"] != "ready_for_next_run":
            return before
        now = datetime.now(timezone.utc)
        run_id = "2b-path-" + now.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        admission = {
            "schema_version": 1, "pilot_id": pilot_id,
            "schedule_sha256": before["schedule_sha256"],
            "run_id": run_id, "slot": assignment["slot"],
            "created_utc": now.isoformat(), "credits": before["credits"],
        }
        prior._write_committed(folder / "admissions" / (run_id + ".json"), admission)
        pending_path = folder / "pending-run.json"
        prior._write_committed(pending_path, admission)
        from experiment_controller.run_2b_path_story_pilot_zai_v4 import run_path_story_pilot

        run_path_story_pilot(
            pilot_id=pilot_id, slot=assignment["slot"], block=assignment["block"],
            arm=assignment["arm"], seed=assignment["seed"], run_id=run_id,
            frozen_fingerprint=schedule["fingerprint"], contract=schedule["contract"],
        )
        pending_path.unlink()
        pending_path.with_suffix(".sha256").unlink()
        return status(pilot_id)
    finally:
        lock.unlink(missing_ok=True)


def reconcile_pending(pilot_id: str) -> dict[str, Any]:
    folder = _folder(pilot_id)
    pending = prior._read_committed(folder / "pending-run.json")
    run_id = pending.get("run_id")
    if not isinstance(run_id, str) or prior.RUN_ID.fullmatch(run_id) is None:
        raise PilotIntegrityError("Pending run ID is invalid")
    if not (LAB / "runs" / run_id / "result.json").is_file():
        raise PilotIntegrityError("Pending attempt has no archived result")
    schedule = load_schedule(pilot_id)
    _attempts(schedule)
    (folder / "pending-run.json").unlink()
    (folder / "pending-run.sha256").unlink()
    return status(pilot_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("docker-check")
    actions.add_parser("prepare")
    for name in ("status", "execute", "reconcile-pending"):
        action = actions.add_parser(name)
        action.add_argument("--pilot-id", required=True)
    args = parser.parse_args()
    if args.action == "docker-check":
        value = docker_check()
    elif args.action == "prepare":
        value = prepare()
    elif args.action == "status":
        value = status(args.pilot_id)
    elif args.action == "execute":
        value = execute(args.pilot_id)
    else:
        value = reconcile_pending(args.pilot_id)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
