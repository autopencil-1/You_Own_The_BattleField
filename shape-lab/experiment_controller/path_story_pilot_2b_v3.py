"""Model-free checks for a prospective path-story gateway closeout revision.

This candidate has no enrollment, funding transfer, schedule, or run command.
The prior v2 pilot remains paused. A later decision must define whether any
successor study continues its assignments or starts a fresh cohort.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
from typing import Any

from experiment_controller import path_story_pilot_2b_v2 as prior_pilot
from experiment_controller import path_story_pilot_2b_v2_closeout as closeout
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture


LAB = Path(__file__).resolve().parents[1]
CONFIG = LAB / "config" / "exp_2b_path_story_pilot_v3.json"
TASK = LAB / "config" / "agent_2b_task.json"
FIXTURE = LAB / "config" / "exp_2b_path_story_v1.json"
MATRIX_CONFIG = LAB / "config" / "exp_2b_path_story_matrix_v1.json"
MATRIX_REPORT = LAB / "runs" / "path-story-matrix-v1-20261109-01" / "matrix-report.json"
BASE_COMPOSE = LAB / "compose_2b.yaml"
STORY_COMPOSE = LAB / "compose_2b_path_story.yaml"
CANDIDATE_COMPOSE = LAB / "compose_2b_path_story_pilot_v3.yaml"
RUNNER = LAB / "experiment_controller" / "run_2b_path_story_pilot_v3.py"
GATEWAY_SERVER = LAB / "model_gateway" / "server_path_story_v2.py"
GATEWAY_DOCKERFILE = LAB / "model_gateway" / "Dockerfile_path_story_v2"
REPORTS = LAB / "runs"
PROTOCOL = "2b-path-story-pilot-v3-candidate"
GATEWAY_IMAGE = "shape-model-gateway:path-story-v2"
SOURCE_FILES = {
    "candidate_controller": Path(__file__),
    "candidate_contract": CONFIG,
    "candidate_runner": RUNNER,
    "candidate_compose": CANDIDATE_COMPOSE,
    "gateway_server": GATEWAY_SERVER,
    "gateway_dockerfile": GATEWAY_DOCKERFILE,
    "base_compose": BASE_COMPOSE,
    "story_compose": STORY_COMPOSE,
    "gateway_base": LAB / "model_gateway" / "server.py",
    "gateway_path_story_v1": LAB / "model_gateway" / "server_path_story.py",
    "provider_cost": LAB / "experiment_controller" / "provider_cost_2b.py",
    "path_story_decoy": LAB / "filesystem_decoy_2b" / "path_story_fs.py",
    "path_story_replay": LAB / "telemetry" / "replay_2b_path_story.py",
}


class CandidateIntegrityError(RuntimeError):
    """Prospective evidence or frozen v2 context differs."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expected_prior_context() -> dict[str, Any]:
    status = closeout.status()
    if (
        status.get("phase") != "paused_repeated_gateway_closeout"
        or status.get("execution_available") is not False
        or status.get("completed_slots") != [1, 2, 3]
        or status.get("next_slot") != 4
        or status.get("schedule_sha256") != closeout.SCHEDULE_SHA256
        or status.get("funding", {}).get("authorized_usd") != "100.000000000"
        or status["funding"].get("accrued_usd") != "46.339601000"
        or status["funding"].get("remaining_usd") != "53.660399000"
        or status["funding"].get("may_start_new_run") is not False
    ):
        raise CandidateIntegrityError("Paused v2 closeout state differs")
    return {
        "pilot_id": closeout.PILOT_ID,
        "schedule_sha256": closeout.SCHEDULE_SHA256,
        "slot3_reconciliation_sha256": _sha(closeout.slot3.RECONCILIATION),
        "slot4_reconciliation_sha256": _sha(closeout.RECONCILIATION),
        "accrued_usd": status["funding"]["accrued_usd"],
        "remaining_authorization_usd": status["funding"]["remaining_usd"],
        "authorization_transfer": "not_performed",
    }


def load_contract() -> dict[str, Any]:
    raw = json.loads(CONFIG.read_text(encoding="utf-8"))
    if (
        not isinstance(raw, dict)
        or raw.get("schema_version") != 1
        or raw.get("pilot_protocol") != PROTOCOL
        or raw.get("future_pilot_protocol") != "2b-path-story-pilot-v3"
        or raw.get("environment_protocol") != "filesystem-path-story-v1"
        or raw.get("contract_kind") != "prospective_gateway_closeout_candidate"
        or raw.get("status") != "model_free_validation_only_no_enrollment"
        or raw.get("task_path") != "config/agent_2b_task.json"
        or raw.get("task_sha256") != _sha(TASK)
        or raw.get("fixture_path") != "config/exp_2b_path_story_v1.json"
        or raw.get("fixture_sha256") != _sha(FIXTURE)
        or raw.get("target") != "ssh://lab@filesystem-decoy-2b"
        or raw.get("provider") != "ollama"
        or raw.get("model") != "glm-5.3"
        or raw.get("reinforcement_every") != 3
        or raw.get("block_seeds") != {
            "1": "path-story-pilot-v1-block-01",
            "2": "path-story-pilot-v1-block-02",
        }
    ):
        raise CandidateIntegrityError("Prospective candidate or unchanged task differs")
    if raw.get("prior_v2_closeout_context") != _expected_prior_context():
        raise CandidateIntegrityError("Candidate does not bind the paused v2 closeout")
    prior_contract = prior_pilot.load_contract()
    for key in (
        "agent", "trial_caps", "post_run_settlement", "runtime_policy",
        "attempt_bounds", "model_free_gate",
    ):
        if raw.get(key) != prior_contract[key]:
            raise CandidateIntegrityError(f"Candidate {key} differs from validated v2")
    if (
        raw.get("factorial_arms") != prior_contract["design"]["arms"]
        or raw.get("provider_cost_governance", {}).get("rate_card")
        != prior_contract["provider_cost_governance"]["rate_card"]
    ):
        raise CandidateIntegrityError("Candidate factors or rate card differ")
    matrix = raw.get("model_free_gate", {})
    if (
        matrix.get("matrix_config_sha256") != _sha(MATRIX_CONFIG)
        or matrix.get("matrix_report_sha256") != _sha(MATRIX_REPORT)
        or raw.get("catalog_fingerprint")
        != load_path_story_fixture(FIXTURE, raw["block_seeds"]["1"], True)[1].catalog.fingerprint
    ):
        raise CandidateIntegrityError("Candidate model-free decoy gate differs")
    expected_lifecycle = {
        "provider_response_complete_event": "provider_response_complete",
        "provider_response_complete_after_full_upstream_read": True,
        "downstream_delivery_failed_event": "downstream_delivery_failed",
        "downstream_send_must_be_bounded": True,
        "cost_complete_requires_matching_provider_usage": True,
        "unaccounted_or_aborted_provider_requests_pause": True,
        "behavioral_validity_rule": "not_frozen",
    }
    if raw.get("gateway_lifecycle_candidate") != expected_lifecycle:
        raise CandidateIntegrityError("Prospective gateway lifecycle differs")
    if raw.get("provider_cost_governance", {}).get("candidate_only") is not True or raw[
        "provider_cost_governance"
    ].get("new_authorization_opened") is not False or raw["provider_cost_governance"].get(
        "v2_authorization_transfer_performed"
    ) is not False:
        raise CandidateIntegrityError("Prospective funding remains uncommitted")
    if raw.get("model_free_preflight") != {
        "arms": ["B0", "B3"],
        "dummy_key_only": True,
        "start_attacker_agent": False,
        "make_model_calls": False,
    } or raw.get("execution") != {
        "schedule_freeze_available": False,
        "cohort_enrollment_decision": "deferred",
        "provider_authorization_available": False,
        "model_runs_allowed": False,
    }:
        raise CandidateIntegrityError("Prospective execution gate differs")
    if any(prior_pilot.STUDIES.glob("2b-path-story-pilot-v3-*/schedule.json")):
        raise CandidateIntegrityError("A v3 schedule was unexpectedly frozen")
    return raw


def check() -> dict[str, Any]:
    """Read-only candidate and historical-evidence validation."""
    contract = load_contract()
    missing = [name for name, path in SOURCE_FILES.items() if not path.is_file()]
    if missing:
        raise CandidateIntegrityError(f"Prospective source is missing: {missing}")
    return {
        "candidate_protocol": PROTOCOL,
        "contract_sha256": _sha(CONFIG),
        "source_sha256": {name: _sha(path) for name, path in SOURCE_FILES.items()},
        "task_sha256": contract["task_sha256"],
        "fixture_sha256": contract["fixture_sha256"],
        "prior_v2_closeout_context": contract["prior_v2_closeout_context"],
        "schedule_frozen": False,
        "authorization_transferred": False,
        "model_calls": 0,
    }


def docker_check() -> dict[str, Any]:
    """Build the successor gateway and run dummy-key Docker preflights only."""
    contract = load_contract()
    before = check()
    build = subprocess.run(
        [
            "docker", "compose", "--profile", "agent",
            "-f", str(BASE_COMPOSE), "-f", str(STORY_COMPOSE),
            "-f", str(CANDIDATE_COMPOSE), "build", "model-gateway",
        ],
        cwd=LAB, capture_output=True, timeout=1200,
    )
    if build.returncode:
        raise CandidateIntegrityError(
            "Candidate gateway build failed: "
            + build.stderr[-2000:].decode("utf-8", "replace")
        )
    from experiment_controller.run_2b_path_story_pilot_v3 import preflight_no_model

    preflights = [
        preflight_no_model(contract=contract, seed=contract["block_seeds"]["1"], arm="B0"),
        preflight_no_model(contract=contract, seed=contract["block_seeds"]["2"], arm="B3"),
    ]
    if any(
        row.get("status") != "passed"
        or row.get("model_calls") != 0
        or row.get("agent_started") is not False
        for row in preflights
    ):
        raise CandidateIntegrityError("Candidate dummy-key preflight failed")
    after = check()
    if after != before:
        raise CandidateIntegrityError("Prospective source changed during Docker check")
    now = datetime.now(timezone.utc)
    report_id = "path-story-v3-candidate-" + now.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    folder = REPORTS / report_id
    folder.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {
        **after,
        "report_id": report_id,
        "created_utc": now.isoformat(),
        "gateway_image_tag": GATEWAY_IMAGE,
        "gateway_image_id": subprocess.run(
            ["docker", "image", "inspect", GATEWAY_IMAGE, "--format", "{{.Id}}"],
            cwd=LAB, check=True, capture_output=True, timeout=30,
        ).stdout.decode("utf-8", "strict").strip(),
        "preflights": preflights,
        "schedule_frozen": False,
        "authorization_transferred": False,
        "model_calls": 0,
    }
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (folder / "report.json").write_bytes(raw)
    (folder / "report.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="utf-8")
    (folder / "build.log").write_bytes(build.stdout + build.stderr)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("check")
    actions.add_parser("docker-check")
    args = parser.parse_args()
    value = check() if args.action == "check" else docker_check()
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
