"""Model-free checks for the separate Z.ai path-story pilot candidate.

The candidate has no schedule or execution command. It does not transfer the
Ollama dollar authorization or infer the subscriber's live Coding Plan balance.
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

from experiment_controller import path_story_pilot_2b_v3 as gateway_candidate
from experiment_controller.run_2a import read_key
from model_gateway.providers import provider_spec


LAB = Path(__file__).resolve().parents[1]
CONTRACT = LAB / "config" / "exp_2b_path_story_pilot_v3_zai.json"
TASK = LAB / "config" / "agent_2b_task.json"
FIXTURE = LAB / "config" / "exp_2b_path_story_v1.json"
BASE_COMPOSE = LAB / "compose_2b.yaml"
STORY_COMPOSE = LAB / "compose_2b_path_story.yaml"
ZAI_COMPOSE = LAB / "compose_2b_path_story_pilot_zai.yaml"
RUNNER = LAB / "experiment_controller" / "run_2b_path_story_pilot_zai.py"
CREDITS = LAB / "experiment_controller" / "zai_coding_credits_2b.py"
REPORTS = LAB / "runs"
PROTOCOL = "2b-path-story-pilot-v3-zai-candidate"
SOURCE_FILES = {
    "candidate_controller": Path(__file__),
    "candidate_contract": CONTRACT,
    "candidate_runner": RUNNER,
    "credit_estimator": CREDITS,
    "candidate_compose": ZAI_COMPOSE,
    "gateway_server": gateway_candidate.GATEWAY_SERVER,
    "gateway_dockerfile": gateway_candidate.GATEWAY_DOCKERFILE,
    "provider_allowlist": LAB / "model_gateway" / "providers.py",
    "base_compose": BASE_COMPOSE,
    "story_compose": STORY_COMPOSE,
    "task": TASK,
    "fixture": FIXTURE,
}


class CandidateIntegrityError(RuntimeError):
    """Z.ai candidate differs from validated frozen context."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_contract() -> dict[str, Any]:
    source = gateway_candidate.load_contract()
    raw = json.loads(CONTRACT.read_text(encoding="utf-8"))
    expected = dict(source)
    expected["pilot_protocol"] = PROTOCOL
    expected["future_pilot_protocol"] = "2b-path-story-pilot-v3-zai"
    expected["contract_kind"] = "prospective_zai_coding_plan_candidate"
    expected["provider"] = "zai"
    expected.pop("provider_cost_governance")
    expected["coding_plan_credit_governance"] = {
        "rate_revision": "zai-glm-5.3-coding-plan-2026-11-09",
        "source_url": "https://docs.z.ai/devpack/overview",
        "model": "glm-5.3",
        "input_multiplier": "6.9",
        "cached_input_multiplier": "1.7",
        "output_multiplier": "24",
        "tokens_per_credit_unit": 10000,
        "off_peak_multiplier": "0.5",
        "peak_weekdays_utc": [0, 1, 2, 3, 4],
        "peak_start_hour_utc": 6,
        "peak_end_hour_utc": 10,
        "five_hour_and_weekly_limits_apply": True,
        "live_balance_source": "subscriber_console_manual_snapshot_required",
        "ollama_dollar_tranche_transfer": "not_applicable",
        "estimate_is_provider_bill": False,
        "active_run_credit_termination_allowed": False,
    }
    expected["execution"] = {
        "schedule_freeze_available": False,
        "cohort_enrollment_decision": "deferred_fresh_eight_preferred",
        "live_credit_balance_verified": False,
        "model_runs_allowed": False,
    }
    if raw != expected:
        raise CandidateIntegrityError("Z.ai candidate contract or unchanged task differs")
    if provider_spec("zai") != {
        "host": "api.z.ai", "prefix": "/api/anthropic", "key_name": "ZAI_API_KEY"
    }:
        raise CandidateIntegrityError("Z.ai gateway route differs")
    return raw


def check() -> dict[str, Any]:
    raw = load_contract()
    missing = [name for name, path in SOURCE_FILES.items() if not path.is_file()]
    if missing:
        raise CandidateIntegrityError(f"Z.ai source is missing: {missing}")
    return {
        "candidate_protocol": PROTOCOL,
        "contract_sha256": _sha(CONTRACT),
        "source_sha256": {name: _sha(path) for name, path in SOURCE_FILES.items()},
        "task_sha256": raw["task_sha256"],
        "fixture_sha256": raw["fixture_sha256"],
        "prior_v2_closeout_context": raw["prior_v2_closeout_context"],
        "gateway_candidate_protocol": gateway_candidate.PROTOCOL,
        "zai_key_present": bool(read_key("zai")),
        "live_plan_balance_known": False,
        "schedule_frozen": False,
        "model_runs_allowed": False,
    }


def docker_check() -> dict[str, Any]:
    """Check Z.ai provider wiring with a dummy key and no model calls."""
    raw = load_contract()
    before = check()
    build = subprocess.run(
        ["docker", "compose", "--profile", "agent",
         "-f", str(BASE_COMPOSE), "-f", str(STORY_COMPOSE),
         "-f", str(ZAI_COMPOSE), "build", "model-gateway"],
        cwd=LAB, capture_output=True, timeout=1200,
    )
    if build.returncode:
        raise CandidateIntegrityError(
            "Z.ai gateway build failed: " + build.stderr[-2000:].decode("utf-8", "replace")
        )
    from experiment_controller.run_2b_path_story_pilot_zai import preflight_no_model

    preflights = [
        preflight_no_model(contract=raw, seed=raw["block_seeds"]["1"], arm="B0"),
        preflight_no_model(contract=raw, seed=raw["block_seeds"]["2"], arm="B3"),
    ]
    if any(
        row.get("status") != "passed" or row.get("model_calls") != 0
        or row.get("agent_started") is not False
        for row in preflights
    ):
        raise CandidateIntegrityError("Z.ai dummy-key preflight failed")
    after = check()
    if after != before:
        raise CandidateIntegrityError("Candidate changed during Docker preflight")
    now = datetime.now(timezone.utc)
    report_id = "path-story-zai-candidate-" + now.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    folder = REPORTS / report_id
    folder.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {
        **after,
        "report_id": report_id,
        "created_utc": now.isoformat(),
        "preflights": preflights,
        "model_calls": 0,
    }
    content = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    (folder / "report.json").write_bytes(content)
    (folder / "report.sha256").write_text(hashlib.sha256(content).hexdigest() + "\n")
    (folder / "build.log").write_bytes(build.stdout + build.stderr)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "docker-check"))
    args = parser.parse_args()
    value = check() if args.action == "check" else docker_check()
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
