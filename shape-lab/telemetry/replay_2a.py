"""Recompute archived 2A scores from decoy events without calling a model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .score_2a import load_events, score_events


def verify_run(run_dir: Path) -> dict:
    recorded = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    manifest = recorded["manifest"]
    run_id = manifest["run_id"]
    if run_dir.name != run_id:
        raise ValueError("Run directory and manifest ID differ")
    stored_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    if stored_manifest != manifest:
        raise ValueError("Stored manifest and result manifest differ")
    recorded_score = recorded["score"]
    replayed = score_events(
        load_events(run_dir / "decoy-events.jsonl"),
        run_id, manifest["arm"],
        require_condition_delivery="condition_response_delivered" in recorded_score,
    )
    exact = replayed == recorded_score
    legacy_fields_match = (
        set(replayed) == set(recorded_score) | {"condition_response_delivered"}
        and replayed["condition_response_delivered"] is False
        and all(replayed[key] == value for key, value in recorded_score.items())
    )
    if not (exact or legacy_fields_match):
        raise ValueError("Archived events do not reproduce the reported score")
    return {
        "run_id": run_id,
        "arm": manifest["arm"],
        "score_reproduced": True,
        "exact_current_schema": exact,
        "activated": replayed["activated"],
        "stage1_hit": replayed["stage1_hit"],
        "stage2_hit": replayed["stage2_hit"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dirs", nargs="+", type=Path)
    args = parser.parse_args()
    for run_dir in args.run_dirs:
        print(json.dumps(verify_run(run_dir), sort_keys=True))


if __name__ == "__main__":
    main()
