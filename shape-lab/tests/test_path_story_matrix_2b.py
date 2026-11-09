"""Model-free checks of the frozen Docker matrix's observation gate."""

from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from experiment_controller.path_story_matrix_2b import (
    _prompt,
    _response_pairs,
    load_matrix_config,
    validate_tool_observation,
)
from test_replay_2b_path_story import journal


CONFIG = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_matrix_v1.json"


def _observation(arm: str, config: dict) -> tuple[bytes, dict]:
    run_id = f"matrix-unit-{arm.lower()}"
    lines = journal(arm, run_id, config["command_plan"], seed=config["seed"])
    pairs = _response_pairs([json.loads(line) for line in lines])
    bodies = [json.loads(base64.b64decode(response["body_b64"])) for _, response in pairs]
    report = {
        "status": "complete",
        "completed_actions": 50,
        "run_id": run_id,
        "arm": arm,
        "target": config["target"],
        "registry_spec": "ssh_tools_2b_path_story:REGISTRY",
        "connection": {
            "tool": "ssh_connect",
            "arguments": {"target": config["target"]},
            "response": bodies[0]["output"] + _prompt(bodies[0], "cwd"),
        },
        "actions": [],
    }
    for index, body in enumerate(bodies[1:], 1):
        response = body["output"]
        if body["exit_code"]:
            response += f"[exit code {body['exit_code']}]\n"
        response += _prompt(body, "cwd_after")
        report["actions"].append(
            {
                "sequence": index,
                "tool": "ssh_exec",
                "arguments": {"command": config["command_plan"][index - 1]},
                "response": response,
            }
        )
    return "".join(lines).encode(), report


class PathStoryMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_matrix_config(CONFIG)

    def test_frozen_fifty_action_plan_observes_all_four_arms(self) -> None:
        for arm in ("B0", "B1", "B2", "B3"):
            with self.subTest(arm=arm):
                events, report = _observation(arm, self.config)
                result = validate_tool_observation(
                    events, report, self.config, arm=arm, run_id=report["run_id"]
                )
                self.assertEqual(result["actions"], 50)
                if arm in {"B0", "B2"}:
                    self.assertEqual(result["materialized_nodes"], 0)
                else:
                    self.assertGreater(result["new_nodes_at_action_50"], 0)
                if arm in {"B2", "B3"}:
                    self.assertGreater(result["reinforcement_events"], 0)

    def test_changed_attacker_image_tool_output_is_rejected(self) -> None:
        events, report = _observation("B1", self.config)
        report = deepcopy(report)
        report["actions"][22]["response"] += "altered"
        with self.assertRaisesRegex(ValueError, "tool output differs at action 23"):
            validate_tool_observation(
                events, report, self.config, arm="B1", run_id=report["run_id"]
            )

    def test_missing_action_fifty_frontier_is_rejected(self) -> None:
        events, report = _observation("B1", self.config)
        rows = [json.loads(line) for line in events.splitlines()]
        last_response = [
            row for row in rows
            if row["event_type"] == "decoy_response" and row["route"] == "/exec"
        ][-1]["sequence"]
        rows = [
            row for row in rows
            if not (
                row["event_type"] == "filesystem_materialized"
                and row["response_sequence"] == last_response
            )
        ]
        changed = b"".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            for row in rows
        )
        with self.assertRaisesRegex(ValueError, "fresh structure at action 50"):
            validate_tool_observation(
                changed, report, self.config, arm="B1", run_id=report["run_id"]
            )

    def test_frozen_fixture_commitment_is_checked_before_docker(self) -> None:
        altered = deepcopy(self.config)
        altered["fixture_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "matrix.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Frozen fixture hash differs"):
                load_matrix_config(path)


if __name__ == "__main__":
    unittest.main()
