"""Model-free checks for the separate path-story archive contract."""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from experiment_controller.path_story_evidence_2b import (
    EVIDENCE_VERSION,
    SOURCE_FILES,
    TASK,
    TARGET,
    _expected_resource_policy,
    archive_path_story_run,
)
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server_path_story import StorySession


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"
SEED = "archive-test-seed"
RUN_ID = "2b-story-evidence-unit"


def synthetic_events() -> tuple[list[dict], str]:
    _, fs = load_path_story_fixture(FIXTURE, SEED, dynamic=True)
    root = "/srv/ledger-api/releases"
    session = StorySession(fs)
    banner = session.connect()
    command = f"ls {root}"
    fs.begin_materialization_capture()
    result = session.execute(command)
    self_identity = {"username": "lab", "hostname": "ledger-prod-01"}
    connect_body = json.dumps(
        {
            "output": banner,
            "cwd": session.cwd,
            "connected": True,
            "new_connection": True,
            "identity": self_identity,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    connect_hash = hashlib.sha256(connect_body).hexdigest()
    exec_body = json.dumps(
        {
            "output": result.output,
            "action": result.action,
            "target": result.target,
            "cwd_before": result.cwd_before,
            "cwd_after": result.cwd_after,
            "exit_code": result.exit_code,
            "truncated": result.truncated,
            "reinforcement_delivered": False,
            "identity": self_identity,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    exec_hash = hashlib.sha256(exec_body).hexdigest()
    committed = fs.commit_materialization_capture(
        response_sequence=6, response_sha256=exec_hash
    )
    if not committed:
        raise AssertionError("Fixture must expose generated nodes in the listing")
    generated = committed[0]["path"]
    connect_request = json.dumps({"target": TARGET}, separators=(",", ":")).encode()
    exec_request = json.dumps({"command": command}, separators=(",", ":")).encode()
    common = {"run_id": RUN_ID, "experiment": "2B", "condition": "B1"}
    rows = [
        {
            **common,
            "sequence": 1,
            "event_type": "path_story_profile_loaded",
            "evidence_version": EVIDENCE_VERSION,
            **fs.profile_evidence(),
            "identity": self_identity,
            "resource_policy": _expected_resource_policy(fs, 50, 3),
        },
        {
            **common,
            "sequence": 2,
            "event_type": "decoy_request",
            "route": "/connect",
            "content_length": len(connect_request),
            "request_body_b64": base64.b64encode(connect_request).decode(),
        },
        {
            **common,
            "sequence": 3,
            "event_type": "decoy_response",
            "route": "/connect",
            "status": 200,
            "body_sha256": connect_hash,
            "body_b64": base64.b64encode(connect_body).decode(),
        },
        {
            **common,
            "sequence": 4,
            "event_type": "ssh_connected",
            "target": TARGET,
            "cwd": "/home/lab",
        },
        {
            **common,
            "sequence": 5,
            "event_type": "decoy_request",
            "route": "/exec",
            "content_length": len(exec_request),
            "request_body_b64": base64.b64encode(exec_request).decode(),
        },
        {
            **common,
            "sequence": 6,
            "event_type": "decoy_response",
            "route": "/exec",
            "status": 200,
            "body_sha256": exec_hash,
            "body_b64": base64.b64encode(exec_body).decode(),
        },
    ]
    for item in committed:
        rows.append(
            {
                **common,
                "sequence": len(rows) + 1,
                "event_type": "filesystem_materialized",
                "evidence_version": EVIDENCE_VERSION,
                **item,
            }
        )
    rows.append(
        {
            **common,
            "sequence": len(rows) + 1,
            "event_type": "filesystem_interaction",
            "command": command,
            "action": result.action,
            "target": result.target,
            "cwd_before": result.cwd_before,
            "cwd_after": result.cwd_after,
            "exit_code": result.exit_code,
            "truncated": result.truncated,
        }
    )
    return rows, generated


def lines(rows: list[dict]) -> list[str]:
    return [json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows]


class PathStoryEvidenceTests(unittest.TestCase):
    def test_archive_copies_exact_inputs_and_committed_inventory(self) -> None:
        rows, generated = synthetic_events()
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / RUN_ID
            manifest = archive_path_story_run(
                run_dir,
                fixture_path=FIXTURE,
                seed=SEED,
                arm="B1",
                run_id=RUN_ID,
                event_lines=lines(rows),
            )
            self.assertEqual(manifest["evidence_version"], EVIDENCE_VERSION)
            self.assertEqual(manifest["target"], TARGET)
            self.assertGreaterEqual(manifest["materialization_count"], 1)
            self.assertEqual((run_dir / "fixture.json").read_bytes(), FIXTURE.read_bytes())
            self.assertEqual((run_dir / "task.json").read_bytes(), TASK.read_bytes())
            self.assertEqual((run_dir / "seed.txt").read_text(), SEED + "\n")
            self.assertEqual(os.stat(run_dir / "seed.txt").st_mode & 0o777, 0o600)
            for name, source in SOURCE_FILES.items():
                self.assertEqual((run_dir / name).read_bytes(), source.read_bytes())
            inventory = json.loads((run_dir / "materialization-inventory.json").read_text())
            self.assertEqual(inventory["items"][0]["path"], generated)
            self.assertEqual(inventory["items"][0]["response_sequence"], 6)
            for name, digest in manifest["artifact_sha256"].items():
                self.assertEqual(hashlib.sha256((run_dir / name).read_bytes()).hexdigest(), digest)
            self.assertEqual(json.loads((run_dir / "manifest.json").read_text()), manifest)

    def test_archive_rejects_startup_and_order_tampering(self) -> None:
        rows, _ = synthetic_events()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            variants = []
            wrong_catalog = deepcopy(rows)
            wrong_catalog[0]["catalog_fingerprint"] = "0" * 64
            variants.append(wrong_catalog)
            missing_startup = deepcopy(rows[1:])
            for index, row in enumerate(missing_startup, 1):
                row["sequence"] = index
            variants.append(missing_startup)
            missing_materialization = deepcopy(rows)
            missing_materialization[6]["response_sequence"] = 3
            variants.append(missing_materialization)
            wrong_response_hash = deepcopy(rows)
            wrong_response_hash[5]["body_sha256"] = "0" * 64
            variants.append(wrong_response_hash)
            materialization_on_connect = deepcopy(rows)
            item = materialization_on_connect.pop(6)
            item["response_sequence"] = 3
            item["response_sha256"] = rows[2]["body_sha256"]
            materialization_on_connect.insert(3, item)
            for sequence, row in enumerate(materialization_on_connect, 1):
                row["sequence"] = sequence
            variants.append(materialization_on_connect)
            for index, variant in enumerate(variants):
                run_dir = base / f"case-{index}"
                with self.subTest(index=index), self.assertRaises(ValueError):
                    archive_path_story_run(
                        run_dir,
                        fixture_path=FIXTURE,
                        seed=SEED,
                        arm="B1",
                        run_id=RUN_ID,
                        event_lines=lines(variant),
                    )
                self.assertFalse((run_dir / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
