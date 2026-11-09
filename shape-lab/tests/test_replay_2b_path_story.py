"""Model-free byte replay and tamper checks for successor path-story evidence."""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import posixpath
import tempfile
import unittest

from experiment_controller.path_story_evidence_2b import (
    EVIDENCE_VERSION,
    TARGET,
    _expected_resource_policy,
    archive_path_story_run,
)
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server import ARMS
from filesystem_decoy_2b.server_path_story import StorySession
from telemetry.replay_2b_path_story import (
    verify_path_story_bundle,
    verify_path_story_pair,
)


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"
SEED = "path-story-replay-seed"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def journal(arm: str, run_id: str, commands: list[str], *, seed: str = SEED) -> list[str]:
    raw, fs = load_path_story_fixture(FIXTURE, seed, ARMS[arm][0])
    session = StorySession(fs)
    rows = []
    command_count = 0
    qualifying_count = 0

    def emit(kind: str, **fields: object) -> int:
        sequence = len(rows) + 1
        rows.append(
            {
                "run_id": run_id,
                "experiment": "2B",
                "condition": arm,
                "timestamp_utc": "2026-11-09T00:00:00Z",
                "elapsed_ms": sequence,
                "source": "filesystem-decoy-2b",
                "sequence": sequence,
                "event_type": kind,
                **fields,
            }
        )
        return sequence

    emit(
        "path_story_profile_loaded",
        evidence_version=EVIDENCE_VERSION,
        **fs.profile_evidence(),
        identity={"username": fs.spec.username, "hostname": fs.spec.hostname},
        resource_policy=_expected_resource_policy(fs, 50, 3),
    )
    connect_request = canonical({"target": TARGET})
    emit(
        "decoy_request",
        route="/connect",
        content_length=len(connect_request),
        request_body_b64=base64.b64encode(connect_request).decode(),
    )
    banner = session.connect()
    connect = {
        "output": banner,
        "cwd": session.cwd,
        "connected": True,
        "new_connection": True,
        "identity": {"username": fs.spec.username, "hostname": fs.spec.hostname},
    }
    body = canonical(connect)
    emit(
        "decoy_response",
        route="/connect",
        status=200,
        body_sha256=sha(body),
        body_b64=base64.b64encode(body).decode(),
    )
    emit("ssh_connected", target=TARGET, cwd=session.cwd)
    for command in commands:
        request = canonical({"command": command})
        emit(
            "decoy_request",
            route="/exec",
            content_length=len(request),
            request_body_b64=base64.b64encode(request).decode(),
        )
        fs.begin_materialization_capture()
        result = session.execute(command)
        command_count += 1
        output = result.output
        reinforced = False
        if result.exit_code == 0 and result.action in {"ls", "cat", "head"}:
            qualifying_count += 1
            if ARMS[arm][1] and qualifying_count % 3 == 0:
                note = (
                    ("\n" if output and not output.endswith("\n") else "")
                    + raw["reinforcement_text"]
                    + "\n"
                )
                if len(output) + len(note) <= fs.max_output_chars:
                    output += note
                    reinforced = True
        response = {
            "output": output,
            "exit_code": result.exit_code,
            "action": result.action,
            "target": result.target,
            "cwd_before": result.cwd_before,
            "cwd_after": result.cwd_after,
            "truncated": result.truncated,
            "reinforcement_delivered": reinforced,
            "identity": {"username": fs.spec.username, "hostname": fs.spec.hostname},
        }
        body = canonical(response)
        response_hash = sha(body)
        response_sequence = emit(
            "decoy_response",
            route="/exec",
            status=200,
            body_sha256=response_hash,
            body_b64=base64.b64encode(body).decode(),
        )
        for item in fs.commit_materialization_capture(
            response_sequence=response_sequence, response_sha256=response_hash
        ):
            emit("filesystem_materialized", evidence_version=EVIDENCE_VERSION, **item)
        emit(
            "filesystem_interaction",
            command=command,
            action=response["action"],
            target=response["target"],
            cwd_before=response["cwd_before"],
            cwd_after=response["cwd_after"],
            exit_code=response["exit_code"],
            truncated=response["truncated"],
        )
        if reinforced:
            emit(
                "reinforcement_delivered",
                command_count=command_count,
                response_sha256=sha(output.encode()),
            )
    return [json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows]


def make_bundle(
    root: Path, arm: str, commands: list[str], *, seed: str = SEED
) -> Path:
    run_id = f"replay-{arm.lower()}-{len(commands)}"
    run_dir = root / run_id
    archive_path_story_run(
        run_dir,
        fixture_path=FIXTURE,
        seed=seed,
        arm=arm,
        run_id=run_id,
        event_lines=journal(arm, run_id, commands, seed=seed),
    )
    return run_dir


def rewrite_archive(run_dir: Path, mutator) -> None:
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    event_path = run_dir / "decoy-events.jsonl"
    events = [json.loads(line) for line in event_path.read_text().splitlines()]
    inventory_path = run_dir / "materialization-inventory.json"
    inventory = json.loads(inventory_path.read_text())
    mutator(events, inventory)
    event_path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in events))
    inventory_path.write_text(json.dumps(inventory, sort_keys=True) + "\n")
    manifest["event_count"] = len(events)
    manifest["response_count"] = sum(row["event_type"] == "decoy_response" for row in events)
    manifest["materialization_count"] = len(inventory["items"])
    for path in (event_path, inventory_path):
        manifest["artifact_sha256"][path.name] = sha(path.read_bytes())
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")


class PathStoryReplayTests(unittest.TestCase):
    def test_replays_static_dynamic_and_common_prefix(self) -> None:
        common = ["pwd", "ls /", "ls /home/lab"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            static = make_bundle(root, "B0", common + ["ls /srv/ledger-api/releases"])
            dynamic = make_bundle(root, "B1", common + ["ls /srv/ledger-api/releases"])
            left = verify_path_story_bundle(static)
            right = verify_path_story_bundle(dynamic)
            self.assertEqual(left["materialized_nodes"], 0)
            self.assertGreater(right["materialized_nodes"], 0)
            pair = verify_path_story_pair(static, dynamic, common)
            self.assertEqual(pair["common_commands"], common)

    def test_replays_reinforcement_arm_and_repeated_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = make_bundle(
                Path(temporary),
                "B3",
                ["ls /", "ls /home/lab", "ls /srv/ledger-api/releases", "ls /srv/ledger-api/releases"],
            )
            result = verify_path_story_bundle(path)
            self.assertGreater(result["materialized_nodes"], 0)
            events = [json.loads(line) for line in (path / "decoy-events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(row["event_type"] == "reinforcement_delivered" for row in events), 1)

    def test_reinforced_text_arm_pair_has_identical_common_prefix(self) -> None:
        common = ["ls /", "ls /home/lab", "cat /home/lab/README.md"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            static = make_bundle(root, "B2", common + ["ls /var/backups/ledger"])
            dynamic = make_bundle(root, "B3", common + ["ls /var/backups/ledger"])
            self.assertEqual(
                verify_path_story_pair(static, dynamic, common)["common_commands"],
                common,
            )
            for run_dir in (static, dynamic):
                events = [json.loads(line) for line in (run_dir / "decoy-events.jsonl").read_text().splitlines()]
                self.assertTrue(any(row["event_type"] == "reinforcement_delivered" for row in events))

    def test_tampered_name_metadata_identity_and_response_are_rejected(self) -> None:
        root_path = "/srv/ledger-api/releases"
        _, fs = load_path_story_fixture(FIXTURE, SEED, True)
        generated = next(
            posixpath.join(root_path, name)
            for name in fs.children(root_path)
            if posixpath.join(root_path, name) not in fs.spec.nodes
        )
        commands = [f"ls {root_path}", f"cat {generated}" if fs.kind(generated) == "file" else f"stat {generated}"]

        def name(events, inventory):
            row = next(row for row in events if row["event_type"] == "filesystem_materialized")
            row["path"] = root_path + "/forged-name"
            inventory["items"][0]["path"] = row["path"]

        def metadata(events, inventory):
            row = next(row for row in events if row["event_type"] == "filesystem_materialized")
            row["node_sha256"] = "0" * 64
            inventory["items"][0]["node_sha256"] = row["node_sha256"]

        def identity(events, inventory):
            row = next(row for row in events if row["event_type"] == "decoy_response")
            body = json.loads(base64.b64decode(row["body_b64"]))
            body["identity"]["hostname"] = "forged-host"
            raw = canonical(body)
            row["body_b64"] = base64.b64encode(raw).decode()
            row["body_sha256"] = sha(raw)

        def content(events, inventory):
            row = next(row for row in events if row["event_type"] == "decoy_response" and row["route"] == "/exec")
            body = json.loads(base64.b64decode(row["body_b64"]))
            body["output"] = "forged content\n"
            raw = canonical(body)
            old_hash = row["body_sha256"]
            row["body_b64"] = base64.b64encode(raw).decode()
            row["body_sha256"] = sha(raw)
            for item in events:
                if item["event_type"] == "filesystem_materialized" and item["response_sha256"] == old_hash:
                    item["response_sha256"] = row["body_sha256"]
            for item in inventory["items"]:
                if item["response_sha256"] == old_hash:
                    item["response_sha256"] = row["body_sha256"]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, mutate in enumerate((name, metadata, identity, content)):
                with self.subTest(tamper=index):
                    path = make_bundle(root / str(index), "B1", commands)
                    rewrite_archive(path, mutate)
                    with self.assertRaises(ValueError):
                        verify_path_story_bundle(path)

    def test_missing_materialization_is_rejected_after_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = make_bundle(Path(temporary), "B1", ["ls /srv/ledger-api/releases"])

            def remove(events, inventory):
                last = max(index for index, row in enumerate(events) if row["event_type"] == "filesystem_materialized")
                events.pop(last)
                inventory["items"].pop()
                for sequence, row in enumerate(events, 1):
                    row["sequence"] = sequence

            rewrite_archive(path, remove)
            with self.assertRaisesRegex(ValueError, "materialization event is missing"):
                verify_path_story_bundle(path)


if __name__ == "__main__":
    unittest.main()
