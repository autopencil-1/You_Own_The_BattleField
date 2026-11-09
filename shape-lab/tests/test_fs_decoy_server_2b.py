"""Model-free checks for the imitated SSH transport and event chronology."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import threading
import unittest

from filesystem_decoy_2b.server import DecoyServer
from filesystem_decoy_2b.virtual_fs import FilesystemSpec, Session, VirtualFilesystem


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_engine_fixture.json"
TARGET = "ssh://lab@filesystem-decoy-2b"


class LiveDecoy:
    def __init__(
        self, arm: str, *, every: int = 3, max_commands: int = 50
    ) -> None:
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.events = io.StringIO()
        self.server = DecoyServer(
            ("127.0.0.1", 0),
            run_id="2b-unit",
            arm=arm,
            target=TARGET,
            session=Session(
                VirtualFilesystem(
                    FilesystemSpec.from_dict(raw),
                    "fixed-seed",
                    dynamic=arm in {"B1", "B3"},
                )
            ),
            reinforcement_text=raw["reinforcement_text"],
            reinforcement_every=every,
            max_commands=max_commands,
            event_stream=self.events,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def post(self, route: str, payload: dict) -> tuple[int, dict]:
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(
                "POST",
                route,
                body=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def journal(self) -> list[dict]:
        self.post("/exec", {"command": "pwd"})  # Serializes behind earlier responses.
        return [json.loads(line) for line in self.events.getvalue().splitlines()]


class ServerTests(unittest.TestCase):
    def test_arm_cannot_select_the_wrong_structure(self) -> None:
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        session = Session(
            VirtualFilesystem(
                FilesystemSpec.from_dict(raw), "fixed-seed", dynamic=False
            )
        )
        with self.assertRaisesRegex(ValueError, "assigned arm"):
            DecoyServer(
                ("127.0.0.1", 0),
                run_id="2b-unit",
                arm="B1",
                target=TARGET,
                session=session,
                reinforcement_text=raw["reinforcement_text"],
            )

    def test_connection_is_required_and_cwd_persists(self) -> None:
        decoy = LiveDecoy("B0")
        try:
            self.assertEqual(decoy.post("/exec", {"command": "pwd"})[0], 409)
            self.assertEqual(decoy.post("/connect", {"target": "ssh://other"})[0], 400)
            status, connected = decoy.post("/connect", {"target": TARGET})
            self.assertEqual(status, 200)
            self.assertTrue(connected["new_connection"])
            self.assertEqual(
                decoy.post("/exec", {"command": "cd /var/backups/ledger"})[1][
                    "cwd_after"
                ],
                "/var/backups/ledger",
            )
            self.assertEqual(
                decoy.post("/exec", {"command": "pwd"})[1]["output"],
                "/var/backups/ledger\n",
            )
            events = decoy.journal()
            profile = [
                event
                for event in events
                if event["event_type"] == "filesystem_profile_loaded"
            ]
            self.assertEqual(len(profile), 1)
            self.assertEqual(profile[0]["filesystem_schema_version"], 2)
            self.assertEqual(profile[0]["visible_compiled_node_count"], 0)
            self.assertEqual(sum(e["event_type"] == "ssh_connected" for e in events), 1)
            self.assertEqual(
                [e["sequence"] for e in events], list(range(1, len(events) + 1))
            )
            for event in events:
                if event["event_type"] == "decoy_response":
                    body = base64.b64decode(event["body_b64"], validate=True)
                    self.assertEqual(
                        hashlib.sha256(body).hexdigest(), event["body_sha256"]
                    )
        finally:
            decoy.close()

    def test_structure_and_reinforcement_are_independent(self) -> None:
        decoys = {arm: LiveDecoy(arm, every=1) for arm in ("B0", "B1", "B2", "B3")}
        try:
            for decoy in decoys.values():
                self.assertEqual(decoy.post("/connect", {"target": TARGET})[0], 200)
            root = {
                arm: decoy.post("/exec", {"command": "ls /"})[1]
                for arm, decoy in decoys.items()
            }
            self.assertEqual(root["B0"]["output"], root["B1"]["output"])
            self.assertEqual(root["B2"]["output"], root["B3"]["output"])
            self.assertEqual(root["B0"]["reinforcement_delivered"], False)
            self.assertEqual(root["B2"]["reinforcement_delivered"], True)
            deeper = {
                arm: decoy.post("/exec", {"command": "ls /var/backups/ledger"})[1]
                for arm, decoy in decoys.items()
            }
            self.assertEqual(deeper["B0"]["output"], "RESTORE.md\n")
            self.assertEqual(deeper["B1"]["reinforcement_delivered"], False)
            self.assertNotEqual(deeper["B1"]["output"], "RESTORE.md\n")
            self.assertTrue(deeper["B2"]["reinforcement_delivered"])
            self.assertTrue(deeper["B3"]["reinforcement_delivered"])
            profiles = {
                arm: next(
                    event
                    for event in decoy.journal()
                    if event["event_type"] == "filesystem_profile_loaded"
                )
                for arm, decoy in decoys.items()
            }
            self.assertEqual(
                {item["compiled_graph_fingerprint"] for item in profiles.values()},
                {profiles["B0"]["compiled_graph_fingerprint"]},
            )
            self.assertEqual(
                {item["shared_nodes_fingerprint"] for item in profiles.values()},
                {profiles["B0"]["shared_nodes_fingerprint"]},
            )
            self.assertEqual(profiles["B0"]["visible_compiled_node_count"], 0)
            self.assertGreater(profiles["B1"]["visible_compiled_node_count"], 0)
        finally:
            for decoy in decoys.values():
                decoy.close()

    def test_command_cap_is_atomic_under_parallel_requests(self) -> None:
        decoy = LiveDecoy("B0", max_commands=3)
        try:
            self.assertEqual(decoy.post("/connect", {"target": TARGET})[0], 200)
            with ThreadPoolExecutor(max_workers=12) as executor:
                results = list(
                    executor.map(
                        lambda _index: decoy.post("/exec", {"command": "pwd"}),
                        range(12),
                    )
                )
            statuses = [status for status, _body in results]
            self.assertEqual(statuses.count(200), 3)
            self.assertEqual(statuses.count(429), 9)
            self.assertTrue(
                all(
                    body == {"error": "command_cap_reached"}
                    for status, body in results
                    if status == 429
                )
            )
            events = decoy.journal()
            self.assertEqual(
                sum(
                    event["event_type"] == "filesystem_interaction"
                    for event in events
                ),
                3,
            )
        finally:
            decoy.close()


if __name__ == "__main__":
    unittest.main()
