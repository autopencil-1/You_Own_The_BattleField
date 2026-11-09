"""Model-free response and materialization journal checks for the successor."""

import base64
import hashlib
from http.client import HTTPConnection, RemoteDisconnected
import io
import json
from pathlib import Path
import threading
import unittest

from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server_path_story import (
    StoryDecoyServer,
    StoryHandler,
    StorySession,
)


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"
TARGET = "ssh://lab@filesystem-decoy-2b"


def _post(port: int, route: str, payload: dict) -> tuple[int, dict]:
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
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


def _events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


class PathStoryEvidenceServerTests(unittest.TestCase):
    def _serve(self, *, dynamic: bool, handler=StoryHandler):
        raw, filesystem = load_path_story_fixture(FIXTURE, "evidence-seed", dynamic)
        stream = io.StringIO()
        server = StoryDecoyServer(
            ("127.0.0.1", 0),
            run_id="2b-story-evidence-unit",
            arm="B1" if dynamic else "B0",
            target=TARGET,
            session=StorySession(filesystem),
            reinforcement_text=raw["reinforcement_text"],
            event_stream=stream,
        )
        server.RequestHandlerClass = handler
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(timeout=3))
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, filesystem, stream

    def test_committed_nodes_follow_delivered_response_once(self) -> None:
        server, filesystem, stream = self._serve(dynamic=True)
        command = "ls /srv/ledger-api/releases"
        self.assertEqual(_post(server.server_port, "/connect", {"target": TARGET})[0], 200)
        status, response = _post(server.server_port, "/exec", {"command": command})
        self.assertEqual(status, 200)
        self.assertIn("release-", response["output"])
        events = _events(stream)
        self.assertEqual(events[0]["event_type"], "path_story_profile_loaded")
        self.assertEqual(events[0]["evidence_version"], "path-story-evidence-v1")
        self.assertEqual(events[0]["identity"], {"username": "lab", "hostname": "ledger-prod-01"})
        self.assertEqual(events[0]["catalog_fingerprint"], filesystem.catalog.fingerprint)
        self.assertEqual(
            [event["sequence"] for event in events],
            list(range(1, len(events) + 1)),
        )
        request = next(
            event
            for event in events
            if event["event_type"] == "decoy_request" and event["route"] == "/exec"
        )
        self.assertEqual(
            json.loads(base64.b64decode(request["request_body_b64"])),
            {"command": command},
        )
        self.assertEqual(
            request["content_length"],
            len(base64.b64decode(request["request_body_b64"])),
        )
        response_event = next(
            event
            for event in events
            if event["event_type"] == "decoy_response" and event["route"] == "/exec"
        )
        body = base64.b64decode(response_event["body_b64"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), response_event["body_sha256"])
        self.assertEqual(json.loads(body), response)
        materialized = [
            event for event in events if event["event_type"] == "filesystem_materialized"
        ]
        self.assertTrue(materialized)
        interaction = next(
            event for event in events if event["event_type"] == "filesystem_interaction"
        )
        self.assertTrue(
            request["sequence"]
            < response_event["sequence"]
            < materialized[0]["sequence"]
            <= materialized[-1]["sequence"]
            < interaction["sequence"]
        )
        for index, event in enumerate(materialized, 1):
            self.assertEqual(event["evidence_version"], "path-story-evidence-v1")
            self.assertEqual(event["inventory_index"], index)
            self.assertEqual(event["response_sequence"], response_event["sequence"])
            self.assertEqual(event["response_sha256"], response_event["body_sha256"])
            self.assertEqual(event["node_sha256"], filesystem.node_fingerprint(event["path"]))
        self.assertEqual(
            tuple(
                {
                    key: event[key]
                    for key in (
                        "response_sequence",
                        "response_sha256",
                        "inventory_index",
                        "path",
                        "node_sha256",
                    )
                }
                for event in materialized
            ),
            filesystem.committed_inventory(),
        )
        self.assertEqual(_post(server.server_port, "/exec", {"command": command})[0], 200)
        self.assertEqual(
            len(
                [
                    event
                    for event in _events(stream)
                    if event["event_type"] == "filesystem_materialized"
                ]
            ),
            len(materialized),
        )

    def test_failed_write_discards_evidence_then_cached_retry_commits(self) -> None:
        class FailOnce(StoryHandler):
            fail_exec = True

            def _reply(self, status, payload):
                if self.path == "/exec" and type(self).fail_exec:
                    type(self).fail_exec = False
                    self.close_connection = True
                    raise BrokenPipeError("injected write failure")
                return super()._reply(status, payload)

        server, filesystem, stream = self._serve(dynamic=True, handler=FailOnce)
        self.assertEqual(_post(server.server_port, "/connect", {"target": TARGET})[0], 200)
        command = "ls /srv/ledger-api/releases"
        with self.assertRaises(RemoteDisconnected):
            _post(server.server_port, "/exec", {"command": command})
        failed = _events(stream)
        self.assertEqual(server.command_count, 0)
        self.assertEqual(
            len([event for event in failed if event["event_type"] == "response_write_failed"]),
            1,
        )
        self.assertFalse(
            [event for event in failed if event["event_type"] == "filesystem_materialized"]
        )
        self.assertTrue(filesystem._children_cache, "Failed response warmed the lazy cache")
        self.assertEqual(_post(server.server_port, "/exec", {"command": command})[0], 200)
        self.assertEqual(server.command_count, 1)
        delivered = _events(stream)
        self.assertTrue(
            [event for event in delivered if event["event_type"] == "filesystem_materialized"]
        )
        self.assertEqual(
            len([event for event in delivered if event["event_type"] == "decoy_response" and event["route"] == "/exec"]),
            1,
        )

    def test_static_arm_does_not_materialize_generated_nodes(self) -> None:
        server, filesystem, stream = self._serve(dynamic=False)
        self.assertEqual(_post(server.server_port, "/connect", {"target": TARGET})[0], 200)
        self.assertEqual(
            _post(server.server_port, "/exec", {"command": "ls /srv/ledger-api/releases"})[0],
            200,
        )
        self.assertEqual(filesystem.committed_inventory(), ())
        self.assertFalse(
            [
                event
                for event in _events(stream)
                if event["event_type"] == "filesystem_materialized"
            ]
        )


if __name__ == "__main__":
    unittest.main()
