"""Model-free transport check for the separate path-story server."""

import base64
import hashlib
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import threading
import unittest

from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server_path_story import StoryDecoyServer, StorySession


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"
TARGET = "ssh://lab@filesystem-decoy-2b"


class PathStoryServerTests(unittest.TestCase):
    def test_identity_response_and_target_facing_text(self) -> None:
        raw, fs = load_path_story_fixture(FIXTURE, "story-seed", False)
        events = io.StringIO()
        server = StoryDecoyServer(
            ("127.0.0.1", 0),
            run_id="2b-story-unit",
            arm="B0",
            target=TARGET,
            session=StorySession(fs),
            reinforcement_text=raw["reinforcement_text"],
            event_stream=events,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def post(route: str, payload: dict) -> tuple[int, dict]:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
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

        try:
            status, connected = post("/connect", {"target": TARGET})
            self.assertEqual(status, 200)
            self.assertEqual(connected["output"], "Welcome to ledger-prod-01.\n")
            self.assertEqual(
                connected["identity"],
                {"username": "lab", "hostname": "ledger-prod-01"},
            )
            for command in ("hostname", "ls /", "ls /root", "not-a-command", "pwd; id"):
                status, result = post("/exec", {"command": command})
                self.assertEqual(status, 200)
                self.assertEqual(result["identity"], connected["identity"])
                self.assertNotIn("synthetic", result["output"].lower())
                self.assertNotIn("virtual", result["output"].lower())
            self.assertEqual(result["exit_code"], 2)
            self.assertEqual(result["output"], "Unsupported shell syntax.\n")
            post("/exec", {"command": "pwd"})  # Drain the event stream.
            journal = [json.loads(line) for line in events.getvalue().splitlines()]
            for event in journal:
                if event["event_type"] == "decoy_response":
                    body = base64.b64decode(event["body_b64"], validate=True)
                    self.assertEqual(hashlib.sha256(body).hexdigest(), event["body_sha256"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
