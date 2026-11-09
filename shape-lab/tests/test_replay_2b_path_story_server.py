"""Loopback successor server → archive → replay integration, without a model."""

from __future__ import annotations

from http.client import HTTPConnection, RemoteDisconnected
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

from experiment_controller.path_story_evidence_2b import archive_path_story_run
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server_path_story import StoryDecoyServer, StoryHandler, StorySession
from telemetry.replay_2b_path_story import verify_path_story_bundle, verify_path_story_pair


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"
TARGET = "ssh://lab@filesystem-decoy-2b"
SEED = "replay-loopback-seed"


def _run_server(
    arm: str,
    run_id: str,
    commands: list[str],
    *,
    fail_first_exec: bool = False,
    max_commands: int = 50,
    extra_requests: tuple[tuple[str, dict[str, str], int], ...] = (),
) -> list[str]:
    raw, fs = load_path_story_fixture(FIXTURE, SEED, arm in {"B1", "B3"})
    event_stream = io.StringIO()
    server = StoryDecoyServer(
        ("127.0.0.1", 0),
        run_id=run_id,
        arm=arm,
        target=TARGET,
        session=StorySession(fs),
        reinforcement_text=raw["reinforcement_text"],
        max_commands=max_commands,
        event_stream=event_stream,
    )
    if fail_first_exec:
        class FailOnce(StoryHandler):
            should_fail = True

            def _reply(self, status, payload):
                if self.path == "/exec" and type(self).should_fail:
                    type(self).should_fail = False
                    self.close_connection = True
                    raise BrokenPipeError("injected write failure")
                return super()._reply(status, payload)

        server.RequestHandlerClass = FailOnce
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(route: str, payload: dict[str, str], expected_status: int = 200) -> dict:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request(
                "POST",
                route,
                body=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if response.status != expected_status:
                raise AssertionError(f"Loopback request failed: {response.status}")
            return json.loads(response.read())
        finally:
            connection.close()

    try:
        connected = post("/connect", {"target": TARGET})
        if not connected["new_connection"]:
            raise AssertionError("Loopback connection did not open")
        for command in commands:
            if fail_first_exec:
                with unittest.TestCase().assertRaises(RemoteDisconnected):
                    post("/exec", {"command": command})
                fail_first_exec = False
            post("/exec", {"command": command})
        for route, payload, status in extra_requests:
            post(route, payload, status)
        # The HTTP body can arrive before the handler's post-write journal
        # events.  Acquire its lock to wait until that transition completes.
        with server.lock:
            return event_stream.getvalue().splitlines(keepends=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class PathStoryLoopbackReplayTests(unittest.TestCase):
    def test_real_server_journal_archives_and_replays_across_structure_arms(self) -> None:
        common = ["pwd", "ls /", "ls /home/lab", "whoami", "cat /home/lab/README.md"]
        commands = common + ["ls /srv/ledger-api/releases"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dirs = {}
            for arm in ("B0", "B1"):
                run_id = f"path-story-loopback-{arm.lower()}"
                run_dir = root / run_id
                archive_path_story_run(
                    run_dir,
                    fixture_path=FIXTURE,
                    seed=SEED,
                    arm=arm,
                    run_id=run_id,
                    event_lines=_run_server(arm, run_id, commands),
                )
                run_dirs[arm] = run_dir
            static = verify_path_story_bundle(run_dirs["B0"])
            dynamic = verify_path_story_bundle(run_dirs["B1"])
            self.assertEqual(static["materialized_nodes"], 0)
            self.assertGreater(dynamic["materialized_nodes"], 0)
            self.assertEqual(
                verify_path_story_pair(run_dirs["B0"], run_dirs["B1"], common)[
                    "common_commands"
                ],
                common,
            )

    def test_failed_write_retries_from_warm_cache_and_replays(self) -> None:
        command = "ls /srv/ledger-api/releases"
        run_id = "path-story-write-retry"
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / run_id
            event_lines = _run_server(
                "B1", run_id, [command], fail_first_exec=True
            )
            archive_path_story_run(
                run_dir,
                fixture_path=FIXTURE,
                seed=SEED,
                arm="B1",
                run_id=run_id,
                event_lines=event_lines,
            )
            replay = verify_path_story_bundle(run_dir)
            self.assertEqual(replay["filesystem_actions"], 1)
            self.assertGreater(replay["materialized_nodes"], 0)
            events = [json.loads(line) for line in event_lines]
            self.assertEqual(
                sum(row["event_type"] == "response_write_failed" for row in events), 1
            )
            self.assertEqual(
                sum(
                    row["event_type"] == "decoy_response" and row["route"] == "/exec"
                    for row in events
                ),
                1,
            )

    def test_command_cap_and_rejected_requests_replay(self) -> None:
        run_id = "path-story-cap-rejections"
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / run_id
            event_lines = _run_server(
                "B0",
                run_id,
                ["ls /"],
                max_commands=1,
                extra_requests=(
                    ("/exec", {"command": "pwd"}, 429),
                    ("/exec", {}, 400),
                    ("/not-here", {}, 404),
                ),
            )
            archive_path_story_run(
                run_dir,
                fixture_path=FIXTURE,
                seed=SEED,
                arm="B0",
                run_id=run_id,
                event_lines=event_lines,
                max_commands=1,
            )
            replay = verify_path_story_bundle(run_dir)
            self.assertEqual(replay["filesystem_actions"], 1)
            self.assertEqual(replay["materialized_nodes"], 0)
            events = [json.loads(line) for line in event_lines]
            self.assertEqual(
                [row["status"] for row in events if row["event_type"] == "decoy_response"],
                [200, 200, 429, 400, 404],
            )


if __name__ == "__main__":
    unittest.main()
