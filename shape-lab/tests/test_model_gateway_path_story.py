"""Local-only lifecycle evidence tests for the versioned path-story gateway."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from http.client import HTTPConnection
import io
import json
import threading
import time
import unittest
from unittest.mock import patch

from model_gateway.server import GatewayHandler
from model_gateway.server_path_story import PathStoryGateway, PathStoryGatewayHandler


def _post(port: int, path: str, body: bytes) -> int:
    client = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        client.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        response = client.getresponse()
        response.read()
        return response.status
    finally:
        client.close()


def _events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def _wait_for_events(stream: io.StringIO, count: int) -> list[dict]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        lines = stream.getvalue().splitlines()
        if len(lines) >= count:
            return [json.loads(line) for line in lines]
        time.sleep(0.01)
    raise AssertionError(f"expected {count} gateway events, got {stream.getvalue()!r}")


class PathStoryGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = PathStoryGateway(
            ("127.0.0.1", 0), "unused-local-key", "test-path-story",
            "glm-5.3", 10, 100, (), "ollama",
        )
        self.thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=2)

    def test_rejections_have_terminal_events_without_caller_secrets(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(
                _post(self.gateway.server_port, "/private?token=secret-query", b"{}"),
                404,
            )
            self.assertEqual(
                _post(self.gateway.server_port, "/v1/messages", b'{"model":"secret-model"}'),
                400,
            )
            events = _wait_for_events(stream, 6)
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_rejected", "request_finished"] * 2,
        )
        self.assertEqual([event["request_id"] for event in events], [1, 1, 1, 2, 2, 2])
        self.assertEqual([event["sequence"] for event in events], list(range(1, 7)))
        self.assertEqual(events[0]["route"], "other")
        self.assertEqual(events[1]["path"], "other")
        self.assertEqual(events[3]["route"], "/v1/messages")
        self.assertNotIn("secret-query", stream.getvalue())
        self.assertNotIn("secret-model", stream.getvalue())
        self.assertNotIn("requested_model", stream.getvalue())

    def test_upstream_usage_event_is_inside_one_request_lifecycle(self) -> None:
        class LocalUpstream:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def request(self, *args: object, **kwargs: object) -> None:
                pass

            def getresponse(self):
                class Response:
                    status = 200

                    def getheader(self, name: str, default: str) -> str:
                        return "application/json"

                    def read(self, limit: int) -> bytes:
                        return b'{"model":"glm-5.3","usage":{"input_tokens":2,"output_tokens":3}}'

                return Response()

            def close(self) -> None:
                pass

        stream = io.StringIO()
        with redirect_stdout(stream), patch("model_gateway.server.HTTPSConnection", LocalUpstream):
            self.assertEqual(
                _post(self.gateway.server_port, "/v1/messages", b'{"model":"glm-5.3"}'),
                200,
            )
            events = _wait_for_events(stream, 3)
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "model_call", "request_finished"],
        )
        self.assertEqual([event["request_id"] for event in events], [1, 1, 1])
        self.assertEqual(events[1]["usage"]["input_tokens"], 2)
        self.assertEqual(events[1]["usage"]["output_tokens"], 3)

    def test_exception_emits_aborted_without_exception_text(self) -> None:
        handler = object.__new__(PathStoryGatewayHandler)
        handler.server = self.gateway
        handler.path = "/v1/messages?token=secret-query"
        stream = io.StringIO()
        with redirect_stdout(stream), patch.object(
            GatewayHandler, "do_POST", side_effect=RuntimeError("secret-exception")
        ):
            with self.assertRaisesRegex(RuntimeError, "secret-exception"):
                handler.do_POST()
        events = _events(stream)
        self.assertEqual([event["event_type"] for event in events], ["request_started", "request_aborted"])
        self.assertEqual([event["request_id"] for event in events], [1, 1])
        self.assertEqual(events[1]["error_type"], "RuntimeError")
        self.assertNotIn("secret-query", stream.getvalue())
        self.assertNotIn("secret-exception", stream.getvalue())

    def test_concurrent_requests_have_unique_ids_and_total_event_order(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            with ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(
                    lambda _: _post(self.gateway.server_port, "/invalid", b"{}"),
                    range(8),
                ))
            events = _wait_for_events(stream, 24)
        self.assertEqual(statuses, [404] * 8)
        self.assertEqual([event["sequence"] for event in events], list(range(1, 25)))
        started = {event["request_id"] for event in events if event["event_type"] == "request_started"}
        finished = {event["request_id"] for event in events if event["event_type"] == "request_finished"}
        self.assertEqual(started, set(range(1, 9)))
        self.assertEqual(finished, started)
        self.assertFalse(any(event["event_type"] == "request_aborted" for event in events))


if __name__ == "__main__":
    unittest.main()
