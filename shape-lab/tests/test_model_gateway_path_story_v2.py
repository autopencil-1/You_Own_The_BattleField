"""Model-free closeout tests for the versioned path-story gateway."""

from __future__ import annotations

from contextlib import redirect_stdout
from http.client import HTTPConnection
import io
import json
import threading
import time
import unittest
from unittest.mock import patch

from model_gateway.server import GatewayHandler
from model_gateway.server_path_story_v2 import (
    DOWNSTREAM_WRITE_TIMEOUT_SECONDS,
    PathStoryGatewayV2,
)


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


def _post(port: int, path: str, body: bytes, *, expect_reply: bool = True) -> int | None:
    client = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        client.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        if not expect_reply:
            try:
                client.getresponse().read()
            except OSError:
                pass
            return None
        response = client.getresponse()
        response.read()
        return response.status
    finally:
        client.close()


def _events(stream: io.StringIO, count: int) -> list[dict]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        lines = stream.getvalue().splitlines()
        if len(lines) >= count:
            return [json.loads(line) for line in lines]
        time.sleep(0.01)
    raise AssertionError(f"expected {count} gateway events")


class PathStoryGatewayV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = PathStoryGatewayV2(
            ("127.0.0.1", 0), "unused-local-key", "test-path-story-v2",
            "glm-5.3", 10, 100, (), "ollama",
        )
        self.thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=2)

    def test_provider_completion_precedes_downstream_finish(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream), patch("model_gateway.server.HTTPSConnection", LocalUpstream):
            self.assertEqual(
                _post(self.gateway.server_port, "/v1/messages", b'{"model":"glm-5.3"}'),
                200,
            )
            events = _events(stream, 4)
        self.assertEqual(
            [row["event_type"] for row in events],
            ["request_started", "model_call", "provider_response_complete", "request_finished"],
        )
        self.assertEqual([row["request_id"] for row in events], [1] * 4)
        self.assertEqual([row["sequence"] for row in events], [1, 2, 3, 4])
        self.assertEqual(events[2]["call_number"], 1)
        self.assertEqual(events[2]["attempt_number"], 1)
        self.assertEqual(events[2]["status"], 200)
        self.assertTrue(events[2]["usage_recorded"])

    def test_downstream_failure_is_bounded_and_keeps_upstream_cost_evidence(self) -> None:
        stream = io.StringIO()
        def broken_reply(handler: GatewayHandler, *args: object, **kwargs: object) -> None:
            self.assertEqual(handler.connection.gettimeout(), DOWNSTREAM_WRITE_TIMEOUT_SECONDS)
            raise BrokenPipeError("secret payload must not be logged")
        with (
            redirect_stdout(stream),
            patch("model_gateway.server.HTTPSConnection", LocalUpstream),
            patch.object(GatewayHandler, "_reply", broken_reply),
        ):
            _post(self.gateway.server_port, "/v1/messages", b'{"model":"glm-5.3"}', expect_reply=False)
            events = _events(stream, 4)
        self.assertEqual(
            [row["event_type"] for row in events],
            ["request_started", "model_call", "provider_response_complete", "downstream_delivery_failed"],
        )
        self.assertEqual(events[-1]["error_type"], "BrokenPipeError")
        self.assertEqual(events[-1]["request_id"], 1)
        self.assertNotIn("secret payload", stream.getvalue())

    def test_downstream_send_timeout_is_a_terminal_delivery_failure(self) -> None:
        stream = io.StringIO()
        with (
            redirect_stdout(stream),
            patch("model_gateway.server.HTTPSConnection", LocalUpstream),
            patch.object(GatewayHandler, "_reply", side_effect=TimeoutError("send timed out")),
        ):
            _post(self.gateway.server_port, "/v1/messages", b'{"model":"glm-5.3"}', expect_reply=False)
            events = _events(stream, 4)
        self.assertEqual(
            [row["event_type"] for row in events],
            ["request_started", "model_call", "provider_response_complete", "downstream_delivery_failed"],
        )
        self.assertEqual(events[-1]["error_type"], "TimeoutError")
        self.assertNotIn("send timed out", stream.getvalue())

    def test_local_rejection_without_upstream_has_a_terminal_event(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(_post(self.gateway.server_port, "/v1/messages", b"{"), 400)
            events = _events(stream, 3)
        self.assertEqual(
            [row["event_type"] for row in events],
            ["request_started", "request_rejected", "request_finished"],
        )
        self.assertFalse(any(row["event_type"] == "provider_response_complete" for row in events))

    def test_pre_request_cap_has_no_provider_completion(self) -> None:
        self.gateway.max_calls = 0
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(
                _post(self.gateway.server_port, "/v1/messages", b'{"model":"glm-5.3"}'),
                429,
            )
            events = _events(stream, 3)
        self.assertEqual(
            [row["event_type"] for row in events],
            ["request_started", "cap_reached", "request_finished"],
        )
        self.assertEqual(events[1]["phase"], "pre_request")

    def test_upstream_429_is_complete_and_rate_limit_is_recorded(self) -> None:
        class RateLimitedUpstream(LocalUpstream):
            def getresponse(self):
                class Response:
                    status = 429

                    def getheader(self, name: str, default: str) -> str:
                        return "application/json"

                    def read(self, limit: int) -> bytes:
                        return b'{"error":"rate_limited"}'

                return Response()

        stream = io.StringIO()
        with redirect_stdout(stream), patch(
            "model_gateway.server.HTTPSConnection", RateLimitedUpstream
        ):
            self.assertEqual(
                _post(self.gateway.server_port, "/v1/messages", b'{"model":"glm-5.3"}'),
                429,
            )
            events = _events(stream, 5)
        self.assertEqual(
            [row["event_type"] for row in events],
            ["request_started", "model_call", "provider_response_complete",
             "provider_rate_limit_rejected", "request_finished"],
        )
        self.assertEqual(events[2]["status"], 429)
        self.assertFalse(events[2]["usage_recorded"])


if __name__ == "__main__":
    unittest.main()
