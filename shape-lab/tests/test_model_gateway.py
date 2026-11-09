"""Model usage extraction used for the enforced trial budget."""

import json
from http.client import HTTPConnection
from pathlib import Path
import threading
import tempfile
import unittest
from unittest.mock import patch

from model_gateway.server import Gateway, reported_usage, served_model, sse_protocol_metadata
from model_gateway.providers import provider_spec
from experiment_controller import run_2a


class UsageTests(unittest.TestCase):
    def test_sse_protocol_metadata_omits_model_content(self) -> None:
        body = b"\n\n".join([
            b'data: {"type":"message_start","message":{"model":"glm-5.3"}}',
            b'data: {"type":"content_block_delta","delta":{"text":"PRIVATE-MARKER"}}',
            b'data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}',
            b'data: {"type":"message_stop"}',
        ])
        metadata = sse_protocol_metadata(body, "text/event-stream")
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["stop_reason"], "tool_use")
        self.assertTrue(metadata["message_stop_seen"])
        self.assertNotIn("PRIVATE-MARKER", json.dumps(metadata))

    def test_anthropic_stream_usage_includes_cached_input(self) -> None:
        chunks = [
            {"type": "message_start", "message": {"usage": {
                "input_tokens": 100,
                "output_tokens": 0,
                "cache_read_input_tokens": 25,
            }, "model": "glm-5.3-flash"}},
            {"type": "message_delta", "usage": {"output_tokens": 12}},
        ]
        body = b"\n\n".join(b"data: " + json.dumps(chunk).encode() for chunk in chunks)
        usage = reported_usage(body, "text/event-stream")
        self.assertIsNotNone(usage)
        self.assertEqual(sum(usage.values()), 137)
        self.assertEqual(served_model(body, "text/event-stream"), "glm-5.3-flash")


class ProviderRateLimitTests(unittest.TestCase):
    def request(self, statuses: list[int], *, max_calls: int = 8,
                retry_delays: tuple[int, ...] = (30, 60, 90),
                provider: str = "zai") -> tuple[int, list[dict], list[int], int]:
        events: list[dict] = []
        waits: list[int] = []
        self.requests: list[tuple[str, str]] = []
        responses = iter(statuses)
        requests = self.requests

        class Upstream:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.host = str(args[0])

            def request(self, method: str, path: str, body: bytes, headers: dict) -> None:
                self.body = body
                requests.append((self.host, path))

            def getresponse(self):
                status = next(responses)
                class Response:
                    def __init__(self, code: int) -> None:
                        self.status = code

                    def getheader(self, key: str, default: str) -> str:
                        return "application/json"

                    def read(self, limit: int) -> bytes:
                        if self.status == 429:
                            return b'{"error":"rate_limit"}'
                        return b'{"model":"glm-5.3-flash","usage":{"input_tokens":1,"output_tokens":1}}'
                return Response(status)

            def close(self) -> None:
                pass

        server = Gateway(("127.0.0.1", 0), "test-key", "test-run", "glm-5.3-flash",
                         max_calls, 100, retry_delays, provider)
        server.emit = lambda kind, **fields: events.append({"kind": kind, **fields})  # type: ignore[method-assign]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch("model_gateway.server.HTTPSConnection", Upstream), patch("model_gateway.server.time.sleep", waits.append):
                client = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                try:
                    client.request("POST", "/v1/messages", body=b'{"model":"glm-5.3-flash"}',
                                   headers={"Content-Type": "application/json"})
                    response = client.getresponse()
                    response.read()
                    status = response.status
                finally:
                    client.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        return status, events, waits, server.calls

    def test_retries_same_request_after_provider_429(self) -> None:
        status, events, waits, calls = self.request([429, 429, 200])
        self.assertEqual(status, 200)
        self.assertEqual(waits, [30, 60])
        self.assertEqual(calls, 1)
        self.assertEqual([item["attempt_number"] for item in events if item["kind"] == "model_call"], [1, 2, 3])
        self.assertFalse(any(item["kind"] == "provider_rate_limit_exhausted" for item in events))

    def test_fails_after_three_waits_with_rate_limit_event(self) -> None:
        status, events, waits, calls = self.request([429, 429, 429, 429])
        self.assertEqual(status, 429)
        self.assertEqual(waits, [30, 60, 90])
        self.assertEqual(calls, 1)
        self.assertEqual([item["attempts"] for item in events if item["kind"] == "provider_rate_limit_exhausted"], [4])

    def test_trial_cap_does_not_retry(self) -> None:
        status, events, waits, calls = self.request([], max_calls=0)
        self.assertEqual(status, 429)
        self.assertEqual(waits, [])
        self.assertEqual(calls, 0)
        self.assertEqual([item["kind"] for item in events], ["cap_reached"])

    def test_connectivity_mode_reports_immediate_provider_limit(self) -> None:
        status, events, waits, calls = self.request([429], retry_delays=())
        self.assertEqual(status, 429)
        self.assertEqual(waits, [])
        self.assertEqual(calls, 1)
        self.assertEqual(events[-1]["kind"], "provider_rate_limit_rejected")

    def test_ollama_cloud_routes_anthropic_messages_to_ollama(self) -> None:
        status, events, waits, calls = self.request([200], provider="ollama")
        self.assertEqual(status, 200)
        self.assertEqual(self.requests, [("ollama.com", "/v1/messages")])
        self.assertEqual(calls, 1)
        self.assertEqual(events[0]["kind"], "model_call")

    def test_provider_allowlist_rejects_arbitrary_hosts(self) -> None:
        with self.assertRaises(ValueError):
            provider_spec("example.com")

    def test_controller_reads_only_selected_provider_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text("ZAI_API_KEY=test-zai\nOLLAMA_API_KEY=test-ollama\n")
            with patch.object(run_2a, "REPO", root):
                self.assertEqual(run_2a.read_key("ollama"), "test-ollama")
                self.assertEqual(run_2a.read_key("zai"), "test-zai")


if __name__ == "__main__":
    unittest.main()
