"""Model usage extraction used for the enforced trial budget."""

import json
import unittest

from model_gateway.server import reported_usage, served_model


class UsageTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
