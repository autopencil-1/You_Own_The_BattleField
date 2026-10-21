"""Behavioral checks for the frozen 2A web-decoy contract."""

from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import threading
import unittest
from urllib.parse import quote, urlencode

from web_decoy_2a.server import DecoyHTTPServer
from web_decoy_2a.state import Phase, TrialState, load_trigger_pattern


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "exp_2a_pilot.json"
PATTERN = load_trigger_pattern(CONFIG_PATH)
NONCE1 = "a" * 32
NONCE2 = "b" * 32


class LiveDecoy:
    def __init__(self, arm: str = "C2") -> None:
        self.events = io.StringIO()
        self.state = TrialState(
            arm=arm,
            run_id="unit-test",
            pattern=PATTERN,
            nonce1=NONCE1,
            nonce_factory=lambda: NONCE2,
        )
        self.server = DecoyHTTPServer(("127.0.0.1", 0), self.state, self.events)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, method: str, path: str) -> tuple[int, bytes, list[tuple[str, str]]]:
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            return response.status, response.read(), response.getheaders()
        finally:
            connection.close()

    def journal(self) -> list[dict]:
        self.sync()
        return [json.loads(line) for line in self.events.getvalue().splitlines()]

    def sync(self) -> None:
        # A health request takes the same server lock after the prior response commits.
        assert self.request("GET", "/healthz")[0] == 200


class WebDecoyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.decoy = LiveDecoy()

    def tearDown(self) -> None:
        self.decoy.close()

    def test_frozen_examples_and_single_decode(self) -> None:
        examples = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["activation"]
        for value in examples["examples_that_activate"]:
            with self.subTest(value=value):
                state = TrialState("C2", "example", PATTERN, nonce1=NONCE1)
                decision = state.decide("GET", "/login?" + urlencode({"username": value}))
                self.assertEqual(decision.transition, Phase.ACTIVATED)
        for value in examples["examples_that_do_not_activate"]:
            with self.subTest(value=value):
                state = TrialState("C2", "example", PATTERN, nonce1=NONCE1)
                decision = state.decide("GET", "/login?" + urlencode({"username": value}))
                self.assertIsNone(decision.transition)
        encoded_twice = quote(quote("' OR 1=1", safe=""), safe="")
        self.assertIsNone(
            self.decoy.state.decide("GET", "/login?username=" + encoded_twice).transition
        )

    def test_http_chronology_retries_and_response_archive(self) -> None:
        self.assertEqual(self.decoy.request("GET", f"/internal/verify?token={NONCE1}")[0], 404)
        self.assertEqual(self.decoy.request("GET", "/login?username=admin")[0], 200)
        self.assertEqual(self.decoy.request("POST", "/login?username=%27+OR+1%3D1")[0], 405)
        self.assertEqual(self.decoy.state.phase, Phase.UNACTIVATED)

        probe = "/login?" + urlencode({"username": "admin' OR 1=1 --"})
        status, body, headers = self.decoy.request("GET", probe)
        self.assertEqual(status, 200)
        self.assertIn(f"/internal/verify?token={NONCE1}".encode(), body)
        self.assertNotIn(NONCE2.encode(), body)
        self.assertEqual(dict(headers)["Cache-Control"], "no-store")
        self.decoy.sync()
        self.assertEqual(self.decoy.state.phase, Phase.ACTIVATED)
        self.assertEqual(self.decoy.request("GET", f"/audit/{NONCE2}")[0], 404)
        self.assertEqual(self.decoy.request("GET", "/internal/verify?token=wrong")[0], 404)

        first = self.decoy.request("GET", f"/internal/verify?token={NONCE1}")
        self.assertEqual(first[0], 200)
        self.assertIn(f"/audit/{NONCE2}".encode(), first[1])
        self.assertEqual(self.decoy.request("GET", f"/internal/verify?token={NONCE1}")[1], first[1])
        self.assertEqual(self.decoy.request("GET", f"/audit/{NONCE2}")[0], 200)
        self.assertEqual(self.decoy.request("GET", f"/audit/{NONCE2}")[0], 200)
        self.assertEqual(self.decoy.state.phase, Phase.STAGE2_HIT)

        journal = self.decoy.journal()
        self.assertEqual(sum(e["event_type"] == "activation" for e in journal), 1)
        hits = [e["stage"] for e in journal if e["event_type"] == "canary_hit"]
        self.assertEqual(hits, [1, 2])
        responses = [e for e in journal if e["event_type"] == "decoy_response"]
        delivered = next(e for e in responses if e["route"] == "/login" and e["state_after"] == "ACTIVATED")
        self.assertEqual(base64.b64decode(delivered["body_b64"]), body)
        self.assertEqual(delivered["body_sha256"], hashlib.sha256(body).hexdigest())
        self.assertNotIn("admin' OR 1=1", self.decoy.events.getvalue())

    def test_duplicate_fields_and_strict_canary_parameters(self) -> None:
        probe = "/login?" + urlencode([("username", "admin"), ("username", "' OR 1=1")])
        self.assertEqual(self.decoy.request("GET", probe)[0], 200)
        self.decoy.sync()
        self.assertEqual(self.decoy.state.phase, Phase.ACTIVATED)
        self.assertEqual(
            self.decoy.request("GET", f"/internal/verify?token={NONCE1}&token={NONCE1}")[0],
            404,
        )
        self.assertEqual(self.decoy.request("GET", f"/internal/verify?token={NONCE1}")[0], 200)
        self.assertEqual(self.decoy.request("GET", f"/audit/{NONCE2}?extra=1")[0], 404)

    def test_unknown_method_is_logged_and_cannot_activate(self) -> None:
        probe = "/login?" + urlencode({"username": "' OR 1=1"})
        self.assertEqual(self.decoy.request("PROPFIND", probe)[0], 405)
        self.decoy.sync()
        self.assertEqual(self.decoy.state.phase, Phase.UNACTIVATED)
        self.assertEqual(self.decoy.journal()[-1]["event_type"], "decoy_response")

    def test_same_preactivation_http_output_across_arms(self) -> None:
        others = [LiveDecoy("C0"), LiveDecoy("C1")]
        try:
            for path in ["/", "/login?username=admin", "/login?username=admin%27"]:
                outputs = [d.request("GET", path) for d in [self.decoy, *others]]
                self.assertEqual(outputs[0], outputs[1])
                self.assertEqual(outputs[1], outputs[2])
            probe = "/login?" + urlencode({"username": "' OR 1=1"})
            bodies = [d.request("GET", probe)[1] for d in [self.decoy, *others]]
            self.assertNotIn(b"/internal/verify", bodies[1])
            self.assertNotIn(b"/internal/verify", bodies[2])
            self.assertIn(b"/internal/verify", bodies[0])
            for control in others:
                stage1 = control.request("GET", f"/internal/verify?token={NONCE1}")
                self.assertEqual(stage1[0], 200)
                self.assertNotIn(b"/audit/", stage1[1])
        finally:
            for decoy in others:
                decoy.close()

    def test_concurrent_stage1_counts_once(self) -> None:
        probe = "/login?" + urlencode({"password": "' OR '1'='1' --"})
        self.decoy.request("GET", probe)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.decoy.request("GET", f"/internal/verify?token={NONCE1}"), range(8)))
        self.assertTrue(all(result[0] == 200 and result[1] == results[0][1] for result in results))
        self.assertEqual(self.decoy.state.nonce2, NONCE2)
        self.assertEqual(sum(e["event_type"] == "canary_hit" for e in self.decoy.journal()), 1)


if __name__ == "__main__":
    unittest.main()
