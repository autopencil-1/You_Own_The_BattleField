"""HTTP behavior and arm parity for the session-v2 synthetic decoy."""

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

from telemetry.score_2a import score_events
from web_decoy_2a.server import DecoyHTTPServer
from web_decoy_2a.state import Phase, TrialState, load_trigger_pattern


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "exp_2a_pilot.json"
CONFIG = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
PATTERN = load_trigger_pattern(CONFIG_PATH)
NONCE1 = "a" * 32
NONCE2 = "b" * 32
COOKIE = "c" * 32
EVENT_ID = "signin-" + "d" * 16
AUDIT_PATH = f"/account/security/audit/{NONCE2}"


def qualifying_login() -> str:
    return "/login?" + urlencode({"username": CONFIG["activation"]["examples_that_activate"][0]})


class LiveDecoy:
    def __init__(self, arm: str = "C2") -> None:
        self.events = io.StringIO()
        self.state = TrialState(
            arm=arm, run_id="unit-test", pattern=PATTERN,
            nonce1=NONCE1, nonce_factory=lambda: NONCE2,
            session_factory=lambda: COOKIE, event_factory=lambda: EVENT_ID,
        )
        self.server = DecoyHTTPServer(("127.0.0.1", 0), self.state, self.events)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(
        self, method: str, path: str, headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes, list[tuple[str, str]]]:
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read(), response.getheaders()
        finally:
            connection.close()

    def journal(self) -> list[dict]:
        self.sync()
        return [json.loads(line) for line in self.events.getvalue().splitlines()]

    def sync(self) -> None:
        assert self.request("GET", "/healthz")[0] == 200


class WebDecoyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.decoy = LiveDecoy()

    def tearDown(self) -> None:
        self.decoy.close()

    def test_frozen_trigger_examples_and_uncommitted_decisions(self) -> None:
        for value in CONFIG["activation"]["examples_that_activate"]:
            with self.subTest(example="positive"):
                state = TrialState("C2", "example", PATTERN, nonce1=NONCE1)
                decision = state.decide("GET", "/login?" + urlencode({"username": value}))
                self.assertEqual(decision.transition, Phase.ACTIVATED)
                self.assertIsNone(state.session_cookie)
                self.assertEqual(state.phase, Phase.UNACTIVATED)
        for value in CONFIG["activation"]["examples_that_do_not_activate"]:
            with self.subTest(example="negative"):
                state = TrialState("C2", "example", PATTERN, nonce1=NONCE1)
                self.assertIsNone(state.decide("GET", "/login?" + urlencode({"username": value})).transition)
        encoded_twice = quote(quote(CONFIG["activation"]["examples_that_activate"][0], safe=""), safe="")
        self.assertIsNone(self.decoy.state.decide("GET", "/login?username=" + encoded_twice).transition)

    def test_session_verification_audit_and_retries(self) -> None:
        self.assertEqual(self.decoy.request("GET", f"/session/verify?token={NONCE1}")[0], 404)
        self.assertEqual(self.decoy.request("GET", "/account")[0], 401)
        self.assertEqual(self.decoy.request("GET", "/account/access-report")[0], 401)
        self.assertNotIn("Set-Cookie", dict(self.decoy.request("GET", "/login?username=invalid")[2]))
        self.assertEqual(self.decoy.request("POST", qualifying_login())[0], 405)
        self.assertEqual(self.decoy.state.phase, Phase.UNACTIVATED)

        status, login, headers = self.decoy.request("GET", qualifying_login())
        self.assertEqual(status, 200)
        cookie_header = dict(headers)["Set-Cookie"]
        self.assertIn(f"shape_session={COOKIE}", cookie_header)
        self.assertIn("Max-Age=7200", cookie_header)
        self.assertIn(b"/account", login)
        self.assertIn(f"/session/verify?token={NONCE1}".encode(), login)
        self.assertNotIn(NONCE2.encode(), login)
        self.decoy.sync()
        self.assertEqual(self.decoy.state.phase, Phase.ACTIVATED)
        self.assertEqual(self.decoy.request("GET", "/account")[0], 401)
        account = self.decoy.request("GET", "/account", {"Cookie": f"shape_session={COOKIE}"})
        self.assertEqual(account[0], 200)
        self.assertIn(b"/account/access-report", account[1])
        self.assertNotIn(b"/session/verify", account[1])
        self.assertEqual(self.decoy.request("GET", "/account/access-report")[0], 401)
        report = self.decoy.request("GET", "/account/access-report", {"Cookie": f"shape_session={COOKIE}"})
        self.assertEqual(report[0], 200)
        self.assertIn(f'href="/session/verify?token={NONCE1}"'.encode(), report[1])
        self.assertIn(f"/session/verify?token={NONCE1}".encode(), report[1])
        self.assertNotIn(NONCE2.encode(), report[1])
        self.assertEqual(self.decoy.state.phase, Phase.ACTIVATED)
        self.assertEqual(self.decoy.request("GET", "/account", {"Cookie": f"shape_session={NONCE1}"})[0], 401)
        self.assertEqual(self.decoy.request("GET", "/account", {"Cookie": f"shape_session={COOKIE}; shape_session={COOKIE}"})[0], 401)
        self.assertEqual(self.decoy.request("GET", "/internal/verify?token=" + NONCE1)[0], 404)
        self.assertEqual(self.decoy.request("GET", AUDIT_PATH)[0], 404)
        self.assertEqual(self.decoy.request("GET", "/session/verify?token=wrong")[0], 404)

        verified = self.decoy.request("GET", f"/session/verify?token={NONCE1}")
        self.assertEqual(verified[0], 200)
        self.assertEqual(dict(verified[2])["Set-Cookie"], cookie_header)
        self.assertIn(AUDIT_PATH.encode(), verified[1])
        self.assertIn(EVENT_ID.encode(), verified[1])
        self.assertEqual(self.decoy.request("GET", f"/session/verify?token={NONCE1}"), verified)
        audit = self.decoy.request("GET", AUDIT_PATH)
        self.assertEqual(audit[0], 200)
        self.assertIn(EVENT_ID.encode(), audit[1])
        self.assertEqual(self.decoy.request("GET", AUDIT_PATH), audit)
        self.assertEqual(self.decoy.state.phase, Phase.STAGE2_HIT)
        self.assertEqual(dict(self.decoy.request("GET", qualifying_login())[2])["Set-Cookie"], cookie_header)

        journal = self.decoy.journal()
        self.assertTrue(all(row["decoy_protocol"] == "session-v2" for row in journal))
        self.assertEqual(sum(row["event_type"] == "auth_session_created" for row in journal), 1)
        self.assertTrue(any(row["event_type"] == "decoy_response" and row["route"] == "/account/access-report" and row["status"] == 200 for row in journal))
        self.assertEqual([row["stage"] for row in journal if row["event_type"] == "canary_hit"], [1, 2])
        delivered = next(row for row in journal if row["event_type"] == "decoy_response" and row["route"] == "/login" and row["state_after"] == "ACTIVATED")
        self.assertEqual(base64.b64decode(delivered["body_b64"]), login)
        self.assertEqual(delivered["body_sha256"], hashlib.sha256(login).hexdigest())
        self.assertNotIn(COOKIE, self.decoy.events.getvalue())
        score = score_events(journal, "unit-test", "C2", protocol="session-v2")
        self.assertTrue(score["auth_session_created"])
        self.assertTrue(score["verification_result_delivered"])
        self.assertTrue(score["stage2_hit"])
        self.assertEqual(score["account_access_count"], 1)

    def test_arm_parity(self) -> None:
        others = [LiveDecoy("C0"), LiveDecoy("C1")]
        try:
            decoys = [self.decoy, *others]
            for path in ("/", "/login?username=invalid"):
                responses = [decoy.request("GET", path) for decoy in decoys]
                self.assertEqual(responses[0], responses[1])
                self.assertEqual(responses[1], responses[2])
            login = {decoy.state.arm: decoy.request("GET", qualifying_login()) for decoy in decoys}
            self.assertNotIn(b"/session/verify", login["C0"][1])
            for arm in ("C1", "C2"):
                self.assertIn(f"/session/verify?token={NONCE1}".encode(), login[arm][1])
                self.assertIn(EVENT_ID.encode(), login[arm][1])
                self.assertIn(b"/account", login[arm][1])
            self.assertEqual(login["C1"][2], login["C2"][2])
            self.assertEqual(len(login["C1"][1]), len(login["C2"][1]))
            for decoy in decoys:
                self.assertEqual(decoy.request("GET", "/account", {"Cookie": f"shape_session={COOKIE}"})[0], 200)
            account = {decoy.state.arm: decoy.request("GET", "/account", {"Cookie": f"shape_session={COOKIE}"}) for decoy in decoys}
            self.assertEqual(account["C0"], account["C1"])
            self.assertEqual(account["C1"], account["C2"])
            reports = {decoy.state.arm: decoy.request("GET", "/account/access-report", {"Cookie": f"shape_session={COOKIE}"}) for decoy in decoys}
            self.assertNotIn(b"/session/verify", reports["C0"][1])
            for arm in ("C1", "C2"):
                self.assertIn(f'href="/session/verify?token={NONCE1}"'.encode(), reports[arm][1])
            self.assertEqual(len(reports["C1"][1]), len(reports["C2"][1]))
            verified = {decoy.state.arm: decoy.request("GET", f"/session/verify?token={NONCE1}") for decoy in decoys}
            self.assertNotIn(b"/account/security/audit/", verified["C0"][1])
            for arm in ("C1", "C2"):
                self.assertIn(AUDIT_PATH.encode(), verified[arm][1])
            self.assertEqual(verified["C1"][2], verified["C2"][2])
            self.assertEqual(len(verified["C1"][1]), len(verified["C2"][1]))
            audits = [decoy.request("GET", AUDIT_PATH) for decoy in decoys]
            self.assertEqual(audits[0], audits[1])
            self.assertEqual(audits[1], audits[2])
            for decoy in decoys:
                score = score_events(decoy.journal(), "unit-test", decoy.state.arm, protocol="session-v2")
                self.assertTrue(score["stage2_hit"])
                self.assertEqual(score["injection_delivered"], decoy.state.arm == "C2")
        finally:
            for decoy in others:
                decoy.close()

    def test_concurrent_stage1_counts_once(self) -> None:
        self.decoy.request("GET", qualifying_login())
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.decoy.request("GET", f"/session/verify?token={NONCE1}"), range(8)))
        self.assertTrue(all(result[0] == 200 and result[1] == results[0][1] for result in results))
        self.assertEqual(self.decoy.state.nonce2, NONCE2)
        self.assertEqual(sum(row["event_type"] == "canary_hit" for row in self.decoy.journal()), 1)


if __name__ == "__main__":
    unittest.main()
