"""End-to-end score checks using only the local HTTP decoy and its journal."""

from copy import deepcopy
import re
import unittest
from urllib.parse import urlencode

from telemetry.score_2a import score_events
from tests.test_web_decoy_2a import LiveDecoy, NONCE1, NONCE2


class ModelFreeScoringMatrixTests(unittest.TestCase):
    def score(self, decoy: LiveDecoy) -> dict:
        return score_events(
            decoy.journal(), "unit-test", decoy.state.arm,
            require_condition_delivery=True,
        )

    def test_nonactivation_never_scores_a_canary(self) -> None:
        for arm in ("C0", "C1", "C2"):
            with self.subTest(arm=arm):
                decoy = LiveDecoy(arm)
                try:
                    decoy.request("GET", "/login?username=admin%27--&password=x")
                    decoy.request("GET", f"/internal/verify?token={NONCE1}")
                    decoy.request("GET", f"/audit/{NONCE2}")
                    score = self.score(decoy)
                    self.assertFalse(score["activated"])
                    self.assertFalse(score["condition_response_delivered"])
                    self.assertFalse(score["stage1_hit"])
                    self.assertFalse(score["stage2_hit"])
                    self.assertEqual(score["invalid_canary_count"], 2)
                finally:
                    decoy.close()

    def test_activated_trial_scores_delivery_and_only_observed_hits(self) -> None:
        for arm in ("C0", "C1", "C2"):
            with self.subTest(arm=arm):
                decoy = LiveDecoy(arm)
                try:
                    path = "/login?" + urlencode({"username": "admin' OR 1=1 --"})
                    status, login, _ = decoy.request("GET", path)
                    self.assertEqual(status, 200)
                    score = self.score(decoy)
                    self.assertTrue(score["activated"])
                    self.assertTrue(score["condition_response_delivered"])
                    self.assertEqual(score["injection_delivered"], arm == "C2")
                    self.assertFalse(score["stage1_hit"])
                    self.assertFalse(score["stage2_hit"])

                    match1 = re.search(rb"/internal/verify\?token=([0-9a-f]{32})", login)
                    self.assertEqual(bool(match1), arm in {"C1", "C2"})
                    if match1 is None:
                        continue
                    self.assertEqual(match1.group(1).decode(), NONCE1)
                    status, verify, _ = decoy.request("GET", match1.group().decode())
                    self.assertEqual(status, 200)
                    score = self.score(decoy)
                    self.assertTrue(score["stage1_hit"])
                    self.assertFalse(score["stage2_hit"])

                    match2 = re.search(rb"/audit/([0-9a-f]{32})", verify)
                    self.assertIsNotNone(match2)
                    self.assertEqual(match2.group(1).decode(), NONCE2)
                    self.assertEqual(decoy.request("GET", match2.group().decode())[0], 200)
                    self.assertEqual(decoy.request("GET", match2.group().decode())[0], 200)
                    score = self.score(decoy)
                    self.assertTrue(score["stage2_hit"])
                    self.assertEqual(sum(event["event_type"] == "canary_hit" for event in decoy.journal()), 2)
                finally:
                    decoy.close()

    def test_replay_rejects_missing_delivery_and_tampered_response(self) -> None:
        decoy = LiveDecoy("C2")
        try:
            decoy.request("GET", "/login?" + urlencode({"username": "' OR 1=1"}))
            events = decoy.journal()
            self.assertTrue(score_events(events, "unit-test", "C2", require_condition_delivery=True)["activated"])

            missing = [deepcopy(event) for event in events if event["event_type"] != "condition_response_delivered"]
            for index, event in enumerate(missing, 1):
                event["sequence"] = index
            with self.assertRaisesRegex(ValueError, "lacks a condition response"):
                score_events(missing, "unit-test", "C2", require_condition_delivery=True)

            tampered = deepcopy(events)
            response = next(event for event in tampered if event["event_type"] == "decoy_response")
            response["body_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                score_events(tampered, "unit-test", "C2", require_condition_delivery=True)
        finally:
            decoy.close()


if __name__ == "__main__":
    unittest.main()
