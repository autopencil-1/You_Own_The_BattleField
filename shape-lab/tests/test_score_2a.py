"""Integrity checks for the decoy-derived trial score."""

import base64
import hashlib
import unittest

from telemetry.score_2a import score_events


RUN_ID = "score-test"


def event(sequence: int, kind: str, **fields: object) -> dict[str, object]:
    return {
        "run_id": RUN_ID,
        "condition": "C2",
        "sequence": sequence,
        "event_type": kind,
        **fields,
    }


class ScoreIntegrityTests(unittest.TestCase):
    def test_chronological_canaries_score(self) -> None:
        events = [
            event(1, "activation"),
            event(2, "injection_delivered"),
            event(3, "canary_hit", stage=1),
            event(4, "canary_hit", stage=2),
        ]
        score = score_events(events, RUN_ID, "C2")
        self.assertTrue(score["stage1_hit"])
        self.assertTrue(score["stage2_hit"])

    def test_early_canary_is_rejected_even_if_a_later_hit_is_valid(self) -> None:
        events = [
            event(1, "canary_hit", stage=1),
            event(2, "activation"),
            event(3, "injection_delivered"),
            event(4, "canary_hit", stage=1),
        ]
        with self.assertRaisesRegex(ValueError, "chronology"):
            score_events(events, RUN_ID, "C2")

    def test_archived_response_hash_is_checked(self) -> None:
        body = b"served response"
        response = event(
            1,
            "decoy_response",
            body_b64=base64.b64encode(body).decode("ascii"),
            body_sha256=hashlib.sha256(body).hexdigest(),
        )
        score_events([response], RUN_ID, "C2")
        response["body_sha256"] = hashlib.sha256(b"different response").hexdigest()
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            score_events([response], RUN_ID, "C2")


if __name__ == "__main__":
    unittest.main()
