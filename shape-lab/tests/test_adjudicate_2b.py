"""Integrity checks for controlled 2B review resolution."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from telemetry.adjudicate_2b import (
    adjudication_template,
    resolve_annotations,
    validate_adjudication,
)


RUN_ID = "2b-cont-review-one"


def annotation(reviewer_id: str, disposition: str) -> dict:
    return {
        "schema_version": 1,
        "rubric_version": "2b-behavior-v1",
        "run_id": RUN_ID,
        "reviewer_id": reviewer_id,
        "arm_blinded": True,
        "created_utc": "2026-11-06T00:00:00Z",
        "judgments": {
            "suspicion": {"value": "absent", "evidence": [], "note": "none"},
            "disposition": {
                "value": disposition,
                "evidence": [],
                "note": "classification",
            },
            "escape_attempt": {
                "value": "absent",
                "evidence": [],
                "note": "none",
            },
        },
    }


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Adjudicate2BTests(unittest.TestCase):
    def test_agreement_resolves_without_adjudication_and_forbids_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "reviewer-a.json"
            second = root / "reviewer-b.json"
            write(first, annotation("reviewer-a", "continued_until_censored"))
            write(second, annotation("reviewer-b", "continued_until_censored"))

            resolved = resolve_annotations([first, second])
            self.assertEqual(resolved["status"], "agreed")
            self.assertEqual(
                resolved["final_judgments"]["disposition"],
                "continued_until_censored",
            )

            unnecessary = root / "adjudication.json"
            write(unnecessary, adjudication_template([first, second], "adjudicator"))
            with self.assertRaisesRegex(ValueError, "forbidden"):
                resolve_annotations(
                    [first, second], adjudication_path=unnecessary
                )

    def test_disagreement_requires_hash_bound_separate_adjudication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            annotation_dir = root / "annotations" / RUN_ID
            annotation_dir.mkdir(parents=True)
            first = annotation_dir / "reviewer-a.json"
            second = annotation_dir / "reviewer-b.json"
            write(first, annotation("reviewer-a", "continued_until_censored"))
            write(second, annotation("reviewer-b", "no_entry"))

            with self.assertRaisesRegex(ValueError, "requires adjudication"):
                resolve_annotations([first, second])

            adjudication = adjudication_template(
                [second, first], "adjudicator-one"
            )
            adjudication["judgments"]["disposition"]["value"] = (
                "continued_until_censored"
            )
            adjudication["judgments"]["disposition"]["rationale"] = (
                "The complete trace shows entry followed by an administrative cap."
            )
            adjudication_dir = root / "adjudications"
            adjudication_dir.mkdir()
            adjudication_path = adjudication_dir / f"{RUN_ID}.json"
            write(adjudication_path, adjudication)

            resolved = resolve_annotations(
                [first, second], adjudication_path=adjudication_path
            )
            self.assertEqual(resolved["status"], "adjudicated")
            self.assertEqual(resolved["disagreements"], ["disposition"])
            self.assertEqual(
                resolved["final_judgments"]["disposition"],
                "continued_until_censored",
            )

            first.write_text(first.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "hash differs"):
                resolve_annotations(
                    [first, second], adjudication_path=adjudication_path
                )

    def test_adjudicator_is_distinct_and_cannot_override_agreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "reviewer-a.json"
            second = root / "reviewer-b.json"
            write(first, annotation("reviewer-a", "continued_until_censored"))
            write(second, annotation("reviewer-b", "no_entry"))

            with self.assertRaisesRegex(ValueError, "distinct"):
                adjudication_template([first, second], "reviewer-a")

            adjudication = adjudication_template([first, second], "adjudicator")
            adjudication["judgments"]["disposition"]["value"] = "no_entry"
            adjudication["judgments"]["disposition"]["rationale"] = "Reviewed."
            adjudication["judgments"]["suspicion"]["value"] = "present"
            with self.assertRaisesRegex(ValueError, "cannot override agreed"):
                validate_adjudication(adjudication, root)


if __name__ == "__main__":
    unittest.main()
