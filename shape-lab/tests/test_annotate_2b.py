"""Checks for arm-label-blinded, hash-addressed 2B review packets."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from telemetry.annotate_2b import project_trace_records


class Annotate2BTests(unittest.TestCase):
    def test_projection_removes_structured_arm_labels_and_hashes_raw_lines(
        self,
    ) -> None:
        run_id = "2b-pilo-review"
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / run_id
            trace = (
                run_dir
                / "agent"
                / "runs"
                / run_id
                / "traces"
                / "executor-one"
                / "events.jsonl"
            )
            trace.parent.mkdir(parents=True)
            eligible = (
                json.dumps(
                    {
                        "type": "assistant_text",
                        "condition": "B3",
                        "study_protocol": "2b-controlled-v2",
                        "study_fingerprint": {"images": {"agent": "secret"}},
                        "controlled_contract_sha256": "a" * 64,
                        "controlled_contract_schema_version": 1,
                        "assignment": {
                            "study_id": "2b-study-secret",
                            "slot": 7,
                            "block": 2,
                            "arm": "B3",
                            "factors": {
                                "structure": True,
                                "reinforcement": True,
                            },
                        },
                        "metadata": {"SHAPE_ARM": "B3", "safe": "kept"},
                        "text": "Continue examining the backup tree.",
                    },
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
            ignored = b'{"type":"raw_event","condition":"B3"}\n'
            trace.write_bytes(eligible + ignored)

            records = project_trace_records(run_dir, run_id)

        self.assertEqual(len(records), 1)
        self.assertNotIn("condition", records[0]["record"])
        self.assertNotIn("study_protocol", records[0]["record"])
        self.assertNotIn("study_fingerprint", records[0]["record"])
        self.assertNotIn("controlled_contract_sha256", records[0]["record"])
        self.assertNotIn(
            "controlled_contract_schema_version", records[0]["record"]
        )
        self.assertNotIn("assignment", records[0]["record"])
        self.assertEqual(records[0]["record"]["metadata"], {"safe": "kept"})
        self.assertEqual(
            records[0]["record"]["text"],
            "Continue examining the backup tree.",
        )
        self.assertEqual(
            records[0]["evidence"]["sha256"], hashlib.sha256(eligible).hexdigest()
        )
        self.assertEqual(records[0]["evidence"]["line"], 1)

    def test_projection_orders_multiple_trace_files_by_recorded_time(self) -> None:
        run_id = "2b-cont-chronology"
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / run_id
            root = run_dir / "agent" / "runs" / run_id / "traces"
            late = root / "a-executor" / "events.jsonl"
            early = root / "z-supervisor" / "events.jsonl"
            late.parent.mkdir(parents=True)
            early.parent.mkdir(parents=True)
            late.write_text(
                json.dumps(
                    {"type": "assistant_text", "recorded_at": 20.0, "text": "late"}
                )
                + "\n"
            )
            early.write_text(
                json.dumps(
                    {"type": "assistant_text", "recorded_at": 10.0, "text": "early"}
                )
                + "\n"
            )

            records = project_trace_records(run_dir, run_id)

        self.assertEqual(
            [item["record"]["text"] for item in records], ["early", "late"]
        )


if __name__ == "__main__":
    unittest.main()
