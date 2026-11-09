"""The pinned v4 Z.ai archive can be verified after Docker image rebuilds."""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from experiment_controller import path_story_pilot_2b_v2 as prior
from experiment_controller import path_story_pilot_2b_zai_v4_archive as archive


class ZaiV4ArchiveTests(unittest.TestCase):
    def test_three_attempt_archive_without_current_docker_images(self) -> None:
        with patch.object(prior, "_image_id", side_effect=AssertionError("Docker image lookup")), patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess call")
        ):
            status = archive.archive_status()
        self.assertTrue(status["schedule_verified"])
        self.assertFalse(status["current_docker_tags_checked"])
        self.assertFalse(status["execution_available"])
        self.assertEqual(status["completed_slots"], [1, 2])
        self.assertEqual(status["next_slot"], 3)
        self.assertEqual(
            [row["classification"] for row in status["attempts"]],
            ["valid", "valid", "controller_error"],
        )
        self.assertEqual(status["estimated_v4_credits"], "817.233025000")
        self.assertEqual(status["predecessor_v3"]["estimated_credits"], "100.809835000")
        self.assertEqual(status["estimated_total_including_v3_carry"], "918.042860000")
        self.assertTrue(all(row["replay_verified"] for row in status["attempts"]))

    def test_pinned_schedule_digest_is_required(self) -> None:
        with patch.object(archive, "SCHEDULE_SHA256", "0" * 64):
            with self.assertRaisesRegex(archive.ArchiveIntegrityError, "schedule SHA-256"):
                archive.archive_status()

    def test_pinned_attempt_digest_is_required(self) -> None:
        changed = {run: dict(hashes) for run, hashes in archive.RUN_HASHES.items()}
        changed["2b-path-20261109152656-9f0b8f"]["gateway_events"] = "0" * 64
        with patch.object(archive, "RUN_HASHES", changed):
            with self.assertRaisesRegex(archive.ArchiveIntegrityError, "result or journal SHA-256"):
                archive.archive_status()


if __name__ == "__main__":
    unittest.main()
