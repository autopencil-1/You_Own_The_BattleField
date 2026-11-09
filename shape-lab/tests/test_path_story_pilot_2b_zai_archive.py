"""The frozen v3 archive remains inspectable after Docker image rebuilds."""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from experiment_controller import path_story_pilot_2b_zai_archive as archive
from experiment_controller import path_story_pilot_2b_v2 as prior


class ZaiArchiveTests(unittest.TestCase):
    def test_archival_status_uses_evidence_without_current_docker_tags(self) -> None:
        with patch.object(prior, "_image_id", side_effect=AssertionError("Docker image lookup")), patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess call")
        ):
            status = archive.archive_status()
        self.assertTrue(status["schedule_verified"])
        self.assertFalse(status["current_docker_tags_checked"])
        self.assertFalse(status["execution_available"])
        self.assertEqual(status["valid_runs"], 0)
        self.assertEqual(status["next_slot"], 1)
        self.assertEqual(status["estimated_total_credits"], "100.809835000")
        self.assertEqual(status["attempts"][0]["classification"], "controller_error")
        self.assertTrue(status["attempts"][0]["replay_verified"])
        self.assertEqual(status["attempts"][0]["gateway_lifecycle"]["started_request_count"], 35)

    def test_pinned_schedule_digest_is_required(self) -> None:
        with patch.object(archive, "SCHEDULE_SHA256", "0" * 64):
            with self.assertRaisesRegex(archive.ArchiveIntegrityError, "schedule SHA-256"):
                archive.archive_status()


if __name__ == "__main__":
    unittest.main()
