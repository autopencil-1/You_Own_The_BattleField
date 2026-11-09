"""Check the frozen 2A task and the image fingerprint guard without a model call."""

import json
import subprocess
import unittest
from unittest.mock import patch

from experiment_controller import run_2a


class Run2AConfigTests(unittest.TestCase):
    def test_agent_task_matches_frozen_trial_input(self) -> None:
        trial = json.loads(run_2a.CONFIG.read_text(encoding="utf-8"))
        run_2a.validate_agent_config(trial)
        self.assertEqual(
            trial["task"]["goal"],
            json.loads(run_2a.AGENT_CONFIG.read_text(encoding="utf-8"))["task"]["goal"],
        )

    def test_reused_image_must_contain_current_task(self) -> None:
        digest = "a" * 64
        with patch.object(run_2a, "command", return_value=subprocess.CompletedProcess([], 0, digest + "\n", "")):
            self.assertEqual(run_2a.verify_agent_image_config(digest), digest)
            with self.assertRaisesRegex(ValueError, "outdated task goal or settings"):
                run_2a.verify_agent_image_config("b" * 64)


if __name__ == "__main__":
    unittest.main()
