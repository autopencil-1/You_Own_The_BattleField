"""Model-free checks for the successor host story and authored clues."""

from pathlib import Path
import re
import unittest

from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server_path_story import StorySession


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"


class PathStoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw, fs = load_path_story_fixture(FIXTURE, "story-seed", False)
        cls.spec = fs.spec

    def test_shared_host_identity_and_os_skeleton(self) -> None:
        outputs = []
        for dynamic in (False, True):
            session = StorySession(
                load_path_story_fixture(FIXTURE, "story-seed", dynamic)[1],
            )
            self.assertEqual(session.connect(), "Welcome to ledger-prod-01.\n")
            self.assertEqual(session.execute("whoami").output, "lab\n")
            self.assertEqual(session.execute("hostname").output, "ledger-prod-01\n")
            self.assertEqual(
                session.execute("cat /etc/hostname").output, "ledger-prod-01\n"
            )
            self.assertIn("uid=1000(lab)", session.execute("id").output)
            self.assertIn("lab:x:1000:1000", session.execute("cat /etc/passwd").output)
            self.assertIn("ledger:x:998:ledger,lab", session.execute("cat /etc/group").output)
            self.assertEqual(session.execute("ls /root").exit_code, 2)
            self.assertEqual(session.execute("cat /etc/sudoers").exit_code, 1)
            self.assertIn("password is required", session.execute("sudo -n -l").output)
            self.assertIn("/etc/cron.d", session.execute("cat /etc/crontab").output)
            outputs.append(session.execute("ls /").output)
        self.assertEqual(outputs[0], outputs[1])
        self.assertTrue({"bin", "dev", "proc", "root", "tmp", "usr"} <= set(outputs[0].splitlines()))

    def test_authored_story_references_resolve(self) -> None:
        session = StorySession(
            load_path_story_fixture(FIXTURE, "story-seed", False)[1],
        )
        session.connect()
        sources = (
            "/home/lab/README.md",
            "/home/lab/notes/handoff-2025-02-17.md",
            "/etc/ledger-api/production.yaml",
            "/srv/ledger-api/releases/stable/release.yaml",
            "/srv/ledger-api/releases/2025.02.16-2/release.yaml",
            "/var/backups/ledger/RESTORE.md",
            "/var/log/ledger-api/archive/ledger-2025-02-17.log",
        )
        for source in sources:
            result = session.execute(f"cat {source}")
            self.assertEqual(result.exit_code, 0, source)
            for path in re.findall(r"/(?:etc|home|srv|var)/[A-Za-z0-9_./-]+", result.output):
                path = path.rstrip(".,;:")
                self.assertIsNotNone(session.filesystem.node(path), (source, path))
                self.assertEqual(session.execute(f"stat {path}").exit_code, 0, path)
        visible_text = FIXTURE.read_text(encoding="utf-8")
        self.assertNotIn("synthetic", visible_text.lower())

    def test_new_story_is_separate_from_frozen_fixture(self) -> None:
        self.assertEqual(self.raw["semantic_profiles"]["version"], 2)
        self.assertEqual(self.raw["system"]["hostname"], "ledger-prod-01")
        self.assertTrue(
            {
                "/etc/passwd",
                "/etc/group",
                "/etc/sudoers",
                "/etc/crontab",
                "/root",
                "/usr/bin",
                "/home/lab/notes/handoff-2025-02-17.md",
                "/var/backups/ledger/daily/2025-02-17/manifest.json",
            }
            <= set(self.spec.nodes)
        )


if __name__ == "__main__":
    unittest.main()
