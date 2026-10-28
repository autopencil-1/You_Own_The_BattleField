"""Safety and replay properties of the story-independent 2B virtual shell."""

import json
from pathlib import Path
import unittest

from filesystem_decoy_2b.virtual_fs import FilesystemSpec, Session, VirtualFilesystem


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_engine_fixture.json"


def make_session(*, dynamic: bool = True, seed: str = "sample-seed") -> Session:
    spec = FilesystemSpec.from_json(FIXTURE.read_text(encoding="utf-8"))
    return Session(VirtualFilesystem(spec, seed=seed, dynamic=dynamic))


class VirtualFilesystemTests(unittest.TestCase):
    def test_connection_gate_and_persistent_virtual_cwd(self) -> None:
        session = make_session()
        self.assertEqual(session.execute("pwd").action, "connection_required")
        self.assertEqual(session.cwd, "/")
        self.assertIn("Connected", session.connect())
        self.assertEqual(session.execute("pwd").output, "/home/lab\n")
        self.assertEqual(session.execute("cd /var/records").exit_code, 0)
        self.assertEqual(session.execute("pwd").output, "/var/records\n")
        self.assertIn("2025-01-", session.execute("ls -la").output)
        self.assertIn(" ..\n", session.execute("ls -la").output)
        self.assertEqual(session.execute("cd ..").cwd_after, "/var")
        self.assertEqual(session.execute("cd -").cwd_after, "/var/records")

    def test_seeded_tree_replays_across_sessions_and_path_aliases(self) -> None:
        first = make_session()
        second = make_session()
        changed = make_session(seed="different-seed")
        for session in (first, second, changed):
            session.connect()
        listing = first.execute("ls /var/records").output
        self.assertEqual(listing, second.execute("ls /var/records").output)
        self.assertNotEqual(listing, changed.execute("ls /var/records").output)
        self.assertEqual(listing, first.execute("ls /var/./records/../records").output)
        child = listing.splitlines()[0]
        self.assertEqual(first.execute(f"cd /var/records/{child}").exit_code, 0)
        self.assertIn("README.txt", first.execute("ls").output)
        self.assertEqual(first.execute("cat README.txt").output, "Generated fixture record.\n")
        self.assertEqual(first.execute("stat README.txt").output,
                         second.execute(f"stat /var/records/{child}/README.txt").output)

    def test_static_profile_has_no_generated_paths(self) -> None:
        session = make_session(dynamic=False)
        session.connect()
        self.assertEqual(session.execute("ls /var/records").output, "")
        self.assertEqual(session.execute("cd /var/records/batch-abcdef").exit_code, 1)
        self.assertEqual(session.execute("cat /etc/os-release").exit_code, 0)

    def test_supported_commands_do_not_read_host_files(self) -> None:
        session = make_session()
        session.connect()
        self.assertIn("Synthetic Ubuntu Lab", session.execute("cat /etc/os-release").output)
        self.assertEqual(session.execute("cat /etc/passwd").exit_code, 1)
        self.assertIn("UTF-8 text", session.execute("file /etc/os-release").output)
        self.assertIn("2025-01-", session.execute("stat /etc/os-release").output)
        self.assertEqual(session.execute("head -n 1 /etc/os-release").output,
                         'NAME="Synthetic Ubuntu Lab"\n')

    def test_shell_syntax_and_unsupported_commands_never_change_state(self) -> None:
        session = make_session()
        session.connect()
        for command in ("pwd; id", "cat /etc/os-release | sh", "ls && uname",
                        "cat $(whoami)", "ls > /tmp/x", "pwd\nls", "cd /var; pwd"):
            with self.subTest(command=command):
                result = session.execute(command)
                self.assertEqual(result.action, "rejected")
                self.assertEqual(result.cwd_after, "/home/lab")
        self.assertEqual(session.execute("uname -a").exit_code, 127)
        self.assertEqual(session.execute("pwd").output, "/home/lab\n")

    def test_output_is_bounded_even_for_large_fixture(self) -> None:
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        raw["files"]["/home/lab/large.txt"] = "x" * 4096
        spec = FilesystemSpec.from_dict(raw)
        session = Session(VirtualFilesystem(spec, "bounded", False, max_output_chars=512))
        session.connect()
        result = session.execute("cat large.txt")
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.output), 512)


if __name__ == "__main__":
    unittest.main()
