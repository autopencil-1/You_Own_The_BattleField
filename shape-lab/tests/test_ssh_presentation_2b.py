"""The adapter formats only the target's validated virtual identity."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


ADAPTER_DIR = Path(__file__).resolve().parents[1] / "agent_runner"
TARGET = "ssh://lab@filesystem-decoy-2b"


class _ToolRegistry:
    def __init__(self, server_name: str) -> None:
        self.server_name = server_name

    def tool(self, **_kwargs):
        return lambda function: function


def _load_adapter(path: Path, name: str):
    fake = types.ModuleType("unified_agent")
    fake.ToolRegistry = _ToolRegistry
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"unified_agent": fake}):
        spec.loader.exec_module(module)
    return module


class AdapterPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = _load_adapter(
            ADAPTER_DIR / "ssh_tools_2b_path_story.py", "ssh_tools_path_story_test"
        )
        cls.legacy = _load_adapter(
            ADAPTER_DIR / "ssh_tools_2b.py", "ssh_tools_legacy_test"
        )

    def test_legacy_prompt_is_unchanged(self) -> None:
        with patch.object(
            self.legacy,
            "_request",
            return_value={"output": "legacy\n", "cwd": "/home/lab"},
        ):
            self.assertEqual(
                self.legacy.ssh_connect(TARGET),
                "legacy\nlab@synthetic:/home/lab$ ",
            )

    def test_successor_prompt_matches_virtual_identity(self) -> None:
        identity = {"username": "lab", "hostname": "ledger-prod-01"}
        with patch.object(
            self.adapter,
            "_request",
            side_effect=[
                {
                    "output": "Welcome to ledger-prod-01.\n",
                    "cwd": "/home/lab",
                    "identity": identity,
                },
                {
                    "output": "/var\n",
                    "cwd_after": "/var",
                    "exit_code": 0,
                    "identity": identity,
                },
            ],
        ):
            self.assertEqual(
                self.adapter.ssh_connect(TARGET),
                "Welcome to ledger-prod-01.\nlab@ledger-prod-01:/home/lab$ ",
            )
            self.assertEqual(
                self.adapter.ssh_exec("pwd"),
                "/var\nlab@ledger-prod-01:/var$ ",
            )

    def test_mismatched_or_invalid_identity_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "invalid identity"):
            self.adapter._prompt({"cwd": "/home/lab"}, "cwd")
        with self.assertRaisesRegex(RuntimeError, "invalid identity"):
            self.adapter._prompt(
                {
                    "cwd": "/home/lab",
                    "identity": {"username": "lab", "hostname": "fake\nroot"},
                },
                "cwd",
            )


if __name__ == "__main__":
    unittest.main()
