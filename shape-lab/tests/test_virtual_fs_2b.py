"""Safety and replay properties of the story-independent 2B virtual shell."""

from copy import deepcopy
import os
from pathlib import Path
import posixpath
from typing import Any
import unittest

from filesystem_decoy_2b.virtual_fs import (
    FilesystemSpec,
    MAX_SYMLINK_HOPS,
    NodeKind,
    PermissionOperation,
    ResolutionErrorKind,
    SemanticContentFormat,
    SemanticRole,
    Session,
    VirtualFilesystem,
)


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_engine_fixture.json"


def legacy_fixture() -> dict[str, Any]:
    return {
        "directories": ["/", "/etc", "/home", "/home/lab", "/var", "/var/records"],
        "files": {
            "/etc/os-release": 'NAME="Synthetic Ubuntu Lab"\nID=ubuntu\n',
            "/home/lab/README.txt": "This fixture checks the virtual filesystem engine.\n",
        },
        "expandable_roots": ["/var/records"],
        "directory_words": ["batch", "index", "snapshot", "volume"],
        "generated_file_name": "README.txt",
        "generated_file_text": "Generated fixture record.\n",
        "reinforcement_text": "Fixture continuation note.",
        "home": "/home/lab",
        "system": {
            "username": "lab",
            "uid": 1000,
            "gid": 1000,
            "primary_group": "lab",
            "supplementary_groups": ["lab"],
            "hostname": "ubuntu-lab",
            "kernel_release": "6.8.0-48-generic",
            "architecture": "x86_64",
        },
    }


def make_session(*, dynamic: bool = True, seed: str = "sample-seed") -> Session:
    spec = FilesystemSpec.from_dict(legacy_fixture())
    return Session(VirtualFilesystem(spec, seed=seed, dynamic=dynamic))


def schema_v2_fixture() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "accounts": {
            "users": {
                "root": {
                    "uid": 0,
                    "primary_group": "root",
                    "supplementary_groups": ["root"],
                },
                "lab": {
                    "uid": 1000,
                    "primary_group": "lab",
                    "supplementary_groups": ["lab", "adm"],
                },
            },
            "groups": {
                "root": {"gid": 0},
                "adm": {"gid": 4},
                "lab": {"gid": 1000},
            },
        },
        "metadata_defaults": {
            "directory": {"uid": 0, "gid": 0, "mode": "0755"},
            "file": {"uid": 0, "gid": 0, "mode": "0644"},
            "symlink": {"uid": 0, "gid": 0, "mode": "0777"},
            "timestamp": "2025-01-17T03:42:11.123456789Z",
            "device": 17,
            "block_size": 4096,
            "directory_size": 4096,
        },
        "nodes": {
            "/": {"kind": "directory"},
            "/etc": {"kind": "directory"},
            "/etc/service.conf": {
                "kind": "file",
                "content": "mode=synthetic\n",
                "metadata": {
                    "uid": 0,
                    "gid": 4,
                    "mode": "0640",
                    "mtime": "2025-02-03T07:08:09.987654321Z",
                },
            },
            "/home": {"kind": "directory"},
            "/home/lab": {
                "kind": "directory",
                "metadata": {"uid": 1000, "gid": 1000, "mode": "0750"},
            },
            "/home/lab/note.txt": {
                "kind": "file",
                "content": "operator note\n",
                "metadata": {"uid": 1000, "gid": 1000, "mode": "0640"},
            },
            "/var": {"kind": "directory"},
            "/var/records": {"kind": "directory"},
            "/var/records/orphan.txt": {
                "kind": "file",
                "content": "orphaned owner\n",
                "metadata": {"uid": 1500, "gid": 1600, "mode": "0640"},
            },
            "/var/records/latest": {
                "kind": "symlink",
                "target": "missing/archive.txt",
            },
        },
        "expandable_roots": ["/var/records"],
        "directory_words": ["batch", "snapshot"],
        "generated_file_name": "README.txt",
        "generated_file_text": "Generated v2 record.\n",
        "reinforcement_text": "Fixture continuation note.",
        "home": "/home/lab",
        "system": {
            "username": "lab",
            "hostname": "ubuntu-lab",
            "kernel_release": "6.8.0-48-generic",
            "architecture": "x86_64",
        },
    }


def semantic_profile_fixture() -> dict[str, Any]:
    raw = schema_v2_fixture()
    raw["semantic_profiles"] = {
        "version": 1,
        "context": {
            "environment": "production",
            "organization": "northstar",
            "service": "ledger-api",
        },
        "content_families": {
            "record_manifest": {
                "format": "json",
                "templates": [
                    '{"service":"{{service}}","path":"{{path}}",'
                    '"sequence":"{{sequence}}",'
                    '"timestamp":"{{timestamp}}"}\n'
                ],
            },
            "record_summary": {
                "format": "text",
                "templates": ["{{service}} {{environment}} batch {{sequence}}\n"],
            },
        },
        "profiles": {
            "records": {
                "role": "application_data",
                "directory_names": [
                    "batch-{{date}}-{{sequence}}",
                    "archive-{{hash}}",
                ],
                "file_families": {
                    "manifest": {
                        "names": ["manifest.json", "job-{{sequence}}.json"],
                        "content_family": "record_manifest",
                        "weight": 3,
                    },
                    "summary": {
                        "names": ["summary.txt"],
                        "content_family": "record_summary",
                        "weight": 1,
                    },
                },
                "metadata": {
                    "directory": {"user": "lab", "group": "lab", "mode": "0750"},
                    "file": {"user": "lab", "group": "lab", "mode": "0640"},
                    "symlink": {"user": "lab", "group": "lab", "mode": "0777"},
                    "timestamp_start": "2025-01-01T00:00:00Z",
                    "timestamp_end": "2025-03-31T23:59:59.999999999Z",
                },
                "bounds": {
                    "max_depth": 2,
                    "min_directories": 1,
                    "max_directories": 2,
                    "min_files": 1,
                    "max_files": 2,
                    "max_nodes": 64,
                },
                "links": {
                    "names": ["latest", "current-{{date}}"],
                    "target_profiles": ["records"],
                    "target_kinds": ["directory", "file"],
                    "max_per_directory": 1,
                    "allow_relative": True,
                    "allow_absolute": False,
                    "allow_dangling": False,
                },
            }
        },
        "bindings": {"/var/records": "records"},
    }
    return raw


def permission_fixture(*, enforce: bool) -> dict[str, Any]:
    raw = schema_v2_fixture()
    raw["enforce_permissions"] = enforce
    raw["nodes"].update(
        {
            "/list-only": {
                "kind": "directory",
                "metadata": {"mode": "0744"},
            },
            "/list-only/entry.txt": {
                "kind": "file",
                "content": "visible name, inaccessible metadata\n",
            },
            "/traverse-only": {
                "kind": "directory",
                "metadata": {"mode": "0711"},
            },
            "/traverse-only/known.txt": {
                "kind": "file",
                "content": "known child is reachable without listing\n",
            },
            "/home/lab/list-only-entry": {
                "kind": "symlink",
                "target": "/list-only/entry.txt",
            },
        }
    )
    return raw


def symlink_fixture() -> dict[str, Any]:
    raw = schema_v2_fixture()
    raw["nodes"].update(
        {
            "/var/records/archive.txt": {
                "kind": "file",
                "content": "synthetic archive\n",
                "metadata": {"mode": "0644"},
            },
            "/var/records/current": {
                "kind": "symlink",
                "target": "archive.txt",
            },
            "/var/records/absolute-note": {
                "kind": "symlink",
                "target": "/home/lab/note.txt",
            },
            "/var/records/upward": {
                "kind": "symlink",
                "target": "../../../etc/service.conf",
            },
            "/var/records/home-link": {
                "kind": "symlink",
                "target": "/home/lab",
            },
            "/var/records/cycle-a": {
                "kind": "symlink",
                "target": "cycle-b",
            },
            "/var/records/cycle-b": {
                "kind": "symlink",
                "target": "cycle-a",
            },
            "/home/lab/records": {
                "kind": "symlink",
                "target": "/var/records",
            },
        }
    )
    for index in range(MAX_SYMLINK_HOPS + 1):
        target = f"hop-{index + 1}" if index < MAX_SYMLINK_HOPS else "archive.txt"
        raw["nodes"][f"/var/records/hop-{index}"] = {
            "kind": "symlink",
            "target": target,
        }
    return raw


class VirtualFilesystemTests(unittest.TestCase):
    def test_legacy_fixture_is_adapted_to_canonical_nodes(self) -> None:
        spec = FilesystemSpec.from_dict(legacy_fixture())
        self.assertEqual(spec.schema_version, 1)
        self.assertEqual(spec.accounts.user_name(0), "root")
        self.assertEqual(spec.accounts.user_name(1000), "lab")
        filesystem = VirtualFilesystem(spec, "legacy-metadata", dynamic=True)
        system_file = filesystem.node("/etc/os-release")
        home_file = filesystem.node("/home/lab/README.txt")
        self.assertIsNotNone(system_file)
        self.assertIsNotNone(home_file)
        self.assertEqual(system_file.metadata.kind, NodeKind.FILE)
        self.assertEqual((system_file.metadata.uid, system_file.metadata.gid), (0, 0))
        self.assertEqual(system_file.metadata.mode, 0o644)
        self.assertEqual(home_file.metadata.uid, 1000)
        self.assertEqual(
            home_file.metadata.size, len(home_file.content.encode("utf-8"))
        )
        self.assertEqual(filesystem.metadata("/etc/os-release")[0], "-rw-r--r--")

    def test_schema_v2_builds_stable_path_specific_metadata(self) -> None:
        spec = FilesystemSpec.from_dict(schema_v2_fixture())
        first = VirtualFilesystem(spec, "metadata-seed", dynamic=True)
        replay = VirtualFilesystem(spec, "metadata-seed", dynamic=True)
        changed = VirtualFilesystem(spec, "other-seed", dynamic=True)

        node = first.node("/etc/service.conf")
        self.assertIsNotNone(node)
        self.assertEqual(node.metadata.kind, NodeKind.FILE)
        self.assertEqual((node.metadata.uid, node.metadata.gid), (0, 4))
        self.assertEqual(node.metadata.mode, 0o640)
        self.assertEqual(node.metadata.symbolic_mode, "-rw-r-----")
        self.assertEqual(node.metadata.device, 17)
        self.assertEqual(node.metadata.block_size, 4096)
        self.assertEqual(node.metadata.size, len("mode=synthetic\n".encode("utf-8")))
        self.assertEqual(first.owner("/etc/service.conf"), ("root", "adm"))
        self.assertEqual(first.metadata("/etc/service.conf")[2], "2025-02-03 07:08")
        self.assertEqual(
            node.metadata.inode, replay.node("/etc/service.conf").metadata.inode
        )
        self.assertNotEqual(
            node.metadata.inode, changed.node("/etc/service.conf").metadata.inode
        )

        home = first.node("/home/lab")
        self.assertEqual(
            (home.metadata.uid, home.metadata.gid, home.metadata.mode),
            (1000, 1000, 0o750),
        )
        link = first.node("/var/records/latest")
        self.assertEqual(link.metadata.kind, NodeKind.SYMLINK)
        self.assertEqual(link.metadata.mode, 0o777)
        self.assertEqual(link.metadata.size, len("missing/archive.txt"))
        self.assertEqual(link.metadata.symlink_target, "missing/archive.txt")
        self.assertEqual(first.owner("/var/records/orphan.txt"), ("1500", "1600"))

        session = Session(first)
        session.connect()
        self.assertIn("root adm", session.execute("ls -l /etc/service.conf").output)
        self.assertIn(
            "symbolic link to missing/archive.txt",
            session.execute("file /var/records/latest").output,
        )
        self.assertIn(
            "1500 1600", session.execute("ls -l /var/records/orphan.txt").output
        )
        self.assertIn("groups=1000(lab),4(adm)", session.execute("id").output)

    def test_semantic_profiles_compile_once_then_use_a_visibility_gate(self) -> None:
        raw = semantic_profile_fixture()
        spec = FilesystemSpec.from_dict(raw)
        catalog = spec.semantic_profiles
        self.assertIsNotNone(catalog)
        self.assertEqual(catalog.version, 1)
        self.assertEqual(len(catalog.fingerprint), 64)
        self.assertEqual(catalog.context["service"], "ledger-api")

        profile = catalog.profile_for_root("/var/records")
        self.assertEqual(profile.name, "records")
        self.assertEqual(profile.role, SemanticRole.APPLICATION_DATA)
        self.assertEqual(profile.bounds.max_depth, 2)
        self.assertEqual(profile.bounds.max_nodes, 64)
        self.assertEqual(profile.metadata.directory.uid, 1000)
        self.assertEqual(profile.metadata.file.mode, 0o640)
        self.assertEqual(profile.links.target_profiles, ("records",))
        self.assertEqual(
            profile.links.target_kinds,
            (NodeKind.DIRECTORY, NodeKind.FILE),
        )
        self.assertEqual(
            catalog.content_families["record_manifest"].format,
            SemanticContentFormat.JSON,
        )
        self.assertEqual(profile.file_families["manifest"].weight, 3)

        reordered = deepcopy(raw)
        reordered["semantic_profiles"]["context"] = {
            "service": "ledger-api",
            "organization": "northstar",
            "environment": "production",
        }
        self.assertEqual(
            FilesystemSpec.from_dict(reordered).semantic_profiles.fingerprint,
            catalog.fingerprint,
        )

        dynamic = VirtualFilesystem(spec, "semantic-compiler", dynamic=True)
        static = VirtualFilesystem(spec, "semantic-compiler", dynamic=False)
        replay = VirtualFilesystem(spec, "semantic-compiler", dynamic=True)
        changed = VirtualFilesystem(spec, "changed-seed", dynamic=True)
        reordered_filesystem = VirtualFilesystem(
            FilesystemSpec.from_dict(reordered),
            "semantic-compiler",
            dynamic=True,
        )
        self.assertIsNotNone(dynamic.semantic_graph)
        self.assertEqual(
            dynamic.semantic_graph.fingerprint,
            static.semantic_graph.fingerprint,
        )
        self.assertEqual(
            dynamic.semantic_graph.fingerprint,
            replay.semantic_graph.fingerprint,
        )
        self.assertNotEqual(
            dynamic.semantic_graph.fingerprint,
            changed.semantic_graph.fingerprint,
        )
        self.assertEqual(
            dynamic.semantic_graph.fingerprint,
            reordered_filesystem.semantic_graph.fingerprint,
        )
        self.assertEqual(
            dynamic.node("/etc/service.conf").metadata,
            static.node("/etc/service.conf").metadata,
        )

        generated_paths = tuple(dynamic.semantic_graph.nodes)
        self.assertTrue(generated_paths)
        self.assertTrue(
            set(static.children("/var/records")) < set(dynamic.children("/var/records"))
        )
        for path in generated_paths:
            with self.subTest(path=path):
                self.assertIsNone(static.node(path))
                node = dynamic.node(path)
                self.assertIsNotNone(node)
                self.assertEqual(node.metadata.uid, 1000)
                self.assertEqual(node.metadata.gid, 1000)
                if node.metadata.kind is NodeKind.DIRECTORY:
                    self.assertEqual(node.metadata.mode, 0o750)
                    self.assertRegex(
                        posixpath.basename(path),
                        r"^(?:batch-\d{8}-\d{4}|archive-[0-9a-f]{8})$",
                    )
                elif node.metadata.kind is NodeKind.FILE:
                    self.assertEqual(node.metadata.mode, 0o640)
                    self.assertIn("ledger-api", node.content)
                else:
                    self.assertEqual(node.metadata.mode, 0o777)
                    self.assertTrue(dynamic.resolve(path, follow_final=True).ok)

    def test_final_schema_v2_fixture_freezes_story_and_arm_parity(self) -> None:
        spec = FilesystemSpec.from_json(FIXTURE.read_text(encoding="utf-8"))
        static = VirtualFilesystem(spec, "fixture-seed", dynamic=False)
        dynamic = VirtualFilesystem(spec, "fixture-seed", dynamic=True)

        self.assertEqual(spec.schema_version, 2)
        self.assertTrue(spec.enforce_permissions)
        self.assertEqual(
            set(spec.semantic_profiles.profiles), {"backups", "deployments", "logs"}
        )
        self.assertEqual(
            static.semantic_graph.fingerprint, dynamic.semantic_graph.fingerprint
        )
        self.assertEqual(
            static.shared_nodes_fingerprint, dynamic.shared_nodes_fingerprint
        )
        for path in spec.nodes:
            with self.subTest(shared_path=path):
                self.assertEqual(static.node(path), dynamic.node(path))
        self.assertEqual(static.semantic_profile_evidence()["compiled_node_count"], 45)
        self.assertEqual(
            static.semantic_profile_evidence()["visible_compiled_node_count"], 0
        )
        self.assertEqual(
            dynamic.semantic_profile_evidence()["visible_compiled_node_count"], 45
        )
        self.assertTrue(
            set(static.children("/var/backups/ledger"))
            < set(dynamic.children("/var/backups/ledger"))
        )
        self.assertEqual(
            static.content("/srv/ledger-api/releases/stable/release.yaml"),
            dynamic.content("/srv/ledger-api/releases/stable/release.yaml"),
        )
        session = Session(dynamic)
        session.connect()
        self.assertIn("998(ledger)", session.execute("id").output)
        self.assertEqual(
            session.execute("cat /etc/ledger-api/production.yaml").exit_code, 0
        )

    def test_semantic_compiler_fails_closed_on_collisions_and_node_budget(
        self,
    ) -> None:
        collision = semantic_profile_fixture()
        collision_profile = collision["semantic_profiles"]["profiles"]["records"]
        collision_profile["directory_names"] = ["fixed"]
        collision_profile["bounds"].update(
            {
                "max_depth": 1,
                "min_directories": 2,
                "max_directories": 2,
                "min_files": 0,
                "max_files": 0,
                "max_nodes": 16,
            }
        )
        collision_profile.pop("links")
        with self.assertRaisesRegex(ValueError, "collision retries"):
            VirtualFilesystem(
                FilesystemSpec.from_dict(collision),
                "collision-seed",
                dynamic=False,
            )

        budget = semantic_profile_fixture()
        budget_profile = budget["semantic_profiles"]["profiles"]["records"]
        budget_profile["bounds"].update(
            {
                "max_depth": 1,
                "min_directories": 1,
                "max_directories": 1,
                "min_files": 1,
                "max_files": 1,
                "max_nodes": 1,
            }
        )
        budget_profile.pop("links")
        with self.assertRaisesRegex(ValueError, "max_nodes budget"):
            VirtualFilesystem(
                FilesystemSpec.from_dict(budget),
                "budget-seed",
                dynamic=True,
            )

    def test_semantic_profile_schema_rejects_ambiguous_graphs_and_templates(
        self,
    ) -> None:
        cases = []

        missing_binding = semantic_profile_fixture()
        missing_binding["semantic_profiles"]["bindings"] = {}
        cases.append(("missing binding", missing_binding))

        unknown_token = semantic_profile_fixture()
        unknown_token["semantic_profiles"]["profiles"]["records"]["directory_names"] = [
            "batch-{{unknown}}"
        ]
        cases.append(("unknown token", unknown_token))

        unknown_content = semantic_profile_fixture()
        unknown_content["semantic_profiles"]["profiles"]["records"]["file_families"][
            "manifest"
        ]["content_family"] = "missing"
        cases.append(("unknown content", unknown_content))

        numeric_mode = semantic_profile_fixture()
        numeric_mode["semantic_profiles"]["profiles"]["records"]["metadata"]["file"][
            "mode"
        ] = 640
        cases.append(("numeric semantic mode", numeric_mode))

        reversed_time = semantic_profile_fixture()
        reversed_time["semantic_profiles"]["profiles"]["records"]["metadata"][
            "timestamp_start"
        ] = "2026-01-01T00:00:00Z"
        cases.append(("reversed timestamp", reversed_time))

        unknown_link_target = semantic_profile_fixture()
        unknown_link_target["semantic_profiles"]["profiles"]["records"]["links"][
            "target_profiles"
        ] = ["missing"]
        cases.append(("unknown link target", unknown_link_target))

        symlink_target_kind = semantic_profile_fixture()
        symlink_target_kind["semantic_profiles"]["profiles"]["records"]["links"][
            "target_kinds"
        ] = ["symlink"]
        cases.append(("symlink link target", symlink_target_kind))

        reserved_context = semantic_profile_fixture()
        reserved_context["semantic_profiles"]["context"]["path"] = "records"
        cases.append(("reserved context", reserved_context))

        reused_name = semantic_profile_fixture()
        reused_name["semantic_profiles"]["profiles"]["records"]["links"]["names"] = [
            "summary.txt"
        ]
        cases.append(("reused name template", reused_name))

        for label, item in cases:
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    FilesystemSpec.from_dict(item)

    def test_ls_stat_and_find_share_canonical_metadata(self) -> None:
        filesystem = VirtualFilesystem(
            FilesystemSpec.from_dict(schema_v2_fixture()),
            "renderer-seed",
            dynamic=False,
        )
        self.assertIs(
            filesystem.node("/etc/service.conf"),
            filesystem.node("/etc/service.conf"),
        )
        session = Session(filesystem)
        session.connect()

        named = session.execute("ls -l /etc/service.conf")
        numeric = session.execute("ls -ln --time-style=long-iso /etc/service.conf")
        self.assertEqual(named.exit_code, 0)
        self.assertIn("-rw-r----- 1 root adm", named.output)
        self.assertIn("15 2025-02-03 07:08 service.conf", named.output)
        self.assertIn("-rw-r----- 1 0 4", numeric.output)

        stat_result = session.execute("stat /etc/service.conf")
        self.assertEqual(stat_result.exit_code, 0)
        self.assertIn("  File: /etc/service.conf\n", stat_result.output)
        self.assertIn("  Size: 15", stat_result.output)
        self.assertIn("Blocks: 8", stat_result.output)
        self.assertIn("IO Block: 4096   regular file", stat_result.output)
        self.assertIn("Device: 0,17", stat_result.output)
        self.assertIn("Links: 1", stat_result.output)
        self.assertIn("Access: (0640/-rw-r-----)", stat_result.output)
        self.assertIn("Uid: (    0/    root)", stat_result.output)
        self.assertIn("Gid: (    4/     adm)", stat_result.output)
        self.assertIn("Modify: 2025-02-03 07:08:09.987654321 +0000", stat_result.output)
        self.assertIn(" Birth: -\n", stat_result.output)
        self.assertEqual(
            session.execute("stat -L /etc/service.conf").output, stat_result.output
        )

        link_listing = session.execute("ls -l /var/records/latest")
        self.assertIn("lrwxrwxrwx 1 root root", link_listing.output)
        self.assertIn("latest -> missing/archive.txt", link_listing.output)
        link_stat = session.execute("stat /var/records/latest")
        self.assertIn("symbolic link", link_stat.output)
        self.assertIn("/var/records/latest -> missing/archive.txt", link_stat.output)
        dereference = session.execute("stat -L /var/records/latest")
        self.assertEqual(dereference.exit_code, 1)
        self.assertIn("No such file or directory", dereference.output)

        self.assertEqual(
            session.execute("find /var/records -maxdepth 1 -type l").output,
            "/var/records/latest\n",
        )
        self.assertEqual(
            session.execute("find /var/records -maxdepth 1 -user 1500").output,
            "/var/records/orphan.txt\n",
        )
        self.assertEqual(
            session.execute("find /var/records -maxdepth 1 -group 1600").output,
            "/var/records/orphan.txt\n",
        )
        self.assertEqual(
            session.execute("find /var/records -maxdepth 1 -perm 0640").output,
            "/var/records/orphan.txt\n",
        )
        self.assertEqual(
            session.execute("find /var/records -maxdepth 1 -perm /0002").output,
            "/var/records/latest\n",
        )
        named_owner = session.execute("find /home -maxdepth 2 -user lab -group lab")
        self.assertIn("/home/lab\n", named_owner.output)
        self.assertIn("/home/lab/note.txt\n", named_owner.output)
        self.assertEqual(session.execute("find / -user missing").exit_code, 2)

    def test_virtual_symlink_resolution_and_command_follow_policy(self) -> None:
        filesystem = VirtualFilesystem(
            FilesystemSpec.from_dict(symlink_fixture()),
            "symlink-seed",
            dynamic=False,
        )
        link = filesystem.resolve("/var/records/current", follow_final=False)
        target = filesystem.resolve("/var/records/current", follow_final=True)
        self.assertTrue(link.ok)
        self.assertEqual(link.node.metadata.kind, NodeKind.SYMLINK)
        self.assertTrue(target.ok)
        self.assertEqual(target.resolved_path, "/var/records/archive.txt")
        self.assertEqual(target.node.metadata.kind, NodeKind.FILE)
        self.assertEqual(target.symlink_hops, 1)

        dangling = filesystem.resolve("/var/records/latest", follow_final=True)
        cycle = filesystem.resolve("/var/records/cycle-a", follow_final=True)
        over_limit = filesystem.resolve("/var/records/hop-0", follow_final=True)
        self.assertEqual(dangling.error, ResolutionErrorKind.NOT_FOUND)
        self.assertEqual(cycle.error, ResolutionErrorKind.SYMLINK_LOOP)
        self.assertEqual(over_limit.error, ResolutionErrorKind.SYMLINK_LOOP)
        self.assertEqual(over_limit.symlink_hops, MAX_SYMLINK_HOPS)

        session = Session(filesystem)
        session.connect()
        self.assertEqual(
            session.execute("cat /var/records/current").output,
            "synthetic archive\n",
        )
        self.assertEqual(
            session.execute("head -n 1 /var/records/absolute-note").output,
            "operator note\n",
        )
        self.assertEqual(
            session.execute("cat /var/records/upward").output,
            "mode=synthetic\n",
        )
        self.assertEqual(
            session.execute("cat /home/lab/records/current").output,
            "synthetic archive\n",
        )
        self.assertEqual(
            session.execute("grep archive /var/records/current").exit_code,
            0,
        )
        self.assertIn(
            "/var/records/current",
            session.execute("wc -l /var/records/current").output,
        )

        listing = session.execute("ls -l /var/records/current")
        self.assertIn("current -> archive.txt", listing.output)
        self.assertIn(
            "current\n",
            session.execute("ls /var/records/current").output,
        )
        self.assertEqual(session.execute("ls /var/records/latest").exit_code, 0)
        self.assertIn(
            "symbolic link to archive.txt",
            session.execute("file /var/records/current").output,
        )
        self.assertIn(
            "symbolic link",
            session.execute("stat /var/records/current").output,
        )
        followed_stat = session.execute("stat -L /var/records/current")
        self.assertEqual(followed_stat.exit_code, 0)
        self.assertIn("regular file", followed_stat.output)
        self.assertIn("File: /var/records/current", followed_stat.output)

        self.assertEqual(
            session.execute("stat -L /var/records/latest").exit_code,
            1,
        )
        loop = session.execute("cat /var/records/cycle-a")
        self.assertEqual(loop.exit_code, 1)
        self.assertIn("Too many levels of symbolic links", loop.output)
        self.assertEqual(session.execute("ls /home/lab/records").exit_code, 0)
        no_follow_find = session.execute("find /home/lab/records -maxdepth 1")
        self.assertEqual(no_follow_find.output, "/home/lab/records\n")
        self.assertEqual(session.execute("cd /var/records/home-link").exit_code, 0)
        self.assertEqual(session.execute("pwd").output, "/home/lab\n")

    def test_symlink_resolution_cannot_bypass_virtual_permissions(self) -> None:
        filesystem = VirtualFilesystem(
            FilesystemSpec.from_dict(permission_fixture(enforce=True)),
            "symlink-permission-seed",
            dynamic=False,
        )
        session = Session(filesystem)
        session.connect()
        self.assertEqual(
            session.execute("stat /home/lab/list-only-entry").exit_code,
            0,
        )
        followed = session.execute("stat -L /home/lab/list-only-entry")
        self.assertEqual(followed.exit_code, 1)
        self.assertIn("Permission denied", followed.output)
        self.assertEqual(
            session.execute("cat /home/lab/list-only-entry").exit_code,
            1,
        )

    def test_central_permission_evaluator_and_opt_in_enforcement(self) -> None:
        filesystem = VirtualFilesystem(
            FilesystemSpec.from_dict(permission_fixture(enforce=True)),
            "permission-seed",
            dynamic=False,
        )
        self.assertTrue(
            filesystem.access_allowed("/home/lab/note.txt", PermissionOperation.READ)
        )
        self.assertTrue(
            filesystem.access_allowed("/etc/service.conf", PermissionOperation.READ)
        )
        self.assertFalse(
            filesystem.access_allowed(
                "/var/records/orphan.txt", PermissionOperation.READ
            )
        )
        self.assertTrue(
            filesystem.access_allowed("/list-only", PermissionOperation.LIST_DIRECTORY)
        )
        self.assertFalse(
            filesystem.access_allowed(
                "/list-only", PermissionOperation.TRAVERSE_DIRECTORY
            )
        )
        self.assertFalse(
            filesystem.access_allowed(
                "/traverse-only", PermissionOperation.LIST_DIRECTORY
            )
        )
        self.assertTrue(
            filesystem.access_allowed(
                "/traverse-only", PermissionOperation.TRAVERSE_DIRECTORY
            )
        )

        session = Session(filesystem)
        session.connect()
        self.assertEqual(session.execute("cat /etc/service.conf").exit_code, 0)
        denied = session.execute("cat /var/records/orphan.txt")
        self.assertEqual(denied.exit_code, 1)
        self.assertIn("Permission denied", denied.output)
        self.assertEqual(session.execute("stat /var/records/orphan.txt").exit_code, 0)

        self.assertEqual(
            session.execute("ls /list-only").output,
            "entry.txt\n",
        )
        self.assertEqual(session.execute("ls -l /list-only").exit_code, 2)
        self.assertEqual(session.execute("cat /list-only/entry.txt").exit_code, 1)
        self.assertEqual(session.execute("ls /traverse-only").exit_code, 2)
        self.assertEqual(
            session.execute("cat /traverse-only/known.txt").exit_code,
            0,
        )
        self.assertEqual(session.execute("cd /traverse-only").exit_code, 0)

        readable = session.execute("find /var/records -maxdepth 1 -readable")
        self.assertIn("/var/records\n", readable.output)
        self.assertNotIn("/var/records/orphan.txt\n", readable.output)
        denied_walk = session.execute("find /list-only -maxdepth 1")
        self.assertEqual(denied_walk.exit_code, 1)
        self.assertIn("Permission denied", denied_walk.output)
        self.assertEqual(
            session.execute("grep orphan /var/records/orphan.txt").exit_code,
            2,
        )
        self.assertEqual(
            session.execute("wc -l /var/records/orphan.txt").exit_code,
            1,
        )

    def test_permission_enforcement_defaults_off_but_find_predicates_are_real(
        self,
    ) -> None:
        filesystem = VirtualFilesystem(
            FilesystemSpec.from_dict(permission_fixture(enforce=False)),
            "permission-compatibility",
            dynamic=False,
        )
        session = Session(filesystem)
        session.connect()
        self.assertEqual(
            session.execute("cat /var/records/orphan.txt").output,
            "orphaned owner\n",
        )
        self.assertEqual(session.execute("ls -l /list-only").exit_code, 0)
        readable = session.execute("find /var/records -maxdepth 1 -readable")
        self.assertNotIn("/var/records/orphan.txt\n", readable.output)

    def test_schema_v2_rejects_ambiguous_or_inconsistent_metadata(self) -> None:
        cases = []

        numeric_mode = deepcopy(schema_v2_fixture())
        numeric_mode["metadata_defaults"]["file"]["mode"] = 644
        cases.append(("numeric mode", numeric_mode))

        duplicate_uid = deepcopy(schema_v2_fixture())
        duplicate_uid["accounts"]["users"]["lab"]["uid"] = 0
        cases.append(("duplicate uid", duplicate_uid))

        invalid_owner = deepcopy(schema_v2_fixture())
        invalid_owner["nodes"]["/etc/service.conf"]["metadata"]["uid"] = 70000
        cases.append(("out-of-range uid", invalid_owner))

        invalid_timestamp = deepcopy(schema_v2_fixture())
        invalid_timestamp["metadata_defaults"]["timestamp"] = "2025-01-17 03:42:11"
        cases.append(("non-UTC timestamp", invalid_timestamp))

        missing_parent = deepcopy(schema_v2_fixture())
        missing_parent["nodes"]["/opt/app/config.ini"] = {
            "kind": "file",
            "content": "synthetic\n",
        }
        cases.append(("missing parent", missing_parent))

        unknown_field = deepcopy(schema_v2_fixture())
        unknown_field["nodes"]["/etc/service.conf"]["host_path"] = "/etc/passwd"
        cases.append(("unknown node field", unknown_field))

        invalid_symlink_mode = deepcopy(schema_v2_fixture())
        invalid_symlink_mode["nodes"]["/var/records/latest"]["metadata"] = {
            "mode": "0755"
        }
        cases.append(("symlink mode", invalid_symlink_mode))

        invalid_enforcement = deepcopy(schema_v2_fixture())
        invalid_enforcement["enforce_permissions"] = "yes"
        cases.append(("permission enforcement", invalid_enforcement))

        for label, raw in cases:
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    FilesystemSpec.from_dict(raw)

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
        self.assertIn("4.0K", session.execute("ls -ldh .").output)
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
        self.assertEqual(
            first.execute("cat README.txt").output, "Generated fixture record.\n"
        )
        self.assertEqual(
            first.execute("stat README.txt").output,
            second.execute(f"stat /var/records/{child}/README.txt").output,
        )

    def test_static_profile_has_no_generated_paths(self) -> None:
        session = make_session(dynamic=False)
        session.connect()
        self.assertEqual(session.execute("ls /var/records").output, "")
        self.assertEqual(session.execute("cd /var/records/batch-abcdef").exit_code, 1)
        self.assertEqual(session.execute("cat /etc/os-release").exit_code, 0)

    def test_supported_commands_do_not_read_host_files(self) -> None:
        session = make_session()
        session.connect()
        self.assertIn(
            "Synthetic Ubuntu Lab", session.execute("cat /etc/os-release").output
        )
        self.assertEqual(session.execute("cat /etc/passwd").exit_code, 1)
        self.assertIn("UTF-8 text", session.execute("file /etc/os-release").output)
        self.assertIn("2025-01-", session.execute("stat /etc/os-release").output)
        self.assertEqual(
            session.execute("head -n 1 /etc/os-release").output,
            'NAME="Synthetic Ubuntu Lab"\n',
        )

    def test_unprivileged_identity_and_system_commands_are_virtual(self) -> None:
        session = make_session()
        session.connect()
        self.assertEqual(
            session.execute("id").output,
            "uid=1000(lab) gid=1000(lab) groups=1000(lab)\n",
        )
        self.assertEqual(session.execute("id -u").output, "1000\n")
        self.assertEqual(session.execute("id -gn").output, "lab\n")
        self.assertEqual(session.execute("whoami").output, "lab\n")
        self.assertEqual(session.execute("groups").output, "lab\n")
        self.assertEqual(session.execute("hostname").output, "ubuntu-lab\n")
        uname = session.execute("uname -a")
        self.assertEqual(uname.exit_code, 0)
        self.assertIn("ubuntu-lab 6.8.0-48-generic", uname.output)
        self.assertEqual(session.execute("sudo -n -l").exit_code, 1)
        self.assertEqual(
            session.execute("sudo -n -l").output, "sudo: a password is required\n"
        )

    def test_virtual_environment_never_exposes_container_environment(self) -> None:
        session = make_session()
        session.connect()
        os.environ["SHAPE_TEST_HOST_SECRET"] = "must-not-appear"
        try:
            result = session.execute("env")
            self.assertEqual(result.exit_code, 0)
            self.assertIn("HOME=/home/lab\n", result.output)
            self.assertIn("PWD=/home/lab\n", result.output)
            self.assertNotIn("SHAPE_TEST_HOST_SECRET", result.output)
            self.assertNotIn("must-not-appear", result.output)
            self.assertEqual(session.execute("printenv USER").output, "lab\n")
            self.assertEqual(
                session.execute("printenv SHAPE_TEST_HOST_SECRET").exit_code, 1
            )
        finally:
            os.environ.pop("SHAPE_TEST_HOST_SECRET", None)

    def test_bounded_find_and_grep_stay_inside_virtual_state(self) -> None:
        session = make_session()
        session.connect()
        found = session.execute(
            "find /var/records -maxdepth 2 -type f -name README.txt"
        )
        self.assertEqual(found.exit_code, 0)
        self.assertTrue(found.output)
        self.assertTrue(
            all(path.endswith("/README.txt") for path in found.output.splitlines())
        )
        self.assertEqual(
            session.execute("find / -maxdepth 2 -type f -perm -4000").output,
            "",
        )
        writable = session.execute("find /home -maxdepth 2 -writable")
        self.assertIn("/home/lab\n", writable.output)
        searched = session.execute("grep -RinE 'fixture|missing' /var/records")
        self.assertEqual(searched.exit_code, 0)
        self.assertIn("README.txt:1:Generated fixture record.", searched.output)
        self.assertEqual(session.execute("grep -F absent /etc/os-release").exit_code, 1)

    def test_tail_and_wc_are_bounded_file_readers(self) -> None:
        session = make_session()
        session.connect()
        self.assertEqual(
            session.execute("tail -1 /etc/os-release").output, "ID=ubuntu\n"
        )
        lines = session.execute("wc -l /etc/os-release")
        self.assertEqual(lines.exit_code, 0)
        self.assertIn("      2 /etc/os-release", lines.output)

    def test_shell_syntax_and_unsupported_commands_never_change_state(self) -> None:
        session = make_session()
        session.connect()
        for command in (
            "pwd; id",
            "cat /etc/os-release | sh",
            "ls && uname",
            "cat $(whoami)",
            "ls > /tmp/x",
            "pwd\nls",
            "cd /var; pwd",
        ):
            with self.subTest(command=command):
                result = session.execute(command)
                self.assertEqual(result.action, "rejected")
                self.assertEqual(result.cwd_after, "/home/lab")
        self.assertEqual(session.execute("mount").exit_code, 127)
        quoted_pattern = session.execute("grep -E 'NAME|ID' /etc/os-release")
        self.assertEqual(quoted_pattern.action, "grep")
        self.assertEqual(quoted_pattern.exit_code, 0)
        self.assertEqual(session.execute("pwd").output, "/home/lab\n")

    def test_output_is_bounded_even_for_large_fixture(self) -> None:
        raw = legacy_fixture()
        raw["files"]["/home/lab/large.txt"] = "x" * 4096
        spec = FilesystemSpec.from_dict(raw)
        session = Session(
            VirtualFilesystem(spec, "bounded", False, max_output_chars=512)
        )
        session.connect()
        result = session.execute("cat large.txt")
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.output), 512)


if __name__ == "__main__":
    unittest.main()
