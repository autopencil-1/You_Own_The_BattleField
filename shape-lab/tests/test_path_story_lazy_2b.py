"""Model-free coherence checks for the successor path-derived filesystem."""

from collections import deque
import json
import os
from pathlib import Path
import posixpath
import re
import subprocess
import sys
import unittest

from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
from filesystem_decoy_2b.server_path_story import StorySession
from filesystem_decoy_2b.virtual_fs import (
    MAX_PATH_CHARS,
    MAX_SEARCH_NODES,
    NodeKind,
    PermissionOperation,
)


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"
SEED = "lazy-story-coherence-seed"


def make_fs(*, dynamic: bool):
    return load_path_story_fixture(FIXTURE, SEED, dynamic)[1]


def scan_generated_nodes(fs, *, limit: int = 512):
    """Inspect a bounded prefix and retain its unvisited frontier."""
    pending = deque((root, 0) for root in sorted(fs.spec.expandable_roots))
    visited = set()
    found = []
    while pending and len(visited) < limit:
        path, depth = pending.popleft()
        if path in visited:
            continue
        visited.add(path)
        node = fs.node(path)
        if node is None:
            raise AssertionError(f"Listed path vanished: {path}")
        if path not in fs.spec.nodes:
            found.append((path, node, depth))
        if node.metadata.kind is NodeKind.DIRECTORY:
            for name in fs.children(path):
                pending.append((posixpath.join(path, name), depth + 1))
    return found, pending, visited


def generated_nodes(fs, *, limit: int = 512):
    return scan_generated_nodes(fs, limit=limit)[0]


class LazyPathStoryTests(unittest.TestCase):
    def test_static_and_dynamic_share_prefix_but_not_expansion(self) -> None:
        static = make_fs(dynamic=False)
        dynamic = make_fs(dynamic=True)
        static_session = StorySession(static)
        dynamic_session = StorySession(dynamic)
        self.assertEqual(static_session.connect(), dynamic_session.connect())
        for command in ("pwd", "whoami", "hostname", "ls /", "ls /home/lab"):
            self.assertEqual(
                static_session.execute(command).output,
                dynamic_session.execute(command).output,
                command,
            )

        new_paths = []
        for root in sorted(dynamic.spec.expandable_roots):
            static_names = set(static.children(root))
            dynamic_names = set(dynamic.children(root))
            self.assertLessEqual(static_names, dynamic_names)
            new_paths.extend(
                posixpath.join(root, name) for name in dynamic_names - static_names
            )
        self.assertTrue(new_paths, "Dynamic arm must reveal at least one new path")
        for path in new_paths[:3]:
            self.assertIsNone(static.node(path), path)
            self.assertIsNotNone(dynamic.node(path), path)
            self.assertNotEqual(static_session.execute(f"stat {path}").exit_code, 0)
            self.assertEqual(dynamic_session.execute(f"stat {path}").exit_code, 0)

    def test_visible_directory_link_counts_and_shared_base_fingerprint(self) -> None:
        static = make_fs(dynamic=False)
        dynamic = make_fs(dynamic=True)
        self.assertEqual(
            static.shared_nodes_fingerprint,
            dynamic.shared_nodes_fingerprint,
        )
        for fs in (static, dynamic):
            session = StorySession(fs)
            session.connect()
            for root in sorted(fs.spec.expandable_roots):
                visible_subdirectories = sum(
                    fs.node(posixpath.join(root, name)).metadata.kind
                    is NodeKind.DIRECTORY
                    for name in fs.children(root)
                )
                expected = 2 + visible_subdirectories
                # The rendered link count may differ across structure arms.
                self.assertEqual(fs.node(root).metadata.nlink, expected, root)
                stat = session.execute(f"stat {root}")
                self.assertEqual(stat.exit_code, 0)
                self.assertIn(f"Links: {expected}", stat.output)

    def test_direct_lookup_listing_order_and_restart_agree(self) -> None:
        first = make_fs(dynamic=True)
        second = make_fs(dynamic=True)
        discovered = generated_nodes(first, limit=128)
        directory = next(
            path for path, node, _ in discovered
            if node.metadata.kind is NodeKind.DIRECTORY
        )
        file = next(
            path for path, node, _ in discovered
            if node.metadata.kind is NodeKind.FILE
        )
        # In the second instance, direct lookups precede parent listings.
        for path in (directory, file):
            parent = posixpath.dirname(path)
            direct_node = second.node(path)
            self.assertIsNotNone(direct_node)
            self.assertEqual(direct_node, first.node(path))
            self.assertEqual(second.children(parent), first.children(parent))
            self.assertEqual(second.children(parent), second.children(parent))
            self.assertEqual(second.node(path), direct_node)

        parent = posixpath.dirname(directory)
        absent = posixpath.join(parent, "absent-path-story-probe")
        self.assertIsNone(second.node(absent))
        self.assertNotIn("absent-path-story-probe", second.children(parent))
        self.assertIsNone(second.node(absent))

        for fs in (first, second):
            session = StorySession(fs)
            session.connect()
            for path in (directory, file):
                self.assertEqual(session.execute(f"stat {path}").exit_code, 0)
                self.assertEqual(session.execute(f"ls -ld {path}").exit_code, 0)

    def test_generated_file_through_real_symlink_and_dot_paths(self) -> None:
        fs = make_fs(dynamic=True)
        root = "/srv/ledger-api/releases"
        alias_root = "/home/lab/release-archive"
        name = next(
            name
            for name in fs.children(root)
            if posixpath.join(root, name) not in fs.spec.nodes
            and fs.node(posixpath.join(root, name)).metadata.kind is NodeKind.FILE
        )
        real = posixpath.join(root, name)
        alias = posixpath.join(alias_root, name)
        session = StorySession(fs)
        session.connect()

        self.assertEqual(
            session.execute(f"ls {root}").output,
            session.execute(f"ls {alias_root}").output,
        )
        expected = session.execute(f"cat {real}")
        self.assertEqual(expected.exit_code, 0)
        self.assertEqual(session.execute(f"cat {alias}").output, expected.output)
        self.assertEqual(fs.resolve(alias, follow_final=True).resolved_path, real)
        for path in (real, alias):
            stat = session.execute(f"stat -L {path}")
            self.assertEqual(stat.exit_code, 0)
            self.assertIn(f"Inode: {fs.node(real).metadata.inode}", stat.output)

        self.assertEqual(session.execute(f"cd {root}").exit_code, 0)
        self.assertEqual(session.execute(f"cat ./{name}").output, expected.output)
        self.assertEqual(
            session.execute(f"cat ../releases/{name}").output,
            expected.output,
        )

    def test_parent_components_follow_intermediate_symlinks(self) -> None:
        fs = make_fs(dynamic=True)
        session = StorySession(fs)
        session.connect()
        physical = session.execute("file /srv/ledger-api/current")
        via_alias = session.execute(
            "file /home/lab/release-archive/../current"
        )
        self.assertEqual(physical.exit_code, 0)
        self.assertEqual(via_alias.exit_code, 0)
        self.assertEqual(via_alias.output, physical.output)

        missing_parent = session.execute("file /missing/../etc/hostname")
        self.assertNotEqual(missing_parent.exit_code, 0)
        self.assertIn("/missing: No such file or directory", missing_parent.output)
        file_parent = session.execute("file /etc/passwd/../hostname")
        self.assertNotEqual(file_parent.exit_code, 0)
        self.assertIn("/etc/passwd: Not a directory", file_parent.output)
        restricted_parent = session.execute("cat /root/../etc/passwd")
        self.assertNotEqual(restricted_parent.exit_code, 0)
        self.assertIn("Permission denied", restricted_parent.output)

    def test_fresh_process_derives_same_node(self) -> None:
        fs = make_fs(dynamic=True)
        path = generated_nodes(fs, limit=64)[0][0]

        def describe(node):
            metadata = node.metadata
            return {
                "path": node.path,
                "kind": metadata.kind.value,
                "content": node.content,
                "target": metadata.symlink_target,
                "uid": metadata.uid,
                "gid": metadata.gid,
                "mode": metadata.mode,
                "inode": metadata.inode,
                "size": metadata.size,
                "mtime_ns": metadata.mtime_ns,
            }

        script = """
import json
import sys
from filesystem_decoy_2b.path_story_fs import load_path_story_fixture
fs = load_path_story_fixture(sys.argv[1], sys.argv[2], True)[1]
node = fs.node(sys.argv[3])
m = node.metadata
print(json.dumps({
    'path': node.path, 'kind': m.kind.value, 'content': node.content,
    'target': m.symlink_target, 'uid': m.uid, 'gid': m.gid,
    'mode': m.mode, 'inode': m.inode, 'size': m.size,
    'mtime_ns': m.mtime_ns,
}, sort_keys=True))
"""
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(FIXTURE.parents[1])
        environment["PYTHONHASHSEED"] = "17"
        result = subprocess.run(
            [sys.executable, "-c", script, str(FIXTURE), SEED, path],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            timeout=10,
        )
        self.assertEqual(json.loads(result.stdout), describe(fs.node(path)))

    def test_metadata_permissions_and_authored_symlink_alias(self) -> None:
        fs = make_fs(dynamic=True)
        session = StorySession(fs)
        session.connect()
        found = generated_nodes(fs, limit=256)
        files = [
            (path, node)
            for path, node, _ in found
            if node.metadata.kind is NodeKind.FILE
            and fs.resolve(path, follow_final=True).ok
            and fs.access_allowed(path, PermissionOperation.READ)
        ]
        self.assertTrue(files, "The path-derived tree needs readable files")
        path, node = files[0]
        content = node.content
        self.assertIsNotNone(content)
        self.assertEqual(node.metadata.size, len(content.encode("utf-8")))
        self.assertEqual(session.execute(f"cat {path}").output, content)
        self.assertEqual(session.execute(f"wc -c {path}").exit_code, 0)
        self.assertIn(str(node.metadata.size), session.execute(f"wc -c {path}").output)
        stat = session.execute(f"stat {path}")
        self.assertEqual(stat.exit_code, 0)
        self.assertIn(f"Size: {node.metadata.size}", stat.output)
        self.assertIn(f"Inode: {node.metadata.inode}", stat.output)
        self.assertEqual(session.execute(f"ls -ld {path}").exit_code, 0)

        alias = "/srv/ledger-api/current"
        link_node = fs.resolve(alias, follow_final=False).node
        target = fs.resolve(alias, follow_final=True)
        self.assertIsNotNone(link_node)
        self.assertTrue(target.ok)
        self.assertIn("symbolic link", session.execute(f"file {alias}").output)
        self.assertEqual(session.execute(f"stat {alias}").exit_code, 0)
        self.assertEqual(session.execute(f"stat -L {alias}").exit_code, 0)
        self.assertIsNotNone(target.node)
        self.assertEqual(
            fs.resolve(alias, follow_final=False).node.metadata.inode,
            link_node.metadata.inode,
        )
        self.assertEqual(target.node.metadata.kind, NodeKind.DIRECTORY)
        self.assertEqual(session.execute(f"ls {alias}").exit_code, 0)
        self.assertEqual(session.execute(f"cd {alias}").exit_code, 0)
        self.assertEqual(session.cwd, target.resolved_path)

    def test_search_is_bounded_and_horizon_has_dead_ends(self) -> None:
        fs = make_fs(dynamic=True)
        session = StorySession(fs)
        session.connect()
        roots = sorted(fs.spec.expandable_roots)
        first_root = roots[0]
        self.assertTrue(
            fs.access_allowed(first_root, PermissionOperation.LIST_DIRECTORY)
        )
        listing = set(fs.children(first_root))
        shallow = session.execute(f"find {first_root} -maxdepth 1")
        self.assertIn(shallow.exit_code, (0, 1))
        shallow_paths = set(shallow.output.splitlines())
        self.assertIn(first_root, shallow_paths)
        for name in listing:
            self.assertIn(posixpath.join(first_root, name), shallow_paths)

        short_walk, short_truncated = fs.walk(first_root, max_nodes=8)
        self.assertEqual(len(short_walk), 8)
        self.assertTrue(short_truncated)
        full_walk, full_truncated = fs.walk(first_root)
        self.assertLessEqual(len(full_walk), MAX_SEARCH_NODES)
        find = session.execute(f"find {first_root}")
        self.assertLessEqual(len(find.output), fs.max_output_chars)
        if full_truncated:
            self.assertTrue(
                "search limit reached" in find.output or find.truncated,
                "A partial find result must be marked",
            )
        grep = session.execute(f"grep -rF ledger {first_root}")
        self.assertLessEqual(len(grep.output), fs.max_output_chars)
        self.assertIn(grep.exit_code, (0, 1, 2))

        found, frontier, visited = scan_generated_nodes(fs, limit=MAX_SEARCH_NODES)
        self.assertEqual(len(visited), MAX_SEARCH_NODES)
        self.assertTrue(
            any(path not in visited for path, _ in frontier),
            "The logical tree should continue past a 512-node bounded scan",
        )
        directories = [
            path for path, node, _ in found if node.metadata.kind is NodeKind.DIRECTORY
        ]
        self.assertTrue(directories)
        self.assertTrue(
            any(
                depth < fs.catalog.limits.max_depth
                and all(
                    fs.node(posixpath.join(path, name)).metadata.kind
                    is not NodeKind.DIRECTORY
                    for name in fs.children(path)
                )
                for path, node, depth in found
                if node.metadata.kind is NodeKind.DIRECTORY
            ),
            "At least one branch should end before the depth ceiling",
        )
        for path, node, _ in found:
            self.assertLessEqual(len(path), MAX_PATH_CHARS)
            self.assertEqual(node.path, path)
            self.assertEqual(fs.node(path), node)
            if node.metadata.kind is NodeKind.FILE:
                self.assertLessEqual(len(node.content.encode("utf-8")), 4096)

    def test_generated_references_json_and_timestamps_are_coherent(self) -> None:
        fs = make_fs(dynamic=True)
        found = generated_nodes(fs, limit=MAX_SEARCH_NODES)
        json_files = 0
        references = 0
        for path, node, _ in found:
            parent = fs.node(posixpath.dirname(path))
            self.assertIsNotNone(parent)
            self.assertLessEqual(
                node.metadata.mtime_ns,
                parent.metadata.mtime_ns,
                path,
            )
            if node.metadata.kind is not NodeKind.FILE:
                continue
            if path.endswith(".json"):
                self.assertIsInstance(json.loads(node.content), dict, path)
                json_files += 1
            for referenced in re.findall(
                r"/(?:etc|home|srv|var|usr|bin|tmp|root)(?:/[A-Za-z0-9._-]+)*",
                node.content,
            ):
                referenced = referenced.rstrip(".,;:")
                references += 1
                resolution = fs.resolve(referenced, follow_final=True)
                self.assertTrue(
                    resolution.ok,
                    f"{path} refers to an unresolved path: {referenced}",
                )
        self.assertGreater(json_files, 0)
        self.assertGreater(references, 0)

    def test_recursive_grep_shares_limit_across_multiple_roots(self) -> None:
        fs = make_fs(dynamic=True)
        session = StorySession(fs)
        session.connect()
        roots = sorted(fs.spec.expandable_roots)
        # Revisit the largest root enough times to exceed the command budget.
        largest = max(roots, key=lambda root: len(fs.walk(root)[0]))
        command = "grep -rFl ledger " + " ".join([largest] * 7 + roots[1:])
        visits = []
        original_walk = fs.walk_accessible

        def record_walk(*args, **kwargs):
            result = original_walk(*args, **kwargs)
            visits.append(len(result[0]))
            return result

        fs.walk_accessible = record_walk
        try:
            result = session.execute(command)
        finally:
            fs.walk_accessible = original_walk
        self.assertGreater(len(visits), 1)
        self.assertLessEqual(sum(visits), MAX_SEARCH_NODES)
        self.assertTrue(
            "search limit reached" in result.output or result.truncated,
            "A clipped multi-root search must identify its partial result",
        )


if __name__ == "__main__":
    unittest.main()
