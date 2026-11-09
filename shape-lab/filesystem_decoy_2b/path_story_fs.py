"""Path-derived successor filesystem for the opt-in 2B story.

The semantic-v2 catalog defines a bounded logical tree.  This module derives
one directory's immediate children at a time; it never compiles that tree in
advance or uses the order in which paths were observed as an input.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import posixpath
import re
from typing import Any, Mapping

from . import semantic_v2
from .semantic_v2 import SemanticV2Catalog, parse_semantic_v2
from .virtual_fs import (
    FilesystemSpec,
    MAX_PATH_CHARS,
    MAX_SEARCH_DEPTH,
    MAX_SEARCH_NODES,
    NodeDefinition,
    NodeKind,
    NodeMetadataOverride,
    PermissionOperation,
    VirtualFilesystem,
)


_TOKEN = re.compile(r"\{\{([a-z][a-z0-9_]*)\}\}")
_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")


@dataclass(frozen=True)
class _GeneratedEntry:
    definition: NodeDefinition
    root: str
    profile_name: str | None
    depth: int


class PathStoryFilesystem(VirtualFilesystem):
    """Lazy, deterministic namespace with the authored tree as a shared base."""

    def __init__(
        self,
        spec: FilesystemSpec,
        seed: str,
        dynamic: bool,
        catalog: SemanticV2Catalog,
        *,
        max_output_chars: int = 8192,
    ) -> None:
        if spec.semantic_profiles is not None:
            raise ValueError("The successor catalog must be parsed separately")
        if set(catalog.bindings) != set(spec.expandable_roots):
            raise ValueError("Semantic-v2 bindings must match expansion roots")
        self.catalog = catalog
        # The authored-base fingerprint is taken before treatment-dependent
        # expansion-root link counts are presented.
        self._fingerprinting_authored_base = True
        self._children_cache: OrderedDict[str, Mapping[str, _GeneratedEntry]] = (
            OrderedDict()
        )
        self._command_search_remaining: int | None = None
        self._explicit_search_depth = False
        self._capture_active = False
        self._capture_suspended = False
        self._staged_paths: OrderedDict[str, None] = OrderedDict()
        self._committed_paths: OrderedDict[str, dict[str, str | int]] = OrderedDict()
        super().__init__(
            spec,
            seed,
            dynamic,
            max_output_chars=max_output_chars,
        )
        self._fingerprinting_authored_base = False

    def _fingerprint_shared_nodes(self) -> str:
        previous = self._fingerprinting_authored_base
        self._fingerprinting_authored_base = True
        try:
            # A prior rendered stat may have cached the treatment-dependent
            # link count.  Recompute only these roots for the authored base.
            for root in self.catalog.bindings:
                self._node_cache.pop(root, None)
            return super()._fingerprint_shared_nodes()
        finally:
            self._fingerprinting_authored_base = previous

    def _hash(self, *parts: str) -> str:
        material = "\x00".join(
            (self.catalog.generator_version, self.catalog.fingerprint, self.seed, *parts)
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _count(self, parent: str, kind: str, minimum: int, maximum: int) -> int:
        if minimum == maximum:
            return minimum
        return minimum + int(self._hash(parent, kind, "count")[:16], 16) % (
            maximum - minimum + 1
        )

    def _generated_entry(self, path: str) -> _GeneratedEntry | None:
        if not self.dynamic or path in self.spec.nodes or path == "/":
            return None
        parent, name = posixpath.split(path)
        entry = self._generated_children(parent).get(name)
        if entry is not None:
            self._stage_path(path)
        return entry

    def begin_materialization_capture(self) -> None:
        if self._capture_active:
            raise RuntimeError("Materialization capture is already active")
        self._staged_paths.clear()
        self._capture_active = True

    def discard_materialization_capture(self) -> None:
        self._capture_active = False
        self._staged_paths.clear()

    def _stage_path(self, path: str) -> None:
        if (
            self._capture_active
            and not self._capture_suspended
            and self.dynamic
            and path not in self.spec.nodes
            and path not in self._committed_paths
        ):
            self._staged_paths.setdefault(path, None)

    @staticmethod
    def _node_payload(node: Any) -> dict[str, Any]:
        metadata = node.metadata
        return {
            "path": node.path,
            "kind": metadata.kind.value,
            "content": node.content,
            "target": metadata.symlink_target,
            "metadata": {
                "uid": metadata.uid,
                "gid": metadata.gid,
                "mode": metadata.mode,
                "inode": metadata.inode,
                "device": metadata.device,
                "nlink": metadata.nlink,
                "size": metadata.size,
                "blocks": metadata.blocks,
                "block_size": metadata.block_size,
                "atime_ns": metadata.atime_ns,
                "mtime_ns": metadata.mtime_ns,
                "ctime_ns": metadata.ctime_ns,
                "birthtime_ns": metadata.birthtime_ns,
            },
        }

    def node_fingerprint(self, path: str) -> str:
        """Hash all rendered node fields, independently of access order."""
        if path != posixpath.normpath(path) or not path.startswith("/"):
            raise ValueError("Node fingerprint needs a normalized absolute path")
        previous = self._capture_suspended
        self._capture_suspended = True
        try:
            node = self.node(path)
            if node is None:
                raise ValueError(f"Cannot fingerprint an absent node: {path}")
            payload = self._node_payload(node)
        finally:
            self._capture_suspended = previous
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def commit_materialization_capture(
        self, *, response_sequence: int, response_sha256: str
    ) -> tuple[dict[str, str | int], ...]:
        """Commit first-seen generated nodes after a response write succeeds."""
        if not self._capture_active or response_sequence < 1:
            raise ValueError("No active capture or invalid response sequence")
        if not re.fullmatch(r"[0-9a-f]{64}", response_sha256):
            raise ValueError("Invalid response digest")
        committed: list[dict[str, str | int]] = []
        for path in self._staged_paths:
            if path in self._committed_paths:
                continue
            item: dict[str, str | int] = {
                "response_sequence": response_sequence,
                "response_sha256": response_sha256,
                "inventory_index": len(self._committed_paths) + 1,
                "path": path,
                "node_sha256": self.node_fingerprint(path),
            }
            self._committed_paths[path] = item
            committed.append(dict(item))
        self.discard_materialization_capture()
        return tuple(committed)

    def committed_inventory(self) -> tuple[dict[str, str | int], ...]:
        return tuple(dict(item) for item in self._committed_paths.values())

    def _directory_state(self, path: str) -> tuple[str, str, int] | None:
        if not self.dynamic:
            return None
        if path in self.catalog.bindings:
            return path, self.catalog.bindings[path], 0
        entry = self._generated_entry(path)
        if entry is None or entry.definition.kind is not NodeKind.DIRECTORY:
            return None
        if entry.profile_name is None:
            raise AssertionError("Generated directory has no child profile")
        return entry.root, entry.profile_name, entry.depth

    @staticmethod
    def _render(template: str, tokens: Mapping[str, str]) -> str:
        return _TOKEN.sub(lambda match: tokens[match.group(1)], template)

    @staticmethod
    def _timestamp_text(timestamp_ns: int) -> str:
        seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
        instant = datetime.fromtimestamp(seconds, timezone.utc)
        return f"{instant:%Y-%m-%dT%H:%M:%S}.{nanoseconds:09d}Z"

    def _record(
        self,
        parent: str,
        root: str,
        profile: Any,
        purpose: str,
        ordinal: int,
        attempt: int,
    ) -> tuple[str, int, dict[str, str]]:
        digest = self._hash(parent, purpose, str(ordinal), str(attempt))
        parent_definition = self._definition(parent)
        if parent_definition is None:
            raise AssertionError("Generated child has no parent")
        parent_time = (
            parent_definition.metadata.mtime_ns
            if parent_definition.metadata.mtime_ns is not None
            else self.spec.metadata_defaults.timestamp_ns
        )
        policy = profile.metadata
        upper = min(policy.timestamp_end_ns, parent_time)
        if upper < policy.timestamp_start_ns:
            raise ValueError("Semantic timestamp window predates its parent")
        # A child is never newer than its directory.  The bounded offset also
        # leaves useful date variation across siblings without exhausting the
        # window along an eight-level path.
        offset_ns = int(digest[:16], 16) % (18 * 60 * 60 * 1_000_000_000)
        timestamp_ns = max(policy.timestamp_start_ns, upper - offset_ns)
        seconds = timestamp_ns // 1_000_000_000
        instant = datetime.fromtimestamp(seconds, timezone.utc)
        tokens = dict(self.catalog.context)
        tokens.update(self.catalog.anchors)
        tokens.update(
            {
                "date": instant.strftime("%Y%m%d"),
                "hash": digest[16:24],
                "hostname": self.spec.hostname,
                "sequence": f"{ordinal + 1:04d}",
                "timestamp": self._timestamp_text(timestamp_ns),
                "username": self.spec.username,
                "parent_path": parent,
                "root_path": root,
            }
        )
        return digest, timestamp_ns, tokens

    @staticmethod
    def _metadata(policy: Any, timestamp_ns: int) -> NodeMetadataOverride:
        return NodeMetadataOverride(
            uid=policy.uid,
            gid=policy.gid,
            mode=policy.mode,
            atime_ns=timestamp_ns,
            mtime_ns=timestamp_ns,
            ctime_ns=timestamp_ns,
        )

    def _choose_family(
        self,
        families: Mapping[str, Any],
        used: Mapping[str, int],
        parent: str,
        purpose: str,
        ordinal: int,
        depth: int,
        continuation_floor: int,
    ) -> tuple[str, Any]:
        eligible = [
            (name, family)
            for name, family in sorted(families.items())
            if depth >= family.min_depth
            and used.get(name, 0) < family.max_per_directory
        ]
        if purpose == "directory":
            continuations = [
                pair
                for pair in eligible
                if self.catalog.profiles[pair[1].child_profile].bounds.max_directories
                > 0
            ]
            terminals = [pair for pair in eligible if pair not in continuations]
            if ordinal < continuation_floor:
                eligible = continuations
            elif terminals:
                # Additional branches are credible dead ends.  Reserving the
                # first ordinals for continuations guarantees a useful horizon
                # for every seed without a traversal-order-dependent quota.
                eligible = terminals
        if not eligible:
            raise ValueError(f"No eligible {purpose} family for {parent}")
        total = sum(family.weight for _, family in eligible)
        choice = int(self._hash(parent, purpose, str(ordinal), "family")[:16], 16) % total
        for name, family in eligible:
            if choice < family.weight:
                return name, family
            choice -= family.weight
        raise AssertionError("Weighted family selection failed")

    def _generated_children(self, parent: str) -> Mapping[str, _GeneratedEntry]:
        if not self.dynamic:
            return {}
        cached = self._children_cache.get(parent)
        if cached is not None:
            self._children_cache.move_to_end(parent)
            for name in cached:
                self._stage_path(posixpath.join(parent, name))
            return cached
        state = self._directory_state(parent)
        if state is None:
            return {}
        root, profile_name, depth = state
        profile = self.catalog.profiles[profile_name]
        bounds = profile.bounds
        directory_count = (
            self._count(
                parent,
                "directory",
                bounds.min_directories,
                bounds.max_directories,
            )
            if depth < self.catalog.limits.max_depth
            else 0
        )
        file_count = self._count(parent, "file", bounds.min_files, bounds.max_files)
        if directory_count + file_count > self.catalog.limits.max_children:
            raise ValueError("Generated directory exceeds its configured child limit")
        entries: dict[str, _GeneratedEntry] = {}
        occupied = {
            posixpath.basename(path)
            for path in self.spec.nodes
            if path != parent and posixpath.dirname(path) == parent
        }
        for purpose, count, families in (
            ("directory", directory_count, profile.directory_families),
            ("file", file_count, profile.file_families),
        ):
            used: dict[str, int] = {}
            for ordinal in range(count):
                family_name, family = self._choose_family(
                    families,
                    used,
                    parent,
                    purpose,
                    ordinal,
                    depth,
                    bounds.min_continuations,
                )
                used[family_name] = used.get(family_name, 0) + 1
                for attempt in range(16):
                    digest, timestamp_ns, tokens = self._record(
                        parent, root, profile, purpose, ordinal, attempt
                    )
                    template = family.names[
                        int(digest[24:32], 16) % len(family.names)
                    ]
                    name = self._render(template, tokens)
                    path = posixpath.join(parent, name)
                    if (
                        not _NAME.fullmatch(name)
                        or name in {".", ".."}
                        or len(path) > min(MAX_PATH_CHARS, self.catalog.limits.max_path_chars)
                        or name in occupied
                        or name in entries
                    ):
                        continue
                    if purpose == "directory":
                        definition = NodeDefinition(
                            NodeKind.DIRECTORY,
                            metadata=self._metadata(
                                profile.metadata.directory, timestamp_ns
                            ),
                        )
                        child_profile = family.child_profile
                    else:
                        tokens.update({"name": name, "path": path})
                        content_family = self.catalog.content_families[
                            family.content_family
                        ]
                        template = content_family.templates[
                            int(digest[32:40], 16) % len(content_family.templates)
                        ]
                        content = self._render(template, tokens)
                        if (
                            len(content.encode("utf-8"))
                            > self.catalog.limits.max_content_bytes
                        ):
                            raise ValueError("Generated content exceeds configured limit")
                        definition = NodeDefinition(
                            NodeKind.FILE,
                            content=content,
                            metadata=self._metadata(profile.metadata.file, timestamp_ns),
                        )
                        child_profile = None
                    entries[name] = _GeneratedEntry(
                        definition, root, child_profile, depth + 1
                    )
                    break
                else:
                    raise ValueError(f"Could not assign a stable name below {parent}")
        self._children_cache[parent] = entries
        self._children_cache.move_to_end(parent)
        for name in entries:
            self._stage_path(posixpath.join(parent, name))
        while len(self._children_cache) > self.catalog.limits.max_cached_nodes // 2:
            self._children_cache.popitem(last=False)
        return entries

    def _definition(self, path: str) -> NodeDefinition | None:
        authored = self.spec.nodes.get(path)
        if authored is not None:
            return authored
        entry = self._generated_entry(path)
        return entry.definition if entry is not None else None

    def children(self, path: str) -> tuple[str, ...]:
        if self.kind(path) != "directory":
            raise ValueError("Not a directory")
        authored = {
            posixpath.basename(item)
            for item in self.spec.nodes
            if item != path and posixpath.dirname(item) == path
        }
        return tuple(sorted(authored | self._generated_children(path).keys()))

    def _inode(self, path: str, kind: NodeKind) -> int:
        if path in self.spec.nodes:
            return super()._inode(path, kind)
        inode = int(self._hash(path, f"inode:{kind.value}")[:16], 16) & (
            (1 << 63) - 1
        )
        inode = inode or 1
        incumbent = self._inode_paths.setdefault(inode, path)
        if incumbent != path:
            raise RuntimeError(
                f"Deterministic inode collision between {incumbent!r} and {path!r}"
            )
        return inode

    def node(self, path: str):
        node = super().node(path)
        if node is not None:
            self._stage_path(path)
        if (
            node is not None
            and path in self.catalog.bindings
            and not self._fingerprinting_authored_base
        ):
            visible_subdirectories = sum(
                self.kind(posixpath.join(path, name)) == NodeKind.DIRECTORY.value
                for name in self.children(path)
            )
            nlink = 2 + visible_subdirectories
            if node.metadata.nlink != nlink:
                node = replace(node, metadata=replace(node.metadata, nlink=nlink))
                self._node_cache[path] = node
        if len(self._node_cache) > self.catalog.limits.max_cached_nodes:
            for candidate in tuple(self._node_cache):
                if candidate not in self.spec.nodes:
                    del self._node_cache[candidate]
                    break
        return node

    def _walk_bounded(
        self,
        start: str,
        *,
        max_depth: int,
        max_nodes: int,
        accessible: bool,
    ) -> tuple[tuple[tuple[str, int], ...], bool, tuple[str, ...]]:
        if self.kind(start) is None:
            raise ValueError("Path does not exist")
        if not 0 <= max_depth <= MAX_SEARCH_DEPTH:
            raise ValueError(f"max depth must be between 0 and {MAX_SEARCH_DEPTH}")
        if not 1 <= max_nodes <= MAX_SEARCH_NODES:
            raise ValueError("Invalid traversal bound")
        if self._command_search_remaining is not None:
            if self._command_search_remaining <= 0:
                return (), True, ()
            max_nodes = min(max_nodes, self._command_search_remaining)
        pending = [(start, 0)]
        visited: list[tuple[str, int]] = []
        denied: list[str] = []
        truncated = False
        while pending:
            path, depth = pending.pop()
            visited.append((path, depth))
            is_directory = self.kind(path) == "directory"
            can_descend = True
            if accessible and is_directory and depth < max_depth:
                can_descend = self.access_allowed(
                    path, PermissionOperation.LIST_DIRECTORY
                ) and self.access_allowed(
                    path, PermissionOperation.TRAVERSE_DIRECTORY
                )
                if not can_descend:
                    denied.append(path)
            if len(visited) >= max_nodes:
                truncated = bool(pending) or (
                    is_directory
                    and can_descend
                    and (
                        depth < max_depth
                        or (
                            max_depth == MAX_SEARCH_DEPTH
                            and not self._explicit_search_depth
                        )
                    )
                    and bool(self.children(path))
                )
                break
            if not is_directory or not can_descend:
                continue
            if depth >= max_depth:
                # An explicit -maxdepth below the implementation ceiling is an
                # intentional query bound.  At the ceiling, undiscovered nodes
                # need an honest partial-result marker.
                if (
                    max_depth == MAX_SEARCH_DEPTH
                    and not self._explicit_search_depth
                    and self.children(path)
                ):
                    truncated = True
                continue
            children = [posixpath.join(path, name) for name in self.children(path)]
            pending.extend((child, depth + 1) for child in reversed(children))
        if self._command_search_remaining is not None:
            self._command_search_remaining -= len(visited)
        return tuple(visited), truncated, tuple(denied)

    def walk(
        self,
        start: str,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: int = MAX_SEARCH_NODES,
    ) -> tuple[tuple[tuple[str, int], ...], bool]:
        visited, truncated, _ = self._walk_bounded(
            start, max_depth=max_depth, max_nodes=max_nodes, accessible=False
        )
        return visited, truncated

    def walk_accessible(
        self,
        start: str,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: int = MAX_SEARCH_NODES,
    ) -> tuple[tuple[tuple[str, int], ...], bool, tuple[str, ...]]:
        return self._walk_bounded(
            start, max_depth=max_depth, max_nodes=max_nodes, accessible=True
        )

    def profile_evidence(self) -> dict[str, str | int]:
        source_hashes = {
            "path_story_fs.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "semantic_v2.py": hashlib.sha256(
                Path(semantic_v2.__file__).read_bytes()
            ).hexdigest(),
        }
        generator_code_fingerprint = hashlib.sha256(
            json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "filesystem_schema_version": self.spec.schema_version,
            "semantic_schema_version": self.catalog.version,
            "generator_version": self.catalog.generator_version,
            "generator_fingerprint": source_hashes["path_story_fs.py"],
            "generator_code_fingerprint": generator_code_fingerprint,
            "catalog_fingerprint": self.catalog.fingerprint,
            "seed_fingerprint": hashlib.sha256(self.seed.encode("utf-8")).hexdigest(),
            "shared_nodes_fingerprint": self.shared_nodes_fingerprint,
            "explicit_node_count": len(self.spec.nodes),
        }


def load_path_story_fixture(
    path: str | Path, seed: str, dynamic: bool
) -> tuple[dict[str, Any], PathStoryFilesystem]:
    """Load the successor profile without invoking the eager v1 compiler."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    catalog = parse_semantic_v2(raw)
    base_raw = dict(raw)
    base_raw.pop("semantic_profiles")
    spec = FilesystemSpec.from_dict(base_raw)
    return raw, PathStoryFilesystem(spec, seed, dynamic, catalog)
