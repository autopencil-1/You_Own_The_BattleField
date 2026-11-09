"""Strict, inert catalog parser for the path-derived 2B filesystem successor.

``parse_semantic_v2(document)`` accepts a complete filesystem schema-v2 JSON
document and returns an immutable :class:`SemanticV2Catalog`. It validates
references against the document's authored nodes and account registry, but
does not generate nodes or depend on the version-1 filesystem parser.

The generator interprets ``{{sequence}}`` as a parent-local child ordinal.
All choices must be derived from the catalog fingerprint, generator version,
trial seed, normalized parent path, child kind, and ordinal. Catalog parsing
has no traversal-order state and performs no host filesystem access.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import posixpath
import re
from types import MappingProxyType
from typing import Any, Mapping


GENERATOR_VERSION = "path-hash-v1"
_ID = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_TOKEN = re.compile(r"\{\{([a-z][a-z0-9_]*)\}\}")
_COMPONENT = re.compile(r"[A-Za-z0-9._-]+\Z")
_TIMESTAMP = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z\Z"
)
_NAME_TOKENS = frozenset({"date", "hash", "hostname", "sequence", "username"})
_CONTENT_TOKENS = _NAME_TOKENS | frozenset(
    {"name", "path", "parent_path", "root_path", "timestamp"}
)
_FORMATS = frozenset({"config", "json", "log", "text", "yaml"})
_ROLES = frozenset(
    {
        "application_data",
        "backup_archive",
        "deployment",
        "service_config",
        "service_log",
        "user_workspace",
    }
)
_CREDENTIAL_SIGNATURES = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
)


@dataclass(frozen=True)
class SemanticV2Limits:
    max_depth: int
    max_path_chars: int
    max_content_bytes: int
    max_cached_nodes: int
    max_children: int


@dataclass(frozen=True)
class SemanticV2KindMetadata:
    uid: int
    gid: int
    mode: int


@dataclass(frozen=True)
class SemanticV2Metadata:
    directory: SemanticV2KindMetadata
    file: SemanticV2KindMetadata
    timestamp_start_ns: int
    timestamp_end_ns: int


@dataclass(frozen=True)
class SemanticV2Bounds:
    min_directories: int
    max_directories: int
    min_files: int
    max_files: int
    min_continuations: int


@dataclass(frozen=True)
class SemanticV2DirectoryFamily:
    name_templates: tuple[str, ...]
    child_profile: str
    weight: int
    max_per_directory: int
    min_depth: int

    @property
    def names(self) -> tuple[str, ...]:
        return self.name_templates


@dataclass(frozen=True)
class SemanticV2FileFamily:
    name_templates: tuple[str, ...]
    content_family: str
    weight: int
    max_per_directory: int
    min_depth: int

    @property
    def names(self) -> tuple[str, ...]:
        return self.name_templates


@dataclass(frozen=True)
class SemanticV2ContentFamily:
    format: str
    templates: tuple[str, ...]


@dataclass(frozen=True)
class SemanticV2Profile:
    name: str
    role: str
    directory_families: Mapping[str, SemanticV2DirectoryFamily]
    file_families: Mapping[str, SemanticV2FileFamily]
    metadata: SemanticV2Metadata
    bounds: SemanticV2Bounds


@dataclass(frozen=True)
class SemanticV2Catalog:
    version: int
    generator_version: str
    fingerprint: str
    context: Mapping[str, str]
    anchors: Mapping[str, str]
    content_families: Mapping[str, SemanticV2ContentFamily]
    profiles: Mapping[str, SemanticV2Profile]
    bindings: Mapping[str, str]
    limits: SemanticV2Limits

    def profile_for_root(self, root: str) -> SemanticV2Profile:
        return self.profiles[self.bindings[root]]


def _object(
    value: Any,
    label: str,
    required: set[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ValueError(f"{label} is missing {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{label} has unknown fields {', '.join(sorted(unknown))}")
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase identifier")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _absolute(path: Any, label: str, max_chars: int) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > max_chars
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
        or posixpath.normpath(path) != path
    ):
        raise ValueError(f"{label} must be a normalized absolute virtual path")
    return path


def _timestamp_ns(value: Any, label: str) -> int:
    if not isinstance(value, str) or (match := _TIMESTAMP.fullmatch(value)) is None:
        raise ValueError(f"{label} must be a UTC RFC 3339 timestamp")
    year, month, day, hour, minute, second = (int(x) for x in match.groups()[:6])
    fraction = (match.group(7) or "").ljust(9, "0")
    try:
        instant = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid UTC timestamp") from exc
    return calendar.timegm(instant.utctimetuple()) * 1_000_000_000 + int(fraction or "0")


def _templates(
    value: Any,
    label: str,
    *,
    allowed_tokens: frozenset[str],
    component: bool,
    max_bytes: int,
    maximum: int = 16,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{label} must contain 1 to {maximum} templates")
    parsed: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item.encode("utf-8")) > max_bytes:
            raise ValueError(f"{label} contains an empty or oversized template")
        tokens = set(_TOKEN.findall(item))
        scrubbed = _TOKEN.sub("token", item)
        if "{{" in scrubbed or "}}" in scrubbed or not tokens <= allowed_tokens:
            raise ValueError(f"{label} contains an unknown or malformed token")
        if component and (
            not _COMPONENT.fullmatch(scrubbed)
            or scrubbed in {".", ".."}
            or scrubbed.startswith("-")
        ):
            raise ValueError(f"{label} is not a safe path-component template")
        if not component and any(pattern.search(item) for pattern in _CREDENTIAL_SIGNATURES):
            raise ValueError(f"{label} contains recognizable credential material")
        parsed.append(item)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"{label} contains duplicate templates")
    return tuple(parsed)


def _check_rendered_names(
    templates: tuple[str, ...], label: str, token_lengths: Mapping[str, int]
) -> None:
    """Reject templates whose actual fixture tokens can exceed a name limit."""

    for template in templates:
        rendered = _TOKEN.sub(lambda match: "x" * token_lengths[match.group(1)], template)
        if len(rendered) > 64:
            raise ValueError(f"{label} can render a name over 64 characters")


def _rendered_name_length(template: str, token_lengths: Mapping[str, int]) -> int:
    return len(_TOKEN.sub(lambda match: "x" * token_lengths[match.group(1)], template))


def _check_rendered_content(
    templates: tuple[str, ...],
    label: str,
    token_lengths: Mapping[str, int],
    max_bytes: int,
) -> None:
    for template in templates:
        rendered = _TOKEN.sub(lambda match: "x" * token_lengths[match.group(1)], template)
        if len(rendered.encode("utf-8")) > max_bytes:
            raise ValueError(f"{label} can render content over max_content_bytes")


def _check_path_budget(
    profiles: Mapping[str, SemanticV2Profile],
    bindings: Mapping[str, str],
    limits: SemanticV2Limits,
    token_lengths: Mapping[str, int],
) -> None:
    """Prove every allowed profile chain fits the configured virtual path cap."""

    frontier = [(root, profile, 0, len(root)) for root, profile in bindings.items()]
    longest: dict[tuple[str, str, int], int] = {}
    while frontier:
        root, profile_name, depth, parent_length = frontier.pop()
        state = (root, profile_name, depth)
        if parent_length <= longest.get(state, -1):
            continue
        longest[state] = parent_length
        profile = profiles[profile_name]
        for family in profile.file_families.values():
            if depth < family.min_depth:
                continue
            for template in family.name_templates:
                if parent_length + 1 + _rendered_name_length(template, token_lengths) > limits.max_path_chars:
                    raise ValueError(f"Profile {profile_name} can exceed max_path_chars")
        if depth >= limits.max_depth:
            continue
        for family in profile.directory_families.values():
            if depth < family.min_depth:
                continue
            for template in family.name_templates:
                child_length = parent_length + 1 + _rendered_name_length(template, token_lengths)
                if child_length > limits.max_path_chars:
                    raise ValueError(f"Profile {profile_name} can exceed max_path_chars")
                frontier.append((root, family.child_profile, depth + 1, child_length))


def _kind_metadata(
    value: Any,
    label: str,
    users: Mapping[str, int],
    groups: Mapping[str, int],
) -> SemanticV2KindMetadata:
    raw = _object(value, label, {"user", "group", "mode"})
    user = raw["user"]
    group = raw["group"]
    if (
        not isinstance(user, str)
        or not isinstance(group, str)
        or user not in users
        or group not in groups
    ):
        raise ValueError(f"{label} references an unknown user or group")
    mode = raw["mode"]
    if not isinstance(mode, str) or re.fullmatch(r"[0-7]{4}\Z", mode) is None:
        raise ValueError(f"{label} mode must be a four-digit octal string")
    return SemanticV2KindMetadata(users[user], groups[group], int(mode, 8))


def _accounts(document: Mapping[str, Any]) -> tuple[dict[str, int], dict[str, int]]:
    accounts = document.get("accounts")
    if not isinstance(accounts, dict):
        raise ValueError("Filesystem document must include an accounts object")
    users_raw = accounts.get("users")
    groups_raw = accounts.get("groups")
    if not isinstance(users_raw, dict) or not isinstance(groups_raw, dict):
        raise ValueError("Filesystem accounts must contain users and groups objects")
    users: dict[str, int] = {}
    groups: dict[str, int] = {}
    for name, details in users_raw.items():
        if not isinstance(name, str) or not _ACCOUNT.fullmatch(name) or not isinstance(details, dict):
            raise ValueError("Filesystem accounts have an invalid user")
        users[name] = _integer(details.get("uid"), f"User {name} uid", 0, 65535)
    for name, details in groups_raw.items():
        if not isinstance(name, str) or not _ACCOUNT.fullmatch(name) or not isinstance(details, dict):
            raise ValueError("Filesystem accounts have an invalid group")
        groups[name] = _integer(details.get("gid"), f"Group {name} gid", 0, 65535)
    return users, groups


def parse_semantic_v2(document: Mapping[str, Any]) -> SemanticV2Catalog:
    """Validate the full fixture and return an immutable version-2 catalog.

    Raises ``ValueError`` for every malformed catalog, dangling reference,
    unsupported token, unsafe name, or impossible fanout. The caller remains
    responsible for enforcing rendered output limits and materialization caps.
    """

    if not isinstance(document, dict) or document.get("schema_version") != 2:
        raise ValueError("Semantic v2 requires a filesystem schema-v2 document")
    raw = _object(
        document.get("semantic_profiles"),
        "Semantic v2 catalog",
        {
            "version",
            "generator_version",
            "context",
            "anchors",
            "content_families",
            "profiles",
            "bindings",
            "limits",
        },
    )
    if type(raw["version"]) is not int or raw["version"] != 2:
        raise ValueError("Semantic catalog version must be 2")
    if raw["generator_version"] != GENERATOR_VERSION:
        raise ValueError(f"Unsupported semantic generator_version: {raw['generator_version']!r}")

    limits_raw = _object(
        raw["limits"],
        "Semantic v2 limits",
        {"max_depth", "max_path_chars", "max_content_bytes", "max_cached_nodes", "max_children"},
    )
    limits = SemanticV2Limits(
        _integer(limits_raw["max_depth"], "max_depth", 1, 8),
        _integer(limits_raw["max_path_chars"], "max_path_chars", 64, 256),
        _integer(limits_raw["max_content_bytes"], "max_content_bytes", 128, 4096),
        _integer(limits_raw["max_cached_nodes"], "max_cached_nodes", 512, 32768),
        _integer(limits_raw["max_children"], "max_children", 1, 16),
    )
    users, groups = _accounts(document)

    roots_raw = document.get("expandable_roots")
    nodes = document.get("nodes")
    if not isinstance(roots_raw, list) or not isinstance(nodes, dict):
        raise ValueError("Filesystem document must include expandable_roots and nodes")
    roots = {_absolute(path, "Expandable root", limits.max_path_chars) for path in roots_raw}
    if len(roots) != len(roots_raw):
        raise ValueError("Expandable roots must be unique")
    for path in roots:
        if path not in nodes or not isinstance(nodes[path], dict) or nodes[path].get("kind") != "directory":
            raise ValueError(f"Expandable root {path} must be an authored directory")

    context_raw = raw["context"]
    if not isinstance(context_raw, dict) or len(context_raw) > 16:
        raise ValueError("Semantic context must have at most 16 values")
    context: dict[str, str] = {}
    for key, value in context_raw.items():
        name = _id(key, "Context key")
        if name in _CONTENT_TOKENS or name.endswith("_anchor"):
            raise ValueError(f"Context key {name} is reserved")
        if not isinstance(value, str) or not _VALUE.fullmatch(value):
            raise ValueError(f"Context value {name} is invalid")
        if any(pattern.search(value) for pattern in _CREDENTIAL_SIGNATURES):
            raise ValueError(f"Context value {name} contains recognizable credential material")
        context[name] = value

    system = document.get("system")
    if not isinstance(system, dict):
        raise ValueError("Filesystem document must include system identity")
    hostname = system.get("hostname")
    username = system.get("username")
    if (
        not isinstance(hostname, str)
        or not _VALUE.fullmatch(hostname)
        or not isinstance(username, str)
        or not _ACCOUNT.fullmatch(username)
    ):
        raise ValueError("Filesystem system identity cannot render safe names")
    token_lengths = {
        "date": 8,
        "hash": 8,
        "hostname": len(hostname),
        "sequence": 4,
        "username": len(username),
        **{key: len(value) for key, value in context.items()},
    }

    anchors_raw = raw["anchors"]
    if not isinstance(anchors_raw, dict) or len(anchors_raw) > 16:
        raise ValueError("Semantic anchors must have at most 16 entries")
    anchors: dict[str, str] = {}
    for key, value in anchors_raw.items():
        name = _id(key, "Anchor key")
        if not name.endswith("_anchor") or name in context:
            raise ValueError(f"Anchor key {name} must end with _anchor")
        path = _absolute(value, f"Anchor {name}", limits.max_path_chars)
        if path not in nodes or not isinstance(nodes[path], dict) or nodes[path].get("kind") not in {"directory", "file"}:
            raise ValueError(f"Anchor {name} must resolve to an authored file or directory")
        anchors[name] = path

    content_tokens = _CONTENT_TOKENS | frozenset(context) | frozenset(anchors)
    name_tokens = _NAME_TOKENS | frozenset(context)
    content_token_lengths = {
        **token_lengths,
        "name": 64,
        "path": limits.max_path_chars,
        "parent_path": limits.max_path_chars,
        "root_path": max((len(root) for root in roots), default=1),
        "timestamp": 30,
        **{key: len(value) for key, value in anchors.items()},
    }
    families_raw = raw["content_families"]
    if not isinstance(families_raw, dict) or not 1 <= len(families_raw) <= 32:
        raise ValueError("Semantic content_families must contain 1 to 32 entries")
    content_families: dict[str, SemanticV2ContentFamily] = {}
    used_anchors: set[str] = set()
    for key, value in families_raw.items():
        name = _id(key, "Content family name")
        family = _object(value, f"Content family {name}", {"format", "templates"})
        if not isinstance(family["format"], str) or family["format"] not in _FORMATS:
            raise ValueError(f"Content family {name} format is invalid")
        templates = _templates(
            family["templates"],
            f"Content family {name}",
            allowed_tokens=content_tokens,
            component=False,
            max_bytes=limits.max_content_bytes,
        )
        _check_rendered_content(
            templates,
            f"Content family {name}",
            content_token_lengths,
            limits.max_content_bytes,
        )
        used_anchors.update(token for item in templates for token in _TOKEN.findall(item) if token in anchors)
        content_families[name] = SemanticV2ContentFamily(family["format"], templates)

    profiles_raw = raw["profiles"]
    if not isinstance(profiles_raw, dict) or not 1 <= len(profiles_raw) <= 32:
        raise ValueError("Semantic profiles must contain 1 to 32 entries")
    profile_names = {_id(name, "Profile name") for name in profiles_raw}
    profiles: dict[str, SemanticV2Profile] = {}
    used_content: set[str] = set()
    for key, value in profiles_raw.items():
        name = _id(key, "Profile name")
        profile = _object(
            value,
            f"Profile {name}",
            {"role", "directory_families", "file_families", "metadata", "bounds"},
        )
        if not isinstance(profile["role"], str) or profile["role"] not in _ROLES:
            raise ValueError(f"Profile {name} role is invalid")
        bounds_raw = _object(
            profile["bounds"],
            f"Profile {name} bounds",
            {"min_directories", "max_directories", "min_files", "max_files", "min_continuations"},
        )
        bounds = SemanticV2Bounds(
            _integer(bounds_raw["min_directories"], f"{name} min_directories", 0, 8),
            _integer(bounds_raw["max_directories"], f"{name} max_directories", 0, 8),
            _integer(bounds_raw["min_files"], f"{name} min_files", 0, 8),
            _integer(bounds_raw["max_files"], f"{name} max_files", 0, 8),
            _integer(bounds_raw["min_continuations"], f"{name} min_continuations", 0, 8),
        )
        if (
            bounds.min_directories > bounds.max_directories
            or bounds.min_files > bounds.max_files
            or bounds.min_continuations > bounds.min_directories
            or bounds.max_directories + bounds.max_files > limits.max_children
        ):
            raise ValueError(f"Profile {name} fanout bounds are impossible")

        metadata_raw = _object(
            profile["metadata"],
            f"Profile {name} metadata",
            {"directory", "file", "timestamp_start", "timestamp_end"},
        )
        start_ns = _timestamp_ns(metadata_raw["timestamp_start"], f"Profile {name} timestamp_start")
        end_ns = _timestamp_ns(metadata_raw["timestamp_end"], f"Profile {name} timestamp_end")
        if start_ns > end_ns:
            raise ValueError(f"Profile {name} timestamp range is reversed")
        metadata = SemanticV2Metadata(
            _kind_metadata(metadata_raw["directory"], f"Profile {name} directory", users, groups),
            _kind_metadata(metadata_raw["file"], f"Profile {name} file", users, groups),
            start_ns,
            end_ns,
        )

        directory_raw = profile["directory_families"]
        file_raw = profile["file_families"]
        if (
            not isinstance(directory_raw, dict)
            or not isinstance(file_raw, dict)
            or len(directory_raw) > 16
            or len(file_raw) > 16
            or not (directory_raw or file_raw)
        ):
            raise ValueError(f"Profile {name} families must be bounded objects")
        if (bounds.max_directories > 0) != bool(directory_raw):
            raise ValueError(f"Profile {name} directory families do not match fanout")
        if (bounds.max_files > 0) != bool(file_raw):
            raise ValueError(f"Profile {name} file families do not match fanout")
        directory_families: dict[str, SemanticV2DirectoryFamily] = {}
        file_families: dict[str, SemanticV2FileFamily] = {}
        claimed_names: set[str] = set()
        for family_key, family_value in directory_raw.items():
            family_name = _id(family_key, "Directory family name")
            family = _object(
                family_value,
                f"Directory family {name}.{family_name}",
                {"names", "child_profile", "weight", "max_per_directory", "min_depth"},
            )
            child_profile = _id(family["child_profile"], f"{name}.{family_name} child_profile")
            if child_profile not in profile_names:
                raise ValueError(f"Directory family {name}.{family_name} has unknown child_profile")
            templates = _templates(
                family["names"],
                f"Directory family {name}.{family_name} names",
                allowed_tokens=name_tokens,
                component=True,
                max_bytes=128,
            )
            _check_rendered_names(templates, f"Directory family {name}.{family_name}", token_lengths)
            if claimed_names & set(templates):
                raise ValueError(f"Profile {name} reuses a name template")
            claimed_names.update(templates)
            maximum = _integer(family["max_per_directory"], f"{name}.{family_name} max_per_directory", 1, bounds.max_directories)
            if maximum > len(templates) and not any("{{sequence}}" in t or "{{hash}}" in t for t in templates):
                raise ValueError(f"Directory family {name}.{family_name} cannot produce enough unique names")
            directory_families[family_name] = SemanticV2DirectoryFamily(
                templates,
                child_profile,
                _integer(family["weight"], f"{name}.{family_name} weight", 1, 100),
                maximum,
                _integer(family["min_depth"], f"{name}.{family_name} min_depth", 0, limits.max_depth - 1),
            )
        for family_key, family_value in file_raw.items():
            family_name = _id(family_key, "File family name")
            family = _object(
                family_value,
                f"File family {name}.{family_name}",
                {"names", "content_family", "weight", "max_per_directory", "min_depth"},
            )
            content_name = _id(family["content_family"], f"{name}.{family_name} content_family")
            if content_name not in content_families:
                raise ValueError(f"File family {name}.{family_name} has unknown content_family")
            templates = _templates(
                family["names"],
                f"File family {name}.{family_name} names",
                allowed_tokens=name_tokens,
                component=True,
                max_bytes=128,
            )
            _check_rendered_names(templates, f"File family {name}.{family_name}", token_lengths)
            if claimed_names & set(templates):
                raise ValueError(f"Profile {name} reuses a name template")
            claimed_names.update(templates)
            maximum = _integer(family["max_per_directory"], f"{name}.{family_name} max_per_directory", 1, bounds.max_files)
            if maximum > len(templates) and not any("{{sequence}}" in t or "{{hash}}" in t for t in templates):
                raise ValueError(f"File family {name}.{family_name} cannot produce enough unique names")
            file_families[family_name] = SemanticV2FileFamily(
                templates,
                content_name,
                _integer(family["weight"], f"{name}.{family_name} weight", 1, 100),
                maximum,
                _integer(family["min_depth"], f"{name}.{family_name} min_depth", 0, limits.max_depth),
            )
            used_content.add(content_name)
        profiles[name] = SemanticV2Profile(
            name,
            profile["role"],
            MappingProxyType(directory_families),
            MappingProxyType(file_families),
            metadata,
            bounds,
        )

    bindings_raw = raw["bindings"]
    if not isinstance(bindings_raw, dict):
        raise ValueError("Semantic bindings must be an object")
    bindings: dict[str, str] = {}
    for path, value in bindings_raw.items():
        root = _absolute(path, "Binding root", limits.max_path_chars)
        profile = _id(value, f"Binding {root} profile")
        if profile not in profiles:
            raise ValueError(f"Binding {root} has an unknown profile")
        bindings[root] = profile
    if set(bindings) != roots:
        raise ValueError("Every expandable root needs exactly one binding")
    if any(child.startswith(parent + "/") for parent in roots for child in roots if child != parent):
        raise ValueError("Expandable roots must not overlap")

    # A profile may be reached via child_profile instead of being bound itself.
    reachable_states: set[tuple[str, int]] = set()
    frontier = [(profile, 0) for profile in bindings.values()]
    while frontier:
        profile_name, depth = frontier.pop()
        state = (profile_name, depth)
        if state in reachable_states:
            continue
        reachable_states.add(state)
        profile = profiles[profile_name]
        eligible_files = [f for f in profile.file_families.values() if f.min_depth <= depth]
        if sum(f.max_per_directory for f in eligible_files) < profile.bounds.min_files:
            raise ValueError(f"Profile {profile_name} cannot meet minimum file fanout at depth {depth}")
        if depth >= limits.max_depth:
            continue
        eligible_dirs = [f for f in profile.directory_families.values() if f.min_depth <= depth]
        if sum(f.max_per_directory for f in eligible_dirs) < profile.bounds.min_directories:
            raise ValueError(f"Profile {profile_name} cannot meet minimum directory fanout at depth {depth}")
        continuation_capacity = sum(
            family.max_per_directory
            for family in eligible_dirs
            if profiles[family.child_profile].bounds.max_directories > 0
        )
        if continuation_capacity < profile.bounds.min_continuations:
            raise ValueError(
                f"Profile {profile_name} cannot meet min_continuations at depth {depth}"
            )
        for family in eligible_dirs:
            frontier.append((family.child_profile, depth + 1))
    if {name for name, _ in reachable_states} != set(profiles):
        raise ValueError("Every semantic profile must be reachable from a binding")
    if used_content != set(content_families):
        raise ValueError("Every content family must be referenced by a file family")
    if used_anchors != set(anchors):
        raise ValueError("Every anchor must be referenced by a content template")

    _check_path_budget(profiles, bindings, limits, token_lengths)

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return SemanticV2Catalog(
        2,
        GENERATOR_VERSION,
        hashlib.sha256(canonical).hexdigest(),
        MappingProxyType(context),
        MappingProxyType(anchors),
        MappingProxyType(content_families),
        MappingProxyType(profiles),
        MappingProxyType(bindings),
        limits,
    )


__all__ = [
    "GENERATOR_VERSION",
    "SemanticV2Bounds",
    "SemanticV2Catalog",
    "SemanticV2ContentFamily",
    "SemanticV2DirectoryFamily",
    "SemanticV2FileFamily",
    "SemanticV2KindMetadata",
    "SemanticV2Limits",
    "SemanticV2Metadata",
    "SemanticV2Profile",
    "parse_semantic_v2",
]
