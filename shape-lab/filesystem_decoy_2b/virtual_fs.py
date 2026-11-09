"""Interpret a small command language against synthetic, deterministic state.

This module never executes a host command or reads a host path. A future 2B
service can give each trial a fresh Session and journal its CommandResult values.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import fnmatch
import hashlib
import json
import posixpath
import re
import shlex
import stat as stat_module
from types import MappingProxyType
from typing import Any, Mapping


MAX_COMMAND_CHARS = 512
MAX_PATH_CHARS = 256
MAX_ARGUMENTS = 12
MAX_SEARCH_DEPTH = 8
MAX_SEARCH_NODES = 512
MAX_SYMLINK_HOPS = 16
MAX_SEMANTIC_COLLISION_ATTEMPTS = 16
SHELL_CONTROL_TOKENS = frozenset({";", "|", "&", ">", "<"})
ACCOUNT_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
SEMANTIC_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,31}")
SEMANTIC_VALUE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SEMANTIC_TOKEN_PATTERN = re.compile(r"\{\{([a-z][a-z0-9_]*)\}\}")
SEMANTIC_NAME_TOKENS = frozenset({"date", "hash", "hostname", "sequence", "username"})
SEMANTIC_CONTENT_TOKENS = SEMANTIC_NAME_TOKENS | frozenset(
    {"name", "path", "timestamp"}
)
UTC_TIMESTAMP_PATTERN = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z"
)
SUPPORTED_COMMANDS = (
    "cat",
    "cd",
    "env",
    "file",
    "find",
    "grep",
    "groups",
    "head",
    "hostname",
    "id",
    "ls",
    "printenv",
    "pwd",
    "stat",
    "sudo",
    "tail",
    "uname",
    "wc",
    "whoami",
)


def _digest(seed: str, path: str, purpose: str) -> str:
    return hashlib.sha256(f"{seed}\x00{path}\x00{purpose}".encode("utf-8")).hexdigest()


def _absolute(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > MAX_PATH_CHARS
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
    ):
        raise ValueError("Fixture paths must be bounded absolute virtual paths")
    canonical = posixpath.normpath(path)
    if canonical != path:
        raise ValueError(f"Fixture path is not normalized: {path!r}")
    return canonical


def _bounded_id(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 65535:
        raise ValueError(f"{label} must be an integer from 0 to 65535")
    return value


def _account_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ACCOUNT_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _semantic_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SEMANTIC_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase semantic identifier")
    return value


def _semantic_template(
    value: Any,
    label: str,
    *,
    allowed_tokens: frozenset[str],
    path_component: bool,
) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a nonempty string")
    byte_limit = 256 if path_component else 4096
    if len(value.encode("utf-8")) > byte_limit:
        raise ValueError(f"{label} is too large")
    tokens = set(SEMANTIC_TOKEN_PATTERN.findall(value))
    scrubbed = SEMANTIC_TOKEN_PATTERN.sub("token", value)
    if "{{" in scrubbed or "}}" in scrubbed or not tokens <= allowed_tokens:
        raise ValueError(f"{label} contains an unsupported semantic token")
    if path_component and (
        not re.fullmatch(r"[A-Za-z0-9._-]+", scrubbed) or scrubbed in {".", ".."}
    ):
        raise ValueError(f"{label} is not a safe path-component template")
    return value


def _strict_object(
    value: Any,
    *,
    label: str,
    required: set[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise ValueError(f"{label} is missing: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _parse_mode(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-7]{4}", value):
        raise ValueError(f"{label} must be a four-digit octal string")
    return int(value, 8)


def _parse_utc_ns(value: Any, label: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a UTC timestamp string")
    match = UTC_TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(f"{label} must use RFC 3339 UTC form ending in Z")
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    fraction = (match.group(7) or "").ljust(9, "0")
    try:
        instant = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid timestamp") from exc
    return calendar.timegm(instant.utctimetuple()) * 1_000_000_000 + int(
        fraction or "0"
    )


class NodeKind(str, Enum):
    DIRECTORY = "directory"
    FILE = "file"
    SYMLINK = "symlink"

    @property
    def type_bits(self) -> int:
        return {
            NodeKind.DIRECTORY: stat_module.S_IFDIR,
            NodeKind.FILE: stat_module.S_IFREG,
            NodeKind.SYMLINK: stat_module.S_IFLNK,
        }[self]


class PermissionOperation(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    LIST_DIRECTORY = "list_directory"
    TRAVERSE_DIRECTORY = "traverse_directory"

    @property
    def required_bit(self) -> int:
        return {
            PermissionOperation.READ: 0o4,
            PermissionOperation.WRITE: 0o2,
            PermissionOperation.EXECUTE: 0o1,
            PermissionOperation.LIST_DIRECTORY: 0o4,
            PermissionOperation.TRAVERSE_DIRECTORY: 0o1,
        }[self]


class ResolutionErrorKind(str, Enum):
    NOT_FOUND = "not_found"
    NOT_DIRECTORY = "not_directory"
    PERMISSION_DENIED = "permission_denied"
    SYMLINK_LOOP = "symlink_loop"


class SemanticRole(str, Enum):
    APPLICATION_DATA = "application_data"
    BACKUP_ARCHIVE = "backup_archive"
    DEPLOYMENT = "deployment"
    SERVICE_CONFIG = "service_config"
    SERVICE_LOG = "service_log"
    USER_WORKSPACE = "user_workspace"


class SemanticContentFormat(str, Enum):
    CONFIG = "config"
    JSON = "json"
    LOG = "log"
    TEXT = "text"
    YAML = "yaml"


@dataclass(frozen=True)
class GroupAccount:
    name: str
    gid: int

    def __post_init__(self) -> None:
        _account_name(self.name, "Group name")
        _bounded_id(self.gid, f"gid for {self.name}")


@dataclass(frozen=True)
class UserAccount:
    name: str
    uid: int
    primary_group: str
    supplementary_groups: tuple[str, ...]

    def __post_init__(self) -> None:
        _account_name(self.name, "User name")
        _bounded_id(self.uid, f"uid for {self.name}")
        _account_name(self.primary_group, f"Primary group for {self.name}")
        if (
            not self.supplementary_groups
            or self.primary_group not in self.supplementary_groups
            or len(set(self.supplementary_groups)) != len(self.supplementary_groups)
        ):
            raise ValueError(f"Supplementary groups for {self.name} are invalid")
        for group in self.supplementary_groups:
            _account_name(group, f"Supplementary group for {self.name}")


@dataclass(frozen=True)
class AccountRegistry:
    users: tuple[UserAccount, ...]
    groups: tuple[GroupAccount, ...]

    def __post_init__(self) -> None:
        user_names = [user.name for user in self.users]
        user_ids = [user.uid for user in self.users]
        group_names = [group.name for group in self.groups]
        group_ids = [group.gid for group in self.groups]
        if len(set(user_names)) != len(user_names) or len(set(user_ids)) != len(
            user_ids
        ):
            raise ValueError("Virtual users need unique names and uids")
        if len(set(group_names)) != len(group_names) or len(set(group_ids)) != len(
            group_ids
        ):
            raise ValueError("Virtual groups need unique names and gids")
        known_groups = set(group_names)
        if any(
            user.primary_group not in known_groups
            or not set(user.supplementary_groups) <= known_groups
            for user in self.users
        ):
            raise ValueError("Every virtual user group must exist in the registry")

    def user(self, name: str) -> UserAccount:
        for user in self.users:
            if user.name == name:
                return user
        raise ValueError(f"Unknown virtual user: {name}")

    def group(self, name: str) -> GroupAccount:
        for group in self.groups:
            if group.name == name:
                return group
        raise ValueError(f"Unknown virtual group: {name}")

    def user_name(self, uid: int) -> str | None:
        return next((user.name for user in self.users if user.uid == uid), None)

    def group_name(self, gid: int) -> str | None:
        return next((group.name for group in self.groups if group.gid == gid), None)


@dataclass(frozen=True)
class KindMetadataDefaults:
    uid: int
    gid: int
    mode: int


@dataclass(frozen=True)
class MetadataDefaults:
    directory: KindMetadataDefaults
    file: KindMetadataDefaults
    symlink: KindMetadataDefaults
    timestamp_ns: int
    device: int = 1
    block_size: int = 4096
    directory_size: int = 4096

    def for_kind(self, kind: NodeKind) -> KindMetadataDefaults:
        return {
            NodeKind.DIRECTORY: self.directory,
            NodeKind.FILE: self.file,
            NodeKind.SYMLINK: self.symlink,
        }[kind]


@dataclass(frozen=True)
class NodeMetadataOverride:
    uid: int | None = None
    gid: int | None = None
    mode: int | None = None
    atime_ns: int | None = None
    mtime_ns: int | None = None
    ctime_ns: int | None = None
    birthtime_ns: int | None = None


@dataclass(frozen=True)
class NodeDefinition:
    kind: NodeKind
    content: str | None = None
    symlink_target: str | None = None
    metadata: NodeMetadataOverride = NodeMetadataOverride()


@dataclass(frozen=True)
class NodeMetadata:
    kind: NodeKind
    uid: int
    gid: int
    mode: int
    inode: int
    device: int
    nlink: int
    size: int
    blocks: int
    block_size: int
    atime_ns: int
    mtime_ns: int
    ctime_ns: int
    birthtime_ns: int | None
    symlink_target: str | None

    @property
    def stat_mode(self) -> int:
        return self.kind.type_bits | self.mode

    @property
    def symbolic_mode(self) -> str:
        return stat_module.filemode(self.stat_mode)


@dataclass(frozen=True)
class PermissionIdentity:
    uid: int
    gids: frozenset[int]

    def __post_init__(self) -> None:
        _bounded_id(self.uid, "Permission identity uid")
        if not self.gids:
            raise ValueError("Permission identity needs at least one gid")
        for gid in self.gids:
            _bounded_id(gid, "Permission identity gid")


@dataclass(frozen=True)
class PermissionEvaluator:
    identity: PermissionIdentity

    def effective_bits(self, metadata: NodeMetadata) -> int:
        if metadata.uid == self.identity.uid:
            return (metadata.mode >> 6) & 0o7
        if metadata.gid in self.identity.gids:
            return (metadata.mode >> 3) & 0o7
        return metadata.mode & 0o7

    def allows(self, metadata: NodeMetadata, operation: PermissionOperation) -> bool:
        if (
            operation
            in {
                PermissionOperation.LIST_DIRECTORY,
                PermissionOperation.TRAVERSE_DIRECTORY,
            }
            and metadata.kind is not NodeKind.DIRECTORY
        ):
            return False
        if self.identity.uid == 0:
            if (
                operation is PermissionOperation.EXECUTE
                and metadata.kind is not NodeKind.DIRECTORY
            ):
                return bool(metadata.mode & 0o111)
            return True
        return bool(self.effective_bits(metadata) & operation.required_bit)


@dataclass(frozen=True)
class VirtualNode:
    path: str
    metadata: NodeMetadata
    content: str | None = None


@dataclass(frozen=True)
class PathResolution:
    requested_path: str
    resolved_path: str | None
    node: VirtualNode | None
    error: ResolutionErrorKind | None
    error_path: str | None
    symlink_hops: int

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class SemanticContentFamily:
    format: SemanticContentFormat
    templates: tuple[str, ...]


@dataclass(frozen=True)
class SemanticFileFamily:
    name_templates: tuple[str, ...]
    content_family: str
    weight: int


@dataclass(frozen=True)
class SemanticExpansionBounds:
    max_depth: int
    min_directories: int
    max_directories: int
    min_files: int
    max_files: int
    max_nodes: int


@dataclass(frozen=True)
class SemanticMetadataPolicy:
    directory: KindMetadataDefaults
    file: KindMetadataDefaults
    symlink: KindMetadataDefaults
    timestamp_start_ns: int
    timestamp_end_ns: int


@dataclass(frozen=True)
class SemanticLinkPolicy:
    name_templates: tuple[str, ...]
    target_profiles: tuple[str, ...]
    target_kinds: tuple[NodeKind, ...]
    max_per_directory: int
    allow_relative: bool
    allow_absolute: bool
    allow_dangling: bool


@dataclass(frozen=True)
class SemanticProfile:
    name: str
    role: SemanticRole
    directory_name_templates: tuple[str, ...]
    file_families: Mapping[str, SemanticFileFamily]
    metadata: SemanticMetadataPolicy
    bounds: SemanticExpansionBounds
    links: SemanticLinkPolicy


@dataclass(frozen=True)
class SemanticProfileCatalog:
    version: int
    context: Mapping[str, str]
    content_families: Mapping[str, SemanticContentFamily]
    profiles: Mapping[str, SemanticProfile]
    bindings: Mapping[str, str]
    fingerprint: str

    def profile_for_root(self, root: str) -> SemanticProfile:
        profile_name = self.bindings[root]
        return self.profiles[profile_name]


@dataclass(frozen=True)
class CompiledSemanticGraph:
    nodes: Mapping[str, NodeDefinition]
    profile_by_path: Mapping[str, str]
    fingerprint: str


@dataclass(frozen=True)
class FilesystemSpec:
    """Content supplied as data; names and clues can be frozen later."""

    schema_version: int
    nodes: Mapping[str, NodeDefinition]
    expandable_roots: frozenset[str]
    directory_words: tuple[str, ...]
    accounts: AccountRegistry
    metadata_defaults: MetadataDefaults
    semantic_profiles: SemanticProfileCatalog | None = None
    generated_file_name: str = "README.txt"
    generated_file_text: str = "Synthetic lab record.\n"
    home: str = "/home/lab"
    username: str = "lab"
    hostname: str = "ubuntu-lab"
    kernel_release: str = "6.8.0-48-generic"
    architecture: str = "x86_64"
    enforce_permissions: bool = False

    @property
    def directories(self) -> frozenset[str]:
        return frozenset(
            path for path, node in self.nodes.items() if node.kind is NodeKind.DIRECTORY
        )

    @property
    def files(self) -> dict[str, str]:
        return {
            path: node.content
            for path, node in self.nodes.items()
            if node.kind is NodeKind.FILE and node.content is not None
        }

    @property
    def uid(self) -> int:
        return self.accounts.user(self.username).uid

    @property
    def primary_group(self) -> str:
        return self.accounts.user(self.username).primary_group

    @property
    def gid(self) -> int:
        return self.accounts.group(self.primary_group).gid

    @property
    def supplementary_groups(self) -> tuple[str, ...]:
        return self.accounts.user(self.username).supplementary_groups

    @property
    def supplementary_gids(self) -> frozenset[int]:
        return frozenset(
            self.accounts.group(name).gid for name in self.supplementary_groups
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> FilesystemSpec:
        if not isinstance(raw, dict):
            raise ValueError("Filesystem specification must be an object")
        version = raw.get("schema_version", 1)
        if not isinstance(version, int) or isinstance(version, bool):
            raise ValueError("Filesystem schema_version must be an integer")
        if version == 1:
            return cls._from_legacy_dict(raw)
        if version == 2:
            return cls._from_v2_dict(raw)
        raise ValueError(f"Unsupported filesystem schema_version: {version}")

    @classmethod
    def _from_legacy_dict(cls, raw: dict[str, Any]) -> FilesystemSpec:
        directories = frozenset(_absolute(item) for item in raw["directories"])
        files = {_absolute(path): content for path, content in raw["files"].items()}
        roots = frozenset(_absolute(item) for item in raw["expandable_roots"])
        words = tuple(raw["directory_words"])
        home = _absolute(raw.get("home", "/home/lab"))
        generated_name = raw.get("generated_file_name", "README.txt")
        generated_text = raw.get("generated_file_text", "Synthetic lab record.\n")
        system = raw.get("system", {})
        if not isinstance(system, dict):
            raise ValueError("System identity must be an object")
        username = system.get("username", "lab")
        uid = system.get("uid", 1000)
        gid = system.get("gid", 1000)
        primary_group = system.get("primary_group", username)
        groups = tuple(system.get("supplementary_groups", [primary_group]))
        hostname = system.get("hostname", "ubuntu-lab")
        kernel_release = system.get("kernel_release", "6.8.0-48-generic")
        architecture = system.get("architecture", "x86_64")
        enforce_permissions = raw.get("enforce_permissions", False)
        if "/" not in directories or home not in directories:
            raise ValueError("Fixture needs a root and an existing home directory")
        if not roots <= directories or directories & files.keys():
            raise ValueError(
                "Expansion roots must be directories; files and directories cannot overlap"
            )
        if any(
            path != "/" and posixpath.dirname(path) not in directories
            for path in directories
        ):
            raise ValueError("Every explicit directory needs an explicit parent")
        if any(posixpath.dirname(path) not in directories for path in files):
            raise ValueError("Every explicit file needs an explicit parent")
        if (
            not words
            or len(set(words)) != len(words)
            or any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", word) for word in words)
        ):
            raise ValueError("Directory words must be unique safe path components")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", generated_name):
            raise ValueError("Generated file name is not a safe path component")
        if (
            not isinstance(generated_text, str)
            or len(generated_text.encode("utf-8")) > 4096
        ):
            raise ValueError("Generated file content is too large")
        if any(
            not isinstance(value, str) or len(value.encode("utf-8")) > 4096
            for value in files.values()
        ):
            raise ValueError("Explicit file content is too large")
        _account_name(username, "Virtual username")
        _account_name(primary_group, "Virtual primary group")
        if (
            not groups
            or len(set(groups)) != len(groups)
            or primary_group not in groups
            or any(
                not isinstance(group, str) or not ACCOUNT_PATTERN.fullmatch(group)
                for group in groups
            )
        ):
            raise ValueError("Virtual supplementary groups are invalid")
        _bounded_id(uid, "Virtual uid")
        _bounded_id(gid, "Virtual gid")
        if not isinstance(enforce_permissions, bool):
            raise ValueError("enforce_permissions must be a boolean")
        if not isinstance(hostname, str) or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname
        ):
            raise ValueError("Virtual hostname is invalid")
        if any(
            not isinstance(value, str)
            or not 1 <= len(value) <= 64
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E for character in value
            )
            for value in (kernel_release, architecture)
        ):
            raise ValueError("Virtual kernel identity is invalid")

        group_accounts = [GroupAccount("root", 0)]
        next_group_id = gid + 1
        for group in groups:
            group_id = gid if group == primary_group else next_group_id
            if group != primary_group:
                next_group_id += 1
            if group == "root" or group_id == 0:
                raise ValueError("Legacy virtual groups conflict with the root account")
            group_accounts.append(GroupAccount(group, group_id))
        if username == "root" or uid == 0:
            raise ValueError("Legacy virtual user conflicts with the root account")
        accounts = AccountRegistry(
            users=(
                UserAccount("root", 0, "root", ("root",)),
                UserAccount(username, uid, primary_group, groups),
            ),
            groups=tuple(group_accounts),
        )
        root_defaults = KindMetadataDefaults(0, 0, 0o755)
        metadata_defaults = MetadataDefaults(
            directory=root_defaults,
            file=KindMetadataDefaults(0, 0, 0o644),
            symlink=KindMetadataDefaults(0, 0, 0o777),
            timestamp_ns=_parse_utc_ns("2025-01-01T00:00:00Z", "Legacy timestamp"),
        )
        nodes: dict[str, NodeDefinition] = {}
        for path in directories:
            home_owned = path == home or path.startswith(home + "/")
            nodes[path] = NodeDefinition(
                NodeKind.DIRECTORY,
                metadata=NodeMetadataOverride(
                    uid=uid if home_owned else 0,
                    gid=gid if home_owned else 0,
                    mode=0o755,
                ),
            )
        for path, content in files.items():
            home_owned = path == home or path.startswith(home + "/")
            nodes[path] = NodeDefinition(
                NodeKind.FILE,
                content=content,
                metadata=NodeMetadataOverride(
                    uid=uid if home_owned else 0,
                    gid=gid if home_owned else 0,
                    mode=0o644,
                ),
            )
        return cls(
            schema_version=1,
            nodes=MappingProxyType(nodes),
            expandable_roots=roots,
            directory_words=words,
            accounts=accounts,
            metadata_defaults=metadata_defaults,
            generated_file_name=generated_name,
            generated_file_text=generated_text,
            home=home,
            username=username,
            hostname=hostname,
            kernel_release=kernel_release,
            architecture=architecture,
            enforce_permissions=enforce_permissions,
        )

    @classmethod
    def _from_v2_dict(cls, raw: dict[str, Any]) -> FilesystemSpec:
        _strict_object(
            raw,
            label="Filesystem specification",
            required={
                "schema_version",
                "nodes",
                "expandable_roots",
                "directory_words",
                "accounts",
                "metadata_defaults",
                "home",
                "system",
            },
            optional={
                "enforce_permissions",
                "generated_file_name",
                "generated_file_text",
                "reinforcement_text",
                "semantic_profiles",
            },
        )
        accounts = cls._parse_accounts(raw["accounts"])
        metadata_defaults = cls._parse_metadata_defaults(
            raw["metadata_defaults"], accounts
        )
        nodes = cls._parse_nodes(raw["nodes"])
        directories = frozenset(
            path for path, node in nodes.items() if node.kind is NodeKind.DIRECTORY
        )
        roots = frozenset(_absolute(item) for item in raw["expandable_roots"])
        words = tuple(raw["directory_words"])
        semantic_profiles = (
            cls._parse_semantic_profiles(raw["semantic_profiles"], roots, accounts)
            if "semantic_profiles" in raw
            else None
        )
        home = _absolute(raw["home"])
        generated_name = raw.get("generated_file_name", "README.txt")
        generated_text = raw.get("generated_file_text", "Synthetic lab record.\n")
        system = _strict_object(
            raw["system"],
            label="System identity",
            required={"username", "hostname", "kernel_release", "architecture"},
        )
        username = _account_name(system["username"], "System username")
        accounts.user(username)
        hostname = system["hostname"]
        kernel_release = system["kernel_release"]
        architecture = system["architecture"]
        enforce_permissions = raw.get("enforce_permissions", False)

        if not isinstance(enforce_permissions, bool):
            raise ValueError("enforce_permissions must be a boolean")

        if "/" not in directories or home not in directories:
            raise ValueError("Fixture needs a root and an existing home directory")
        if not roots <= directories:
            raise ValueError("Expansion roots must be directories")
        if any(
            path != "/"
            and (
                posixpath.dirname(path) not in nodes
                or nodes[posixpath.dirname(path)].kind is not NodeKind.DIRECTORY
            )
            for path in nodes
        ):
            raise ValueError("Every explicit node needs an explicit directory parent")
        cls._validate_generation(words, generated_name, generated_text)
        cls._validate_host_identity(hostname, kernel_release, architecture)
        return cls(
            schema_version=2,
            nodes=MappingProxyType(nodes),
            expandable_roots=roots,
            directory_words=words,
            accounts=accounts,
            metadata_defaults=metadata_defaults,
            semantic_profiles=semantic_profiles,
            generated_file_name=generated_name,
            generated_file_text=generated_text,
            home=home,
            username=username,
            hostname=hostname,
            kernel_release=kernel_release,
            architecture=architecture,
            enforce_permissions=enforce_permissions,
        )

    @staticmethod
    def _validate_generation(words: tuple[Any, ...], name: Any, text: Any) -> None:
        if (
            not words
            or len(set(words)) != len(words)
            or any(
                not isinstance(word, str)
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", word)
                for word in words
            )
        ):
            raise ValueError("Directory words must be unique safe path components")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
            raise ValueError("Generated file name is not a safe path component")
        if not isinstance(text, str) or len(text.encode("utf-8")) > 4096:
            raise ValueError("Generated file content is too large")

    @staticmethod
    def _validate_host_identity(hostname: Any, kernel: Any, architecture: Any) -> None:
        if not isinstance(hostname, str) or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname
        ):
            raise ValueError("Virtual hostname is invalid")
        if any(
            not isinstance(value, str)
            or not 1 <= len(value) <= 64
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E for character in value
            )
            for value in (kernel, architecture)
        ):
            raise ValueError("Virtual kernel identity is invalid")

    @staticmethod
    def _parse_semantic_profiles(
        value: Any,
        expandable_roots: frozenset[str],
        accounts: AccountRegistry,
    ) -> SemanticProfileCatalog:
        raw = _strict_object(
            value,
            label="Semantic profile catalog",
            required={
                "version",
                "context",
                "content_families",
                "profiles",
                "bindings",
            },
        )
        version = raw["version"]
        if not isinstance(version, int) or isinstance(version, bool) or version != 1:
            raise ValueError("Semantic profile catalog version must be 1")

        context_raw = raw["context"]
        if not isinstance(context_raw, dict) or len(context_raw) > 16:
            raise ValueError("Semantic context must be an object with at most 16 keys")
        context: dict[str, str] = {}
        for key, item in context_raw.items():
            name = _semantic_id(key, "Semantic context key")
            if name in SEMANTIC_CONTENT_TOKENS:
                raise ValueError(f"Semantic context key is reserved: {name}")
            if not isinstance(item, str) or not SEMANTIC_VALUE_PATTERN.fullmatch(item):
                raise ValueError(f"Semantic context value for {name} is invalid")
            context[name] = item
        name_tokens = SEMANTIC_NAME_TOKENS | frozenset(context)
        content_tokens = SEMANTIC_CONTENT_TOKENS | frozenset(context)

        def templates(
            items: Any,
            label: str,
            *,
            allowed_tokens: frozenset[str],
            path_component: bool,
            maximum: int,
            allow_empty: bool = False,
        ) -> tuple[str, ...]:
            if (
                not isinstance(items, list)
                or len(items) > maximum
                or (not allow_empty and not items)
            ):
                raise ValueError(f"{label} must be a bounded list")
            parsed = tuple(
                _semantic_template(
                    item,
                    f"{label} item",
                    allowed_tokens=allowed_tokens,
                    path_component=path_component,
                )
                for item in items
            )
            if len(set(parsed)) != len(parsed):
                raise ValueError(f"{label} must not contain duplicates")
            return parsed

        content_raw = raw["content_families"]
        if not isinstance(content_raw, dict) or not 1 <= len(content_raw) <= 32:
            raise ValueError("Semantic content_families must contain 1 to 32 entries")
        content_families: dict[str, SemanticContentFamily] = {}
        for raw_name, raw_family in content_raw.items():
            name = _semantic_id(raw_name, "Content family name")
            family = _strict_object(
                raw_family,
                label=f"Content family {name}",
                required={"format", "templates"},
            )
            try:
                content_format = SemanticContentFormat(family["format"])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Content family {name} has an invalid format"
                ) from exc
            content_families[name] = SemanticContentFamily(
                content_format,
                templates(
                    family["templates"],
                    f"Content family {name} templates",
                    allowed_tokens=content_tokens,
                    path_component=False,
                    maximum=16,
                ),
            )

        profiles_raw = raw["profiles"]
        if not isinstance(profiles_raw, dict) or not 1 <= len(profiles_raw) <= 16:
            raise ValueError("Semantic profiles must contain 1 to 16 entries")
        known_profile_names = {
            _semantic_id(name, "Semantic profile name") for name in profiles_raw
        }

        def kind_policy(item: Any, label: str, kind: NodeKind) -> KindMetadataDefaults:
            details = _strict_object(
                item,
                label=label,
                required={"user", "group", "mode"},
            )
            user_name = _account_name(details["user"], f"User for {label}")
            group_name = _account_name(details["group"], f"Group for {label}")
            uid = accounts.user(user_name).uid
            gid = accounts.group(group_name).gid
            mode = _parse_mode(details["mode"], f"Mode for {label}")
            if kind is NodeKind.SYMLINK and mode != 0o777:
                raise ValueError("Semantic symlink metadata must use mode 0777")
            return KindMetadataDefaults(uid, gid, mode)

        profiles: dict[str, SemanticProfile] = {}
        referenced_content: set[str] = set()
        for raw_name, raw_profile in profiles_raw.items():
            name = _semantic_id(raw_name, "Semantic profile name")
            profile = _strict_object(
                raw_profile,
                label=f"Semantic profile {name}",
                required={
                    "role",
                    "directory_names",
                    "file_families",
                    "metadata",
                    "bounds",
                },
                optional={"links"},
            )
            try:
                role = SemanticRole(profile["role"])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Semantic profile {name} has an invalid role"
                ) from exc

            directory_names = templates(
                profile["directory_names"],
                f"Semantic profile {name} directory_names",
                allowed_tokens=name_tokens,
                path_component=True,
                maximum=32,
            )
            claimed_name_templates = set(directory_names)
            file_families_raw = profile["file_families"]
            if (
                not isinstance(file_families_raw, dict)
                or not 1 <= len(file_families_raw) <= 16
            ):
                raise ValueError(
                    f"Semantic profile {name} file_families must contain 1 to 16 entries"
                )
            file_families: dict[str, SemanticFileFamily] = {}
            for raw_family_name, raw_file_family in file_families_raw.items():
                family_name = _semantic_id(raw_family_name, "File family name")
                file_family = _strict_object(
                    raw_file_family,
                    label=f"File family {family_name}",
                    required={"names", "content_family"},
                    optional={"weight"},
                )
                content_name = _semantic_id(
                    file_family["content_family"],
                    f"Content reference for file family {family_name}",
                )
                if content_name not in content_families:
                    raise ValueError(
                        f"File family {family_name} references unknown content family"
                    )
                weight = file_family.get("weight", 1)
                if (
                    not isinstance(weight, int)
                    or isinstance(weight, bool)
                    or not 1 <= weight <= 100
                ):
                    raise ValueError(f"File family {family_name} has invalid weight")
                file_names = templates(
                    file_family["names"],
                    f"File family {family_name} names",
                    allowed_tokens=name_tokens,
                    path_component=True,
                    maximum=16,
                )
                if claimed_name_templates & set(file_names):
                    raise ValueError(f"Semantic profile {name} reuses a name template")
                claimed_name_templates.update(file_names)
                file_families[family_name] = SemanticFileFamily(
                    file_names,
                    content_name,
                    weight,
                )
                referenced_content.add(content_name)

            metadata_raw = _strict_object(
                profile["metadata"],
                label=f"Semantic profile {name} metadata",
                required={"directory", "file", "timestamp_start", "timestamp_end"},
                optional={"symlink"},
            )
            timestamp_start = _parse_utc_ns(
                metadata_raw["timestamp_start"],
                f"Timestamp start for semantic profile {name}",
            )
            timestamp_end = _parse_utc_ns(
                metadata_raw["timestamp_end"],
                f"Timestamp end for semantic profile {name}",
            )
            if timestamp_start > timestamp_end:
                raise ValueError(f"Semantic profile {name} timestamp range is reversed")
            metadata = SemanticMetadataPolicy(
                kind_policy(
                    metadata_raw["directory"],
                    f"Semantic profile {name} directory metadata",
                    NodeKind.DIRECTORY,
                ),
                kind_policy(
                    metadata_raw["file"],
                    f"Semantic profile {name} file metadata",
                    NodeKind.FILE,
                ),
                kind_policy(
                    metadata_raw.get(
                        "symlink",
                        {"user": "root", "group": "root", "mode": "0777"},
                    ),
                    f"Semantic profile {name} symlink metadata",
                    NodeKind.SYMLINK,
                ),
                timestamp_start,
                timestamp_end,
            )

            bounds_raw = _strict_object(
                profile["bounds"],
                label=f"Semantic profile {name} bounds",
                required={
                    "max_depth",
                    "min_directories",
                    "max_directories",
                    "min_files",
                    "max_files",
                    "max_nodes",
                },
            )
            if any(
                not isinstance(bounds_raw[field], int)
                or isinstance(bounds_raw[field], bool)
                for field in bounds_raw
            ):
                raise ValueError(f"Semantic profile {name} bounds must be integers")
            bounds = SemanticExpansionBounds(
                bounds_raw["max_depth"],
                bounds_raw["min_directories"],
                bounds_raw["max_directories"],
                bounds_raw["min_files"],
                bounds_raw["max_files"],
                bounds_raw["max_nodes"],
            )
            if (
                not 1 <= bounds.max_depth <= MAX_SEARCH_DEPTH
                or not 0 <= bounds.min_directories <= bounds.max_directories <= 15
                or not 0 <= bounds.min_files <= bounds.max_files <= 16
                or not 1 <= bounds.max_nodes <= MAX_SEARCH_NODES
            ):
                raise ValueError(f"Semantic profile {name} bounds are invalid")

            links_raw = profile.get("links")
            if links_raw is None:
                links = SemanticLinkPolicy((), (), (), 0, False, False, False)
            else:
                link_details = _strict_object(
                    links_raw,
                    label=f"Semantic profile {name} links",
                    required={
                        "names",
                        "target_profiles",
                        "target_kinds",
                        "max_per_directory",
                        "allow_relative",
                        "allow_absolute",
                        "allow_dangling",
                    },
                )
                link_names = templates(
                    link_details["names"],
                    f"Semantic profile {name} link names",
                    allowed_tokens=name_tokens,
                    path_component=True,
                    maximum=8,
                    allow_empty=True,
                )
                targets_raw = link_details["target_profiles"]
                if not isinstance(targets_raw, list) or len(targets_raw) > 16:
                    raise ValueError(
                        f"Semantic profile {name} link targets must be a bounded list"
                    )
                target_profiles = tuple(
                    _semantic_id(target, f"Link target for semantic profile {name}")
                    for target in targets_raw
                )
                if (
                    len(set(target_profiles)) != len(target_profiles)
                    or not set(target_profiles) <= known_profile_names
                ):
                    raise ValueError(
                        f"Semantic profile {name} has invalid link target profiles"
                    )
                target_kinds_raw = link_details["target_kinds"]
                if not isinstance(target_kinds_raw, list) or len(target_kinds_raw) > 2:
                    raise ValueError(
                        f"Semantic profile {name} link target kinds are invalid"
                    )
                try:
                    target_kinds = tuple(NodeKind(item) for item in target_kinds_raw)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Semantic profile {name} link target kinds are invalid"
                    ) from exc
                if len(set(target_kinds)) != len(target_kinds) or any(
                    kind is NodeKind.SYMLINK for kind in target_kinds
                ):
                    raise ValueError(
                        f"Semantic profile {name} link target kinds are invalid"
                    )
                max_links = link_details["max_per_directory"]
                flags = (
                    link_details["allow_relative"],
                    link_details["allow_absolute"],
                    link_details["allow_dangling"],
                )
                if (
                    not isinstance(max_links, int)
                    or isinstance(max_links, bool)
                    or not 0 <= max_links <= 8
                    or any(not isinstance(flag, bool) for flag in flags)
                    or (
                        max_links == 0
                        and (
                            link_names or target_profiles or target_kinds or any(flags)
                        )
                    )
                    or (max_links > 0 and not link_names)
                    or (max_links > 0 and not target_kinds)
                    or (max_links > 0 and not any(flags[:2]))
                    or (max_links > 0 and not flags[2] and not target_profiles)
                ):
                    raise ValueError(f"Semantic profile {name} link policy is invalid")
                if claimed_name_templates & set(link_names):
                    raise ValueError(f"Semantic profile {name} reuses a name template")
                links = SemanticLinkPolicy(
                    link_names,
                    target_profiles,
                    target_kinds,
                    max_links,
                    flags[0],
                    flags[1],
                    flags[2],
                )

            profiles[name] = SemanticProfile(
                name,
                role,
                directory_names,
                MappingProxyType(file_families),
                metadata,
                bounds,
                links,
            )

        if referenced_content != set(content_families):
            raise ValueError("Every semantic content family must be referenced")

        bindings_raw = raw["bindings"]
        if not isinstance(bindings_raw, dict):
            raise ValueError("Semantic profile bindings must be an object")
        bindings: dict[str, str] = {}
        for raw_root, raw_profile_name in bindings_raw.items():
            root = _absolute(raw_root)
            profile_name = _semantic_id(raw_profile_name, f"Profile binding for {root}")
            if profile_name not in profiles:
                raise ValueError(f"Binding for {root} references an unknown profile")
            bindings[root] = profile_name
        if set(bindings) != set(expandable_roots):
            raise ValueError("Every expandable root needs exactly one semantic binding")
        if set(bindings.values()) != set(profiles):
            raise ValueError(
                "Every semantic profile must be bound to an expandable root"
            )
        ordered_roots = sorted(bindings)
        if any(
            child.startswith(parent + "/")
            for index, parent in enumerate(ordered_roots)
            for child in ordered_roots[index + 1 :]
        ):
            raise ValueError("Semantic expandable roots must not overlap")
        if (
            sum(profiles[name].bounds.max_nodes for name in bindings.values())
            > MAX_SEARCH_NODES
        ):
            raise ValueError("Semantic root node budgets exceed the global limit")

        canonical = json.dumps(
            raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        fingerprint = hashlib.sha256(canonical).hexdigest()
        return SemanticProfileCatalog(
            version,
            MappingProxyType(context),
            MappingProxyType(content_families),
            MappingProxyType(profiles),
            MappingProxyType(bindings),
            fingerprint,
        )

    @staticmethod
    def _parse_accounts(value: Any) -> AccountRegistry:
        raw = _strict_object(value, label="Accounts", required={"users", "groups"})
        if not isinstance(raw["users"], dict) or not isinstance(raw["groups"], dict):
            raise ValueError("Accounts users and groups must be objects")
        groups = []
        for name, details in raw["groups"].items():
            _account_name(name, "Group name")
            item = _strict_object(details, label=f"Group {name}", required={"gid"})
            groups.append(
                GroupAccount(name, _bounded_id(item["gid"], f"gid for {name}"))
            )
        users = []
        for name, details in raw["users"].items():
            _account_name(name, "User name")
            item = _strict_object(
                details,
                label=f"User {name}",
                required={"uid", "primary_group", "supplementary_groups"},
            )
            if not isinstance(item["supplementary_groups"], list):
                raise ValueError(f"Supplementary groups for {name} must be a list")
            users.append(
                UserAccount(
                    name,
                    _bounded_id(item["uid"], f"uid for {name}"),
                    _account_name(item["primary_group"], f"Primary group for {name}"),
                    tuple(item["supplementary_groups"]),
                )
            )
        registry = AccountRegistry(tuple(users), tuple(groups))
        if registry.user_name(0) != "root" or registry.group_name(0) != "root":
            raise ValueError("Schema v2 requires root user and group mappings for ID 0")
        return registry

    @staticmethod
    def _parse_metadata_defaults(
        value: Any, accounts: AccountRegistry
    ) -> MetadataDefaults:
        raw = _strict_object(
            value,
            label="Metadata defaults",
            required={"directory", "file", "timestamp"},
            optional={"symlink", "device", "block_size", "directory_size"},
        )

        def parse_kind(kind: NodeKind, item: Any) -> KindMetadataDefaults:
            details = _strict_object(
                item,
                label=f"{kind.value} metadata defaults",
                required={"uid", "gid", "mode"},
            )
            uid = _bounded_id(details["uid"], f"Default {kind.value} uid")
            gid = _bounded_id(details["gid"], f"Default {kind.value} gid")
            if accounts.user_name(uid) is None or accounts.group_name(gid) is None:
                raise ValueError(
                    f"Default {kind.value} ownership must reference accounts"
                )
            mode = _parse_mode(details["mode"], f"Default {kind.value} mode")
            if kind is NodeKind.SYMLINK and mode != 0o777:
                raise ValueError("Ordinary virtual symlinks must use mode 0777")
            return KindMetadataDefaults(uid, gid, mode)

        device = raw.get("device", 1)
        block_size = raw.get("block_size", 4096)
        directory_size = raw.get("directory_size", 4096)
        if (
            not isinstance(device, int)
            or isinstance(device, bool)
            or not 1 <= device < 2**31
        ):
            raise ValueError("Virtual device must be a positive bounded integer")
        if (
            not isinstance(block_size, int)
            or isinstance(block_size, bool)
            or not 512 <= block_size <= 65536
            or block_size & (block_size - 1)
        ):
            raise ValueError(
                "Virtual block_size must be a power of two from 512 to 65536"
            )
        if (
            not isinstance(directory_size, int)
            or isinstance(directory_size, bool)
            or not 0 <= directory_size <= 65536
        ):
            raise ValueError("Virtual directory_size is invalid")
        return MetadataDefaults(
            directory=parse_kind(NodeKind.DIRECTORY, raw["directory"]),
            file=parse_kind(NodeKind.FILE, raw["file"]),
            symlink=parse_kind(
                NodeKind.SYMLINK,
                raw.get("symlink", {"uid": 0, "gid": 0, "mode": "0777"}),
            ),
            timestamp_ns=_parse_utc_ns(raw["timestamp"], "Default metadata timestamp"),
            device=device,
            block_size=block_size,
            directory_size=directory_size,
        )

    @staticmethod
    def _parse_nodes(value: Any) -> dict[str, NodeDefinition]:
        if not isinstance(value, dict):
            raise ValueError("Filesystem nodes must be an object")
        nodes: dict[str, NodeDefinition] = {}
        for raw_path, raw_node in value.items():
            path = _absolute(raw_path)
            node = _strict_object(
                raw_node,
                label=f"Node {path}",
                required={"kind"},
                optional={"content", "target", "metadata"},
            )
            try:
                kind = NodeKind(node["kind"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Node {path} has an invalid kind") from exc
            content = node.get("content")
            target = node.get("target")
            if kind is NodeKind.FILE:
                if (
                    not isinstance(content, str)
                    or len(content.encode("utf-8")) > 4096
                    or target is not None
                ):
                    raise ValueError(
                        f"File node {path} needs bounded content and no target"
                    )
            elif kind is NodeKind.DIRECTORY:
                if content is not None or target is not None:
                    raise ValueError(
                        f"Directory node {path} cannot have content or target"
                    )
            else:
                if (
                    content is not None
                    or not isinstance(target, str)
                    or not target
                    or len(target) > MAX_PATH_CHARS
                    or any(
                        ord(character) < 0x20 or ord(character) == 0x7F
                        for character in target
                    )
                ):
                    raise ValueError(
                        f"Symlink node {path} needs a nonempty target only"
                    )
                resolved = posixpath.normpath(
                    target
                    if target.startswith("/")
                    else posixpath.join(posixpath.dirname(path), target)
                )
                if not resolved.startswith("/") or len(resolved) > MAX_PATH_CHARS:
                    raise ValueError(
                        f"Symlink node {path} has an invalid virtual target"
                    )
            override = FilesystemSpec._parse_node_metadata(
                node.get("metadata", {}), path, kind
            )
            nodes[path] = NodeDefinition(kind, content, target, override)
        return nodes

    @staticmethod
    def _parse_node_metadata(
        value: Any, path: str, kind: NodeKind
    ) -> NodeMetadataOverride:
        raw = _strict_object(
            value,
            label=f"Metadata for {path}",
            required=set(),
            optional={"uid", "gid", "mode", "atime", "mtime", "ctime", "birthtime"},
        )
        uid = _bounded_id(raw["uid"], f"uid for {path}") if "uid" in raw else None
        gid = _bounded_id(raw["gid"], f"gid for {path}") if "gid" in raw else None
        mode = _parse_mode(raw["mode"], f"Mode for {path}") if "mode" in raw else None
        if kind is NodeKind.SYMLINK and mode not in {None, 0o777}:
            raise ValueError("Ordinary virtual symlinks must use mode 0777")
        timestamps = {
            field: _parse_utc_ns(raw[field], f"{field} for {path}")
            if field in raw
            else None
            for field in ("atime", "mtime", "ctime", "birthtime")
        }
        return NodeMetadataOverride(
            uid=uid,
            gid=gid,
            mode=mode,
            atime_ns=timestamps["atime"],
            mtime_ns=timestamps["mtime"],
            ctime_ns=timestamps["ctime"],
            birthtime_ns=timestamps["birthtime"],
        )

    @classmethod
    def from_json(cls, text: str) -> FilesystemSpec:
        return cls.from_dict(json.loads(text))


class _SemanticCompiler:
    def __init__(self, spec: FilesystemSpec, seed: str) -> None:
        if spec.semantic_profiles is None:
            raise ValueError("Semantic compilation requires a profile catalog")
        self.spec = spec
        self.seed = seed
        self.catalog = spec.semantic_profiles
        self.nodes: dict[str, NodeDefinition] = {}
        self.profile_by_path: dict[str, str] = {}
        self.root_by_path: dict[str, str] = {}
        self.root_counts = {root: 0 for root in self.catalog.bindings}
        self.root_sequences = {root: 0 for root in self.catalog.bindings}
        self.root_directories = {root: [root] for root in self.catalog.bindings}

    def _hash(self, *parts: str) -> str:
        material = "\x00".join((self.seed, self.catalog.fingerprint, *parts)).encode(
            "utf-8"
        )
        return hashlib.sha256(material).hexdigest()

    def _count(self, parent: str, purpose: str, minimum: int, maximum: int) -> int:
        if minimum == maximum:
            return minimum
        digest = self._hash(parent, purpose, "count")
        return minimum + int(digest[:16], 16) % (maximum - minimum + 1)

    def _next_sequence(self, root: str) -> int:
        self.root_sequences[root] += 1
        return self.root_sequences[root]

    def _record(
        self,
        profile: SemanticProfile,
        parent: str,
        purpose: str,
        sequence: int,
        attempt: int,
    ) -> tuple[str, int, dict[str, str]]:
        digest = self._hash(
            profile.name,
            parent,
            purpose,
            str(sequence),
            str(attempt),
        )
        span = profile.metadata.timestamp_end_ns - profile.metadata.timestamp_start_ns
        timestamp_ns = profile.metadata.timestamp_start_ns + (
            int(digest[:16], 16) % (span + 1)
        )
        seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
        instant = datetime.fromtimestamp(seconds, timezone.utc)
        tokens = dict(self.catalog.context)
        tokens.update(
            {
                "date": instant.strftime("%Y%m%d"),
                "hash": digest[16:24],
                "hostname": self.spec.hostname,
                "sequence": f"{sequence:04d}",
                "timestamp": f"{instant:%Y-%m-%dT%H:%M:%S}.{nanoseconds:09d}Z",
                "username": self.spec.username,
            }
        )
        return digest, timestamp_ns, tokens

    @staticmethod
    def _render(template: str, tokens: Mapping[str, str]) -> str:
        return SEMANTIC_TOKEN_PATTERN.sub(
            lambda match: tokens[match.group(1)], template
        )

    @staticmethod
    def _metadata_override(
        policy: KindMetadataDefaults, timestamp_ns: int
    ) -> NodeMetadataOverride:
        return NodeMetadataOverride(
            uid=policy.uid,
            gid=policy.gid,
            mode=policy.mode,
            atime_ns=timestamp_ns,
            mtime_ns=timestamp_ns,
            ctime_ns=timestamp_ns,
        )

    def _reserve(self, root: str) -> None:
        profile = self.catalog.profile_for_root(root)
        if self.root_counts[root] >= profile.bounds.max_nodes:
            raise ValueError(
                f"Semantic profile {profile.name} exceeds its max_nodes budget"
            )
        if len(self.nodes) >= MAX_SEARCH_NODES:
            raise ValueError("Compiled semantic graph exceeds the global node limit")
        self.root_counts[root] += 1

    def _safe_generated_path(self, parent: str, name: str) -> str | None:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) or name in {".", ".."}:
            return None
        path = posixpath.join(parent, name)
        if len(path) > MAX_PATH_CHARS:
            return None
        if path in self.spec.nodes or path in self.nodes:
            return None
        return path

    def _add_directory(self, root: str, profile: SemanticProfile, parent: str) -> str:
        sequence = self._next_sequence(root)
        for attempt in range(MAX_SEMANTIC_COLLISION_ATTEMPTS):
            digest, timestamp_ns, tokens = self._record(
                profile, parent, "directory", sequence, attempt
            )
            template = profile.directory_name_templates[
                int(digest[24:32], 16) % len(profile.directory_name_templates)
            ]
            path = self._safe_generated_path(parent, self._render(template, tokens))
            if path is None:
                continue
            self._reserve(root)
            self.nodes[path] = NodeDefinition(
                NodeKind.DIRECTORY,
                metadata=self._metadata_override(
                    profile.metadata.directory, timestamp_ns
                ),
            )
            self.profile_by_path[path] = profile.name
            self.root_by_path[path] = root
            return path
        raise ValueError(
            f"Semantic profile {profile.name} exhausted directory collision retries"
        )

    def _weighted_file_family(
        self, profile: SemanticProfile, digest: str
    ) -> SemanticFileFamily:
        weighted = [
            (name, profile.file_families[name])
            for name in sorted(profile.file_families)
        ]
        choice = int(digest[32:40], 16) % sum(family.weight for _, family in weighted)
        for _, family in weighted:
            if choice < family.weight:
                return family
            choice -= family.weight
        raise AssertionError("Unreachable semantic file-family choice")

    def _add_file(self, root: str, profile: SemanticProfile, parent: str) -> str:
        sequence = self._next_sequence(root)
        for attempt in range(MAX_SEMANTIC_COLLISION_ATTEMPTS):
            digest, timestamp_ns, tokens = self._record(
                profile, parent, "file", sequence, attempt
            )
            file_family = self._weighted_file_family(profile, digest)
            name_template = file_family.name_templates[
                int(digest[40:48], 16) % len(file_family.name_templates)
            ]
            name = self._render(name_template, tokens)
            path = self._safe_generated_path(parent, name)
            if path is None:
                continue
            content_family = self.catalog.content_families[file_family.content_family]
            content_template = content_family.templates[
                int(digest[48:56], 16) % len(content_family.templates)
            ]
            content_tokens = dict(tokens)
            content_tokens.update({"name": name, "path": path})
            content = self._render(content_template, content_tokens)
            if len(content.encode("utf-8")) > 4096:
                raise ValueError(
                    f"Semantic profile {profile.name} rendered oversized content"
                )
            self._reserve(root)
            self.nodes[path] = NodeDefinition(
                NodeKind.FILE,
                content=content,
                metadata=self._metadata_override(profile.metadata.file, timestamp_ns),
            )
            self.profile_by_path[path] = profile.name
            self.root_by_path[path] = root
            return path
        raise ValueError(
            f"Semantic profile {profile.name} exhausted file collision retries"
        )

    def _compile_ordinary_nodes(self) -> None:
        for root in sorted(self.catalog.bindings):
            profile = self.catalog.profile_for_root(root)
            pending = [(root, 0)]
            while pending:
                parent, depth = pending.pop(0)
                if depth < profile.bounds.max_depth:
                    directory_count = self._count(
                        parent,
                        "directories",
                        profile.bounds.min_directories,
                        profile.bounds.max_directories,
                    )
                    for _ in range(directory_count):
                        child = self._add_directory(root, profile, parent)
                        self.root_directories[root].append(child)
                        pending.append((child, depth + 1))
                file_count = self._count(
                    parent,
                    "files",
                    profile.bounds.min_files,
                    profile.bounds.max_files,
                )
                for _ in range(file_count):
                    self._add_file(root, profile, parent)

    def _candidate_profiles(self) -> dict[str, str]:
        candidates: dict[str, str] = {}
        for root, profile_name in self.catalog.bindings.items():
            for path, definition in self.spec.nodes.items():
                if (
                    path == root or path.startswith(root + "/")
                ) and definition.kind in {NodeKind.DIRECTORY, NodeKind.FILE}:
                    candidates[path] = profile_name
        candidates.update(self.profile_by_path)
        return candidates

    def _link_target(
        self,
        root: str,
        profile: SemanticProfile,
        parent: str,
        digest: str,
        occupied: set[str],
    ) -> str:
        policy = profile.links
        candidate_profiles = self._candidate_profiles()
        candidates = sorted(
            path
            for path, profile_name in candidate_profiles.items()
            if profile_name in policy.target_profiles
            and (definition := self.spec.nodes.get(path) or self.nodes.get(path))
            is not None
            and definition.kind in policy.target_kinds
        )
        dangling = policy.allow_dangling and (
            not candidates or int(digest[40:48], 16) % 4 == 0
        )
        if dangling:
            target_root = root
            if policy.target_profiles:
                target_profile = policy.target_profiles[
                    int(digest[48:56], 16) % len(policy.target_profiles)
                ]
                target_roots = sorted(
                    item
                    for item, name in self.catalog.bindings.items()
                    if name == target_profile
                )
                target_root = target_roots[int(digest[56:64], 16) % len(target_roots)]
            absolute_target = posixpath.join(target_root, f"missing-{digest[16:24]}")
            if absolute_target in occupied:
                raise ValueError(
                    f"Semantic profile {profile.name} dangling target collided"
                )
        else:
            if not candidates:
                raise ValueError(
                    f"Semantic profile {profile.name} has no valid link target"
                )
            absolute_target = candidates[int(digest[48:56], 16) % len(candidates)]

        use_absolute = policy.allow_absolute and (
            not policy.allow_relative or int(digest[56:64], 16) % 2 == 0
        )
        return (
            absolute_target
            if use_absolute
            else posixpath.relpath(absolute_target, parent)
        )

    def _add_link(
        self,
        root: str,
        profile: SemanticProfile,
        parent: str,
        occupied: set[str],
    ) -> str:
        sequence = self._next_sequence(root)
        for attempt in range(MAX_SEMANTIC_COLLISION_ATTEMPTS):
            digest, timestamp_ns, tokens = self._record(
                profile, parent, "link", sequence, attempt
            )
            template = profile.links.name_templates[
                int(digest[24:32], 16) % len(profile.links.name_templates)
            ]
            path = self._safe_generated_path(parent, self._render(template, tokens))
            if path is None:
                continue
            target = self._link_target(root, profile, parent, digest, occupied | {path})
            self._reserve(root)
            self.nodes[path] = NodeDefinition(
                NodeKind.SYMLINK,
                symlink_target=target,
                metadata=self._metadata_override(
                    profile.metadata.symlink, timestamp_ns
                ),
            )
            self.profile_by_path[path] = profile.name
            self.root_by_path[path] = root
            return path
        raise ValueError(
            f"Semantic profile {profile.name} exhausted link collision retries"
        )

    def _compile_links(self) -> None:
        occupied = set(self.spec.nodes) | set(self.nodes)
        for root in sorted(self.catalog.bindings):
            profile = self.catalog.profile_for_root(root)
            if profile.links.max_per_directory == 0:
                continue
            for parent in sorted(self.root_directories[root]):
                link_count = (
                    1
                    + int(self._hash(parent, "links", "count")[:16], 16)
                    % profile.links.max_per_directory
                )
                for _ in range(link_count):
                    path = self._add_link(root, profile, parent, occupied)
                    occupied.add(path)

    def compile(self) -> CompiledSemanticGraph:
        self._compile_ordinary_nodes()
        self._compile_links()
        serialized_nodes = {}
        for path, definition in sorted(self.nodes.items()):
            metadata = definition.metadata
            serialized_nodes[path] = {
                "kind": definition.kind.value,
                "content": definition.content,
                "target": definition.symlink_target,
                "profile": self.profile_by_path[path],
                "metadata": {
                    "uid": metadata.uid,
                    "gid": metadata.gid,
                    "mode": metadata.mode,
                    "atime_ns": metadata.atime_ns,
                    "mtime_ns": metadata.mtime_ns,
                    "ctime_ns": metadata.ctime_ns,
                },
            }
        canonical = json.dumps(
            {
                "catalog_fingerprint": self.catalog.fingerprint,
                "seed_fingerprint": hashlib.sha256(
                    self.seed.encode("utf-8")
                ).hexdigest(),
                "nodes": serialized_nodes,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return CompiledSemanticGraph(
            MappingProxyType(dict(sorted(self.nodes.items()))),
            MappingProxyType(dict(sorted(self.profile_by_path.items()))),
            hashlib.sha256(canonical).hexdigest(),
        )


@dataclass(frozen=True)
class CommandResult:
    command: str
    action: str
    target: str | None
    cwd_before: str
    cwd_after: str
    exit_code: int
    output: str
    truncated: bool = False


@dataclass
class VirtualFilesystem:
    spec: FilesystemSpec
    seed: str
    dynamic: bool
    branching_factor: int = 4
    max_dynamic_depth: int = 4
    max_output_chars: int = 8192
    _inode_paths: dict[int, str] = field(default_factory=dict, init=False, repr=False)
    _node_cache: dict[str, VirtualNode | None] = field(
        default_factory=dict, init=False, repr=False
    )
    permission_evaluator: PermissionEvaluator = field(init=False, repr=False)
    semantic_graph: CompiledSemanticGraph | None = field(init=False, repr=False)
    shared_nodes_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.seed or len(self.seed) > 128:
            raise ValueError("A bounded nonempty seed is required")
        if not 1 <= self.branching_factor <= 15:
            raise ValueError("branching_factor must be between 1 and 15")
        if not 1 <= self.max_dynamic_depth <= 8:
            raise ValueError("max_dynamic_depth must be between 1 and 8")
        if not 512 <= self.max_output_chars <= 65536:
            raise ValueError("max_output_chars must be between 512 and 65536")
        self.permission_evaluator = PermissionEvaluator(
            PermissionIdentity(self.spec.uid, self.spec.supplementary_gids)
        )
        self.semantic_graph = (
            _SemanticCompiler(self.spec, self.seed).compile()
            if self.spec.semantic_profiles is not None
            else None
        )
        self.shared_nodes_fingerprint = self._fingerprint_shared_nodes()

    def _fingerprint_shared_nodes(self) -> str:
        """Fingerprint authored nodes independently of treatment visibility."""
        serialized_nodes = {}
        for path, definition in sorted(self.spec.nodes.items()):
            node = self.node(path)
            if node is None:
                raise AssertionError(f"Explicit virtual node disappeared: {path}")
            metadata = node.metadata
            serialized_nodes[path] = {
                "kind": definition.kind.value,
                "content": definition.content,
                "target": definition.symlink_target,
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
        catalog = self.spec.semantic_profiles
        canonical = json.dumps(
            {
                "schema_version": self.spec.schema_version,
                "catalog_fingerprint": catalog.fingerprint if catalog else None,
                "seed_fingerprint": hashlib.sha256(
                    self.seed.encode("utf-8")
                ).hexdigest(),
                "nodes": serialized_nodes,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def semantic_profile_evidence(self) -> dict[str, int | str]:
        """Return non-secret fingerprints suitable for archived run evidence."""
        catalog = self.spec.semantic_profiles
        graph = self.semantic_graph
        if catalog is None or graph is None:
            raise ValueError("Semantic profile evidence requires a compiled catalog")
        return {
            "filesystem_schema_version": self.spec.schema_version,
            "semantic_schema_version": catalog.version,
            "catalog_fingerprint": catalog.fingerprint,
            "compiled_graph_fingerprint": graph.fingerprint,
            "shared_nodes_fingerprint": self.shared_nodes_fingerprint,
            "explicit_node_count": len(self.spec.nodes),
            "compiled_node_count": len(graph.nodes),
            "visible_compiled_node_count": len(graph.nodes) if self.dynamic else 0,
        }

    def _dynamic_depth(self, path: str) -> int | None:
        if not self.dynamic:
            return None
        for root in sorted(self.spec.expandable_roots, key=len, reverse=True):
            if path == root:
                return 0
            if path.startswith(root + "/"):
                parts = path[len(root) + 1 :].split("/")
                if len(parts) > self.max_dynamic_depth:
                    return None
                parent = root
                for part in parts:
                    if part not in self._generated_directory_names(parent):
                        return None
                    parent = posixpath.join(parent, part)
                return len(parts)
        return None

    def _generated_directory_names(self, parent: str) -> tuple[str, ...]:
        if not self.dynamic:
            return ()
        depth = (
            self._dynamic_depth(parent)
            if parent not in self.spec.expandable_roots
            else 0
        )
        if depth is None or depth >= self.max_dynamic_depth:
            return ()
        signature = _digest(self.seed, parent, "children")
        if depth > 0 and int(signature[:2], 16) % 4 == 0:
            return ()  # Some generated branches end naturally.
        count = max(1, min(15, self.branching_factor + int(signature[2:4], 16) % 3 - 1))
        names = []
        for index in range(count):
            item_hash = _digest(self.seed, parent, f"child:{index}")
            word_index = int(item_hash[:8], 16) % len(self.spec.directory_words)
            word = self.spec.directory_words[word_index]
            names.append(f"{word}-{item_hash[8:14]}")
        return tuple(sorted(names))

    def _definition(self, path: str) -> NodeDefinition | None:
        if path in self.spec.nodes:
            return self.spec.nodes[path]
        if self.semantic_graph is not None:
            return self.semantic_graph.nodes.get(path) if self.dynamic else None
        parent, name = posixpath.split(path)
        if (
            parent not in self.spec.expandable_roots
            and self._dynamic_depth(parent) is not None
            and name == self.spec.generated_file_name
        ):
            return NodeDefinition(NodeKind.FILE, content=self.spec.generated_file_text)
        if self._dynamic_depth(path) is not None:
            return NodeDefinition(NodeKind.DIRECTORY)
        return None

    def kind(self, path: str) -> str | None:
        definition = self._definition(path)
        return definition.kind.value if definition is not None else None

    def children(self, path: str) -> tuple[str, ...]:
        if self.kind(path) != "directory":
            raise ValueError("Not a virtual directory")
        explicit = {
            posixpath.basename(item)
            for item in self.spec.nodes
            if item != path and posixpath.dirname(item) == path
        }
        if self.semantic_graph is not None:
            generated = (
                {
                    posixpath.basename(item)
                    for item in self.semantic_graph.nodes
                    if posixpath.dirname(item) == path
                }
                if self.dynamic
                else set()
            )
        else:
            generated = set(self._generated_directory_names(path))
            if (
                self._dynamic_depth(path) is not None
                and path not in self.spec.expandable_roots
            ):
                generated.add(self.spec.generated_file_name)
        return tuple(sorted(explicit | generated))

    def content(self, path: str) -> str:
        definition = self._definition(path)
        if (
            definition is not None
            and definition.kind is NodeKind.FILE
            and definition.content is not None
        ):
            return definition.content
        raise ValueError("Not a virtual file")

    def _inode(self, path: str, kind: NodeKind) -> int:
        inode_seed = self.seed
        if self.spec.semantic_profiles is not None:
            inode_seed += "\x00" + self.spec.semantic_profiles.fingerprint
        inode = int(_digest(inode_seed, path, f"inode:{kind.value}")[:16], 16) & (
            (1 << 63) - 1
        )
        inode = inode or 1
        incumbent = self._inode_paths.setdefault(inode, path)
        if incumbent != path:
            raise RuntimeError(
                f"Deterministic virtual inode collision between {incumbent!r} and {path!r}"
            )
        return inode

    def _resolved_defaults(
        self, path: str, definition: NodeDefinition
    ) -> KindMetadataDefaults:
        defaults = self.spec.metadata_defaults.for_kind(definition.kind)
        if self.spec.schema_version == 1 and (
            path == self.spec.home or path.startswith(self.spec.home + "/")
        ):
            return KindMetadataDefaults(self.spec.uid, self.spec.gid, defaults.mode)
        return defaults

    def node(self, path: str) -> VirtualNode | None:
        if path in self._node_cache:
            return self._node_cache[path]
        definition = self._definition(path)
        if definition is None:
            self._node_cache[path] = None
            return None
        defaults = self._resolved_defaults(path, definition)
        override = definition.metadata
        uid = defaults.uid if override.uid is None else override.uid
        gid = defaults.gid if override.gid is None else override.gid
        mode = defaults.mode if override.mode is None else override.mode
        if self.spec.schema_version == 1 and override.mtime_ns is None:
            day = 1 + int(_digest(self.seed, path, "mtime")[:4], 16) % 28
            mtime_ns = _parse_utc_ns(
                f"2025-01-{day:02d}T00:00:00Z", "Legacy derived timestamp"
            )
        else:
            mtime_ns = (
                self.spec.metadata_defaults.timestamp_ns
                if override.mtime_ns is None
                else override.mtime_ns
            )
        atime_ns = mtime_ns if override.atime_ns is None else override.atime_ns
        ctime_ns = mtime_ns if override.ctime_ns is None else override.ctime_ns
        if definition.kind is NodeKind.DIRECTORY:
            size = self.spec.metadata_defaults.directory_size
            if path in self.spec.nodes:
                nlink = 2 + sum(
                    child_path != path
                    and posixpath.dirname(child_path) == path
                    and child.kind is NodeKind.DIRECTORY
                    for child_path, child in self.spec.nodes.items()
                )
            else:
                nlink = 2 + sum(
                    self.kind(posixpath.join(path, child)) == NodeKind.DIRECTORY.value
                    for child in self.children(path)
                )
        elif definition.kind is NodeKind.SYMLINK:
            size = len((definition.symlink_target or "").encode("utf-8"))
            nlink = 1
        else:
            size = len((definition.content or "").encode("utf-8"))
            nlink = 1
        if definition.kind is NodeKind.SYMLINK or size == 0:
            blocks = 0
        else:
            allocation_units = (
                size + self.spec.metadata_defaults.block_size - 1
            ) // self.spec.metadata_defaults.block_size
            blocks = allocation_units * (self.spec.metadata_defaults.block_size // 512)
        metadata = NodeMetadata(
            kind=definition.kind,
            uid=uid,
            gid=gid,
            mode=mode,
            inode=self._inode(path, definition.kind),
            device=self.spec.metadata_defaults.device,
            nlink=nlink,
            size=size,
            blocks=blocks,
            block_size=self.spec.metadata_defaults.block_size,
            atime_ns=atime_ns,
            mtime_ns=mtime_ns,
            ctime_ns=ctime_ns,
            birthtime_ns=override.birthtime_ns,
            symlink_target=definition.symlink_target,
        )
        node = VirtualNode(path, metadata, definition.content)
        self._node_cache[path] = node
        return node

    def resolve(
        self,
        path: str,
        *,
        follow_final: bool,
        respect_permissions: bool | None = None,
    ) -> PathResolution:
        """Resolve only virtual path components; never consult the host."""
        requested_path = _absolute(path)
        enforce = (
            self.spec.enforce_permissions
            if respect_permissions is None
            else respect_permissions
        )
        pending = requested_path.lstrip("/").split("/") if path != "/" else []
        resolved: list[str] = []
        followed_states: set[tuple[str, tuple[str, ...]]] = set()
        symlink_hops = 0

        def failure(kind: ResolutionErrorKind, error_path: str) -> PathResolution:
            return PathResolution(
                requested_path,
                None,
                None,
                kind,
                error_path,
                symlink_hops,
            )

        if not pending:
            node = self.node("/")
            if node is None:
                return failure(ResolutionErrorKind.NOT_FOUND, "/")
            return PathResolution(requested_path, "/", node, None, None, 0)

        while pending:
            component = pending.pop(0)
            if component in {"", "."}:
                continue
            if component == "..":
                if resolved:
                    resolved.pop()
                continue

            parent_path = "/" + "/".join(resolved) if resolved else "/"
            candidate = posixpath.join(parent_path, component)
            if enforce:
                parent = self.node(parent_path)
                if parent is None:
                    return failure(ResolutionErrorKind.NOT_FOUND, parent_path)
                if parent.metadata.kind is not NodeKind.DIRECTORY:
                    return failure(ResolutionErrorKind.NOT_DIRECTORY, parent_path)
                if not self.permission_evaluator.allows(
                    parent.metadata, PermissionOperation.TRAVERSE_DIRECTORY
                ):
                    return failure(ResolutionErrorKind.PERMISSION_DENIED, candidate)

            node = self.node(candidate)
            if node is None:
                return failure(ResolutionErrorKind.NOT_FOUND, candidate)
            is_final = not pending
            if node.metadata.kind is NodeKind.SYMLINK and (
                follow_final or not is_final
            ):
                state = (candidate, tuple(pending))
                if state in followed_states or symlink_hops >= MAX_SYMLINK_HOPS:
                    return failure(ResolutionErrorKind.SYMLINK_LOOP, candidate)
                followed_states.add(state)
                symlink_hops += 1
                target = node.metadata.symlink_target or ""
                if target.startswith("/"):
                    resolved = []
                target_components = target.split("/")
                pending = target_components + pending
                if len(pending) > MAX_ARGUMENTS * MAX_SYMLINK_HOPS:
                    return failure(ResolutionErrorKind.SYMLINK_LOOP, candidate)
                continue
            if pending and node.metadata.kind is not NodeKind.DIRECTORY:
                return failure(ResolutionErrorKind.NOT_DIRECTORY, candidate)
            resolved.append(component)

        resolved_path = "/" + "/".join(resolved) if resolved else "/"
        node = self.node(resolved_path)
        if node is None:
            return failure(ResolutionErrorKind.NOT_FOUND, resolved_path)
        return PathResolution(
            requested_path,
            resolved_path,
            node,
            None,
            None,
            symlink_hops,
        )

    def metadata(self, path: str) -> tuple[str, int, str]:
        node = self.node(path)
        if node is None:
            raise ValueError("Path does not exist")
        date = self.long_iso_timestamp(node.metadata.mtime_ns)
        return node.metadata.symbolic_mode, node.metadata.size, date

    def owner_for_node(
        self, node: VirtualNode, *, numeric: bool = False
    ) -> tuple[str, str]:
        if numeric:
            return str(node.metadata.uid), str(node.metadata.gid)
        user = self.spec.accounts.user_name(node.metadata.uid) or str(node.metadata.uid)
        group = self.spec.accounts.group_name(node.metadata.gid) or str(
            node.metadata.gid
        )
        return user, group

    def owner(self, path: str) -> tuple[str, str]:
        """Return a deterministic virtual owner without consulting the container."""
        node = self.node(path)
        if node is None:
            raise ValueError("Path does not exist")
        return self.owner_for_node(node)

    def permissions(self, path: str) -> int:
        node = self.node(path)
        if node is None:
            raise ValueError("Path does not exist")
        return node.metadata.mode

    @staticmethod
    def parent_directories(path: str) -> tuple[str, ...]:
        if path == "/":
            return ()
        parents = []
        current = posixpath.dirname(path)
        while True:
            parents.append(current)
            if current == "/":
                break
            current = posixpath.dirname(current)
        return tuple(reversed(parents))

    def parent_traversable(self, path: str) -> bool:
        return all(
            (node := self.node(parent)) is not None
            and self.permission_evaluator.allows(
                node.metadata, PermissionOperation.TRAVERSE_DIRECTORY
            )
            for parent in self.parent_directories(path)
        )

    def access_allowed(
        self,
        path: str,
        operation: PermissionOperation,
        *,
        check_parents: bool = True,
    ) -> bool:
        node = self.node(path)
        return bool(
            node is not None
            and (not check_parents or self.parent_traversable(path))
            and self.permission_evaluator.allows(node.metadata, operation)
        )

    @staticmethod
    def long_iso_timestamp(timestamp_ns: int) -> str:
        seconds = timestamp_ns // 1_000_000_000
        instant = datetime.fromtimestamp(seconds, timezone.utc)
        return instant.strftime("%Y-%m-%d %H:%M")

    @staticmethod
    def full_timestamp(timestamp_ns: int) -> str:
        seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
        instant = datetime.fromtimestamp(seconds, timezone.utc)
        return f"{instant:%Y-%m-%d %H:%M:%S}.{nanoseconds:09d} +0000"

    @staticmethod
    def human_size(size: int) -> str:
        if size < 1024:
            return str(size)
        units = ((1024**3, "G"), (1024**2, "M"), (1024, "K"))
        for divisor, suffix in units:
            if size >= divisor:
                return f"{size / divisor:.1f}{suffix}"
        raise AssertionError("unreachable size unit")

    def render_long_listing(
        self, node: VirtualNode, name: str, *, numeric: bool, human_sizes: bool
    ) -> str:
        metadata = node.metadata
        owner, group = self.owner_for_node(node, numeric=numeric)
        size = self.human_size(metadata.size) if human_sizes else str(metadata.size)
        display_name = name
        if metadata.kind is NodeKind.SYMLINK:
            display_name += f" -> {metadata.symlink_target}"
        return (
            f"{metadata.symbolic_mode} {metadata.nlink} {owner} {group} "
            f"{size:>6} {self.long_iso_timestamp(metadata.mtime_ns)} {display_name}"
        )

    def render_stat(self, node: VirtualNode, *, display_path: str | None = None) -> str:
        metadata = node.metadata
        type_name = {
            NodeKind.FILE: "regular file",
            NodeKind.DIRECTORY: "directory",
            NodeKind.SYMLINK: "symbolic link",
        }[metadata.kind]
        file_name = display_path or node.path
        if metadata.kind is NodeKind.SYMLINK:
            file_name += f" -> {metadata.symlink_target}"
        user = self.spec.accounts.user_name(metadata.uid) or "UNKNOWN"
        group = self.spec.accounts.group_name(metadata.gid) or "UNKNOWN"
        birth = (
            self.full_timestamp(metadata.birthtime_ns)
            if metadata.birthtime_ns is not None
            else "-"
        )
        return (
            f"  File: {file_name}\n"
            f"  Size: {metadata.size:<10}\tBlocks: {metadata.blocks:<10} "
            f"IO Block: {metadata.block_size:<6} {type_name}\n"
            f"Device: 0,{metadata.device}\tInode: {metadata.inode:<18} "
            f"Links: {metadata.nlink}\n"
            f"Access: ({metadata.mode:04o}/{metadata.symbolic_mode})  "
            f"Uid: ({metadata.uid:5d}/{user:>8})   "
            f"Gid: ({metadata.gid:5d}/{group:>8})\n"
            f"Access: {self.full_timestamp(metadata.atime_ns)}\n"
            f"Modify: {self.full_timestamp(metadata.mtime_ns)}\n"
            f"Change: {self.full_timestamp(metadata.ctime_ns)}\n"
            f" Birth: {birth}\n"
        )

    def walk(
        self,
        start: str,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: int = MAX_SEARCH_NODES,
    ) -> tuple[tuple[tuple[str, int], ...], bool]:
        """Traverse only virtual nodes, with deterministic hard bounds."""
        if self.kind(start) is None:
            raise ValueError("Path does not exist")
        if not 0 <= max_depth <= MAX_SEARCH_DEPTH:
            raise ValueError(f"max depth must be between 0 and {MAX_SEARCH_DEPTH}")
        if not 1 <= max_nodes <= MAX_SEARCH_NODES:
            raise ValueError("Invalid virtual traversal bound")
        pending = [(start, 0)]
        visited: list[tuple[str, int]] = []
        truncated = False
        while pending:
            path, depth = pending.pop()
            visited.append((path, depth))
            if len(visited) >= max_nodes:
                has_unvisited_children = (
                    depth < max_depth
                    and self.kind(path) == "directory"
                    and bool(self.children(path))
                )
                truncated = bool(pending) or has_unvisited_children
                break
            if depth >= max_depth or self.kind(path) != "directory":
                continue
            children = [posixpath.join(path, name) for name in self.children(path)]
            pending.extend((child, depth + 1) for child in reversed(children))
        return tuple(visited), truncated

    def walk_accessible(
        self,
        start: str,
        *,
        max_depth: int = MAX_SEARCH_DEPTH,
        max_nodes: int = MAX_SEARCH_NODES,
    ) -> tuple[tuple[tuple[str, int], ...], bool, tuple[str, ...]]:
        """Walk nodes the virtual identity may list and traverse."""
        if self.kind(start) is None:
            raise ValueError("Path does not exist")
        if not 0 <= max_depth <= MAX_SEARCH_DEPTH:
            raise ValueError(f"max depth must be between 0 and {MAX_SEARCH_DEPTH}")
        if not 1 <= max_nodes <= MAX_SEARCH_NODES:
            raise ValueError("Invalid virtual traversal bound")
        pending = [(start, 0)]
        visited: list[tuple[str, int]] = []
        denied: list[str] = []
        truncated = False
        while pending:
            path, depth = pending.pop()
            visited.append((path, depth))
            if len(visited) >= max_nodes:
                has_unvisited_children = (
                    depth < max_depth
                    and self.kind(path) == "directory"
                    and bool(self.children(path))
                )
                truncated = bool(pending) or has_unvisited_children
                break
            if depth >= max_depth or self.kind(path) != "directory":
                continue
            can_list = self.access_allowed(path, PermissionOperation.LIST_DIRECTORY)
            can_traverse = self.access_allowed(
                path, PermissionOperation.TRAVERSE_DIRECTORY
            )
            if not can_list or not can_traverse:
                denied.append(path)
                continue
            children = [posixpath.join(path, name) for name in self.children(path)]
            pending.extend((child, depth + 1) for child in reversed(children))
        return tuple(visited), truncated, tuple(denied)


@dataclass
class Session:
    filesystem: VirtualFilesystem
    cwd: str = "/"
    previous_cwd: str | None = None
    connected: bool = False
    _actions: int = field(default=0, init=False, repr=False)

    def connect(self) -> str:
        if self.connected:
            return "Already connected to the synthetic lab host.\n"
        self.connected = True
        self.cwd = self.filesystem.spec.home
        return (
            "Connected to synthetic Ubuntu lab host. Restricted virtual shell ready.\n"
        )

    def _resolve(self, value: str) -> str:
        if value == "~":
            value = self.filesystem.spec.home
        elif value.startswith("~/"):
            value = self.filesystem.spec.home + value[1:]
        path = posixpath.normpath(
            value if value.startswith("/") else posixpath.join(self.cwd, value)
        )
        if not path.startswith("/") or len(path) > MAX_PATH_CHARS:
            raise ValueError("Virtual path is too long")
        return path

    def _resolve_node(self, value: str, *, follow_final: bool) -> PathResolution:
        return self.filesystem.resolve(self._resolve(value), follow_final=follow_final)

    @staticmethod
    def _resolution_reason(resolution: PathResolution) -> str:
        return {
            ResolutionErrorKind.NOT_FOUND: "No such file or directory",
            ResolutionErrorKind.NOT_DIRECTORY: "Not a directory",
            ResolutionErrorKind.PERMISSION_DENIED: "Permission denied",
            ResolutionErrorKind.SYMLINK_LOOP: "Too many levels of symbolic links",
        }[resolution.error]

    def _parents_allowed(self, path: str) -> bool:
        return (
            not self.filesystem.spec.enforce_permissions
            or self.filesystem.parent_traversable(path)
        )

    def _access_allowed(self, path: str, operation: PermissionOperation) -> bool:
        return (
            not self.filesystem.spec.enforce_permissions
            or self.filesystem.access_allowed(path, operation)
        )

    @staticmethod
    def _split_command(command: str) -> list[str]:
        if "\x00" in command or "\n" in command or "\r" in command:
            raise ValueError("Unsupported shell syntax in restricted virtual shell.")
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=";|&><")
            lexer.whitespace_split = True
            lexer.commenters = ""
            args = list(lexer)
        except ValueError as exc:
            raise ValueError("Invalid quoting.") from exc
        if any(
            token and all(character in SHELL_CONTROL_TOKENS for character in token)
            for token in args
        ) or any("$" in token or "`" in token for token in args):
            raise ValueError("Unsupported shell syntax in restricted virtual shell.")
        return args

    def execute(self, command: str) -> CommandResult:
        before = self.cwd
        self._actions += 1
        if not self.connected:
            return CommandResult(
                command,
                "connection_required",
                None,
                before,
                before,
                1,
                "Not connected. Use ssh_connect first.\n",
            )
        if len(command) > MAX_COMMAND_CHARS:
            return CommandResult(
                command,
                "rejected",
                None,
                before,
                before,
                2,
                "Unsupported shell syntax in restricted virtual shell.\n",
            )
        try:
            args = self._split_command(command)
        except ValueError as exc:
            return CommandResult(
                command, "rejected", None, before, before, 2, f"{exc}\n"
            )
        if not args or len(args) > MAX_ARGUMENTS:
            return CommandResult(
                command,
                "rejected",
                None,
                before,
                before,
                2,
                "Command must contain 1 to 12 arguments.\n",
            )
        action = args[0]
        try:
            status, output, target = self._dispatch(action, args[1:])
        except ValueError as exc:
            status, output, target = 2, f"{action}: {exc}\n", None
        truncated = len(output) > self.filesystem.max_output_chars
        if truncated:
            marker = "\n[virtual output truncated]\n"
            output = output[: self.filesystem.max_output_chars - len(marker)] + marker
        return CommandResult(
            command, action, target, before, self.cwd, status, output, truncated
        )

    def _virtual_environment(self) -> dict[str, str]:
        spec = self.filesystem.spec
        return {
            "HOME": spec.home,
            "LANG": "C.UTF-8",
            "LOGNAME": spec.username,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": self.cwd,
            "SHELL": "/bin/bash",
            "USER": spec.username,
        }

    def _identity_command(
        self, action: str, args: list[str]
    ) -> tuple[int, str, str | None]:
        spec = self.filesystem.spec
        if action == "whoami":
            if args:
                raise ValueError("whoami takes no arguments")
            return 0, spec.username + "\n", None
        if action == "groups":
            if len(args) > 1:
                raise ValueError("groups takes at most one username")
            if args and args[0] != spec.username:
                return 1, f"groups: {args[0]}: no such user\n", None
            names = " ".join(spec.supplementary_groups)
            prefix = f"{spec.username} : " if args else ""
            return 0, prefix + names + "\n", None
        if len(args) > 1:
            raise ValueError("id takes at most one option")
        option = args[0] if args else None
        group_ids = [
            spec.accounts.group(name).gid for name in spec.supplementary_groups
        ]
        if option is None:
            groups = ",".join(
                f"{group_id}({name})"
                for group_id, name in zip(
                    group_ids, spec.supplementary_groups, strict=True
                )
            )
            return (
                0,
                f"uid={spec.uid}({spec.username}) gid={spec.gid}({spec.primary_group}) "
                f"groups={groups}\n",
                None,
            )
        values = {
            "-u": str(spec.uid),
            "-g": str(spec.gid),
            "-G": " ".join(str(value) for value in group_ids),
            "-un": spec.username,
            "-gn": spec.primary_group,
        }
        if option not in values:
            raise ValueError("unsupported id option")
        return 0, values[option] + "\n", None

    def _system_command(
        self, action: str, args: list[str]
    ) -> tuple[int, str, str | None]:
        spec = self.filesystem.spec
        if action == "hostname":
            if args not in ([], ["-s"], ["-f"]):
                raise ValueError("hostname supports only -s or -f")
            value = spec.hostname.split(".", 1)[0] if args == ["-s"] else spec.hostname
            return 0, value + "\n", None
        if (
            any(not re.fullmatch(r"-[asrm]+", option) for option in args)
            or len(args) > 1
        ):
            raise ValueError("unsupported uname option")
        option = args[0] if args else "-s"
        values = {
            "s": "Linux",
            "r": spec.kernel_release,
            "m": spec.architecture,
        }
        if "a" in option:
            output = (
                f"Linux {spec.hostname} {spec.kernel_release} #1 SMP PREEMPT_DYNAMIC "
                f"Ubuntu {spec.architecture} GNU/Linux"
            )
        else:
            output = " ".join(values[flag] for flag in option[1:])
        return 0, output + "\n", None

    def _find(self, args: list[str]) -> tuple[int, str, str | None]:
        fs = self.filesystem
        position = 0
        start_value = "."
        if args and not args[0].startswith("-"):
            start_value = args[0]
            position = 1
        requested_start = self._resolve(start_value)
        resolution = fs.resolve(requested_start, follow_final=False)
        if not resolution.ok:
            return (
                1,
                f"find: '{requested_start}': {self._resolution_reason(resolution)}\n",
                requested_start,
            )
        start = resolution.resolved_path
        if start is None or resolution.node is None:
            raise AssertionError("Successful virtual resolution needs a node")

        min_depth = 0
        max_depth = MAX_SEARCH_DEPTH
        kind_filter: NodeKind | None = None
        name_pattern: str | None = None
        ignore_case = False
        owner_filter: int | None = None
        group_filter: int | None = None
        permission_filter: str | None = None
        require_readable = False
        require_writable = False
        value_options = {
            "-maxdepth",
            "-mindepth",
            "-type",
            "-name",
            "-iname",
            "-user",
            "-group",
            "-perm",
        }
        while position < len(args):
            option = args[position]
            position += 1
            if option in value_options:
                if position >= len(args):
                    raise ValueError(f"find option {option} requires a value")
                value = args[position]
                position += 1
                if option in {"-maxdepth", "-mindepth"}:
                    if not value.isdigit() or not 0 <= int(value) <= MAX_SEARCH_DEPTH:
                        raise ValueError(
                            f"{option} requires a number from 0 to {MAX_SEARCH_DEPTH}"
                        )
                    if option == "-maxdepth":
                        max_depth = int(value)
                    else:
                        min_depth = int(value)
                elif option == "-type":
                    type_values = {
                        "f": NodeKind.FILE,
                        "d": NodeKind.DIRECTORY,
                        "l": NodeKind.SYMLINK,
                    }
                    if value not in type_values:
                        raise ValueError("find -type supports f, d, or l")
                    kind_filter = type_values[value]
                elif option in {"-name", "-iname"}:
                    name_pattern = value
                    ignore_case = option == "-iname"
                elif option == "-user":
                    if value.isdigit():
                        owner_filter = _bounded_id(int(value), "find -user ID")
                    else:
                        try:
                            owner_filter = fs.spec.accounts.user(value).uid
                        except ValueError as exc:
                            raise ValueError(
                                f"'{value}' is not the name of a known user"
                            ) from exc
                elif option == "-group":
                    if value.isdigit():
                        group_filter = _bounded_id(int(value), "find -group ID")
                    else:
                        try:
                            group_filter = fs.spec.accounts.group(value).gid
                        except ValueError as exc:
                            raise ValueError(
                                f"'{value}' is not the name of a known group"
                            ) from exc
                else:
                    if not re.fullmatch(r"[-/]?[0-7]{3,4}", value):
                        raise ValueError("find -perm requires an octal mode")
                    permission_filter = value
            elif option == "-readable":
                require_readable = True
            elif option == "-writable":
                require_writable = True
            elif option in {"-xdev", "-print"}:
                continue
            else:
                raise ValueError(f"unsupported find option: {option}")
        if min_depth > max_depth:
            raise ValueError("find mindepth exceeds maxdepth")

        denied: tuple[str, ...] = ()
        if fs.spec.enforce_permissions:
            nodes, traversal_truncated, denied = fs.walk_accessible(
                start, max_depth=max_depth
            )
        else:
            nodes, traversal_truncated = fs.walk(start, max_depth=max_depth)
        matches: list[str] = []
        for path, depth in nodes:
            if depth < min_depth:
                continue
            node = fs.node(path)
            if node is None:
                continue
            metadata = node.metadata
            if kind_filter is not None and metadata.kind is not kind_filter:
                continue
            basename = posixpath.basename(path) if path != "/" else "/"
            if name_pattern is not None:
                candidate = basename.casefold() if ignore_case else basename
                pattern = name_pattern.casefold() if ignore_case else name_pattern
                if not fnmatch.fnmatchcase(candidate, pattern):
                    continue
            if owner_filter is not None and metadata.uid != owner_filter:
                continue
            if group_filter is not None and metadata.gid != group_filter:
                continue
            mode = metadata.mode
            if permission_filter is not None:
                prefix = permission_filter[0] if permission_filter[0] in "-/" else ""
                requested = int(permission_filter[len(prefix) :], 8)
                if prefix == "-" and mode & requested != requested:
                    continue
                if prefix == "/" and mode & requested == 0:
                    continue
                if not prefix and mode != requested:
                    continue
            if require_readable and not fs.access_allowed(
                path, PermissionOperation.READ
            ):
                continue
            if require_writable and not fs.access_allowed(
                path, PermissionOperation.WRITE
            ):
                continue
            matches.append(path)
        output = "\n".join(matches) + ("\n" if matches else "")
        output += "".join(f"find: '{path}': Permission denied\n" for path in denied)
        if traversal_truncated:
            output += "find: virtual search limit reached\n"
        return (1 if denied else 0), output, requested_start

    @staticmethod
    def _grep_matcher(pattern: str, *, fixed: bool, ignore_case: bool) -> Any:
        if len(pattern) > 128:
            raise ValueError("grep pattern is too long")
        if fixed:
            needle = pattern.casefold() if ignore_case else pattern
            return lambda line: needle in (line.casefold() if ignore_case else line)
        if not pattern or not re.fullmatch(r"[A-Za-z0-9_./:@=,\- ^$|]+", pattern):
            raise ValueError("unsupported regular expression")
        alternatives = pattern.split("|")
        if any(
            not value or "^" in value[1:] or "$" in value[:-1] for value in alternatives
        ):
            raise ValueError("unsupported regular expression")

        def matches(line: str) -> bool:
            candidate = line.casefold() if ignore_case else line
            for expression in alternatives:
                anchored_start = expression.startswith("^")
                anchored_end = expression.endswith("$")
                literal = expression[anchored_start : len(expression) - anchored_end]
                literal = literal.casefold() if ignore_case else literal
                if anchored_start and anchored_end and candidate == literal:
                    return True
                if (
                    anchored_start
                    and not anchored_end
                    and candidate.startswith(literal)
                ):
                    return True
                if anchored_end and not anchored_start and candidate.endswith(literal):
                    return True
                if not anchored_start and not anchored_end and literal in candidate:
                    return True
            return False

        return matches

    def _grep(self, args: list[str]) -> tuple[int, str, str | None]:
        recursive = False
        ignore_case = False
        line_numbers = False
        fixed = False
        list_files = False
        force_filename: bool | None = None
        position = 0
        while (
            position < len(args)
            and args[position].startswith("-")
            and args[position] != "-"
        ):
            option = args[position]
            position += 1
            if option == "--":
                break
            if not re.fullmatch(r"-[rRiFnHhlE]+", option):
                raise ValueError(f"unsupported grep option: {option}")
            recursive |= "r" in option.lower()
            ignore_case |= "i" in option
            line_numbers |= "n" in option
            fixed |= "F" in option
            list_files |= "l" in option
            if "H" in option:
                force_filename = True
            if "h" in option:
                force_filename = False
        if len(args) - position < 2:
            raise ValueError("grep requires a pattern and at least one virtual path")
        pattern = args[position]
        raw_paths = args[position + 1 :]
        matcher = self._grep_matcher(pattern, fixed=fixed, ignore_case=ignore_case)
        files: list[str] = []
        permission_errors: list[str] = []
        traversal_truncated = False
        for raw_path in raw_paths:
            requested_path = self._resolve(raw_path)
            resolution = self.filesystem.resolve(requested_path, follow_final=True)
            if not resolution.ok:
                return (
                    2,
                    f"grep: {requested_path}: {self._resolution_reason(resolution)}\n",
                    requested_path,
                )
            path = resolution.resolved_path
            node = resolution.node
            if path is None or node is None:
                raise AssertionError("Successful virtual resolution needs a node")
            if node.metadata.kind is NodeKind.FILE:
                files.append(path)
                continue
            if not recursive:
                return 2, f"grep: {requested_path}: Is a directory\n", requested_path
            if self.filesystem.spec.enforce_permissions:
                nodes, truncated, denied = self.filesystem.walk_accessible(path)
                permission_errors.extend(denied)
            else:
                nodes, truncated = self.filesystem.walk(path)
            traversal_truncated |= truncated
            files.extend(
                item for item, _ in nodes if self.filesystem.kind(item) == "file"
            )
        files = list(dict.fromkeys(files))[:MAX_SEARCH_NODES]
        show_filename = (
            force_filename
            if force_filename is not None
            else len(files) > 1 or recursive
        )
        output: list[str] = []
        matched = False
        for path in files:
            if not self._access_allowed(path, PermissionOperation.READ):
                permission_errors.append(path)
                continue
            file_matched = False
            for line_number, line in enumerate(
                self.filesystem.content(path).splitlines(), 1
            ):
                if not matcher(line):
                    continue
                matched = True
                file_matched = True
                if list_files:
                    output.append(path)
                    break
                prefix = f"{path}:" if show_filename else ""
                if line_numbers:
                    prefix += f"{line_number}:"
                output.append(prefix + line)
            if list_files and file_matched:
                continue
        if traversal_truncated:
            output.append("grep: virtual search limit reached")
        output.extend(
            f"grep: {path}: Permission denied"
            for path in dict.fromkeys(permission_errors)
        )
        target = self._resolve(raw_paths[0])
        return (
            (2 if permission_errors else 0 if matched else 1),
            "\n".join(output) + ("\n" if output else ""),
            target,
        )

    def _wc(self, args: list[str]) -> tuple[int, str, str | None]:
        options = ""
        if args and args[0].startswith("-"):
            options = args.pop(0)[1:]
            if not options or any(option not in "lwc" for option in options):
                raise ValueError("wc supports only -l, -w, and -c")
        if not 1 <= len(args) <= 3:
            raise ValueError("wc requires 1 to 3 files")
        options = options or "lwc"
        totals = {"l": 0, "w": 0, "c": 0}
        lines: list[str] = []
        last_requested_path = ""
        for raw_path in args:
            requested_path = self._resolve(raw_path)
            last_requested_path = requested_path
            resolution = self.filesystem.resolve(requested_path, follow_final=True)
            if not resolution.ok:
                return (
                    1,
                    f"wc: {requested_path}: {self._resolution_reason(resolution)}\n",
                    requested_path,
                )
            path = resolution.resolved_path
            node = resolution.node
            if path is None or node is None:
                raise AssertionError("Successful virtual resolution needs a node")
            if node.metadata.kind is not NodeKind.FILE:
                return 1, f"wc: {requested_path}: Is a directory\n", requested_path
            if not self._access_allowed(path, PermissionOperation.READ):
                return 1, f"wc: {requested_path}: Permission denied\n", requested_path
            content = self.filesystem.content(path)
            counts = {
                "l": len(content.splitlines()),
                "w": len(content.split()),
                "c": len(content.encode("utf-8")),
            }
            for key in totals:
                totals[key] += counts[key]
            rendered = " ".join(f"{counts[key]:>7}" for key in options)
            lines.append(f"{rendered} {requested_path}")
        if len(args) > 1:
            rendered = " ".join(f"{totals[key]:>7}" for key in options)
            lines.append(f"{rendered} total")
        return 0, "\n".join(lines) + "\n", last_requested_path

    def _dispatch(self, action: str, args: list[str]) -> tuple[int, str, str | None]:
        fs = self.filesystem
        if action in {"id", "whoami", "groups"}:
            return self._identity_command(action, args)
        if action in {"hostname", "uname"}:
            return self._system_command(action, args)
        if action in {"env", "printenv"}:
            environment = self._virtual_environment()
            if action == "env":
                if args:
                    raise ValueError(
                        "env takes no arguments in the restricted virtual shell"
                    )
                return (
                    0,
                    "".join(f"{key}={value}\n" for key, value in environment.items()),
                    None,
                )
            if not args:
                return (
                    0,
                    "".join(f"{key}={value}\n" for key, value in environment.items()),
                    None,
                )
            if len(args) > 3:
                raise ValueError("printenv accepts at most three names")
            found = [environment[name] for name in args if name in environment]
            output = "".join(f"{value}\n" for value in found)
            return (0 if len(found) == len(args) else 1), output, None
        if action == "sudo":
            if args == ["-n", "-l"]:
                return 1, "sudo: a password is required\n", None
            if args == ["-l"]:
                return 1, "sudo: a terminal is required to read the password\n", None
            raise ValueError("sudo supports only non-executing privilege listing")
        if action == "pwd":
            if args:
                raise ValueError("pwd takes no arguments")
            return 0, self.cwd + "\n", self.cwd
        if action == "cd":
            if len(args) > 1:
                raise ValueError("cd takes at most one path")
            if args == ["-"]:
                if self.previous_cwd is None:
                    return 1, "cd: OLDPWD not set\n", None
                requested_path = self.previous_cwd
            else:
                requested_path = self._resolve(args[0] if args else fs.spec.home)
            resolution = fs.resolve(requested_path, follow_final=True)
            if not resolution.ok:
                return (
                    1,
                    f"cd: {requested_path}: {self._resolution_reason(resolution)}\n",
                    requested_path,
                )
            path = resolution.resolved_path
            node = resolution.node
            if path is None or node is None:
                raise AssertionError("Successful virtual resolution needs a node")
            if node.metadata.kind is not NodeKind.DIRECTORY:
                return 1, f"cd: {requested_path}: Not a directory\n", requested_path
            if not self._access_allowed(path, PermissionOperation.TRAVERSE_DIRECTORY):
                return 1, f"cd: {requested_path}: Permission denied\n", requested_path
            self.previous_cwd, self.cwd = self.cwd, path
            return 0, (path + "\n") if args == ["-"] else "", path
        if action == "ls":
            long = False
            show_all = False
            human_sizes = False
            directory_entry = False
            numeric = False
            paths = []
            for arg in args:
                if arg == "--all":
                    show_all = True
                elif arg == "--numeric-uid-gid":
                    numeric = True
                    long = True
                elif arg == "--time-style=long-iso":
                    continue
                elif re.fullmatch(r"-[lah1dn]+", arg):
                    long |= "l" in arg
                    show_all |= "a" in arg
                    human_sizes |= "h" in arg
                    directory_entry |= "d" in arg
                    numeric |= "n" in arg
                    long |= "n" in arg
                elif arg.startswith("-"):
                    raise ValueError("unsupported ls option")
                else:
                    paths.append(arg)
            if len(paths) > 1:
                raise ValueError("ls accepts one path")
            requested_path = self._resolve(paths[0] if paths else ".")
            resolution = fs.resolve(requested_path, follow_final=False)
            if not resolution.ok:
                return (
                    2,
                    f"ls: cannot access '{requested_path}': "
                    f"{self._resolution_reason(resolution)}\n",
                    requested_path,
                )
            if (
                not long
                and not directory_entry
                and resolution.node is not None
                and resolution.node.metadata.kind is NodeKind.SYMLINK
            ):
                followed = fs.resolve(requested_path, follow_final=True)
                if (
                    followed.ok
                    and followed.node is not None
                    and followed.node.metadata.kind is NodeKind.DIRECTORY
                ):
                    resolution = followed
            path = resolution.resolved_path
            path_node = resolution.node
            if path is None or path_node is None:
                raise AssertionError("Successful virtual resolution needs a node")
            if not self._parents_allowed(path):
                return (
                    2,
                    f"ls: cannot access '{requested_path}': Permission denied\n",
                    requested_path,
                )
            if path_node.metadata.kind is NodeKind.DIRECTORY and not directory_entry:
                if not self._access_allowed(
                    path, PermissionOperation.LIST_DIRECTORY
                ) or (
                    long
                    and not self._access_allowed(
                        path, PermissionOperation.TRAVERSE_DIRECTORY
                    )
                ):
                    return (
                        2,
                        f"ls: cannot open directory '{requested_path}': "
                        "Permission denied\n",
                        requested_path,
                    )
                names = fs.children(path)
                if show_all:
                    names = (".", "..", *names)
                resolved_entries = []
                for name in names:
                    child = self._resolve(posixpath.join(path, name))
                    resolved_entries.append((name, child, fs.node(child)))
                entries = tuple(resolved_entries)
            else:
                name = (
                    posixpath.basename(requested_path) if requested_path != "/" else "/"
                )
                entries = ((name, path, path_node),)
            lines = []
            for name, child, node in entries:
                if node is None:
                    return (
                        2,
                        f"ls: cannot access '{child}': No such file or directory\n",
                        child,
                    )
                if long:
                    lines.append(
                        fs.render_long_listing(
                            node, name, numeric=numeric, human_sizes=human_sizes
                        )
                    )
                else:
                    lines.append(name)
            if (
                long
                and path_node.metadata.kind is NodeKind.DIRECTORY
                and not directory_entry
            ):
                total_blocks = sum(
                    node.metadata.blocks for _, _, node in entries if node is not None
                )
                lines.insert(0, f"total {(total_blocks + 1) // 2}")
            return (
                0,
                "\n".join(lines) + ("\n" if lines else ""),
                requested_path,
            )
        if action in {"cat", "head", "tail"}:
            count = 10
            if action in {"head", "tail"} and args[:1] == ["-n"]:
                if (
                    len(args) < 3
                    or not args[1].isdigit()
                    or not 1 <= int(args[1]) <= 100
                ):
                    raise ValueError(f"{action} -n requires a number from 1 to 100")
                count = int(args[1])
                args = args[2:]
            elif (
                action in {"head", "tail"}
                and args
                and re.fullmatch(r"-[0-9]{1,3}", args[0])
            ):
                count = int(args.pop(0)[1:])
                if not 1 <= count <= 100:
                    raise ValueError(f"{action} count must be from 1 to 100")
            if not 1 <= len(args) <= 3 or (
                action in {"head", "tail"} and len(args) != 1
            ):
                requirement = (
                    "one file" if action in {"head", "tail"} else "1 to 3 files"
                )
                raise ValueError(f"{action} requires {requirement}")
            contents = []
            last_requested_path = ""
            for item in args:
                requested_path = self._resolve(item)
                last_requested_path = requested_path
                resolution = fs.resolve(requested_path, follow_final=True)
                if not resolution.ok:
                    return (
                        1,
                        f"{action}: {requested_path}: "
                        f"{self._resolution_reason(resolution)}\n",
                        requested_path,
                    )
                path = resolution.resolved_path
                node = resolution.node
                if path is None or node is None:
                    raise AssertionError("Successful virtual resolution needs a node")
                if node.metadata.kind is not NodeKind.FILE:
                    return 1, f"{action}: {requested_path}: Is a directory\n", path
                if not self._access_allowed(path, PermissionOperation.READ):
                    return 1, f"{action}: {requested_path}: Permission denied\n", path
                content = fs.content(path)
                if action == "head":
                    content = "".join(content.splitlines(keepends=True)[:count])
                elif action == "tail":
                    content = "".join(content.splitlines(keepends=True)[-count:])
                contents.append(content)
            return 0, "".join(contents), last_requested_path
        if action == "find":
            return self._find(args)
        if action == "grep":
            return self._grep(args)
        if action == "wc":
            return self._wc(args)
        if action == "stat":
            follow = False
            if args[:1] and args[0] in {"-L", "--dereference"}:
                follow = True
                args = args[1:]
            if len(args) != 1:
                raise ValueError("stat supports one path and optional -L")
            requested_path = self._resolve(args[0])
            resolution = fs.resolve(requested_path, follow_final=follow)
            if not resolution.ok:
                return (
                    1,
                    f"stat: cannot statx '{requested_path}': "
                    f"{self._resolution_reason(resolution)}\n",
                    requested_path,
                )
            path = resolution.resolved_path
            node = resolution.node
            if path is None or node is None:
                raise AssertionError("Successful virtual resolution needs a node")
            if not self._parents_allowed(path):
                return (
                    1,
                    f"stat: cannot statx '{requested_path}': Permission denied\n",
                    requested_path,
                )
            return 0, fs.render_stat(node, display_path=requested_path), requested_path
        if action == "file":
            if len(args) != 1:
                raise ValueError("file requires one path")
            requested_path = self._resolve(args[0])
            resolution = fs.resolve(requested_path, follow_final=False)
            if not resolution.ok:
                return (
                    1,
                    f"file: {requested_path}: {self._resolution_reason(resolution)}\n",
                    requested_path,
                )
            path = resolution.resolved_path
            node = resolution.node
            if path is None or node is None:
                raise AssertionError("Successful virtual resolution needs a node")
            if not self._parents_allowed(path) or (
                node.metadata.kind is NodeKind.FILE
                and not self._access_allowed(path, PermissionOperation.READ)
            ):
                return 1, f"file: {requested_path}: Permission denied\n", requested_path
            kind = node.metadata.kind
            if kind is NodeKind.SYMLINK:
                description = f"symbolic link to {node.metadata.symlink_target}"
            else:
                description = (
                    "directory" if kind is NodeKind.DIRECTORY else "UTF-8 text"
                )
            return 0, f"{requested_path}: {description}\n", requested_path
        return 127, f"{action}: command not found in restricted virtual shell\n", None
