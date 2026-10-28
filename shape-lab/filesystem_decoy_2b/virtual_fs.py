"""Interpret a small command language against synthetic, deterministic state.

This module never executes a host command or reads a host path. A future 2B
service can give each trial a fresh Session and journal its CommandResult values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import posixpath
import re
import shlex
from typing import Any


MAX_COMMAND_CHARS = 512
MAX_PATH_CHARS = 256
MAX_ARGUMENTS = 12
FORBIDDEN_COMMAND_CHARS = frozenset(";|&><$`\n\r\x00")


def _digest(seed: str, path: str, purpose: str) -> str:
    return hashlib.sha256(f"{seed}\x00{path}\x00{purpose}".encode("utf-8")).hexdigest()


def _absolute(path: str) -> str:
    if not path.startswith("/") or "\x00" in path or len(path) > MAX_PATH_CHARS:
        raise ValueError("Fixture paths must be bounded absolute virtual paths")
    canonical = posixpath.normpath(path)
    if canonical != path:
        raise ValueError(f"Fixture path is not normalized: {path!r}")
    return canonical


@dataclass(frozen=True)
class FilesystemSpec:
    """Content supplied as data; names and clues can be frozen later."""

    directories: frozenset[str]
    files: dict[str, str]
    expandable_roots: frozenset[str]
    directory_words: tuple[str, ...]
    generated_file_name: str = "README.txt"
    generated_file_text: str = "Synthetic lab record.\n"
    home: str = "/home/lab"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> FilesystemSpec:
        if not isinstance(raw, dict):
            raise ValueError("Filesystem specification must be an object")
        directories = frozenset(_absolute(item) for item in raw["directories"])
        files = {_absolute(path): content for path, content in raw["files"].items()}
        roots = frozenset(_absolute(item) for item in raw["expandable_roots"])
        words = tuple(raw["directory_words"])
        home = _absolute(raw.get("home", "/home/lab"))
        generated_name = raw.get("generated_file_name", "README.txt")
        generated_text = raw.get("generated_file_text", "Synthetic lab record.\n")
        if "/" not in directories or home not in directories:
            raise ValueError("Fixture needs a root and an existing home directory")
        if not roots <= directories or directories & files.keys():
            raise ValueError("Expansion roots must be directories; files and directories cannot overlap")
        if any(path != "/" and posixpath.dirname(path) not in directories for path in directories):
            raise ValueError("Every explicit directory needs an explicit parent")
        if any(posixpath.dirname(path) not in directories for path in files):
            raise ValueError("Every explicit file needs an explicit parent")
        if not words or len(set(words)) != len(words) or any(
            not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", word) for word in words
        ):
            raise ValueError("Directory words must be unique safe path components")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", generated_name):
            raise ValueError("Generated file name is not a safe path component")
        if not isinstance(generated_text, str) or len(generated_text) > 4096:
            raise ValueError("Generated file content is too large")
        if any(not isinstance(value, str) or len(value) > 4096 for value in files.values()):
            raise ValueError("Explicit file content is too large")
        return cls(directories, files, roots, words, generated_name, generated_text, home)

    @classmethod
    def from_json(cls, text: str) -> FilesystemSpec:
        return cls.from_dict(json.loads(text))


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

    def __post_init__(self) -> None:
        if not self.seed or len(self.seed) > 128:
            raise ValueError("A bounded nonempty seed is required")
        if not 1 <= self.branching_factor <= 15:
            raise ValueError("branching_factor must be between 1 and 15")
        if not 1 <= self.max_dynamic_depth <= 8:
            raise ValueError("max_dynamic_depth must be between 1 and 8")
        if not 512 <= self.max_output_chars <= 65536:
            raise ValueError("max_output_chars must be between 512 and 65536")

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
        depth = self._dynamic_depth(parent) if parent not in self.spec.expandable_roots else 0
        if depth is None or depth >= self.max_dynamic_depth:
            return ()
        signature = _digest(self.seed, parent, "children")
        if depth > 0 and int(signature[:2], 16) % 4 == 0:
            return ()  # Some generated branches end naturally.
        count = max(1, min(15, self.branching_factor + int(signature[2:4], 16) % 3 - 1))
        names = []
        for index in range(count):
            item_hash = _digest(self.seed, parent, f"child:{index}")
            word = self.spec.directory_words[int(item_hash[:8], 16) % len(self.spec.directory_words)]
            names.append(f"{word}-{item_hash[8:14]}")
        return tuple(sorted(names))

    def kind(self, path: str) -> str | None:
        if path in self.spec.directories:
            return "directory"
        if path in self.spec.files:
            return "file"
        parent, name = posixpath.split(path)
        if (parent not in self.spec.expandable_roots
                and self._dynamic_depth(parent) is not None
                and name == self.spec.generated_file_name):
            return "file"
        return "directory" if self._dynamic_depth(path) is not None else None

    def children(self, path: str) -> tuple[str, ...]:
        if self.kind(path) != "directory":
            raise ValueError("Not a virtual directory")
        explicit = {posixpath.basename(item) for item in self.spec.directories | self.spec.files.keys()
                    if item != path and posixpath.dirname(item) == path}
        generated = set(self._generated_directory_names(path))
        if self._dynamic_depth(path) is not None and path not in self.spec.expandable_roots:
            generated.add(self.spec.generated_file_name)
        return tuple(sorted(explicit | generated))

    def content(self, path: str) -> str:
        if path in self.spec.files:
            return self.spec.files[path]
        if self.kind(path) == "file":
            return self.spec.generated_file_text
        raise ValueError("Not a virtual file")

    def metadata(self, path: str) -> tuple[str, int, str]:
        kind = self.kind(path)
        if kind is None:
            raise ValueError("Path does not exist")
        mode = "drwxr-xr-x" if kind == "directory" else "-rw-r--r--"
        size = 4096 if kind == "directory" else len(self.content(path).encode("utf-8"))
        day = 1 + int(_digest(self.seed, path, "mtime")[:4], 16) % 28
        return mode, size, f"2025-01-{day:02d}"


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
        return "Connected to synthetic Ubuntu lab host. Restricted virtual shell ready.\n"

    def _resolve(self, value: str) -> str:
        if value == "~":
            value = self.filesystem.spec.home
        elif value.startswith("~/"):
            value = self.filesystem.spec.home + value[1:]
        path = posixpath.normpath(value if value.startswith("/") else posixpath.join(self.cwd, value))
        if not path.startswith("/") or len(path) > MAX_PATH_CHARS:
            raise ValueError("Virtual path is too long")
        return path

    def execute(self, command: str) -> CommandResult:
        before = self.cwd
        self._actions += 1
        if not self.connected:
            return CommandResult(command, "connection_required", None, before, before, 1,
                                 "Not connected. Use ssh_connect first.\n")
        if len(command) > MAX_COMMAND_CHARS or any(char in FORBIDDEN_COMMAND_CHARS for char in command):
            return CommandResult(command, "rejected", None, before, before, 2,
                                 "Unsupported shell syntax in restricted virtual shell.\n")
        try:
            args = shlex.split(command)
        except ValueError:
            return CommandResult(command, "rejected", None, before, before, 2, "Invalid quoting.\n")
        if not args or len(args) > MAX_ARGUMENTS:
            return CommandResult(command, "rejected", None, before, before, 2,
                                 "Command must contain 1 to 12 arguments.\n")
        action = args[0]
        try:
            status, output, target = self._dispatch(action, args[1:])
        except ValueError as exc:
            status, output, target = 2, f"{action}: {exc}\n", None
        truncated = len(output) > self.filesystem.max_output_chars
        if truncated:
            marker = "\n[virtual output truncated]\n"
            output = output[: self.filesystem.max_output_chars - len(marker)] + marker
        return CommandResult(command, action, target, before, self.cwd, status, output, truncated)

    def _dispatch(self, action: str, args: list[str]) -> tuple[int, str, str | None]:
        fs = self.filesystem
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
                path = self.previous_cwd
            else:
                path = self._resolve(args[0] if args else fs.spec.home)
            if fs.kind(path) != "directory":
                return 1, f"cd: {path}: No such directory\n", path
            self.previous_cwd, self.cwd = self.cwd, path
            return 0, (path + "\n") if args == ["-"] else "", path
        if action == "ls":
            long = False
            show_all = False
            paths = []
            for arg in args:
                if arg in {"-l", "-a", "-la", "-al", "--all"}:
                    long |= "l" in arg
                    show_all |= "a" in arg
                elif arg.startswith("-"):
                    raise ValueError("unsupported ls option")
                else:
                    paths.append(arg)
            if len(paths) > 1:
                raise ValueError("ls accepts one path")
            path = self._resolve(paths[0] if paths else ".")
            kind = fs.kind(path)
            if kind is None:
                return 2, f"ls: cannot access '{path}': No such file or directory\n", path
            names = fs.children(path) if kind == "directory" else (posixpath.basename(path),)
            if show_all and kind == "directory":
                names = (".", "..", *names)
            lines = []
            for name in names:
                child = self._resolve(posixpath.join(path, name)) if kind == "directory" else path
                if long:
                    mode, size, date = fs.metadata(child)
                    lines.append(f"{mode} 1 lab lab {size:>6} {date} {name}")
                else:
                    lines.append(name)
            return 0, "\n".join(lines) + ("\n" if lines else ""), path
        if action in {"cat", "head"}:
            count = 10
            if action == "head" and args[:1] == ["-n"]:
                if len(args) < 3 or not args[1].isdigit() or not 1 <= int(args[1]) <= 100:
                    raise ValueError("head -n requires a number from 1 to 100")
                count = int(args[1])
                args = args[2:]
            if not 1 <= len(args) <= 3 or (action == "head" and len(args) != 1):
                raise ValueError(f"{action} requires {'one file' if action == 'head' else '1 to 3 files'}")
            contents = []
            for item in args:
                path = self._resolve(item)
                kind = fs.kind(path)
                if kind != "file":
                    return 1, f"{action}: {path}: {'Is a directory' if kind else 'No such file'}\n", path
                content = fs.content(path)
                contents.append("".join(content.splitlines(keepends=True)[:count]) if action == "head" else content)
            return 0, "".join(contents), self._resolve(args[-1])
        if action in {"stat", "file"}:
            if len(args) != 1:
                raise ValueError(f"{action} requires one path")
            path = self._resolve(args[0])
            kind = fs.kind(path)
            if kind is None:
                return 1, f"{action}: {path}: No such file or directory\n", path
            mode, size, date = fs.metadata(path)
            if action == "stat":
                return 0, f"  File: {path}\n  Size: {size}\n  Type: {kind}\n  Mode: {mode}\n  Modified: {date}\n", path
            return 0, f"{path}: {'directory' if kind == 'directory' else 'UTF-8 text'}\n", path
        return 127, f"{action}: command not found in restricted virtual shell\n", None
