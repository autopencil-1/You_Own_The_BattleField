"""Opt-in 2B story presentation, separate from the frozen v3 server."""

import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import posixpath
from typing import Any

from .server import ARMS, MAX_REQUEST_BYTES, DecoyHandler, DecoyServer
from .path_story_fs import PathStoryFilesystem, load_path_story_fixture
from .virtual_fs import (
    CommandResult,
    MAX_PATH_CHARS,
    MAX_SEARCH_DEPTH,
    MAX_SEARCH_NODES,
    NodeKind,
    PermissionOperation,
    Session,
)


class StorySession(Session):
    def connect(self) -> str:
        if self.connected:
            return "Already connected.\n"
        self.connected = True
        self.cwd = self.filesystem.spec.home
        return f"Welcome to {self.filesystem.spec.hostname}.\n"

    def _resolve(self, value: str) -> str:
        if ".." not in value.split("/"):
            return super()._resolve(value)
        if value == "~":
            value = self.filesystem.spec.home
        elif value.startswith("~/"):
            value = self.filesystem.spec.home + value[1:]
        raw_path = value if value.startswith("/") else posixpath.join(self.cwd, value)
        components = [part for part in raw_path.split("/") if part and part != "."]
        resolved = "/"
        for index, component in enumerate(components):
            if component == "..":
                resolved = posixpath.dirname(resolved)
                continue
            candidate = posixpath.join(resolved, component)
            if len(candidate) > MAX_PATH_CHARS:
                raise ValueError("Path is too long")
            if index < len(components) - 1:
                step = self.filesystem.resolve(candidate, follow_final=True)
                if not step.ok:
                    raise ValueError(f"{candidate}: {self._resolution_reason(step)}")
                if step.node is None or step.node.metadata.kind is not NodeKind.DIRECTORY:
                    raise ValueError(f"{candidate}: Not a directory")
                if step.resolved_path is None:
                    raise AssertionError("Successful resolution needs a path")
                if self.filesystem.spec.enforce_permissions and not self.filesystem.access_allowed(
                    step.resolved_path, PermissionOperation.TRAVERSE_DIRECTORY
                ):
                    raise ValueError(f"{candidate}: Permission denied")
                resolved = step.resolved_path
            else:
                resolved = candidate
        if len(resolved) > MAX_PATH_CHARS:
            raise ValueError("Path is too long")
        return resolved

    def execute(self, command: str) -> CommandResult:
        result = super().execute(command)
        if not (
            result.exit_code
            or result.truncated
            or (
                result.action in {"find", "grep"}
                and "virtual search limit reached" in result.output
            )
        ):
            return result
        output = result.output
        for old, new in (
            (" in restricted virtual shell", ""),
            ("virtual search limit reached", "search limit reached"),
            ("[virtual output truncated]", "[output truncated]"),
            ("Virtual path", "Path"),
            ("virtual path", "path"),
        ):
            output = output.replace(old, new)
        return replace(result, output=output)

    def _find(self, args: list[str]) -> tuple[int, str, str | None]:
        filesystem = self.filesystem
        if not isinstance(filesystem, PathStoryFilesystem):
            raise ValueError("Path-story search requires the successor filesystem")
        filesystem._explicit_search_depth = "-maxdepth" in args
        try:
            return super()._find(args)
        finally:
            filesystem._explicit_search_depth = False

    def _grep(self, args: list[str]) -> tuple[int, str, str | None]:
        filesystem = self.filesystem
        if not isinstance(filesystem, PathStoryFilesystem):
            raise ValueError("Path-story search requires the successor filesystem")
        # The inherited grep combines multiple recursive roots.  Reserve room
        # for direct file arguments, then share one traversal budget across all
        # roots so its final file slice cannot silently hide matches.
        filesystem._command_search_remaining = MAX_SEARCH_NODES - len(args)
        try:
            return super()._grep(args)
        finally:
            filesystem._command_search_remaining = None


class StoryHandler(DecoyHandler):
    def _reply(self, status: int, payload: dict) -> bytes:
        if status == 200 and self.path in {"/connect", "/exec"}:
            server: StoryDecoyServer = self.server  # type: ignore[assignment]
            spec = server.session.filesystem.spec
            payload["identity"] = {
                "username": spec.username,
                "hostname": spec.hostname,
            }
            if payload.get("truncated") and isinstance(payload.get("output"), str):
                payload["output"] = payload["output"].replace(
                    "[virtual output truncated]", "[output truncated]"
                )
        return super()._reply(status, payload)

    def do_POST(self) -> None:
        """Journal bounded raw input and commit nodes after successful output."""
        server: StoryDecoyServer = self.server  # type: ignore[assignment]
        try:
            length: int | None = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = None
        bounded = length is not None and 0 <= length <= MAX_REQUEST_BYTES
        raw_body = self.rfile.read(length) if bounded else None

        with server.lock:
            request_fields: dict[str, Any] = {
                "route": self.path,
                "content_length": length,
            }
            if raw_body is not None:
                request_fields["request_body_b64"] = base64.b64encode(raw_body).decode(
                    "ascii"
                )
            server.emit("decoy_request", **request_fields)
            session = server.session
            filesystem = session.filesystem
            if not isinstance(filesystem, PathStoryFilesystem):
                raise AssertionError("Path-story server needs its successor filesystem")
            previous = (
                session.connected,
                session.cwd,
                session.previous_cwd,
                server.command_count,
                server.qualifying_count,
            )
            filesystem.begin_materialization_capture()
            try:
                payload: Any = None
                if self.path not in {"/connect", "/exec"}:
                    status, response = 404, {"error": "not_found"}
                elif not bounded:
                    status, response = 413, {"error": "request_size"}
                else:
                    try:
                        payload = json.loads(raw_body)
                    except (ValueError, UnicodeDecodeError):
                        status, response = 400, {"error": "invalid_json"}
                    else:
                        if not isinstance(payload, dict):
                            status, response = 400, {"error": "invalid_request"}
                        elif self.path == "/connect":
                            if (
                                set(payload) != {"target"}
                                or payload["target"] != server.target
                            ):
                                status, response = 400, {"error": "target_not_allowed"}
                            else:
                                first = not session.connected
                                banner = session.connect()
                                status, response = (
                                    200,
                                    {
                                        "output": banner,
                                        "cwd": session.cwd,
                                        "connected": True,
                                        "new_connection": first,
                                    },
                                )
                        elif set(payload) != {"command"} or not isinstance(
                            payload["command"], str
                        ):
                            status, response = 400, {"error": "invalid_command"}
                        elif not session.connected:
                            status, response = 409, {"error": "connection_required"}
                        elif server.command_count >= server.max_commands:
                            status, response = 429, {"error": "command_cap_reached"}
                        else:
                            result = session.execute(payload["command"])
                            server.command_count += 1
                            output = result.output
                            output_truncated = result.truncated
                            reinforced = False
                            if result.exit_code == 0 and result.action in {
                                "ls",
                                "cat",
                                "head",
                            }:
                                server.qualifying_count += 1
                                if (
                                    ARMS[server.arm][1]
                                    and server.qualifying_count
                                    % server.reinforcement_every
                                    == 0
                                ):
                                    note = (
                                        (
                                            "\n"
                                            if output and not output.endswith("\n")
                                            else ""
                                        )
                                        + server.reinforcement_text
                                        + "\n"
                                    )
                                    if (
                                        len(output) + len(note)
                                        <= session.filesystem.max_output_chars
                                    ):
                                        output += note
                                        reinforced = True
                            if len(output) > session.filesystem.max_output_chars:
                                marker = "\n[virtual output truncated]\n"
                                output = (
                                    output[
                                        : session.filesystem.max_output_chars
                                        - len(marker)
                                    ]
                                    + marker
                                )
                                output_truncated = True
                            status, response = (
                                200,
                                {
                                    "output": output,
                                    "exit_code": result.exit_code,
                                    "action": result.action,
                                    "target": result.target,
                                    "cwd_before": result.cwd_before,
                                    "cwd_after": result.cwd_after,
                                    "truncated": output_truncated,
                                    "reinforcement_delivered": reinforced,
                                },
                            )
                try:
                    body = self._reply(status, response)
                except OSError as exc:
                    (
                        session.connected,
                        session.cwd,
                        session.previous_cwd,
                        server.command_count,
                        server.qualifying_count,
                    ) = previous
                    server.emit(
                        "response_write_failed",
                        route=self.path,
                        error_type=type(exc).__name__,
                    )
                    return
                body_sha256 = hashlib.sha256(body).hexdigest()
                server.emit(
                    "decoy_response",
                    route=self.path,
                    status=status,
                    body_sha256=body_sha256,
                    body_b64=base64.b64encode(body).decode("ascii"),
                )
                response_sequence = server.sequence
                for item in filesystem.commit_materialization_capture(
                    response_sequence=response_sequence,
                    response_sha256=body_sha256,
                ):
                    server.emit(
                        "filesystem_materialized",
                        evidence_version="path-story-evidence-v1",
                        **item,
                    )
                if (
                    self.path == "/connect"
                    and status == 200
                    and response["new_connection"]
                ):
                    server.emit("ssh_connected", target=server.target, cwd=session.cwd)
                if self.path == "/exec" and status == 200:
                    server.emit(
                        "filesystem_interaction",
                        command=payload["command"],
                        action=response["action"],
                        target=response["target"],
                        cwd_before=response["cwd_before"],
                        cwd_after=response["cwd_after"],
                        exit_code=response["exit_code"],
                        truncated=response["truncated"],
                    )
                    if response["reinforcement_delivered"]:
                        server.emit(
                            "reinforcement_delivered",
                            command_count=server.command_count,
                            response_sha256=hashlib.sha256(
                                response["output"].encode()
                            ).hexdigest(),
                        )
            finally:
                filesystem.discard_materialization_capture()


class StoryDecoyServer(DecoyServer):
    def __init__(self, *args, **kwargs) -> None:
        if not isinstance(kwargs.get("session"), StorySession):
            raise ValueError("Path-story server requires the story session")
        if not isinstance(kwargs["session"].filesystem, PathStoryFilesystem):
            raise ValueError("Path-story server requires the successor filesystem")
        super().__init__(*args, **kwargs)
        self.RequestHandlerClass = StoryHandler
        filesystem = self.session.filesystem
        evidence = filesystem.profile_evidence()
        self.emit(
            "path_story_profile_loaded",
            evidence_version="path-story-evidence-v1",
            **evidence,
            identity={
                "username": filesystem.spec.username,
                "hostname": filesystem.spec.hostname,
            },
            resource_policy={
                "max_depth": filesystem.catalog.limits.max_depth,
                "max_path_chars": filesystem.catalog.limits.max_path_chars,
                "max_content_bytes": filesystem.catalog.limits.max_content_bytes,
                "max_cached_nodes": filesystem.catalog.limits.max_cached_nodes,
                "max_children": filesystem.catalog.limits.max_children,
                "max_search_depth": MAX_SEARCH_DEPTH,
                "max_search_nodes": MAX_SEARCH_NODES,
                "max_output_chars": filesystem.max_output_chars,
                "max_commands": self.max_commands,
                "reinforcement_every": self.reinforcement_every,
            },
        )


def main() -> None:
    arm = os.environ.get("SHAPE_ARM", "B0")
    if arm not in ARMS:
        raise ValueError("Unknown 2B arm")
    config_path = Path(
        os.environ.get(
            "SHAPE_2B_PROFILE_PATH", "/app/config/exp_2b_path_story_v1.json"
        )
    )
    if config_path.name != "exp_2b_path_story_v1.json":
        raise ValueError("Path-story server requires its successor fixture")
    raw, fs = load_path_story_fixture(
        config_path,
        os.environ.get("SHAPE_2B_SEED", "fixture-seed"),
        dynamic=ARMS[arm][0],
    )
    server = StoryDecoyServer(
        ("0.0.0.0", int(os.environ.get("SHAPE_2B_PORT", "8082"))),
        run_id=os.environ["SHAPE_RUN_ID"],
        arm=arm,
        target=os.environ.get("SHAPE_2B_TARGET", "ssh://lab@filesystem-decoy-2b"),
        session=StorySession(fs),
        reinforcement_text=raw.get("reinforcement_text", ""),
        reinforcement_every=int(os.environ.get("SHAPE_2B_REINFORCEMENT_EVERY", "3")),
        max_commands=int(os.environ.get("SHAPE_2B_MAX_COMMANDS", "50")),
    )
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
