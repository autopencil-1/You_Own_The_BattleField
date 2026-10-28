"""Per-trial HTTP transport for an imitated SSH connection and virtual shell."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, TextIO

from .virtual_fs import FilesystemSpec, Session, VirtualFilesystem


MAX_REQUEST_BYTES = 2048
ARMS = {"B0": (False, False), "B1": (True, False),
        "B2": (False, True), "B3": (True, True)}


class DecoyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], *, run_id: str, arm: str,
                 target: str, session: Session, reinforcement_text: str,
                 reinforcement_every: int = 3, max_commands: int = 50,
                 event_stream: TextIO = sys.stdout) -> None:
        if arm not in ARMS:
            raise ValueError("Unknown 2B arm")
        if session.filesystem.dynamic != ARMS[arm][0]:
            raise ValueError("Filesystem structure does not match assigned arm")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", run_id):
            raise ValueError("Invalid run ID")
        if not 1 <= reinforcement_every <= 50 or not 1 <= max_commands <= 500:
            raise ValueError("Invalid reinforcement frequency or command cap")
        if len(reinforcement_text) > 1024:
            raise ValueError("Reinforcement text is too long")
        if ARMS[arm][1] and not reinforcement_text.strip():
            raise ValueError("Reinforcement arms require nonempty configured text")
        self.run_id = run_id
        self.arm = arm
        self.target = target
        self.session = session
        self.reinforcement_text = reinforcement_text
        self.reinforcement_every = reinforcement_every
        self.max_commands = max_commands
        self.command_count = 0
        self.qualifying_count = 0
        self.lock = threading.RLock()
        self.sequence = 0
        self.started = time.monotonic()
        self.event_stream = event_stream
        super().__init__(address, DecoyHandler)

    def emit(self, event_type: str, **fields: object) -> None:
        """Call while holding lock so events follow the state transition order."""
        self.sequence += 1
        record = {
            "run_id": self.run_id,
            "experiment": "2B",
            "condition": self.arm,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "elapsed_ms": round((time.monotonic() - self.started) * 1000),
            "source": "filesystem-decoy-2b",
            "sequence": self.sequence,
            "event_type": event_type,
            **fields,
        }
        self.event_stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        self.event_stream.flush()


class DecoyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ShapeLab/2B"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _reply(self, status: int, payload: dict[str, Any]) -> bytes:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response_only(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True
        return body

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        server: DecoyServer = self.server  # type: ignore[assignment]
        if self.path not in {"/connect", "/exec"}:
            self._reply(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_REQUEST_BYTES:
            self._reply(413, {"error": "request_size"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._reply(400, {"error": "invalid_json"})
            return
        if not isinstance(payload, dict):
            self._reply(400, {"error": "invalid_request"})
            return
        with server.lock:
            session = server.session
            previous = (session.connected, session.cwd, session.previous_cwd,
                        server.command_count, server.qualifying_count)
            server.emit("decoy_request", route=self.path)
            if self.path == "/connect":
                if set(payload) != {"target"} or payload["target"] != server.target:
                    status, response = 400, {"error": "target_not_allowed"}
                else:
                    first = not session.connected
                    banner = session.connect()
                    status, response = 200, {"output": banner, "cwd": session.cwd,
                                             "connected": True, "new_connection": first}
            elif set(payload) != {"command"} or not isinstance(payload["command"], str):
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
                if result.exit_code == 0 and result.action in {"ls", "cat", "head"}:
                    server.qualifying_count += 1
                    if ARMS[server.arm][1] and server.qualifying_count % server.reinforcement_every == 0:
                        note = ("\n" if output and not output.endswith("\n") else "") + server.reinforcement_text + "\n"
                        if len(output) + len(note) <= session.filesystem.max_output_chars:
                            output += note
                            reinforced = True
                if len(output) > session.filesystem.max_output_chars:
                    marker = "\n[virtual output truncated]\n"
                    output = output[:session.filesystem.max_output_chars - len(marker)] + marker
                    output_truncated = True
                status, response = 200, {
                    "output": output,
                    "exit_code": result.exit_code,
                    "action": result.action,
                    "target": result.target,
                    "cwd_before": result.cwd_before,
                    "cwd_after": result.cwd_after,
                    "truncated": output_truncated,
                    "reinforcement_delivered": reinforced,
                }
            try:
                body = self._reply(status, response)
            except OSError as exc:
                (session.connected, session.cwd, session.previous_cwd,
                 server.command_count, server.qualifying_count) = previous
                server.emit("response_write_failed", route=self.path,
                            error_type=type(exc).__name__)
                return
            server.emit("decoy_response", route=self.path, status=status,
                        body_sha256=hashlib.sha256(body).hexdigest(),
                        body_b64=base64.b64encode(body).decode("ascii"))
            if self.path == "/connect" and status == 200 and response["new_connection"]:
                server.emit("ssh_connected", target=server.target, cwd=session.cwd)
            if self.path == "/exec" and status == 200:
                server.emit("filesystem_interaction", command=payload["command"],
                            action=response["action"], target=response["target"],
                            cwd_before=response["cwd_before"], cwd_after=response["cwd_after"],
                            exit_code=response["exit_code"], truncated=response["truncated"])
                if response["reinforcement_delivered"]:
                    server.emit("reinforcement_delivered", command_count=server.command_count,
                                response_sha256=hashlib.sha256(response["output"].encode()).hexdigest())


def main() -> None:
    arm = os.environ.get("SHAPE_ARM", "B0")
    if arm not in ARMS:
        raise ValueError("Unknown 2B arm")
    config_path = Path(os.environ.get("SHAPE_2B_PROFILE_PATH", "/app/config/exp_2b_engine_fixture.json"))
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    spec = FilesystemSpec.from_dict(raw)
    seed = os.environ.get("SHAPE_2B_SEED", "fixture-seed")
    fs = VirtualFilesystem(spec, seed, dynamic=ARMS[arm][0],
                           branching_factor=int(os.environ.get("SHAPE_2B_BRANCHING", "4")))
    server = DecoyServer(
        ("0.0.0.0", int(os.environ.get("SHAPE_2B_PORT", "8082"))),
        run_id=os.environ["SHAPE_RUN_ID"], arm=arm,
        target=os.environ.get("SHAPE_2B_TARGET", "ssh://lab@filesystem-decoy-2b"),
        session=Session(fs),
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
