"""HTTP adapter and JSONL journal for the 2A trial state machine."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import TextIO

from .state import Decision, TrialState, load_trigger_pattern


class DecoyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        trial: TrialState,
        event_stream: TextIO = sys.stdout,
    ) -> None:
        self.trial = trial
        self.event_stream = event_stream
        self.trial_lock = threading.RLock()
        self.started_at = time.monotonic()
        self.sequence = 0
        super().__init__(server_address, DecoyHandler)

    def emit(self, event_type: str, **data: object) -> None:
        """Call while holding trial_lock to preserve event and state order."""
        self.sequence += 1
        event = {
            "run_id": self.trial.run_id,
            "experiment": "2A",
            "condition": self.trial.arm,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "elapsed_ms": round((time.monotonic() - self.started_at) * 1000),
            "source": "web-decoy-2a",
            "sequence": self.sequence,
            "event_type": event_type,
            **data,
        }
        self.event_stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        self.event_stream.flush()


class DecoyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ShapeLab/1.0"
    sys_version = ""

    def __getattr__(self, name: str):
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

    def log_message(self, format: str, *args: object) -> None:
        # BaseHTTPRequestHandler includes raw query strings in its default log.
        pass

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    def do_TRACE(self) -> None:
        self._handle()

    def do_CONNECT(self) -> None:
        self._handle()

    def _handle(self) -> None:
        server: DecoyHTTPServer = self.server  # type: ignore[assignment]
        self.close_connection = True
        with server.trial_lock:
            trial = server.trial
            before = trial.phase.value
            decision = trial.decide(self.command, self.path, self.headers.get("Content-Length"))
            body = b"" if self.command == "HEAD" else decision.body
            headers = [
                ("Content-Type", decision.content_type),
                ("Cache-Control", "no-store"),
                ("Content-Length", str(len(body))),
                ("Connection", "close"),
            ]
            if not decision.health:
                server.emit(
                    "decoy_request",
                    method=self.command,
                    route=decision.route,
                    state_before=before,
                    state_after=before,
                )
            try:
                self.send_response_only(decision.status)
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                if body:
                    self.wfile.write(body)
                self.wfile.flush()
            except OSError as exc:
                if not decision.health:
                    server.emit(
                        "response_write_failed",
                        method=self.command,
                        route=decision.route,
                        status=decision.status,
                        state_before=before,
                        state_after=before,
                        error_type=type(exc).__name__,
                    )
                return
            if decision.health:
                return
            trial.commit(decision)
            after = trial.phase.value
            server.emit(
                "decoy_response",
                method=self.command,
                route=decision.route,
                status=decision.status,
                state_before=before,
                state_after=after,
                headers=headers,
                body_sha256=hashlib.sha256(body).hexdigest(),
                body_b64=base64.b64encode(body).decode("ascii"),
            )
            self._emit_outcome(server, decision, before, after)

    def _emit_outcome(
        self, server: DecoyHTTPServer, decision: Decision, before: str, after: str
    ) -> None:
        common = {
            "method": self.command,
            "route": decision.route,
            "status": decision.status,
            "state_before": before,
            "state_after": after,
        }
        if decision.transition is not None:
            if decision.transition.value == "ACTIVATED":
                server.emit("activation", trigger_field=decision.trigger_field, **common)
            else:
                server.emit(
                    "canary_hit",
                    stage=1 if decision.transition.value == "STAGE1_HIT" else 2,
                    **common,
                )
        if decision.injection:
            server.emit(
                "injection_delivered",
                first_activation=decision.transition is not None,
                **common,
            )
        if decision.invalid_canary:
            server.emit("invalid_canary", **common)


def main() -> None:
    config_path = Path(
        os.environ.get(
            "SHAPE_CONFIG_PATH",
            str(Path(__file__).resolve().parents[1] / "config" / "exp_2a_pilot.json"),
        )
    )
    pattern = load_trigger_pattern(config_path)
    trial = TrialState(
        arm=os.environ.get("SHAPE_ARM", "C2"),
        run_id=os.environ.get("SHAPE_RUN_ID", "2a-dev"),
        pattern=pattern,
    )
    port = int(os.environ.get("SHAPE_PORT", "8080"))
    if not 1 <= port <= 65535:
        raise ValueError("SHAPE_PORT must be a valid TCP port")
    server = DecoyHTTPServer(("0.0.0.0", port), trial)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
