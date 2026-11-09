"""Versioned gateway request lifecycle evidence for the path-story pilot.

The existing gateway still enforces the model and token caps. This successor
adds a start and terminal event around every POST so cost admission can wait
for requests already in flight when the attacker process stops.
"""

from __future__ import annotations

import os
from pathlib import Path
import threading
from urllib.parse import urlsplit

from .server import ALLOWED_PATHS, Gateway, GatewayHandler


_LIFECYCLE_EVENTS = frozenset(
    {"request_started", "request_finished", "request_aborted"}
)


def _safe_route(value: str) -> str:
    """Keep only frozen API routes; never journal a query or arbitrary path."""
    try:
        path = urlsplit(value).path
    except ValueError:
        return "other"
    return path if path in ALLOWED_PATHS else "other"


class PathStoryGateway(Gateway):
    """Give all gateway events a total journal order and request identity."""

    def __init__(self, *args, **kwargs) -> None:
        self.event_lock = threading.RLock()
        self.request_sequence = 0
        self.request_context = threading.local()
        super().__init__(*args, **kwargs)
        self.RequestHandlerClass = PathStoryGatewayHandler

    def emit(self, event_type: str, **fields: object) -> None:
        if event_type == "request_rejected":
            # The inherited handler may put a caller-supplied path or model
            # string in a rejection event. Neither is needed for settlement.
            fields["path"] = _safe_route(str(fields.get("path", "")))
            fields.pop("requested_model", None)
        request_id = getattr(self.request_context, "request_id", None)
        if request_id is not None and event_type not in _LIFECYCLE_EVENTS:
            fields.setdefault("request_id", request_id)
        with self.event_lock:
            super().emit(event_type, **fields)

    def start_request(self, route: str) -> int:
        with self.event_lock:
            self.request_sequence += 1
            request_id = self.request_sequence
            self.emit("request_started", request_id=request_id, route=route)
            return request_id


class PathStoryGatewayHandler(GatewayHandler):
    """Bound each POST to one durable terminal event."""

    def do_POST(self) -> None:
        gateway: PathStoryGateway = self.server  # type: ignore[assignment]
        route = _safe_route(self.path)
        request_id = gateway.start_request(route)
        gateway.request_context.request_id = request_id
        try:
            super().do_POST()
        except BaseException as exc:
            gateway.emit(
                "request_aborted",
                request_id=request_id,
                route=route,
                error_type=type(exc).__name__,
            )
            raise
        else:
            gateway.emit("request_finished", request_id=request_id, route=route)
        finally:
            del gateway.request_context.request_id


def main() -> None:
    key = Path(os.environ.get("SHAPE_KEY_FILE", "/run/secrets/model_api_key")).read_text(
        encoding="utf-8"
    ).strip()
    if not key:
        raise ValueError("Empty gateway key")
    server = PathStoryGateway(
        ("0.0.0.0", int(os.environ.get("SHAPE_GATEWAY_PORT", "8081"))),
        key,
        os.environ["SHAPE_RUN_ID"],
        os.environ.get("SHAPE_MODEL", "glm-5.3"),
        int(os.environ.get("SHAPE_MAX_MODEL_CALLS", "60")),
        int(os.environ.get("SHAPE_MAX_MODEL_TOKENS", "100000000")),
        tuple(
            int(value)
            for value in os.environ.get("SHAPE_PROVIDER_429_RETRY_DELAYS", "").split(",")
            if value
        ),
        os.environ.get("SHAPE_MODEL_PROVIDER", "ollama"),
    )
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
