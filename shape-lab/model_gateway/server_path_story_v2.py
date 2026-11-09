"""Path-story gateway with separate provider and downstream closeout evidence.

The upstream response and its usage are journaled before sending bytes back to
the agent. A stopped agent can therefore fail downstream delivery without
making already recorded provider usage ambiguous. This successor leaves the
frozen path-story v1 gateway unchanged.
"""

from __future__ import annotations

import os
from pathlib import Path

from .server import GatewayHandler
from .server_path_story import PathStoryGateway, _safe_route


DOWNSTREAM_WRITE_TIMEOUT_SECONDS = 10.0


class PathStoryGatewayV2(PathStoryGateway):
    """Journal every completed provider response before downstream delivery."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.RequestHandlerClass = PathStoryGatewayHandlerV2

    def emit(self, event_type: str, **fields: object) -> None:
        if event_type != "model_call":
            super().emit(event_type, **fields)
            return
        # The inherited gateway emits model_call only after reading the full
        # upstream response. Keep that event and its completion marker adjacent
        # in the total journal order, even when other handlers are concurrent.
        with self.event_lock:
            super().emit(event_type, **fields)
            super().emit(
                "provider_response_complete",
                call_number=fields.get("call_number"),
                attempt_number=fields.get("attempt_number"),
                status=fields.get("status"),
                usage_recorded=isinstance(fields.get("usage"), dict),
            )


class PathStoryGatewayHandlerV2(GatewayHandler):
    """Bound the response write and record its separate terminal result."""

    def _reply(
        self, status: int, body: bytes, content_type: str = "application/json"
    ) -> None:
        try:
            self.connection.settimeout(DOWNSTREAM_WRITE_TIMEOUT_SECONDS)
            super()._reply(status, body, content_type)
        except OSError as exc:
            # The client may have been stopped at the behavioral wall cap.
            # This is a downstream transport outcome, never an upstream bill.
            self._downstream_error_type = type(exc).__name__
            self.close_connection = True

    def do_POST(self) -> None:
        gateway: PathStoryGatewayV2 = self.server  # type: ignore[assignment]
        route = _safe_route(self.path)
        request_id = gateway.start_request(route)
        gateway.request_context.request_id = request_id
        self._downstream_error_type: str | None = None
        try:
            GatewayHandler.do_POST(self)
        except BaseException as exc:
            gateway.emit(
                "request_aborted", request_id=request_id, route=route,
                error_type=type(exc).__name__,
            )
            raise
        else:
            if self._downstream_error_type is None:
                gateway.emit("request_finished", request_id=request_id, route=route)
            else:
                gateway.emit(
                    "downstream_delivery_failed", request_id=request_id,
                    route=route, error_type=self._downstream_error_type,
                )
        finally:
            del gateway.request_context.request_id


def main() -> None:
    key = Path(
        os.environ.get("SHAPE_KEY_FILE", "/run/secrets/model_api_key")
    ).read_text(encoding="utf-8").strip()
    if not key:
        raise ValueError("Empty gateway key")
    server = PathStoryGatewayV2(
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
