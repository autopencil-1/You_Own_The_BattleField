"""Single-upstream model proxy with per-trial call and reported-token caps."""

from __future__ import annotations

from datetime import datetime, timezone
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit


UPSTREAM_HOST = "api.z.ai"
UPSTREAM_PREFIX = "/api/anthropic"
ALLOWED_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def reported_usage(body: bytes, content_type: str) -> dict[str, int] | None:
    """Read final cumulative usage from JSON or Anthropic SSE without retaining content."""
    candidates: list[dict] = []
    if "text/event-stream" in content_type:
        for line in body.splitlines():
            if not line.startswith(b"data: "):
                continue
            try:
                item = json.loads(line[6:])
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(item, dict):
                candidates.append(item.get("message", item))
    else:
        try:
            value = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return None
        if isinstance(value, dict):
            candidates.append(value)
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    found = False
    for candidate in candidates:
        if not isinstance(candidate, dict) or not isinstance(candidate.get("usage"), dict):
            continue
        found = True
        for key in usage:
            value = candidate["usage"].get(key)
            if isinstance(value, int) and value >= 0:
                usage[key] = max(usage[key], value)
    return usage if found else None


def served_model(body: bytes, content_type: str) -> str | None:
    """Read only the upstream model identifier from a JSON or SSE response."""
    if "text/event-stream" in content_type:
        lines = (line[6:] for line in body.splitlines() if line.startswith(b"data: "))
    else:
        lines = iter((body,))
    for line in lines:
        try:
            item = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(item, dict):
            message = item.get("message", item)
            if isinstance(message, dict) and isinstance(message.get("model"), str):
                return message["model"]
    return None


class Gateway(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], key: str, run_id: str, model: str, max_calls: int, max_tokens: int):
        self.key = key
        self.run_id = run_id
        self.model = model
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.calls = 0
        self.tokens = 0
        self.usage_missing = False
        self.lock = threading.Lock()
        self.sequence = 0
        self.started = time.monotonic()
        super().__init__(address, GatewayHandler)

    def emit(self, event_type: str, **fields: object) -> None:
        self.sequence += 1
        event = {
            "run_id": self.run_id,
            "source": "model-gateway",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "elapsed_ms": round((time.monotonic() - self.started) * 1000),
            "sequence": self.sequence,
            "event_type": event_type,
            **fields,
        }
        print(json.dumps(event, sort_keys=True, separators=(",", ":")), flush=True)


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _reply(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        gateway: Gateway = self.server  # type: ignore[assignment]
        if self.path == "/healthz":
            self._reply(200, b"ok\n", "text/plain")
        else:
            gateway.emit("request_rejected", method="GET", path=urlsplit(self.path).path, status=404)
            self._reply(404, b'{"error":"not_found"}')

    def do_POST(self) -> None:
        gateway: Gateway = self.server  # type: ignore[assignment]
        path = urlsplit(self.path)
        if path.scheme or path.netloc or path.fragment or path.path not in ALLOWED_PATHS:
            gateway.emit("request_rejected", method="POST", path=path.path, status=404)
            self._reply(404, b'{"error":"not_found"}')
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_REQUEST_BYTES:
            gateway.emit("request_rejected", method="POST", path=path.path, status=413)
            self._reply(413, b'{"error":"request_size"}')
            return
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            gateway.emit("request_rejected", method="POST", path=path.path, status=400, reason="invalid_json")
            self._reply(400, b'{"error":"invalid_json"}')
            return
        if not isinstance(payload, dict) or payload.get("model") != gateway.model:
            gateway.emit("request_rejected", method="POST", path=path.path, status=400, reason="model_not_allowed", requested_model=payload.get("model") if isinstance(payload, dict) else None)
            self._reply(400, b'{"error":"model_not_allowed"}')
            return
        with gateway.lock:
            if gateway.calls >= gateway.max_calls or gateway.tokens >= gateway.max_tokens or gateway.usage_missing:
                gateway.emit(
                    "cap_reached", calls=gateway.calls, tokens=gateway.tokens,
                    overage_tokens=max(0, gateway.tokens - gateway.max_tokens),
                    usage_missing=gateway.usage_missing,
                )
                self._reply(429, b'{"error":"trial_cap_reached"}')
                return
            gateway.calls += 1
            call_number = gateway.calls
            started = time.monotonic()
            headers = {
                "Authorization": "Bearer " + gateway.key,
                "Content-Type": "application/json",
                "Accept": self.headers.get("Accept", "application/json"),
                "Accept-Encoding": "identity",
                "Anthropic-Version": self.headers.get("Anthropic-Version", "2023-06-01"),
            }
            if self.headers.get("Anthropic-Beta"):
                headers["Anthropic-Beta"] = self.headers["Anthropic-Beta"]
            connection = HTTPSConnection(UPSTREAM_HOST, timeout=180, context=ssl.create_default_context())
            try:
                upstream_path = UPSTREAM_PREFIX + path.path
                if path.query:
                    upstream_path += "?" + path.query
                connection.request("POST", upstream_path, body=body, headers=headers)
                response = connection.getresponse()
                upstream_status = response.status
                content_type = response.getheader("Content-Type", "application/json")
                result = response.read(MAX_RESPONSE_BYTES + 1)
                if len(result) > MAX_RESPONSE_BYTES:
                    raise ValueError("upstream response too large")
                usage = reported_usage(result, content_type) if upstream_status == 200 else None
                if upstream_status == 200 and path.path == "/v1/messages":
                    if usage is None:
                        gateway.usage_missing = True
                    else:
                        gateway.tokens += sum(usage.values())
                gateway.emit(
                    "model_call",
                    call_number=call_number,
                    path=path.path,
                    model=gateway.model,
                    served_model=served_model(result, content_type) if upstream_status == 200 else None,
                    status=upstream_status,
                    usage=usage,
                    total_tokens=gateway.tokens,
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
                if gateway.calls >= gateway.max_calls or gateway.tokens >= gateway.max_tokens or gateway.usage_missing:
                    gateway.emit(
                        "cap_reached", calls=gateway.calls, tokens=gateway.tokens,
                        overage_tokens=max(0, gateway.tokens - gateway.max_tokens),
                        usage_missing=gateway.usage_missing,
                    )
                self._reply(upstream_status, result, content_type)
            except Exception as exc:
                gateway.emit("gateway_error", call_number=call_number, error_type=type(exc).__name__)
                self._reply(502, b'{"error":"upstream_failure"}')
            finally:
                connection.close()


def main() -> None:
    key = Path(os.environ.get("SHAPE_KEY_FILE", "/run/secrets/zai_api_key")).read_text(encoding="utf-8").strip()
    if not key:
        raise ValueError("Empty gateway key")
    server = Gateway(
        ("0.0.0.0", int(os.environ.get("SHAPE_GATEWAY_PORT", "8081"))),
        key,
        os.environ["SHAPE_RUN_ID"],
        os.environ.get("SHAPE_MODEL", "glm-5.3-flash"),
        int(os.environ.get("SHAPE_MAX_MODEL_CALLS", "60")),
        int(os.environ.get("SHAPE_MAX_MODEL_TOKENS", "200000")),
    )
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
