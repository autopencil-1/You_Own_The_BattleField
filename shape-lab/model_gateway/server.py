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

from .providers import provider_spec

ALLOWED_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
SSE_EVENT_TYPES = frozenset({
    "message_start", "content_block_start", "content_block_delta", "content_block_stop",
    "message_delta", "message_stop", "ping", "error",
})
SSE_STOP_REASONS = frozenset({
    "end_turn", "tool_use", "max_tokens", "stop_sequence", "pause_turn", "refusal",
    "model_context_window_exceeded",
})


def sse_protocol_metadata(body: bytes, content_type: str) -> dict[str, object] | None:
    """Keep only response framing and terminal metadata, never model content."""
    if "text/event-stream" not in content_type.lower():
        return None
    counts: dict[str, int] = {}
    unknown_events = 0
    parse_errors = 0
    stop_reason: str | None = None
    for line in body.splitlines():
        if not line.startswith(b"data:"):
            continue
        try:
            item = json.loads(line[5:].strip())
        except (ValueError, UnicodeDecodeError):
            parse_errors += 1
            continue
        if not isinstance(item, dict):
            unknown_events += 1
            continue
        event_type = item.get("type")
        if not isinstance(event_type, str) or event_type not in SSE_EVENT_TYPES:
            unknown_events += 1
            continue
        counts[event_type] = counts.get(event_type, 0) + 1
        if event_type == "message_delta":
            delta = item.get("delta")
            value = delta.get("stop_reason") if isinstance(delta, dict) else None
            if isinstance(value, str):
                stop_reason = value if value in SSE_STOP_REASONS else "other"
    return {
        "response_bytes": len(body),
        "event_counts": counts,
        "unknown_events": unknown_events,
        "parse_errors": parse_errors,
        "message_stop_seen": counts.get("message_stop", 0) > 0,
        "stop_reason": stop_reason,
    }


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

    def __init__(self, address: tuple[str, int], key: str, run_id: str, model: str,
                 max_calls: int, max_tokens: int, retry_delays: tuple[int, ...] = (),
                 provider: str = "ollama"):
        upstream = provider_spec(provider)
        self.key = key
        self.run_id = run_id
        self.model = model
        self.provider = provider
        self.upstream_host = upstream["host"]
        self.upstream_prefix = upstream["prefix"]
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.calls = 0
        self.tokens = 0
        self.usage_missing = False
        self.retry_delays = retry_delays
        self.lock = threading.Lock()
        self.sequence = 0
        self.started = time.monotonic()
        super().__init__(address, GatewayHandler)

    def cap_state(self) -> tuple[str, list[str]] | None:
        """Return the frozen cap classification for the current counters.

        Missing provider usage is an instrumentation failure, not an
        administrative model-budget censor.  When a single response crosses
        both declared limits, token exhaustion wins the deterministic tie
        while every coincident trigger remains in the event.
        """

        if self.usage_missing:
            return "usage_missing", ["usage_missing"]
        triggered = []
        if self.calls >= self.max_calls:
            triggered.append("model_call_cap")
        if self.tokens >= self.max_tokens:
            triggered.append("model_token_cap")
        if not triggered:
            return None
        selected = (
            "model_token_cap"
            if "model_token_cap" in triggered
            else "model_call_cap"
        )
        return selected, triggered

    def emit_cap_reached(self, *, phase: str, request_path: str) -> None:
        state = self.cap_state()
        if state is None:
            raise RuntimeError("cap event requested before a gateway bound was reached")
        reason, triggered = state
        self.emit(
            "cap_reached",
            cap_reason=reason,
            triggered_reasons=triggered,
            phase=phase,
            request_path=request_path,
            calls=self.calls,
            max_calls=self.max_calls,
            tokens=self.tokens,
            max_tokens=self.max_tokens,
            overage_tokens=max(0, self.tokens - self.max_tokens),
            usage_missing=self.usage_missing,
        )

    def emit(self, event_type: str, **fields: object) -> None:
        self.sequence += 1
        event = {
            "run_id": self.run_id,
            "source": "model-gateway",
            "provider": self.provider,
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
            if gateway.cap_state() is not None:
                gateway.emit_cap_reached(
                    phase="pre_request",
                    request_path=path.path,
                )
                self._reply(429, b'{"error":"trial_cap_reached"}')
                return
            gateway.calls += 1
            call_number = gateway.calls
            headers = {
                "Authorization": "Bearer " + gateway.key,
                "Content-Type": "application/json",
                "Accept": self.headers.get("Accept", "application/json"),
                "Accept-Encoding": "identity",
                "Anthropic-Version": self.headers.get("Anthropic-Version", "2023-06-01"),
            }
            if self.headers.get("Anthropic-Beta"):
                headers["Anthropic-Beta"] = self.headers["Anthropic-Beta"]
            upstream_path = gateway.upstream_prefix + path.path
            if path.query:
                upstream_path += "?" + path.query
            for attempt_number in range(1, len(gateway.retry_delays) + 2):
                attempt_started = time.monotonic()
                connection = HTTPSConnection(gateway.upstream_host, timeout=180, context=ssl.create_default_context())
                try:
                    connection.request("POST", upstream_path, body=body, headers=headers)
                    response = connection.getresponse()
                    upstream_status = response.status
                    content_type = response.getheader("Content-Type", "application/json")
                    result = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(result) > MAX_RESPONSE_BYTES:
                        raise ValueError("upstream response too large")
                except Exception as exc:
                    gateway.emit("gateway_error", call_number=call_number,
                                 attempt_number=attempt_number, error_type=type(exc).__name__)
                    self._reply(502, b'{"error":"upstream_failure"}')
                    return
                finally:
                    connection.close()
                usage = reported_usage(result, content_type) if upstream_status == 200 else None
                if upstream_status == 200 and path.path == "/v1/messages":
                    if usage is None:
                        gateway.usage_missing = True
                    else:
                        gateway.tokens += sum(usage.values())
                gateway.emit(
                    "model_call",
                    call_number=call_number,
                    attempt_number=attempt_number,
                    path=path.path,
                    model=gateway.model,
                    served_model=served_model(result, content_type) if upstream_status == 200 else None,
                    status=upstream_status,
                    usage=usage,
                    sse=sse_protocol_metadata(result, content_type) if upstream_status == 200 else None,
                    total_tokens=gateway.tokens,
                    duration_ms=round((time.monotonic() - attempt_started) * 1000),
                )
                if upstream_status == 429:
                    if attempt_number <= len(gateway.retry_delays):
                        delay = gateway.retry_delays[attempt_number - 1]
                        gateway.emit("provider_rate_limit_wait", call_number=call_number,
                                     attempt_number=attempt_number, delay_seconds=delay)
                        time.sleep(delay)
                        continue
                    gateway.emit("provider_rate_limit_exhausted" if gateway.retry_delays else "provider_rate_limit_rejected",
                                 call_number=call_number, attempts=attempt_number)
                if gateway.cap_state() is not None:
                    gateway.emit_cap_reached(
                        phase="post_response",
                        request_path=path.path,
                    )
                self._reply(upstream_status, result, content_type)
                return


def main() -> None:
    key = Path(os.environ.get("SHAPE_KEY_FILE", "/run/secrets/model_api_key")).read_text(encoding="utf-8").strip()
    if not key:
        raise ValueError("Empty gateway key")
    server = Gateway(
        ("0.0.0.0", int(os.environ.get("SHAPE_GATEWAY_PORT", "8081"))),
        key,
        os.environ["SHAPE_RUN_ID"],
        os.environ.get("SHAPE_MODEL", "glm-5.3"),
        int(os.environ.get("SHAPE_MAX_MODEL_CALLS", "60")),
        int(os.environ.get("SHAPE_MAX_MODEL_TOKENS", "100000000")),
        tuple(int(value) for value in os.environ.get("SHAPE_PROVIDER_429_RETRY_DELAYS", "").split(",") if value),
        os.environ.get("SHAPE_MODEL_PROVIDER", "ollama"),
    )
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
