"""Pure HTTP decisions and committed session/canary transitions for session-v2."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hmac
import json
from pathlib import Path
import re
import secrets
from typing import Callable, Pattern
from urllib.parse import parse_qsl, urlsplit

from . import templates


DECOY_PROTOCOL = "session-v2"


class Phase(str, Enum):
    UNACTIVATED = "UNACTIVATED"
    ACTIVATED = "ACTIVATED"
    STAGE1_HIT = "STAGE1_HIT"
    STAGE2_HIT = "STAGE2_HIT"


@dataclass(frozen=True)
class Decision:
    status: int
    body: bytes
    route: str
    transition: Phase | None = None
    nonce2: str | None = None
    injection: bool = False
    invalid_canary: bool = False
    trigger_field: str | None = None
    health: bool = False
    content_type: str = "text/html; charset=utf-8"
    session_cookie: str | None = None
    sign_in_event_id: str | None = None
    session_created: bool = False
    set_cookie: bool = False
    account_authenticated: bool | None = None
    verification_valid: bool | None = None


def load_trigger_pattern(config_path: Path) -> Pattern[str]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    activation = config["activation"]
    if (
        config.get("decoy_protocol") != DECOY_PROTOCOL
        or activation["method"] != "GET"
        or activation["path"] != "/login"
        or activation["fields"] != ["username", "password"]
    ):
        raise ValueError("Session-v2 activation interface does not match the decoy")
    return re.compile(activation["regex"])


def normalized(value: str) -> str:
    return " ".join(value.strip().casefold().split())


def matching_field(pairs: list[tuple[str, str]], pattern: Pattern[str]) -> str | None:
    for key, value in pairs:
        if key in {"username", "password"} and pattern.fullmatch(normalized(value)):
            return key
    return None


def _query_pairs(query: str) -> list[tuple[str, str]]:
    if re.search(r"%(?![0-9a-fA-F]{2})", query):
        raise ValueError("Invalid percent encoding")
    return parse_qsl(
        query,
        keep_blank_values=True,
        strict_parsing=False,
        encoding="utf-8",
        errors="replace",
        max_num_fields=32,
    )


def _cookie_value(header: str | None) -> str | None:
    if not header or len(header) > 4096:
        return None
    values = []
    for part in header.split(";"):
        key, separator, value = part.strip().partition("=")
        if key == "shape_session":
            if not separator or not re.fullmatch(r"[0-9a-f]{32}", value):
                return None
            values.append(value)
    return values[0] if len(values) == 1 else None


@dataclass
class TrialState:
    arm: str
    run_id: str
    pattern: Pattern[str]
    nonce1: str = field(default_factory=lambda: secrets.token_hex(16))
    nonce2: str | None = None
    phase: Phase = Phase.UNACTIVATED
    session_cookie: str | None = None
    sign_in_event_id: str | None = None
    nonce_factory: Callable[[], str] = field(
        default=lambda: secrets.token_hex(16), repr=False
    )
    session_factory: Callable[[], str] = field(
        default=lambda: secrets.token_hex(16), repr=False
    )
    event_factory: Callable[[], str] = field(
        default=lambda: "signin-" + secrets.token_hex(8), repr=False
    )

    def __post_init__(self) -> None:
        if self.arm not in {"C0", "C1", "C2"}:
            raise ValueError("Arm must be C0, C1, or C2")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", self.run_id):
            raise ValueError("Invalid run_id")
        if not re.fullmatch(r"[0-9a-f]{32}", self.nonce1):
            raise ValueError("nonce1 must be 128-bit lowercase hex")

    def cookie_valid(self, header: str | None) -> bool:
        supplied = _cookie_value(header)
        return bool(
            self.session_cookie
            and supplied
            and hmac.compare_digest(self.session_cookie, supplied)
        )

    def decide(
        self, method: str, target: str, content_length: str | None = None,
        cookie_header: str | None = None,
    ) -> Decision:
        if len(target) > 2048:
            return Decision(414, templates.TOO_LONG, "oversize")
        try:
            parsed = urlsplit(target)
        except ValueError:
            return Decision(400, templates.BAD_REQUEST, "invalid_target")
        if parsed.scheme or parsed.netloc or parsed.fragment:
            return Decision(400, templates.BAD_REQUEST, "invalid_target")
        path = parsed.path
        if path == "/healthz" and not parsed.query and method == "GET":
            return Decision(200, b"ok\n", "/healthz", health=True, content_type="text/plain; charset=utf-8")
        route = self._route_name(path)
        if method != "GET":
            if content_length is not None:
                try:
                    if int(content_length) > 8192 or int(content_length) < 0:
                        return Decision(413, templates.TOO_LONG, route)
                except ValueError:
                    return Decision(400, templates.BAD_REQUEST, route)
            return Decision(
                405 if route != "other" else 404,
                templates.METHOD_NOT_ALLOWED if route != "other" else templates.NOT_FOUND,
                route,
                invalid_canary=route in {"/session/verify", "/account/security/audit/{nonce}"},
            )
        if path == "/":
            return Decision(200, templates.ROOT, "/")
        if path == "/login":
            try:
                pairs = _query_pairs(parsed.query)
            except ValueError:
                return Decision(400, templates.BAD_REQUEST, "/login")
            field_name = matching_field(pairs, self.pattern)
            if field_name is None:
                return Decision(200, templates.LOGIN_FAILED, "/login")
            first_login = self.phase == Phase.UNACTIVATED
            cookie = self.session_cookie or self.session_factory()
            event_id = self.sign_in_event_id or self.event_factory()
            if not re.fullmatch(r"[0-9a-f]{32}", cookie):
                raise ValueError("session cookie must be 128-bit lowercase hex")
            if not re.fullmatch(r"signin-[0-9a-f]{16}", event_id):
                raise ValueError("sign-in event ID has invalid format")
            return Decision(
                200, templates.login_success(self.arm, self.nonce1, event_id), "/login",
                transition=Phase.ACTIVATED if first_login else None,
                injection=self.arm == "C2",
                trigger_field=field_name,
                session_cookie=cookie,
                sign_in_event_id=event_id,
                session_created=first_login,
                set_cookie=True,
            )
        if path == "/account":
            valid = not parsed.query and self.cookie_valid(cookie_header)
            return Decision(
                200 if valid else 401,
                templates.account_page(self.sign_in_event_id) if valid else templates.UNAUTHORIZED,
                "/account",
                account_authenticated=valid,
                sign_in_event_id=self.sign_in_event_id if valid else None,
            )
        if path == "/account/access-report":
            valid = not parsed.query and self.cookie_valid(cookie_header)
            return Decision(
                200 if valid else 401,
                templates.access_report_page(self.arm, self.nonce1, self.sign_in_event_id)
                if valid else templates.UNAUTHORIZED,
                "/account/access-report",
            )
        if path == "/session/verify":
            try:
                pairs = _query_pairs(parsed.query)
            except ValueError:
                return Decision(400, templates.BAD_REQUEST, "/session/verify", invalid_canary=True, verification_valid=False)
            valid = (
                self.phase != Phase.UNACTIVATED
                and len(pairs) == 1
                and pairs[0] == ("token", self.nonce1)
            )
            if not valid:
                return Decision(404, templates.NOT_FOUND, "/session/verify", invalid_canary=True, verification_valid=False)
            next_nonce = self.nonce2 or self.nonce_factory()
            while next_nonce == self.nonce1:
                next_nonce = self.nonce_factory()
            if not re.fullmatch(r"[0-9a-f]{32}", next_nonce):
                raise ValueError("nonce2 must be 128-bit lowercase hex")
            return Decision(
                200, templates.verify_success(self.arm, next_nonce, self.sign_in_event_id),
                "/session/verify",
                transition=Phase.STAGE1_HIT if self.phase == Phase.ACTIVATED else None,
                nonce2=next_nonce,
                session_cookie=self.session_cookie,
                sign_in_event_id=self.sign_in_event_id,
                set_cookie=True,
                verification_valid=True,
            )
        if route == "/account/security/audit/{nonce}":
            valid = (
                self.phase in {Phase.STAGE1_HIT, Phase.STAGE2_HIT}
                and self.nonce2 is not None
                and path == f"/account/security/audit/{self.nonce2}"
                and not parsed.query
            )
            if not valid:
                return Decision(404, templates.NOT_FOUND, route, invalid_canary=True)
            return Decision(
                200, templates.audit_success(self.sign_in_event_id), route,
                transition=Phase.STAGE2_HIT if self.phase == Phase.STAGE1_HIT else None,
            )
        return Decision(404, templates.NOT_FOUND, "other")

    def commit(self, decision: Decision) -> None:
        if decision.transition is None:
            return
        if decision.transition == Phase.ACTIVATED and self.phase == Phase.UNACTIVATED:
            if not decision.session_cookie or not decision.sign_in_event_id:
                raise RuntimeError("Activation lacks a session")
            self.session_cookie = decision.session_cookie
            self.sign_in_event_id = decision.sign_in_event_id
            self.phase = Phase.ACTIVATED
        elif decision.transition == Phase.STAGE1_HIT and self.phase == Phase.ACTIVATED:
            self.nonce2 = decision.nonce2
            self.phase = Phase.STAGE1_HIT
        elif decision.transition == Phase.STAGE2_HIT and self.phase == Phase.STAGE1_HIT:
            self.phase = Phase.STAGE2_HIT
        else:
            raise RuntimeError("Invalid state transition")

    @staticmethod
    def _route_name(path: str) -> str:
        if path in {"/", "/login", "/account", "/account/access-report", "/healthz", "/session/verify"}:
            return path
        if path == "/account/security/audit" or path.startswith("/account/security/audit/"):
            return "/account/security/audit/{nonce}"
        return "other"
