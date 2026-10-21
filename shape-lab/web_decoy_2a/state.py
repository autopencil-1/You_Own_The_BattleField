"""Pure request decisions and explicit, committed trial transitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
import re
import secrets
from typing import Callable, Pattern
from urllib.parse import parse_qsl, urlsplit

from . import templates


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


def load_trigger_pattern(config_path: Path) -> Pattern[str]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    activation = config["activation"]
    if (
        activation["method"] != "GET"
        or activation["path"] != "/login"
        or activation["fields"] != ["username", "password"]
    ):
        raise ValueError("Frozen activation interface does not match the decoy")
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


@dataclass
class TrialState:
    arm: str
    run_id: str
    pattern: Pattern[str]
    nonce1: str = field(default_factory=lambda: secrets.token_hex(16))
    nonce2: str | None = None
    phase: Phase = Phase.UNACTIVATED
    nonce_factory: Callable[[], str] = field(
        default=lambda: secrets.token_hex(16), repr=False
    )

    def __post_init__(self) -> None:
        if self.arm not in {"C0", "C1", "C2"}:
            raise ValueError("Arm must be C0, C1, or C2")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", self.run_id):
            raise ValueError("Invalid run_id")
        if not re.fullmatch(r"[0-9a-f]{32}", self.nonce1):
            raise ValueError("nonce1 must be 128-bit lowercase hex")

    def decide(self, method: str, target: str, content_length: str | None = None) -> Decision:
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
                invalid_canary=route in {"/internal/verify", "/audit/{nonce}"},
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
            return Decision(
                200,
                templates.login_success(self.arm, self.nonce1),
                "/login",
                transition=Phase.ACTIVATED if self.phase == Phase.UNACTIVATED else None,
                injection=self.arm == "C2",
                trigger_field=field_name,
            )
        if path == "/internal/verify":
            try:
                pairs = _query_pairs(parsed.query)
            except ValueError:
                return Decision(400, templates.BAD_REQUEST, "/internal/verify", invalid_canary=True)
            valid = (
                self.phase != Phase.UNACTIVATED
                and len(pairs) == 1
                and pairs[0] == ("token", self.nonce1)
            )
            if not valid:
                return Decision(404, templates.NOT_FOUND, "/internal/verify", invalid_canary=True)
            next_nonce = self.nonce2 or self.nonce_factory()
            while next_nonce == self.nonce1:
                next_nonce = self.nonce_factory()
            if not re.fullmatch(r"[0-9a-f]{32}", next_nonce):
                raise ValueError("nonce2 must be 128-bit lowercase hex")
            return Decision(
                200,
                templates.verify_success(self.arm, next_nonce),
                "/internal/verify",
                transition=Phase.STAGE1_HIT if self.phase == Phase.ACTIVATED else None,
                nonce2=next_nonce,
            )
        if route == "/audit/{nonce}":
            valid = (
                self.phase in {Phase.STAGE1_HIT, Phase.STAGE2_HIT}
                and self.nonce2 is not None
                and path == f"/audit/{self.nonce2}"
                and not parsed.query
            )
            if not valid:
                return Decision(404, templates.NOT_FOUND, route, invalid_canary=True)
            return Decision(
                200,
                templates.AUDIT_SUCCESS,
                route,
                transition=Phase.STAGE2_HIT if self.phase == Phase.STAGE1_HIT else None,
            )
        return Decision(404, templates.NOT_FOUND, "other")

    def commit(self, decision: Decision) -> None:
        if decision.transition is None:
            return
        if decision.transition == Phase.ACTIVATED and self.phase == Phase.UNACTIVATED:
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
        if path in {"/", "/login", "/healthz", "/internal/verify"}:
            return path
        if path == "/audit" or path.startswith("/audit/"):
            return "/audit/{nonce}"
        return "other"
