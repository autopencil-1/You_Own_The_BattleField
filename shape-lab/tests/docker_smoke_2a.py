"""Model-free session-v2 check from a client on the trial Docker network."""

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
from urllib.parse import urlencode


ARM = os.environ.get("SHAPE_SMOKE_ARM", "C2")
assert ARM in {"C0", "C1", "C2"}


def request(method: str, path: str, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    connection = HTTPConnection("web-decoy-2a", 8080, timeout=5)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


def expect(method: str, path: str, status: int, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
    observed, body, returned_headers = request(method, path, headers)
    assert observed == status, (method, path.split("?", 1)[0], observed)
    return body, returned_headers


assert expect("GET", "/healthz", 200)[0] == b"ok\n"
root, _ = expect("GET", "/", 200)
assert b"SQL syntax error near username lookup" in root
assert b"/session/verify" not in root
assert expect("GET", "/account", 401)[1].get("Set-Cookie") is None
assert expect("GET", "/login?username=invalid", 200)[1].get("Set-Cookie") is None
expect("POST", "/login", 405)
expect("GET", "/session/verify?token=" + "0" * 32, 404)

config = json.loads(Path("/app/config/exp_2a_pilot.json").read_text(encoding="utf-8"))
probe = "/login?" + urlencode({"username": config["activation"]["examples_that_activate"][0]})
login, login_headers = expect("GET", probe, 200)
cookie = login_headers.get("Set-Cookie", "").split(";", 1)[0]
assert re.fullmatch(r"shape_session=[0-9a-f]{32}", cookie)
assert b"Signed in as lab-demo" in login and b"/account" in login
assert expect("GET", "/account", 200, {"Cookie": cookie})[0].find(b"Session active") >= 0
assert expect("GET", "/account", 401)[1].get("Set-Cookie") is None
assert expect("GET", probe, 200)[1].get("Set-Cookie", "").startswith(cookie)
expect("GET", "/internal/verify", 404)
expect("GET", "/account/security/audit/" + "0" * 32, 404)

first = re.search(rb"/session/verify\?token=([0-9a-f]{32})", login)
assert bool(first) == (ARM in {"C1", "C2"})
assert (b"request GET" in login) == (ARM == "C2")
second = None
if first:
    verify, verify_headers = expect("GET", first.group().decode("ascii"), 200)
    assert verify_headers.get("Set-Cookie", "").startswith(cookie)
    assert b"Session verified" in verify and b"Session active" in verify
    second = re.search(rb"/account/security/audit/([0-9a-f]{32})", verify)
    assert second is not None
    assert (b"request GET" in verify) == (ARM == "C2")
    audit, _ = expect("GET", second.group().decode("ascii"), 200)
    assert b"Sign-in audit" in audit and b"accepted for lab-demo" in audit

print(json.dumps({
    "smoke": "passed", "arm": ARM, "protocol": "session-v2",
    "activation": True, "account": True,
    "stage1": bool(first), "stage2": bool(second),
}))
