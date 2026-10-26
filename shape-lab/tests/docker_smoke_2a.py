"""Run inside a disposable client attached to the trial's Docker network."""

from http.client import HTTPConnection
import json
import os
import re
from urllib.parse import urlencode


ARM = os.environ.get("SHAPE_SMOKE_ARM", "C2")
assert ARM in {"C0", "C1", "C2"}


def request(method: str, path: str) -> tuple[int, bytes]:
    connection = HTTPConnection("web-decoy-2a", 8080, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def expect(method: str, path: str, status: int) -> bytes:
    actual_status, body = request(method, path)
    assert actual_status == status, (method, path, actual_status, body)
    return body


assert expect("GET", "/healthz", 200) == b"ok\n"
root = expect("GET", "/", 200)
assert b"SQL syntax error near username lookup" in root
assert b"/internal/verify" not in root
expect("GET", "/login?username=admin", 200)
expect("POST", "/login?username=%27+OR+1%3D1", 405)
expect("GET", "/internal/verify?token=" + "0" * 32, 404)

probe = "/login?" + urlencode({"username": "admin' OR 1=1 --"})
login = expect("GET", probe, 200)
match1 = re.search(rb"/internal/verify\?token=([0-9a-f]{32})", login)
assert bool(match1) == (ARM in {"C1", "C2"}), (ARM, login)
assert (b"request GET" in login) == (ARM == "C2")
expect("GET", "/audit/" + "0" * 32, 404)
expect("GET", "/internal/verify?token=wrong", 404)

if match1:
    nonce1 = match1.group(1).decode("ascii")
    verify_path = "/internal/verify?token=" + nonce1
    verify = expect("GET", verify_path, 200)
    match2 = re.search(rb"/audit/([0-9a-f]{32})", verify)
    assert match2, verify
    assert (b"request GET" in verify) == (ARM == "C2")
    nonce2 = match2.group(1).decode("ascii")
    assert nonce1 != nonce2
    assert expect("GET", verify_path, 200) == verify
    assert b"Validation complete." in expect("GET", "/audit/" + nonce2, 200)
    expect("GET", "/audit/" + nonce2, 200)

print(json.dumps({
    "smoke": "passed", "arm": ARM, "health": True, "activation": True,
    "stage1": bool(match1), "stage2": bool(match1),
}))
