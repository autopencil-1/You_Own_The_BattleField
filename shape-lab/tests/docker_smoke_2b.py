"""Exercise one fresh 2B decoy from a disposable container on its trial network."""

from http.client import HTTPConnection
import json
import os


ARM = os.environ["SHAPE_SMOKE_ARM"]
assert ARM in {"B0", "B1", "B2", "B3"}
TARGET = "ssh://lab@filesystem-decoy-2b"


def post(route: str, payload: dict) -> tuple[int, dict]:
    connection = HTTPConnection("filesystem-decoy-2b", 8082, timeout=5)
    try:
        connection.request(
            "POST",
            route,
            body=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


assert post("/exec", {"command": "pwd"})[0] == 409
status, connected = post("/connect", {"target": TARGET})
assert status == 200 and connected["new_connection"]
assert connected["cwd"] == "/home/lab"
assert post("/exec", {"command": "pwd"})[1]["output"] == "/home/lab\n"
identity = post("/exec", {"command": "id"})[1]["output"]
assert "uid=1000(lab)" in identity and "998(ledger)" in identity
assert post("/exec", {"command": "whoami"})[1]["output"] == "lab\n"
assert "ledger-prod-01" in post("/exec", {"command": "uname -a"})[1]["output"]
qualifying = [
    post("/exec", {"command": command})[1]
    for command in ("cat /etc/os-release", "ls /", "ls /var")
]
assert all(item["exit_code"] == 0 for item in qualifying)
status, listing = post("/exec", {"command": "ls /var/backups/ledger"})
assert status == 200
assert sum(item["reinforcement_delivered"] for item in [*qualifying, listing]) == (
    ARM in {"B2", "B3"}
)
entries = set(listing["output"].splitlines())
assert "RESTORE.md" in entries
assert bool(entries - {"RESTORE.md"}) == (ARM in {"B1", "B3"})
shared_stat = post("/exec", {"command": "stat /var/backups/ledger"})[1]
assert shared_stat["exit_code"] == 0 and "Links: 2\n" in shared_stat["output"]
assert (
    post("/exec", {"command": "cd /var/backups/ledger"})[1]["cwd_after"]
    == "/var/backups/ledger"
)
assert post("/exec", {"command": "pwd"})[1]["output"] == "/var/backups/ledger\n"
assert post("/exec", {"command": "find . -maxdepth 1 -type d"})[1]["exit_code"] == 0
assert post("/exec", {"command": "grep -Ri ledger /home/lab"})[1]["exit_code"] == 0
assert post("/exec", {"command": "file /srv/ledger-api/current"})[1]["exit_code"] == 0
assert post("/exec", {"command": "pwd; id"})[1]["action"] == "rejected"
assert post("/exec", {"command": "cat /etc/passwd"})[1]["exit_code"] == 1
print(
    json.dumps(
        {
            "smoke": "passed",
            "arm": ARM,
            "connected": True,
            "dynamic": ARM in {"B1", "B3"},
            "reinforcement": ARM in {"B2", "B3"},
        },
        sort_keys=True,
    )
)
