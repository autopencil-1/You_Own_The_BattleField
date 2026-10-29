"""Small local lifecycle wrapper for the host-side dashboard server."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

from .core import LAB, RUNS, private_json, read_json


PORT = 8787
STATE = RUNS / ".dashboard-service"
PID_FILE = STATE / "server.json"
LOG_FILE = STATE / "server.log"
URL = f"http://127.0.0.1:{PORT}/"


def _start_ticks(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(") ", 1)[1].split()
        return fields[19]
    except (OSError, IndexError):
        return None


def _owned_process(state: dict | None) -> int | None:
    pid = state.get("pid") if state else None
    if not isinstance(pid, int) or pid <= 1 or _start_ticks(pid) != state.get("start_ticks"):
        return None
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except OSError:
        return None
    return pid if b"uvicorn" in command and b"dashboard.app:app" in command else None


def _healthy() -> bool:
    try:
        with urlopen(f"http://127.0.0.1:{PORT}/api/experiments", timeout=0.5) as response:
            return response.status == 200 and b'"schema_version":1' in response.read(4096)
    except (OSError, URLError):
        return False


def start() -> int:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    state = read_json(PID_FILE)
    if _owned_process(state):
        if _healthy():
            print(f"Dashboard already running at {URL}")
            return 0
        print("Dashboard process exists but is not healthy; inspect runs/.dashboard-service/server.log", file=sys.stderr)
        return 1
    PID_FILE.unlink(missing_ok=True)
    if _healthy():
        print(f"Port {PORT} is occupied by a dashboard outside make up; stop it before retrying", file=sys.stderr)
        return 1
    descriptor = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "wb") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "dashboard.app:app", "--host", "127.0.0.1",
             "--port", str(PORT), "--no-access-log"],
            cwd=LAB, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    for _ in range(50):
        if process.poll() is not None:
            print("Dashboard failed to start; inspect runs/.dashboard-service/server.log", file=sys.stderr)
            return 1
        if _healthy():
            ticks = _start_ticks(process.pid)
            if ticks is None:
                print("Dashboard exited during startup", file=sys.stderr)
                return 1
            private_json(PID_FILE, {"pid": process.pid, "start_ticks": ticks, "port": PORT})
            print(f"Dashboard ready at {URL}")
            return 0
        time.sleep(0.2)
    process.terminate()
    print("Dashboard did not become healthy; inspect runs/.dashboard-service/server.log", file=sys.stderr)
    return 1


def stop() -> int:
    state = read_json(PID_FILE)
    pid = _owned_process(state)
    if pid is None:
        PID_FILE.unlink(missing_ok=True)
        print("Dashboard is not running under make up")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(30):
        if _owned_process(state) is None:
            PID_FILE.unlink(missing_ok=True)
            print("Dashboard stopped")
            return 0
        time.sleep(0.2)
    print("Dashboard did not stop within six seconds", file=sys.stderr)
    return 1


def status() -> int:
    pid = _owned_process(read_json(PID_FILE))
    if pid and _healthy():
        print(f"Dashboard running (pid {pid}): {URL}")
        return 0
    print("Dashboard not running under make up")
    return 1


def restart() -> int:
    return start() if stop() == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop", "restart", "status"))
    action = parser.parse_args().action
    return {"start": start, "stop": stop, "restart": restart, "status": status}[action]()


if __name__ == "__main__":
    raise SystemExit(main())
