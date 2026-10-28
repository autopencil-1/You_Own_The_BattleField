"""Loopback-only dashboard API and static UI."""

from __future__ import annotations

import asyncio
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.sse import EventSourceResponse, ServerSentEvent
from fastapi.staticfiles import StaticFiles

from .core import (FixtureRequest, JOBS, UI_DIST, capabilities, collector,
                   job_status, list_runs, provisional_snapshot, run_path, run_snapshot)
from .jobs import launch_fixture


app = FastAPI(title="SHAPE experiment console", docs_url=None, redoc_url=None)


def _session_token() -> str:
    JOBS.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = JOBS / "session.token"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()
    token = secrets.token_urlsafe(32)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(token + "\n")
    return token


def _guard_launch(request: Request, token: str | None) -> None:
    host = request.headers.get("host", "")
    allowed_hosts = {"127.0.0.1:8787", "localhost:8787", "127.0.0.1:5173", "localhost:5173", "testserver"}
    if host not in allowed_hosts or request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(403, "Local console only")
    origin = request.headers.get("origin")
    if origin not in {f"http://{host}", "http://127.0.0.1:5173", "http://localhost:5173"}:
        raise HTTPException(403, "Same-origin launch required")
    if not token or not secrets.compare_digest(token, _session_token()):
        raise HTTPException(403, "Invalid launch token")


@app.get("/api/session")
async def session(response: Response) -> dict[str, str]:
    response.headers["Cache-Control"] = "no-store"
    return {"launch_token": _session_token()}


@app.get("/api/experiments")
async def experiments() -> dict:
    return capabilities()


@app.get("/api/runs")
async def runs(limit: int = 80) -> dict:
    if not 1 <= limit <= 200:
        raise HTTPException(422, "limit must be 1..200")
    return {"runs": list_runs(limit)}


@app.post("/api/runs", status_code=202)
async def start_run(request: Request, payload: FixtureRequest,
                    x_shape_launch_token: str | None = Header(default=None)) -> dict:
    _guard_launch(request, x_shape_launch_token)
    try:
        return launch_fixture(payload)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/jobs/{run_id}")
async def job(run_id: str) -> dict:
    try:
        status = job_status(run_id)
    except ValueError as exc:
        raise HTTPException(404, "Unknown job") from exc
    if status is None:
        raise HTTPException(404, "Unknown job")
    return status


@app.get("/api/runs/{run_id}")
async def detail(run_id: str) -> dict:
    try:
        return run_snapshot(run_id)
    except (FileNotFoundError, ValueError) as exc:
        pending = provisional_snapshot(run_id) if isinstance(exc, FileNotFoundError) else None
        if pending is not None:
            return pending
        raise HTTPException(404, "Unknown run") from exc


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, after: int = 0, limit: int = 200) -> dict:
    if after < 0 or not 1 <= limit <= 500:
        raise HTTPException(422, "Invalid event range")
    try:
        rows = collector.collect(run_id)
    except (FileNotFoundError, ValueError) as exc:
        if isinstance(exc, FileNotFoundError) and provisional_snapshot(run_id) is not None:
            return {"events": [], "latest_event_id": 0, "has_more": False}
        raise HTTPException(404, "Unknown run") from exc
    selected = [row for row in rows if row["event_id"] > after][:limit]
    return {"events": selected, "latest_event_id": len(rows),
            "has_more": bool(selected and selected[-1]["event_id"] < len(rows))}


def _checked_run(run_id: str) -> str:
    try:
        run_path(run_id)
    except (FileNotFoundError, ValueError) as exc:
        if isinstance(exc, FileNotFoundError) and provisional_snapshot(run_id) is not None:
            return run_id
        raise HTTPException(404, "Unknown run") from exc
    return run_id


@app.get("/api/runs/{run_id}/stream", response_class=EventSourceResponse)
async def stream(request: Request, after: int = 0,
                 last_event_id: int | None = Header(default=None),
                 run_id: str = Depends(_checked_run)):
    cursor = max(0, last_event_id if last_event_id is not None else after)
    while not await request.is_disconnected():
        try:
            rows = collector.collect(run_id)
        except FileNotFoundError:
            rows = []
        for row in rows:
            if row["event_id"] <= cursor:
                continue
            cursor = row["event_id"]
            yield ServerSentEvent(data=row, event="run_event", id=str(cursor))
        await asyncio.sleep(0.5)


if UI_DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=UI_DIST / "assets"), name="assets")

    @app.get("/")
    async def home() -> FileResponse:
        return FileResponse(UI_DIST / "index.html", headers={"Cache-Control": "no-store"})
