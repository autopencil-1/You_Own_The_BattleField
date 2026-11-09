"""Loopback-only dashboard API and static UI."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.sse import EventSourceResponse, ServerSentEvent
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from .core import (RunRequest, JOBS, UI_DIST, capabilities, collector,
                   job_status, list_runs, materialization_page, provisional_snapshot, raw_event_record,
                   run_path, run_snapshot)
from .jobs import launch_run
from .pilot_2b import PILOT_ID as PATH_STORY_PILOT_ID, launch_next, public_status


app = FastAPI(title="SHAPE experiment console", docs_url=None, redoc_url=None)
launch_log = logging.getLogger("uvicorn.error")


class LaunchEnvelope(BaseModel):
    run: RunRequest
    launch_token: str


class PilotLaunchEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    launch_token: str


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


LOCAL_HOSTS = {"127.0.0.1:8787", "localhost:8787", "127.0.0.1:5173", "localhost:5173", "testserver"}


def _trusted_launch_origin(host: str, origin: str | None) -> bool:
    return host in LOCAL_HOSTS and origin in {
        f"http://{host}", "http://127.0.0.1:5173", "http://localhost:5173",
    }


def _guard_launch(request: Request, token: str | None) -> None:
    def reject(detail: str) -> None:
        launch_log.warning(
            "Launch rejected: %s; host=%r origin=%r peer=%r forwarded_for=%s "
            "forwarded_host=%r forwarded_proto=%r fetch_site=%r token_present=%s",
            detail, request.headers.get("host"), request.headers.get("origin"),
            request.client.host if request.client else None,
            "x-forwarded-for" in request.headers,
            request.headers.get("x-forwarded-host"),
            request.headers.get("x-forwarded-proto"),
            request.headers.get("sec-fetch-site"), bool(token),
        )
        raise HTTPException(403, detail)

    if request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
        reject("Local console only")
    if not _trusted_launch_origin(request.headers.get("host", ""), request.headers.get("origin")):
        reject("Same-origin launch required")
    if not token or not secrets.compare_digest(token, _session_token()):
        reject("Invalid launch token")


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


@app.get("/api/2b/path-story-pilot")
async def path_story_pilot_status() -> dict:
    try:
        return await asyncio.to_thread(public_status)
    except Exception as exc:
        return {
            "pilot_id": PATH_STORY_PILOT_ID,
            "phase": "integrity_error",
            "launch_available": False,
            "launch_reason": f"Frozen pilot check failed: {type(exc).__name__}: {exc}",
        }


@app.post("/api/2b/path-story-pilot/run-next", status_code=202)
async def path_story_pilot_run_next(request: Request, payload: PilotLaunchEnvelope) -> dict:
    _guard_launch(request, payload.launch_token)
    try:
        current = await asyncio.to_thread(public_status)
        if not current["launch_available"]:
            raise HTTPException(409, current["launch_reason"] or "Frozen pilot is unavailable")
        return await asyncio.to_thread(launch_next, current)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(409, f"Frozen pilot launch failed: {type(exc).__name__}: {exc}") from exc


@app.post("/api/runs", status_code=202)
async def start_run(request: Request, payload: LaunchEnvelope | RunRequest,
                    x_shape_launch_token: str | None = Header(default=None)) -> dict:
    run = payload.run if isinstance(payload, LaunchEnvelope) else payload
    token = payload.launch_token if isinstance(payload, LaunchEnvelope) else x_shape_launch_token
    _guard_launch(request, token)
    try:
        return launch_run(run)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


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


@app.get("/api/runs/{run_id}/events/{event_id}/raw")
async def raw_event(run_id: str, event_id: int) -> dict:
    try:
        return raw_event_record(run_id, event_id)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(404, "Raw event unavailable") from exc


@app.get("/api/runs/{run_id}/materializations")
async def materializations(run_id: str, after: int = 0, limit: int = 100) -> dict:
    if after < 0 or not 1 <= limit <= 200:
        raise HTTPException(422, "Invalid materialization range")
    try:
        return materialization_page(run_id, after=after, limit=limit)
    except FileNotFoundError as exc:
        raise HTTPException(404, "Materialization archive unavailable") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


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
