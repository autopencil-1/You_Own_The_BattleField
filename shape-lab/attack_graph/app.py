"""Local read-only graph API and analyst UI."""

from __future__ import annotations

from collections import deque
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from neo4j import READ_ACCESS
from pydantic import BaseModel, Field

from db import connect, scan_id
from threat_model import example_result, generate_result, make_prompt, retrieve


UI_DIR = Path("/app/ui")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.driver = connect()
    try:
        yield
    finally:
        app.state.driver.close()


app = FastAPI(title="Bugcamp attack graph", version="0.1.0", lifespan=lifespan)


def query(request: Request, cypher: str, **parameters) -> list[dict]:
    with request.app.state.driver.session(database="neo4j", default_access_mode=READ_ACCESS) as session:
        return [record.data() for record in session.run(cypher, scan=scan_id(), **parameters)]


def payloads(request: Request, label: str) -> list[dict]:
    allowed = {"GraphEntity", "ServiceObservation", "EndpointObservation", "Finding", "RouteCatalogArea",
               "Principal", "OwnershipRule", "AccessRule"}
    if label not in allowed:
        raise ValueError("Unsupported label")
    rows = query(request, f"MATCH (n:{label} {{scan_id:$scan}}) RETURN n.payload_json AS payload ORDER BY n.key")
    return [json.loads(row["payload"]) for row in rows]


def graph_topology(request: Request) -> tuple[list[dict], list[dict]]:
    nodes = payloads(request, "GraphEntity")
    edges = [json.loads(row["payload"]) for row in query(
        request,
        "MATCH ()-[r]->() WHERE r.scan_id=$scan AND r.graph_kind IS NOT NULL "
        "RETURN r.payload_json AS payload ORDER BY r.key",
    )]
    return nodes, edges


@app.get("/api/health")
def health(request: Request):
    rows = query(request, "MATCH (s:Scan {id:$scan}) RETURN s.id AS scan_id")
    return {"ok": bool(rows), "scan_id": rows[0]["scan_id"] if rows else None}


def overview_payload(request: Request) -> dict:
    rows = query(request, "MATCH (s:Scan {id:$scan}) RETURN properties(s) AS scan")
    if not rows:
        raise HTTPException(status_code=404, detail="Scan has not been imported")
    scan = rows[0]["scan"]
    nodes, edges = graph_topology(request)
    return {
        "schema_version": scan["schema_version"],
        "scope": scan["scope"],
        "scan_id": scan["id"],
        "collected_at_kst": scan["collected_at_kst"],
        "metrics": json.loads(scan["metrics_json"]),
        "path_policy": json.loads(scan["path_policy_json"]),
        "sources": json.loads(scan["sources_json"]),
        "groups": json.loads(scan["groups_json"]),
        "third_party_references": json.loads(scan["third_party_references_json"]),
        "network_policy": json.loads(scan["network_policy_json"]),
        "network_exposures": json.loads(scan["network_exposures_json"]),
        "nodes": nodes,
        "edges": edges,
        "services": payloads(request, "ServiceObservation"),
        "endpoints": payloads(request, "EndpointObservation"),
        "findings": payloads(request, "Finding"),
        "api_route_catalog": payloads(request, "RouteCatalogArea"),
        "principals": payloads(request, "Principal"),
        "ownership_rules": payloads(request, "OwnershipRule"),
        "access_rules": payloads(request, "AccessRule"),
    }


@app.get("/api/graph/overview")
def overview(request: Request):
    return overview_payload(request)


class ThreatModelRequest(BaseModel):
    goal: str = Field(min_length=8, max_length=500)
    target_asset_id: str | None = None


@app.post("/api/threat-model/context")
def threat_model_context(request: Request, body: ThreatModelRequest):
    try:
        context = retrieve(overview_payload(request), body.goal, body.target_asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {**context, "model_configured": bool(os.environ.get("OLLAMA_API_KEY")),
            "generation_enabled": model_generation_enabled(),
            "prompt_messages": make_prompt(context)}


def model_generation_enabled() -> bool:
    return bool(os.environ.get("OLLAMA_API_KEY")) and os.environ.get(
        "THREAT_MODEL_EXTERNAL_EXPORT_ALLOWED", "false").lower() == "true"


@app.get("/api/threat-model/status")
def threat_model_status():
    return {"model": "glm-5.3", "provider": "ollama_cloud",
            "generation_enabled": model_generation_enabled(), "export_destination": "ollama.com"}


@app.get("/api/threat-model/example")
def threat_model_example(request: Request):
    return example_result(overview_payload(request))


@app.post("/api/threat-model/generate")
def threat_model_generate(request: Request, body: ThreatModelRequest):
    if not model_generation_enabled():
        raise HTTPException(status_code=503, detail="External evidence export is disabled pending explicit approval")
    try:
        result = generate_result(overview_payload(request), body.goal, body.target_asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        status = 503 if "not configured" in str(exc) or "disabled" in str(exc) else 502
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    with request.app.state.driver.session(database="neo4j") as session:
        session.execute_write(persist_result, result)
    return result


def persist_result(tx, result: dict) -> None:
    """Commit the run, actions, and paths together or leave no partial run."""
    tx.run("""MATCH (scan:Scan {id:$scan})
            CREATE (run:ThreatModelRun {id:$id, scan_id:$scan, created_at:$created_at,
                model:$model, provider:$provider, planner_version:$planner_version,
                goal:$goal, target_asset_id:$target_asset_id,
                result_json:$result_json})
            CREATE (scan)-[:HAS_THREAT_MODEL_RUN]->(run)""",
        scan=scan_id(), id=result["id"], created_at=result["created_at"],
        model=result["model"], provider=result["provider"],
        planner_version=result["planner_version"], goal=result["goal"],
        target_asset_id=result["target_asset_id"],
        result_json=json.dumps(result, ensure_ascii=False, separators=(",", ":"))).consume()
    for action in result["actions"]:
        tx.run("""MATCH (run:ThreatModelRun {id:$run_id})
                MATCH (asset:GraphEntity {key:$asset_key})
                CREATE (candidate:CandidateAction {key:$key, id:$id, scan_id:$scan,
                    status:$status, payload_json:$payload_json})
                CREATE (run)-[:PROPOSES_ACTION]->(candidate)
                CREATE (candidate)-[:TARGETS_ASSET]->(asset)""",
            run_id=result["id"], asset_key=f"{scan_id()}:{action['asset_id']}",
            key=f"{result['id']}:{action['id']}", id=action["id"],
            scan=scan_id(), status=action["status"],
            payload_json=json.dumps(action, ensure_ascii=False)).consume()
    for hypothesis in result.get("hypotheses", []):
        tx.run("""MATCH (run:ThreatModelRun {id:$run_id})
                MATCH (asset:GraphEntity {key:$asset_key})
                MATCH (action:CandidateAction {key:$action_key})
                CREATE (hypothesis:VulnerabilityHypothesis {key:$key, id:$id,
                    scan_id:$scan, status:'conditional', category:$category,
                    payload_json:$payload_json})
                CREATE (run)-[:PROPOSES_HYPOTHESIS]->(hypothesis)
                CREATE (hypothesis)-[:TARGETS_ASSET]->(asset)
                CREATE (action)-[:MODELS_HYPOTHESIS]->(hypothesis)""",
            run_id=result["id"], asset_key=f"{scan_id()}:{hypothesis['asset_id']}",
            action_key=f"{result['id']}:{hypothesis['id']}",
            key=f"{result['id']}:hypothesis:{hypothesis['id']}", id=hypothesis["id"],
            scan=scan_id(), category=hypothesis["category"],
            payload_json=json.dumps(hypothesis, ensure_ascii=False)).consume()
    for index, path in enumerate(result["paths"]):
        tx.run("""MATCH (run:ThreatModelRun {id:$run_id})
                CREATE (path:CandidatePath {key:$key, scan_id:$scan, status:$status,
                    payload_json:$payload_json})
                CREATE (run)-[:PROPOSES_PATH]->(path)""",
            run_id=result["id"], key=f"{result['id']}:path:{index}",
            scan=scan_id(), status=path["status"],
            payload_json=json.dumps(path, ensure_ascii=False)).consume()
        for position, action_id in enumerate(path["action_ids"]):
            tx.run("""MATCH (path:CandidatePath {key:$path_key})
                    MATCH (action:CandidateAction {key:$action_key})
                    CREATE (path)-[:USES_ACTION {position:$position}]->(action)""",
                path_key=f"{result['id']}:path:{index}",
                action_key=f"{result['id']}:{action_id}", position=position).consume()


@app.get("/api/threat-model/latest")
def threat_model_latest(request: Request):
    rows = query(request, """MATCH (:Scan {id:$scan})-[:HAS_THREAT_MODEL_RUN]->(run:ThreatModelRun)
        RETURN run.result_json AS result ORDER BY run.created_at DESC LIMIT 1""")
    return json.loads(rows[0]["result"]) if rows else {"run": None}


@app.post("/api/threat-model/revalidate-latest")
def threat_model_revalidate_latest(request: Request):
    """Apply current local validation to the last saved model output without a model call."""
    previous = threat_model_latest(request)
    if not previous.get("id") or not previous.get("hypotheses"):
        raise HTTPException(status_code=404, detail="No hypothesis-first run to revalidate")
    source_id = previous.get("revalidated_from", previous["id"])
    source_rows = query(request, """MATCH (run:ThreatModelRun {id:$source_id, scan_id:$scan})
        RETURN run.result_json AS result LIMIT 1""", source_id=source_id)
    source = json.loads(source_rows[0]["result"]) if source_rows else previous
    entry = [dict(item) for item in previous["hypotheses"]
             if not item["id"].startswith("next-")]
    downstream = [{**item, "id": item["id"].removeprefix("next-")}
                  for item in previous["hypotheses"] if item["id"].startswith("next-")]
    result = generate_result(
        overview_payload(request), previous["goal"], previous.get("target_asset_id"),
        model_output={"hypotheses": entry, "gaps": []},
        followup_output={"hypotheses": downstream, "gaps": []} if downstream else None)
    result.update({"model": source["model"], "provider": source["provider"],
                   "revalidated_from": source_id})
    result["gaps"] = [gap for gap in source.get("gaps", [])
                      if isinstance(gap, str) and gap.strip()
                      and gap.strip() != "— needed:"]
    if len(result["gaps"]) < len(source.get("gaps", [])):
        result["gaps"].append(
            "The source model-level gap summary was malformed; use each hypothesis's missing evidence for verification.")
    result["gaps"].append("Locally revalidated from a saved GLM run; no new model call was made.")
    with request.app.state.driver.session(database="neo4j") as session:
        session.execute_write(persist_result, result)
    return result


@app.get("/api/graph/subgraph")
def subgraph(
    request: Request,
    root: str = Query(..., min_length=1),
    depth: int = Query(2, ge=0, le=3),
    limit: int = Query(100, ge=1, le=100),
):
    nodes, edges = graph_topology(request)
    by_id = {node["id"]: node for node in nodes}
    if root not in by_id:
        raise HTTPException(status_code=404, detail="Graph entity not found")
    adjacency: dict[str, list[dict]] = {node_id: [] for node_id in by_id}
    for edge in edges:
        adjacency[edge["from"]].append(edge)
        adjacency[edge["to"]].append(edge)
    selected = {root}
    queue = deque([(root, 0)])
    while queue:
        current, distance = queue.popleft()
        if distance >= depth:
            continue
        for edge in adjacency[current]:
            neighbor = edge["to"] if edge["from"] == current else edge["from"]
            if neighbor not in selected and len(selected) < limit:
                selected.add(neighbor)
                queue.append((neighbor, distance + 1))
    return {
        "scan_id": scan_id(), "root": root, "depth": depth,
        "nodes": [node for node in nodes if node["id"] in selected],
        "edges": [edge for edge in edges if edge["from"] in selected and edge["to"] in selected],
    }


@app.get("/api/graph/endpoints")
def endpoints(
    request: Request,
    group: str | None = None,
    search: str | None = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    condition = "n.scan_id=$scan AND ($group IS NULL OR n.group_id=$group) AND ($search IS NULL OR toLower(n.url) CONTAINS toLower($search))"
    params = {"group": group, "search": search, "limit": limit, "offset": offset}
    count = query(request, f"MATCH (n:EndpointObservation) WHERE {condition} RETURN count(n) AS total", **params)[0]["total"]
    rows = query(
        request,
        f"MATCH (n:EndpointObservation) WHERE {condition} "
        "RETURN n.payload_json AS payload ORDER BY n.url, n.row_id SKIP $offset LIMIT $limit",
        **params,
    )
    return {"scan_id": scan_id(), "total": count, "offset": offset, "limit": limit,
            "items": [json.loads(row["payload"]) for row in rows]}


if (UI_DIR / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=UI_DIR / "assets"), name="assets")


@app.get("/")
def ui():
    index = UI_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail="UI bundle has not been built")
    return FileResponse(index, headers={"Cache-Control": "no-store"})
