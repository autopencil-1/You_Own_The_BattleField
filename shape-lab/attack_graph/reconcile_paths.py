"""Upgrade saved candidate runs to the causal linear planner without model calls."""

from __future__ import annotations

import json

from db import connect, scan_id
from threat_model import plan_paths


def reconcile(tx, run_id: str, result: dict, paths: list[dict], blocked: list[dict]) -> None:
    previous_paths = result["paths"]
    result["paths"] = paths
    result["blocked_actions"] = blocked
    result["planner_version"] = 2
    tx.run("""MATCH (run:ThreatModelRun {id:$run_id, scan_id:$scan})
        SET run.legacy_paths_json=coalesce(run.legacy_paths_json, $legacy_paths_json),
            run.result_json=$result_json, run.planner_version=2""",
        run_id=run_id, scan=scan_id(),
        legacy_paths_json=json.dumps(previous_paths, ensure_ascii=False),
        result_json=json.dumps(result, ensure_ascii=False, separators=(",", ":"))).consume()
    tx.run("""MATCH (run:ThreatModelRun {id:$run_id})-[:PROPOSES_PATH]->(path:CandidatePath)
        DETACH DELETE path""", run_id=run_id).consume()
    for index, path in enumerate(paths):
        path_key = f"{run_id}:path:{index}"
        tx.run("""MATCH (run:ThreatModelRun {id:$run_id})
            CREATE (path:CandidatePath {key:$path_key, scan_id:$scan, status:$status,
                payload_json:$payload_json})
            CREATE (run)-[:PROPOSES_PATH]->(path)""",
            run_id=run_id, path_key=path_key, scan=scan_id(), status=path["status"],
            payload_json=json.dumps(path, ensure_ascii=False)).consume()
        for position, action_id in enumerate(path["action_ids"]):
            tx.run("""MATCH (path:CandidatePath {key:$path_key})
                MATCH (action:CandidateAction {key:$action_key})
                CREATE (path)-[:USES_ACTION {position:$position}]->(action)""",
                path_key=path_key, action_key=f"{run_id}:{action_id}", position=position).consume()


def main() -> None:
    driver = connect()
    changed = 0
    old_paths = 0
    new_paths = 0
    try:
        with driver.session(database="neo4j") as session:
            rows = session.run("""MATCH (run:ThreatModelRun {scan_id:$scan})
                RETURN run.id AS id, run.result_json AS result ORDER BY run.created_at""",
                scan=scan_id()).data()
            for row in rows:
                result = json.loads(row["result"])
                if result.get("planner_version", 1) >= 2:
                    continue
                paths, blocked = plan_paths(result["actions"], result["initial_capabilities"],
                                            result.get("target_asset_id"))
                old_paths += len(result["paths"])
                new_paths += len(paths)
                session.execute_write(reconcile, row["id"], result, paths, blocked)
                changed += 1
    finally:
        driver.close()
    print(json.dumps({"updated_runs": changed, "old_paths": old_paths, "causal_paths": new_paths}))


if __name__ == "__main__":
    main()
