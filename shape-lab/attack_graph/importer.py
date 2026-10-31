"""Idempotently project the crawl and provisional CMDB into Neo4j.

Only JSON row literals are read from the SQL dump. The dump is never executed.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re

from db import connect, scan_id


SNAPSHOT_PATH = Path(os.environ.get("GRAPH_SNAPSHOT_PATH", "/data/graph.json"))
SQL_PATH = Path(os.environ.get("GRAPH_SQL_PATH", "/data/bugcamp.io_443.sql"))
INSERT = re.compile(
    r'^INSERT INTO "bugcamp_crawl"\."([^"]+)".*?\$asm_row\$(.*?)\$asm_row\$::jsonb\);'
)
REL_TYPE = re.compile(r"^[A-Z][A-Z0-9_]*$")
BATCH_SIZE = 500

CONSTRAINTS = [
    "CREATE CONSTRAINT scan_id IF NOT EXISTS FOR (n:Scan) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT graph_entity_key IF NOT EXISTS FOR (n:GraphEntity) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT url_value IF NOT EXISTS FOR (n:Url) REQUIRE n.url IS UNIQUE",
    "CREATE CONSTRAINT service_observation_key IF NOT EXISTS FOR (n:ServiceObservation) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT endpoint_observation_key IF NOT EXISTS FOR (n:EndpointObservation) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT crawl_map_observation_key IF NOT EXISTS FOR (n:CrawlMapObservation) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT finding_key IF NOT EXISTS FOR (n:Finding) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT route_catalog_key IF NOT EXISTS FOR (n:RouteCatalogArea) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT principal_key IF NOT EXISTS FOR (n:Principal) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT ownership_rule_key IF NOT EXISTS FOR (n:OwnershipRule) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT access_rule_key IF NOT EXISTS FOR (n:AccessRule) REQUIRE n.key IS UNIQUE",
]


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def read_inputs() -> tuple[dict, list[dict], list[dict], dict]:
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    expected_scan = scan_id()
    if snapshot["scan_id"] != expected_scan:
        raise ValueError("Snapshot scan ID does not match GRAPH_SCAN_ID")

    crawl_edges: list[dict] = []
    findings: list[dict] = []
    crawl_maps: list[dict] = []
    with SQL_PATH.open(encoding="utf-8") as stream:
        for line in stream:
            match = INSERT.match(line)
            if match and match.group(1) in {"endpoint_crawl_edge", "endpoint_finding", "endpoint_crawl_map"}:
                row = json.loads(match.group(2))
                if row["scan_id"] != expected_scan:
                    raise ValueError("SQL row belongs to another scan")
                destination = {"endpoint_crawl_edge": crawl_edges,
                               "endpoint_finding": findings,
                               "endpoint_crawl_map": crawl_maps}[match.group(1)]
                destination.append(row)

    if len(crawl_edges) != snapshot["metrics"]["crawl_links"] or len(findings) != snapshot["metrics"]["findings"]:
        raise ValueError("SQL row counts do not match snapshot metrics")
    if len(snapshot["endpoints"]) != snapshot["metrics"]["folded_endpoints"]:
        raise ValueError("Endpoint count does not match snapshot metrics")
    if len(crawl_maps) != 1:
        raise ValueError("Expected one crawl map row")
    crawl_map = crawl_maps[0]
    if (crawl_map["url_count"] != snapshot["metrics"]["discovered_urls"]
            or crawl_map["edge_count"] != len(crawl_edges)
            or crawl_map["folded_url_count"] != len(snapshot["endpoints"])):
        raise ValueError("Crawl map counts do not match imported observations")
    return snapshot, crawl_edges, findings, crawl_map


def batches(rows: list, size: int = BATCH_SIZE):
    for start in range(0, len(rows), size):
        yield rows[start:start + size]


def run_batches(session, query: str, rows: list[dict], scan: str) -> None:
    for batch in batches(rows):
        session.run(query, rows=batch, scan=scan).consume()


def topology_key(scan: str, edge: dict) -> str:
    identity = {key: edge.get(key) for key in ("from", "to", "kind", "path_pattern", "priority")}
    digest = hashlib.sha256(compact(identity).encode("utf-8")).hexdigest()[:24]
    return f"{scan}:topology:{digest}"


def import_graph(driver, snapshot: dict, crawl_edges: list[dict], raw_findings: list[dict], crawl_map: dict) -> dict[str, int]:
    scan = snapshot["scan_id"]
    with driver.session(database="neo4j") as session:
        for command in CONSTRAINTS:
            session.run(command).consume()

        session.run(
            """MERGE (s:Scan {id:$scan})
               SET s.scope=$scope, s.collected_at_kst=$collected_at_kst,
                   s.metrics_json=$metrics_json, s.path_policy_json=$path_policy_json,
                   s.sources_json=$sources_json, s.groups_json=$groups_json,
                   s.third_party_references_json=$third_party_references_json,
                   s.network_policy_json=$network_policy_json,
                   s.network_exposures_json=$network_exposures_json,
                   s.schema_version=$schema_version""",
            scan=scan, scope=snapshot["scope"], collected_at_kst=snapshot["collected_at_kst"],
            metrics_json=compact(snapshot["metrics"]), path_policy_json=compact(snapshot["path_policy"]),
            sources_json=compact(snapshot["sources"]), groups_json=compact(snapshot["groups"]),
            third_party_references_json=compact(snapshot["third_party_references"]),
            network_policy_json=compact(snapshot["network_policy"]),
            network_exposures_json=compact(snapshot["network_exposures"]),
            schema_version=snapshot["schema_version"],
        ).consume()

        graph_nodes = [{
            "key": f"{scan}:{node['id']}", "id": node["id"], "kind": node["kind"],
            "evidence_state": node["evidence_state"], "visibility": node["visibility"],
            "asset_id": node.get("asset_id") or node.get("asset_identity"),
            "asset_id_provenance": node.get("asset_id_provenance"),
            "payload_json": compact(node),
        } for node in snapshot["nodes"]]
        run_batches(session, """MATCH (s:Scan {id:$scan}) UNWIND $rows AS row
            MERGE (n:GraphEntity {key:row.key})
            SET n.id=row.id, n.scan_id=$scan, n.kind=row.kind,
                n.evidence_state=row.evidence_state, n.visibility=row.visibility,
                n.asset_id=row.asset_id, n.asset_id_provenance=row.asset_id_provenance,
                n.payload_json=row.payload_json
            MERGE (s)-[:HAS_GRAPH_ENTITY]->(n)""", graph_nodes, scan)

        topology_by_kind: dict[str, list[dict]] = defaultdict(list)
        for edge in snapshot["edges"]:
            kind = edge["kind"]
            if not REL_TYPE.fullmatch(kind):
                raise ValueError(f"Invalid relationship type: {kind}")
            topology_by_kind[kind].append({
                "key": topology_key(scan, edge), "from_key": f"{scan}:{edge['from']}",
                "to_key": f"{scan}:{edge['to']}", "kind": kind,
                "protocol": edge.get("protocol"), "service": edge.get("service"),
                "port": edge.get("port"), "network_policy": edge.get("network_policy"),
                "attack_step": edge.get("attack_step"),
                "evidence_state": edge["evidence_state"], "payload_json": compact(edge),
            })
        for kind, rel_rows in topology_by_kind.items():
            query = f"""UNWIND $rows AS row
                MATCH (a:GraphEntity {{key:row.from_key}})
                MATCH (b:GraphEntity {{key:row.to_key}})
                MERGE (a)-[r:{kind} {{key:row.key}}]->(b)
                SET r.scan_id=$scan, r.graph_kind=row.kind,
                    r.protocol=row.protocol, r.service=row.service, r.port=row.port,
                    r.network_policy=row.network_policy, r.attack_step=row.attack_step,
                    r.evidence_state=row.evidence_state, r.payload_json=row.payload_json"""
            run_batches(session, query, rel_rows, scan)

        services = [{
            "key": f"{scan}:{row['service_id']}", "ip_key": f"{scan}:ip:{row['ip']}",
            "service_id": row["service_id"], "ip": row["ip"],
            "payload_json": compact(row),
        } for row in snapshot["services"]]
        run_batches(session, """MATCH (scan:Scan {id:$scan}) UNWIND $rows AS row
            MERGE (service:ServiceObservation {key:row.key})
            SET service.scan_id=$scan, service.service_id=row.service_id,
                service.ip=row.ip, service.payload_json=row.payload_json
            WITH scan, service, row
            MATCH (ip:GraphEntity {key:row.ip_key})
            MERGE (scan)-[:HAS_SERVICE_OBSERVATION]->(service)
            MERGE (ip)-[:HAS_SERVICE_OBSERVATION]->(service)""", services, scan)

        session.run("""MATCH (scan:Scan {id:$scan})
            MATCH (service:ServiceObservation {key:$service_key})
            MERGE (map:CrawlMapObservation {key:$map_key})
            SET map.scan_id=$scan, map.row_id=$row_id,
                map.url_count=$url_count, map.edge_count=$edge_count,
                map.folded_url_count=$folded_url_count,
                map.folded_edge_count=$folded_edge_count,
                map.doc_json=$doc_json
            MERGE (scan)-[:HAS_CRAWL_MAP]->(map)
            MERGE (map)-[:OBSERVED_VIA]->(service)""",
            scan=scan, service_key=f"{scan}:{crawl_map['service_id']}",
            map_key=f"{scan}:{crawl_map['id']}", row_id=crawl_map["id"],
            url_count=crawl_map["url_count"], edge_count=crawl_map["edge_count"],
            folded_url_count=crawl_map["folded_url_count"],
            folded_edge_count=crawl_map["folded_edge_count"],
            doc_json=compact(crawl_map["doc"]),
        ).consume()

        urls = sorted({row["url"] for row in snapshot["endpoints"]}
                      | {row["url"] for row in crawl_edges}
                      | {row["parent_url"] for row in crawl_edges})
        for batch in batches(urls):
            session.run("UNWIND $urls AS url MERGE (:Url {url:url})", urls=batch).consume()

        endpoints = [{
            "key": f"{scan}:{row['id']}", "id": row["id"], "url": row["url"],
            "group": row["group"], "status": row["status"], "tested": row["tested"],
            "crawled": row["crawled"], "service_key": f"{scan}:{row['service_id']}",
            "surface_key": f"{scan}:surface:{'api' if row['group'].startswith('api-') else 'web'}",
            "payload_json": compact(row),
        } for row in snapshot["endpoints"]]
        run_batches(session, """MATCH (scan:Scan {id:$scan}) UNWIND $rows AS row
            MERGE (endpoint:EndpointObservation {key:row.key})
            SET endpoint.scan_id=$scan, endpoint.row_id=row.id,
                endpoint.url=row.url, endpoint.group_id=row.group,
                endpoint.status=row.status, endpoint.tested=row.tested,
                endpoint.crawled=row.crawled, endpoint.payload_json=row.payload_json
            WITH scan, endpoint, row
            MATCH (url:Url {url:row.url})
            MATCH (service:ServiceObservation {key:row.service_key})
            MATCH (surface:GraphEntity {key:row.surface_key})
            MERGE (scan)-[:HAS_ENDPOINT]->(endpoint)
            MERGE (endpoint)-[:OBSERVES_URL]->(url)
            MERGE (endpoint)-[:OBSERVED_VIA]->(service)
            MERGE (surface)-[:HAS_ENDPOINT]->(endpoint)""", endpoints, scan)

        crawl_relations = [{
            "key": f"{scan}:crawl:{row['id']}", "id": row["id"],
            "parent_url": row["parent_url"], "url": row["url"],
            "kind": row["kind"], "seed_word": row.get("seed_word"),
            "is_expanded": row.get("is_expanded"),
        } for row in crawl_edges]
        run_batches(session, """UNWIND $rows AS row
            MATCH (parent:Url {url:row.parent_url})
            MATCH (target:Url {url:row.url})
            MERGE (parent)-[edge:DISCOVERED {key:row.key}]->(target)
            SET edge.scan_id=$scan, edge.row_id=row.id, edge.kind=row.kind,
                edge.seed_word=row.seed_word, edge.is_expanded=row.is_expanded""",
                    crawl_relations, scan)

        raw_by_id = {row["id"]: row for row in raw_findings}
        findings = []
        for row in snapshot["findings"]:
            raw = raw_by_id[row["id"]]
            findings.append({
                "key": f"{scan}:{row['id']}", "id": row["id"],
                "endpoint_key": f"{scan}:{raw['endpoint_id']}",
                "payload_json": compact(row),
            })
        run_batches(session, """MATCH (scan:Scan {id:$scan}) UNWIND $rows AS row
            MERGE (finding:Finding {key:row.key})
            SET finding.scan_id=$scan, finding.row_id=row.id,
                finding.payload_json=row.payload_json
            WITH scan, finding, row
            MATCH (endpoint:EndpointObservation {key:row.endpoint_key})
            MERGE (scan)-[:HAS_FINDING]->(finding)
            MERGE (endpoint)-[:HAS_FINDING]->(finding)""", findings, scan)

        catalog = [{
            "key": f"{scan}:catalog:{row['area']}", "area": row["area"],
            "payload_json": compact(row),
        } for row in snapshot["api_route_catalog"]]
        run_batches(session, """MATCH (scan:Scan {id:$scan})
            MATCH (api:GraphEntity {key:$scan + ':app:bugcamp-api'})
            UNWIND $rows AS row
            MERGE (area:RouteCatalogArea {key:row.key})
            SET area.scan_id=$scan, area.area=row.area, area.payload_json=row.payload_json
            MERGE (scan)-[:HAS_ROUTE_CATALOG_AREA]->(area)
            MERGE (api)-[:HAS_ROUTE_CATALOG_AREA]->(area)""", catalog, scan)

        principals = [{
            "key": f"{scan}:principal:{row['id']}", "id": row["id"],
            "role_token": row.get("role_token"),
            "payload_json": compact(row),
        } for row in snapshot["principals"]]
        run_batches(session, """MATCH (scan:Scan {id:$scan}) UNWIND $rows AS row
            MERGE (principal:Principal {key:row.key})
            SET principal.scan_id=$scan, principal.id=row.id,
                principal.role_token=row.role_token,
                principal.payload_json=row.payload_json
            MERGE (scan)-[:HAS_PRINCIPAL]->(principal)""", principals, scan)

        ownership_rules = [{
            "key": f"{scan}:ownership:{row['id']}", "id": row["id"],
            "owners": row["owners"], "payload_json": compact(row),
        } for row in snapshot["ownership_rules"]]
        run_batches(session, """MATCH (scan:Scan {id:$scan}) UNWIND $rows AS row
            MERGE (rule:OwnershipRule {key:row.key})
            SET rule.scan_id=$scan, rule.id=row.id, rule.payload_json=row.payload_json
            MERGE (scan)-[:HAS_OWNERSHIP_RULE]->(rule)
            WITH rule, row
            UNWIND row.owners AS principal_id
            MATCH (principal:Principal {key:$scan + ':principal:' + principal_id})
            MERGE (rule)-[:NAMES_OWNER]->(principal)""", ownership_rules, scan)

        access_rules = [{
            "key": f"{scan}:access:{row['id']}", "id": row["id"],
            "tier": row["tier"], "principals": row["required_principals"],
            "required_session": row["required_session"],
            "evidence_state": row["evidence_state"],
            "payload_json": compact(row),
        } for row in snapshot["access_rules"]]
        run_batches(session, """MATCH (scan:Scan {id:$scan}) UNWIND $rows AS row
            MERGE (rule:AccessRule {key:row.key})
            SET rule.scan_id=$scan, rule.id=row.id, rule.tier=row.tier,
                rule.required_session=row.required_session,
                rule.evidence_state=row.evidence_state,
                rule.payload_json=row.payload_json
            MERGE (scan)-[:HAS_ACCESS_RULE]->(rule)""", access_rules, scan)
        run_batches(session, """UNWIND $rows AS row
            MATCH (rule:AccessRule {key:row.key})
            UNWIND row.principals AS principal_id
            MATCH (principal:Principal {key:$scan + ':principal:' + principal_id})
            MERGE (rule)-[:REQUIRES_PRINCIPAL]->(principal)""", access_rules, scan)
        run_batches(session, """UNWIND $rows AS row
            MATCH (rule:AccessRule {key:row.key})
            UNWIND CASE WHEN row.tier='mixed' THEN ['web','api'] ELSE [row.tier] END AS tier
            MATCH (surface:GraphEntity {key:$scan + ':surface:' + tier})
            MERGE (rule)-[:GOVERNS_SURFACE]->(surface)""", access_rules, scan)

        counts = {}
        queries = {
            "graph_nodes": "MATCH (n:GraphEntity {scan_id:$scan}) RETURN count(n) AS total",
            "topology_links": "MATCH ()-[r]->() WHERE r.scan_id=$scan AND r.graph_kind IS NOT NULL RETURN count(r) AS total",
            "services": "MATCH (n:ServiceObservation {scan_id:$scan}) RETURN count(n) AS total",
            "endpoints": "MATCH (n:EndpointObservation {scan_id:$scan}) RETURN count(n) AS total",
            "crawl_links": "MATCH ()-[r:DISCOVERED]->() WHERE r.scan_id=$scan RETURN count(r) AS total",
            "findings": "MATCH (n:Finding {scan_id:$scan}) RETURN count(n) AS total",
            "crawl_maps": "MATCH (n:CrawlMapObservation {scan_id:$scan}) RETURN count(n) AS total",
            "route_catalog_areas": "MATCH (n:RouteCatalogArea {scan_id:$scan}) RETURN count(n) AS total",
            "principals": "MATCH (n:Principal {scan_id:$scan}) RETURN count(n) AS total",
            "ownership_rules": "MATCH (n:OwnershipRule {scan_id:$scan}) RETURN count(n) AS total",
            "access_rules": "MATCH (n:AccessRule {scan_id:$scan}) RETURN count(n) AS total",
            "urls": "MATCH (n:Url) RETURN count(n) AS total",
        }
        for name, query in queries.items():
            counts[name] = session.run(query, scan=scan).single()["total"]
        expected = {
            "graph_nodes": len(snapshot["nodes"]),
            "topology_links": len(snapshot["edges"]),
            "services": len(snapshot["services"]),
            "endpoints": len(snapshot["endpoints"]),
            "crawl_links": len(crawl_edges),
            "findings": len(snapshot["findings"]),
            "crawl_maps": 1,
            "route_catalog_areas": len(snapshot["api_route_catalog"]),
            "principals": len(snapshot["principals"]),
            "ownership_rules": len(snapshot["ownership_rules"]),
            "access_rules": len(snapshot["access_rules"]),
        }
        for name, value in expected.items():
            if counts[name] != value:
                raise RuntimeError(f"Imported {name}: expected {value}, found {counts[name]}")
        return counts


def main() -> None:
    snapshot, crawl_edges, findings, crawl_map = read_inputs()
    driver = connect()
    try:
        counts = import_graph(driver, snapshot, crawl_edges, findings, crawl_map)
    finally:
        driver.close()
    print(compact({"scan_id": snapshot["scan_id"], "counts": counts}))


if __name__ == "__main__":
    main()
