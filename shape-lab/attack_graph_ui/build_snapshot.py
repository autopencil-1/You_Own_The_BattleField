"""Build the read-only UI snapshot from the crawl dump and provisional CMDB.

The PostgreSQL dump is parsed as data. No SQL from the archive is executed.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "BUGCAMP_CRAWL"
INSERT = re.compile(
    r'^INSERT INTO "bugcamp_crawl"\."([^"]+)".*?\$asm_row\$(.*?)\$asm_row\$::jsonb\);'
)

GROUPS = [
    ("ticket-pages", "Ticket pages", "web"),
    ("profiles", "Profiles", "web"),
    ("programs", "Programs", "web"),
    ("hacktivity", "Hacktivity", "web"),
    ("nuxt-bundles", "Nuxt bundles", "web"),
    ("api-attachments", "Ticket attachments", "api"),
    ("api-other", "Other API routes", "api"),
    ("web-other", "Other web routes", "web"),
]


def read_dump() -> dict[str, list[dict]]:
    rows: dict[str, list[dict]] = defaultdict(list)
    with (SOURCE / "bugcamp.io_443.sql").open(encoding="utf-8") as stream:
        for line in stream:
            match = INSERT.match(line)
            if match:
                rows[match.group(1)].append(json.loads(match.group(2)))
    return rows


def group_for(url: str) -> str:
    path = urlsplit(url).path
    if path.startswith("/api/tickets/") and "/attachment/" in path:
        return "api-attachments"
    if path.startswith("/api/"):
        return "api-other"
    unlocalized = re.sub(r"^/en(?=/|$)", "", path)
    if re.match(r"^/tickets/[^/]+$", unlocalized):
        return "ticket-pages"
    if unlocalized.startswith("/@"):
        return "profiles"
    if unlocalized.startswith("/programs"):
        return "programs"
    if unlocalized.startswith("/hacktivity"):
        return "hacktivity"
    if unlocalized.startswith("/_nuxt/"):
        return "nuxt-bundles"
    return "web-other"


def main() -> None:
    rows = read_dump()
    expected = {
        "service_information": 2,
        "webapp_information_endpoint": 522,
        "endpoint_crawl_edge": 9854,
        "endpoint_crawl_map": 1,
        "endpoint_finding": 4,
    }
    for table, count in expected.items():
        if len(rows[table]) != count:
            raise ValueError(f"{table}: expected {count}, got {len(rows[table])}")

    cmdb = json.loads((SOURCE / "provisional_cmdb.json").read_text(encoding="utf-8"))
    endpoint_rows = rows["webapp_information_endpoint"]
    groups = {id_: {"id": id_, "label": label, "tier": tier, "count": 0}
              for id_, label, tier in GROUPS}
    endpoints = []
    for row in endpoint_rows:
        group_id = group_for(row["url"])
        groups[group_id]["count"] += 1
        endpoints.append({
            "id": row["id"],
            "url": row["url"],
            "group": group_id,
            "status": row["status_code"],
            "content_type": row["content_type"],
            "tested": row["url_tested"],
            "crawled": row["is_crawled"],
            "fold_reason": row["fold_reason"],
            "service_id": row["service_id"],
        })
    endpoints.sort(key=lambda row: (row["group"], row["url"]))

    findings = [{
        "id": row["id"],
        "url": row["url"],
        "group": group_for(row["url"]),
        "type": row["finding_type"],
        "name": row["finding_name"],
        "severity": row["severity"],
        "verified": row["verified"],
        "verify_method": row["verify_method"],
    } for row in rows["endpoint_finding"]]

    map_row = rows["endpoint_crawl_map"][0]
    web_count = sum(group["count"] for group in groups.values() if group["tier"] == "web")
    api_count = sum(group["count"] for group in groups.values() if group["tier"] == "api")
    nodes = cmdb["nodes"] + [
        {"id": "surface:web", "kind": "RouteSurface", "name": "Web routes",
         "count": web_count, "visibility": "external", "evidence_state": "crawl_observed"},
        {"id": "surface:api", "kind": "RouteSurface", "name": "API routes",
         "count": api_count, "visibility": "external", "evidence_state": "crawl_observed"},
    ]
    edges = cmdb["edges"] + [
        {"from": "app:bugcamp-nuxt", "to": "surface:web", "kind": "SERVES_ROUTE_FAMILY",
         "evidence_state": "analyst_asserted"},
        {"from": "app:bugcamp-api", "to": "surface:api", "kind": "SERVES_ROUTE_FAMILY",
         "evidence_state": "analyst_asserted"},
    ]
    for dependency in cmdb["logical_store_connections"]:
        nodes.append({"id": dependency["id"], "kind": "LogicalStoreRole",
                      "name": dependency["role"].capitalize(), "visibility": "internal",
                      "evidence_state": "user_confirmed" if dependency.get("technology") else "unknown",
                      "connection_state": dependency["connection_state"],
                      "asset_identity": dependency["asset_identity"],
                      "asset_id_provenance": dependency.get("asset_id_provenance"),
                      "technology": dependency.get("technology"),
                      "deployment": dependency.get("deployment"),
                      "technology_candidates": dependency.get("technology_candidates", []),
                      "deployment_candidates": dependency.get("deployment_candidates", []),
                      "database_instance_ref": dependency.get("database_instance_ref"),
                      "port": dependency.get("port"),
                      "port_candidates": dependency.get("port_candidates", []),
                      "status": dependency["status"]})
        edges.append({"from": dependency["from"], "to": dependency["id"],
                      "kind": dependency["relationship"],
                      "direction": dependency["direction"],
                      "evidence_state": dependency["connection_state"]})
        if dependency.get("published_via"):
            edges.append({"from": dependency["id"], "to": dependency["published_via"],
                          "kind": "PUBLISHED_VIA", "evidence_state": "user_confirmed"})
        if dependency.get("database_instance_ref"):
            edges.append({"from": dependency["id"], "to": dependency["database_instance_ref"],
                          "kind": "RESIDES_IN", "evidence_state": "user_confirmed"})

    nodes.append({"id": "network:internet", "kind": "NetworkSource", "name": "Any IP",
                  "visibility": "external", "evidence_state": "user_confirmed"})
    for exposure in cmdb["network_exposures"]:
        edges.append({"from": "network:internet", "to": exposure["to"],
                      "kind": "CAN_REACH", "protocol": exposure["protocol"],
                      "service": exposure["service"],
                      "port": exposure["port"], "network_policy": cmdb["network_policy"]["id"],
                      "evidence_state": "user_confirmed", "attack_step": False})

    node_ids = [node["id"] for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("Duplicate graph node ID")
    if any(edge["from"] not in node_ids or edge["to"] not in node_ids for edge in edges):
        raise ValueError("Graph edge refers to an unknown node")
    principal_ids = {principal["id"] for principal in cmdb["principals"]}
    if any(principal not in principal_ids for rule in cmdb["access_rules"]
           for principal in rule["required_principals"]):
        raise ValueError("Access rule refers to an unknown principal")
    if any(principal not in principal_ids for rule in cmdb["ownership_rules"]
           for principal in rule["owners"]):
        raise ValueError("Ownership rule refers to an unknown principal")

    snapshot = {
        "schema_version": 2,
        "scope": cmdb["scope"],
        "path_policy": cmdb["path_policy"],
        "scan_id": cmdb["source_scan_id"],
        "collected_at_kst": "2026-10-30 04:25:07",
        "metrics": {
            "discovered_urls": map_row["url_count"],
            "folded_endpoints": len(endpoints),
            "crawl_links": len(rows["endpoint_crawl_edge"]),
            "findings": len(findings),
            "tested_endpoints": sum(bool(row["tested"]) for row in endpoints),
            "crawled_endpoints": sum(bool(row["crawled"]) for row in endpoints),
            "status_counts": dict(Counter(str(row["status"]) for row in endpoints)),
        },
        "nodes": nodes,
        "edges": edges,
        "services": [{
            "ip": row["ip"],
            "service_id": row["service_id"],
            "port": row["port_number"],
            "product_label": row["service_product"],
            "root_status": row["http_banner"]["status_code"],
            "root_location": row["http_banner"]["headers"].get("Location"),
            "endpoint_rows": sum(endpoint["service_id"] == row["service_id"]
                                 for endpoint in endpoints),
        } for row in rows["service_information"]],
        "groups": list(groups.values()),
        "endpoints": endpoints,
        "findings": findings,
        "api_route_catalog": cmdb["api_route_catalog"],
        "third_party_references": cmdb["third_party_references"],
        "network_policy": cmdb["network_policy"],
        "network_exposures": cmdb["network_exposures"],
        "principals": cmdb["principals"],
        "ownership_rules": cmdb["ownership_rules"],
        "access_rules": cmdb["access_rules"],
        "sources": cmdb["sources"],
    }
    destination = HERE.parent / "attack_graph" / "snapshot.json"
    destination.write_text(json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + "\n",
                           encoding="utf-8")
    print(f"wrote {destination} ({len(nodes)} nodes, {len(edges)} edges, {len(endpoints)} endpoints)")


if __name__ == "__main__":
    main()
