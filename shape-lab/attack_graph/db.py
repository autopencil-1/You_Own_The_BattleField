"""Neo4j connection shared by the importer and read-only API."""

from __future__ import annotations

import os
import time

from neo4j import GraphDatabase


def scan_id() -> str:
    return os.environ["GRAPH_SCAN_ID"]


def connect(*, attempts: int = 30, delay_seconds: float = 2.0):
    driver = GraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]),
        connection_timeout=10,
    )
    for attempt in range(attempts):
        try:
            driver.verify_connectivity()
            return driver
        except Exception:
            if attempt == attempts - 1:
                driver.close()
                raise
            time.sleep(delay_seconds)
    raise RuntimeError("Neo4j did not become ready")
