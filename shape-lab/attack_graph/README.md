# Bugcamp Neo4j graph service

The local Compose stack, importer, and read-only FastAPI server are documented in the [UI README](../attack_graph_ui/README.md). Run Compose commands from this directory. Neo4j data persists in the `bugcamp-attack-graph_neo4j_data` volume; only the API/UI is published, on `127.0.0.1:8791`.

`importer.py` reads the derived `snapshot.json` and JSON row literals from the original SQL dump. It does not execute dump SQL. Each observation and topology link has a stable scan-scoped key, so rerunning the importer updates the same records. The importer verifies counts after every run.
