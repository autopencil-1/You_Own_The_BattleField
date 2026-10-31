# Bugcamp attack surface graph UI

This local analyst UI shows the 2026-10-30 `bugcamp.io:443` crawl beside the user-supplied CMDB. The asset graph labels crawl observations as ASM and other supplied infrastructure as CMDB. The RAG threat model asks GLM-5.3 for testable vulnerability hypotheses, then a local planner chains them with known routing and checks capability prerequisites. Hypotheses appear before routes; a chosen route appears on the graph with known steps and unverified weakness steps distinguished. Its routes are conditional; URL discovery, network reachability, and a route ACL do not establish an exploitable transition. All assets are in target scope; defense priority can be added later. See [research and method](../attack_graph/THREAT_MODEL_RAG.md).

**Preview local example** shows ten offline, unverified hypotheses and eighteen illustrative chains without calling Ollama or saving a run. It includes the separate SQL injection, credential recovery, login, and authorization steps. The user approved exporting selected sanitized Bugcamp evidence to Ollama Cloud; the latest saved GLM-derived run was locally revalidated under stricter capability rules and contains fifteen hypotheses and twenty-five conditional routes.

## Chosen stack

| Layer | Decision | Role |
| --- | --- | --- |
| Graph store | Neo4j Community `2026.10.1` in a dedicated Docker Compose project | Store versioned assets, observations, typed relationships, and later path prerequisites. Not part of the SHAPE trial network. |
| Graph API, ingestion, and RAG | Python FastAPI with Neo4j Python driver 6.x | Parse the PostgreSQL dump as data, retrieve evidence, validate model actions, and plan conditional routes. |
| Browser UI | React 19, TypeScript 5.9, Vite 7, Cytoscape.js 3 | Render evidence-aware subgraphs and inspect endpoints. Node 24 is used for builds. |
| Source evidence | The original PostgreSQL SQL dump and `provisional_cmdb.json` | Preserve original scan data and analyst assertions. Neo4j is a derived projection. |

Docker runs Neo4j and the API with a persistent Neo4j volume and a local, ignored `.env` file. Bolt stays on the internal Compose network; only the API is exposed on `127.0.0.1:8791`. FastAPI serves the Vite production bundle. The model key is read at runtime, never stored in the graph or UI bundle.

## Current slice

The UI reads `/api/graph/overview` from Neo4j. The graph holds 16 asset and network records, 25 topology and network relationships, 522 endpoint observations, 9,854 raw discovery links, two service observations, four finding summaries, 11 route catalog areas, one source crawl-map record, five principals, six ownership rules, and 12 access rules. The analyst canvas shows the four API-to-store connections and seven public network links. The external-surface view shows the crawl-facing subset. Endpoint drill-down keeps crawled URLs separate from the analyst's route catalog.

The asset graph uses two visible source classes: **ASM** for crawl-observed assets and links, **CMDB** for all supplied or inferred asset data. The detailed evidence state remains in the source records and access-rule inspector. When a saved candidate route exists, the analyst graph overlays its actions as empty red outline boxes beneath the assets. Red lines show step order and the affected asset; selecting a box displays the action description, prerequisites, gained capability, citations, and missing evidence. The overlay never marks a candidate as a verified exploit. The route picker switches between saved candidate paths. Existing runs were reconciled to remove independent-action permutations, with their original path lists retained on the run nodes as `legacy_paths_json`; newly generated paths require a causal capability dependency between adjacent steps. The UI also filters any older noncausal paths it receives.

The resource and backend target IDs use stable `synthetic:` values. They support graph joins and repeat imports; they are not AWS identifiers. Each app tier has one representative backend target ID, while the actual target count remains unknown. The user confirmed `web_tg` as `ip/HTTP:80`, `api_tg` as `ip/HTTP:3000`, RDS MySQL 8, a session table in that RDS instance, EFS ticket files, and S3 public uploads served through CloudFront.

The user supplied a network policy allowing any source IP to reach each modeled service port. `CAN_REACH` represents that network assumption, including the database and EFS. It does not imply a valid session, IAM permission, ticket ownership, or S3 object access. Access rules preserve observed responses separately from inferred principal and ownership checks. The `admin` username has no distinct role token in the supplied code, so it receives no automatic staff grant.

The view switch is a presentation preview, **not an access control boundary**. The overview response contains internal CMDB assertions. Keep the stack on loopback; add real authentication and server-side projections before sharing it with other users. The threat-model generator stores candidate runs in Neo4j; it does not probe the target.

## Run locally

First create a local Neo4j password, if `.env` does not already exist. From `shape-lab/attack_graph/`:

```sh
python3 -c 'import os,secrets; fd=os.open(".env",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.write(fd,("NEO4J_PASSWORD="+secrets.token_urlsafe(32)+"\n").encode()); os.close(fd)'
```

Build the derived import input and browser bundle, then start Neo4j, import, and start the API:

```sh
cd ../attack_graph_ui
python3 build_snapshot.py
npm ci
npm run build
cd ../attack_graph
docker compose up -d neo4j
docker compose build api
docker compose --profile import run --rm importer
docker compose up -d api
```

Open `http://127.0.0.1:8791/`. The Vite development server can run on `127.0.0.1:5174` with `npm run dev`; it proxies `/api` to the same local API. Vite 7 needs Node 20.19+ or 22.12+; Node 24 is used in this workspace. The SQL dump is mode `0600` here, so the importer runs with the host owner UID/GID. Set `GRAPH_IMPORT_UID` and `GRAPH_IMPORT_GID` in `.env` if those are not `1000:1000`.

For live GLM-5.3 generation, pass the existing root `.env` Ollama credential to Compose when starting the API. From `shape-lab/attack_graph/`, run `docker compose --env-file ../../.env --env-file .env up -d --force-recreate api` with `THREAT_MODEL_EXTERNAL_EXPORT_ALLOWED=true` in the local graph `.env`. The key stays in the container environment and is not sent to the browser. **Inspect retrieval** works without a key. Generation sends selected evidence to `https://ollama.com/v1/chat/completions`; no model key is needed for `python3 -m unittest test_threat_model.py`.

`build_snapshot.py` parses the dump's JSON row literals without executing SQL. It checks table counts and writes `attack_graph/snapshot.json` for ingestion, leaving out screenshot bucket paths, response bodies, and embedded source-code excerpts. The importer also reads raw crawl links, findings, and the crawl-map record from the dump. Both the snapshot and `.env` are ignored by Git. MERGE keys make repeat imports of the same scan idempotent. Additions and property updates can be reimported; removal from an existing scan needs explicit reconciliation because the importer retains prior records.

The map reports 568 discovered URLs; 555 distinct URL strings occur in the imported endpoint and raw crawl-link rows. These are different source measures. The map document and its counts are retained on `CrawlMapObservation`.

Graph read routes: `/api/health`, `/api/graph/overview`, `/api/graph/subgraph?root=origin:bugcamp.io:443&depth=2&limit=100`, and `/api/graph/endpoints?group=api-attachments&limit=10&offset=0`. The overview includes network policy, principals, ownership rules, and access rules. The subgraph response is bounded to 100 graph entities and depth 3; the endpoint route pages up to 100 observations. Threat-model routes are `GET /api/threat-model/status`, `POST /api/threat-model/context` for inspectable retrieval, `POST /api/threat-model/generate` for GLM generation and persistence, and `GET /api/threat-model/latest` for the last run. Both POST routes accept `{"goal":"...","target_asset_id":null}`; `target_asset_id` can be any graph node ID. Generation may incur model usage.

## Graph semantics

Canonical assets and endpoints receive stable IDs. Scan observations carry `scan_id`, timestamp, source, and evidence state. `OBSERVED_ON`, `ROUTES_TO`, `TARGETS`, `REFERENCES_HOST`, and `CAN_REACH` describe surface, topology, or network relationships. They are not attack steps. An attack transition additionally needs an actor or role, prerequisites, a weakness or permission, and the gained capability. `REQUIRES_PRINCIPAL`, `NAMES_OWNER`, and `GOVERNS_SURFACE` connect the access model in Neo4j. `ThreatModelRun`, `CandidateAction`, and `CandidatePath` retain model proposals and their conditional status.

The UI uses the same overview contract as the original generated snapshot. Server-side visibility controls are still required before a multi-user deployment.

## Remaining input for possible attack paths

1. Evidence of exploitable weaknesses or granted permissions to promote conditional actions. Pattern findings alone do not establish compromise.
2. Confirmation of the inferred role and object checks, especially private-ticket disclosure, crew membership, manager ownership, and partial disclosure behavior.
3. Store-level permissions and identity policies. The allow-any-IP rule covers network filtering only.
4. Real AWS and backend target IDs if later data must be joined across inventories. Their exact strings do not change path feasibility, but identity equivalence and target cardinality can change graph results.

The sanitized listener sketch records `/api/*` to `api_tg` and default to `web_tg` as analyst assertions. The user confirms no URL rewrite; the actual listener configuration export has not been supplied.
