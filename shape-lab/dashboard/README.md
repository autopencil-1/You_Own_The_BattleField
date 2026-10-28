# Local SHAPE console: first slice

This local UI has an index page for 2A and 2B, archived-run viewing, live
decoy events, a separate agent activity pane for archived agent traces, and a
button to launch **model-free deterministic fixture checks**. It does not yet
launch 2A connectivity/pilot or any 2B agent run. Every UI-created fixture is
marked as an engineering check, not an experimental result.

## Start

Use Python 3.12 and Node.js 20.19+ or 22.12+ from `shape-lab/`:

```sh
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python -r requirements-dashboard.txt
cd dashboard_ui
npm ci
npm run build
cd ..
.venv/bin/uvicorn dashboard.app:app --host 127.0.0.1 --port 8787
```

Open <http://127.0.0.1:8787/>. The UI and launch API are loopback-only. A
browser launch uses a local session token stored under ignored `runs/`; no
provider key is sent to the browser. Node.js is only needed to build or edit
the frontend. For development, run `npm run dev` in `dashboard_ui/`; its API
proxy points at the local Python server.

Select 2A or 2B, choose an arm, and click **Run experiment**. The default
reuses already-built Docker images; select **Build images** if the images are
missing or need refreshing. 2B also accepts a validated fixture seed and
branching factor. One dashboard job runs at a time.

The run page appears immediately, including before the controller creates its
run directory. During execution the controllers mirror decoy logs to
`decoy-live.jsonl` (and gateway/agent logs where applicable). The API writes a
derived `monitor-events.jsonl` inside each ignored run directory. Final raw
`decoy-events.jsonl`, traces, manifests, and replay checks remain authoritative.

The upper-right **Agent elapsed** timer starts only when an `AGENT_STARTED`
record is observed. Fixture checks launch no agent, so that timer displays
`—`. The nearby **Decoy engaged** timer starts from the first decoy request
for 2A or first virtual filesystem interaction for 2B.

## Current boundary

- The right pane displays exact archived response text after verifying its
  SHA-256. 2A HTTP request/response and canary events appear in order; 2B
  connection, command, and reinforcement events appear in order.
- The left pane displays PentestGPT's recorded visible commentary, tool calls,
  tool results, and structured events for archived agent runs. PentestGPT
  omits private reasoning content, and the UI labels that omission.
- Selecting an agent action may show nearby server activity, explicitly marked
  **time-correlated**. Exact 2A/2B tool-to-server interaction IDs and the
  launch controls for real-agent modes are later slices.
- The local dashboard does not alter trial prompts, treatments, or caps.

Run the checks with:

```sh
.venv/bin/python -m unittest discover -s tests -v
cd dashboard_ui && npm run build
```
