# Local SHAPE console

This local UI has an index page for 2A and 2B, archived-run viewing, live
agent and decoy events, and allowlisted launch controls. It offers 2A C2 pilot,
2A connectivity, 2B B0 connectivity, and model-free deterministic checks.
The 2B connectivity run uses generic fixture content and is an engineering
check; the final 2B B0–B3 study remains pending its synthetic story.

## Start

From the repository root, put a nonempty `ZAI_API_KEY` in `.env`, then run:

```sh
make up
```

This installs dashboard dependencies, builds the frontend and both sets of
Docker images, and starts the host-side dashboard in the background. It does
not start an agent or call a model until you launch a model-backed run in the
UI. Open <http://127.0.0.1:8787/>. Use `make status` to check the server and
`make down` to stop the dashboard. Active trial workers continue to their
controller cap if the dashboard is stopped. Logs and the service PID live in
ignored `shape-lab/runs/.dashboard-service/`.

The UI and launch API are loopback-only. A browser launch uses a local session
token stored under ignored `runs/`; no provider key is sent to the browser.
Node.js is needed only to build or edit the frontend. For development, run
`npm run dev` in `dashboard_ui/`; its API proxy points at the local Python
server.

Select 2A or 2B, choose an available mode and arm, review the effective caps,
and click **Run experiment**. The default reuses images built by `make up`;
select **Rebuild Docker images** after changing image sources. 2B accepts a
validated fixture seed, and deterministic checks accept a branching factor.
The 2A pilot uses C2 only; 2B connectivity uses B0 only. One dashboard job
runs at a time.

The root `.env` supplies the Z.AI key to a temporary gateway-only secret file
when a model-backed run begins. Agent model, effort, task, and caps come from
the pinned `config/agent_2a_task.json` and `config/agent_2b_task.json` files;
the UI displays them but does not accept arbitrary environment overrides.

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
  **time-correlated**. Exact 2A/2B tool-to-server interaction IDs are a later
  slice.
- The local dashboard does not alter trial prompts, treatments, or caps.

Run the checks from the repository root with:

```sh
make check
```
