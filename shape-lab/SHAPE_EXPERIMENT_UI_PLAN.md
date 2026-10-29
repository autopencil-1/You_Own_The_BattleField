# SHAPE experiment console: 2A and 2B

**Status:** implementation plan, 2026-10-26. This expands the 2B-specific
monitor design in [2B_MONITOR_UI_PLAN.md](2B_MONITOR_UI_PLAN.md) into one local
dashboard that can launch and monitor either experiment. The 2B synthetic story
and its full agent-run protocol are still pending.

## Product shape

The home page has two experiment cards, **2A · OBEY** and **2B · EXPLORE**.
Each card shows its available run modes, latest run, and a **New run** button.
A common recent-runs table filters by experiment, mode, status, and date.
Clicking a run opens the same two-pane live/replay layout: observable agent
activity on the left, target-server behavior on the right, and a sticky timer
at the upper right. The server pane has an experiment-specific renderer.

```text
┌ SHAPE experiments ────────────────────────────────────────────────────────┐
│ [ 2A · OBEY        New run ]   [ 2B · EXPLORE        New run ]             │
│ Recent runs: experiment | mode | status | started | duration | open        │
└───────────────────────────────────────────────────────────────────────────┘

┌ Run 2a-...  LIVE ───────────────────────── Agent 04:12 / 20:00 ─────────┐
│ Agent activity                 │ Web decoy: request → response → canary    │
│ Supervisor decision            │ GET /login  200  state ACTIVATED          │
│ Executor Bash/curl call        │ C2 response delivered                     │
│ Tool result                    │ Stage 1 pending · Stage 2 pending          │
└────────────────────────────────┴──────────────────────────────────────────┘
```

```text
Home  ──►  Choose 2A or 2B  ──►  Configure run  ──►  Review resolved settings
  ▲                                       │                    │
  └──────────── Recent runs ◄─────────────┴────────── Run experiment
                                    │
                                    ▼
                            Live monitor / replay
```

This is a **local operator console**, not a component of the attacker or decoy
network. It binds to `127.0.0.1` by default. The browser never receives a
model key or direct Docker access.

## Shared monitor and experiment-specific panels

| Region | Shared behavior | 2A detail | 2B detail |
|---|---|---|---|
| Left agent feed | Supervisor/Executor role, visible commentary, structured summaries, tool calls/results, local command activity, errors | Highlight `Bash`/`curl` calls to the web target; one tool call may create several HTTP requests | Highlight `ssh_connect`/`ssh_exec`; distinguish remote virtual commands from local Bash |
| Right server feed | Raw event timestamps, request/response pairs, exact response preview, state changes, selected-event detail | HTTP method and route, status, exact response body, activation, condition response, injection delivery, stage-1 and stage-2 canary hits | Virtual command, path/cwd, exit code, exact output, generated branch, reinforcement delivery |
| Upper-right timer | Agent elapsed from `agent_started`, cap progress, time since last relevant action | Time from first qualifying web request and from activation, when present | Time from successful virtual entry plus decoy dwell |
| Bottom metrics | Model calls/tokens, agent tool calls, caps, telemetry health | Requests; activation and canary stages as observed by the decoy | Filesystem actions; unique directories; reinforcement count |

The 2A decoy intentionally logs normalized routes rather than raw login query
values. Show the actual agent command separately, but do not claim that the
server recorded the full URL. Add a server-generated `request_id` to associate
each 2A request, response, and state transition. An agent `Bash` call can make
multiple requests, so the UI groups server events in the call's time interval
and labels that relation **time-correlated** unless exact evidence is available.
The 2B adapter can carry an internal `interaction_id` to join its transport
events to decoy responses, as specified in the 2B monitor plan. Never draw a
false one-to-one connector for ambiguous activity.

The PentestGPT trace omits private reasoning content. The agent feed displays
observable commentary and structured decisions, with a neutral **model
working** state while no text is available. Do not change prompts just to
make the dashboard look more active.

## Launch modes and current availability

| Experiment | Mode offered now | Current controller behavior | UI rule |
|---|---|---|---|
| 2A | Deterministic check | Model-free decoy check for C0/C1/C2 | Select arm; label result **fixture check** |
| 2A | Connectivity check | Bounded real-agent smoke | Select arm; label **engineering check**, not treatment result |
| 2A | C2 pilot | Full C2 engineering pilot with frozen task/caps | C2 fixed; show model-use and 20-minute cap before launch |
| 2A | Controlled cohort | Separate `controlled_2a.py` prepare/execute/status workflow, with pilot and fingerprint gates | Dedicated study workflow: prepare balanced schedule, preview, then execute; individual arm/cap controls disabled |
| 2B | Deterministic check | Model-free B0/B1/B2/B3 fixture | Select arm and validated seed; label **fixture check** |
| 2B | Connectivity check | B0-only, bounded real-agent check on generic fixture | Available after the user's explicit approval; label it an engineering check, never a study result |
| 2B | Pilot and 40-run study | Not implemented yet | Show **planned**, not a functioning launch button; implement after story/profile freeze |

The home page must never make fixture checks look like agent outcomes. For a
controlled cohort, the existing readiness and fingerprint checks remain in
the controller; the UI cannot bypass them. A cohort run's arm is assigned by
its frozen schedule, not by a browser field.

## Configuration form: allowlisted values

The UI uses named, versioned **profiles**, rather than a free-form environment
variable editor. It loads the selected profile, shows effective settings and
their source, validates any exploratory overrides, and archives the resolved
request plus its SHA-256 in the run manifest. Each profile has a clear status:
`fixture`, `engineering`, `pilot`, or `study-frozen`.

| Field | Where offered | Rule |
|---|---|---|
| Experiment / mode / arm | All applicable single runs | Enumerated choices; 2A pilot forces C2, 2B connectivity forces B0, controlled studies use schedule assignments |
| Build images or reuse pinned images | Engineering and fixture runs | Default to reuse only when image fingerprint matches; otherwise build and show expected preparation stage |
| 2B deterministic seed | 2B fixture and later experimental profile | Validated short text; logged and hashed |
| 2B branching factor and reinforcement cadence | Exploratory 2B fixture previews | Bounded integers; wire through explicit controller parameters, not arbitrary environment injection; changes label run exploratory |
| Wall, tool, model-call, and token caps | Exploratory single-agent runs only | Positive numbers no higher than that mode's approved maximum; changes mark the run non-comparable to a frozen cohort |
| Fixed model, target, task, treatment text, trigger rule, agent revisions, network, credential path | Read-only profile details | Changing these requires a new versioned profile and a new freeze, not a hidden UI override |
| Provider key | Status only | Show **configured/missing**. Read it host-side only when an authorized model run begins; never show, edit, or send its value to the browser |

This gives the requested environment controls without accepting arbitrary
`SHAPE_*`, `ANTHROPIC_*`, shell commands, mount paths, or credential values from
the browser. The current controllers set some values internally, so adding a
field requires a validated controller argument and a manifest entry; simply
setting an environment variable in the UI would be misleading.

Before launch, a review sheet shows: experiment, mode, arm or blinded schedule,
profile version/hash, image action, effective caps, whether a real model will
be called, and the output run location. **Run experiment** submits exactly
that reviewed request. On success, navigate to the job page immediately,
showing build/preflight; switch to its live run view once the controller emits
the run ID. The agent timer begins only at `agent_started`.

## Host control plane

The earlier 2B plan's observer remains read-only. A separate host-side
`RunManager` accepts validated launch requests, starts the existing Python
controllers with an argument array (never a shell command string), and writes
a durable job journal. Limit to one active trial by default so Docker resource
contention does not become an uncontrolled study variable. Keep a global lock
across API restarts. Store the child PID, run ID once known, controller phase,
exit status, and output artifact path; recover status after a UI restart.

The controller owns Docker Compose and trial caps. The UI service is not put
on the trial network. The monitor collector tails the host-mounted agent trace
and follows decoy/gateway Docker logs into per-run files while the controller
is active. At teardown, reconcile live captures with archived final logs and
surface telemetry gaps. Raw artifacts remain the source of truth; the UI's
combined timeline is a derived view.

An operator **Stop run** action may be offered for an active single run. It
must ask the controller to stop gracefully, archive the result, and record
`manual_stop`; it must not kill an arbitrary PID or delete containers directly.
In a controlled cohort, any manual stop is retained and classified under the
study's existing invalid/censoring rules rather than silently replaced.

Because `Run experiment` invokes Docker and can spend model budget, protect
its POST endpoints with a local session token, same-origin/Origin check, and
CSRF protection. Bind to loopback, use no permissive CORS, accept only JSON
matching a closed schema, and allowlist file reads beneath `shape-lab/runs/`.
The browser receives neither `.env` contents nor secrets mounted in the
gateway. A remote-access design would be a separate decision.

## API and event schema

Keep the FastAPI + SSE and React + TypeScript stack from the 2B plan. Add
launch/status endpoints to the read-only monitor API:

| Method and path | Purpose |
|---|---|
| `GET /api/experiments` | Capability matrix and profiles for 2A/2B |
| `GET /api/runs` | Filtered list of active and archived runs |
| `POST /api/runs` | Validate and enqueue one permitted single run; return `job_id` immediately |
| `GET /api/jobs/{job_id}` | Build, preflight, agent, collection, scoring, or failed status |
| `POST /api/runs/{run_id}/stop` | Controlled manual stop with recorded reason |
| `GET /api/runs/{run_id}` | Snapshot, effective config, timer origin, counters |
| `GET /api/runs/{run_id}/stream` | Numbered SSE events with resume |
| `GET /api/runs/{run_id}/events?after=N` | Paged replay |
| `POST /api/studies/2a/prepare` | Invoke existing gated cohort preparation |
| `POST /api/studies/2a/{study_id}/execute` | Execute a prepared schedule without changing assignments |

One projection schema should cover both experiments:

```json
{
  "schema_version": 1,
  "run_id": "2a-... or 2b-...",
  "experiment": "2A",
  "event_id": 42,
  "source": "agent|decoy|gateway|controller",
  "kind": "tool_call|decoy_response|activation|...",
  "occurred_utc": "2026-10-26T00:00:00.000Z",
  "source_sequence": 7,
  "call_id": "if-known",
  "request_id": "if-2a-server-event",
  "interaction_id": "if-2b-ssh-event",
  "raw_ref": {"source": "decoy", "line": 12}
}
```

The live timer uses an explicit `agent_started` event rather than today's
manifest `started_utc`, which precedes build and preflight in both controllers.
Use the browser's monotonic clock to interpolate between server heartbeats;
resynchronize on reconnect and freeze at `agent_stopped`. 2A activation and
2B decoy-entry timers have their own event anchors. Display `unknown` when an
anchor is missing, never `00:00` by assumption.

## Build sequence and verification

1. Create the shared run/profile schema and capability matrix. Refactor both
   controllers to accept validated launch requests while preserving their
   current CLI entry points and frozen study invariants.
2. Add the host `RunManager` and explicit lifecycle events. Test one-job lock,
   restart recovery, invalid settings, failed builds, and manual stop.
3. Implement the common collector, live log followers, replay index, SSE API,
   and source-specific 2A/2B event adapters. Verify response hashes against
   raw archives and show unpaired events honestly.
4. Build the home page, configuration/review flow, shared agent feed, and the
   2A/2B server panels. Make the elapsed timer visible through all run phases.
5. Exercise 2A C0/C1/C2 and 2B B0/B1/B2/B3 with model-free fixture runs from
   the UI. Verify that the browser can disconnect/reconnect and replay the
   same event sequence, and that no model call occurs in fixture mode.
6. Check the existing 2A connectivity and pilot flows through the UI only when
   explicitly launched. The B0 fixture connectivity run is available as an
   engineering check after user approval. Keep the 2B pilot and 40-run study
   gated until its synthetic story and versioned experimental profile are
   frozen; then add the agreed 10-minute or 50-action cap.

No backend result should depend on whether anyone opened the dashboard. A
closed browser, API restart, or telemetry display failure must not alter the
controller's trial outcome or archived evidence.
