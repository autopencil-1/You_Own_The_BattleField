# Agent activity feed: evidence and next slice

## Evidence from the 2026-10-30 Ollama C2 pilot

Run `2a-pilo-20261030072921-301f3c` has 53 projected monitor events. The left
feed shows 31 cards, including one agent-start marker. Fifteen of those cards
are transport details: four session starts, five omitted-reasoning markers,
and three `StructuredOutput` calls with their three acknowledgement results.
The same three structured decisions then appear again in `turn_completed`.
This explains the repeated JSON and the low signal in the current feed.

The meaningful sequence is: supervisor assigned discovery task T1; the
executor issued three Bash probe calls and reported a completed discovery;
the supervisor assigned test task T2; the gateway crossed the 200,000 reported
token cap and rejected the next model request; the second executor episode
failed before another target action. The manifest currently reports only
`agent_exit` with code 1, which hides the more specific cap observation.

## Sources and display rules

| Source | What it establishes | Default presentation |
| --- | --- | --- |
| `agent/runs/<id>/state.sqlite3` `transitions` | Committed task plans, results, and failures, keyed by revision | One task or decision card per committed transition |
| `agent/runs/<id>/traces/*/events.jsonl` | Visible commentary, tool calls, tool results, and terminal episode errors | Commentary and paired tool activity; one failure card per failed episode |
| `agent/runs/<id>/summary.json` | Final task and attempt statuses | Final run summary after the agent exits |
| `decoy-live.jsonl` / `decoy-events.jsonl` | Target requests, responses, activation, and canary stages | Server timeline and time-correlated tool detail |
| `gateway-live.jsonl` / `gateway-events.jsonl` | Model attempts, reported tokens, retry waits, provider or trial caps | Compact model/cap markers and run-level failure reason |
| `manifest.json` | Controller termination and fixed settings | Run header and final status |

The traces intentionally omit private reasoning content. The UI must not
reconstruct or imply unseen reasoning from token counts or `raw_event` markers.
Every displayed summary should retain a reference to its authoritative raw
line or committed state revision.

## Proposed default left feed

1. **Task plan:** supervisor summary, task ID, kind, objective, target, and
   next task. Derive it from `plan_committed`, not the duplicate
   `StructuredOutput` call and `turn_completed` payloads.
2. **Visible commentary:** the agent's recorded text, with a short preview and
   full text on expansion. Label it as commentary, not private reasoning.
3. **Tool interaction:** one card per call/result pair, showing the exact
   command or tool input, success or error, a short output preview, duration
   when available, and full input/output on expansion. Pair by episode ID and
   call ID. Keep decoy events on the server side and label their relationship
   as time-correlated until an exact request ID exists.
4. **Task outcome:** `attempt_committed` outcome, grounded summary, observation
   ID, or `attempt_failed` failure kind/message. Show final task status from
   `summary.json` when the run closes.
5. **Run outcome:** controller termination, agent exit, and the observed
   gateway cap or provider error. Distinguish a model-token cap from a provider
   HTTP 429 and from an agent-level failure.

## Diagnostics and implementation order

Keep session starts, omitted-reasoning notices, `StructuredOutput` transport
calls and acknowledgements, raw trace events, full JSON fields, and detailed
usage behind an explicit **Diagnostics** view or expanded card. Do not delete
them from the archive. Show a single note that reasoning content is omitted.
The monitor projection currently caps each string at 12,000 characters; add
a path-validated, on-demand raw-line endpoint for longer records so expansion
can reach the authoritative archive without loading every full record upfront.

Implemented in the dashboard: committed transitions are projected from the
SQLite database in read-only mode; the default **Activity** feed pairs tool
calls and results and uses those transitions in place of structured decision
transport records. **Diagnostics** retains the trace records. Expansion loads
an authoritative source record on demand. The 2A pilot and a 2B connectivity
archive were checked for ordering and terminal cause. Event collection remains
derived from the archive and scoring is unchanged.
