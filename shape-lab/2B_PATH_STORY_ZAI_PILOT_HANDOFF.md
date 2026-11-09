# Z.ai path-story pilot handoff — 2026-11-09

Work is stopped at the user's request because their network connection is
unstable. Do not start another model run until the user resumes.

## Frozen study

- Pilot ID: `2b-path-story-pilot-v3-zai-20261109124716-3c0485`
- Schedule SHA-256: `32af55e9b613d25d80ea8e3c386f5d0cf1be85a86e87b95e2fd35edb660bf9c5`
- Fresh, balanced eight-slot cohort; unchanged PentestGPT task and path-story
  filesystem fixture. Prior Ollama v2 slots and dollar ledger remain separate.
- User-approved local Coding Plan shares: 14,000 estimated credits per rolling
  five hours and 35,000 estimated credits for this pilot overall. The controller
  requires 7,500 uncommitted credits in both shares before each new run and
  never stops an active run for the local credit share. Other subscriber usage
  cannot be seen by this controller.
- The published Z.ai table identifies 140,000 Max credits as weekly. The
  35,000 pilot share has no automatic reset, avoiding dependence on the user's
  recollection of a monthly period.

## Checks and first attempt

- A minimal direct request to the documented Z.ai Anthropic Coding Plan route
  returned HTTP 200, model `glm-5.3`, and provider token usage. The key was not
  written to a report or printed.
- B0/B3 dummy-key Docker preflights passed with no attacker process and zero
  model calls. Report:
  `runs/path-story-zai-candidate-20261109122935-0e4fe8/report.json`.
- Slot 1 attempt `2b-path-20261109124816-55aca0` is infrastructure-invalid,
  reason `controller_error` derived from agent failure. All 35 gateway model
  responses were HTTP 200, served `glm-5.3`, had complete SSE framing and
  reported usage. All 35 provider and downstream request lifecycles settled.
  The replay archive exists. The agent process exited with code 0 but its
  trial summary reports `provider: episode stream ended without TurnCompleted`.
  Root cause is unresolved; do not blindly retry.
- Estimated attempt use: 100.809835 credits. Status after the attempt shows
  no completed slots, next slot 1, no pending run, and 34,899.190165 total /
  13,899.190165 rolling five-hour credits left in the local shares. These are
  estimates from gateway token usage, not live Z.ai account balances.

## Resume point

1. Read `agent/runs` and `agent/workspaces` trace event **types and timestamps**
   for the invalid attempt, without changing the PentestGPT task or treating
   the failed attempt as a behavioral outcome. Determine why Claude Code's
   stream lacked `ResultMessage`/`TurnCompleted` despite complete gateway SSE.
2. If an instrumentation fix is needed, version it. The schedule fingerprints
   the current runner, controller, Compose, gateway, and task source; do not
   silently edit those files and continue under the frozen schedule.
3. Verify the archived attempt and local credit ledger before any replacement.
   The controller's `execute` command starts at most one assignment per call.

Read-only status command:

```sh
PYTHONPATH=shape-lab python3 -m experiment_controller.path_story_pilot_2b_zai_execution status \
  --pilot-id 2b-path-story-pilot-v3-zai-20261109124716-3c0485
```
