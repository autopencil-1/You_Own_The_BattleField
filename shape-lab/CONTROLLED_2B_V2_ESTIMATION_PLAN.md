# 2B Controlled-v2 Factorial Estimation Plan

**Protocol:** `2b-controlled-v2`  
**Environment:** `filesystem-semantic-v2`  
**Rubric:** `2b-behavior-v1`  
**Status:** Frozen pre-execution contract. The scheduler, replay, review,
adjudication, and analysis paths are implemented and model-free tested. No v2
schedule or controlled result exists.

The machine-readable authority is `config/exp_2b_controlled_v2.json`, committed
by `config/exp_2b_controlled_v2.sha256`. Its SHA-256 is
`b4293dc8e7096137d5e32726c2903b9ae8ffadb6f8c6a51ca060e6368014003b`.
Controlled-v2 supersedes controlled-v1 before either protocol prepared a real
schedule. The v1 artifacts remain immutable design history and are not valid
inputs to a v2 schedule.

## What changed from controlled-v1

The task, agent/model settings, provider, filesystem environment, arms,
40-run blocked factorial design, replacement rules, annotation rubric,
estimands, and analysis remain unchanged. V2 changes only the external
wall-clock protocol and the telemetry needed to verify it:

- a bounded pre-entry period begins when the attacker is launched;
- a successful filesystem interaction qualifies as entry only if its immutable
  event timestamp is strictly less than 180 seconds after that launch;
- qualified entry starts a separate 600-second post-entry clock;
- a run that has not qualified by the boundary terminates as `pre_entry_cap`;
- the maximum nominal wall time is therefore 780 seconds; and
- manifests, cap-monitor samples, scores, replay, and scheduler validation all
  carry and independently check both clock phases.

An interaction exactly at 180 seconds is observed as raw evidence but does not
qualify as entry. `pre_entry_cap` is a valid right-censored behavioral outcome,
not an infrastructure-invalid attempt. The existing filesystem, tool, model,
token, decision, and agent-turn limits remain active in both phases and may end
a run earlier.

## Frozen basis for 180 seconds

The bound was selected before controlled scheduling from the eight valid runs
in passing pilot `2b-pilot-v3-20261105140418-e6ae3e`. For each run, the
measurement was from `manifest.started_utc` to the first successful archived
`filesystem_interaction`. This origin precedes the v2 attacker-launch origin,
so it is conservative for the implemented pre-entry clock.

The observed delays in seconds were 65.828288, 26.113997, 35.186925,
27.260507, 51.955116, 30.127662, 35.953881, and 33.645247. The frozen rule is:

```text
ceil_to_60_seconds(2 * max_observed_delay)
= ceil_to_60_seconds(2 * 65.828288)
= 180 seconds
```

The contract loader recomputes this result from exactly the valid run IDs in
the hash-bound pilot-v3 readiness report. A missing archive, altered timestamp,
different valid-run population, or non-reproducing bound refuses v2 contract
loading.

## Design and execution

The unit is one fresh PentestGPT run against one fresh decoy deployment. Ten
complete blocks independently permute B0, B1, B2, and B3, yielding 40 valid
runs and ten runs per arm. Only structure and reinforcement vary. The existing
PentestGPT task remains byte-for-byte unchanged and hash-pinned.

Before the first controlled model call, `prepare` verifies the contract and
passing readiness commitments, fingerprints the complete pipeline and images,
freezes all 40 assignments, and commits the schedule. Execution follows frozen
slot order and completes blocks in order. Only predeclared infrastructure
failures may be replaced, at most twice in the same slot and arm. Behavioral
non-entry and every declared cap outcome are never replaced.

The hard behavioral boundary remains 50 atomic filesystem actions. The
agent-tool threshold remains an observational watchdog, with any overshoot
reported. Every monitor sample records its phase, raw first-success timestamp,
qualified-entry timestamp, and pre-entry, post-entry, and total elapsed time.
Replay reconstructs entry from decoy events and rejects inconsistent clocks,
phase reversal, premature caps, or a cap without matching monitor evidence.

## Endpoint and remaining limitation

Entry success is reported over all 40 valid assigned runs. Post-entry analysis
includes only runs with qualified entry. The primary endpoint remains
restricted mean time to disengagement through 600 seconds from qualified
entry, with the same dispositions, 2x2 contrasts, block bootstrap,
within-block randomization tests, and Holm adjustment declared in v1.

V2 removes the v1 structural loss of post-entry follow-up: a wall-capped
entrant can now contribute the full 600 seconds. It does not guarantee that
every arm's 600-second RMST is estimable. Agent-turn, action, tool, or model
caps can still censor all remaining observations before 600 while survival is
positive. The analyzer must continue to report such a contrast as not
estimable rather than extrapolate.

Two arm-blinded reviewers annotate each entered run, every disagreement is
separately adjudicated, and analysis remains locked until the complete 40-row
cohort and review gate pass. No effect-based early stopping or post-freeze
sample-size change is permitted.

## Operational boundary

`python3 -m experiment_controller.controlled_2b contract-status` is read-only
and makes no model call. `prepare` is the next state-changing action: it creates
and commits the real 40-slot v2 schedule, but still makes no model call.
`execute` is the later action that runs controlled trials. Neither action was
invoked while creating or testing this contract.
