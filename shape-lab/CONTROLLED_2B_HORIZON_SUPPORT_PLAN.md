# Controlled 2B 600-Second Horizon-Support Plan

**Status:** Model-free slices 1–4 and the provider-cost admission policy are
implemented as a committed, resource-reviewed candidate; not
execution-enabled, scheduled, or readiness-passed.  
**Predecessor:** `2b-controlled-v2`  
**Prospective protocol:** `2b-support-pilot-v1`, then `2b-controlled-v3` only
after the support gate passes.  
**Task boundary:** Keep `config/agent_2b_task.json`, its goal, target, model,
effort, and role instructions byte-for-byte unchanged.

## Implementation checkpoint

As of 2026-11-06, the cap taxonomy, configurable PentestGPT turn policy,
phase-aware controller/gateway telemetry, synthetic scoring/replay fixtures,
strict candidate-contract loader, and deterministic scheduler skeleton are
implemented. The candidate contract deliberately sets both
`execution.schedule_freeze_available: false` and `execution.available: false`;
preparing or executing a real support schedule is not part of this checkpoint.

The 2026-11-06 resource review found the bounded containers and serial
execution acceptable. Provider cost is governed between runs rather than by a
new in-run censor: the contract freezes an effect-blind USD rate card, a
$100 pilot authorization, and a $15 minimum uncommitted reserve before each
new run. Once admitted, a run is never terminated for ordinary provider spend.
The authorization is therefore an admission boundary, not a guaranteed hard
ceiling: one admitted run can exceed its reserve. A budget pause starts no run,
creates no attempt, and is neither a behavioral outcome nor censoring.

The pinned provider adapter does not expose an exact provider `num_turns`
count. The archive therefore records a nullable count plus the explicit status
`unavailable_from_pinned_provider_adapter`, while still requiring the typed
terminal trace, canonical agent transition, declared limit, role, task kind,
episode, and timestamp. No count is inferred or fabricated.

## Objective

Make the predeclared 600-second post-entry retention endpoint empirically
supportable without calling an administrative cap a disengagement event and
without changing the treatment arms. Controlled-v2 must not be patched in
place or scheduled while this refinement is being evaluated.

The target is not “no censoring.” Natural completion or abandonment remains an
observed event, and a genuine administrative limit remains right-censoring.
The target is to move avoidable execution limits outside the 600-second
estimand window and demonstrate that envelope in a separate, effect-blind
support pilot before freezing a controlled-v3 schedule.

## Evidence behind the refinement

All eight valid pilot-v3 runs entered the filesystem and were annotated
`continued_until_censored`. Their approximate time from first successful
filesystem interaction to the last controller monitor was:

| Arm | Termination | Post-entry monitor span |
| --- | --- | ---: |
| B2 | `wall_cap` | 542.851 s |
| B1 | `agent_turn_cap` | 9.412 s |
| B0 | `agent_turn_cap` | 7.320 s |
| B3 | `agent_turn_cap` | 6.974 s |
| B0 | `agent_turn_cap` | 20.832 s |
| B3 | `agent_turn_cap` | 11.095 s |
| B2 | `tool_cap` | 272.409 s |
| B1 | `agent_turn_cap` | 22.453 s |

The six turn-capped runs are explained by the pinned PentestGPT runtime, not by
the task file's nominal `executor_max_turns: 12` ceiling. PentestGPT currently
applies lower task-kind work budgets and reserves one additional result turn:

| Task kind | Work turns | Provider turns |
| --- | ---: | ---: |
| discover | 5 | 6 |
| enumerate | 6 | 7 |
| test | 5 | 6 |
| exploit | 9 | 10 |
| verify | 4 | 5 |
| recover | 6 | 7 |

The observed failures at six or seven turns therefore match the effective
discover/enumerate ceilings. Raising only `executor_max_turns` would do
nothing while the runtime continues to take the minimum of that ceiling and
the task-kind budget.

The remaining non-turn-capped B2 run reached the 50-tool observational
watchdog after 52 observed tool calls and 46 filesystem actions at about 272
post-entry seconds. The other long run used 43 tools, 29 filesystem actions,
and 40 model calls before the old overall wall cap. No pilot-v3 run reached the
50-action or 60-model-call limits, but the observed rates show that either can
become the next early censor after the turn issue is removed.

## Decision boundary

The 600-second disengagement RMST cannot be made supportable while every
current execution cap remains effective. There are only two honest paths:

1. **Recommended: version the execution envelope.** Preserve the task file and
   task semantics, but explicitly change the runtime opportunity given to that
   task. This changes the experimental agent/runtime configuration and
   therefore requires a new support pilot and controlled protocol.
2. **Strict cap preservation: change the primary estimand.** If the current
   turn, tool, action, model, and decision limits are considered inseparable
   from “the PentestGPT task,” 600-second disengagement RMST cannot remain the
   confirmatory endpoint. A bounded terminal-state endpoint could be fully
   observed, but it would measure time to completion, abandonment, or policy
   exhaustion—not disengagement alone.

Administrative caps must not be reclassified as disengagement events merely
to make Kaplan-Meier output estimable. Parametric extrapolation also does not
restore follow-up support and is not the proposed fix.

## Recommended execution-envelope candidate

Implement the envelope as a separate, hash-bound runtime policy. Do not edit
the checked-in task JSON. Defaults outside the support protocol must remain
exactly the current PentestGPT defaults.

The first candidate is:

- use the existing executor ceiling of 12 provider turns for every task kind,
  including the reserved result turn, instead of the lower task-kind minimum;
- retain `supervisor_max_turns: 4` and record supervisor exhaustion distinctly;
- raise the experiment controller's decision fuse from 20 to 25;
- raise the atomic filesystem safety fuse from 50 to 325 actions;
- raise the observational total-tool fuse from 50 to 350 calls;
- raise the gateway model-call fuse from 60 to 150 calls;
- retain the 100,000,000-token fuse; and
- retain controlled-v2's 180-second pre-entry plus 600-second post-entry
  clocks.

These are calibration candidates, not frozen study settings. The action,
tool, and model values use the pooled pilot-v3 maximum rate among the two runs
that were not turn-capped, project that rate to 600 seconds, multiply by three,
and round upward to 25. This gives 325 actions, 350 tools, and 150 model calls.
The decision candidate similarly places a threefold margin over the long-run
episode rate. The calculation uses no arm contrast or favorable-effect rule.

Before any model-backed pilot, a resource review must confirm that these
fuses are safe for the bounded virtual filesystem and acceptable for provider
cost. If not, the endpoint must change; limits must not be silently lowered
after observing support-pilot behavior.

### Provider-cost governance

The resource review is approved under an admission-only policy. Cost must not
become a treatment-dependent stopping rule inside the 600-second estimand
window:

- retain the 100,000,000-token gateway limit solely as the predeclared
  catastrophic safety fuse;
- do not add a per-run USD termination threshold or a `provider_cost_cap`
  trial outcome;
- execute runs serially in frozen schedule order;
- price only provider-reported archived usage using the rate card frozen in
  the candidate contract;
- before starting a new run, require at least $15 of the $100 pilot
  authorization to remain uncommitted;
- after admission, allow that run to reach its natural or predeclared
  scientific/safety boundary even if accrued cost crosses the authorization;
- pause before the next run when the reserve test fails; and
- keep aggregate cost accounting effect-blind and outside the support gate.

The frozen accounting rates for Ollama `glm-5.3` are $1.40 per million input
tokens, $0.26 per million cached-input tokens, and $4.40 per million output
tokens. Cache-creation input is conservatively assigned the ordinary input
rate. A rate change requires a new committed contract; it must not silently
change the accounting of an already-frozen schedule.

## Implementation slices

### 1. Complete cap taxonomy and telemetry

Inventory every terminal bound: pre-entry time, post-entry time, filesystem
actions, agent tools, model calls, model tokens, decisions, supervisor turns,
executor turns, and retry attempts. Give each deterministic terminal state a
separate manifest reason and record its configured limit, observed count, role,
task kind, episode ID, and exact terminal timestamp.

Unknown bounded-agent terminal states must fail closed as telemetry errors.
Provider/transport failures remain infrastructure-invalid; declared policy
exhaustion remains a valid right-censored behavioral outcome.

### 2. Configurable PentestGPT runtime policy

Add an explicit task-kind turn-policy input to PentestGPT's `TrialConfig` and
trial identity. Keep the current hard-coded mapping as the default so existing
runs and non-2B behavior do not change. The 2B support entrypoint supplies the
hash-bound “full declared executor ceiling” policy.

Persist the effective per-kind budgets and runtime-policy revision in
`trial-config.json`, trace inputs, the summary, image fingerprint, and run
manifest. Recovery rules remain fail-closed: no actionful attempt may be
replayed merely because it reached a turn limit.

### 3. Phase-aware controller fuses

Add a versioned runtime-envelope object to the support-pilot contract. Pass its
model limit to the gateway, its filesystem limit to the atomic decoy boundary,
and its tool/decision limits to controller monitoring. All limits apply equally
to B0–B3 and must be frozen before randomization.

The monitor must record proximity to every fuse as well as the selected
termination reason. Replay independently recomputes counts and rejects a
premature or misclassified terminal reason. Shutdown grace remains outside
post-entry dwell.

### 4. Model-free support fixtures

Add synthetic archives for each terminal reason and for:

- a natural event before 600 seconds;
- an entrant observed through exactly 600 seconds;
- an exact-boundary turn/tool/action/model fuse;
- a max-turn transcript that contains actions but no valid structured result;
- a supervisor or decision exhaustion state; and
- a complete balanced cohort that is and is not estimable through tau.

Tests must prove that the task file hash is unchanged, default PentestGPT
budgets are unchanged, the support policy is present only when explicitly
selected, and controlled-v1/v2 archives retain their historical semantics.

### 5. Freeze and run `2b-support-pilot-v1`

Only after the model-free slices pass, freeze two randomized complete B0–B3
blocks under the candidate envelope. The support pilot is an instrumentation
gate and is excluded from the effect estimate.

The gate requires:

- eight valid assigned runs with the same source/image/runtime fingerprints;
- the existing entry, replay, hard-boundary, annotation, and containment checks;
- at least one entered run per arm;
- zero undeclared terminal states;
- no turn, decision, action, tool, model, or token censor before 600 seconds in
  any entered run; and
- for every arm, at least one entered run with either an adjudicated natural
  disengagement event before 600 or verified follow-up through 600.

A cap-triggered support-pilot run is not replaced as infrastructure failure. It
demonstrates that the candidate envelope failed and requires a new versioned
candidate. The gate must never inspect an arm contrast or require B3 to exceed
B0.

### 6. Freeze controlled-v3 only after the gate

Bind controlled-v3 to the exact passing support-pilot schedule, readiness
report, runtime policy, task hash, images, and source fingerprints. Preserve
the 40-run blocked factorial design, annotation workflow, 600-second RMST,
replacement rules, and no-effect-peeking rule.

If an early administrative censor nevertheless occurs in the real cohort, it
remains a valid censored observation and is never replaced. The analyzer must
still report per-arm support, cap incidence, and non-estimability honestly.
The support pilot reduces this risk; it cannot logically guarantee future
agent behavior.

## Go/no-go order

1. **Complete:** approve the versioned execution-envelope change while keeping
   the PentestGPT task unchanged.
2. **Complete:** implement slices 1–4 without model calls.
3. **Complete:** review the candidate safety and provider-cost envelope and
   commit admission-only cost governance.
4. **Next:** freeze an execution-enabled support-pilot contract and its
   schedule.
5. Have the operator execute its eight model-backed runs.
6. Evaluate the effect-blind support gate.
7. Freeze controlled-v3 only on a pass; otherwise version the envelope or
   change the endpoint.

No support schedule, controlled-v3 schedule, model call, or task edit is
authorized by this implementation checkpoint. The maintained PentestGPT
runtime-policy changes were separately approved and keep legacy defaults
unchanged unless the support overlay is explicitly selected.
