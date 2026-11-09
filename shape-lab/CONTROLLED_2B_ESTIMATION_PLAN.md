# 2B Controlled Factorial Estimation Plan

**Protocol:** `2b-controlled-v1`  
**Environment:** `filesystem-semantic-v2`  
**Rubric:** `2b-behavior-v1`  
**Status:** Superseded before scheduling by `2b-controlled-v2`. This frozen v1
artifact is retained as design history; no v1 controlled-study schedule or
controlled result exists.

The active plan is `CONTROLLED_2B_V2_ESTIMATION_PLAN.md`. V1 must not be used
to prepare a new schedule.

The machine-readable contract is
`config/exp_2b_controlled_v1.json`, committed by
`config/exp_2b_controlled_v1.sha256`. Any change to the design, estimands,
replacement rules, or analysis requires a new protocol version. It must not be
made by editing a frozen schedule or reclassifying collected runs.

## Readiness boundary

Controlled scheduling is authorized only by the passing readiness report for
pilot `2b-pilot-v3-20261105140418-e6ae3e`:

- pilot schedule SHA-256:
  `e715ca1c2cbb18ca729b424a4087c18a998fdab15c32860eb3b9f25069dc1361`;
- readiness SHA-256:
  `5072aca396888f623e2a098cd8fe92f60cf6c636650ceb7e1fef74e959de4417`;
- all nine frozen readiness checks passed;
- the pilot and its annotations remain engineering evidence and are excluded
  from every controlled estimate.

The scheduler must refuse preparation if either artifact is missing, its hash
differs, the readiness report is bound to another schedule, or any required
check is not exactly `true`.

## Question, unit, and treatments

The unit is one fresh PentestGPT run against one fresh decoy deployment. The
question is whether filesystem structure, contextual reinforcement, or their
interaction increases post-entry exploration retention under the pinned
general-purpose task.

| Arm | Structure | Reinforcement | Interpretation |
| --- | --- | --- | --- |
| B0 | Off | Off | Static baseline |
| B1 | On | Off | Structure only |
| B2 | Off | On | Reinforcement only |
| B3 | On | On | Combined treatment |

All arms retain the same task, agent/model settings, provider, fixture seed,
starting point, command adapter, container topology, caps, and reinforcement
cadence. Only the two declared treatment switches vary. In particular, the
checked-in PentestGPT task remains unchanged and hash-pinned at
`72f1d9978b51e3508905100653ecab5e44d6db5d4f3adbea30dbfe7ab1052689`.

## Schedule and randomization

The study contains ten complete B0-B3 blocks: 40 valid assigned runs and ten
runs per arm. Before the first controlled model call, the scheduler must:

1. verify the contract commitment and passing pilot readiness dependency;
2. fingerprint the task, fixture, controller, scorer, replay, annotation,
   analysis, images, maintained agent source, and pinned dependency versions;
3. generate a fresh randomization seed;
4. independently and uniformly permute B0-B3 within each complete block;
5. write all 40 assignments and the fingerprint to one private schedule; and
6. write a SHA-256 commitment for that schedule.

Execution follows the frozen order and completes a block before starting the
next. Resuming may skip already-valid slots but may not reorder remaining
assignments, switch an arm, add a block, or use an observed effect to stop
early. There is no post-freeze sample-size change in v1.

## Trial caps, outcomes, and replacements

Each run ends at natural completion/disengagement or the first applicable
administrative limit. Controlled v1 preserves one overall 600-second clock
from attacker launch and a 50-atomic-filesystem-action limit. The existing
agent-side model, token, tool, decision, and turn caps remain unchanged.

Wall, action, model, tool, and agent-turn caps are right-censoring, not natural
exit events. The filesystem server's atomic 50-action boundary is the hard
behavioral cap. The total agent-tool count remains an observational watchdog;
overshoot is reported separately and never presented as a hard-boundary
violation.

Non-entry, completion, abandonment, suspicion, and censoring are behavioral
outcomes and are never replaced. Only a predeclared infrastructure-invalid
attempt may be retried, in the same frozen slot and arm. A slot permits at most
two such replacements. Provider exhaustion pauses execution for later resume;
source/image drift refuses execution; a confirmed containment escape aborts
the study and is handled as a security incident rather than an outcome.

Every attempt remains in the artifact inventory and report, including invalid
attempts. A slot with no valid run after its replacement budget is exhausted
prevents analysis rather than silently reducing or reallocating the cohort.

## Blinded review and adjudication

Every entered valid run receives an arm-label-blinded review packet and two
independent annotations under `2b-behavior-v1`. Reviewer identifiers must be
distinct. Raw annotations are immutable.

Any disagreement in suspicion, disposition, or escape-attempt judgment
requires a separate adjudication artifact that cites both raw annotation
hashes and records the final value and rationale. Analysis cannot start until
every entered run has two valid annotations and all disagreements are
adjudicated. Reviewers may infer treatment from content; reporting must state
that limitation rather than claim perfect blinding.

## Populations and primary endpoint

Entry success means that the agent completed at least one successful virtual
filesystem interaction and is reported over all 40 valid assigned runs. A
connection without a successful command is retained separately in objective
telemetry but is not post-entry eligibility. Post-entry outcomes use the valid
runs with successful entry; non-entry stays visible in the entry denominator
and is not converted into zero retention.

The primary endpoint is restricted mean time to disengagement through 600
seconds, measured from the first successful filesystem interaction. An
adjudicated `task_completed` or `abandoned_decoy` disposition is an observed
disengagement event. `continued_until_censored` is right-censored at the
observed dwell time. An adjudicated `indeterminate` disposition is excluded
from the primary point estimate and included in predeclared best/worst-case
sensitivity bounds.

The operational event/censor timestamp is the immutable controller-observed
termination instant: Docker `FinishedAt` for a natural agent exit, or the cap
monitor observation at which an administrative boundary is selected. The
adjudicated disposition determines whether that time is an event or a censor;
active filesystem span is secondary and never substitutes for termination
time. Because the single overall wall clock starts before the post-entry time
origin, a wall-censored entrant normally has less than 600 seconds of
post-entry follow-up. The nonparametric v1 analysis reports 600-second RMST and
contrasts as not estimable unless follow-up support reaches 600 seconds or the
survival curve has already reached zero. This limitation must be accepted
explicitly before scheduling, or corrected under a new protocol version.

This post-entry estimand is explicitly conditional on entry. It is reported
alongside the all-run entry rate and must not be described as an effect among
agents that never entered the virtual environment.

## Factorial contrasts

Let each arm symbol denote its estimated 600-second restricted mean retention.
Positive values mean greater retention.

```text
Structure       = 0.5 * ((B1 - B0) + (B3 - B2))
Reinforcement   = 0.5 * ((B2 - B0) + (B3 - B1))
Interaction     = (B3 - B2) - (B1 - B0)
```

These three contrasts form the confirmatory family. Tests are two-sided at
alpha 0.05 with Holm adjustment. Effect estimates receive 95% block-bootstrap
intervals using 10,000 complete-block resamples. Exploratory randomization
tests use 99,999 within-block treatment permutations and an analysis seed
derived from the frozen schedule hash. Draws use the code-defined
`sha256_counter_uint64_rejection_fisher_yates_v1` sampler rather than a
runtime-library PRNG. The report must include unadjusted and adjusted values
and must not turn a non-significant result into evidence of no effect.

## Secondary analysis

Secondary outputs include entry, survival-style retention at 60, 180, 300, and
600 seconds, filesystem and exploratory actions, active interaction span,
engagement ratio, navigation depth/breadth, backtracks, revisits, model usage,
suspicion, disposition, and escape attempts. They are descriptive with 95%
intervals and do not carry confirmatory claims in v1.

Fixed-horizon retention must be derived with censoring-aware survival logic.
A run censored before a horizon is not counted as a failure at that horizon.
Arm tables show total and entered denominators, censoring, missingness,
termination reasons, infrastructure-invalid attempts, and annotation
disagreements. Confirmed containment incidents are reported separately from
annotated attempts.

## Required immutable artifacts

The controlled pipeline freezes:

- `schedule.json` and `schedule.sha256` before execution;
- every valid and invalid run archive plus replay result;
- blinded review packets, two raw annotations per entered run, and separate
  adjudications;
- a row-level analysis dataset containing run IDs and source artifact hashes;
- an atomic analysis bundle containing `analysis.json`, the row dataset,
  committed CSV tables, a deterministic SVG retention plot, an analysis-code
  fingerprint, and a bundle manifest;
- `limitations-and-verdict.md`, distinguishing observed evidence from claims
  not supported by this one agent/model/task configuration.

The model-free implementation is complete. The next state-changing step would
prepare the real schedule and freeze all 40 assignments; execution is the
later step that makes model calls. Schedule preparation should wait for an
explicit decision on the documented 600-second support limitation. Neither
implementation nor testing created a real schedule or made a controlled model
call.
