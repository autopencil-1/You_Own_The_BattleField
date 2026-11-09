# SHAPE 2B implementation status

**Updated:** 2026-11-06. **Stage:** pilot v3 completed, annotated, and passed
its frozen readiness gate. The `2b-controlled-v2` contract and model-free
scheduler, review, adjudication, and analysis pipeline are implemented. The
support-pilot resource review is complete, the failed v1 and v2 envelopes are
preserved as excluded design evidence, and the replacement
`2b-support-pilot-v3` execution contract and eight-slot schedule are frozen.
V3 has made no model call. No controlled schedule exists, and all support
pilots remain excluded from experimental estimation.

## Implemented

- A virtual filesystem that interprets `pwd`, `ls`, `cd`, `cat`, `head`, `tail`,
  `stat`, `file`, `find`, `grep`, and `wc`, plus virtual unprivileged identity,
  host, environment, and sudo-listing commands, without invoking a host shell,
  reading host paths, or exposing the container environment. It keeps session
  cwd, normalizes aliases, and renders dynamic paths reproducibly from SHA-256
  of a seed and path. Depth, branching, search, command, file, and output sizes
  are bounded.
- A typed, immutable POSIX-shaped metadata core with strict schema-v2 parsing,
  account/group registries, exact-node ownership/mode/timestamps, seeded
  inodes, computed size/link/block fields, numeric orphan-owner fallback, and
  schema-v1 compatibility for dedicated legacy tests. `ls`, `stat`, `file`, and
  `find` now share cached canonical nodes and GNU-shaped, deterministic
  metadata rendering/filtering. One evaluator now handles owner/group/other
  access, supplementary groups, parent traversal, directory listing, and
  `find -readable/-writable`. Command enforcement is a strict opt-in profile
  setting. A component-wise, virtual-only symlink resolver now provides typed
  dangling/cycle/permission failures, bounded link following, and consistent
  command-specific follow/no-follow behavior.
- Schema v2 accepts an optional, strictly validated semantic profile catalog:
  typed root roles, story context, content/name families, metadata windows,
  expansion bounds, link relationships, exact root bindings, and a canonical
  SHA-256 fingerprint. Catalogs compile eagerly into immutable, deterministic
  graphs with coherent per-node tokens, metadata, content, and bounded link
  edges. Static and dynamic arms compile the same graph; only visibility
  differs. Profiles without a catalog retain the legacy generator.
- A per-trial decoy service with an imitated SSH connection gate, independently
  switchable dynamic structure and reinforcement, and sequenced JSONL events.
  Archived responses include exact bytes and hashes. One startup event records
  the loaded catalog, compiled-graph, shared-node, and visibility evidence.
- A lab-only PentestGPT entrypoint that exposes `ssh_connect` and `ssh_exec`
  through the pinned UnifiedAgent MCP tool seam. The PentestGPT source checkout
  remains unchanged. Both roles use one decoy-side session.
- Separate 2B Docker images and Compose topology. The attacker and decoy join
  an internal network; only the model gateway joins the egress network. No
  service publishes a host port. The real provider key is gateway-only.
- A model-free controller that creates a fresh Compose project, checks network
  placement and direct egress, exercises all four arm switches and the actual
  attacker-image tool client, independently checks static/dynamic graph parity,
  archives profile/events/image/config hashes, and tears down containers. A
  bounded real-agent connectivity mode is implemented but has not been invoked.
- A model-free replay checker for event sequence, response hashes, connection
  chronology, command/result consistency, reinforcement attribution, profile
  artifact integrity, runtime fingerprints, and arm-specific graph visibility.
- A versioned `2b-pilot-v3` contract over the frozen
  `filesystem-semantic-v2` environment that pins the existing
  PentestGPT task and filesystem fixture by hash without changing the task.
  The controller pre-randomizes two balanced B0-B3 blocks, verifies source,
  image, task-in-image, provider, and configuration fingerprints, enforces the
  external 600-second/50-filesystem-action stop rules, and permits at most two
  infrastructure-invalid replacements. It is not exposed through the generic
  `run_2b` CLI or dashboard. The rendered schedule has a separate SHA-256
  commitment that is checked on every load.
- The 50-filesystem-action boundary is now explicitly primary and remains
  atomically enforced by the decoy. Every v3 run archives cap-monitor samples;
  replay verifies the sample chronology and cap evidence; and readiness fails
  on a hard-cap violation or missing monitor. The total-tool threshold remains
  an observational watchdog, with overshoot and maximum monitor gap reported
  separately.
- A durable PentestGPT `max_turns` terminal result is now recorded as
  `agent_turn_cap`, accepted as a valid behavioral outcome, and scored as
  right-censored. The controller requires matching structured terminal
  evidence; unrelated agent failures remain infrastructure-invalid. Legacy v1
  manifests retain their original classification.
- A deterministic objective scorer for entry, censoring, retention horizons,
  navigation, tool engagement, reinforcement, model usage, and termination;
  an arm-label-blinded review-packet generator; and the frozen
  `2b-behavior-v1` suspicion, disposition, and escape-attempt rubric. Positive
  and indeterminate judgments cite exact immutable trace lines and hashes.
  Replay now verifies the complete agent artifact inventory and recomputes the
  unannotated pilot score.
- A committed `2b-controlled-v2` machine-readable contract and estimation
  plan. They bind schedule preparation to the exact passing v3 readiness
  report, freeze ten complete randomized B0-B3 blocks (40 valid runs), preserve
  the task and v3 caps, define same-slot infrastructure replacements, require
  two blinded reviewers plus adjudication, and predeclare the post-entry RMST
  endpoint and 2x2 factorial contrasts. V2 adds a 180-second pre-entry bound
  followed by a separate 600-second post-entry clock. The contract loader
  validates its own commitment, recomputes the bound from exactly the eight
  valid pilot-v3 archives, and verifies the pilot schedule/readiness hashes
  without making a model call.
- A controlled scheduler that commits ten complete randomized B0-B3 blocks,
  fingerprints the complete execution/replay/review/analysis pipeline, executes
  frozen slots in complete-block order, permits only two same-slot
  infrastructure replacements, pauses on provider exhaustion, and aborts on
  hard-cap or containment-integrity failures. Preparation is model-free and
  has not been invoked for a real study.
- Controlled-only objective timing from the first successful filesystem
  interaction, with failed pre-entry actions excluded from post-entry
  navigation metrics. The attacker has a bounded 180-second pre-entry phase;
  qualified entry starts a separate 600-second clock, with maximum nominal
  time 780 seconds. The controller records both phases and the selected
  termination time; Docker `FinishedAt` distinguishes natural exit from a cap,
  and replay reconstructs qualification and verifies every monitor sample
  without including shutdown grace in dwell.
- Deterministic, arm-blinded review-packet commitments; exactly two distinct
  reviewers per entered run; hash-bound separate adjudication on every
  disagreement; rejection of non-entry review artifacts; and immutable source
  provenance in the row dataset.
- A strict 40-row censor-aware analysis with Kaplan-Meier retention, 600-second
  RMST, block-bootstrap factorial intervals, within-block randomization tests,
  Holm adjustment, secondary intervals, and indeterminate sensitivity bounds.
  Inference uses a versioned SHA-256 counter sampler, not a runtime PRNG.
  Atomic output includes committed JSON, CSV tables, an SVG retention plot,
  and a limitations/verdict document.
- A committed, non-executable `2b-support-pilot-v1` candidate contract and
  deterministic two-block scheduler skeleton. The candidate keeps the task
  byte-for-byte unchanged, selects the full declared executor ceiling only
  through a hash-bound runtime overlay, records distinct wall/action/tool/model/
  decision/turn/attempt cap reasons, and requires replay of exact trigger
  evidence plus every terminal and nonterminal policy exhaustion. Its
  effect-blind gate rejects any entered run without either a natural event
  before 600 seconds or verified follow-up through 600 seconds; it computes no
  arm contrast or ranking. The future execution wrapper fails closed while
  `execution.available` is false, and the public scheduler refuses to freeze
  assignments while `schedule_freeze_available` is false.
- Effect-blind provider-cost accounting under a frozen Ollama `glm-5.3` rate
  card. A $100 pilot authorization and $15 reserve are checked only before a
  new serial run starts. A budget pause creates no attempt or censored outcome,
  and cost can never terminate an active run. The predeclared 100,000,000-token
  limit remains the catastrophic safety fuse, while cost stays outside the
  600-second support gate.
- The v1 execution overlay and schedule are retained byte-for-byte as
  superseded history. Its first slot made one excluded attempt,
  `2b-supp-20261106043201-bdf8a4`, which exposed both a cap-evidence label bug
  and an inadequate 12-turn executor envelope. Correcting only the label makes
  the archived outcome a valid right-censored `executor_turn_cap`, 15.827695
  seconds after qualified entry; it does not make the v1 support design
  adequate. The attempt and its $0.477794960 provider cost are never imported
  into v2.
- A versioned `2b-support-pilot-v2` execution overlay keeps the task
  byte-for-byte unchanged and raises only the support envelope to 500 executor
  turns, 500 model calls, 500 agent tool calls, and 500 filesystem actions.
  The 180-second pre-entry clock, 600-second post-entry clock, 25 decisions,
  four supervisor turns, 100,000,000-token safety fuse, and effect-blind cost
  admission remain unchanged. The first v2 schedule is preserved but
  superseded after its first attempt failed before any provider call: the
  generic maintained-agent validator still imposed its historical 100-turn
  maximum. The validator now permits up to 1,000 turns, with focused boundary
  tests proving that the frozen 500-turn support setting is accepted and 1,001
  is rejected. Fresh schedule `2b-support-pilot-v2-20261106050510-2cf465`
  freezes two balanced B0-B3 blocks (eight slots) with schedule SHA-256
  `c970b56fe1b58ab51513c084e22d12e79691ff6752fa8c8e3eea7da50556187f`.
  Its first two attempts both reached qualified entry and the full 600-second
  post-entry wall cap, but replay rejected their incomplete policy-exhaustion
  inventories. Durable-state reconstruction shows that each attempt exhausted
  the two-attempt-per-task ceiling twice, before 600 seconds; that independently
  fails the frozen effect-blind support gate. Their combined provider cost is
  $10.684347160. No further v2 run should be started.
- External-stop inventory reconstruction now reads the canonical SQLite state
  through a disposable byte copy, so a controller wall stop can preserve and
  inventory nonterminal attempt exhaustion without mutating WAL evidence. The
  focused telemetry regression passes 22 tests. A diagnostic investigation
  checkpointed the already-excluded first v2 attempt's archived SQLite WAL;
  the expected and observed hashes are preserved in a separate integrity
  incident record, and that archive must remain excluded. The second archive
  remains hash-intact and reproduces fully when its two durable
  `task_attempt_cap` occurrences are projected into a temporary manifest.
- The execution-enabled `2b-support-pilot-v3` contract keeps the task
  byte-for-byte unchanged and places every configurable agent-side
  administrative ceiling at 500: decisions, supervisor and executor turns,
  supervisor attempts, and attempts per task. The external 500 action/tool/
  model-call fuses, 100,000,000-token safety fuse, and 180+600-second clocks
  remain unchanged. V3 explicitly binds the repaired cap taxonomy and agent
  entrypoint in addition to the complete execution pipeline. Its committed
  opening balance carries forward both v2 attempts and $10.684347160 under the
  unchanged $100 authorization and $15 between-run reserve. Schedule
  `2b-support-pilot-v3-20261106055726-49c7fa` freezes two balanced B0-B3 blocks
  with schedule SHA-256
  `291cdacf8aa4931bb0fdb19e8d3d33df3d03be6d14232e1e5ff3e1c8284b852c`.
  It has zero v3 attempts; opening remaining authorization is $89.315652840.
- Support-only gateway and controller instrumentation for atomic call/token
  caps, missing-usage infrastructure failures, dual-phase wall clocks,
  proximity samples, exact trigger timestamps, deterministic tie precedence,
  and combined policy-exhaustion manifests. Synthetic fixtures cover natural
  exit, exact-boundary caps, hidden attempt exhaustion, and estimable and
  non-estimable cohorts while preserving pilot-v3 and controlled-v2 semantics.
- Maintained PentestGPT now exposes versioned turn and attempt policies. Its
  defaults reproduce the historical task-kind and two-attempt limits, while
  v3 can configure supervisor attempts and attempts per task up to 1,000 and
  persists them in the CLI contract, trial identity, summary, run spec, and
  durable state. Trial identity, trace input, and terminal output also persist
  the selected executor policy and effective limits. Exact provider turn
  counts remain nullable because the pinned adapter does not expose them;
  archives record that unavailability rather than estimating a count.
- A schema-v2 `ledger-prod-01` fixture with coherent `ledger-api` configuration,
  release, service-log, backup, and operator-home paths. Three semantic profiles
  compile 45 deterministic nodes for the frozen fixture seed. B0/B2 hide them;
  B1/B3 expose them. Explicit nodes and graph compilation remain shared.
- The local dashboard can prepare both image sets with `make up` and launch the
  bounded B0 fixture connectivity check on explicit operator action. The
  dashboard does not start a model run during setup.

## Verification

- The support-focused model-free regression set passed 90 tests spanning the
  runtime overlay, cap taxonomy, candidate contract/scheduler, runner,
  scoring/replay, historical pilot/controlled contracts, annotation,
  adjudication, and analysis. Nine gateway tests also passed with only a local
  ephemeral loopback socket and mocked upstream responses.
- The final support-v2 contract/runtime/scheduler/scoring/replay regression
  slice passed 53 focused tests. All three 2B images were rebuilt before the v2
  schedule freeze, and the frozen schedule is balanced at one B0-B3 assignment
  per block.
- The maintained PentestGPT trial regression passed all 16 tests after aligning
  its generic executor-turn validation boundary with the support envelope;
  focused Ruff lint and formatting checks also pass.
- The final support-v3 controller, contract, cost-carry, taxonomy, scoring, and
  replay slice passed 65 focused tests with resource warnings treated as
  errors. The maintained-agent trial and memory slice passed 28 tests, strict
  mypy, Ruff lint, and formatting. The rebuilt attacker image accepted all five
  configurable v3 administrative bounds at 500.
- The maintained PentestGPT policy/trace changes passed 74 focused tests,
  Ruff, and strict mypy checks. The task JSON SHA-256 remains
  `72f1d9978b51e3508905100653ecab5e44d6db5d4f3adbea30dbfe7ab1052689`.
- `docker compose --profile agent -f compose_2b.yaml config --quiet` passes
  with provider 429 retry delays explicitly empty for the candidate envelope.

- The complete local suite discovered 125 tests: 106 executed and passed, while
  19 optional dashboard or attacker-runtime tests were skipped because those
  dependencies are absent in the host environment.
- `docker compose --profile agent -f compose_2b.yaml config --quiet`: passed.
- `shape-2b-attacker:dev` built and passed its offline image/tool smoke with
  networking disabled.
- Fresh model-free Docker fixture checks passed for B0, B1, B2, and B3 after
  final fixture integration, and all four archives replayed successfully. All
  checks exercised the actual `ssh_connect`/`ssh_exec` client inside the attacker
  image and verified no direct external egress. Each archive contained 20
  filesystem actions; B0/B1 recorded zero reinforcement deliveries and B2/B3
  recorded one. All four shared catalog, compiled-graph, and shared-node
  fingerprints, while runtime compiled-node visibility was 0/45/0/45. Replayed
  results retained `experimental_result: false`. The latest post-pilot-infra
  matrix is `2b-dete-20261105104951-128cd3` (B0),
  `2b-dete-20261105104952-172e51` (B1),
  `2b-dete-20261105104952-f7344f` (B2), and
  `2b-dete-20261105104952-723041` (B3).
- The offline pilot fingerprint check passed against all three existing image
  IDs. It verified the task, SSH adapter, entrypoint, fixture, filesystem
  engine/server, gateway sources, and maintained PentestGPT source *inside*
  the images against the workspace hashes; the embedded and workspace task
  hashes both remained `72f1d997...2689`.
- Diagnostic pilot `2b-pilot-20261105111132-1dc131` produced one valid
  action-capped run and two entered, replayable runs that terminated at the
  pinned PentestGPT turn bound. Both were classified as `agent_failure` by v1,
  exposing a replacement-policy mismatch rather than a provider, archive, or
  containment failure. The pilot is retired and must not be resumed.
- `make up` built both image sets and started the dashboard; one model-free B0
  run launched through its API completed and replayed successfully.
- The fixture archives replay. One early B2 check failed because its smoke
  script looked for reinforcement on the fourth qualifying command instead of
  the configured third; the failed archive remains in ignored `runs/`, and the
  corrected B2 check passed.

## Boundary before experimental runs

`config/exp_2b_engine_fixture.json` now contains a believable but wholly
synthetic operational story. It is still an engineering fixture, not an
experimental result, and its checked-in SHA-256 is
`31c65ec971a3c85b0592bf9196fd66b76079e1b7474d222c0e8b788749f848f3`.
The Compose file explicitly marks the profile as `fixture`; the agent
entrypoint refuses model use on that profile unless the controller opts into a
bounded connectivity check. Model-backed pilot calls were used only to validate
instrumentation; no pilot contributes to the controlled 2B estimate.

The schema-v2 fixture story, static-tree comparability, objective scorer,
annotation rubric, pilot gate, replay checks, and runner are integrated. The
PentestGPT task remains byte-for-byte identified by SHA-256
`72f1d9978b51e3508905100653ecab5e44d6db5d4f3adbea30dbfe7ab1052689`.
The eight-run engineering pilot is an instrumentation gate: two randomized,
balanced B0-B3 blocks with a 10-minute-or-50-filesystem-action cap. Passing it
does not require B3 to outperform B0 and does not contribute to the later
effect estimate.

Pilot v2 schedule `2b-pilot-v2-20261105114740-d51bc4` completed eight valid
runs and passed its declared gate after annotation. It remains preserved under
schedule SHA-256
`795947a947fff6e0f1ee0a9fa88c6a2bff0cdd5c020837157fda32e0330ff7e3`.
Its 56/50 observational tool-watchdog overshoot motivated the v3 cap-evidence
slice; the atomic filesystem boundary still held at 50 actions.

Pilot `2b-pilot-v3-20261105140418-e6ae3e` froze two balanced B0-B3 blocks and
the v3 controller/scorer/replay fingerprints. Its schedule SHA-256 is
`e715ca1c2cbb18ca729b424a4087c18a998fdab15c32860eb3b9f25069dc1361`.
It completed eight valid runs with zero infrastructure-invalid attempts. After
arm-blinded annotation, all nine gate checks passed and readiness was frozen at
SHA-256
`5072aca396888f623e2a098cd8fe92f60cf6c636650ceb7e1fef74e959de4417`.
One run contained an annotated adapter-bypass attempt, but no confirmed
containment escape incident occurred.

The separately committed `2b-controlled-v2` contract specifies ten complete
blocks and 40 valid assignments, but the assignments themselves have not been
created. Its 180-second bound was frozen as the next 60-second increment above
twice the pilot-v3 maximum start-to-first-success delay: twice 65.828288 seconds
rounds to 180 seconds. Qualified entry then receives the full 600-second
post-entry window, resolving the v1 structural support mismatch. Earlier
agent-turn, action, tool, or model censoring can still make an arm's RMST
non-estimable; the analyzer reports that rather than extrapolating. V1 is
preserved as superseded design history and was never scheduled. Preparing v2
is model-free; executing it is the later step that makes controlled model
calls. The prospective, not-yet-execution-enabled remediation is specified in
`CONTROLLED_2B_HORIZON_SUPPORT_PLAN.md`; it separates the unchanged task from a
versioned execution envelope and requires a new effect-blind support pilot
before any controlled-v3 freeze.

The reviewed support candidate, v1 evidence, and the hash-bound v2 contract,
schedule, manifests, results, and gateway evidence remain immutable; the first
v2 archive's SQLite checkpoint incident is separately recorded as described
above. The v2 contract
`07097d23f859fbf40efb959a0f1900b30e14fdeec15adc4b37a182ad4618ff58`
and its schedule remain frozen history, but execution should not continue: two
independent entered runs already demonstrate a pre-600 administrative
exhaustion, so v2 cannot pass its aggregate support rule. V3 contract
`1e415ce158af4a66b213f96fbe8de962e62e1e4edf36cb5df4c439ba63a73c51`
and the new schedule above bind the repaired durable-state collector, carry
forward the $10.684347160 provider spend, and move configurable administrative
bounds behind the outer experimental fuses. A support cap remains a valid
behavioral censor and is never converted into infrastructure failure or
replaced.

The agent still has its provider's ordinary local Bash tool inside the
isolated attacker container. Only decoy-side `ssh_exec` events count as remote
filesystem exploration; local Bash actions need separate accounting.
