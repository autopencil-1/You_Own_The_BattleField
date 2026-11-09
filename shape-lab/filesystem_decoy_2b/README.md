# 2B Virtual Filesystem Core

This package is the story-independent part of SHAPE 2B. `virtual_fs.py` holds a
synthetic path tree and interprets a restricted command set: `pwd`, `ls`, `cd`,
`cat`, `head`, `tail`, `stat`, `file`, bounded `find`, bounded `grep`, and `wc`.
It also supplies virtual unprivileged host context through `id`, `whoami`,
`groups`, `hostname`, `uname`, `env`, `printenv`, and a non-executing
`sudo -n -l` response. A `Session` must connect before commands work; its
current directory persists between calls. No command reaches a host shell, no
virtual path resolves to a host file, and the virtual environment never reads
the decoy container's real process environment.

The engine converts its data specification into typed virtual nodes with
immutable POSIX-shaped metadata. Schema v2 supports account/group registries,
per-node ownership, four-digit octal modes, nanosecond UTC timestamps, stable
seeded inodes, computed size/link/block fields, and symlink metadata. The
legacy directories/files form remains supported through a schema-v1
compatibility adapter. Generated names derive from SHA-256 of the trial seed
and normalized virtual path. `dynamic=False` disables generated branches
without changing the command interface. Depth, branching, command length,
argument count, search traversal, file content, and response size are bounded.

`ls`, `stat`, `file`, and `find` consume the same cached node for each
normalized path. Long `ls` supports named or numeric ownership, human-readable
sizes, deterministic UTC timestamps, directory totals, and symlink arrows.
`stat` exposes stable POSIX-shaped fields, while `find` filters by file,
directory, or symlink type, user/group name or ID, and exact/all/any permission
bits.

The virtual-only resolver expands relative and absolute symlink targets one
component at a time, follows intermediate links, detects dangling targets and
cycles, and stops after 16 hops. `ls -l`, default `stat`, `file`, and default
`find` preserve the final link. `stat -L`, content readers, recursive `grep`,
and `cd` follow it. Resolution never consults a host path, and permission-aware
profiles check traversal rights across both the link path and expanded target.

One permission evaluator applies the virtual user's UID and all supplementary
GIDs with owner/group/other precedence. It distinguishes file access,
directory listing, and directory traversal, including execute/search checks on
parent directories. `find -readable/-writable` always uses these semantics.
The strict `enforce_permissions` profile setting additionally gates filesystem
commands; it defaults to false. The integrated schema-v2 fixture enables it
with explicit `lab`, `adm`, and `ledger` membership.

See [METADATA_REFERENCE_AND_DESIGN.md](METADATA_REFERENCE_AND_DESIGN.md) for
the engineering decisions and Ubuntu reference harness. The exact semantic
catalog wire contract is in
[SEMANTIC_PROFILE_SCHEMA.md](SEMANTIC_PROFILE_SCHEMA.md). Semantic catalogs
compile eagerly into immutable, fingerprinted graphs in every arm. The
`dynamic` setting controls only whether compiled nodes are visible. Profiles
without a semantic catalog retain the legacy generator.

`config/exp_2b_engine_fixture.json` is a believable but wholly synthetic
`ledger-api` engineering fixture. It exercises three semantic roles under
release, log, and backup roots. It remains marked `fixture`, produces
`experimental_result: false`, and is not evidence of an agent-retention effect.

`config/exp_2b_path_story_v1.json` is the successor story and presentation
fixture. It adds a virtual Ubuntu directory skeleton, matching `/etc/passwd`
and `/etc/group`, a restricted `/root`, and connected release, backup, log,
configuration, and operator-note records. The `host-v1` presentation returns
the virtual `lab` and `ledger-prod-01` identity in the decoy response; the
adapter renders `lab@ledger-prod-01:<cwd>$` and the connection banner uses the
same hostname. It uses separate server, adapter, entrypoint, image definitions,
and a Compose overlay so the frozen v3 source and Compose hashes still verify.
Select the successor with:

```sh
docker compose --profile agent \
  -f compose_2b.yaml -f compose_2b_path_story.yaml config --quiet
```

The successor fixture now uses semantic profile version 2 and the separate
`path_story_fs.py` engine. The catalog validates role transitions, weighted
name and content families, ownership, timestamps, bounds, and references to
authored paths. Each dynamic directory derives its children from its
normalized path, the seed, the catalog fingerprint, and `path-hash-v1`. A
direct lookup, repeated `ls`, and discovery through `find` therefore resolve
to the same nodes regardless of visit order. B0/B2 expose the authored tree;
B1/B3 also expose these path-derived branches. An authored release-archive
symlink can reach the same generated paths. Recursive search has a 512-node
per-command work bound and marks partial output; rendered content, path length,
cached nodes, and responses have separate limits. A per-profile continuation
floor preserves a wide search horizon across seeds; optional terminal
branches still end earlier. The successor session resolves `..` after
intermediate symlinks component by component.

This is still an engineering fixture. Thirty model-free seeds produced
1,149–2,396 generated nodes with natural dead ends, but no agent behavior has
been measured against this successor. The Ubuntu skeleton still lacks binary
and device contents and full shell behavior. The old fixture, controlled-v3
cohort, and PentestGPT task remain unchanged.

The successor server now records [path-story materialization evidence](PATH_STORY_EVIDENCE.md)
after each successful response write. The separate
`experiment_controller.path_story_evidence_2b` helper archives the exact
fixture, private seed, task, source, response journal, and ordered node
inventory. `telemetry.replay_2b_path_story` reconstructs response bytes and
node fingerprints from a fresh session; it also checks a specified common
prefix across a static/dynamic pair. The next gate is a model-free Docker
B0–B3 matrix through the attacker-image tool seam.

`server.py` offers one per-trial `/connect` and `/exec` session over the private
Compose network. Its response journal records exact response bytes and hashes,
the virtual command, path transition, and whether reinforcement was delivered.
It also emits one startup record containing the catalog, compiled-graph, and
shared-node fingerprints. The controller archives an independently compiled
static/dynamic parity record, and replay verifies that record against the
runtime event and arm visibility.
The lab-only PentestGPT entrypoint exposes `ssh_connect` and `ssh_exec` through
UnifiedAgent's MCP tool seam. Both agent roles share the decoy's session. The
connection is imitated; there is no SSH daemon or host shell behind it.

The model-free fixture check builds both 2B images and exercises the actual
tool client from the attacker image. From `shape-lab/`:

```sh
python3 -m unittest discover -s tests -v
docker compose --profile agent -f compose_2b.yaml config --quiet
python3 -m experiment_controller.run_2b --mode deterministic --arm B0
python3 -m experiment_controller.run_2b --mode deterministic --arm B1 --no-build
python3 -m experiment_controller.run_2b --mode deterministic --arm B2 --no-build
python3 -m experiment_controller.run_2b --mode deterministic --arm B3 --no-build
```

The bounded `--mode connectivity` path is an engineering-only B0 check. The
experimental pilot has a separate frozen controller so an ad-hoc CLI run
cannot enter its cohort. Its task is the existing
`config/agent_2b_task.json`; the pilot contract pins the file by hash and does
not rewrite it. The agent never receives its arm.

The pilot infrastructure is defined by
[`../2B_TRIAL_CONTRACT.md`](../2B_TRIAL_CONTRACT.md) and
`config/exp_2b_pilot.json`. `prepare` freezes image/source fingerprints and an
eight-slot balanced schedule but makes no model call. `execute` does make real
model calls. Pilot v1 is preserved as diagnostic evidence after it exposed a
reproducible turn-cap classification problem. Pilot v2 records a durable
PentestGPT `max_turns` terminal state as the valid, right-censored
`agent_turn_cap` outcome and does not modify the task:

```sh
python3 -m experiment_controller.pilot_2b prepare
python3 -m experiment_controller.pilot_2b execute --pilot-id <id> --max-new-runs 1
python3 -m experiment_controller.pilot_2b status --pilot-id <id>
python3 -m telemetry.annotate_2b runs/<run-id> --output <review-packet.json>
python3 -m experiment_controller.pilot_2b gate --pilot-id <id> --write
```

The generated annotation template is intentionally incomplete until a blinded
reviewer supplies identity, time, judgments, and required evidence references.
Pilot runs test readiness only and are excluded from a later effect estimate.
See [../2B_IMPLEMENTATION_STATUS.md](../2B_IMPLEMENTATION_STATUS.md) for the
current handoff and verification evidence. Archived fixture checks can be
verified with `python3 -m telemetry.replay_2b runs/<run-id>`.
