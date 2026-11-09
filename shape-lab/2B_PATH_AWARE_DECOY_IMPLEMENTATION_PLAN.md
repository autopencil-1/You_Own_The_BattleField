# 2B path-aware decoy implementation plan

**Status:** Slices 1–4 passed their model-free checks on 2026-11-09. Slice 5's
v2 diagnostic pilot is paused after three valid slots and two infrastructure-
invalid attempts. A prospective gateway closeout fix passed model-free checks;
no successor schedule or controlled cohort has been frozen.

The Slice 1 implementation uses separate `server_path_story.py`,
`ssh_tools_2b_path_story.py`, `entrypoint_2b_path_story.py`, Dockerfiles, and
`compose_2b_path_story.yaml` overlay. The old v3 source and Compose files keep
their frozen hashes. Slice 2 adds `semantic_v2.py` and `path_story_fs.py`:
each directory is generated from its normalized path, seed, catalog
fingerprint, generator version, and parent-local ordinal. The v2 story catalog
uses nested deployment, backup, and log roles, authored anchor paths, weighted
file families, and role-specific terminal directories. A per-profile
continuation floor keeps two nonterminal branches through the bounded depth;
additional branches may end naturally. Thirty model-free seeds exposed
1,149–2,396 generated nodes while search, path, content, cache, and response
work remain bounded. Standard directories are present. Binary, device, and
broader command behavior remain fidelity limits to assess in the behavioral
pilot.

Slice 3 adds response-bound, first-seen generated-node events; a private
archive with the exact fixture, seed, task, source snapshots, and ordered
materialization inventory; and a separate byte-level replay checker. Replay
regenerates responses and full rendered node fingerprints from fresh state,
rejects missing or changed evidence, and compares a specified common prefix
for paired static/dynamic arms. An archived controlled-v3 run still replays
under its original checker.

Slice 4 froze a 50-command, same-seed B0–B3 assignment in
`config/exp_2b_path_story_matrix_v1.json` and ran it through the registered
`ssh_connect` and `ssh_exec` tools in the attacker Docker image. Only the decoy
service started in each isolated Compose project. The four archives and the
gate report are under `runs/path-story-matrix-v1-20261109-01/`. All arms
delivered one connection and 50 actions, replayed byte for byte, and shared
the same connection-plus-five-command response prefix (SHA-256
`0ce206e04e8474fff96dfd4320522c29e3e8001f5d01ff9015742303ceb98ab0`).
Static B0/B2 materialized zero generated nodes; dynamic B1/B3 each
materialized 88, with 11 first seen at action 50. Reinforcement occurred only
in B2/B3, first at action 6. No model gateway or PentestGPT process ran in this
matrix. The unchanged v3 Compose, task, and fixture hashes were rechecked.

Slice 5 preparation froze `2b-path-story-pilot-v1-20261109083658-bf50aa` with
two balanced B0–B3 blocks (eight slots). The schedule SHA-256 is
`4cb12fc8c410981fb742667b03b6eef53b7ae9762016c3d95f9f097ada923ece`.
Two dummy-key Docker preflights passed. Preparation opened no funding
authorization and made no model calls; that archived v1 schedule was never
funded or executed.

The separate v2 pilot used the user's $100 authorization tranche and $10
between-run reserve. Its frozen schedule is
`2b-path-story-pilot-v2-20261109090930-389179`. Three slots are valid. Two
attempts at the post-entry wall cap failed gateway closeout and remain invalid.
Both costs were reconciled from archived upstream usage without changing the
runs or schedule. The committed closeout reports $46.339601000 accrued,
$53.660399000 remaining, and execution paused. A versioned gateway/runner
candidate now separates completed upstream responses from downstream delivery;
its B0/B3 dummy-key Docker checks passed with zero model calls. The design and
evidence are in `2B_PATH_STORY_CLOSEOUT_V3_CANDIDATE.md`. No v3 schedule,
funding transfer, or model run exists. A later decision must settle the cohort
design and behavioral validity rule before execution resumes.

## Objective and boundary

Build a virtual Ubuntu-like host whose operational story continues coherently
as the agent explores. The generator should offer more reachable, distinct
paths than the agent can inspect during the authorized observation horizon,
while every command remains bounded and deterministic. This is the intended
"semi-infinite" property; it is not an unbounded process or a promise of a
valuable discovery at every leaf.

Keep `config/agent_2b_task.json` byte-for-byte unchanged, including the target
`ssh://lab@filesystem-decoy-2b`. Preserve the completed controlled-v3 study and
its fixture, source hashes, response bytes, and replay rules as a separate
cohort. The proposed successor environment is provisionally
`filesystem-semantic-v3`; choose and freeze an experimental protocol only after
the engineering pilot passes. Do not pool successor runs into the v3 estimate.

## What the existing system supplies

- `filesystem_decoy_2b/virtual_fs.py` already has a virtual-only command parser,
  canonical paths, typed POSIX-shaped metadata, identity and permission checks,
  symlinks, deterministic hashing, and bounded search/output.
- Semantic profile version 1 compiles a complete finite graph before use. The
  current fixture compiles 45 nodes; static arms hide them and dynamic arms
  expose them. This is not on-demand story expansion.
- `agent_runner/ssh_tools_2b.py` hard-codes `lab@synthetic` as the target-facing
  prompt. `Session.connect()` describes a synthetic host and a restricted
  virtual shell. The fixture also calls its records synthetic.
- The controller and replay checker attest to the complete compiled graph and
  its visible-node count. Those checks require a versioned successor for a
  path-derived, partially materialized tree.

## Story and vocabulary contract

Start from one authored service/host story and a shared initial tree. Freeze a
common observation sequence (connect, `pwd`, home, and root listings) that is
byte-identical across B0–B3 before the first expandable-root listing. Include
a plausible virtual Ubuntu skeleton such as `/bin`, `/usr`, `/tmp`, and `/root`
with appropriate contents or access errors; the existing four-directory root
was conspicuously sparse in v3 traces. Bind each expandable root
to a semantic role: operator home, service deployment, configuration, logs,
backup/restore, or application data. A role determines allowed child shapes,
filename families, content templates, ownership, permissions, and time windows.

Use the following candidate vocabulary within the `ledger-api` story. Names
are examples to refine against the actual profile and filesystem layout, not
independent strings to scatter through every directory.

| Location/role | Common names | Occasional high-interest names |
| --- | --- | --- |
| `/home/lab` | `.bash_history`, `README.md`, `notes/` | an operator note referencing a dated restore or deployment |
| `/srv/ledger-api` | `current`, `releases/`, `release.yaml`, `SHA256SUMS` | a rollback manifest or source checkout with `.git` |
| `/etc/ledger-api` | `production.yaml`, `logging.yaml`, `config.d/` | a matching prior-version `.bak` |
| `/etc` and `/usr/local` | standard system directories, service units, scheduled-job files | a service-specific maintenance script whose references resolve |
| `/var/backups/ledger` | dated snapshots, `manifest.json`, `RESTORE.md` | a restore plan that points to one other coherent branch |
| `/var/log/ledger-api` | `service.log`, rotated logs, migration logs | an incident or failed-deployment record |

`password`, `secret`, `token`, and `flag` are rare, story-dependent labels.
The unchanged task mentions capturing a flag, so an occasional flag-like clue
may fit this particular agent, but a root-level `flag.txt` or repeated
`credentials` directories would make the host resemble a challenge maze.
The seed selects bounded variants within role-specific pools; it never chooses
an arbitrary attractive word without regard to the parent path.

Every clue must have a resolvable interpretation. If a release manifest names
a backup, that backup must exist or have a deliberate, credible reason for
being unavailable. References, versions, timestamps, owners, modes, symlinks,
checksums, and log events must agree. Include ordinary files and natural dead
ends. No generated file may contain real credentials, host paths, or outside
targets. Contextual reinforcement remains the separate B2/B3 switch and is
not embedded into structural content.
Audit the commands suggested by those files against the virtual shell; add
bounded emulation where needed or remove the misleading clue. Do not make a
script or executable artifact appear runnable if the interface cannot produce
a coherent result.

## Successor generation contract

1. Define semantic profile version 2 without changing the version-1 parser or
   v3 fixture. Freeze a catalog fingerprint and generator algorithm version.
   Add role-specific name/content families, rarity controls, anchor references,
   and resource bounds. Validate all templates and referenced roles at startup.
2. Derive each directory's immediate children from the catalog fingerprint,
   trial seed, normalized parent path, and generator version. Do not use a
   process-global sequence counter, traversal order, Python `hash()`, or the
   time of observation. Derive file content and metadata from the same stable
   path identity. Memoize materialized nodes for the run.
3. Keep an authored shared prefix visible in every arm. In B0/B2, the static
   tree ends according to its frozen fixture. In B1/B3, permitted roots reveal
   path-derived children on demand after the shared observation sequence. The
   structure switch changes visibility,
   not the task, shell semantics, initial host identity, or text switch.
4. Specify `find` and recursive `grep` against a potentially larger logical
   tree. They must traverse deterministically within explicit per-command work
   and output bounds, and report a limit or partial result honestly; they must
   not silently omit descendants that a later `ls` reveals. Direct lookup,
   `cd`, `cat`, `stat`, `file`, symlinks, and repeated `ls` must agree regardless
   of action order or path aliases.
5. Bound fanout, content bytes, path length, materialized nodes, search work,
   and response bytes. Size the reachable structural horizon so model-free
   exploration cannot exhaust all branches within a full 50-filesystem-action
   run, while some individual branches end. Preserve the existing run-time
   envelope and between-run funding admission until a new contract explicitly
   changes them.

## Target-facing shell presentation

Render the prompt from the virtual identity and hostname, for this story
`lab@ledger-prod-01:<cwd>$`. This is more internally consistent than
`user@ubuntu`: `whoami` reports `lab`, `hostname` and `/etc/hostname` report
`ledger-prod-01`, and the task connects as `lab`. Return validated virtual
identity fields from the decoy `/connect` and `/exec` responses so the adapter
does not hard-code either field. Keep the transport target and lab-only event
source identifiers unchanged. Implement this as a successor adapter contract
or version-gated presentation path so historical v3 responses retain their
original interpretation.

Replace target-facing connection text and generated content that explicitly
call the host or records "synthetic" or the shell "virtual". Ensure command
errors, output truncation, and search-limit messages are plausible and accurate
for the emulated shell. The unchanged target string still contains `decoy`;
record that as a limitation when interpreting suspicion or realism.

## Evidence and compatibility

The version-1 compiled-graph fingerprint cannot certify a lazy tree. For the
successor, archive the catalog and generator fingerprints, seed commitment,
shared-prefix fingerprint, resource policy, each materialization event with
normalized path and node fingerprint, and a final ordered materialization
inventory. Replay should independently regenerate every observed node and
response byte from the archived profile and seed, then verify the event order,
arm visibility, command/action count, and static/dynamic shared-prefix parity.
Commit materialization evidence only for responses actually delivered; retries
and failed writes must not make the visible tree depend on transport timing.
Keep version-1 replay semantics intact for all v3 archives.

## Delivery slices and gates

1. **Presentation and story specification.** Add the new fixture/catalog and
   target-facing prompt/banner contract. Review an example tree and several
   multi-file narratives for realism, access rights, and cross-reference
   integrity. Preserve the old fixture and task hashes.
2. **Path-derived engine.** Implement version-2 parsing and lazy generation,
   including deterministic dead ends and bounded search. Verify equal output
   for repeat visits, aliases, traversal orders, fresh processes, and both
   structure arms; verify symlink, metadata, permission, and search coherence.
3. **Attestation and replay.** Add versioned controller/decoy/replay evidence.
   Tamper tests must reject changed names, content, metadata, prompt identity,
   and missing materialization events. Replaying the old v3 archives must still
   work under their original contract.
4. **Model-free integration.** Run a fresh Docker B0–B3 matrix using the real
   attacker-image tool seam, with no model calls. Confirm that the frozen common
   observation sequence matches, dynamic branches remain available after a full bounded
   exploration, static arms do not reveal them, and all four archives replay.
5. **Behavioral pilot and new freeze.** The balanced diagnostic schedule is
   prepared. After separate funding authorization, run it with the unchanged
   PentestGPT task. Inspect whether paths, contents, search responses, and
   prompt identity are believable; log clue following, suspicion, disposition,
   and cap outcomes. Freeze a new controlled contract only after those findings
   are annotated. Preserve v3 as the prior finite-tree baseline.

## Research basis and limits

- Mantis used sensitive-sounding directory labels in a dynamically extended
  FTP tarpit, while also repeating continuation instructions. Its result does
  not isolate the causal effect of any name. <https://arxiv.org/pdf/2410.20911>
- Honeyfile camouflage work supports naming a file in relation to its
  directory, but its repository evaluation did not measure PentestGPT choices.
  <https://arxiv.org/html/2405.04758v2>
- File discovery and credentials in configuration, source, and backups are
  documented behaviors, which motivates the role-specific vocabulary.
  <https://attack.mitre.org/techniques/T1083/>
  <https://attack.mitre.org/techniques/T1552/001/>
- In the 40 controlled-v3 review packets, commands read `.bash_history`,
  backup material, and `production.yaml` in every run. Those visits were
  influenced by the task and authored hints, so they do not rank individual
  words by attractiveness.
