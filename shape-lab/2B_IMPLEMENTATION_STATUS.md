# SHAPE 2B implementation status

**Updated:** 2026-10-26. **Stage:** story-independent engineering setup. No 2B
agent pilot or controlled study has run, so there is no retention finding.

## Implemented

- A virtual filesystem that interprets `pwd`, `ls`, `cd`, `cat`, `head`, `stat`,
  and `file` without invoking a host shell or reading host paths. It keeps
  session cwd, normalizes aliases, and renders dynamic paths reproducibly from
  SHA-256 of a seed and path. Depth, branching, command, file, and output sizes
  are bounded.
- A per-trial decoy service with an imitated SSH connection gate, independently
  switchable dynamic structure and reinforcement, and sequenced JSONL events.
  Archived responses include exact bytes and hashes.
- A lab-only PentestGPT entrypoint that exposes `ssh_connect` and `ssh_exec`
  through the pinned UnifiedAgent MCP tool seam. The PentestGPT source checkout
  remains unchanged. Both roles use one decoy-side session.
- Separate 2B Docker images and Compose topology. The attacker and decoy join
  an internal network; only the model gateway joins the egress network. No
  service publishes a host port. The real provider key is gateway-only.
- A model-free controller that creates a fresh Compose project, checks network
  placement and direct egress, exercises all four arm switches and the actual
  attacker-image tool client, archives events and image/config hashes, and
  tears down containers. A bounded real-agent connectivity mode is implemented
  but has not been invoked.
- A model-free replay checker for event sequence, response hashes, connection
  chronology, command/result consistency, and reinforcement attribution.

## Verification

- `python3 -m unittest discover -s tests -v`: 24 tests passed.
- `docker compose --profile agent -f compose_2b.yaml config --quiet`: passed.
- `shape-2b-attacker:dev` built and passed its offline image/tool smoke with
  networking disabled.
- Model-free Docker fixture checks passed for B0, B1, B2, and B3. Each check
  exercised the actual `ssh_connect`/`ssh_exec` client inside the attacker
  image and verified no direct external egress.
- The fixture archives replay. One early B2 check failed because its smoke
  script looked for reinforcement on the fourth qualifying command instead of
  the configured third; the failed archive remains in ignored `runs/`, and the
  corrected B2 check passed.

## Boundary before experimental runs

`config/exp_2b_engine_fixture.json` contains generic test content only. It is
not a believable trap and its runs have `experimental_result: false`. The
Compose file explicitly marks the profile as `fixture`; the agent entrypoint
refuses model use on that profile unless the controller opts into a bounded
connectivity check. No inference has been spent on 2B.

The synthetic host story, final files/clues, static-tree comparability,
reinforcement wording and schedule, and suspicion/abandonment rubric remain to
be decided and frozen. After that: build and fingerprint final images; run one
actual agent connectivity check; pilot the final configuration; then prepare
the randomized 10-runs-per-arm, 10-minute-or-50-action study already agreed
with the user. The 2A model-call and token caps remain additional upper bounds.

The agent still has its provider's ordinary local Bash tool inside the
isolated attacker container. Only decoy-side `ssh_exec` events count as remote
filesystem exploration; local Bash actions need separate accounting.
