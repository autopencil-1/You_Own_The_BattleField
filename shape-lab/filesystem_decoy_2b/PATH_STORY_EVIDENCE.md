# Path-story materialization evidence v1

This is the successor evidence contract for the path-derived 2B fixture. It is
separate from the semantic-v1 compiled-graph evidence used by controlled v3.
The PentestGPT task and historical v3 archives are unchanged.

## Runtime journal

The decoy emits one `path_story_profile_loaded` event before requests. It
records the semantic schema and generator versions, catalog and generator code
fingerprints, a seed commitment, the authored-base fingerprint, virtual host
identity, and resource limits. Each POST records its route and content length;
bounded request bodies are archived as raw bytes.
After a response is written and flushed, `decoy_response` records its exact
body bytes and SHA-256 digest. First-seen generated paths touched while
computing that response then receive ordered `filesystem_materialized` events.
Each event binds a normalized path and a fingerprint of its complete rendered
node (kind, content or link target, and metadata) to the response sequence and
digest. Repeated accesses do not create a second inventory entry.

A failed response write discards staged paths and rolls back the session's
visible command state. A later retry records paths even if computation from
the failed attempt warmed an internal cache. Successful server flush is the
journal's delivery boundary; it cannot prove that a client received every
byte before a network failure.

## Archive and replay

`experiment_controller.path_story_evidence_2b` archives the exact fixture,
private trial seed, unchanged task, source snapshots, decoy event stream,
startup profile, and first-commit materialization inventory. The manifest
hashes each artifact and records the arm, run identity, resource policy, and
catalog/generator commitments. The seed is kept in a private `0600` file; only
its SHA-256 commitment appears in the runtime journal. Replay requires the
matching successor source version in the checkout and verifies it against the
archived source hashes; a future generator revision needs a separate versioned
replay path.

`telemetry.replay_2b_path_story` checks artifact hashes and event chronology,
constructs a fresh filesystem from the archived fixture and seed, and
recomputes response bytes and materialized node fingerprints. Static arms must
have no generated-node events. Pair verification compares B0 with B1 or B2
with B3 for a specified common transcript before expandable-root observation;
the authored-base fingerprint must match. Expansion-root link counts may
legitimately differ once generated directories become visible.

The model-free Docker B0–B3 integration gate passed on 2026-11-09. The frozen
command assignment is `config/exp_2b_path_story_matrix_v1.json`; the four
archived bundles and gate report are in `runs/path-story-matrix-v1-20261109-01/`.
Each arm has 50 actions and 51 replayed responses. The common connection and
five-command prefix is byte-identical across the four arms. Static arms have
no materialization events; dynamic arms each have 88, including 11 linked to
the 50th action. The matrix invoked the registered attacker-image SSH tools
with no model gateway or PentestGPT process. A behavioral pilot requires its
own subsequent contract and run evidence.
