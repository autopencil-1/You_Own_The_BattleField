# 2B path-specific metadata: reference and design spike

**Status:** Reference spike, typed metadata core, shared command rendering,
central permission evaluation, virtual-only symlink resolution, semantic
profile schema, deterministic compiler, and final schema-v2 fixture integration
complete.  
**Reference target:** Ubuntu 24.04 image
`sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`,
GNU coreutils 9.4, GNU findutils 4.9.0.  
**Experiment boundary:** This document defines engineering behavior. It is not
evidence that a decoy retains an agent.

## Decision

Keep the explicit, in-memory 2B interpreter. Add a small immutable POSIX-shaped
metadata model rather than importing a complete fake filesystem. Use Cowrie's
metadata/content separation as an architecture reference, and use Ubuntu GNU
tool output plus Linux/POSIX documentation as the observable behavior oracle.

This preserves the important 2B boundary: virtual paths are data and must never
be passed to `open`, `os.stat`, a host shell, or a mounted host tree.

## Evidence reviewed

- Cowrie's
  [HONEYFS documentation](https://docs.cowrie.org/en/latest/HONEYFS.html)
  separates a metadata tree from file content. Its filesystem source models
  type, UID, GID, size, mode, timestamps, content, and symlink targets. Adopt
  the separation and resolver ideas, not its pickle format, positional lists,
  host-backed content, or mutable session implementation.
- Linux [inode(7)](https://man7.org/linux/man-pages/man7/inode.7.html) and
  [stat(2)](https://man7.org/linux/man-pages/man2/stat.2.html) define the core
  metadata and the distinction between `stat` and `lstat` behavior.
- GNU Coreutils documents
  [`stat`](https://www.gnu.org/software/coreutils/manual/html_node/stat-invocation.html),
  [long `ls` output](https://www.gnu.org/software/coreutils/manual/coreutils.html),
  and [file timestamps](https://www.gnu.org/software/coreutils/manual/html_node/File-timestamps.html).
  GNU Findutils documents the exact, all-bits, and any-bit forms of
  [`find -perm`](https://www.gnu.org/software/findutils/manual/html_node/find_html/Mode-Bits.html).
- Linux [symlink(7)](https://man7.org/linux/man-pages/man7/symlink.7.html)
  defines dangling links, link-following distinctions, and loop behavior.
- Python's [`stat` module](https://docs.python.org/3/library/stat.html) can
  interpret and render mode bits without accessing a real path.
- pyfakefs is a useful semantic cross-check, but its broad mutable filesystem
  and Python filesystem-patching behavior are unnecessary for this restricted
  interpreter. PyFilesystem's general namespaced metadata API is also broader
  than this experiment needs.

## Local command inventory

The ignored historical 2B engineering archives were inspected only for
`filesystem_interaction` command/action fields. They contain model-free checks
and connectivity work, not an experimental sample. Counts at the time of this
spike were:

| Action | Recorded interactions |
|---|---:|
| `ls` | 67 |
| `pwd` | 44 |
| `cat` | 43 |
| `uname` | 25 |
| rejected syntax | 24 |
| `cd` | 21 |
| `file` | 17 |
| `id` | 11 |
| `whoami` | 9 |
| `mount` | 8 |
| `grep` | 8 |
| `find` | 8 |

Observed metadata-relevant forms include `ls -la /home/lab`,
`find . -maxdepth 1 -type d`, `file /home/lab/README.txt`, and identity probes.
The current unit suite also depends on `ls -ldh`, `stat`, `find -user`,
`find -group`, `find -perm`, `-readable`, and `-writable`. Therefore the first
implementation slice must make `ls`, `stat`, and `find` consume one canonical
metadata object. `file`, permission enforcement, and symlink-aware `cat`/`cd`
follow from the same object.

Several agents attempted compound strings such as `id; uname -a; ...`. Those
remain intentionally rejected. They do not justify invoking a real shell or
adding shell composition to the restricted interface.

## Reproducible Ubuntu reference

[`reference/generate_ubuntu_24_04_reference.sh`](reference/generate_ubuntu_24_04_reference.sh)
creates a synthetic tree in a network-disabled, read-only container with a
bounded tmpfs at `/reference`. It does not mount the repository or any host
path. The tree covers:

- named and unknown numeric owners/groups;
- regular files and directories with `0440`, `0640`, `0644`, `0711`, `0744`,
  `0750`, `0755`, `1777`, and `2750` modes;
- fixed access and modification timestamps;
- hard-link inode/link-count relationships;
- valid, dangling, and cyclic symbolic links;
- exact, all-bits, and any-bit `find -perm` behavior;
- the difference between directory read/list and execute/traverse permission;
- long `ls`, stable `stat` fields, and normalized default `stat` layout.

The checked-in snapshot excludes or labels values that an overlay/tmpfs cannot
stabilize: device number, inode number, ctime, and birth time. Their semantics
remain part of the design, but exact runtime values are not golden data.

Run the reference or compare it to the snapshot from the repository root:

```sh
shape-lab/filesystem_decoy_2b/reference/generate_ubuntu_24_04_reference.sh
shape-lab/filesystem_decoy_2b/reference/generate_ubuntu_24_04_reference.sh --check
```

## Frozen schema decisions for Phase 2

### Canonical objects

Use immutable typed objects:

```python
class NodeKind(Enum):
    DIRECTORY = "directory"
    FILE = "file"
    SYMLINK = "symlink"

@dataclass(frozen=True)
class NodeMetadata:
    kind: NodeKind
    uid: int
    gid: int
    mode: int
    inode: int
    device: int
    nlink: int
    size: int
    blocks: int
    block_size: int
    atime_ns: int
    mtime_ns: int
    ctime_ns: int
    birthtime_ns: int | None
    symlink_target: str | None
```

`mode` stores permission and special bits. `kind` is separate in configuration;
the implementation computes a full `st_mode` when it calls `stat.filemode()`.
Configuration modes are four-digit octal strings such as `"0640"`, never JSON
numbers.

An account registry maps user/group names to numeric IDs. Nodes store UID/GID;
renderers resolve names and fall back to the numeric value when no mapping
exists. Do not independently store a node's numeric and textual ownership.

### Rule precedence

Metadata resolution is deterministic:

1. node-kind defaults;
2. the longest matching normalized subtree profile;
3. an exact-path override;
4. derived immutable fields such as inode, blocks, link count, and content
   size.

Initial subtree rules use normalized roots, not arbitrary globs. Conflicting
rules at equal specificity are invalid. Every resolved value and the metadata
profile version contribute to the trial/profile fingerprint.

### Derived and frozen fields

- Regular-file size is the UTF-8 content byte length.
- Symlink size is the target pathname byte length.
- Directory apparent size defaults to 4096 for the Ubuntu-like presentation;
  it is an emulation policy, not a portable Linux guarantee.
- Device is a fixed per-profile virtual device ID.
- Inode is a stable positive integer derived from SHA-256 of profile version,
  seed, normalized path, and kind, with collision detection.
- Regular files and symlinks initially have link count 1. Directory link count
  is 2 plus the number of direct subdirectories. Hard links remain deferred.
- Story timestamps are UTC instants normalized to integer nanoseconds.
- Reads do not mutate atime. This is an explicit replay-preserving virtual
  `noatime` policy.

### Symlink boundary

Base metadata is separate from symlink resolution. The component-wise resolver
supports relative and absolute *virtual* targets, dangling links, cycle
detection, a 16-hop limit, and typed failures. It never consults the container
filesystem. Intermediate links are always followed; the final-link policy is:

- `ls -l` and default `stat` describe the link itself;
- `stat -L`, `cat`, `head`, `tail`, `wc`, `grep`, and `cd` follow it;
- `find` defaults to no-follow behavior;
- a target can never escape the normalized virtual namespace.

When permission enforcement is enabled, every directory component encountered
before and after a link expansion must grant virtual traversal permission.

### Permission boundary

One evaluator handles owner/group/other bits, supplementary groups, ancestor
search permission, file reads/writes, directory listing, and directory
traversal. `find -readable/-writable` always uses the evaluator. Command
enforcement is controlled by the strict `enforce_permissions` boolean, which
defaults to false for compatibility and must use the same value in every
experimental arm. The final schema-v2 fixture enables it with the `lab` user in
the `adm` and `ledger` supplementary groups so its authored and generated
operational paths remain intentionally readable and traversable.

## Typed metadata core (Slice 2)

Implemented on 2026-11-04:

- immutable `NodeKind`, `NodeMetadata`, `VirtualNode`, account/group, defaults,
  override, and node-definition types;
- a strict schema-v2 loader with exact-node metadata, four-digit octal modes,
  nanosecond UTC timestamps, registered defaults, numeric orphan ownership,
  safe symlink targets, and explicit-parent validation;
- a schema-v1 compatibility adapter retained in dedicated unit fixtures;
- stable seeded inode derivation with collision detection, computed byte sizes,
  block counts, directory link counts, ownership lookup, and frozen timestamps;
- one canonical node lookup behind the existing `metadata()`, `owner()`, and
  `permissions()` compatibility helpers.

The integrated engine fixture now uses schema v2. Dedicated unit fixtures keep
the schema-v1 adapter exercised independently of the production-like story.

## Shared metadata renderers (Slice 3)

Implemented on 2026-11-04:

- one cached `VirtualNode` instance per normalized path, shared by `ls`,
  `stat`, `file`, and `find`;
- deterministic UTC long-ISO timestamps, stable inode/device/link/block
  fields, named or numeric ownership, human-readable sizes, directory totals,
  and symlink arrows in long `ls` output;
- GNU-shaped default `stat` output with type, mode, UID/GID, size, blocks,
  inode, links, and nanosecond access/change/modify/birth timestamps;
- metadata-native `find -type f|d|l`, `-user`, `-group`, and exact/all/any-bit
  `-perm` matching, including numeric orphan UID/GID lookup;
- a stable no-follow representation for symlinks in long `ls`, default `stat`,
  `file`, and default `find`.

The renderer deliberately uses a fixed long-ISO UTC format rather than GNU
`ls`'s clock-relative recent/old timestamp selection. This keeps archived
responses byte-stable while preserving the fields relevant to the experiment.

## Central permission evaluator (Slice 4)

Implemented on 2026-11-04:

- typed permission operations and one immutable identity containing the
  effective UID plus every primary/supplementary GID;
- POSIX owner-before-group-before-other class selection, with bounded root
  behavior and separate file read/write/execute, directory list, and directory
  traversal checks;
- ancestor execute/search evaluation for path access, plus a permission-aware
  bounded walker that reports inaccessible directory boundaries;
- shared evaluation for `find -readable/-writable` and opt-in enforcement in
  `cd`, `ls`, `cat`, `head`, `tail`, `stat`, `file`, recursive `find`/`grep`,
  and `wc`;
- reference-shaped tests for owner access, supplementary-group access,
  unrelated-owner denial, `0744` list-only directories, and `0711`
  traverse-only directories;
- strict validation of `enforce_permissions`, defaulting to false so existing
  schema-v1 fixtures and all current B0-B3 arms retain their prior output.

Plain `ls` may enumerate a list-only directory, while long `ls` refuses to
invent child metadata without traversal permission. Conversely, a known child
under a traverse-only directory can be read even though the directory cannot
be enumerated.

## Virtual-only symlink resolver (Slice 5)

Implemented on 2026-11-05:

- component-wise expansion of relative and absolute virtual targets, including
  `.` and `..`, without opening or inspecting a host path;
- explicit `PathResolution` results for missing targets, non-directory
  components, permission denial, cycles, and hop-limit exhaustion;
- intermediate-link following with command-specific final-link behavior:
  metadata inspection preserves the final link, while content/navigation
  commands and `stat -L` follow it;
- permission checks at each traversed component, preventing a link in an
  accessible directory from bypassing a restricted target directory;
- bounded handling of valid, dangling, cyclic, over-limit, relative, absolute,
  upward-relative, directory, and intermediate links;
- shared resolver integration across `cd`, `ls`, `cat`, `head`, `tail`, `stat`,
  `file`, `find`, `grep`, and `wc`.

Plain `ls` preserves dangling and file links, but follows a command-line link
to a directory when listing its contents. Long `ls` and `ls -d` preserve the
link itself.

## Semantic profile schema (Slice 6)

Implemented on 2026-11-05:

- optional schema-v2 `semantic_profiles` catalogs with a version, bounded story
  context, reusable content families, reusable root profiles, and exact
  expandable-root bindings;
- controlled roles, content formats, safe name/content template tokens,
  weighted file families, profile-local metadata/timestamp policy, bounded
  expansion geometry, and declared symlink relationships;
- immutable typed catalog objects and canonical SHA-256 fingerprints that are
  insensitive to JSON object key order;
- graph validation requiring every root and profile to be bound, every content
  family to be referenced, and every link target profile to exist;
- collision rejection for reused directory/file/link templates and strict
  startup failure for unknown fields, tokens, references, accounts, modes, or
  reversed timestamp windows;
- an explicit compatibility boundary: configurations without semantic catalogs
  continue using the legacy generator.

The complete wire contract and limits are documented in
[`SEMANTIC_PROFILE_SCHEMA.md`](SEMANTIC_PROFILE_SCHEMA.md).

## Deterministic semantic compiler (Slice 7)

Implemented on 2026-11-05:

- eager immutable graph compilation for every semantic configuration,
  independent of whether dynamic nodes are visible;
- one coherent record per node driving UTC date/timestamp, root-scoped
  sequence, hash, name, content, ownership, mode, and story timestamp;
- sorted map traversal, weighted file-family choice, canonical compiled-graph
  SHA-256 fingerprints, and identical graphs for static/dynamic instances with
  the same catalog and seed;
- explicit `file`/`directory` link target kinds, valid-target selection only
  after ordinary nodes exist, bounded relative/absolute targets, and declared
  deterministic dangling links;
- a 16-attempt whole-record collision policy and fail-closed enforcement of
  content, path, per-root node, and global graph bounds;
- a visibility-only structure treatment: `dynamic=False` hides the compiled
  graph, while `dynamic=True` exposes it beneath bound roots; explicit nodes
  are identical in both.

Schema-v1 and schema-v2 configurations without `semantic_profiles` keep the
legacy word-list/README generator for compatibility tests.

## Final schema-v2 fixture integration (Slice 8)

Implemented on 2026-11-05:

- one coherent synthetic `ledger-prod-01` story with authored configuration,
  release, log, backup, operator-home, ownership, permissions, timestamp, and
  symlink metadata;
- separate `deployment`, `service_log`, and `backup_archive` semantic profiles
  bound to three non-overlapping expandable roots;
- controller-side compilation of both visibility states with fail-closed graph,
  shared-node, and visibility parity checks before a container starts;
- exact `VirtualNode` equality for every authored path across visibility states;
  authored directory link counts use authored child directories only, so
  treatment visibility cannot leak through otherwise-shared `stat` metadata;
- an archived `filesystem-profile.json`, matching manifest record, and one
  runtime `filesystem_profile_loaded` event from the instantiated decoy;
- replay validation of all three fingerprints and the expected 0/compiled-node
  visibility split for B0/B2 versus B1/B3;
- story-aware Docker smoke and attacker-image tool probes, while preserving the
  fixture-only and `experimental_result: false` boundary.

No metadata implementation slices remain. Experimental pilot/scoring decisions
are tracked separately from this infrastructure acceptance gate.

Hard links, device nodes, FIFOs, sockets, ACLs, extended attributes, and Linux
capabilities are outside the first implementation. They should not receive
partial observable behavior merely because the schema could represent them.

## Phase 2 acceptance gate

- No virtual operation calls a host-path API or command executor.
- Invalid profiles fail before the service starts.
- Same profile and seed produce byte-identical command results and telemetry.
- `ls`, `stat`, `find`, and `file` agree on type, ownership, mode, size, and
  timestamps.
- Permission decisions are identical across B0-B3 and never consult host
  credentials or host paths.
- Shared starting nodes have identical metadata in B0-B3; only assigned
  dynamic/reinforcement factors differ.
- Symlink loops and traversal are bounded and cannot leave virtual state.
- Existing unit, Docker B0-B3, and replay checks remain green.
