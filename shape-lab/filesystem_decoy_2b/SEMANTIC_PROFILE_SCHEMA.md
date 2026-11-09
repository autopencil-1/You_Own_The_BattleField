# 2B semantic profile schema

**Schema version:** `semantic_profiles.version = 1`  
**Implementation status:** Strict parsing, typed representation, graph
validation, deterministic compilation, graph fingerprinting, and dynamic
visibility gating are implemented. The final schema-v2 engineering fixture,
manifest evidence, runtime attestation, and replay validation are integrated.

The optional `semantic_profiles` block belongs to a filesystem schema-v2
document. When present, it replaces generic word-list generation. Schema-v1
and schema-v2 documents without a catalog retain the existing
`directory_words`, `generated_file_name`, and `generated_file_text`
compatibility path.

## Shape

```json
{
  "semantic_profiles": {
    "version": 1,
    "context": {
      "environment": "production",
      "organization": "northstar",
      "service": "ledger-api"
    },
    "content_families": {
      "record_manifest": {
        "format": "json",
        "templates": [
          "{\"service\":\"{{service}}\",\"path\":\"{{path}}\"}\n"
        ]
      }
    },
    "profiles": {
      "records": {
        "role": "application_data",
        "directory_names": [
          "batch-{{date}}-{{sequence}}",
          "archive-{{hash}}"
        ],
        "file_families": {
          "manifest": {
            "names": ["manifest.json", "job-{{sequence}}.json"],
            "content_family": "record_manifest",
            "weight": 3
          }
        },
        "metadata": {
          "directory": {"user": "lab", "group": "lab", "mode": "0750"},
          "file": {"user": "lab", "group": "lab", "mode": "0640"},
          "symlink": {"user": "lab", "group": "lab", "mode": "0777"},
          "timestamp_start": "2025-01-01T00:00:00Z",
          "timestamp_end": "2025-03-31T23:59:59.999999999Z"
        },
        "bounds": {
          "max_depth": 2,
          "min_directories": 1,
          "max_directories": 2,
          "min_files": 1,
          "max_files": 2,
          "max_nodes": 64
        },
        "links": {
          "names": ["latest"],
          "target_profiles": ["records"],
          "target_kinds": ["directory", "file"],
          "max_per_directory": 1,
          "allow_relative": true,
          "allow_absolute": false,
          "allow_dangling": false
        }
      }
    },
    "bindings": {
      "/var/records": "records"
    }
  }
}
```

## Catalog rules

- `version` is exactly `1`.
- `context` has at most 16 lowercase identifiers. Values are bounded safe
  fragments containing letters, digits, `.`, `_`, or `-`. Built-in template
  token names are reserved.
- `content_families` contains 1–32 entries. Formats are `config`, `json`,
  `log`, `text`, or `yaml`. Each family contains 1–16 unique, nonempty UTF-8
  templates, each at most 4096 bytes.
- `profiles` contains 1–16 entries. Every profile must be bound to at least one
  expandable root, and every expandable root must have exactly one binding.
- Every content family must be referenced. File, directory, and link name
  templates cannot be reused within a profile.
- Unknown fields, identifiers, accounts, groups, references, roles, formats,
  tokens, and non-string octal modes fail before the service starts.

## Profile rules

Supported roles are:

- `application_data`
- `backup_archive`
- `deployment`
- `service_config`
- `service_log`
- `user_workspace`

`directory_names` contains 1–32 safe path-component templates.
`file_families` contains 1–16 weighted families; each has 1–16 safe name
templates, a valid content-family reference, and a weight from 1–100.

Metadata users and groups must exist in the schema-v2 account registry. Modes
are four-digit octal strings. Symlink mode is `0777`. Timestamp bounds are UTC
RFC 3339 instants and must be ordered.

Expansion bounds are deliberately below the virtual-shell global limits:

- `max_depth`: 1–8
- directory fanout: 0–15, with minimum no greater than maximum
- file fanout: 0–16, with minimum no greater than maximum
- `max_nodes`: 1–512

The optional `links` policy declares names, allowed destination profiles,
allowed target kinds (`directory` and/or `file`), relative/absolute target
forms, explicit dangling-link permission, and a maximum of 0–8 links per
directory. Symlinks cannot be selected as generated link targets. A disabled
policy must be entirely empty.

## Template tokens

Name templates may use catalog context keys plus:

- `{{date}}`
- `{{hash}}`
- `{{hostname}}`
- `{{sequence}}`
- `{{username}}`

Content templates may additionally use `{{name}}`, `{{path}}`, and
`{{timestamp}}`.

Compiler token forms are frozen:

- `date`: UTC `YYYYMMDD`
- `sequence`: four decimal digits, scoped monotonically to a bound root
- `hash`: eight lowercase hexadecimal characters
- `timestamp`: UTC RFC 3339 with nine fractional digits and `Z`
- `path` and `name`: the final compiled virtual path and basename

One deterministic node record supplies every token, timestamp, metadata field,
name, and content choice for that node. A compiler retry replaces the entire
record rather than mixing values from separate hashes.

## Compilation and visibility

The compiler processes roots, profile maps, and candidate targets in sorted
order. Object key order therefore cannot affect the graph. Configured template
list order and weights remain meaningful.

For each bound root it deterministically selects bounded directory and file
counts, renders safe names of at most 64 characters, and materializes immutable
`NodeDefinition` objects. Link generation runs only after ordinary nodes exist.
An enabled link policy creates 1–`max_per_directory` links for each compiled
directory. When dangling links are permitted, a deterministic one-in-four
selection produces an explicit nonexistent target; otherwise the target must
be a compiled or explicit file/directory in an allowed target profile.

Name collisions retry at most 16 complete node records. Exhausting retries,
rendering content over 4096 bytes, exceeding a root's `max_nodes`, or exceeding
the 512-node global graph bound fails construction. The compiler never silently
truncates a graph.

Every `VirtualFilesystem` compiles the graph, regardless of arm. The same
catalog and seed therefore give static and dynamic instances the same compiled
graph fingerprint. `dynamic=False` hides compiled nodes; `dynamic=True`
exposes them. Explicit starting nodes remain visible and identical in both.

## Fingerprint and experiment boundary

The parser canonicalizes the complete `semantic_profiles` object using sorted
JSON keys and hashes it with SHA-256. Object key order therefore does not alter
the fingerprint, while any semantic value or list-order change does.

The compiled-graph fingerprint covers the catalog fingerprint, a digest of the
trial seed, every generated path, content or target, profile assignment, and
metadata value. Shared explicit nodes remain identical in B0–B3; only arms
assigned dynamic structure expose compiled nodes beneath bound expandable
roots.

The final fixture also records a seed-specific shared-node fingerprint over
every authored path, content or target, resolved owner/mode/timestamps, inode,
size, allocation, and explicit-tree link count. Its controller compiles both
visibility states before launch and fails unless catalog, compiled graph, and
shared-node fingerprints match, static visibility is zero, and dynamic
visibility is complete. The decoy emits the same fingerprints in one startup
event. Each archive stores the parity contract in `filesystem-profile.json`
and its manifest; replay verifies the artifact hash, manifest copy, startup
event, and arm-specific visible-node count.
