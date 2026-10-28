# 2B Virtual Filesystem Core

This package is the story-independent part of SHAPE 2B. `virtual_fs.py` holds a
synthetic path tree and interprets a restricted command set: `pwd`, `ls`, `cd`,
`cat`, `head`, `stat`, and `file`. A `Session` must connect before commands work;
its current directory persists between calls. No command reaches a host shell,
and no virtual path resolves to a host file.

The engine takes its explicit directories, files, expansion roots, vocabulary,
and generated file text from a data specification. Generated names derive from
SHA-256 of the trial seed and normalized virtual path. `dynamic=False` disables
generated branches without changing the command interface. Depth, branching,
command length, argument count, file content, and response size are bounded.

`config/exp_2b_engine_fixture.json` is **only a test fixture**. It is not the
experimental host story and must not be used as B0–B3 treatment content.

`server.py` offers one per-trial `/connect` and `/exec` session over the private
Compose network. Its response journal records exact response bytes and hashes,
the virtual command, path transition, and whether reinforcement was delivered.
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

The bounded `--mode connectivity` path is implemented but intentionally not
run against the fixture yet. It would use the real model, so its evidence would
establish tool reachability only. The final host story, static and dynamic
profiles, reinforcement wording and timing, scoring rubric, pilot gate, and
randomized analysis remain to be frozen. The agent never receives its arm.
See [../2B_IMPLEMENTATION_STATUS.md](../2B_IMPLEMENTATION_STATUS.md) for the
current handoff and verification evidence. Archived fixture checks can be
verified with `python3 -m telemetry.replay_2b runs/<run-id>`.
