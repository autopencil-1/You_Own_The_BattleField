# SHAPE Lab

This lab runs a synthetic web decoy, a pinned PentestGPT agent, and a bounded Z.AI model gateway. The trial inputs and caps are frozen in [2A_TRIAL_CONTRACT.md](2A_TRIAL_CONTRACT.md) and [config/exp_2a_pilot.json](config/exp_2a_pilot.json). The route and scoring design is in [WEB_DECOY_2A_PLAN.md](WEB_DECOY_2A_PLAN.md). The proposed three-arm study is in [CONTROLLED_2A_ESTIMATION_PLAN.md](CONTROLLED_2A_ESTIMATION_PLAN.md).

The story-independent 2B virtual filesystem, imitated SSH tools, and model-free
fixture checks are documented in [filesystem_decoy_2b/README.md](filesystem_decoy_2b/README.md).
The proposed 2A/2B monitoring and experiment launch console is specified in
[SHAPE_EXPERIMENT_UI_PLAN.md](SHAPE_EXPERIMENT_UI_PLAN.md); the detailed 2B
monitor pane is in [2B_MONITOR_UI_PLAN.md](2B_MONITOR_UI_PLAN.md).
The first local UI slice and its startup instructions are in
[dashboard/README.md](dashboard/README.md).

## Run a check

From `shape-lab/`:

```sh
python3 -m unittest discover -s tests -v
docker compose --profile agent -f compose.yaml config --quiet
python3 -m experiment_controller.run_2a --mode deterministic
python3 -m experiment_controller.run_2a --mode connectivity
```

`deterministic` checks the decoy without a model call; pass `--arm C0`, `--arm C1`, or `--arm C2` to check each condition. `connectivity` builds the pinned agent and gateway, then stops when it observes both a successful model response and a decoy request, or when a smoke cap is reached. It requires `ZAI_API_KEY` in the repository root `.env`. Use `--no-build` to reuse images already built from the same source. For the C2 engineering pilot, use `--mode pilot --arm C2`. Controlled C0/C1/C2 trials follow a separate protocol after pilot validation.

## Attacker image

`attacker-agent` uses the lab image `shape-2a-attacker:dev`. Its build stage resolves the pinned PentestGPT lockfile; its runtime contains Python, the agent and bundled Claude CLI, `curl`, and `bash`. The runtime excludes Git and uv. It copies only the arm-blind task file, so the arm and activation examples stay outside the attacker image. The controller records the built image ID for every run and checks the network and credential mounts before agent execution.

Build and check the image from `shape-lab/` without a model call:

```sh
docker compose --profile agent -f compose.yaml build attacker-agent
docker run --rm --network none --read-only --user 10001:10001 \
  --tmpfs /tmp:rw,nosuid,size=16m --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount "type=bind,src=$PWD/tests,dst=/smoke,readonly" \
  --entrypoint python shape-2a-attacker:dev /smoke/attacker_image_smoke.py
```

To recompute reported scores from archived decoy events, run `python3 -m telemetry.replay_2a runs/<run-id>` or pass `runs/*` to check every archive. The replay checks event order, response hashes, the stored manifest, and reported score equality without a model call. It marks older 13-field scores as schema-compatible when every stored field matches and the only added field is false condition delivery. `python3 -m unittest tests.test_scoring_matrix_2a -v` checks nonactivation, activation, both canary stages, and tampered archives through the local HTTP decoy.

## Trial isolation and artifacts

The controller creates a fresh Compose project and run ID for each invocation. The agent and decoy share only an internal network; the gateway also joins an egress network and is the only container receiving the real model key. The agent receives a placeholder token and calls the gateway through `ANTHROPIC_BASE_URL`. No service publishes a host port.

Each run saves a private, ignored directory under `runs/<run-id>/`. `manifest.json` records the arm, caps, source commits, image IDs, resolved Compose hash, bundled Claude Code CLI version, and termination reason. `trial-config.json`, `compose.resolved.yaml`, `decoy-events.jsonl`, `gateway-events.jsonl`, `agent-stdout.log`, and `agent/` preserve evidence. `result.json` includes the score. The scorer checks decoy event order and archived response hashes and reports activation and stage hits from decoy observations, not agent claims. The temporary real-key file is deleted after Compose teardown. Do not commit run artifacts or `.env`.
