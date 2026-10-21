# SHAPE 2A Web Decoy

This lab runs a synthetic web decoy, a pinned PentestGPT agent, and a bounded Z.AI model gateway. The trial inputs and caps are frozen in [2A_TRIAL_CONTRACT.md](2A_TRIAL_CONTRACT.md) and [config/exp_2a_pilot.json](config/exp_2a_pilot.json). The route and scoring design is in [WEB_DECOY_2A_PLAN.md](WEB_DECOY_2A_PLAN.md).

## Run a check

From `shape-lab/`:

```sh
python3 -m unittest discover -s tests -v
docker compose --profile agent -f compose.yaml config --quiet
python3 -m experiment_controller.run_2a --mode deterministic
python3 -m experiment_controller.run_2a --mode connectivity
```

`deterministic` builds and checks the C2 decoy without a model call. `connectivity` builds the pinned agent and gateway, then stops when it observes both a successful model response and a decoy request, or when a smoke cap is reached. It requires `ZAI_API_KEY` in the repository root `.env`. Use `--no-build` to reuse images already built from the same source. For the C2 engineering pilot, use `--mode pilot --arm C2`. Controlled C0/C1/C2 trials follow a separate protocol after pilot validation.

## Trial isolation and artifacts

The controller creates a fresh Compose project and run ID for each invocation. The agent and decoy share only an internal network; the gateway also joins an egress network and is the only container receiving the real model key. The agent receives a placeholder token and calls the gateway through `ANTHROPIC_BASE_URL`. No service publishes a host port.

Each run saves a private, ignored directory under `runs/<run-id>/`. `manifest.json` records the arm, caps, source commits, image IDs, resolved Compose hash, bundled Claude Code CLI version, and termination reason. `trial-config.json`, `compose.resolved.yaml`, `decoy-events.jsonl`, `gateway-events.jsonl`, `agent-stdout.log`, and `agent/` preserve evidence. `result.json` includes the score. The scorer checks decoy event order and archived response hashes and reports activation and stage hits from decoy observations, not agent claims. The temporary real-key file is deleted after Compose teardown. Do not commit run artifacts or `.env`.
