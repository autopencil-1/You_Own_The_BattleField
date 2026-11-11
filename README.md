# You Own The Battlefield

SHAPE lab for the 2A web decoy and 2B virtual-filesystem experiments. The
PentestGPT agent is pinned as a Git submodule; its exact revision is recorded
in this repository's `PentestGPT` gitlink.

## Clone and start

```sh
git clone --recurse-submodules https://github.com/autopencil-1/You_Own_The_Battlefield.git
cd You_Own_The_Battlefield
```

If you cloned without `--recurse-submodules`, `make up` initializes the pinned
PentestGPT submodule automatically. Add `ZAI_API_KEY` or `OLLAMA_API_KEY` to the
root `.env`, then start the local dashboard and Docker images:

```sh
make up
```

Open <http://127.0.0.1:8787/>. The setup requires Docker, Python 3.12+, Node.js
20.19+ or 22.12+, and npm. `make serve` refreshes the dashboard without
rebuilding the frozen experiment images. `make down` stops the dashboard.

The experiment documentation and run instructions are in
[shape-lab/README.md](shape-lab/README.md).
