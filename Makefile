LAB := $(CURDIR)/shape-lab
VENV := $(LAB)/.venv
PYTHON ?= python3
NVM_NODE_DIR := $(shell ls -d $(HOME)/.nvm/versions/node/v*/bin 2>/dev/null | sort -V | tail -1)
ifneq ($(NVM_NODE_DIR),)
export PATH := $(NVM_NODE_DIR):$(PATH)
endif

.PHONY: up down status setup images check

up: images
	@cd "$(LAB)" && "$(VENV)/bin/python" -m dashboard.service restart

down:
	@if [ -x "$(VENV)/bin/python" ]; then cd "$(LAB)" && "$(VENV)/bin/python" -m dashboard.service stop; else echo 'Dashboard is not set up'; fi

status:
	@cd "$(LAB)" && "$(VENV)/bin/python" -m dashboard.service status

setup:
	@command -v docker >/dev/null || { echo 'Docker is required' >&2; exit 1; }
	@command -v npm >/dev/null || { echo 'Node.js and npm are required' >&2; exit 1; }
	@$(PYTHON) -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ is required"'
	@if [ ! -x "$(VENV)/bin/python" ]; then $(PYTHON) -m venv "$(VENV)"; fi
	@if [ ! -f "$(VENV)/.dashboard-deps-stamp" ] || [ "$(LAB)/requirements-dashboard.txt" -nt "$(VENV)/.dashboard-deps-stamp" ]; then \
		set -e; \
		if command -v uv >/dev/null; then UV_CACHE_DIR="$(LAB)/.cache/uv" uv pip install --python "$(VENV)/bin/python" -r "$(LAB)/requirements-dashboard.txt"; \
		else "$(VENV)/bin/python" -m pip install -r "$(LAB)/requirements-dashboard.txt"; fi; \
		touch "$(VENV)/.dashboard-deps-stamp"; \
	fi
	@node -e 'const [major,minor]=process.versions.node.split(".").map(Number); if (!(major===20 && minor>=19 || major===22 && minor>=12 || major>22)) { console.error("Node.js 20.19+ or 22.12+ is required"); process.exit(1) }'
	@if [ ! -f "$(LAB)/dashboard_ui/node_modules/.package-lock.json" ] || [ "$(LAB)/dashboard_ui/package-lock.json" -nt "$(LAB)/dashboard_ui/node_modules/.package-lock.json" ]; then \
		cd "$(LAB)/dashboard_ui" && npm ci; \
	fi
	@cd "$(LAB)/dashboard_ui" && npm run build

images: setup
	@docker info --format '{{.ServerVersion}}' >/dev/null || { echo 'Docker daemon is unavailable' >&2; exit 1; }
	@cd "$(LAB)" && "$(VENV)/bin/python" -c 'from experiment_controller.run_2a import read_key; read_key(); print("Z.AI credential configured in repository .env")'
	@cd "$(LAB)" && docker compose --profile agent -f compose.yaml build web-decoy-2a model-gateway attacker-agent
	@cd "$(LAB)" && docker compose --profile agent -f compose_2b.yaml build filesystem-decoy-2b attacker-agent

check: setup
	@cd "$(LAB)" && "$(VENV)/bin/python" -m unittest discover -s tests -v
