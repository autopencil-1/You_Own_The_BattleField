FROM python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git bash \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir uv==0.11.25

WORKDIR /opt/pentestgpt_agent
COPY --from=pentest_source . /opt/pentestgpt_agent
RUN uv sync --locked --no-dev --extra claude

WORKDIR /opt/shape
COPY agent_runner/entrypoint.py /opt/shape/entrypoint.py
COPY config/exp_2a_pilot.json /opt/shape/exp_2a_pilot.json

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/pentestgpt_agent/.venv/bin:$PATH \
    HOME=/work/home \
    CLAUDE_CONFIG_DIR=/work/home/.claude

WORKDIR /work
USER 10001:10001
CMD ["python", "/opt/shape/entrypoint.py"]
