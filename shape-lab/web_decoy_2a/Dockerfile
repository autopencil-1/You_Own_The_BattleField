FROM python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SHAPE_PORT=8080

WORKDIR /app
COPY web_decoy_2a /app/web_decoy_2a
COPY config/exp_2a_pilot.json /app/config/exp_2a_pilot.json

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()" || exit 1

CMD ["python", "-m", "web_decoy_2a.server"]
