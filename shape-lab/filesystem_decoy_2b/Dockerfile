FROM python:3.12.15-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY filesystem_decoy_2b /app/filesystem_decoy_2b
COPY config/exp_2b_engine_fixture.json /app/config/exp_2b_engine_fixture.json

USER 10001:10001
EXPOSE 8082
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8082/healthz', timeout=2).read()" || exit 1
CMD ["python", "-m", "filesystem_decoy_2b.server"]
