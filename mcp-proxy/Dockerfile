# Container image for the Ephorate MCP proxy (streamable-HTTP deployment mode).
# Build from the repo root so the uv workspace resolves:
#   docker build -f mcp-proxy/Dockerfile -t ephorate-mcp .
# Run (mount your config + provide secrets via env):
#   docker run -p 8090:8090 \
#     -e EPHORATE_API_KEY=... -e GITHUB_TOKEN=... \
#     -v $PWD/ephorate-mcp.yaml:/etc/ephorate/ephorate-mcp.yaml ephorate-mcp
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy

RUN pip install --no-cache-dir uv

WORKDIR /app
COPY . /app

# Install the mcp-proxy package with the MCP runtime extra, from the lockfile.
RUN uv sync --frozen --package ephorate-mcp --extra runtime

# Run unprivileged.
RUN useradd --uid 10001 --create-home ephorate
USER ephorate

EXPOSE 8090

# The proxy must listen on 0.0.0.0 inside the container (set listen.bind).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/healthz').status==200 else 1)"

ENTRYPOINT ["uv", "run", "--package", "ephorate-mcp", "ephorate-mcp", \
            "--config", "/etc/ephorate/ephorate-mcp.yaml"]
