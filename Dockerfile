# syntax=docker/dockerfile:1.7

# Build the wheel (and its dependency wheels) in a throwaway stage.
FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml ./
COPY agents ./agents
COPY subsystems.yaml ./
RUN pip wheel --wheel-dir /wheels .

# Runtime image: non-root, no compiler, read-only root filesystem friendly.
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    AGENT_BUS=redis \
    AGENT_REDIS_URL=redis://redis:6379/0 \
    AGENT_SUBSYSTEMS_FILE=/app/subsystems.yaml \
    AGENT_WORKSPACE=/data/workspace \
    AGENT_HEALTH_HOST=0.0.0.0 \
    AGENT_HEALTH_PORT=8080 \
    AGENT_SHARED_SECRET_FILE=/run/secrets/agent_shared_secret \
    AGENT_HEALTH_TOKEN_FILE=/run/secrets/health_token \
    AGENT_LOG_JSON=true

RUN groupadd --system --gid 10001 usoc \
    && useradd --system --uid 10001 --gid usoc \
        --home-dir /nonexistent --shell /usr/sbin/nologin usoc

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels agent-mesh \
    && rm -rf /wheels
COPY subsystems.yaml /app/subsystems.yaml

RUN mkdir -p /data/workspace \
    && chown -R usoc:usoc /data
USER usoc

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "agents", "probe", "--url", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["python", "-m", "agents"]
CMD ["serve"]
