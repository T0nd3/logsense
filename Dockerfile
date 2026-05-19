# ── LogSense — production image ───────────────────────────────────────────
# Multi-stage: builder installs deps, final image is lean.
#
# Build:  docker build -t logsense .
# Run:    docker run -p 8080:8080 -v $(pwd)/data:/data logsense

# ── stage 1: dependencies ─────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Only copy what pip needs to resolve deps
COPY pyproject.toml .
COPY log_analyzer/ log_analyzer/
COPY cli/ cli/

RUN pip install --no-cache-dir --prefix=/install -e ".[web]"


# ── stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="LogSense"
LABEL org.opencontainers.image.description="Local log analysis with LLM support"
LABEL org.opencontainers.image.source="https://github.com/T0nd3/logsense"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source (needed for editable install resolution)
COPY --from=builder /build /app

# Persistent data directory (db, config override)
RUN mkdir -p /data
VOLUME ["/data"]

# Non-root user for safety
RUN useradd -r -u 1001 -s /bin/false logsense \
 && chown -R logsense:logsense /app /data
USER logsense

EXPOSE 8080

# Config is mounted at runtime; db goes to /data
ENV LOGSENSE_CONFIG=/app/config.yaml

CMD ["analyzer", "serve", "--host", "0.0.0.0", "--port", "8080"]
