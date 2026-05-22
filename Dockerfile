# ── Logatory — production image ───────────────────────────────────────────
# Multi-stage: builder compiles a real wheel, runtime stage is lean.
#
# Build:  docker build -t logatory .
# Run:    docker run -p 8080:8080 -v logatory-data:/data logatory

# ── stage 1: build & install ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY pyproject.toml .
COPY logatory/ logatory/
COPY cli/ cli/

# Regular (non-editable) install so cli/ and logatory/ are physically
# copied into site-packages — no dependency on the source directory at runtime.
RUN pip install --no-cache-dir --prefix=/install ".[web]"


# ── stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Logatory"
LABEL org.opencontainers.image.description="Local log analysis with LLM support"
LABEL org.opencontainers.image.source="https://github.com/T0nd3/logatory"

WORKDIR /app

# Packages are in site-packages — source directory is no longer needed.
COPY --from=builder /install /usr/local

# Minimal default config: point the database at the persistent /data volume.
# Override by mounting your own file: -v ./config.yaml:/app/config.yaml:ro
RUN echo "db_path: /data/logatory.db" > /app/config.yaml

# Persistent data directory (SQLite db, optional config override)
RUN mkdir -p /data

# Non-root user for safety
RUN useradd -r -u 1001 -s /bin/false logatory \
 && chown -R logatory:logatory /app /data
USER logatory

EXPOSE 8080

# Used by --reload / uvicorn factory mode
ENV LOGATORY_CONFIG=/app/config.yaml

CMD ["logatory", "serve", "--host", "0.0.0.0", "--port", "8080", "--config", "/app/config.yaml"]
