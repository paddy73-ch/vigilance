FROM python:3.12-slim

# Non-root user
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} vigilance && \
    useradd -u ${UID} -g ${GID} -m -s /bin/bash vigilance

# System dependencies for paramiko, ssh, healthcheck, building, and postgresql
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    curl \
    ca-certificates \
    gcc \
    libffi-dev \
    libssl-dev \
    postgresql-client \
    gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy application code first (needed for editable install)
COPY pyproject.toml .
COPY vigilance/ ./vigilance/
COPY config/ ./config/
COPY alembic.ini .

# Create data directory with correct ownership before switching user
RUN mkdir -p /app/data /app/data/ssh && \
    chown -R 1000:1000 /app/data

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Entry point
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Volume for data persistence
VOLUME ["/app/data"]

# Run as root for entrypoint (permission fixes), then drop to vigilance via gosu
USER root

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    VIGILANCE_DATABASE_URL=sqlite+aiosqlite:////app/data/vigilance.db \
    VIGILANCE_CONFIG_PATH=/app/data/config.yaml

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "vigilance.main:app", "--host", "0.0.0.0", "--port", "8000"]