FROM python:3.12-slim

# Non-root user
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} vigilance && \
    useradd -u ${UID} -g ${GID} -m -s /bin/bash vigilance

# System dependencies for paramiko, ssh, healthcheck, and building
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    curl \
    ca-certificates \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application code
COPY vigilance/ ./vigilance/
COPY config/ ./config/
COPY alembic.ini .

# Entry point
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Volume for data persistence
VOLUME ["/app/data"]

# Non-root user
USER vigilance

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    VIGILANCE_DB_PATH=/app/data/vigilance.db \
    VIGILANCE_CONFIG_PATH=/app/data/config.yaml

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "vigilance.__init__:app", "--host", "0.0.0.0", "--port", "8000"]