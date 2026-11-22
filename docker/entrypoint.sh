#!/bin/bash
set -e

echo "Starting Vigilance..."

# Fix permissions on data volume (runs as root)
mkdir -p /app/data /app/data/ssh
chown -R vigilance:vigilance /app/data

# Wait for PostgreSQL if using PostgreSQL database
if [[ "${VIGILANCE_DATABASE_URL:-}" == postgresql+asyncpg://* ]]; then
    echo "Waiting for PostgreSQL..."
    # Extract host and port from DATABASE_URL
    # Format: postgresql+asyncpg://user:pass@host:port/dbname
    DB_HOST=$(echo "$VIGILANCE_DATABASE_URL" | sed -n 's/.*@\([^:]*\):.*/\1/p')
    DB_PORT=$(echo "$VIGILANCE_DATABASE_URL" | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
    DB_USER=$(echo "$VIGILANCE_DATABASE_URL" | sed -n 's/.*\/\/\([^:]*\):.*/\1/p')
    DB_NAME=$(echo "$VIGILANCE_DATABASE_URL" | sed -n 's/.*\/\([^?]*\).*/\1/p')

    # Default values if not extracted
    DB_HOST=${DB_HOST:-postgres}
    DB_PORT=${DB_PORT:-5432}
    DB_USER=${DB_USER:-vigilance}
    DB_NAME=${DB_NAME:-vigilance}

    echo "Waiting for PostgreSQL at $DB_HOST:$DB_PORT..."
    until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; do
        echo "PostgreSQL not ready, waiting..."
        sleep 2
    done
    echo "PostgreSQL is ready!"
fi

# Create config.yaml from example if it doesn't exist
if [ ! -f /app/data/config.yaml ]; then
    echo "Creating config.yaml from example"
    cp /app/config/config.yaml.example /app/data/config.yaml
fi

# Create SSH directory if it doesn't exist
mkdir -p /app/data/ssh

# Initialize known_hosts if it doesn't exist
if [ ! -f /app/data/ssh/known_hosts ]; then
    touch /app/data/ssh/known_hosts
    chmod 644 /app/data/ssh/known_hosts
fi

# Check for SSH key
if [ ! -f /app/data/ssh/id_rsa ]; then
    echo "WARNING: SSH key not found at /app/data/ssh/id_rsa"
    echo "Generate with: ssh-keygen -t ed25519 -f /app/data/ssh/id_rsa"
fi

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

echo "Starting application..."
# Drop privileges and run as vigilance user
exec gosu vigilance "$@"