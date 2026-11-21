#!/bin/bash
set -e

echo "Starting Vigilance..."

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
exec "$@"