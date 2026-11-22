# SQLite to PostgreSQL Migration Plan

## Goal
Replace SQLite with PostgreSQL to fix database locking issues during concurrent CVE sync operations.

## Current State
- SQLite with aiosqlite driver (`sqlite+aiosqlite:///`)
- Database file at `/app/data/vigilance.db`
- NullPool added but still locking due to WAL mode contention
- CVE sync background tasks conflict with health checks and API requests

## Required Changes

### 1. Dependencies (pyproject.toml)
- Add `asyncpg>=0.29.0` to dependencies
- Keep `aiosqlite` for potential fallback/testing (optional)
- Update `sqlalchemy[asyncio]` (already includes asyncpg support)

### 2. Configuration (vigilance/config.py)
- Replace `db_path: str = "/app/data/vigilance.db"` with `database_url: str = "sqlite+aiosqlite:////app/data/vigilance.db"`
- Support PostgreSQL URL format: `postgresql+asyncpg://user:pass@host:5432/dbname`
- Parse URL to extract components for validation

### 3. Database Engine (vigilance/database/base.py)
- Remove SQLite-specific PRAGMA settings (journal_mode=WAL, busy_timeout, etc.)
- Use appropriate pool settings for PostgreSQL (QueuePool with size/overflow)
- Remove `poolclass=NullPool` for PostgreSQL (use default pool)
- Keep NullPool only if using SQLite

### 4. Docker Compose (docker/docker-compose.yml)
- Add `postgres` service:
  - Image: `postgres:16-alpine`
  - Environment: POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB
  - Volume: `postgres_data:/var/lib/postgresql/data`
  - Healthcheck: `pg_isready`
- Update `vigilance` service:
  - Add `depends_on: postgres`
  - Change `VIGILANCE_DB_PATH` to `VIGILANCE_DATABASE_URL`
  - Set `VIGILANCE_DATABASE_URL=postgresql+asyncpg://vigilance:password@postgres:5432/vigilance`
  - Remove `vigilance_data` volume (or keep for config/ssh keys only)

### 5. Dockerfile (docker/Dockerfile)
- Add `postgresql-client` to apt packages (for pg_dump/pg_restore in entrypoint)
- Keep existing Python dependencies

### 6. Alembic (alembic.ini / migrations)
- Existing migrations are PostgreSQL-compatible (standard SQLAlchemy types)
- No changes needed to migration files
- `alembic.ini` sqlalchemy.url will be overridden at runtime via env var

### 7. Entrypoint (docker/entrypoint.sh)
- Add logic to wait for PostgreSQL readiness before running migrations
- Use `pg_isready` or simple connection test

### 8. Deploy Script (deploy.sh)
- Update to handle PostgreSQL migration:
  - Backup: `pg_dump` instead of sqlite3 backup
  - Restore: `pg_restore` if needed
  - Run migrations after deploy

### 9. Environment Files
- Update `.env.example` with PostgreSQL variables
- Update `.env` on host with actual values

## Migration Strategy

### Option A: Fresh Deploy (Recommended)
1. Deploy new docker-compose with PostgreSQL
2. Run migrations on empty database
3. Re-discover inventory
4. Re-sync CVE data

### Option B: Data Migration (If preserving data)
1. Export SQLite data: `sqlite3 vigilance.db .dump > dump.sql`
2. Convert SQL to PostgreSQL-compatible (sed for types, sequences)
3. Import to PostgreSQL: `psql -d vigilance < dump.sql`
4. Fix sequences: `SELECT setval(pg_get_serial_sequence('table', 'id'), max(id)) FROM table;`

**Recommendation**: Option A (fresh deploy) - simpler, cleaner, CVE data can be re-synced.

## Validation Steps
1. Container starts without errors
2. Health check passes (`/api/health` returns database: "ok")
3. CVE sync trigger works without "database is locked"
4. Multiple concurrent syncs don't deadlock
5. Dashboard stats load correctly
6. Findings API returns data with host info

## Files to Modify
1. `pyproject.toml` - add asyncpg
2. `vigilance/config.py` - database_url config
3. `vigilance/database/base.py` - engine setup for PostgreSQL
4. `docker/docker-compose.yml` - add postgres service
5. `docker/Dockerfile` - add postgresql-client
6. `docker/entrypoint.sh` - wait for postgres
7. `deploy.sh` - update for postgres
8. `.env.example` - add postgres variables

## Out of Scope
- SQLite fallback support (can be added later if needed)
- Automated data migration from existing SQLite
- PostgreSQL tuning (max_connections, shared_buffers, etc.)
- Backup/restore automation (manual pg_dump for now)