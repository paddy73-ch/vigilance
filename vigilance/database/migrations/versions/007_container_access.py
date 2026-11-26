"""Containers via `pct exec` became the default; installations from before keep reaching them by SSH."""

from alembic import op
import sqlalchemy as sa

revision = "007_container_access"
down_revision = "006_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    names = [r[0] for r in conn.execute(sa.text("SELECT name FROM proxmox_nodes"))]
    for name in names:
        key = f"container_access.{name}"
        if conn.execute(sa.text("SELECT 1 FROM app_settings WHERE key = :k"), {"k": key}).first():
            continue
        conn.execute(sa.text("INSERT INTO app_settings (key, value, description, updated_at) "
                             "VALUES (:k, 'ssh', 'How Vigilance reaches the containers (pct or ssh)', CURRENT_TIMESTAMP)"),
                     {"k": key})


def downgrade() -> None:
    op.execute("DELETE FROM app_settings WHERE key LIKE 'container_access.%'")
