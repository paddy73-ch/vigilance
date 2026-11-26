"""Snapshot taken before an action (name), and whether one was requested."""

from alembic import op
import sqlalchemy as sa

revision = "008_action_snapshot"
down_revision = "007_container_access"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("action_runs", sa.Column("snapshot_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("action_runs", sa.Column("snapshot", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("action_runs", "snapshot")
    op.drop_column("action_runs", "snapshot_requested")
