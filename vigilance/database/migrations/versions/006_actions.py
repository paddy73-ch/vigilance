"""Upgrade availability per host; remediation runs executed by Vigilance."""

from alembic import op
import sqlalchemy as sa

revision = "006_actions"
down_revision = "005_removal_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inventories", sa.Column("upgrade_check", sa.Text(), nullable=True))
    op.create_table(
        "action_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("batch_id", sa.String(length=36), nullable=False),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("inventories.id", ondelete="SET NULL"), nullable=True),
        sa.Column("host_name", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="queued"),
        sa.Column("commands", sa.Text(), nullable=True),
        sa.Column("skipped", sa.Text(), nullable=True),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_action_runs_batch_id", "action_runs", ["batch_id"])


def downgrade() -> None:
    op.drop_index("ix_action_runs_batch_id", table_name="action_runs")
    op.drop_table("action_runs")
    op.drop_column("inventories", "upgrade_check")
