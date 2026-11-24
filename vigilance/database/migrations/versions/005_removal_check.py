"""Per host: result of the read-only removal check for obsolete packages."""

from alembic import op
import sqlalchemy as sa

revision = "005_removal_check"
down_revision = "004_scan_status_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inventories", sa.Column("removal_check", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("inventories", "removal_check")
