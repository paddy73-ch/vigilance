"""Track CVE source sync state."""
from alembic import op
import sqlalchemy as sa

revision = "002_cve_sync_status"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cve_sync_status", sa.Column("status", sa.String(length=16), nullable=False, server_default="idle"))


def downgrade() -> None:
    op.drop_column("cve_sync_status", "status")
