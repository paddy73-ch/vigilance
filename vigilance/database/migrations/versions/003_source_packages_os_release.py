"""Store source packages and OS release for release-specific CVE lookups."""
from alembic import op
import sqlalchemy as sa

revision = "003_source_packages_os_release"
down_revision = "002_cve_sync_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inventories", sa.Column("os_id", sa.String(length=32), nullable=True))
    op.add_column("inventories", sa.Column("os_version_id", sa.String(length=32), nullable=True))
    op.add_column("inventories", sa.Column("os_codename", sa.String(length=64), nullable=True))
    op.add_column("discovered_tools", sa.Column("source_name", sa.String(length=255), nullable=True))
    op.add_column("discovered_tools", sa.Column("source_version", sa.String(length=128), nullable=True))
    op.create_index("idx_discovered_tools_source_name", "discovered_tools", ["source_name"])
    # Findings of the previous matcher (bare "Debian" ecosystem, substring matching) are
    # mostly false positives and must not show up as "fixed" later: start clean.
    # OSV/GHSA records are re-downloaded with the new parser on the next sync.
    op.execute("DELETE FROM vulnerability_findings")
    op.execute("DELETE FROM cve_entries WHERE source IN ('osv', 'ghsa')")


def downgrade() -> None:  # findings deleted by upgrade() are not restored
    op.drop_index("idx_discovered_tools_source_name", table_name="discovered_tools")
    op.drop_column("discovered_tools", "source_version")
    op.drop_column("discovered_tools", "source_name")
    op.drop_column("inventories", "os_codename")
    op.drop_column("inventories", "os_version_id")
    op.drop_column("inventories", "os_id")
