"""Scan status per host, removed packages, daily finding snapshots, upstream IDs for search."""
import json

from alembic import op
import sqlalchemy as sa

revision = "004_scan_status_snapshots"
down_revision = "003_source_packages_os_release"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inventories", sa.Column("last_scan_at", sa.DateTime(), nullable=True))
    op.add_column("inventories", sa.Column("last_scan_status", sa.String(length=16), nullable=True))
    op.add_column("inventories", sa.Column("last_scan_error", sa.Text(), nullable=True))
    op.add_column("cve_entries", sa.Column("upstream_ids", sa.String(length=512), nullable=True))
    op.add_column("discovered_tools", sa.Column("removed_at", sa.DateTime(), nullable=True))
    op.create_table(
        "finding_snapshots",
        sa.Column("day", sa.Date(), primary_key=True),
        sa.Column("patchable", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("without_fix", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fixed_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("patchable_by_severity", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    # Backfill upstream IDs from the stored OSV/GHSA records
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, raw_data FROM cve_entries WHERE raw_data IS NOT NULL")).fetchall()
    for row_id, raw in rows:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            continue
        ids = list(data.get("upstream") or []) + list(data.get("aliases") or [])
        if data.get("cve_id"):
            ids.append(data["cve_id"])
        ids = [i for i in dict.fromkeys(ids) if isinstance(i, str)]
        if ids:
            bind.execute(sa.text("UPDATE cve_entries SET upstream_ids = :v WHERE id = :id"),
                         {"v": ",".join(ids)[:512], "id": row_id})


def downgrade() -> None:
    op.drop_table("finding_snapshots")
    op.drop_column("discovered_tools", "removed_at")
    op.drop_column("cve_entries", "upstream_ids")
    op.drop_column("inventories", "last_scan_error")
    op.drop_column("inventories", "last_scan_status")
    op.drop_column("inventories", "last_scan_at")
