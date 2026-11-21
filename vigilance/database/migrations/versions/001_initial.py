"""Initial migration

Revision ID: 001_initial
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Proxmox Nodes
    op.create_table(
        "proxmox_nodes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=512), nullable=False),
        sa.Column("token_id", sa.String(length=255), nullable=False),
        sa.Column("token_secret", sa.String(length=512), nullable=False),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # Inventories
    op.create_table(
        "inventories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("proxmox_node_id", sa.Integer(), nullable=False),
        sa.Column("vmid", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["proxmox_node_id"], ["proxmox_nodes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("proxmox_node_id", "vmid", name="uq_node_vmid"),
    )
    op.create_index("idx_inventory_node", "inventories", ["proxmox_node_id"], unique=False)

    # Discovered Tools
    op.create_table(
        "discovered_tools",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("inventory_id", sa.Integer(), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("detected_version", sa.String(length=128), nullable=True),
        sa.Column("cpe_name", sa.String(length=512), nullable=True),
        sa.Column("cpe_version", sa.String(length=128), nullable=True),
        sa.Column("package_manager", sa.String(length=32), nullable=True),
        sa.Column("raw_data", sa.Text(), nullable=True),
        sa.Column("discovered_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("scan_run_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["inventory_id"], ["inventories.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_discovered_tools_inventory", "discovered_tools", ["inventory_id"], unique=False)
    op.create_index("idx_discovered_tools_tool_name", "discovered_tools", ["tool_name"], unique=False)
    op.create_index("idx_discovered_tools_source_type", "discovered_tools", ["source_type"], unique=False)

    # Scan Runs
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("nodes_scanned", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("tools_found", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("new_findings", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_scan_runs_type", "scan_runs", ["scan_type"], unique=False)
    op.create_index("idx_scan_runs_status", "scan_runs", ["status"], unique=False)

    # CVE Entries
    op.create_table(
        "cve_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=256), nullable=True),
        sa.Column("affected_ranges", sa.Text(), nullable=True),
        sa.Column("references", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("modified_at", sa.DateTime(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("raw_data", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_index("idx_cve_entries_severity", "cve_entries", ["severity"], unique=False)
    op.create_index("idx_cve_entries_source", "cve_entries", ["source"], unique=False)

    # Vulnerability Findings
    op.create_table(
        "vulnerability_findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("discovered_tool_id", sa.Integer(), nullable=False),
        sa.Column("cve_entry_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'open'")),
        sa.Column("matched_version", sa.String(length=128), nullable=True),
        sa.Column("fixed_version", sa.String(length=128), nullable=True),
        sa.Column("match_details", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("scan_run_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["cve_entry_id"], ["cve_entries.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["discovered_tool_id"], ["discovered_tools.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("discovered_tool_id", "cve_entry_id", name="uq_tool_cve"),
    )
    op.create_index("idx_vuln_findings_tool", "vulnerability_findings", ["discovered_tool_id"], unique=False)
    op.create_index("idx_vuln_findings_cve", "vulnerability_findings", ["cve_entry_id"], unique=False)
    op.create_index("idx_vuln_findings_status", "vulnerability_findings", ["status"], unique=False)

    # Suppressions
    op.create_table(
        "suppressions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=False),
        sa.Column("tool_name_pattern", sa.String(length=255), nullable=True),
        sa.Column("inventory_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["inventory_id"], ["inventories.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Tool Overrides
    op.create_table(
        "tool_overrides",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("cpe_name", sa.String(length=512), nullable=True),
        sa.Column("package_name", sa.String(length=255), nullable=True),
        sa.Column("ecosystem", sa.String(length=64), nullable=True),
        sa.Column("version_pattern", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tool_name"),
    )

    # CVE Sync Status
    op.create_table(
        "cve_sync_status",
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("entries_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("next_sync_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("source"),
    )

    # App Settings
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_table("cve_sync_status")
    op.drop_table("tool_overrides")
    op.drop_table("suppressions")
    op.drop_index("idx_vuln_findings_status", table_name="vulnerability_findings")
    op.drop_index("idx_vuln_findings_cve", table_name="vulnerability_findings")
    op.drop_index("idx_vuln_findings_tool", table_name="vulnerability_findings")
    op.drop_table("vulnerability_findings")
    op.drop_index("idx_cve_entries_source", table_name="cve_entries")
    op.drop_index("idx_cve_entries_severity", table_name="cve_entries")
    op.drop_table("cve_entries")
    op.drop_index("idx_scan_runs_status", table_name="scan_runs")
    op.drop_index("idx_scan_runs_type", table_name="scan_runs")
    op.drop_table("scan_runs")
    op.drop_index("idx_discovered_tools_source_type", table_name="discovered_tools")
    op.drop_index("idx_discovered_tools_tool_name", table_name="discovered_tools")
    op.drop_index("idx_discovered_tools_inventory", table_name="discovered_tools")
    op.drop_table("discovered_tools")
    op.drop_index("idx_inventory_node", table_name="inventories")
    op.drop_table("inventories")
    op.drop_table("proxmox_nodes")