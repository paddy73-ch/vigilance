from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Integer, String, Text, Boolean, DateTime, ForeignKey, UniqueConstraint, Index, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from vigilance.database.base import Base


class ProxmoxNode(Base):
    __tablename__ = "proxmox_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    token_id: Mapped[str] = mapped_column(String(255), nullable=False)
    token_secret: Mapped[str] = mapped_column(String(512), nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    inventories: Mapped[List["Inventory"]] = relationship(back_populates="node", cascade="all, delete-orphan")


class Inventory(Base):
    __tablename__ = "inventories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    proxmox_node_id: Mapped[int] = mapped_column(ForeignKey("proxmox_nodes.id"), nullable=False)
    vmid: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)  # lxc | qemu
    status: Mapped[Optional[str]] = mapped_column(String(64))
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    os_id: Mapped[Optional[str]] = mapped_column(String(32))  # debian, ubuntu, alpine
    os_version_id: Mapped[Optional[str]] = mapped_column(String(32))  # 13, 24.04, 3.20.3
    os_codename: Mapped[Optional[str]] = mapped_column(String(64))  # trixie, noble
    tags: Mapped[Optional[str]] = mapped_column(Text)  # JSON array
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    node: Mapped["ProxmoxNode"] = relationship(back_populates="inventories")
    discovered_tools: Mapped[List["DiscoveredTool"]] = relationship(back_populates="inventory", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("proxmox_node_id", "vmid", name="uq_node_vmid"),
        Index("idx_inventory_node", "proxmox_node_id"),
    )

    @property
    def node_name(self) -> Optional[str]:
        return self.node.name if self.node else None


class DiscoveredTool(Base):
    __tablename__ = "discovered_tools"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    inventory_id: Mapped[int] = mapped_column(ForeignKey("inventories.id"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # proxmox_api, ssh_docker, ssh_pkg, ssh_custom, ssh_service
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    detected_version: Mapped[Optional[str]] = mapped_column(String(128))
    cpe_name: Mapped[Optional[str]] = mapped_column(String(512))
    cpe_version: Mapped[Optional[str]] = mapped_column(String(128))
    package_manager: Mapped[Optional[str]] = mapped_column(String(32))
    # Source package / version (dpkg source:Package, apk origin). CVE data is keyed on these.
    source_name: Mapped[Optional[str]] = mapped_column(String(255))
    source_version: Mapped[Optional[str]] = mapped_column(String(128))
    raw_data: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scan_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_runs.id"))

    inventory: Mapped["Inventory"] = relationship(back_populates="discovered_tools")
    findings: Mapped[List["VulnerabilityFinding"]] = relationship(back_populates="tool", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_discovered_tools_inventory", "inventory_id"),
        Index("idx_discovered_tools_tool_name", "tool_name"),
        Index("idx_discovered_tools_source_type", "source_type"),
        Index("idx_discovered_tools_source_name", "source_name"),
    )


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)  # full, incremental, cve_sync
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # running, completed, failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    nodes_scanned: Mapped[int] = mapped_column(Integer, default=0)
    tools_found: Mapped[int] = mapped_column(Integer, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        Index("idx_scan_runs_type", "scan_type"),
        Index("idx_scan_runs_status", "status"),
    )


class CVEEntry(Base):
    __tablename__ = "cve_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)  # osv, ghsa, nvd, debian, ubuntu
    title: Mapped[Optional[str]] = mapped_column(String(512))
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(String(16))  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score: Mapped[Optional[float]] = mapped_column()
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(256))
    affected_ranges: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    references: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    modified_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    raw_data: Mapped[Optional[str]] = mapped_column(Text)  # JSON

    findings: Mapped[List["VulnerabilityFinding"]] = relationship(back_populates="cve")

    __table_args__ = (
        Index("idx_cve_entries_severity", "severity"),
        Index("idx_cve_entries_source", "source"),
    )


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    discovered_tool_id: Mapped[int] = mapped_column(ForeignKey("discovered_tools.id"), nullable=False)
    cve_entry_id: Mapped[int] = mapped_column(ForeignKey("cve_entries.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open, fixed, suppressed, unknown_version
    matched_version: Mapped[Optional[str]] = mapped_column(String(128))
    fixed_version: Mapped[Optional[str]] = mapped_column(String(128))
    match_details: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    scan_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_runs.id"))

    tool: Mapped["DiscoveredTool"] = relationship(back_populates="findings")
    cve: Mapped["CVEEntry"] = relationship(back_populates="findings")

    __table_args__ = (
        UniqueConstraint("discovered_tool_id", "cve_entry_id", name="uq_tool_cve"),
        Index("idx_vuln_findings_tool", "discovered_tool_id"),
        Index("idx_vuln_findings_cve", "cve_entry_id"),
        Index("idx_vuln_findings_status", "status"),
    )


class Suppression(Base):
    __tablename__ = "suppressions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name_pattern: Mapped[Optional[str]] = mapped_column(String(255))
    inventory_id: Mapped[Optional[int]] = mapped_column(ForeignKey("inventories.id"))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_by: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    inventory: Mapped[Optional["Inventory"]] = relationship()


class ToolOverride(Base):
    __tablename__ = "tool_overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    cpe_name: Mapped[Optional[str]] = mapped_column(String(512))
    package_name: Mapped[Optional[str]] = mapped_column(String(255))
    ecosystem: Mapped[Optional[str]] = mapped_column(String(64))
    version_pattern: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CVESyncStatus(Base):
    __tablename__ = "cve_sync_status"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="idle", server_default="idle")
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    entries_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    next_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    description: Mapped[Optional[str]] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
