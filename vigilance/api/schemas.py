from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel, Field


# Health
class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    database: str
    version: str = "0.1.0"


# Proxmox Nodes
class ProxmoxNodeBase(BaseModel):
    name: str
    url: str
    token_id: str
    token_secret: str = ""
    verify_tls: bool = True


class ProxmoxNodeCreate(ProxmoxNodeBase):
    pass


class ProxmoxNodeUpdate(BaseModel):
    url: Optional[str] = None
    token_id: Optional[str] = None
    token_secret: Optional[str] = None
    verify_tls: Optional[bool] = None


class ProxmoxNodeResponse(ProxmoxNodeBase):
    token_secret: str = Field(default="", exclude=True)
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Inventories (VMs/LXCs)
class InventoryResponse(BaseModel):
    id: int
    proxmox_node_id: int
    vmid: int
    name: str
    type: str
    status: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    tags: Optional[str] = None
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Discovered Tools
class DiscoveredToolResponse(BaseModel):
    id: int
    inventory_id: int
    source_type: str
    tool_name: str
    detected_version: Optional[str] = None
    cpe_name: Optional[str] = None
    cpe_version: Optional[str] = None
    package_manager: Optional[str] = None
    raw_data: Optional[str] = None
    discovered_at: datetime

    class Config:
        from_attributes = True


# Scan Runs
class ScanRunResponse(BaseModel):
    id: int
    scan_type: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    nodes_scanned: int
    tools_found: int
    new_findings: int
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


# CVE Entries
class CVEEntryResponse(BaseModel):
    id: int
    cve_id: str
    source: str
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_ranges: Optional[str] = None
    references: Optional[str] = None
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    fetched_at: datetime

    class Config:
        from_attributes = True


# Vulnerability Findings
class VulnerabilityFindingResponse(BaseModel):
    id: int
    discovered_tool_id: int
    cve_entry_id: int
    status: str
    matched_version: Optional[str] = None
    fixed_version: Optional[str] = None
    match_details: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    scan_run_id: Optional[int] = None
    tool: Optional[DiscoveredToolResponse] = None
    cve: Optional[CVEEntryResponse] = None

    class Config:
        from_attributes = True


class FindingDetailResponse(VulnerabilityFindingResponse):
    tool: DiscoveredToolResponse
    cve: CVEEntryResponse
    inventory: InventoryResponse


# Suppressions
class SuppressionBase(BaseModel):
    cve_id: str
    tool_name_pattern: Optional[str] = None
    inventory_id: Optional[int] = None
    reason: str
    expires_at: Optional[datetime] = None


class SuppressionCreate(SuppressionBase):
    pass


class SuppressionResponse(SuppressionBase):
    id: int
    created_by: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# Tool Overrides
class ToolOverrideBase(BaseModel):
    tool_name: str
    cpe_name: Optional[str] = None
    package_name: Optional[str] = None
    ecosystem: Optional[str] = None
    version_pattern: Optional[str] = None
    description: Optional[str] = None


class ToolOverrideCreate(ToolOverrideBase):
    pass


class ToolOverrideUpdate(BaseModel):
    cpe_name: Optional[str] = None
    package_name: Optional[str] = None
    ecosystem: Optional[str] = None
    version_pattern: Optional[str] = None
    description: Optional[str] = None


class ToolOverrideResponse(ToolOverrideBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# CVE Sync Status
class CVESyncStatusResponse(BaseModel):
    source: str
    status: str = "idle"
    last_sync_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    entries_count: int
    error_message: Optional[str] = None
    next_sync_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CVESyncStatusWithEntriesResponse(CVESyncStatusResponse):
    entries: List[CVEEntryResponse] = []


# Settings
class SettingResponse(BaseModel):
    key: str
    value: str
    description: Optional[str] = None
    updated_at: datetime

    class Config:
        from_attributes = True


class GotifyTestRequest(BaseModel):
    url: str
    token: str


class GotifyTestResponse(BaseModel):
    success: bool
    message: str


# Scan Trigger
class ScanTriggerRequest(BaseModel):
    full: bool = False
    node_name: Optional[str] = None


class ScanTriggerResponse(BaseModel):
    scan_run_id: int
    message: str


# CVE Sync Trigger
class CVESyncTriggerRequest(BaseModel):
    source: Optional[str] = None


class CVESyncTriggerResponse(BaseModel):
    results: dict
    message: str


# Dashboard Stats
class DashboardStats(BaseModel):
    total_nodes: int
    total_vms: int
    total_lxcs: int
    total_tools: int
    open_findings: int
    findings_by_severity: dict
    findings_by_status: dict
    recent_scans: List[ScanRunResponse]
    cve_sync_status: List[CVESyncStatusResponse]
