"""Vigilance - Self-hosted Security & Patch Monitoring for Proxmox"""

__version__ = "0.14.1"
__author__ = "Vigilance Team"
__description__ = "Self-hosted Security & Patch Monitoring for Proxmox"

from vigilance.config import settings
from vigilance.database import (
    Base,
    engine,
    async_session_maker,
    get_db,
    init_db,
    close_db,
    ProxmoxNode,
    Inventory,
    DiscoveredTool,
    ScanRun,
    CVEEntry,
    VulnerabilityFinding,
    Suppression,
    ToolOverride,
    CVESyncStatus,
    AppSetting,
)

__all__ = [
    "settings",
    "Base",
    "engine",
    "async_session_maker",
    "get_db",
    "init_db",
    "close_db",
    "ProxmoxNode",
    "Inventory",
    "DiscoveredTool",
    "ScanRun",
    "CVEEntry",
    "VulnerabilityFinding",
    "Suppression",
    "ToolOverride",
    "CVESyncStatus",
    "AppSetting",
]