import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml


class ProxmoxNodeConfig:
    def __init__(self, data: dict):
        self.name = data.get("name")
        self.url = data.get("url")
        self.token_id = data.get("token_id")
        self.token_secret = data.get("token_secret")
        self.verify_tls = data.get("verify_tls", True)
        ssh = data.get("ssh", {})
        self.ssh_host = ssh.get("host")
        self.ssh_port = ssh.get("port", 22)
        self.ssh_user = ssh.get("user", "root")
        self.ssh_key_path = ssh.get("key_path")
        self.ssh_known_hosts = ssh.get("known_hosts")


class DiscoveryConfig:
    def __init__(self, data: dict):
        ssh = data.get("ssh", {})
        self.ssh_timeout = ssh.get("timeout", 30)
        self.ssh_parallel_jobs = ssh.get("parallel_jobs", 10)
        self.ssh_strict_host_key_checking = ssh.get("strict_host_key_checking", True)
        self.docker_enabled = data.get("docker", {}).get("enabled", True)
        pkg = data.get("packages", {})
        self.packages_enabled = pkg.get("enabled", True)
        self.packages_managers = pkg.get("managers", ["dpkg", "apk", "rpm"])
        svc = data.get("services", {})
        self.services_enabled = svc.get("enabled", True)
        self.services_include_patterns = svc.get("include_patterns", [])
        self.custom_checks = data.get("custom_checks", [])


class CVESyncConfig:
    def __init__(self, data: dict):
        sources = data.get("sources", {})
        self.osv = sources.get("osv", {"enabled": True, "interval_hours": 6})
        self.ghsa = sources.get("ghsa", {"enabled": True, "interval_hours": 6})
        # NVD has no package-level query for distro packages; matching is name based only.
        self.nvd = sources.get("nvd", {"enabled": False, "interval_hours": 24, "api_key": "", "max_pages": 0})
        # OSV's Debian:N data is generated from the Debian Security Tracker, so the
        # tracker itself is off by default to avoid duplicate findings.
        self.debian = sources.get("debian", {"enabled": False, "interval_hours": 12, "suites": ["bookworm", "trixie"]})
        self.ubuntu = sources.get("ubuntu", {"enabled": False, "interval_hours": 12, "releases": ["noble", "jammy", "focal"]})


class GotifyConfig:
    def __init__(self, data: dict):
        self.enabled = data.get("enabled", True)
        self.url = data.get("url", "")
        self.token = data.get("token", "")
        self.min_severity = data.get("min_severity", "HIGH")
        self.digest_mode = data.get("digest_mode", False)
        self.digest_interval_minutes = data.get("digest_interval_minutes", 60)


class WebhookConfig:
    def __init__(self, data: dict):
        self.name = data.get("name")
        self.url = data.get("url")
        self.min_severity = data.get("min_severity", "CRITICAL")
        self.template = data.get("template", "default")


class NotificationsConfig:
    def __init__(self, data: dict):
        self.gotify = GotifyConfig(data.get("gotify", {}))
        self.webhooks = [WebhookConfig(w) for w in data.get("webhooks", [])]


class ScanConfig:
    def __init__(self, data: dict):
        self.interval_hours = data.get("interval_hours", 24)
        self.full_scan_on_start = data.get("full_scan_on_start", True)
        self.incremental = data.get("incremental", True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="VIGILANCE_",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite+aiosqlite:////app/data/vigilance.db"
    config_path: str = "/app/data/config.yaml"

    # Proxmox (from env, can be overridden by config.yaml)
    proxmox_url: str = ""
    proxmox_token_id: str = ""
    proxmox_token_secret: str = ""
    proxmox_verify_tls: bool = True

    # Gotify
    gotify_url: str = ""
    gotify_token: str = ""
    gotify_min_severity: str = "HIGH"
    gotify_digest_mode: bool = False

    # Auth
    auth_mode: str = "proxy"  # proxy, builtin, both
    api_token: str = ""
    remote_user_header: str = "Remote-User"

    # CVE Sync
    cve_sync_interval_hours: int = 6
    nvd_api_key: str = ""
    github_token: str = ""

    # Scan
    scan_interval_hours: int = 24
    ssh_timeout: int = 30
    ssh_parallel_jobs: int = 10

    # App
    log_level: str = "INFO"
    secret_key: str = "change-me-in-production"

    # Parsed config.yaml (loaded after env)
    proxmox_nodes: List[ProxmoxNodeConfig] = []
    discovery: Optional[DiscoveryConfig] = None
    cve_sync: Optional[CVESyncConfig] = None
    notifications: Optional[NotificationsConfig] = None
    scan: Optional[ScanConfig] = None
    overrides: Dict[str, str] = {}
    suppressions: List[Dict[str, Any]] = []

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        valid_schemes = ("sqlite+aiosqlite://", "postgresql+asyncpg://")
        if not any(v.startswith(scheme) for scheme in valid_schemes):
            raise ValueError(f"database_url must start with one of: {valid_schemes}")
        return v

    @field_validator("auth_mode")
    @classmethod
    def validate_auth_mode(cls, v: str) -> str:
        if v not in ("proxy", "builtin", "both"):
            raise ValueError("auth_mode must be 'proxy', 'builtin', or 'both'")
        return v

    def load_config_yaml(self):
        path = Path(self.config_path)
        if not path.exists():
            return

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        # Proxmox nodes
        self.proxmox_nodes = [ProxmoxNodeConfig(n) for n in data.get("proxmox", {}).get("nodes", [])]

        # Discovery
        self.discovery = DiscoveryConfig(data.get("discovery", {}))

        # CVE Sync
        self.cve_sync = CVESyncConfig(data.get("cve_sync", {}))

        # Notifications
        self.notifications = NotificationsConfig(data.get("notifications", {}))

        # Scan
        self.scan = ScanConfig(data.get("scan", {}))

        # Overrides
        self.overrides = data.get("overrides", {})

        # Suppressions
        self.suppressions = data.get("suppressions", [])

        # Override from env if set
        if self.proxmox_url and self.proxmox_nodes:
            self.proxmox_nodes[0].url = self.proxmox_url
        if self.proxmox_token_id and self.proxmox_nodes:
            self.proxmox_nodes[0].token_id = self.proxmox_token_id
        if self.proxmox_token_secret and self.proxmox_nodes:
            self.proxmox_nodes[0].token_secret = self.proxmox_token_secret

        if self.gotify_url and self.notifications:
            self.notifications.gotify.url = self.gotify_url
        if self.gotify_token and self.notifications:
            self.notifications.gotify.token = self.gotify_token


settings = Settings()
settings.load_config_yaml()