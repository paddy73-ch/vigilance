from vigilance.discovery.proxmox import ProxmoxClient, ProxmoxNodeInfo, ProxmoxVM, ProxmoxLXC
from vigilance.discovery.ssh import SSHClient, SSHClientPool, CommandResult, get_ssh_pool
from vigilance.discovery.docker import discover_docker_on_host, discover_docker_all, DockerContainer, DockerImage
from vigilance.discovery.packages import discover_packages_on_host, discover_packages_all, PackageInfo
from vigilance.discovery.services import discover_services_on_host, discover_services_all, ServiceInfo
from vigilance.discovery.custom import run_custom_check, run_all_custom_checks, CustomCheckResult
from vigilance.discovery.orchestrator import DiscoveryOrchestrator, ScanResult

__all__ = [
    "ProxmoxClient",
    "ProxmoxNodeInfo",
    "ProxmoxVM",
    "ProxmoxLXC",
    "SSHClient",
    "SSHClientPool",
    "CommandResult",
    "get_ssh_pool",
    "discover_docker_on_host",
    "discover_docker_all",
    "DockerContainer",
    "DockerImage",
    "discover_packages_on_host",
    "discover_packages_all",
    "PackageInfo",
    "discover_services_on_host",
    "discover_services_all",
    "ServiceInfo",
    "run_custom_check",
    "run_all_custom_checks",
    "CustomCheckResult",
    "DiscoveryOrchestrator",
    "ScanResult",
]