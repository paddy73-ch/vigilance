import logging
from dataclasses import dataclass
from typing import List, Optional
import aiohttp

from vigilance.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ProxmoxNodeInfo:
    node: str
    status: str
    cpu: float
    maxcpu: int
    mem: int
    maxmem: int
    disk: int
    maxdisk: int
    level: str
    uptime: int
    id: str
    ssl_fingerprint: str


@dataclass
class ProxmoxVM:
    vmid: int
    name: str
    status: str
    node: str
    type: str  # qemu
    maxmem: int
    maxdisk: int
    cpu: float
    netin: int
    netout: int
    diskread: int
    diskwrite: int
    uptime: int
    ip: Optional[str] = None


@dataclass
class ProxmoxLXC:
    vmid: int
    name: str
    status: str
    node: str
    type: str  # lxc
    maxmem: int
    maxdisk: int
    cpu: float
    netin: int
    netout: int
    diskread: int
    diskwrite: int
    uptime: int
    ip: Optional[str] = None


class ProxmoxClient:
    def __init__(self, node_config):
        self.base_url = node_config.url.rstrip("/")
        self.token_id = node_config.token_id
        self.token_secret = node_config.token_secret
        self.verify_tls = node_config.verify_tls
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(verify_ssl=self.verify_tls)
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers={"Authorization": f"PVEAPIToken={self.token_id}={self.token_secret}"},
            timeout=aiohttp.ClientTimeout(total=30),
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        if not self.session:
            raise RuntimeError("Client not initialized. Use async with.")
        url = f"{self.base_url}{path}"
        async with self.session.request(method, url, **kwargs) as resp:
            if resp.status >= 400:
                text = await resp.text()
                raise aiohttp.ClientResponseError(
                    request_info=resp.request_info,
                    history=resp.history,
                    status=resp.status,
                    message=text,
                )
            return await resp.json()

    async def get_nodes(self) -> List[ProxmoxNodeInfo]:
        data = await self._request("GET", "/api2/json/nodes")
        nodes = []
        for item in data.get("data", []):
            nodes.append(ProxmoxNodeInfo(**item))
        return nodes

    async def get_vms(self, node: str) -> List[ProxmoxVM]:
        data = await self._request("GET", f"/api2/json/nodes/{node}/qemu")
        vms = []
        for item in data.get("data", []):
            item.setdefault("node", node)
            item.setdefault("type", "qemu")
            item.setdefault("diskread", 0)
            item.setdefault("diskwrite", 0)
            vms.append(ProxmoxVM(**{key: value for key, value in item.items() if key in ProxmoxVM.__dataclass_fields__}))
        return vms

    async def get_lxcs(self, node: str) -> List[ProxmoxLXC]:
        data = await self._request("GET", f"/api2/json/nodes/{node}/lxc")
        lxcs = []
        for item in data.get("data", []):
            item.setdefault("node", node)
            item.setdefault("type", "lxc")
            item.setdefault("diskread", 0)
            item.setdefault("diskwrite", 0)
            lxcs.append(ProxmoxLXC(**{key: value for key, value in item.items() if key in ProxmoxLXC.__dataclass_fields__}))
        return lxcs

    async def get_vm_config(self, node: str, vmid: int) -> dict:
        data = await self._request("GET", f"/api2/json/nodes/{node}/qemu/{vmid}/config")
        return data.get("data", {})

    async def get_lxc_config(self, node: str, vmid: int) -> dict:
        data = await self._request("GET", f"/api2/json/nodes/{node}/lxc/{vmid}/config")
        return data.get("data", {})

    async def get_vm_interfaces(self, node: str, vmid: int) -> dict:
        data = await self._request("GET", f"/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
        return data.get("data", {})

    async def get_lxc_interfaces(self, node: str, vmid: int) -> dict:
        data = await self._request("GET", f"/api2/json/nodes/{node}/lxc/{vmid}/interfaces")
        return data.get("data", {})


async def create_proxmox_client(node_name: str) -> Optional[ProxmoxClient]:
    """Create a ProxmoxClient for a configured node."""
    for node_config in settings.proxmox_nodes:
        if node_config.name == node_name:
            return ProxmoxClient(node_config)
    return None


async def get_all_proxmox_clients() -> List[ProxmoxClient]:
    """Create clients for all configured Proxmox nodes."""
    clients = []
    for node_config in settings.proxmox_nodes:
        clients.append(ProxmoxClient(node_config))
    return clients
