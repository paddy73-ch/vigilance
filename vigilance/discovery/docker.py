import json
import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from vigilance.discovery.ssh import get_ssh_pool, CommandResult
from vigilance.config import settings

logger = logging.getLogger(__name__)


@dataclass
class DockerContainer:
    id: str
    name: str
    image: str
    image_id: str
    status: str
    ports: str
    created: str


@dataclass
class DockerImage:
    repository: str
    tag: str
    image_id: str
    created: str
    size: str


def parse_docker_ps(output: str) -> List[DockerContainer]:
    """Parse `docker ps --format json` output."""
    containers = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            containers.append(DockerContainer(
                id=data.get("ID", "")[:12],
                name=data.get("Names", ""),
                image=data.get("Image", ""),
                image_id=data.get("ImageID", "")[:12],
                status=data.get("Status", ""),
                ports=data.get("Ports", ""),
                created=data.get("CreatedAt", ""),
            ))
        except json.JSONDecodeError:
            continue
    return containers


def parse_docker_images(output: str) -> List[DockerImage]:
    """Parse `docker images --format json` output."""
    images = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            images.append(DockerImage(
                repository=data.get("Repository", ""),
                tag=data.get("Tag", ""),
                image_id=data.get("ID", "")[:12],
                created=data.get("CreatedSince", ""),
                size=data.get("Size", ""),
            ))
        except json.JSONDecodeError:
            continue
    return images


def parse_image_name(image: str) -> tuple[str, str]:
    """Parse Docker image name into (name, tag)."""
    if "@" in image:
        # Digest format: name@sha256:...
        name, digest = image.split("@", 1)
        return name, digest
    elif ":" in image and not image.startswith("sha256:"):
        # Name:tag format
        parts = image.rsplit(":", 1)
        if "/" in parts[1] or "." in parts[1]:
            # It's a registry path with port, not a tag
            return image, "latest"
        return parts[0], parts[1]
    return image, "latest"


async def discover_docker_on_host(host: str, port: int, user: str, key_path: str, known_hosts: str) -> dict:
    """Discover Docker containers and images on a single host via SSH."""
    pool = get_ssh_pool()
    targets = [{"host": host, "port": port, "user": user, "key_path": key_path, "known_hosts": known_hosts}]

    # Check if docker is available
    check_result = pool.run_parallel(targets, "which docker")
    if not check_result[host].success:
        logger.debug(f"Docker not found on {host}")
        return {"containers": [], "images": []}

    # Get containers
    ps_result = pool.run_parallel(targets, "docker ps --format '{{json .}}'")
    containers = parse_docker_ps(ps_result[host].stdout) if ps_result[host].success else []

    # Get images
    images_result = pool.run_parallel(targets, "docker images --format '{{json .}}'")
    images = parse_docker_images(images_result[host].stdout) if images_result[host].success else []

    return {"containers": containers, "images": images}


async def discover_docker_all() -> dict:
    """Discover Docker on all configured Proxmox nodes and their VMs/LXCs."""
    results = {}

    for node_config in settings.proxmox_nodes:
        if not node_config.ssh_host:
            continue

        # Discover on Proxmox node itself
        host_result = await discover_docker_on_host(
            node_config.ssh_host,
            node_config.ssh_port,
            node_config.ssh_user,
            node_config.ssh_key_path,
            node_config.ssh_known_hosts,
        )
        results[f"{node_config.name} (host)"] = host_result

        # TODO: Discover on VMs/LXCs - would need IP addresses from inventory

    return results