import logging
import paramiko
import shlex
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable
import threading

from vigilance.config import settings

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    host: str
    command: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool


AUTH_REJECTED = "SSH-Anmeldung abgelehnt"

DEFAULT_KEY_PATH = "/app/data/ssh/id_rsa"
DEFAULT_KNOWN_HOSTS = "/app/data/ssh/known_hosts"

# Containers reached through the Proxmox host ("pct exec") get this pseudo address instead of an IP.
PCT_PREFIX = "pct:"
PCT_COMMAND = "/usr/sbin/pct"
# sshd allows 10 sessions per connection by default (MaxSessions); all containers of a node share one
PCT_MAX_SESSIONS = 8
PCT_SUDO_MISSING = ("sudo-Regel für pct exec fehlt auf dem Proxmox-Host: Der Scan-Benutzer darf "
                    "„pct exec“ nicht als root ausführen (README, Abschnitt Zugang zu Containern)")


def pct_host(node_name: str, vmid: int) -> str:
    return f"{PCT_PREFIX}{node_name}:{int(vmid)}"


def parse_pct_host(host: str):
    """("pve", 124) for "pct:pve:124", else None."""
    if not host or not host.startswith(PCT_PREFIX):
        return None
    node, _, vmid = host[len(PCT_PREFIX):].rpartition(":")
    return (node, int(vmid)) if node and vmid.isdigit() else None


def describe_connect_error(e: Exception, host: str, port: int) -> str:
    """Short German reason for a failed SSH connect, shown in the UI."""
    if isinstance(e, paramiko.AuthenticationException):
        return (AUTH_REJECTED + ": Der Schlüssel von Vigilance ist auf dem Host nicht eingetragen "
                "(Verwaltung › Einstellungen)")
    if isinstance(e, paramiko.BadHostKeyException):
        return f"SSH-Host-Schlüssel von {host} hat sich geändert"
    if isinstance(e, paramiko.SSHException) and "not found in known_hosts" in str(e):
        return f"SSH-Host-Schlüssel von {host} ist unbekannt"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return f"Keine Antwort von {host} (Port {port})"
    if isinstance(e, (paramiko.ssh_exception.NoValidConnectionsError, ConnectionError, OSError)):
        return f"Keine SSH-Verbindung zu {host} (Port {port})"
    return f"SSH-Verbindung zu {host} fehlgeschlagen"


class SSHClient:
    def __init__(self, host: str, port: int, user: str, key_path: str, known_hosts: str, timeout: int = 30):
        self.host = host
        self.port = port
        self.user = user
        self.key_path = key_path
        self.known_hosts = known_hosts
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self.last_error: Optional[str] = None
        self._lock = threading.Lock()

    def connect(self) -> bool:
        with self._lock:
            if self._client and self._client.get_transport() and self._client.get_transport().is_active():
                return True

            try:
                self._client = paramiko.SSHClient()
                self._client.load_host_keys(self.known_hosts)
                if settings.discovery and settings.discovery.ssh_strict_host_key_checking:
                    self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
                else:
                    self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                key = paramiko.Ed25519Key.from_private_key_file(self.key_path)
                self._client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.user,
                    pkey=key,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                )
                return True
            except Exception as e:
                logger.error(f"SSH connection failed to {self.host}: {e}")
                self.last_error = describe_connect_error(e, self.host, self.port)
                self._client = None
                return False

    def disconnect(self):
        with self._lock:
            if self._client:
                self._client.close()
                self._client = None

    def run_command(self, command: str, timeout: Optional[int] = None) -> CommandResult:
        if not self.connect():
            return CommandResult(
                host=self.host,
                command=command,
                stdout="",
                stderr=self.last_error or f"Keine SSH-Verbindung zu {self.host}",
                exit_code=-1,
                success=False,
            )

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout or self.timeout)
            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            return CommandResult(
                host=self.host,
                command=command,
                stdout=stdout_text.strip(),
                stderr=stderr_text.strip(),
                exit_code=exit_code,
                success=exit_code == 0,
            )
        except socket.timeout:
            return CommandResult(
                host=self.host,
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout or self.timeout}s",
                exit_code=-1,
                success=False,
            )
        except Exception as e:
            logger.error(f"Command failed on {self.host}: {e}")
            return CommandResult(
                host=self.host,
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                success=False,
            )


class PctClient:
    """Runs commands in a container with `sudo pct exec <vmid> -- sh -c …` over the SSH connection to its
    Proxmox host. Same interface as SSHClient, so every discovery module and the actions use it as is."""

    def __init__(self, label: str, node_client: "SSHClient", vmid: int, slots: threading.BoundedSemaphore):
        self.host = label
        self.vmid = int(vmid)
        self._node = node_client
        self._slots = slots

    @property
    def last_error(self) -> Optional[str]:
        return self._node.last_error

    def connect(self) -> bool:
        return self._node.connect()

    def disconnect(self):
        pass  # the connection to the Proxmox host is shared with the other containers

    def run_command(self, command: str, timeout: Optional[int] = None) -> CommandResult:
        wrapped = f"sudo -n {PCT_COMMAND} exec {self.vmid} -- sh -c {shlex.quote(command)}"
        with self._slots:
            res = self._node.run_command(wrapped, timeout)
        res.host, res.command = self.host, command
        if not res.success:
            err = res.stderr or ""
            if err.startswith("sudo:"):
                res.stderr = PCT_SUDO_MISSING
            elif f"container '{self.vmid}' not running" in err:
                res.stderr = f"Container {self.vmid} läuft nicht"
            elif err.startswith("Configuration file") and "does not exist" in err:
                res.stderr = f"Container {self.vmid} gibt es auf dem Proxmox-Host nicht"
        return res


class SSHClientPool:
    def __init__(self, max_workers: int = 10):
        self._max_workers = max_workers
        self._clients: Dict[str, SSHClient] = {}
        self._pct_slots: Dict[str, threading.BoundedSemaphore] = {}
        self._lock = threading.Lock()

    @property
    def max_workers(self) -> int:
        return settings.ssh_parallel_jobs or self._max_workers

    def get_client(self, host: str, port: int, user: str, key_path: str, known_hosts: str, timeout: int) -> SSHClient:
        pct = parse_pct_host(host)
        if pct:
            return self._pct_client(host, *pct, timeout)
        key = f"{host}:{port}:{user}"
        with self._lock:
            if key not in self._clients:
                self._clients[key] = SSHClient(host, port, user, key_path, known_hosts, timeout)
            return self._clients[key]

    def _pct_client(self, label: str, node_name: str, vmid: int, timeout: int):
        """Container `vmid` through its Proxmox host: SSH as the host user (vigilance-scan), then pct exec."""
        cfg = next((c for c in settings.proxmox_nodes if c.name == node_name), None)
        if not cfg or not cfg.ssh_host:
            raise RuntimeError(f"Kein SSH-Zugang zum Proxmox-Host {node_name} konfiguriert")
        node_client = self.get_client(cfg.ssh_host, cfg.ssh_port or 22, cfg.host_user,
                                      cfg.ssh_key_path or DEFAULT_KEY_PATH,
                                      cfg.ssh_known_hosts or DEFAULT_KNOWN_HOSTS, timeout)
        with self._lock:
            slots = self._pct_slots.setdefault(node_name, threading.BoundedSemaphore(PCT_MAX_SESSIONS))
        return PctClient(label, node_client, vmid, slots)

    def run_parallel(
        self,
        targets: List[dict],
        command: str,
        timeout: Optional[int] = None,
    ) -> Dict[str, CommandResult]:
        results = {}
        effective_timeout = timeout or settings.ssh_timeout or 30

        def run_on_target(target):
            client = self.get_client(
                target["host"],
                target.get("port", 22),
                target.get("user", "root"),
                target["key_path"],
                target["known_hosts"],
                target.get("timeout", effective_timeout),
            )
            return client.run_command(command, timeout)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {executor.submit(run_on_target, t): t for t in targets}
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results[target["host"]] = result
                except Exception as e:
                    logger.error(f"Parallel command failed on {target['host']}: {e}")
                    results[target["host"]] = CommandResult(
                        host=target["host"],
                        command=command,
                        stdout="",
                        stderr=str(e),
                        exit_code=-1,
                        success=False,
                    )
        return results

    def close_all(self):
        with self._lock:
            for client in self._clients.values():
                client.disconnect()
            self._clients.clear()


# Global pool instance
ssh_pool = SSHClientPool()


def get_ssh_pool() -> SSHClientPool:
    return ssh_pool