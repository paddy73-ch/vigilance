"""Vigilance's own SSH key (per instance, generated on first use, never in the repository).

Distributing the public key to the LXCs is done outside Vigilance (Ansible).
"""

import logging
import os
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SSH_DIR = Path("/app/data/ssh")
SSH_PRIVATE_KEY = SSH_DIR / "id_rsa"  # historical file name; the key type is ed25519
SSH_PUBLIC_KEY = SSH_DIR / "id_rsa.pub"


def _comment() -> str:
    return f"vigilance@{socket.gethostname()}"


def _generate(private_key: Path) -> None:
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", _comment(), "-f", str(private_key)],
        check=True,
    )


def ensure_ssh_key(private_key: Path = SSH_PRIVATE_KEY, public_key: Path = SSH_PUBLIC_KEY) -> str:
    """Return the public key; generate a key pair only if none exists. Never overwrites a key."""
    private_key.parent.mkdir(parents=True, exist_ok=True)
    if not private_key.exists():
        logger.warning("No SSH key at %s - generating a new ed25519 key", private_key)
        _generate(private_key)
    if not public_key.exists():
        pub = subprocess.run(["ssh-keygen", "-y", "-f", str(private_key)], check=True,
                             capture_output=True, text=True).stdout.strip()
        public_key.write_text(pub + "\n")
    os.chmod(private_key, 0o600)
    return public_key.read_text().strip()


def rotate_ssh_key(private_key: Path = SSH_PRIVATE_KEY, public_key: Path = SSH_PUBLIC_KEY) -> str:
    """Move the current key aside (*.old-<timestamp>) and generate a new one. Returns the new public key."""
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    for path in (private_key, public_key):
        if path.exists():
            shutil.move(str(path), f"{path}.old-{stamp}")
    _generate(private_key)
    return ensure_ssh_key(private_key, public_key)
