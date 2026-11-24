"""Operating-system restrictions of advisories.

All scanned hosts run Linux (LXC containers, the Proxmox host). Some advisories only affect
other systems, e.g. CVE-2023-28436 (Tailscale SSH on FreeBSD).

Two levels, on purpose:

* ``goos_restriction``: structured data. Reviewed entries of the Go vulnerability database list
  the affected systems in ``affected[].ecosystem_specific.imports[].goos``. If that list exists
  for every import and does not contain linux, the finding is "not_affected" (filtered, with the
  reason shown). Entries without the field are never filtered - it is missing on many
  OS-specific entries too (e.g. GO-2023-2186, Windows only).
* ``os_hint``: the title names another system ("... on FreeBSD"). Only shown as a hint with a
  one-click exception; a text match is not reliable enough to hide a finding.
"""

import json
import re
from typing import Dict, Iterable, Optional, Set

HOST_GOOS = "linux"

_OS_NAMES = {
    "freebsd": "FreeBSD", "openbsd": "OpenBSD", "netbsd": "NetBSD", "dragonfly": "DragonFly BSD",
    "windows": "Windows", "darwin": "macOS", "macos": "macOS", "ios": "iOS", "android": "Android",
    "illumos": "illumos", "solaris": "Solaris", "aix": "AIX", "plan9": "Plan 9", "js": "JavaScript/WASM",
    "wasip1": "WASI", "linux": "Linux",
}
_HINT_RE = re.compile(
    r"\b(?:on|for|in|under)\s+(FreeBSD|OpenBSD|NetBSD|Windows|macOS|Mac OS|Darwin|iOS|Android|illumos|Solaris|AIX)\b",
    re.IGNORECASE,
)


def os_label(goos: str) -> str:
    return _OS_NAMES.get(goos.lower(), goos)


def goos_restriction(raw: dict, package: Optional[str] = None) -> Optional[Set[str]]:
    """Operating systems an OSV record is restricted to for this package, or None (no restriction known)."""
    found = None
    for affected in raw.get("affected", []) or []:
        if package and (affected.get("package") or {}).get("name") != package:
            continue
        imports = (affected.get("ecosystem_specific") or {}).get("imports") or []
        if not imports:
            return None
        systems: Set[str] = set()
        for imp in imports:
            goos = imp.get("goos")
            if not goos:
                return None  # at least one import affects every system
            systems.update(g.lower() for g in goos)
        found = (found or set()) | systems
    return found


def raw_of(cve) -> dict:
    try:
        return json.loads(getattr(cve, "raw_data", None) or "{}")
    except (TypeError, ValueError):
        return {}


def restriction_map(cves: Iterable, key_of) -> Dict[tuple, Set[str]]:
    """{(vulnerability key, package): systems} from all records that carry a goos restriction.

    Used so that a GHSA record (which has no such field) inherits the restriction of the
    GO-… record for the same CVE.
    """
    result: Dict[tuple, Set[str]] = {}
    for cve in cves:
        raw = raw_of(cve)
        if not raw.get("affected"):
            continue
        key = key_of(cve)
        if not key:
            continue
        for affected in raw["affected"]:
            package = (affected.get("package") or {}).get("name")
            systems = goos_restriction(raw, package)
            if systems:
                result[(key, package)] = systems
    return result


def not_for_host(systems: Optional[Set[str]]) -> bool:
    return bool(systems) and HOST_GOOS not in systems


def os_hint(*texts: Optional[str]) -> Optional[str]:
    """'FreeBSD' if a text says the issue is limited to another system, else None.

    Texts are checked in order (title before description); a text that also names Linux gives no hint.
    """
    for text in texts:
        if not text or re.search(r"\blinux\b", text, re.IGNORECASE):
            continue
        m = _HINT_RE.search(text)
        if m:
            name = m.group(1)
            return {"mac os": "macOS", "darwin": "macOS"}.get(name.lower(), _OS_NAMES.get(name.lower(), name))
    return None
