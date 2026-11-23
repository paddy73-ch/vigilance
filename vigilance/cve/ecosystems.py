"""Map discovered packages to advisory-database ecosystems.

OSV ecosystems are release specific (``Debian:13``, ``Alpine:v3.20``,
``Ubuntu:24.04:LTS``). Querying the bare ``Debian`` ecosystem evaluates a
package against the fix in *unstable*, which reports stable packages as
vulnerable although the security team already fixed them.
"""

from typing import Optional

# package_manager values of tools that GHSA covers -> GHSA ecosystem names
GHSA_ECOSYSTEMS = {
    "pip": "pip",
    "pypi": "pip",
    "npm": "npm",
    "gem": "rubygems",
    "rubygems": "rubygems",
    "cargo": "rust",
    "rust": "rust",
    "go": "go",
    "maven": "maven",
    "nuget": "nuget",
    "composer": "composer",
    "pub": "pub",
    "hex": "erlang",
    "swift": "swift",
}


def _ubuntu_is_lts(version: str) -> bool:
    # Ubuntu LTS releases are the .04 releases of even years (20.04, 22.04, 24.04, 26.04).
    try:
        year, month = version.split(".")[:2]
        return month == "04" and int(year) % 2 == 0
    except ValueError:
        return False


def osv_ecosystem(package_manager: Optional[str], os_id: Optional[str], os_version_id: Optional[str],
                  is_lts: Optional[bool] = None) -> Optional[str]:
    """Return the release-specific OSV ecosystem, or None if it cannot be determined."""
    pm = (package_manager or "").lower()
    os_id = (os_id or "").lower()
    version = (os_version_id or "").strip()
    if not version:
        return None
    if pm == "dpkg" and os_id == "debian":
        return f"Debian:{version.split('.')[0]}"
    if pm == "dpkg" and os_id == "ubuntu":
        lts = _ubuntu_is_lts(version) if is_lts is None else is_lts
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    if pm == "apk" and os_id == "alpine":
        major_minor = ".".join(version.split(".")[:2])
        return f"Alpine:v{major_minor}"
    return None


def ghsa_ecosystem(package_manager: Optional[str]) -> Optional[str]:
    return GHSA_ECOSYSTEMS.get((package_manager or "").lower())
