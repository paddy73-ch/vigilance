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


# ---------------------------------------------------------------- packages from vendor repositories
#
# Some software is installed from the vendor's own apt repository (pkgs.tailscale.com,
# download.docker.com, packagecloud). Debian has no advisories for it ("NOT-FOR-US"), but the
# Go vulnerability data does, keyed on the Go module. The deb version maps to the module version.
# Only packages where that mapping is reliable are listed. Not here on purpose: docker-ce - the
# advisories on github.com/docker/docker have no fixed version (every version would match) and
# Docker 29 versions do not map to the github.com/moby/moby/v2 module versions.
VENDOR_GO_MODULES = {
    "tailscale": "tailscale.com",
    "crowdsec": "github.com/crowdsecurity/crowdsec",
    "containerd.io": "github.com/containerd/containerd",  # + /vN for major versions >= 2
}
_MAJOR_SUFFIX = {"containerd.io"}


def upstream_version(deb_version: str) -> str:
    """5:29.10.0-1~debian.13~trixie -> 29.10.0; 1.90.6 -> 1.90.6"""
    v = deb_version.split(":", 1)[-1]
    return v.split("-", 1)[0].split("~", 1)[0]


def vendor_go_module(package: Optional[str], deb_version: Optional[str]) -> Optional[tuple]:
    """(Go module, module version) for a package from a vendor repository, or None."""
    module = VENDOR_GO_MODULES.get(package or "")
    if not module or not deb_version:
        return None
    version = upstream_version(deb_version)
    if not version or not version[0].isdigit():
        return None
    if package in _MAJOR_SUFFIX:
        major = version.split(".")[0]
        if major.isdigit() and int(major) >= 2:
            module = f"{module}/v{major}"
    return module, version
