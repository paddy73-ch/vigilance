import json
import logging
import re
from dataclasses import dataclass
from functools import total_ordering
from typing import List, Optional

from packaging.version import Version, InvalidVersion

from vigilance.cve.models import CVEData, AffectedRange, MatchResult
from vigilance.config import settings

logger = logging.getLogger(__name__)


@dataclass
class VersionMatch:
    affected: bool
    fixed_version: Optional[str] = None
    details: dict = None


def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    """Compare two upstream/revision strings like dpkg's verrevcmp()."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


@total_ordering
class DebianVersion:
    """Debian package version ([epoch:]upstream[-revision]) with dpkg ordering."""

    def __init__(self, version: str):
        version = version.strip()
        if not version:
            raise ValueError("empty version")
        epoch, sep, rest = version.partition(":")
        if sep and epoch.isdigit():
            self.epoch = int(epoch)
        else:
            self.epoch = 0
            rest = version
        upstream, sep, revision = rest.rpartition("-")
        if not sep:
            upstream, revision = rest, ""
        if not upstream or not upstream[0].isdigit():
            raise ValueError(f"invalid Debian version: {version!r}")
        self.upstream = upstream
        self.revision = revision
        self.original = version

    def _cmp(self, other: "DebianVersion") -> int:
        if self.epoch != other.epoch:
            return self.epoch - other.epoch
        res = _dpkg_verrevcmp(self.upstream, other.upstream)
        if res:
            return res
        return _dpkg_verrevcmp(self.revision, other.revision)

    def __eq__(self, other):
        if not isinstance(other, DebianVersion):
            return NotImplemented
        return self._cmp(other) == 0

    def __lt__(self, other):
        if not isinstance(other, DebianVersion):
            return NotImplemented
        return self._cmp(other) < 0

    def __hash__(self):
        return hash((self.epoch, self.upstream, self.revision))

    def __str__(self):
        return self.original

    def __repr__(self):
        return f"DebianVersion({self.original!r})"


def compare_debian_versions(a: str, b: str) -> int:
    """Return <0, 0 or >0 like `dpkg --compare-versions`."""
    return DebianVersion(a)._cmp(DebianVersion(b))


def parse_debian_version(version: str) -> Optional[DebianVersion]:
    """Parse a Debian/Ubuntu version (e.g. 1:1.2.3-4+deb12u1, 1.25.0-2ubuntu1).

    Unlike PEP 440 parsing this keeps the Debian revision, which is where
    security fixes usually land (e.g. ``+deb12u6`` -> ``+deb12u7``).
    """
    try:
        return DebianVersion(version)
    except (ValueError, AttributeError):
        return None


def parse_semver(version: str) -> Optional[Version]:
    """Parse SemVer version."""
    try:
        return Version(version)
    except InvalidVersion:
        return None


def check_version_in_range(detected_version: str, range_obj: AffectedRange) -> VersionMatch:
    """Check if a detected version falls within an affected range."""
    # DEBIAN and UBUNTU use the same version format
    ecosystem = (getattr(range_obj, "ecosystem", None) or "").lower()
    if range_obj.type in ("DEBIAN", "UBUNTU") or ecosystem.startswith(("debian", "ubuntu")):
        detected = parse_debian_version(detected_version)
        introduced = parse_debian_version(range_obj.introduced) if range_obj.introduced else None
        fixed = parse_debian_version(range_obj.fixed) if range_obj.fixed else None
        last_affected = parse_debian_version(range_obj.last_affected) if range_obj.last_affected else None
    else:
        # Default to SemVer for CPE, ECOSYSTEM, etc.
        detected = parse_semver(detected_version)
        introduced = parse_semver(range_obj.introduced) if range_obj.introduced else None
        fixed = parse_semver(range_obj.fixed) if range_obj.fixed else None
        last_affected = parse_semver(range_obj.last_affected) if range_obj.last_affected else None

    if not detected:
        return VersionMatch(affected=False, details={"error": "Could not parse detected version"})

    # If no fixed version and no last_affected, we can't determine if version is affected
    # Skip this range (return not affected)
    if fixed is None and last_affected is None:
        return VersionMatch(
            affected=False,
            details={"reason": "No fixed or last_affected version specified, cannot determine if affected"}
        )

    # Check if version >= introduced
    if introduced and detected < introduced:
        return VersionMatch(affected=False, details={"reason": f"Version {detected_version} < introduced {introduced}"})

    # Check if version < fixed (fixed is the first non-affected version)
    if fixed and detected >= fixed:
        return VersionMatch(
            affected=False,
            fixed_version=str(fixed),
            details={"reason": f"Version {detected_version} >= fixed {fixed}"}
        )

    # Check last_affected (inclusive upper bound)
    if last_affected and detected > last_affected:
        return VersionMatch(
            affected=False,
            details={"reason": f"Version {detected_version} > last_affected {last_affected}"}
        )

    # Version is affected
    return VersionMatch(
        affected=True,
        fixed_version=range_obj.fixed,
        details={
            "detected_version": detected_version,
            "introduced": str(introduced) if introduced else "0",
            "fixed": range_obj.fixed,
            "last_affected": str(last_affected) if last_affected else None,
            "range_type": range_obj.type,
        }
    )


def _extract_package_from_cpe(cpe: str) -> str:
    """Extract package name from CPE string (e.g., cpe:2.3:a:gnu:wget:1.5.3 -> wget)."""
    # CPE format: cpe:2.3:part:vendor:product:version:...
    parts = cpe.split(":")
    if len(parts) >= 5:
        return parts[4].lower()  # product name
    return cpe.lower()


def _extract_version_from_cpe(cpe: str) -> Optional[str]:
    """Extract version from CPE string (e.g., cpe:2.3:a:gnu:wget:1.5.3 -> 1.5.3)."""
    # CPE format: cpe:2.3:part:vendor:product:version:...
    parts = cpe.split(":")
    if len(parts) >= 6:
        version = parts[5]
        if version and version != "*":
            return version
    return None


def match_tool_against_cves(tool, cve: CVEData) -> MatchResult:
    """Match a discovered tool against a CVE entry."""
    detected_version = tool.detected_version
    if not detected_version:
        return MatchResult(
            affected=False,
            details={"error": "No version detected for tool"}
        )

    tool_name = tool.tool_name.lower()
    cpe_name = (tool.cpe_name or "").lower()
    package_manager = (tool.package_manager or "").lower()

    # Database CVEs store ranges as JSON; sync results already contain objects.
    ranges = cve.affected_ranges
    if isinstance(ranges, str):
        try:
            ranges = json.loads(ranges)
        except json.JSONDecodeError:
            ranges = []

    # Check each affected range
    for raw_range in ranges or []:
        range_obj = raw_range if isinstance(raw_range, AffectedRange) else AffectedRange(**raw_range)
        # Check if this range applies to our tool
        range_repo = (range_obj.repo or "").lower()

        # Match by package name / CPE - stricter matching
        if range_repo:
            matched = False
            if range_obj.type == "CPE":
                # Extract package name from CPE
                cpe_package = _extract_package_from_cpe(range_repo)
                cpe_version = _extract_version_from_cpe(range_repo)
                
                # Check package name match
                if cpe_package == tool_name or cpe_package in cpe_name:
                    # If CPE has a specific version, check if detected version matches
                    if cpe_version:
                        # CPE version is specific - only match if detected version equals it
                        if cpe_version == detected_version or cpe_version in detected_version:
                            matched = True
                    else:
                        # CPE version is * (any) or not specified - match any version
                        matched = True
            elif range_obj.type in ("DEBIAN", "UBUNTU", "ECOSYSTEM"):
                # Exact match for package name
                if range_repo == tool_name:
                    matched = True
                # Also check CPE name for docker/containers
                elif range_repo in cpe_name:
                    matched = True
            else:
                # Fallback: substring match (legacy behavior)
                if range_repo in tool_name or tool_name in range_repo:
                    matched = True
                elif range_repo in cpe_name:
                    matched = True

            if not matched:
                continue  # Range doesn't apply to this tool

        match = check_version_in_range(detected_version, range_obj)
        if match.affected:
            return MatchResult(
                affected=True,
                fixed_version=match.fixed_version,
                details=match.details,
            )

    return MatchResult(affected=False, details={"reason": "No matching affected range found"})


def get_best_cpe_for_tool(tool_name: str, package_manager: str) -> str:
    """Get the best CPE name for a tool, checking overrides first."""
    # This would check the database for tool_overrides
    # For now, return a basic CPE
    if package_manager == "docker":
        return f"cpe:2.3:a:{tool_name}:{tool_name}"
    elif package_manager in ["dpkg", "apt", "apk", "rpm"]:
        return f"cpe:2.3:a:{tool_name}:{tool_name}"
    return f"cpe:2.3:a:{tool_name}:{tool_name}"
