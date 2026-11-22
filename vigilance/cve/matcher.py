import json
import logging
import re
from dataclasses import dataclass
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


def parse_debian_version(version: str) -> Optional[Version]:
    """Parse Debian version format (e.g., 1.2.3-4+deb11u1)."""
    try:
        # Remove epoch if present (e.g., 1:1.2.3 -> 1.2.3)
        if ":" in version:
            version = version.split(":", 1)[1]
        return Version(version)
    except InvalidVersion:
        # Try to normalize
        normalized = re.sub(r"[+-].*$", "", version)
        try:
            return Version(normalized)
        except InvalidVersion:
            return None


def parse_semver(version: str) -> Optional[Version]:
    """Parse SemVer version."""
    try:
        return Version(version)
    except InvalidVersion:
        return None


def check_version_in_range(detected_version: str, range_obj: AffectedRange) -> VersionMatch:
    """Check if a detected version falls within an affected range."""
    if range_obj.type == "DEBIAN":
        detected = parse_debian_version(detected_version)
        introduced = parse_debian_version(range_obj.introduced) if range_obj.introduced else None
        fixed = parse_debian_version(range_obj.fixed) if range_obj.fixed else None
        last_affected = parse_debian_version(range_obj.last_affected) if range_obj.last_affected else None
    else:
        # Default to SemVer
        detected = parse_semver(detected_version)
        introduced = parse_semver(range_obj.introduced) if range_obj.introduced else None
        fixed = parse_semver(range_obj.fixed) if range_obj.fixed else None
        last_affected = parse_semver(range_obj.last_affected) if range_obj.last_affected else None

    if not detected:
        return VersionMatch(affected=False, details={"error": "Could not parse detected version"})

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

        # Match by package name / CPE
        if range_repo:
            if range_repo in tool_name or tool_name in range_repo:
                pass  # Good match
            elif range_repo in cpe_name:
                pass  # Good match
            elif package_manager in ["dpkg", "apt"] and range_obj.type == "DEBIAN":
                pass  # Debian package match
            elif package_manager in ["apk"] and range_obj.type == "ECOSYSTEM":
                pass  # Alpine package match
            elif package_manager in ["docker"] and range_obj.type in ["ECOSYSTEM", "CPE"]:
                pass  # Docker image match
            else:
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
