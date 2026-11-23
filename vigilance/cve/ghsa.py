"""GitHub Security Advisories (global advisory database, REST API).

Advisories are requested per ecosystem with the ``affects`` parameter
(``name@version``), so GitHub only returns advisories that affect exactly
the discovered package versions. GHSA covers language ecosystems (pip, npm,
Go, Maven, ...), not distribution packages such as dpkg/apk.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.config import settings
from vigilance.cve.cvss import cvss3_base_score, score_to_severity
from vigilance.cve.ecosystems import ghsa_ecosystem
from vigilance.cve.models import AffectedRange, CVEData, Reference

logger = logging.getLogger(__name__)

# (GHSA ecosystem, package name, version)
QueryKey = Tuple[str, str, str]

# Keep URLs short; each chunk lists a package name at most once so that a
# returned advisory can be attributed to exactly one name@version.
AFFECTS_CHUNK = 100


def tool_query_key(tool) -> Optional[QueryKey]:
    ecosystem = ghsa_ecosystem(tool.package_manager)
    if not ecosystem or not tool.tool_name or not tool.detected_version:
        return None
    return ecosystem, tool.tool_name, tool.detected_version


@dataclass
class GHSASyncOutcome:
    cves: List[CVEData] = field(default_factory=list)
    matches: Dict[QueryKey, Set[str]] = field(default_factory=dict)  # query key -> GHSA ids
    queried: int = 0


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt
    except ValueError:
        return None


def parse_advisory(node: dict) -> Optional[CVEData]:
    """Convert a REST global advisory into CVEData (id = GHSA id, CVE id in the title)."""
    ghsa_id = node.get("ghsa_id")
    if not ghsa_id:
        return None

    cvss_vector = None
    cvss_score = None
    for key in ("cvss_v3", "cvss"):
        data = (node.get("cvss_severities") or {}).get(key) if key == "cvss_v3" else node.get(key)
        if data and data.get("vector_string"):
            cvss_vector = data["vector_string"]
            cvss_score = data.get("score") or cvss3_base_score(cvss_vector)
            break
    severity = score_to_severity(cvss_score) if cvss_score else None
    if not severity and node.get("severity"):
        severity = {"moderate": "MEDIUM"}.get(node["severity"].lower(), node["severity"].upper())

    ranges = []
    for vuln in node.get("vulnerabilities", []) or []:
        pkg = vuln.get("package") or {}
        first_patched = vuln.get("first_patched_version")
        if isinstance(first_patched, dict):  # GraphQL shape
            first_patched = first_patched.get("identifier")
        ranges.append(AffectedRange(
            type="ECOSYSTEM",
            introduced="0",
            fixed=first_patched,
            repo=pkg.get("name"),
            ecosystem=pkg.get("ecosystem"),
            events=[{"vulnerable_version_range": vuln.get("vulnerable_version_range")}],
        ))

    refs = [Reference(url=ref, type="ADVISORY") for ref in node.get("references", []) or [] if isinstance(ref, str)]
    if node.get("html_url"):
        refs.insert(0, Reference(url=node["html_url"], type="ADVISORY"))

    cve_id = node.get("cve_id")
    summary = node.get("summary")
    title = f"{cve_id}: {summary}" if cve_id and summary else (summary or cve_id)

    return CVEData(
        cve_id=ghsa_id,
        source="ghsa",
        title=title[:512] if title else None,
        description=node.get("description"),
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        affected_ranges=ranges,
        references=refs,
        published_at=_parse_date(node.get("published_at")),
        modified_at=_parse_date(node.get("updated_at")),
        raw_data=node,
    )


class GHSAClient:
    BASE_URL = "https://api.github.com/advisories"

    def __init__(self):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vigilance-cve-sync",
        }
        github_token = getattr(settings, "github_token", "") or getattr(settings, "ghsa_token", "")
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        self.client = httpx.AsyncClient(timeout=30.0, headers=headers)

    async def close(self):
        await self.client.aclose()

    @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(3), reraise=True)
    async def _get(self, url: str, params: Optional[dict] = None) -> httpx.Response:
        response = await self.client.get(url, params=params)
        if response.status_code >= 400:
            logger.error("GitHub API returned HTTP %s: %s", response.status_code, response.text[:200])
        response.raise_for_status()
        return response

    async def advisories_affecting(self, ecosystem: str, packages: List[Tuple[str, str]]) -> List[dict]:
        """List advisories affecting any of the given (name, version) pairs (follows Link pagination)."""
        params: Optional[dict] = {
            "ecosystem": ecosystem,
            "affects": ",".join(f"{name}@{version}" for name, version in packages),
            "per_page": 100,
        }
        url: Optional[str] = self.BASE_URL
        advisories: List[dict] = []
        while url:
            response = await self._get(url, params)
            data = response.json()
            if not isinstance(data, list):
                raise RuntimeError("GitHub advisories returned a non-list response")
            advisories.extend(data)
            url = response.links.get("next", {}).get("url")
            params = None  # the next link already carries all query parameters
        return advisories


def _chunks(keys: List[QueryKey]) -> Iterable[List[QueryKey]]:
    """Group keys per ecosystem into chunks with unique package names."""
    by_ecosystem: Dict[str, List[QueryKey]] = defaultdict(list)
    for key in keys:
        by_ecosystem[key[0]].append(key)
    for eco_keys in by_ecosystem.values():
        remaining = sorted(eco_keys)
        while remaining:
            chunk, rest, names = [], [], set()
            for key in remaining:
                if key[1] not in names and len(chunk) < AFFECTS_CHUNK:
                    chunk.append(key)
                    names.add(key[1])
                else:
                    rest.append(key)
            yield chunk
            remaining = rest


async def sync_ghsa_for_tools(tools: Iterable) -> GHSASyncOutcome:
    """Query GHSA only for discovered packages of GHSA-covered ecosystems."""
    outcome = GHSASyncOutcome()
    keys = sorted({k for k in (tool_query_key(t) for t in tools) if k})
    outcome.queried = len(keys)
    if not keys:
        return outcome

    client = GHSAClient()
    try:
        found: Dict[str, CVEData] = {}
        for chunk in _chunks(keys):
            ecosystem = chunk[0][0]
            by_name = {name.lower(): (ecosystem, name, version) for _, name, version in chunk}
            for node in await client.advisories_affecting(ecosystem, [(n, v) for _, n, v in chunk]):
                cve = parse_advisory(node)
                if not cve:
                    continue
                found[cve.cve_id] = cve
                for r in cve.affected_ranges:
                    key = by_name.get((r.repo or "").lower())
                    if key and (r.ecosystem or ecosystem) == ecosystem:
                        outcome.matches.setdefault(key, set()).add(cve.cve_id)
        outcome.cves = list(found.values())
        logger.info("GHSA: %d package versions queried, %d advisories", outcome.queried, len(outcome.cves))
        return outcome
    finally:
        await client.close()
