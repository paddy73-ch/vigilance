"""OSV.dev client.

Only the package versions that were actually discovered are queried, using
``/v1/querybatch`` with release-specific ecosystems (``Debian:13`` etc.).
OSV evaluates the version server-side, so every returned vulnerability is a
direct match for that package version. Full records are fetched from
``/v1/vulns/{id}`` only when they are new or were modified since the last sync.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.cve.cvss import cvss3_base_score, score_to_severity
from vigilance.cve.ecosystems import osv_ecosystem
from vigilance.cve.models import AffectedRange, CVEData, Reference

logger = logging.getLogger(__name__)

# (ecosystem, package name, version)
QueryKey = Tuple[str, str, str]

QUERYBATCH_MAX = 1000

# Bump when parse_vuln() changes so stored records are re-downloaded and re-parsed.
OSV_PARSER_VERSION = 2
PARSER_MARKER = f'"_vigilance_parser": {OSV_PARSER_VERSION}'
DETAIL_CONCURRENCY = 20

# Debian security tracker urgency -> severity (used when no CVSS v3 vector is present)
_URGENCY_SEVERITY = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "unimportant": "LOW",
}


def tool_query_key(tool) -> Optional[QueryKey]:
    """Build the OSV query key for a discovered tool, or None if OSV cannot be queried for it."""
    inventory = getattr(tool, "inventory", None)
    ecosystem = osv_ecosystem(
        tool.package_manager,
        getattr(inventory, "os_id", None),
        getattr(inventory, "os_version_id", None),
    )
    if not ecosystem:
        return None
    name = getattr(tool, "source_name", None) or tool.tool_name
    version = getattr(tool, "source_version", None) or tool.detected_version
    if not name or not version:
        return None
    return ecosystem, name, version


@dataclass
class OSVSyncOutcome:
    cves: List[CVEData] = field(default_factory=list)  # new or modified records only
    matches: Dict[QueryKey, Set[str]] = field(default_factory=dict)  # query key -> OSV ids
    queried: int = 0
    skipped_tools: int = 0


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt
    except ValueError:
        return None


def parse_vuln(vuln: dict) -> Optional[CVEData]:
    """Convert an OSV record into CVEData."""
    vuln_id = vuln.get("id")
    if not vuln_id:
        return None

    cvss_vector = None
    cvss_score = None
    for sev in vuln.get("severity", []) or []:
        if sev.get("type") == "CVSS_V3" and sev.get("score"):
            cvss_vector = sev["score"]
            cvss_score = cvss3_base_score(cvss_vector)
            break
    severity = score_to_severity(cvss_score)

    ranges: List[AffectedRange] = []
    urgencies = []
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package", {}) or {}
        urgency = (affected.get("ecosystem_specific") or {}).get("urgency")
        if urgency:
            urgencies.append(urgency.lower())
        for r in affected.get("ranges", []) or []:
            events = r.get("events", []) or []
            # Split event lists into introduced/fixed (or last_affected) segments
            introduced = "0"
            open_segment = False
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                    open_segment = True
                elif "fixed" in event or "last_affected" in event:
                    ranges.append(AffectedRange(
                        type=r.get("type", "ECOSYSTEM"),
                        introduced=introduced,
                        fixed=event.get("fixed"),
                        last_affected=event.get("last_affected"),
                        repo=pkg.get("name"),
                        ecosystem=pkg.get("ecosystem"),
                        events=events,
                    ))
                    open_segment = False
            if open_segment:
                # Affected with no fix available yet
                ranges.append(AffectedRange(
                    type=r.get("type", "ECOSYSTEM"),
                    introduced=introduced,
                    repo=pkg.get("name"),
                    ecosystem=pkg.get("ecosystem"),
                    events=events,
                ))

    if not severity:
        severity = (vuln.get("database_specific") or {}).get("severity")
        severity = severity.upper() if isinstance(severity, str) else None
    if not severity:
        for urgency in ("high", "medium", "low", "unimportant"):
            if urgency in urgencies:
                severity = _URGENCY_SEVERITY[urgency]
                break

    upstream = vuln.get("upstream") or vuln.get("aliases") or []
    title = vuln.get("summary") or (", ".join(upstream[:3]) if upstream else None)

    refs = [Reference(url=ref.get("url", ""), type=ref.get("type", "WEB")) for ref in vuln.get("references", []) or []]

    return CVEData(
        cve_id=vuln_id,
        source="osv",
        title=title,
        description=vuln.get("details"),
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        affected_ranges=ranges,
        references=refs,
        published_at=_parse_date(vuln.get("published")),
        modified_at=_parse_date(vuln.get("modified")),
        raw_data={**vuln, "_vigilance_parser": OSV_PARSER_VERSION},
        aliases=[a for a in dict.fromkeys(list(vuln.get("upstream") or []) + list(vuln.get("aliases") or []))
                 if isinstance(a, str)],
    )


class OSVClient:
    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60.0, headers={"User-Agent": "vigilance-cve-sync"})

    async def close(self):
        await self.client.aclose()

    @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(3), reraise=True)
    async def _post_querybatch(self, queries: List[dict]) -> List[dict]:
        response = await self.client.post(f"{self.BASE_URL}/querybatch", json={"queries": queries})
        response.raise_for_status()
        results = response.json().get("results", [])
        if len(results) != len(queries):
            raise RuntimeError(f"OSV querybatch returned {len(results)} results for {len(queries)} queries")
        return results

    async def query_batch(self, keys: List[QueryKey]) -> Dict[QueryKey, Dict[str, Optional[str]]]:
        """Return {query key: {vuln id: modified}} for all keys (paginating where needed)."""
        found: Dict[QueryKey, Dict[str, Optional[str]]] = {key: {} for key in keys}
        pending: List[Tuple[QueryKey, Optional[str]]] = [(key, None) for key in keys]
        while pending:
            chunk, pending = pending[:QUERYBATCH_MAX], pending[QUERYBATCH_MAX:]
            queries = []
            for (ecosystem, name, version), page_token in chunk:
                query = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                if page_token:
                    query["page_token"] = page_token
                queries.append(query)
            results = await self._post_querybatch(queries)
            for (key, _), result in zip(chunk, results):
                for vuln in result.get("vulns", []) or []:
                    found[key][vuln["id"]] = vuln.get("modified")
                if result.get("next_page_token"):
                    pending.append((key, result["next_page_token"]))
        return found

    @retry(wait=wait_exponential(multiplier=1, min=2, max=30), stop=stop_after_attempt(3), reraise=True)
    async def get_vuln(self, vuln_id: str) -> dict:
        response = await self.client.get(f"{self.BASE_URL}/vulns/{vuln_id}")
        response.raise_for_status()
        return response.json()


async def sync_osv_for_tools(tools: Iterable, known_modified: Optional[Dict[str, Optional[datetime]]] = None) -> OSVSyncOutcome:
    """Query OSV for exactly the discovered package versions.

    Args:
        tools: DiscoveredTool objects (with ``inventory`` loaded for OS release info)
        known_modified: {OSV id: modified_at} of records already stored; unchanged
            records are not downloaded again.
    """
    known_modified = known_modified or {}
    outcome = OSVSyncOutcome()
    keys: Set[QueryKey] = set()
    for tool in tools:
        key = tool_query_key(tool)
        if key:
            keys.add(key)
        elif tool.package_manager in ("dpkg", "apk", "rpm"):
            outcome.skipped_tools += 1
    if outcome.skipped_tools:
        logger.info("OSV: %d package(s) skipped (OS release unknown or unsupported)", outcome.skipped_tools)
    if not keys:
        return outcome

    client = OSVClient()
    try:
        sorted_keys = sorted(keys)
        outcome.queried = len(sorted_keys)
        found = await client.query_batch(sorted_keys)
        all_ids: Dict[str, Optional[str]] = {}
        for key, vulns in found.items():
            if vulns:
                outcome.matches[key] = set(vulns)
            all_ids.update(vulns)

        to_fetch = [
            vuln_id for vuln_id, modified in all_ids.items()
            if vuln_id not in known_modified or known_modified[vuln_id] != _parse_date(modified)
        ]
        logger.info(
            "OSV: %d package versions queried, %d affected, %d advisories (%d new/changed)",
            outcome.queried, len(outcome.matches), len(all_ids), len(to_fetch),
        )

        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def fetch(vuln_id: str) -> Optional[CVEData]:
            async with semaphore:
                try:
                    return parse_vuln(await client.get_vuln(vuln_id))
                except Exception as exc:  # keep the sync going; record stays as before
                    logger.warning("OSV: could not fetch %s: %s", vuln_id, exc)
                    return None

        for cve in await asyncio.gather(*(fetch(v) for v in to_fetch)):
            if cve:
                outcome.cves.append(cve)
        return outcome
    finally:
        await client.close()
