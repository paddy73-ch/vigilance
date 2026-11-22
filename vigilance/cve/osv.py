import asyncio
import json
import logging
from datetime import datetime
from typing import List, Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.cve.models import CVEData, AffectedRange, Reference
from vigilance.config import settings

logger = logging.getLogger(__name__)


class OSVClient:
    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def close(self):
        await self.client.aclose()

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
    )
    async def fetch_all_vulns(self, page_size: int = 1000) -> List[CVEData]:
        """Fetch all vulnerabilities from OSV (paginated)."""
        all_vulns = []
        page_token = None

        while True:
            params = {"page_size": page_size}
            if page_token:
                params["page_token"] = page_token

            response = await self.client.get(f"{self.BASE_URL}/vulns", params=params)
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])
            for vuln in vulns:
                cve = self._parse_vuln(vuln)
                if cve:
                    all_vulns.append(cve)

            page_token = data.get("next_page_token")
            if not page_token:
                break

        logger.info(f"Fetched {len(all_vulns)} vulnerabilities from OSV")
        return all_vulns

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
    )
    async def query_by_package(self, package: str, ecosystem: str, version: str) -> List[CVEData]:
        """Query OSV for vulnerabilities affecting a specific package/version."""
        payload = {
            "package": {"name": package, "ecosystem": ecosystem},
            "version": version,
        }
        response = await self.client.post(f"{self.BASE_URL}/query", json=payload)
        response.raise_for_status()
        data = response.json()

        vulns = data.get("vulns", [])
        return [self._parse_vuln(v) for v in vulns if self._parse_vuln(v)]

    def _parse_vuln(self, vuln: dict) -> Optional[CVEData]:
        try:
            cve_id = vuln.get("id", "")
            if not cve_id:
                return None

            # Extract severity from database_specific or CVSS
            severity = None
            cvss_score = None
            cvss_vector = None

            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    cvss_vector = sev.get("score")
                    # Parse CVSS vector for score
                    if cvss_vector and cvss_vector.startswith("CVSS:3"):
                        cvss_score = self._parse_cvss_score(cvss_vector)
                        severity = self._score_to_severity(cvss_score)
                    break

            # Fallback to database_specific
            if not severity:
                db_specific = vuln.get("database_specific", {})
                severity = db_specific.get("severity")

            # Parse affected ranges
            ranges = []
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    ranges.append(AffectedRange(
                        type=r.get("type", "ECOSYSTEM"),
                        introduced=r.get("events", [{}])[0].get("introduced", "0") if r.get("events") else "0",
                        fixed=r.get("events", [{}])[-1].get("fixed") if r.get("events") else None,
                        last_affected=r.get("events", [{}])[-1].get("last_affected") if r.get("events") else None,
                        repo=affected.get("package", {}).get("name"),
                        events=r.get("events", []),
                    ))

            # Parse references
            refs = []
            for ref in vuln.get("references", []):
                refs.append(Reference(
                    url=ref.get("url", ""),
                    type=ref.get("type", "WEB"),
                ))

            # Parse dates
            published = vuln.get("published")
            modified = vuln.get("modified")

            return CVEData(
                cve_id=cve_id,
                source="osv",
                title=vuln.get("summary"),
                description=vuln.get("details"),
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                affected_ranges=ranges,
                references=refs,
                published_at=self._parse_date(published) if published else None,
                modified_at=self._parse_date(modified) if modified else None,
                raw_data=vuln,
            )
        except Exception as e:
            logger.error(f"Failed to parse OSV vuln {vuln.get('id', 'unknown')}: {e}")
            return None

    def _parse_cvss_score(self, vector: str) -> Optional[float]:
        """Extract base score from CVSS vector."""
        try:
            # Simple extraction - in reality use cvsslib
            parts = vector.split("/")
            for part in parts:
                if part.startswith("AV:") or part.startswith("AC:") or part.startswith("PR:"):
                    continue
            return None
        except Exception:
            return None

    def _score_to_severity(self, score: Optional[float]) -> Optional[str]:
        if score is None:
            return None
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "NONE"

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            return None


async def sync_osv() -> List[CVEData]:
    """Sync all vulnerabilities from OSV."""
    client = OSVClient()
    try:
        return await client.fetch_all_vulns()
    finally:
        await client.close()


async def sync_osv_for_tools(tools) -> List[CVEData]:
    """Query OSV for the package versions discovered on the hosts."""
    client = OSVClient()
    ecosystems = {"dpkg": "Debian", "apk": "Alpine", "rpm": "Fedora"}
    found = {}
    try:
        seen = set()
        queries = []
        for tool in tools:
            ecosystem = ecosystems.get(tool.package_manager)
            if not ecosystem or not tool.tool_name or not tool.detected_version:
                continue
            key = (tool.tool_name, tool.detected_version, ecosystem)
            if key in seen:
                continue
            seen.add(key)
            queries.append(key)

        semaphore = asyncio.Semaphore(20)

        async def query(key):
            async with semaphore:
                try:
                    return await client.query_by_package(key[0], key[2], key[1])
                except Exception as exc:
                    logger.debug("OSV query failed for %s: %s", key[0], exc)
                    return []

        for cves in await asyncio.gather(*(query(key) for key in queries)):
            for cve in cves:
                found[cve.cve_id] = cve
        return list(found.values())
    finally:
        await client.close()
