import logging
from typing import List, Optional
import httpx
import xml.etree.ElementTree as ET
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.cve.models import CVEData, AffectedRange, Reference
from vigilance.config import settings

logger = logging.getLogger(__name__)


class DebianSecurityTracker:
    BASE_URL = "https://security-tracker.debian.org/tracker/data/json"

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60.0)

    async def close(self):
        await self.client.aclose()

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
    )
    async def fetch_for_suites(self, suites: List[str]) -> List[CVEData]:
        """Fetch Debian security data for specific suites."""
        all_cves = []

        for suite in suites:
            try:
                url = f"{self.BASE_URL}/{suite}"
                response = await self.client.get(url)
                response.raise_for_status()
                data = response.json()

                for cve_id, cve_data in data.items():
                    cve = self._parse_cve(cve_id, cve_data, suite)
                    if cve:
                        all_cves.append(cve)
            except Exception as e:
                logger.error(f"Failed to fetch Debian data for {suite}: {e}")

        logger.info(f"Fetched {len(all_cves)} CVE entries from Debian Security Tracker")
        return all_cves

    def _parse_cve(self, cve_id: str, cve_data: dict, suite: str) -> Optional[CVEData]:
        try:
            # Get description
            description = cve_data.get("description", "")

            # Get severity from highest severity across packages
            severity = None
            cvss_score = None

            # Parse affected packages
            ranges = []
            packages = cve_data.get("packages", {})
            for pkg_name, pkg_data in packages.items():
                status = pkg_data.get("status", "")
                if status in ("fixed", "vulnerable"):
                    fixed_version = pkg_data.get("fixed_version")
                    ranges.append(AffectedRange(
                        type="DEBIAN",
                        introduced="0",
                        fixed=fixed_version,
                        repo=pkg_name,
                        events=[
                            {"introduced": "0"},
                            {"fixed": fixed_version} if fixed_version else {},
                        ],
                    ))

            # Parse references
            refs = []
            refs.append(Reference(
                url=f"https://security-tracker.debian.org/tracker/{cve_id}",
                type="ADVISORY",
            ))

            return CVEData(
                cve_id=cve_id,
                source="debian",
                title=None,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=None,
                affected_ranges=ranges,
                references=refs,
                published_at=None,
                modified_at=None,
                raw_data={"suite": suite, "data": cve_data},
            )
        except Exception as e:
            logger.error(f"Failed to parse Debian CVE {cve_id}: {e}")
            return None


async def sync_debian(suites: List[str]) -> List[CVEData]:
    """Sync CVE data from Debian Security Tracker for given suites."""
    client = DebianSecurityTracker()
    try:
        return await client.fetch_for_suites(suites)
    finally:
        await client.close()