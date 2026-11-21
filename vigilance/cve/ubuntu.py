import logging
from typing import List, Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.cve.models import CVEData, AffectedRange, Reference
from vigilance.config import settings

logger = logging.getLogger(__name__)


class UbuntuSecurityTracker:
    BASE_URL = "https://api.launchpad.net/1.0"

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60.0)

    async def close(self):
        await self.client.aclose()

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
    )
    async def fetch_for_releases(self, releases: List[str]) -> List[CVEData]:
        """Fetch Ubuntu security data for specific releases."""
        all_cves = []

        # Use Ubuntu CVE tracker data
        for release in releases:
            try:
                # Fetch from Ubuntu's JSON feed
                url = f"https://people.canonical.com/~ubuntu-security/cve/pkg/{release}.json"
                response = await self.client.get(url)
                if response.status_code == 404:
                    continue
                response.raise_for_status()
                data = response.json()

                for cve_id, cve_data in data.items():
                    cve = self._parse_cve(cve_id, cve_data, release)
                    if cve:
                        all_cves.append(cve)
            except Exception as e:
                logger.error(f"Failed to fetch Ubuntu data for {release}: {e}")

        logger.info(f"Fetched {len(all_cves)} CVE entries from Ubuntu Security Tracker")
        return all_cves

    def _parse_cve(self, cve_id: str, cve_data: dict, release: str) -> Optional[CVEData]:
        try:
            description = cve_data.get("description", "")

            # Parse packages
            ranges = []
            packages = cve_data.get("pkgs", [])
            for pkg in packages:
                pkg_name = pkg.get("name", "")
                pkg_status = pkg.get("status", "")
                if pkg_status in ("released", "pending"):
                    fixed_version = pkg.get("version", "")
                    ranges.append(AffectedRange(
                        type="UBUNTU",
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
                url=f"https://ubuntu.com/security/{cve_id}",
                type="ADVISORY",
            ))

            return CVEData(
                cve_id=cve_id,
                source="ubuntu",
                title=None,
                description=description,
                severity=None,
                cvss_score=None,
                cvss_vector=None,
                affected_ranges=ranges,
                references=refs,
                published_at=None,
                modified_at=None,
                raw_data={"release": release, "data": cve_data},
            )
        except Exception as e:
            logger.error(f"Failed to parse Ubuntu CVE {cve_id}: {e}")
            return None


async def sync_ubuntu(releases: List[str]) -> List[CVEData]:
    """Sync CVE data from Ubuntu Security Tracker for given releases."""
    client = UbuntuSecurityTracker()
    try:
        return await client.fetch_for_releases(releases)
    finally:
        await client.close()