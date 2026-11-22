import logging
from datetime import datetime
from typing import List, Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.cve.models import CVEData, AffectedRange, Reference
from vigilance.config import settings

logger = logging.getLogger(__name__)


class GHSAClient:
    BASE_URL = "https://api.github.com/advisories"

    def __init__(self):
        # GitHub Advisory API doesn't require auth for public data, but token helps with rate limits
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "vigilance-cve-sync",
        }
        github_token = getattr(settings, "github_token", "") or getattr(settings, "ghsa_token", "")
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        self.client = httpx.AsyncClient(timeout=30.0, headers=headers)

    async def close(self):
        await self.client.aclose()

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
    )
    async def fetch_advisories(self, per_page: int = 100, max_pages: int = 0) -> List[CVEData]:
        """Fetch GitHub Security Advisories using the public REST API.
        
        Args:
            per_page: Results per page (max 100)
            max_pages: Maximum pages to fetch (0 = no limit)
        """
        all_advisories = []
        page = 1
        while True:
            if max_pages and page > max_pages:
                break
            response = await self.client.get(self.BASE_URL, params={"per_page": per_page, "page": page})
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                body = e.response.text[:200]
                logger.error(f"GitHub API returned HTTP {status}: {body}")
                raise
            advisories = response.json()
            if not isinstance(advisories, list):
                logger.error("GitHub advisories returned a non-list response; stopping pagination")
                break
            for node in advisories:
                cve = self._parse_advisory(node)
                if cve:
                    all_advisories.append(cve)
            if len(advisories) < per_page:
                break
            page += 1

        logger.info(f"Fetched {len(all_advisories)} advisories from GHSA")
        return all_advisories

    def _parse_advisory(self, node: dict) -> Optional[CVEData]:
        try:
            ghsa_id = node.get("ghsa_id", node.get("ghsaId", ""))
            if not ghsa_id:
                return None

            # Get CVE ID if available
            cve_id = ghsa_id
            for ident in node.get("identifiers", []):
                if isinstance(ident, dict) and ident.get("type") == "CVE":
                    cve_id = ident.get("value")
                    break

            severity = node.get("severity")
            cvss_score = None
            cvss_vector = None
            cvss = node.get("cvss") or {}
            if cvss:
                cvss_score = cvss.get("score")
                cvss_vector = cvss.get("vectorString")

            # Parse vulnerabilities for affected ranges
            ranges = []
            vulnerabilities = node.get("vulnerabilities", [])
            if isinstance(vulnerabilities, dict):
                vulnerabilities = vulnerabilities.get("nodes", [])
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                pkg = vuln.get("package", {})
                if not isinstance(pkg, dict):
                    pkg = {}
                version_range = vuln.get("vulnerable_version_range", vuln.get("vulnerableVersionRange", ""))
                first_patched = vuln.get("first_patched_version") or vuln.get("firstPatchedVersion") or {}
                if not isinstance(first_patched, dict):
                    first_patched = {}

                ranges.append(AffectedRange(
                    type="ECOSYSTEM",
                    introduced="0",
                    fixed=first_patched.get("identifier") if first_patched else None,
                    last_affected=version_range if version_range else None,
                    repo=pkg.get("name"),
                    events=[
                        {"introduced": "0"},
                        {"fixed": first_patched.get("identifier")} if first_patched else {},
                    ],
                ))

            # Parse references
            refs = []
            for ref in node.get("references", []):
                if isinstance(ref, str):
                    refs.append(Reference(url=ref, type="ADVISORY"))
                    continue
                refs.append(Reference(
                    url=ref.get("url", ""),
                    type="ADVISORY",
                ))

            published = node.get("published_at", node.get("publishedAt"))
            updated = node.get("updated_at", node.get("updatedAt"))

            return CVEData(
                cve_id=cve_id,
                source="ghsa",
                title=node.get("summary"),
                description=node.get("description"),
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                affected_ranges=ranges,
                references=refs,
                published_at=self._parse_date(published) if published else None,
                modified_at=self._parse_date(updated) if updated else None,
                raw_data=node,
            )
        except Exception as e:
            logger.error(f"Failed to parse GHSA advisory {node.get('ghsaId', 'unknown')}: {e}")
            return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            return None


async def sync_ghsa(max_pages: int = 0) -> List[CVEData]:
    """Sync all advisories from GitHub Security Advisories.
    
    Args:
        max_pages: Maximum pages to fetch (0 = no limit)
    """
    client = GHSAClient()
    try:
        return await client.fetch_advisories(max_pages=max_pages)
    finally:
        await client.close()
