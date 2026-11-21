import logging
from datetime import datetime
from typing import List, Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.cve.models import CVEData, AffectedRange, Reference
from vigilance.config import settings

logger = logging.getLogger(__name__)


class GHSAClient:
    BASE_URL = "https://api.github.com/graphql"

    def __init__(self):
        # GitHub Advisory API doesn't require auth for public data, but token helps with rate limits
        headers = {"Accept": "application/vnd.github+json"}
        if settings.get("github_token"):
            headers["Authorization"] = f"Bearer {settings.github_token}"
        self.client = httpx.AsyncClient(timeout=30.0, headers=headers)

    async def close(self):
        await self.client.aclose()

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
    )
    async def fetch_advisories(self, per_page: int = 100) -> List[CVEData]:
        """Fetch GitHub Security Advisories using GraphQL."""
        all_advisories = []
        cursor = None

        query = """
        query($cursor: String) {
            securityAdvisories(first: 100, after: $cursor, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
                pageInfo {
                    hasNextPage
                    endCursor
                }
                nodes {
                    ghsaId
                    summary
                    description
                    severity
                    cvss {
                        score
                        vectorString
                    }
                    identifiers {
                        type
                        value
                    }
                    references {
                        url
                    }
                    publishedAt
                    updatedAt
                    vulnerabilities(first: 10) {
                        nodes {
                            package {
                                name
                                ecosystem
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }
            }
        }
        """

        while True:
            variables = {"cursor": cursor}
            response = await self.client.post(
                self.BASE_URL,
                json={"query": query, "variables": variables},
            )
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                logger.error(f"GraphQL errors: {data['errors']}")
                break

            advisories = data.get("data", {}).get("securityAdvisories", {})
            for node in advisories.get("nodes", []):
                cve = self._parse_advisory(node)
                if cve:
                    all_advisories.append(cve)

            page_info = advisories.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

        logger.info(f"Fetched {len(all_advisories)} advisories from GHSA")
        return all_advisories

    def _parse_advisory(self, node: dict) -> Optional[CVEData]:
        try:
            ghsa_id = node.get("ghsaId", "")
            if not ghsa_id:
                return None

            # Get CVE ID if available
            cve_id = ghsa_id
            for ident in node.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve_id = ident.get("value")
                    break

            severity = node.get("severity")
            cvss_score = None
            cvss_vector = None
            cvss = node.get("cvss", {})
            if cvss:
                cvss_score = cvss.get("score")
                cvss_vector = cvss.get("vectorString")

            # Parse vulnerabilities for affected ranges
            ranges = []
            for vuln in node.get("vulnerabilities", {}).get("nodes", []):
                pkg = vuln.get("package", {})
                version_range = vuln.get("vulnerableVersionRange", "")
                first_patched = vuln.get("firstPatchedVersion", {})

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
                refs.append(Reference(
                    url=ref.get("url", ""),
                    type="ADVISORY",
                ))

            published = node.get("publishedAt")
            updated = node.get("updatedAt")

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


async def sync_ghsa() -> List[CVEData]:
    """Sync all advisories from GitHub Security Advisories."""
    client = GHSAClient()
    try:
        return await client.fetch_advisories()
    finally:
        await client.close()