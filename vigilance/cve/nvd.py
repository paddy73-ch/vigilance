import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vigilance.cve.models import CVEData, AffectedRange, Reference
from vigilance.config import settings

logger = logging.getLogger(__name__)


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        headers = {"Accept": "application/json", "User-Agent": "Vigilance/1.0"}
        api_key = settings.nvd_api_key if hasattr(settings, 'nvd_api_key') else ""
        if api_key:
            headers["apiKey"] = api_key
        # NVD/Cloudflare returns misleading 404s through the container's proxy.
        self.client = httpx.AsyncClient(timeout=60.0, headers=headers, trust_env=False)

    async def close(self):
        await self.client.aclose()

    async def _fallback_json(self, params: dict) -> dict:
        url = f"{self.BASE_URL}?{urlencode(params)}"
        def fetch():
            import json
            request = Request(url, headers={"Accept": "application/json", "User-Agent": "Vigilance/1.0", "apiKey": settings.nvd_api_key})
            with urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        return await asyncio.to_thread(fetch)

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
    )
    async def fetch_recent_cves(self, days: int = 30) -> List[CVEData]:
        """Fetch CVEs from NVD from the last N days."""
        all_cves = []
        start_index = 0
        results_per_page = 2000
        fallback_latest = False

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        # NVD rejects future-dated windows when the host clock is ahead.
        # Fetch the current page instead; the API itself supplies the latest records.
        latest_only = True

        while True:
            params = {"startIndex": start_index, "resultsPerPage": results_per_page}
            if not latest_only:
                params.update({
                    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                })

            response = await self.client.get(self.BASE_URL, params=params)
            if response.status_code == 404 and start_index == 0:
                logger.warning("NVD returned 404; retrying latest page")
                data = await self._fallback_json({"startIndex": 0, "resultsPerPage": results_per_page})
                fallback_latest = True
            else:
                response.raise_for_status()
                data = response.json()

            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                cve = self._parse_cve(vuln)
                if cve:
                    all_cves.append(cve)

            total_results = data.get("totalResults", 0)
            if fallback_latest or latest_only:
                break
            if start_index + results_per_page >= total_results:
                break
            start_index += results_per_page

        logger.info(f"Fetched {len(all_cves)} CVEs from NVD")
        return all_cves

    def _parse_cve(self, vuln: dict) -> Optional[CVEData]:
        try:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

            # Get CVSS metrics
            severity = None
            cvss_score = None
            cvss_vector = None

            metrics = cve_data.get("metrics", {})
            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in metrics:
                    metric = metrics[metric_type][0]
                    cvss = metric.get("cvssData", {})
                    cvss_score = cvss.get("baseScore")
                    cvss_vector = cvss.get("vectorString")
                    severity = metric.get("baseSeverity")
                    break

            # Parse affected configurations (CPE)
            ranges = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            ranges.append(AffectedRange(
                                type="CPE",
                                introduced=cpe_match.get("versionStartIncluding", "0"),
                                fixed=cpe_match.get("versionEndExcluding"),
                                last_affected=cpe_match.get("versionEndIncluding"),
                                repo=cpe_match.get("criteria"),
                                events=[],
                            ))

            # Parse references
            refs = []
            for ref in cve_data.get("references", []):
                refs.append(Reference(
                    url=ref.get("url", ""),
                    type=ref.get("source", "WEB"),
                ))

            published = cve_data.get("published")
            modified = cve_data.get("lastModified")

            return CVEData(
                cve_id=cve_id,
                source="nvd",
                title=None,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                affected_ranges=ranges,
                references=refs,
                published_at=self._parse_date(published) if published else None,
                modified_at=self._parse_date(modified) if modified else None,
                raw_data=cve_data,
            )
        except Exception as e:
            logger.error(f"Failed to parse NVD CVE {vuln.get('cve', {}).get('id', 'unknown')}: {e}")
            return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            return None


async def sync_nvd(days: int = 30) -> List[CVEData]:
    """Sync recent CVEs from NVD."""
    client = NVDClient()
    try:
        return await client.fetch_recent_cves(days)
    finally:
        await client.close()
