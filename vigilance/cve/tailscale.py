"""Tailscale security bulletins (https://tailscale.com/security-bulletins/) as an advisory source.

Debian does not package Tailscale (the tracker marks it NOT-FOR-US) and recent bulletins are not
in the Go vulnerability data, so the bulletin feed is the only source for the `tailscale` deb from
pkgs.tailscale.com. The feed is RSS with an HTML body per bulletin; versions and platforms are only
in the text. Each bulletin is therefore classified:

* ``client``      - the Tailscale client is affected and a fixed version was found: becomes an
                    advisory for the package ``tailscale`` (affected below the fixed version)
* ``other``       - concerns something else (coordination server, Kubernetes operator,
                    libtailscale, DERP, proxy-to-grafana) or says no action is required
* ``platform``    - the structured "Affected platforms" line excludes Linux
* ``unparsed``    - client, but no fixed version recognised: stored for reference, no finding

Only ``client`` produces findings. A new phrasing that no pattern knows ends up in ``unparsed``
and is reported on the sources page instead of silently matching every version.
"""

import html
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Optional, Tuple

import httpx

from vigilance.cve.cvss import cvss3_base_score, score_to_severity
from vigilance.cve.models import AffectedRange, CVEData, Reference

logger = logging.getLogger(__name__)

FEED_URL = "https://tailscale.com/security-bulletins/index.xml"
PACKAGE = "tailscale"
SOURCE = "tailscale"

_V = r"v?(\d+\.\d+(?:\.\d+)?)"
# Ordered: the Linux-specific statement wins over a general one
FIX_PATTERNS = [
    rf"on Linux before Tailscale (?:version )?{_V}",
    rf"Patched Tailscale client versions?\s*:\s*{_V}",
    rf"fixed in Tailscale (?:client )?versions? {_V}",
    rf"Tailscale (?:client )?versions? {_V} (?:fixes|resolves|redacts|addresses)",
    rf"\bVersion {_V} (?:fixes|resolves)",
    rf"fixed (?:this|the) (?:bug|issue|vulnerability) in (?:Tailscale )?(?:client )?version {_V}",
    rf"Tailscale {_V} or later includes",
    rf"(?:upgrade|update)\b[^.]{{0,80}}?\bto (?:Tailscale )?(?:version )?{_V} or later",
    rf"Tailscale (?:client )?versions? (?:earlier than|prior to|before) {_V}",
]
INTRODUCED_PATTERN = re.compile(rf"versions? between {_V} and", re.IGNORECASE)
NOT_CLIENT = re.compile(
    r"coordination server|control plane|Kubernetes operator|libtailscale|DERP server|proxy-to-grafana",
    re.IGNORECASE,
)
NO_ACTION = re.compile(r"no action (?:is )?(?:required|needed|necessary)", re.IGNORECASE)
PLATFORMS = re.compile(r"Affected platforms\s*:\s*(.+?)\s+Patched", re.IGNORECASE)
SEVERITY = re.compile(r"Severity\s*:\s*(Critical|High|Medium|Low)", re.IGNORECASE)
VECTOR = re.compile(r"(CVSS:3\.[01]/[A-Z:/]+)")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


def html_to_text(fragment: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html.unescape(fragment or ""))
    return re.sub(r"\s+", " ", text).strip()


def _first_paragraph(fragment: str) -> str:
    m = re.search(r"<p>(.*?)</p>", html.unescape(fragment or ""), re.DOTALL)
    return html_to_text(m.group(1)) if m else html_to_text(fragment)[:400]


def classify(text: str, first_paragraph: str) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """(classification, fixed version, introduced version, platforms) for one bulletin."""
    platforms = None
    m = PLATFORMS.search(text)
    if m:
        platforms = m.group(1).strip()
        if not re.search(r"\b(all|linux)\b", platforms, re.IGNORECASE):
            return "platform", None, None, platforms
    if NOT_CLIENT.search(first_paragraph):
        return "other", None, None, platforms
    fixed = None
    for pattern in FIX_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            fixed = m.group(1)
            break
    if not fixed:
        return ("other" if NO_ACTION.search(text) else "unparsed"), None, None, platforms
    intro = INTRODUCED_PATTERN.search(text)
    return "client", fixed, intro.group(1) if intro else None, platforms


def parse_feed(xml_text: str) -> List[CVEData]:
    root = ET.fromstring(xml_text)
    result = []
    for item in root.findall("./channel/item"):
        bulletin_id = (item.findtext("title") or "").strip()
        if not re.match(r"^TS-\d{4}-\d+$", bulletin_id):
            continue
        body = item.findtext("description") or ""
        text = html_to_text(body)
        first = _first_paragraph(body)
        kind, fixed, introduced, platforms = classify(text, first)
        m = re.search(r"Description\s*:\s*(.+?)(?=\s+(?:Affected platforms|What happened)\b|$)", text, re.IGNORECASE)
        summary = (m.group(1) if m else first).strip()
        vector = VECTOR.search(text)
        score = cvss3_base_score(vector.group(1)) if vector else None
        sev = SEVERITY.search(text)
        severity = score_to_severity(score) if score else (sev.group(1).upper() if sev else None)
        published = None
        try:
            published = parsedate_to_datetime(item.findtext("pubDate") or "").replace(tzinfo=None)
        except (TypeError, ValueError):
            pass
        link = (item.findtext("link") or "").strip()
        ranges = []
        if kind == "client":
            ranges.append(AffectedRange(type="ECOSYSTEM", introduced=introduced or "0", fixed=fixed,
                                        repo=PACKAGE, ecosystem="Tailscale"))
        result.append(CVEData(
            cve_id=bulletin_id,
            source=SOURCE,
            title=(summary[:250] or bulletin_id),
            description=text[:8000],
            severity=severity,
            cvss_score=score,
            cvss_vector=vector.group(1) if vector else None,
            affected_ranges=ranges,
            references=[Reference(url=link, type="ADVISORY")] if link.startswith("https://") else [],
            published_at=published,
            modified_at=published,
            raw_data={"classification": kind, "fixed": fixed, "introduced": introduced, "platforms": platforms,
                      "link": link},
            aliases=sorted(set(CVE_ID.findall(text))),
        ))
    return result


def summary(bulletins: List[CVEData]) -> str:
    counts = {}
    for b in bulletins:
        counts[b.raw_data["classification"]] = counts.get(b.raw_data["classification"], 0) + 1
    unparsed = [b.cve_id for b in bulletins if b.raw_data["classification"] == "unparsed"]
    text = (f"{len(bulletins)} Bulletins: {counts.get('client', 0)} mit Fix-Version für den Client, "
            f"{counts.get('other', 0)} betreffen andere Produkte oder brauchen keine Aktion, "
            f"{counts.get('platform', 0)} nur andere Plattformen")
    if unparsed:
        text += f", {len(unparsed)} ohne erkannte Fix-Version: {', '.join(unparsed)}"
    return text + "."


async def fetch_bulletins() -> List[CVEData]:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True,
                                 headers={"User-Agent": "Vigilance (homelab CVE monitor)"}) as client:
        response = await client.get(FEED_URL)
        response.raise_for_status()
    bulletins = parse_feed(response.text)
    logger.info("Tailscale: %s", summary(bulletins))
    return bulletins
