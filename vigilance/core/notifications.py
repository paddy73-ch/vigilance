import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
import httpx

from vigilance.config import settings
from vigilance.database.models import VulnerabilityFinding, CVEEntry, DiscoveredTool, Inventory

logger = logging.getLogger(__name__)


@dataclass
class GotifyConfig:
    enabled: bool
    url: str
    token: str
    min_severity: str
    digest_mode: bool
    digest_interval_minutes: int


SEVERITY_PRIORITY = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    "NONE": 1,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    try:
        return SEVERITY_ORDER.index(severity) <= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def format_finding_message(finding: VulnerabilityFinding, tool: DiscoveredTool, inventory: Inventory, cve: CVEEntry) -> str:
    lines = [
        f"## {cve.cve_id}: {cve.title or 'No title'}",
        f"**Severity:** {cve.severity or 'UNKNOWN'} (CVSS: {cve.cvss_score or 'N/A'})",
        f"**Tool:** {tool.tool_name} ({tool.detected_version or 'unknown version'})",
        f"**Host:** {inventory.name} ({inventory.ip_address or 'no IP'})",
        f"**Proxmox Node:** {inventory.node.name if inventory.node else 'Unknown'}",
        f"**Source:** {tool.source_type}",
        "",
        f"**Description:** {cve.description or 'No description available'}",
        "",
    ]

    if finding.fixed_version:
        lines.append(f"**Fixed in version:** {finding.fixed_version}")

    if cve.references:
        try:
            refs = json.loads(cve.references)
            if refs:
                lines.append("")
                lines.append("**References:**")
                for ref in refs[:5]:  # Limit to 5
                    url = ref.get("url", "")
                    ref_type = ref.get("type", "")
                    if url:
                        lines.append(f"- [{ref_type}]({url})")
        except json.JSONDecodeError:
            pass

    lines.append("")
    lines.append(f"*First seen: {finding.first_seen_at.strftime('%Y-%m-%d %H:%M:%S')}*")
    if settings.public_url:
        lines.append(f"[Open in Vigilance]({settings.public_url.rstrip('/')}/hosts/{inventory.id})")

    return "\n".join(lines)


async def send_gotify_message(
    config: GotifyConfig,
    title: str,
    message: str,
    priority: int = 5,
    extras: Optional[dict] = None,
) -> tuple[bool, Optional[str]]:
    if not config.enabled or not config.url or not config.token:
        return False, "Gotify not configured (enabled, url, or token missing)"

    url = f"{config.url.rstrip('/')}/message"
    params = {"token": config.token}
    payload = {
        "title": title,
        "message": message,
        "priority": priority,
    }
    if extras:
        payload["extras"] = extras

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, params=params, json=payload)
            response.raise_for_status()
            return True, None
    except httpx.ConnectError as e:
        return False, f"Connection failed: {e}"
    except httpx.TimeoutException as e:
        return False, f"Timeout: {e}"
    except httpx.HTTPStatusError as e:
        return False, f"HTTP {e.response.status_code}: {e.response.text}"
    except Exception as e:
        logger.error(f"Failed to send Gotify notification: {e}")
        return False, f"Error: {type(e).__name__}: {e}"


async def notify_finding(finding: VulnerabilityFinding, tool: DiscoveredTool, inventory: Inventory, cve: CVEEntry):
    if not settings.notifications or not settings.notifications.gotify:
        return

    config = settings.notifications.gotify

    if not severity_meets_threshold(cve.severity or "NONE", config.min_severity):
        return

    if config.digest_mode:
        # Store for digest (implemented in scheduler)
        await queue_digest_finding(finding, tool, inventory, cve)
        return

    message = format_finding_message(finding, tool, inventory, cve)
    priority = SEVERITY_PRIORITY.get(cve.severity or "NONE", 5)

    await send_gotify_message(
        config=config,
        title=f"[Vigilance] {cve.severity or 'Unknown'} CVE in {tool.tool_name}",
        message=message,
        priority=priority,
        extras={"client::display": {"contentType": "text/markdown"}},
    )


async def notify_digest(findings_data: List[dict]):
    if not settings.notifications or not settings.notifications.gotify:
        return

    config = settings.notifications.gotify
    if not config.digest_mode or not findings_data:
        return

    # Group by severity
    by_severity = {}
    for f in findings_data:
        sev = f["cve"].severity or "NONE"
        by_severity.setdefault(sev, []).append(f)

    lines = [
        f"# Vigilance Security Digest - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
        f"**Total findings:** {len(findings_data)}",
        "",
    ]

    for severity in SEVERITY_ORDER:
        if severity not in by_severity:
            continue
        items = by_severity[severity]
        lines.append(f"## {severity} ({len(items)})")
        for item in items[:10]:  # Limit per severity
            tool = item["tool"]
            inv = item["inventory"]
            cve = item["cve"]
            lines.append(f"- **{cve.cve_id}** in `{tool.tool_name}` on `{inv.name}` ({inv.ip_address or 'no IP'})")
        if len(items) > 10:
            lines.append(f"  *... and {len(items) - 10} more*")
        lines.append("")

    message = "\n".join(lines)
    priority = SEVERITY_PRIORITY.get(max(by_severity.keys(), key=lambda k: SEVERITY_PRIORITY.get(k, 1)), 5)

    await send_gotify_message(
        config=config,
        title=f"[Vigilance] Security Digest - {len(findings_data)} findings",
        message=message,
        priority=priority,
        extras={"client::display": {"contentType": "text/markdown"}},
    )


# In-memory queue for digest mode
_digest_queue: List[dict] = []


async def queue_digest_finding(finding: VulnerabilityFinding, tool: DiscoveredTool, inventory: Inventory, cve: CVEEntry):
    _digest_queue.append({
        "finding": finding,
        "tool": tool,
        "inventory": inventory,
        "cve": cve,
    })


async def get_digest_queue() -> List[dict]:
    global _digest_queue
    items = _digest_queue
    _digest_queue = []
    return items


async def send_test_gotify(url: Optional[str] = None, token: Optional[str] = None) -> tuple[bool, Optional[str]]:
    if not settings.notifications or not settings.notifications.gotify:
        return False, "Gotify not configured in settings"

    config = settings.notifications.gotify
    # Use provided url/token for testing, fallback to configured values
    test_url = url or config.url
    test_token = token or config.token
    
    if not test_url or not test_token:
        return False, "No URL or token provided (and none configured)"

    test_config = GotifyConfig(
        enabled=True,
        url=test_url,
        token=test_token,
        min_severity=config.min_severity,
        digest_mode=config.digest_mode,
        digest_interval_minutes=config.digest_interval_minutes,
    )
    
    return await send_gotify_message(
        config=test_config,
        title="[Vigilance] Test Notification",
        message="This is a test message from Vigilance. If you see this, Gotify integration is working!",
        priority=5,
        extras={"client::display": {"contentType": "text/markdown"}},
    )


async def send_webhook(webhook_config, findings_data: List[dict]):
    if not webhook_config.url:
        return

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if webhook_config.template == "slack":
                payload = format_slack_payload(findings_data)
            else:
                payload = {"findings": findings_data}

            await client.post(webhook_config.url, json=payload)
    except Exception as e:
        logger.error(f"Failed to send webhook to {webhook_config.name}: {e}")


def format_slack_payload(findings_data: List[dict]) -> dict:
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Vigilance Alert: {len(findings_data)} findings"},
        }
    ]

    for item in findings_data[:5]:
        tool = item["tool"]
        inv = item["inventory"]
        cve = item["cve"]
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{cve.cve_id}* ({cve.severity}) in `{tool.tool_name}` on `{inv.name}`",
            },
        })

    if len(findings_data) > 5:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"... and {len(findings_data) - 5} more findings"}],
        })

    return {"blocks": blocks}