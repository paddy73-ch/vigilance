"""Limitations page (docs/LIMITATIONS.md) and the (i) notes."""
import httpx
import pytest

from vigilance.cve.tailscale import features, limitation_note
from vigilance.main import app
from vigilance.web.routes import LIMITATIONS_FILE, render_limitations


def test_limitations_file_rendered():
    assert LIMITATIONS_FILE.exists()
    html = render_limitations()
    assert "<h1>Grenzen von Vigilance</h1>" in html and "<table>" in html
    assert "<script" not in html


@pytest.mark.asyncio
async def test_limitations_page():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/admin/limits")
    assert r.status_code == 200 and "Grenzen von Vigilance" in r.text and 'href="/admin/limits"' in r.text


def test_tailscale_note():
    assert features("Tailscale SSH Unix socket forwarding", None) == ["Tailscale SSH"]
    assert features("tailscale serve Unix backends could reach privileged sockets", None) == ["Serve"]
    assert "Laut Titel geht es um Tailscale SSH" in limitation_note("Memory exhaustion in Tailscale SSH session handling")
    # the body is ignored: a certificate bulletin that mentions Serve in passing gets the general note
    n = limitation_note("Leaked private keys for TLS intermediates", "certificates used by Serve")
    assert "Laut Titel" not in n and "sieht Vigilance nicht" in n
