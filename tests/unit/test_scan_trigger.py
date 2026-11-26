"""'Jetzt scannen' in der Übersicht und verständliche SSH-Fehler."""
import socket

import paramiko
import pytest

from tests.unit.test_views import AUTH, client  # noqa: F401  (fixture)
from vigilance.discovery.ssh import describe_connect_error


@pytest.mark.asyncio
async def test_trigger_scan_without_body(client, monkeypatch):  # noqa: F811
    """The overview button posts without a body; that must start a scan, not answer 422."""
    import vigilance.api.routes.scans as scans
    calls = []

    async def fake(full=False):
        calls.append(full)
        return 42

    monkeypatch.setattr(scans, "trigger_scan_now", fake)
    r = await client.post("/api/scans/trigger", headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json()["scan_run_id"] == 42 and calls == [False]
    r = await client.post("/api/scans/trigger", headers=AUTH, json={"full": True})
    assert r.status_code == 200 and calls == [False, True]


@pytest.mark.parametrize("exc, expected", [
    (paramiko.AuthenticationException("Authentication failed."), "Schlüssel von Vigilance"),
    (paramiko.ssh_exception.NoValidConnectionsError({("192.0.2.2", 22): OSError("refused")}), "Keine SSH-Verbindung"),
    (socket.timeout("timed out"), "Keine Antwort"),
    (paramiko.SSHException("Server '192.0.2.2' not found in known_hosts"), "unbekannt"),
])
def test_connect_errors_are_explained(exc, expected):
    assert expected in describe_connect_error(exc, "192.0.2.2", 22)
