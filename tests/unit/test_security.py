import re
import shutil
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vigilance.config import settings
from vigilance.core import auth_token
from vigilance.database.base import get_db
from vigilance.main import app

WRITE_ENDPOINTS = [
    ("POST", "/api/settings", {"scan_interval_hours": 24}),
    ("POST", "/api/cves/sync", None),
    ("POST", "/api/scans/trigger", None),
    ("POST", "/api/suppressions", {"cve_id": "CVE-1", "reason": "x"}),
    ("POST", "/api/auth/token", None),
]


@pytest_asyncio.fixture
async def client(db_engine, monkeypatch):
    maker = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with maker() as session:
            yield session
            await session.commit()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(settings, "api_token", "")
    monkeypatch.setattr(settings, "trusted_proxies", "")
    monkeypatch.setattr(settings, "auth_mode", "proxy")
    auth_token.reset_failures()
    # client address 192.0.2.47 like a browser in the LAN
    transport = httpx.ASGITransport(app=app, client=("192.0.2.47", 51000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        c.maker = maker
        yield c
    app.dependency_overrides.clear()


async def _new_token(client) -> str:
    async with client.maker() as db:
        return await auth_token.rotate_token(db)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", WRITE_ENDPOINTS)
async def test_write_endpoints_need_token(client, method, path, body):
    resp = await client.request(method, path, json=body)
    assert resp.status_code == 401, path


@pytest.mark.asyncio
async def test_remote_user_header_is_ignored_from_untrusted_client(client):
    resp = await client.post("/api/settings", json={"scan_interval_hours": 24}, headers={"Remote-User": "niemand"})
    assert resp.status_code == 401
    assert (await client.get("/api/auth/me", headers={"Remote-User": "niemand"})).status_code == 401


@pytest.mark.asyncio
async def test_remote_user_header_from_trusted_proxy(client, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "192.0.2.101, 198.51.100.0/24")
    assert (await client.get("/api/auth/me", headers={"Remote-User": "patrick"})).status_code == 401  # .47 is not trusted
    monkeypatch.setattr(settings, "trusted_proxies", "192.0.2.0/24")
    resp = await client.get("/api/auth/me", headers={"Remote-User": "patrick"})
    assert resp.status_code == 200 and resp.json()["auth_method"] == "proxy"


@pytest.mark.asyncio
async def test_reads_work_without_token(client):
    assert (await client.get("/api/findings")).status_code == 200
    assert (await client.get("/api/settings/api-token")).json() == {"configured": False, "source": None, "created_at": None}


@pytest.mark.asyncio
async def test_generated_token_rotation(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "env-token-123")
    env = {"Authorization": "Bearer env-token-123"}
    assert (await client.get("/api/auth/me", headers=env)).status_code == 200
    assert (await client.get("/api/settings/api-token")).json()["source"] == "env"

    resp = await client.post("/api/auth/token", headers=env)
    assert resp.status_code == 200
    new = resp.json()["access_token"]
    assert new.startswith("vig_") and len(new) > 40
    # env token no longer valid once a token was generated; new one works
    assert (await client.get("/api/auth/me", headers=env)).status_code == 401
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {new}"})).status_code == 200
    info = (await client.get("/api/settings/api-token")).json()
    assert info["source"] == "generated" and new not in str(info)

    # rotating again invalidates the previous generated token
    newer = (await client.post("/api/auth/token", headers={"Authorization": f"Bearer {new}"})).json()["access_token"]
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {new}"})).status_code == 401
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {newer}"})).status_code == 200


@pytest.mark.asyncio
async def test_settings_write_with_token(client):
    token = await _new_token(client)
    resp = await client.post("/api/settings", json={"ssh_timeout": 30}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_rate_limit_after_failed_attempts(client):
    await _new_token(client)
    for _ in range(auth_token.MAX_FAILURES):
        assert (await client.get("/api/auth/me", headers={"Authorization": "Bearer wrong"})).status_code == 401
    assert (await client.get("/api/auth/me", headers={"Authorization": "Bearer wrong"})).status_code == 429


def test_no_private_key_in_source():
    root = Path(__file__).resolve().parents[2] / "vigilance"
    for path in root.rglob("*.py"):
        assert not re.search(r"BEGIN (OPENSSH|RSA|EC) PRIVATE KEY", path.read_text()), path


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not installed")
def test_ssh_key_generated_and_never_overwritten(tmp_path):
    from vigilance.discovery.sshkey import ensure_ssh_key, rotate_ssh_key
    priv, pub = tmp_path / "id_rsa", tmp_path / "id_rsa.pub"
    first = ensure_ssh_key(priv, pub)
    assert first.startswith("ssh-ed25519 ")
    assert ensure_ssh_key(priv, pub) == first  # existing key is kept
    second = rotate_ssh_key(priv, pub)
    assert second != first and second.startswith("ssh-ed25519 ")
    assert len(list(tmp_path.glob("id_rsa.old-*"))) == 1 and len(list(tmp_path.glob("id_rsa.pub.old-*"))) == 1
