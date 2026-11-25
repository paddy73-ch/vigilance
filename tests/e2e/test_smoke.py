"""Browser smoke test: every page loads without errors, at desktop and phone width.

Runs only with VIGILANCE_E2E=1 and Playwright + Chromium installed:
    VIGILANCE_E2E=1 pytest tests/e2e
Optional: VIGILANCE_E2E_CHROME=/path/to/chrome
"""
import asyncio
import os
import socket
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("VIGILANCE_E2E") != "1", reason="set VIGILANCE_E2E=1")

PAGES = ["/", "/hosts", "/vulnerabilities", "/vulnerabilities?view=cve&fix=", "/admin/sources",
         "/admin/exceptions", "/admin/settings", "/vulnerabilities/fixed"]


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    db_file = tmp_path_factory.mktemp("e2e") / "e2e.db"
    cfg = db_file.parent / "config.yaml"
    cfg.write_text("scan:\n  full_scan_on_start: false\n")
    url = f"sqlite+aiosqlite:///{db_file}"
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from tests.unit.test_views import _seed
    from vigilance.database.base import Base, get_db

    engine = create_async_engine(url)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with maker() as db:
            hosts = await _seed(db)
            return hosts["adguard"].id
    host_id = asyncio.run(setup())

    import uvicorn
    from vigilance.main import app

    async def override_get_db():
        async with maker() as session:
            yield session
            await session.commit()
    app.dependency_overrides[get_db] = override_get_db
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}", host_id
    srv.should_exit = True
    t.join(timeout=5)
    app.dependency_overrides.clear()


@pytest.mark.parametrize("width", [1400, 400])
def test_pages_render_cleanly(server, width):
    playwright = pytest.importorskip("playwright.sync_api")
    base, host_id = server
    with playwright.sync_playwright() as p:
        kwargs = {"args": ["--no-sandbox"]}
        if os.environ.get("VIGILANCE_E2E_CHROME"):
            kwargs["executable_path"] = os.environ["VIGILANCE_E2E_CHROME"]
        browser = p.chromium.launch(**kwargs)
        page = browser.new_page(viewport={"width": width, "height": 900})
        problems, external = [], []
        page.on("pageerror", lambda e: problems.append(f"pageerror {e}"))
        page.on("console", lambda m: problems.append(f"console {m.type}: {m.text}") if m.type in ("error", "warning") else None)
        page.on("request", lambda r: external.append(r.url) if not r.url.startswith(base) else None)
        for path in PAGES + [f"/hosts/{host_id}"]:
            page.goto(base + path)
            page.wait_for_load_state("networkidle")
            overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1")
            assert not overflow, f"{path} scrolls horizontally at {width}px"
            assert page.locator("main").inner_text().strip(), f"{path} is empty"
        assert not problems, problems
        assert not external, external
        browser.close()


def test_write_action_asks_for_token_and_drawer_works(server):
    playwright = pytest.importorskip("playwright.sync_api")
    base, host_id = server
    with playwright.sync_playwright() as p:
        kwargs = {"args": ["--no-sandbox"]}
        if os.environ.get("VIGILANCE_E2E_CHROME"):
            kwargs["executable_path"] = os.environ["VIGILANCE_E2E_CHROME"]
        browser = p.chromium.launch(**kwargs)
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        page.goto(base + "/")
        page.get_by_role("button", name="Jetzt scannen").click()
        page.locator("#vigilance-token-dialog").wait_for()
        page.get_by_role("button", name="Abbrechen").click()
        # host detail -> expand package -> drawer with escaped content
        page.goto(base + f"/hosts/{host_id}")
        page.locator("tr.clickable", has=page.locator(".pkg", has_text="glib2.0")).first.click()
        page.get_by_text("CVE-2024-52533").first.click()
        # the drawer shows "Lädt …" first; wait for the loaded header instead of reading it at once
        page.locator(".drawer-head", has_text="CVE-2024-52533").wait_for(timeout=10000)
        assert page.locator(".drawer a[href^='javascript']").count() == 0
        browser.close()


def test_hosts_table_sorts_by_column(server):
    playwright = pytest.importorskip("playwright.sync_api")
    base, _ = server
    with playwright.sync_playwright() as p:
        kwargs = {"args": ["--no-sandbox"]}
        if os.environ.get("VIGILANCE_E2E_CHROME"):
            kwargs["executable_path"] = os.environ["VIGILANCE_E2E_CHROME"]
        browser = p.chromium.launch(**kwargs)
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        page.goto(base + "/hosts")
        names = page.locator("#hosts-table tbody tr td:first-child")
        names.first.wait_for()

        def shown():
            return [n.strip() for n in names.all_inner_texts()]

        page.locator("th button", has_text="Name").click()
        assert shown() == sorted(shown(), key=str.lower)
        assert "sort=name&dir=asc" in page.url
        page.locator("th button", has_text="Name").click()
        assert shown() == sorted(shown(), key=str.lower, reverse=True)
        assert page.locator("th[aria-sort='descending']").count() == 1
        page.reload()  # the sort is kept in the address
        names.first.wait_for()
        assert shown() == sorted(shown(), key=str.lower, reverse=True)
        page.locator("th button", has_text="Name").click()  # third click: back to "most urgent first"
        assert page.locator("th[aria-sort='ascending'], th[aria-sort='descending']").count() == 0
        assert page.url.endswith("/hosts")
        browser.close()
