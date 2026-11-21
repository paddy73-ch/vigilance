import asyncio
import typer
from rich.console import Console
from rich.table import Table

from vigilance.config import settings
from vigilance.core.notifications import send_test_gotify
from vigilance.core.scheduler import trigger_scan_now, trigger_cve_sync_now
from vigilance.database.base import init_db, async_session_maker
from vigilance.database import crud

app = typer.Typer(name="vigilance", help="Vigilance - Security & Patch Monitoring for Proxmox")
console = Console()


@app.command()
def test_gotify():
    """Test Gotify connectivity."""
    console.print("Testing Gotify connection...")
    success = asyncio.run(send_test_gotify())
    if success:
        console.print("[green]✓[/green] Test notification sent successfully")
    else:
        console.print("[red]✗[/red] Failed to send test notification")
        console.print("Check your Gotify URL and token in .env")


@app.command()
def scan_now(full: bool = typer.Option(False, "--full", help="Run full scan instead of incremental")):
    """Trigger a discovery scan."""
    console.print(f"Starting {'full' if full else 'incremental'} scan...")
    scan_run_id = asyncio.run(trigger_scan_now(full=full))
    console.print(f"[green]✓[/green] Scan completed (run ID: {scan_run_id})")


@app.command()
def sync_cves(source: str = typer.Option(None, "--source", help="Specific source to sync (osv, ghsa, nvd, debian, ubuntu)")):
    """Trigger CVE database sync."""
    if source:
        console.print(f"Syncing CVE data from {source}...")
    else:
        console.print("Syncing CVE data from all enabled sources...")
    results = asyncio.run(trigger_cve_sync_now())
    console.print("[green]✓[/green] CVE sync completed")
    for src, result in results.items():
        status = result.get("status", "unknown")
        count = result.get("count", 0)
        console.print(f"  {src}: {status} ({count} entries)")


@app.command()
def db_upgrade():
    """Run database migrations."""
    console.print("Running database migrations...")
    asyncio.run(init_db())
    console.print("[green]✓[/green] Database migrations completed")


@app.command()
def config_check():
    """Validate configuration."""
    console.print("Validating configuration...")
    errors = []

    if not settings.proxmox_nodes:
        errors.append("No Proxmox nodes configured")

    if not settings.api_token:
        errors.append("No API token configured (VIGILANCE_API_TOKEN)")

    if settings.notifications and settings.notifications.gotify:
        if not settings.notifications.gotify.url:
            errors.append("Gotify URL not configured")
        if not settings.notifications.gotify.token:
            errors.append("Gotify token not configured")

    if errors:
        console.print("[red]Configuration errors:[/red]")
        for err in errors:
            console.print(f"  - {err}")
        raise typer.Exit(1)
    else:
        console.print("[green]✓[/green] Configuration is valid")


@app.command()
def list_nodes():
    """List configured Proxmox nodes."""
    table = Table(title="Proxmox Nodes")
    table.add_column("Name", style="cyan")
    table.add_column("URL", style="blue")
    table.add_column("Token ID", style="green")
    table.add_column("TLS Verify", style="yellow")
    table.add_column("SSH Host", style="magenta")

    for node in settings.proxmox_nodes:
        table.add_row(
            node.name,
            node.url,
            node.token_id,
            "Yes" if node.verify_tls else "No",
            node.ssh_host or "Not configured",
        )

    console.print(table)


@app.command()
def list_overrides():
    """List tool overrides from database."""
    async def _list():
        async with async_session_maker() as db:
            overrides = await crud.get_tool_overrides(db)
            return overrides

    overrides = asyncio.run(_list())

    table = Table(title="Tool Overrides")
    table.add_column("Tool Name", style="cyan")
    table.add_column("CPE Name", style="blue")
    table.add_column("Package Name", style="green")
    table.add_column("Ecosystem", style="yellow")
    table.add_column("Version Pattern", style="magenta")

    for o in overrides:
        table.add_row(
            o.tool_name,
            o.cpe_name or "",
            o.package_name or "",
            o.ecosystem or "",
            o.version_pattern or "",
        )

    console.print(table)


@app.command()
def version():
    """Show version information."""
    console.print("Vigilance v0.1.0")
    console.print("Self-hosted Security & Patch Monitoring for Proxmox")


if __name__ == "__main__":
    app()