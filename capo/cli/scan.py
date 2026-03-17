"""Scanning & enumeration CLI commands."""

import typer

from capo.cli.helpers import ensure_target
from capo.utils.display import print_info

scan_app = typer.Typer(help="Scanning & enumeration wrappers")


@scan_app.command("quick")
def scan_quick(
    target: str | None = typer.Argument(None, help="Target IP (uses current if not set)"),
    profile: str = typer.Option("normal", "--profile", "-p", help="Scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """Quick all-ports TCP scan with Nmap."""
    ensure_target(target)
    from capo.modules.triggers import check_triggers
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.quick_scan(target)
    if not dry_run:
        check_triggers()


@scan_app.command("detailed")
def scan_detailed(
    ports: str | None = typer.Option(None, "--ports", "-p", help="Ports to scan (comma-separated)"),
    target: str | None = typer.Argument(None, help="Target IP"),
    profile: str = typer.Option("normal", "--profile", help="Scan profile"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """Detailed version/script scan on discovered ports."""
    ensure_target(target)
    from capo.modules.triggers import check_triggers
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.detailed_scan(ports, target)
    if not dry_run:
        check_triggers()


@scan_app.command("udp")
def scan_udp(
    target: str | None = typer.Argument(None, help="Target IP"),
    profile: str = typer.Option("normal", "--profile", help="Scan profile"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """UDP top-ports scan."""
    ensure_target(target)
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.udp_scan(target)


@scan_app.command("vuln")
def scan_vuln(
    ports: str | None = typer.Option(None, "--ports", "-p", help="Ports to scan"),
    target: str | None = typer.Argument(None, help="Target IP"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """Run Nmap vuln scripts (OSCP-safe NSE scripts)."""
    ensure_target(target)
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(dry_run=dry_run)
    nmap.vuln_scan(ports, target)


@scan_app.command("full")
def scan_full(
    target: str | None = typer.Argument(None, help="Target IP"),
    profile: str = typer.Option("normal", "--profile", help="Scan profile"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """Run full recon pipeline: quick -> detailed -> triggers."""
    ensure_target(target)
    from capo.modules.triggers import check_triggers
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper

    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    print_info("=== Phase 1: Quick all-ports scan ===")
    nmap.quick_scan(target)

    print_info("=== Phase 2: Detailed scan on open ports ===")
    nmap.detailed_scan(target=target)

    if not dry_run:
        print_info("=== Phase 3: Context-Aware Suggestions ===")
        check_triggers()
