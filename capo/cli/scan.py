"""Scanning & enumeration CLI commands."""

import typer

from capo.cli.helpers import ensure_target
from capo.utils.display import print_info

scan_app = typer.Typer(help="Scanning & enumeration wrappers")


@scan_app.command("quick")
def scan_quick(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", "-p", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
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
    ports: str | None = typer.Option(None, "--ports", "-p", help="ports to scan (comma-separated)"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
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
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """UDP top-ports scan."""
    ensure_target(target)
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.udp_scan(target)


@scan_app.command("vuln")
def scan_vuln(
    ports: str | None = typer.Option(None, "--ports", "-p", help="ports to scan (comma-separated)"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Run Nmap vuln scripts (OSCP-safe NSE scripts)."""
    ensure_target(target)
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(dry_run=dry_run)
    nmap.vuln_scan(ports, target)


@scan_app.command("custom")
def scan_custom(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    nmap_args: str = typer.Option(..., "--args", "-a", help="custom nmap flags, e.g. '-p 80,443 -sC -sV'"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Custom nmap scan — pass any nmap flags while results still parse into state."""
    ensure_target(target)
    from capo.modules.triggers import check_triggers
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(dry_run=dry_run)
    nmap.custom_scan(nmap_args, target)
    if not dry_run:
        check_triggers()


@scan_app.command("ports")
def scan_ports(
    ports: str = typer.Argument(..., help="port list, e.g. '80,443,8080-8090'"),
    target: str | None = typer.Option(None, "--target", "-t", help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    no_scripts: bool = typer.Option(False, "--no-scripts", help="skip default NSE scripts (-sC)"),
    no_versions: bool = typer.Option(False, "--no-versions", help="skip version detection (-sV)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Scan a specific port list with version/script detection — no prior quick scan required."""
    ensure_target(target)
    from capo.modules.triggers import check_triggers
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.ports_scan(ports, target, run_scripts=not no_scripts, detect_versions=not no_versions)
    if not dry_run:
        check_triggers()


@scan_app.command("os")
def scan_os(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """OS detection scan (-O --osscan-guess). Best run as root."""
    ensure_target(target)
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.os_scan(target)


@scan_app.command("scripts")
def scan_scripts(
    scripts: str = typer.Argument(..., help="NSE scripts, e.g. 'smb-vuln-ms17-010,http-title'"),
    ports: str | None = typer.Option(None, "--ports", "-p", help="ports (uses discovered if omitted)"),
    target: str | None = typer.Option(None, "--target", "-t", help="target IP (current if omitted)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Run specific NSE scripts against discovered or specified ports."""
    ensure_target(target)
    from capo.modules.wrappers.nmap_wrapper import NmapWrapper
    nmap = NmapWrapper(dry_run=dry_run)
    nmap.scripts_scan(scripts, ports, target)


@scan_app.command("full")
def scan_full(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
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
