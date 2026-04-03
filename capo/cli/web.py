"""Web fuzzing CLI commands."""

import typer

from capo.cli.helpers import ensure_target
from capo.utils.display import print_error

web_app = typer.Typer(help="Web fuzzing wrappers")


@web_app.command("fuzz")
def web_fuzz(
    port: int = typer.Option(80, "--port", "-p", help="target port"),
    https: bool = typer.Option(False, "--https", "-s", help="use HTTPS"),
    wordlist: str | None = typer.Option(None, "--wordlist", "-w", help="custom wordlist path"),
    extensions: str = typer.Option("", "--ext", "-e", help="file extensions (.php,.txt,.html)"),
    host: str = typer.Option("ip", "--host", help="URL host type: ip or domain"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="domain/subdomain when --host domain"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Directory/file fuzzing with ffuf."""
    ensure_target(target)
    host = host.lower().strip()
    if host not in {"ip", "domain"}:
        print_error("Invalid --host value. Use: ip or domain")
        raise typer.Exit(1)
    from capo.modules.triggers import check_triggers
    from capo.modules.wrappers.web_wrapper import WebFuzzWrapper
    web = WebFuzzWrapper(profile=profile, dry_run=dry_run)
    web.dir_fuzz(port, https, wordlist, target, extensions, host, domain)
    if not dry_run:
        check_triggers()


@web_app.command("vhost")
def web_vhost(
    domain: str | None = typer.Option(None, "--domain", "-d", help="base domain"),
    port: int = typer.Option(80, "--port", "-p", help="target port"),
    https: bool = typer.Option(False, "--https", "-s", help="use HTTPS"),
    wordlist: str | None = typer.Option(None, "--wordlist", "-w", help="custom wordlist path"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Virtual host discovery with ffuf."""
    ensure_target(target)
    from capo.modules.wrappers.web_wrapper import WebFuzzWrapper
    web = WebFuzzWrapper(profile=profile, dry_run=dry_run)
    web.vhost_fuzz(domain, port, https, wordlist, target)


@web_app.command("subdns")
def web_subdns(
    domain: str | None = typer.Option(None, "--domain", "-d", help="base domain (uses state if omitted)"),
    wordlist: str | None = typer.Option(None, "--wordlist", "-w", help="custom wordlist path"),
    resolver: str | None = typer.Option(None, "--resolver", "-r", help="custom DNS resolver IP"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Subdomain DNS enumeration (gobuster dns / ffuf fallback)."""
    ensure_target(target)
    from capo.modules.triggers import check_triggers
    from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

    web = WebFuzzWrapper(profile=profile, dry_run=dry_run)
    web.subdns_fuzz(domain, wordlist, target, resolver)
    if not dry_run:
        check_triggers()


@web_app.command("recursive")
def web_recursive(
    port: int = typer.Option(80, "--port", "-p", help="target port"),
    https: bool = typer.Option(False, "--https", "-s", help="use HTTPS"),
    wordlist: str | None = typer.Option(None, "--wordlist", "-w", help="custom wordlist path"),
    depth: int = typer.Option(2, "--depth", "-D", help="recursion depth"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Recursive directory fuzzing."""
    ensure_target(target)
    from capo.modules.wrappers.web_wrapper import WebFuzzWrapper
    web = WebFuzzWrapper(profile=profile, dry_run=dry_run)
    web.recursive_fuzz(port, https, wordlist, depth, target)
