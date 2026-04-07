"""Target management CLI commands."""

import typer

from capo.campaign import campaign_manager
from capo.cli.helpers import require_target
from capo.errors import TargetError
from capo.state import state_manager
from capo.utils.display import (
    print_directory_tree,
    print_error,
    print_info,
    print_success,
)

target_app = typer.Typer(help="Target management commands")


@target_app.command("set")
def target_set(
    ip: str = typer.Argument(..., help="target IP or hostname"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="target domain"),
    campaign: str | None = typer.Option(None, "--campaign", "-c", help="link to a campaign"),
):
    """Set the current target and initialize workspace."""
    if campaign:
        campaign_manager.set_campaign(campaign)

    try:
        workspace = state_manager.set_target(ip)
    except TargetError as e:
        print_error(str(e))
        raise typer.Exit(1)

    if domain:
        state_manager.add_domain(domain)

    print_success(f"Target set: {ip}")
    if domain:
        print_info(f"Domain: {domain}")
    if campaign_manager.active:
        print_info(f"Campaign Active: {campaign_manager.name}")

    print_info(f"Workspace: {workspace}")
    print_directory_tree(workspace)


@target_app.command("campaign")
def target_campaign(
    name: str = typer.Argument(None, help="campaign name"),
    clear: bool = typer.Option(False, "--clear", help="exit the current campaign"),
):
    """Set, show, or clear the active campaign."""
    if clear:
        campaign_manager.clear_campaign()
        print_success("Exited campaign. Operating in single-host mode.")
        return

    if name:
        campaign_manager.set_campaign(name)
        print_success(f"Campaign set: {name}")
        if state_manager.target:
            campaign_manager.add_host(str(state_manager.target))
            print_info(f"Host {state_manager.target} bound to campaign.")
    else:
        if campaign_manager.active:
            print_info(f"Active Campaign: {campaign_manager.name}")
        else:
            print_info("No active campaign. Operating in single-host mode.")


@target_app.command("set-domain")
def target_set_domain(
    domain: str = typer.Argument(..., help="domain name"),
    dc_ip: str | None = typer.Option(None, "--dc-ip", help="Domain Controller IP"),
):
    """Add/set domain information for AD engagements.

    Can be called multiple times to add additional domains.
    Use --dc-ip to set Domain Controller IP alongside the domain.

    Examples:
        capo target set-domain flight.htb
        capo target set-domain flight.htb --dc-ip 10.129.2.5
        capo target set-domain dc.flight.htb          # add second domain
    """
    if not state_manager.target and not campaign_manager.active:
        print_error("No target or campaign set.")
        raise typer.Exit(1)

    if campaign_manager.active:
        campaign_manager.update_domain_info(domain_name=domain, dc_ip=dc_ip)
    else:
        state_manager.add_domain(domain)
        if dc_ip:
            info = state_manager.get("domain_info", {})
            info["dc_ip"] = dc_ip
            state_manager.set("domain_info", info)

    print_success(f"Domain set: {domain}")
    domains = state_manager.get("domains", [])
    if len(domains) > 1:
        print_info(f"All domains: {', '.join(domains)}")


@target_app.command("set-lhost")
def target_set_lhost(
    lhost: str = typer.Argument(..., help="your attack machine IP"),
    lport: int = typer.Option(443, "--lport", "-p", help="listener port"),
):
    """Set your local host IP for reverse shells and pivoting."""
    require_target()
    state_manager.set("lhost", lhost)
    state_manager.set("lport", lport)
    print_success(f"LHOST={lhost}, LPORT={lport}")
