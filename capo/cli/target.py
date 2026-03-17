"""Target management CLI commands."""

import typer

from capo.state import state_manager
from capo.campaign import campaign_manager
from capo.utils.display import (
    print_directory_tree,
    print_error,
    print_info,
    print_state_table,
    print_success,
)

target_app = typer.Typer(help="Target management commands")


@target_app.command("set")
def target_set(
    ip: str = typer.Argument(..., help="Target IP or hostname"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="Target domain"),
    campaign: str | None = typer.Option(None, "--campaign", "-c", help="Link to a campaign"),
):
    """Set the current target and initialize workspace."""
    if campaign:
        campaign_manager.set_campaign(campaign)
        
    try:
        workspace = state_manager.set_target(ip)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)
        
    if domain:
        state_manager.set("domain", domain)
        state_manager.state.setdefault("domain_info", {})["domain_name"] = domain

    print_success(f"Target set: {ip}")
    if domain:
        print_info(f"Domain: {domain}")
    if campaign_manager.active:
        print_info(f"Campaign Active: {campaign_manager.name}")
        
    print_info(f"Workspace: {workspace}")
    print_directory_tree(workspace)


@target_app.command("show")
def target_show():
    """Show current target information."""
    if campaign_manager.active:
        print_info(f"Active Campaign: {campaign_manager.name}")
        
    if not state_manager.target:
        print_error("No target set. Use: capo target set <IP>")
        raise typer.Exit(1)
    print_state_table(state_manager.state)


@target_app.command("campaign")
def target_campaign(
    name: str = typer.Argument(None, help="Campaign name"),
    clear: bool = typer.Option(False, "--clear", help="Exit the current campaign"),
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
            # Could show campaign stats here
        else:
            print_info("No active campaign. Operating in single-host mode.")


@target_app.command("set-domain")
def target_set_domain(
    domain: str = typer.Argument(..., help="Domain name"),
    dc_ip: str | None = typer.Option(None, "--dc-ip", help="Domain Controller IP"),
):
    """Set domain information for AD engagements."""
    if not state_manager.target and not campaign_manager.active:
        print_error("No target or campaign set.")
        raise typer.Exit(1)
        
    if campaign_manager.active:
        campaign_manager.update_domain_info(domain_name=domain, dc_ip=dc_ip)
    else:
        state_manager.set("domain", domain)
        info = state_manager.get("domain_info", {})
        info["domain_name"] = domain
        if dc_ip:
            info["dc_ip"] = dc_ip
        state_manager.set("domain_info", info)
        
    print_success(f"Domain set: {domain}")


@target_app.command("set-lhost")
def target_set_lhost(
    lhost: str = typer.Argument(..., help="Your attack machine IP"),
    lport: int = typer.Option(443, "--lport", "-p", help="Listener port"),
):
    """Set your local host IP for reverse shells and pivoting."""
    if not state_manager.target:
        print_error("No target set first.")
        raise typer.Exit(1)
    state_manager.set("lhost", lhost)
    state_manager.set("lport", lport)
    print_success(f"LHOST={lhost}, LPORT={lport}")


@target_app.command("add-user")
def target_add_user(
    username: str = typer.Argument(..., help="Username to add"),
):
    """Manually add a discovered username."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    state_manager.add_user(username)
    print_success(f"Added user: {username}")


@target_app.command("add-cred")
def target_add_cred(
    username: str = typer.Argument(..., help="Username"),
    password: str = typer.Argument(..., help="Password"),
    service: str = typer.Option("", "--service", "-s", help="Service name"),
):
    """Add discovered credentials."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    state_manager.add_credential(username, password, service)
    print_success(f"Credential added: {username}")


@target_app.command("add-hash")
def target_add_hash(
    hash_value: str = typer.Argument(..., help="Hash value"),
    username: str = typer.Option("", "--user", "-u", help="Associated username"),
):
    """Add a discovered hash."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    state_manager.add_hash(hash_value, username)
    print_success("Hash added.")


@target_app.command("add-vhost")
def target_add_vhost(
    vhost: str = typer.Argument(..., help="Domain or subdomain to add"),
):
    """Manually add a discovered vhost/subdomain."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    state_manager.add_vhost(vhost)
    print_success(f"Added vhost: {vhost}")


@target_app.command("flag")
def target_flag(
    flag_type: str = typer.Argument(..., help="Flag type: local or proof"),
    value: str = typer.Argument(..., help="Flag value"),
):
    """Record a captured flag (local.txt / proof.txt)."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    key = f"{flag_type}_txt"
    state_manager.set_flag(key, value)
    print_success(f"🚩 {flag_type}.txt = {value}")


@target_app.command("note")
def target_note(
    note: str = typer.Argument(..., help="Note text"),
):
    """Add a quick note to the target."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    state_manager.add_note(note)
    print_success("Note added.")
