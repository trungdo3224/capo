"""Manual finding entry CLI commands — record what you discovered."""

import typer

from capo.cli.helpers import require_target
from capo.state import state_manager
from capo.utils.display import print_success

found_app = typer.Typer(help="Record discovered data — users, creds, hashes, vhosts, flags, notes")


@found_app.command("user")
def found_user(
    username: str = typer.Argument(..., help="username to add"),
):
    """Add a discovered username."""
    require_target()
    state_manager.add_user(username)
    print_success(f"Added user: {username}")


@found_app.command("cred")
def found_cred(
    username: str = typer.Argument(..., help="username"),
    password: str = typer.Argument(..., help="password"),
    service: str = typer.Option("", "--service", "-s", help="service name"),
):
    """Add discovered credentials."""
    require_target()
    state_manager.add_credential(username, password, service)
    print_success(f"Credential added: {username}")


@found_app.command("hash")
def found_hash(
    hash_value: str = typer.Argument(..., help="hash value"),
    username: str = typer.Option("", "--user", "-u", help="associated username"),
):
    """Add a discovered hash."""
    require_target()
    state_manager.add_hash(hash_value, username)
    print_success("Hash added.")


@found_app.command("vhost")
def found_vhost(
    vhost: str = typer.Argument(..., help="domain or subdomain to add"),
):
    """Add a discovered vhost/subdomain."""
    require_target()
    state_manager.add_vhost(vhost)
    print_success(f"Added vhost: {vhost}")


@found_app.command("flag")
def found_flag(
    flag_type: str = typer.Argument(..., help="flag type: local or proof"),
    value: str = typer.Argument(..., help="flag value"),
):
    """Record a captured flag (local.txt / proof.txt)."""
    require_target()
    key = f"{flag_type}_txt"
    state_manager.set_flag(key, value)
    print_success(f"🚩 {flag_type}.txt = {value}")


@found_app.command("note")
def found_note(
    note: str = typer.Argument(..., help="note text"),
):
    """Add a quick note to the target."""
    require_target()
    state_manager.add_note(note)
    print_success("Note added.")
