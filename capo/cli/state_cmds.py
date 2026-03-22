"""State inspection & management CLI commands."""

import typer

from capo.cli.helpers import print_json_data, require_target
from capo.state import state_manager
from capo.utils.display import (
    console,
    print_credentials_table,
    print_directory_tree,
    print_error,
    print_ports_table,
    print_state_table,
    print_success,
    print_warning,
)

state_app = typer.Typer(help="State inspection & management")


@state_app.command("show")
def state_show(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show full target state."""
    require_target()
    if as_json:
        console.print_json(state_manager.export_state())
    else:
        print_state_table(state_manager.state, mgr=state_manager)


@state_app.command("ports")
def state_ports(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show discovered ports and services."""
    require_target()
    ports = state_manager.get("ports", [])
    if as_json:
        print_json_data(ports)
    elif ports:
        print_ports_table(ports)
    else:
        print_warning("No ports discovered yet. Run: capo scan quick")


@state_app.command("users")
def state_users(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show discovered users."""
    require_target()
    users = state_manager.get("users", [])
    if as_json:
        print_json_data(users)
    elif users:
        for u in users:
            console.print(f"  [cyan]•[/cyan] {u}")
    else:
        print_warning("No users discovered yet.")


@state_app.command("creds")
def state_creds(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show discovered credentials."""
    require_target()
    creds = state_manager.get("credentials", [])
    if as_json:
        print_json_data(creds)
    elif creds:
        print_credentials_table(creds)
    else:
        print_warning("No credentials discovered yet.")


@state_app.command("dirs")
def state_dirs():
    """Show discovered web directories."""
    require_target()
    from rich.table import Table
    dirs = state_manager.get("directories", [])
    if dirs:
        table = Table(title="Discovered Directories", border_style="cyan")
        table.add_column("Path", style="cyan")
        table.add_column("Status", style="green", justify="right")
        for d in dirs:
            table.add_row(d.get("path", ""), str(d.get("status", "")))
        console.print(table)
    else:
        print_warning("No directories discovered yet. Run: capo web fuzz")


@state_app.command("export")
def state_export(
    fmt: str = typer.Option("json", "--format", "-f", help="Export format: json, csv, markdown"),
    section: str = typer.Option("all", "--section", "-s", help="CSV section: ports, users, credentials, hashes, shares"),
):
    """Export state data in various formats."""
    require_target()
    if fmt == "json":
        console.print_json(state_manager.export_state())
    elif fmt == "csv":
        from capo.modules.reporting import export_csv
        console.print(export_csv(section=section))
    elif fmt == "markdown":
        from capo.modules.reporting import generate_markdown
        console.print(generate_markdown())
    else:
        print_error(f"Unknown format: {fmt}. Use: json, csv, markdown")


@state_app.command("history")
def state_history():
    """Show scan execution history."""
    require_target()
    from rich.table import Table
    history = state_manager.get("scan_history", [])
    if history:
        table = Table(title="Scan History", border_style="cyan")
        table.add_column("Time", style="dim")
        table.add_column("Tool", style="cyan")
        table.add_column("Duration", style="yellow", justify="right")
        table.add_column("Command", style="white", max_width=70)
        for h in history:
            dur = h.get("duration", 0)
            dur_str = f"{dur:.1f}s" if dur else ""
            table.add_row(
                h.get("timestamp", "")[:19],
                h.get("tool", ""),
                dur_str,
                h.get("command", "")[:70],
            )
        console.print(table)
    else:
        print_warning("No scan history yet.")


@state_app.command("workspace")
def state_workspace():
    """Show workspace directory structure."""
    require_target()
    print_directory_tree(state_manager.workspace)


@state_app.command("refresh")
def state_refresh(
    notes_only: bool = typer.Option(False, "--notes", "-n", help="Only regenerate notes.md"),
    files_only: bool = typer.Option(False, "--files", "-f", help="Only regenerate loot files"),
):
    """Regenerate loot files and notes.md from current state.

    Examples:
        capo state refresh          # refresh everything
        capo state refresh --notes  # only regenerate notes.md
        capo state refresh --files  # only regenerate loot files
    """
    require_target()

    do_files = not notes_only
    do_notes = not files_only

    if do_files:
        ws = state_manager.workspace
        loot = ws / "loot"
        loot.mkdir(parents=True, exist_ok=True)

        synced = False
        users = state_manager.get("users", [])
        if users:
            (loot / "users.txt").write_text("\n".join(users) + "\n", encoding="utf-8")
            filtered = [
                u for u in users
                if not u.startswith("SM_")
                and not u.startswith("HealthMailbox")
                and not u.startswith("$")
                and u not in ("Guest", "DefaultAccount", "krbtgt")
            ]
            (loot / "users_filtered.txt").write_text("\n".join(filtered) + "\n", encoding="utf-8")
            print_success(f"users.txt ({len(users)}), users_filtered.txt ({len(filtered)})")
            synced = True

        hashes = state_manager.get("hashes", [])
        if hashes:
            (loot / "hashes.txt").write_text(
                "\n".join(h["hash"] for h in hashes) + "\n", encoding="utf-8"
            )
            print_success(f"hashes.txt ({len(hashes)})")
            synced = True

        creds = state_manager.get("credentials", [])
        if creds:
            lines = [f"{c['username']}:{c['password']}" for c in creds]
            (loot / "creds.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            print_success(f"creds.txt ({len(creds)})")
            synced = True

        if not synced:
            print_warning("No data to sync yet.")

    if do_notes:
        result = state_manager.refresh_notes()
        if result:
            print_success(f"Updated {result.name}")
        else:
            print_error("Failed to refresh notes.")
