"""State inspection & management CLI commands."""

import typer

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
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    if as_json:
        console.print_json(state_manager.export_state())
    else:
        print_state_table(state_manager.state)


@state_app.command("ports")
def state_ports(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show discovered ports and services."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    ports = state_manager.get("ports", [])
    if as_json:
        import json as _json
        console.print_json(_json.dumps(ports, indent=2))
    elif ports:
        print_ports_table(ports)
    else:
        print_warning("No ports discovered yet. Run: capo scan quick")


@state_app.command("users")
def state_users(
    as_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show discovered users."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    users = state_manager.get("users", [])
    if as_json:
        import json as _json
        console.print_json(_json.dumps(users, indent=2))
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
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    creds = state_manager.get("credentials", [])
    if as_json:
        import json as _json
        console.print_json(_json.dumps(creds, indent=2))
    elif creds:
        print_credentials_table(creds)
    else:
        print_warning("No credentials discovered yet.")


@state_app.command("dirs")
def state_dirs():
    """Show discovered web directories."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
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
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
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
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
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
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    print_directory_tree(state_manager.workspace)


@state_app.command("sync-files")
def state_sync_files():
    """Regenerate loot files (users.txt, hashes.txt, creds.txt) from state."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    ws = state_manager.workspace
    loot = ws / "loot"
    loot.mkdir(parents=True, exist_ok=True)

    users = state_manager.get("users", [])
    if users:
        (loot / "users.txt").write_text("\n".join(users) + "\n", encoding="utf-8")
        # Filtered list: skip service/system accounts
        filtered = [
            u for u in users
            if not u.startswith("SM_")
            and not u.startswith("HealthMailbox")
            and not u.startswith("$")
            and u not in ("Guest", "DefaultAccount", "krbtgt")
        ]
        (loot / "users_filtered.txt").write_text("\n".join(filtered) + "\n", encoding="utf-8")
        print_success(f"users.txt ({len(users)}), users_filtered.txt ({len(filtered)})")

    hashes = state_manager.get("hashes", [])
    if hashes:
        (loot / "hashes.txt").write_text(
            "\n".join(h["hash"] for h in hashes) + "\n", encoding="utf-8"
        )
        print_success(f"hashes.txt ({len(hashes)})")

    creds = state_manager.get("credentials", [])
    if creds:
        lines = [f"{c['username']}:{c['password']}" for c in creds]
        (loot / "creds.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print_success(f"creds.txt ({len(creds)})")

    if not users and not hashes and not creds:
        print_warning("No data to sync yet.")


@state_app.command("refresh-notes")
def state_refresh_notes():
    """Regenerate notes.md from current state data."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    result = state_manager.refresh_notes()
    if result:
        print_success(f"Updated {result.name}")
    else:
        print_error("Failed to refresh notes.")
