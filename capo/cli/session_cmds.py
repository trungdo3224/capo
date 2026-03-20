"""Session management CLI commands."""

import typer
from rich.panel import Panel
from rich.table import Table

from capo.modules.session_db import session_db
from capo.utils.display import console, print_error, print_success, print_warning

session_app = typer.Typer(help="Session management — named engagement contexts with command tracking")


def _activate_managers(session: dict):
    """Set target + campaign from a session dict."""
    from capo.campaign import campaign_manager
    from capo.state import state_manager

    state_manager.set_target(session["target_ip"])
    if session["domain"]:
        state_manager.add_domain(session["domain"])
    if session["campaign"]:
        campaign_manager.set_campaign(session["campaign"])


# ── Session lifecycle ──────────────────────────────────────


@session_app.command("new")
def session_new(
    name: str = typer.Argument(..., help="Session name (e.g. Forest, Sauna)"),
    target_ip: str = typer.Argument(..., help="Target IP address"),
    domain: str = typer.Option("", "--domain", "-d", help="Domain name (e.g. htb.local)"),
    campaign: str = typer.Option("", "--campaign", "-c", help="Campaign name"),
):
    """Create a new session and activate it."""
    try:
        session = session_db.create_session(name, target_ip, domain, campaign)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)

    session_db.activate_session(name)
    _activate_managers(session)

    print_success(f"Session '{name}' created and activated")
    console.print(f"  Target: [cyan]{target_ip}[/cyan]")
    if domain:
        console.print(f"  Domain: [cyan]{domain}[/cyan]")
    if campaign:
        console.print(f"  Campaign: [cyan]{campaign}[/cyan]")


@session_app.command("use")
def session_use(
    name: str = typer.Argument(..., help="Session name to activate"),
):
    """Switch to an existing session."""
    try:
        session = session_db.activate_session(name)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)

    _activate_managers(session)
    print_success(f"Switched to session '{name}' → {session['target_ip']}")


@session_app.command("list")
def session_list():
    """List all sessions."""
    sessions = session_db.list_sessions()
    if not sessions:
        print_warning("No sessions yet. Create one: capo session new <name> <ip>")
        return

    table = Table(title="Sessions", border_style="cyan")
    table.add_column("Name", style="cyan bold")
    table.add_column("Target", style="white")
    table.add_column("Domain", style="dim")
    table.add_column("Campaign", style="dim")
    table.add_column("Status", style="green")
    table.add_column("Commands", justify="right")
    table.add_column("Updated", style="dim")

    active_name = session_db.active_session_name
    for s in sessions:
        summary = session_db.session_summary(s["name"])
        status = s["status"]
        if s["name"] == active_name:
            status = f"[bold green]● {status}[/bold green]"
        table.add_row(
            s["name"],
            s["target_ip"],
            s.get("domain", ""),
            s.get("campaign", ""),
            status,
            str(summary.get("total_commands", 0)),
            s["updated_at"][:19],
        )
    console.print(table)


@session_app.command("show")
def session_show(
    name: str = typer.Argument(None, help="Session name (defaults to active)"),
):
    """Show session details with recent commands and findings."""
    name = name or session_db.active_session_name
    if not name:
        print_error("No active session. Use: capo session new <name> <ip>")
        raise typer.Exit(1)

    summary = session_db.session_summary(name)
    if not summary:
        print_error(f"Session '{name}' not found.")
        raise typer.Exit(1)

    # Header panel
    active = " [bold green](active)[/bold green]" if name == session_db.active_session_name else ""
    header = (
        f"[bold cyan]{summary['name']}[/bold cyan]{active}\n"
        f"Target: [white]{summary['target_ip']}[/white]"
    )
    if summary.get("domain"):
        header += f"  Domain: [white]{summary['domain']}[/white]"
    if summary.get("campaign"):
        header += f"  Campaign: [white]{summary['campaign']}[/white]"
    header += f"\nStatus: [green]{summary['status']}[/green]"
    header += (
        f"\n\nCommands: [yellow]{summary['total_commands']}[/yellow]  "
        f"Key steps: [yellow]{summary['key_steps']}[/yellow]  "
        f"Findings: [yellow]{summary['findings_count']}[/yellow]"
    )
    if summary.get("first_command_at"):
        header += f"\nFirst: {summary['first_command_at'][:19]}  Last: {summary['last_command_at'][:19]}"

    console.print(Panel(header, title="Session", border_style="cyan"))

    # Recent commands
    cmds = session_db.list_commands(name)
    if cmds:
        table = Table(title="Recent Commands (last 15)", border_style="dim")
        table.add_column("#", style="dim", justify="right")
        table.add_column("Tool", style="cyan")
        table.add_column("Command", style="white", max_width=60)
        table.add_column("Dur", style="yellow", justify="right")
        table.add_column("Key", justify="center")
        table.add_column("Time", style="dim")
        for c in cmds[-15:]:
            dur = f"{c['duration']:.1f}s" if c["duration"] else ""
            key = "[bold yellow]★[/bold yellow]" if c["is_key"] else ""
            table.add_row(
                str(c["id"]),
                c["tool"],
                c["command"][:60],
                dur,
                key,
                c["created_at"][:19],
            )
        console.print(table)

    # Findings
    findings = session_db.list_findings(name)
    if findings:
        ftable = Table(title="Findings", border_style="red")
        ftable.add_column("#", style="dim", justify="right")
        ftable.add_column("Title", style="white")
        ftable.add_column("Category", style="cyan")
        ftable.add_column("Severity", style="yellow")
        ftable.add_column("Cmd #", style="dim", justify="right")
        for f in findings:
            sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}
            sev_style = sev_colors.get(f["severity"], "white")
            ftable.add_row(
                str(f["id"]),
                f["title"],
                f["category"],
                f"[{sev_style}]{f['severity']}[/{sev_style}]",
                str(f["command_id"] or ""),
            )
        console.print(ftable)


@session_app.command("delete")
def session_delete(
    name: str = typer.Argument(..., help="Session name to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a session and all its data."""
    session = session_db.get_session(name)
    if not session:
        print_error(f"Session '{name}' not found.")
        raise typer.Exit(1)

    if not force:
        summary = session_db.session_summary(name)
        console.print(
            f"Delete session '{name}'? "
            f"({summary.get('total_commands', 0)} commands, "
            f"{summary.get('findings_count', 0)} findings)"
        )
        confirm = typer.confirm("Continue?")
        if not confirm:
            raise typer.Abort()

    session_db.delete_session(name)
    print_success(f"Session '{name}' deleted.")


# ── Command tracking ───────────────────────────────────────


@session_app.command("commands")
def session_commands(
    key: bool = typer.Option(False, "--key", "-k", help="Show only key commands"),
    tool: str = typer.Option(None, "--tool", "-t", help="Filter by tool name"),
):
    """List commands in the active session."""
    if not session_db.active_session_name:
        print_error("No active session.")
        raise typer.Exit(1)

    cmds = session_db.list_commands(key_only=key, tool=tool)
    if not cmds:
        print_warning("No commands recorded yet.")
        return

    table = Table(
        title=f"Commands — {session_db.active_session_name}",
        border_style="cyan",
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Tool", style="cyan")
    table.add_column("Command", style="white", max_width=70)
    table.add_column("Dur", style="yellow", justify="right")
    table.add_column("Key", justify="center")
    table.add_column("Src", style="dim")
    table.add_column("Time", style="dim")
    for c in cmds:
        dur = f"{c['duration']:.1f}s" if c["duration"] else ""
        key_mark = "[bold yellow]★[/bold yellow]" if c["is_key"] else ""
        table.add_row(
            str(c["id"]),
            c["tool"],
            c["command"][:70],
            dur,
            key_mark,
            c["source"],
            c["created_at"][:19],
        )
    console.print(table)


@session_app.command("log")
def session_log(
    command: str = typer.Argument(..., help="Command string to record"),
    tool: str = typer.Option("manual", "--tool", "-t", help="Tool name"),
):
    """Manually log a command run outside capo."""
    if not session_db.active_session_name:
        print_error("No active session.")
        raise typer.Exit(1)

    cmd_id = session_db.record_command(
        tool=tool, command=command, source="manual",
    )
    print_success(f"Logged command #{cmd_id}")


# ── Marking & findings ────────────────────────────────────


@session_app.command("mark")
def session_mark(
    cmd_id: int = typer.Argument(..., help="Command ID to mark"),
    key: bool = typer.Option(False, "--key", "-k", help="Mark as key step"),
    finding: str = typer.Option(None, "--finding", "-f", help="Create finding with this title"),
    category: str = typer.Option("general", "--category", help="Finding category"),
    severity: str = typer.Option("info", "--severity", help="Finding severity"),
):
    """Mark a command as a key step and/or create a finding from it."""
    if not key and not finding:
        print_error("Provide at least --key or --finding")
        raise typer.Exit(1)

    cmd = session_db.get_command(cmd_id)
    if not cmd:
        print_error(f"Command #{cmd_id} not found.")
        raise typer.Exit(1)

    if key:
        session_db.mark_key(cmd_id, True)
        print_success(f"Command #{cmd_id} marked as key step ★")

    if finding:
        fid = session_db.add_finding(
            title=finding,
            command_id=cmd_id,
            category=category,
            severity=severity,
        )
        print_success(f"Finding #{fid} created: {finding}")


@session_app.command("findings")
def session_findings():
    """List findings in the active session."""
    if not session_db.active_session_name:
        print_error("No active session.")
        raise typer.Exit(1)

    findings = session_db.list_findings()
    if not findings:
        print_warning("No findings yet. Use: capo session mark <cmd_id> --finding 'title'")
        return

    table = Table(
        title=f"Findings — {session_db.active_session_name}",
        border_style="red",
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Title", style="white")
    table.add_column("Category", style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Cmd #", style="dim", justify="right")
    table.add_column("Time", style="dim")

    sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}
    for f in findings:
        sev_style = sev_colors.get(f["severity"], "white")
        table.add_row(
            str(f["id"]),
            f["title"],
            f["category"],
            f"[{sev_style}]{f['severity']}[/{sev_style}]",
            str(f["command_id"] or ""),
            f["created_at"][:19],
        )
    console.print(table)
