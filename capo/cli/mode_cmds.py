"""Exam mode management CLI commands."""

import typer

from capo.state import state_manager
from capo.utils.display import console, print_error

mode_app = typer.Typer(help="Exam mode management (OSCP/CPTS)")


@mode_app.command("set")
def mode_set(
    mode: str = typer.Argument(..., help="Exam mode: oscp or cpts"),
):
    """Set exam mode (oscp/cpts)."""
    from capo.modules.mode import mode_manager
    mode_manager.set_mode(mode)


@mode_app.command("show")
def mode_show():
    """Show current exam mode and restrictions."""
    from rich.table import Table

    from capo.modules.mode import mode_manager
    info = mode_manager.get_mode_info()
    table = Table(title="Exam Mode", border_style="cyan")
    table.add_column("Setting", style="bold white")
    table.add_column("Value", style="green")
    table.add_row("Mode", info["mode"])
    table.add_row("AI/LLM Enabled", "Yes" if info["ai_enabled"] else "No")
    table.add_row("Metasploit Used", "Yes" if info["metasploit_used"] else "No")
    if info["restrictions"]:
        table.add_row("Restricted Tools", ", ".join(info["restrictions"]))
    console.print(table)


@mode_app.command("use-msf")
def mode_use_msf():
    """Mark Metasploit as used on current machine (OSCP: 1 machine only)."""
    from capo.modules.mode import mode_manager
    mode_manager.mark_metasploit_used()


def register_suggest_command(app: typer.Typer):
    """Register the suggest command on the main app."""

    @app.command("suggest")
    def suggest():
        """Show context-aware suggestions based on current state."""
        if not state_manager.target:
            print_error("No target set.")
            raise typer.Exit(1)
        from capo.modules.triggers import check_triggers
        check_triggers()
