"""Exam mode management CLI commands."""

import click
import typer

from capo.cli.helpers import require_target
from capo.utils.display import console


def _set_mode(args: list[str]):
    """Set exam mode from fallback args."""
    from capo.modules.mode import mode_manager
    mode_manager.set_mode(args[0])


class _ModeGroup(typer.core.TyperGroup):
    """Routes unknown subcommands to _set_mode (e.g. 'capo mode oscp')."""

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            _set_mode(list(args))
            raise typer.Exit()


mode_app = typer.Typer(help="Exam mode management (OSCP/CPTS)", cls=_ModeGroup)


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
        require_target()
        from capo.modules.triggers import check_triggers
        check_triggers()
