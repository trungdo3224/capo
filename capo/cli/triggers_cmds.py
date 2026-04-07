"""Custom trigger management CLI commands."""

import typer

from capo.cli.helpers import require_target

triggers_app = typer.Typer(help="Service trigger management")


@triggers_app.callback(invoke_without_command=True)
def triggers_check(ctx: typer.Context):
    """Show discovered services for the current target."""
    if ctx.invoked_subcommand is not None:
        return
    require_target()
    from capo.modules.triggers import check_triggers
    check_triggers()
