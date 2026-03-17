"""Suggestion daemon CLI commands."""

import typer

daemon_app = typer.Typer(help="Suggestion daemon")


@daemon_app.command("start")
def daemon_start():
    """Start the priority-based suggestion engine daemon."""
    from capo.modules.daemon import Daemon
    d = Daemon()
    d.run()
