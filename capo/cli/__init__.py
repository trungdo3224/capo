"""C.A.P.O CLI package — assembles all command groups into the main Typer app."""

import typer

from capo import __version__
from capo.config import ensure_dirs
from capo.errors import CapoError
from capo.utils.display import banner, console, print_error

# Initialize Typer app
app = typer.Typer(
    name="capo",
    help="C.A.P.O - Context-Aware Pentest Orchestrator for OSCP/CPTS",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


# ─────────────── Global Callback ───────────────

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
):
    """C.A.P.O - Context-Aware Pentest Orchestrator."""
    ensure_dirs()
    if version:
        console.print(f"C.A.P.O v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        banner()


# ─────────────── Register Sub-Apps ───────────────

from capo.cli.target import target_app
from capo.cli.scan import scan_app
from capo.cli.nxc import nxc_app
from capo.cli.brute import brute_app
from capo.cli.web import web_app
from capo.cli.state_cmds import state_app
from capo.cli.mode_cmds import mode_app
from capo.cli.report import report_app
from capo.cli.triggers_cmds import triggers_app
from capo.cli.methodology_cmds import methodology_app
from capo.cli.daemon_cmds import daemon_app
from capo.cli.studio_cmds import app as studio_app

app.add_typer(target_app, name="target")
app.add_typer(scan_app, name="scan")
app.add_typer(nxc_app, name="nxc")
app.add_typer(brute_app, name="brute")
app.add_typer(web_app, name="web")
app.add_typer(state_app, name="state")
app.add_typer(mode_app, name="mode")
app.add_typer(report_app, name="report")
app.add_typer(triggers_app, name="triggers")
app.add_typer(methodology_app, name="methodology")
app.add_typer(daemon_app, name="daemon")
app.add_typer(studio_app, name="studio")


# ─────────────── Register Standalone Commands ───────────────

from capo.cli.cheatsheet import register_cheatsheet_commands
from capo.cli.mode_cmds import register_suggest_command

register_cheatsheet_commands(app)
register_suggest_command(app)
