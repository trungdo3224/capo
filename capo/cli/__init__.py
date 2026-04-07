"""C.A.P.O CLI package — assembles all command groups into the main Typer app."""

import typer

from capo import __version__
from capo.config import ensure_dirs
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
    version: bool = typer.Option(False, "--version", "-v", help="show version"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="suppress suggestions & banners"),
    verbose: bool = typer.Option(False, "--verbose", help="full output (overrides quiet config)"),
):
    """C.A.P.O - Context-Aware Pentest Orchestrator."""
    ensure_dirs()
    from capo.config import output_config
    if verbose:
        output_config.quiet = False
    elif quiet:
        output_config.quiet = True
    if version:
        console.print(f"C.A.P.O v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        banner()


# ─────────────── Register Sub-Apps ───────────────

from capo.cli.target import target_app
from capo.cli.found import found_app
from capo.cli.scan import scan_app
from capo.cli.enumerate_cmds import enumerate_app
from capo.cli.nxc import nxc_app
from capo.cli.kerberos_cmds import kerberos_app
from capo.cli.brute import brute_app
from capo.cli.web import web_app
from capo.cli.state_cmds import state_app
from capo.cli.triggers_cmds import triggers_app
from capo.cli.methodology_cmds import methodology_app
from capo.cli.session_cmds import session_app
from capo.cli.report import report_app

app.add_typer(target_app, name="target")
app.add_typer(found_app, name="found")
app.add_typer(scan_app, name="scan")
app.add_typer(enumerate_app, name="enumerate")
app.add_typer(nxc_app, name="nxc")
app.add_typer(kerberos_app, name="kerberos")
app.add_typer(brute_app, name="brute")
app.add_typer(web_app, name="web")
app.add_typer(state_app, name="state")
app.add_typer(triggers_app, name="triggers")
app.add_typer(methodology_app, name="methodology")
app.add_typer(session_app, name="session")
app.add_typer(report_app, name="report")


# ─────────────── Register Standalone Commands ───────────────

from capo.cli.cheatsheet import register_cheatsheet_commands

register_cheatsheet_commands(app)
