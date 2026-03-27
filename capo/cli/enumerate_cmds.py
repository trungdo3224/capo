"""CLI command for `capo enumerate`."""

from typing import Optional

import typer

enumerate_app = typer.Typer(help="Run service enumeration against open ports")


@enumerate_app.callback(invoke_without_command=True)
def enumerate_run(
    ctx: typer.Context,
    services: Optional[list[str]] = typer.Argument(
        None,
        help="Service names or port numbers to scope (e.g. smb http 445). Omit for all.",
    ),
    username: str = typer.Option("", "-u", "--user", help="Username for authenticated enum"),
    password: str = typer.Option("", "-p", "--pass", help="Password for authenticated enum"),
):
    """Enumerate discovered services — runs tools, parses output, updates state.

    Examples:
        capo enumerate              # all services with open ports
        capo enumerate smb          # just SMB
        capo enumerate smb http     # SMB + HTTP
        capo enumerate 445 80       # by port number
        capo enumerate -u admin -p pass  # authenticated enum
    """
    if ctx.invoked_subcommand is not None:
        return

    from capo.modules.enumerate import enumerate_engine
    enumerate_engine.run(services=services, username=username, password=password)
