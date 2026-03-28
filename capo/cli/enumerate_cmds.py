"""CLI command for `capo enumerate`."""

from typing import Optional

import typer

enumerate_app = typer.Typer(help="Run service enumeration against open ports")


@enumerate_app.callback(invoke_without_command=True)
def enumerate_run(
    ctx: typer.Context,
    services: Optional[list[str]] = typer.Option(
        None, "-s", "--services",
        help="Service names or port numbers to scope (e.g. -s smb -s http -s 445). Omit for all.",
    ),
    username: str = typer.Option("", "-u", "--user", help="Username for authenticated enum"),
    password: str = typer.Option("", "-p", "--pass", help="Password for authenticated enum"),
    wordlist: str = typer.Option("", "-w", "--wordlist", help="Custom wordlist path for web fuzzing"),
    wordlist_size: str = typer.Option(
        "small", "-W", "--wordlist-size",
        help="Wordlist size for web fuzzing: small, medium, large",
    ),
    community: str = typer.Option(
        "", "-C", "--community",
        help="SNMP community string (default: auto-detect via onesixtyone, fallback: public)",
    ),
    manual: bool = typer.Option(
        False, "-m", "--manual",
        help="Print resolved commands without executing — copy and run yourself.",
    ),
):
    """Enumerate discovered services — runs tools, parses output, updates state.

    Examples:
        capo enumerate                    # all services with open ports
        capo enumerate -s smb             # just SMB
        capo enumerate -s smb -s http     # SMB + HTTP
        capo enumerate -s 445 -s 80       # by port number
        capo enumerate -u admin -p pass   # authenticated enum
        capo enumerate -s http -W medium  # medium wordlist for dir fuzz
        capo enumerate -w /path/to/custom.txt  # custom wordlist
        capo enumerate -s snmp -C internal     # override SNMP community string
        capo enumerate -m                      # print commands, don't run
        capo enumerate -s smb -m               # print SMB commands only
    """
    if ctx.invoked_subcommand is not None:
        return

    from capo.modules.enumerate import enumerate_engine
    enumerate_engine.run(
        services=services, username=username, password=password,
        wordlist=wordlist, wordlist_size=wordlist_size,
        community=community, manual=manual,
    )
