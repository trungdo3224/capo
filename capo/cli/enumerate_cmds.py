"""CLI command for `capo enumerate`."""

from typing import Optional

import typer

enumerate_app = typer.Typer(help="Run service enumeration against open ports")


@enumerate_app.callback(invoke_without_command=True)
def enumerate_run(
    ctx: typer.Context,
    services: Optional[list[str]] = typer.Option(
        None, "-s", "--services",
        help="service names or port numbers to scope (e.g. -s smb -s http -s 445), omit for all",
    ),
    username: str = typer.Option("", "-u", "--user", help="username for authenticated enum"),
    password: str = typer.Option("", "-p", "--pass", help="password for authenticated enum"),
    wordlist: str = typer.Option("", "-w", "--wordlist", help="custom wordlist path for web fuzzing"),
    wordlist_size: str = typer.Option(
        "small", "-W", "--wordlist-size",
        help="wordlist size: small, medium, large",
    ),
    community: str = typer.Option(
        "", "-C", "--community",
        help="SNMP community string (default: auto-detect, fallback: public)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="print command without executing",
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
        capo enumerate --dry-run               # print commands, don't run
        capo enumerate -s smb --dry-run        # print SMB commands only
    """
    if ctx.invoked_subcommand is not None:
        return

    from capo.modules.enumerate import enumerate_engine
    enumerate_engine.run(
        services=services, username=username, password=password,
        wordlist=wordlist, wordlist_size=wordlist_size,
        community=community, manual=dry_run,
    )
