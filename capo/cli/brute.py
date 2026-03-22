"""Password bruteforce CLI commands (Hydra)."""

import typer

from capo.cli.helpers import ensure_target
from capo.errors import CapoError
from capo.utils.display import print_error, print_warning

brute_app = typer.Typer(help="Password bruteforce wrappers (Hydra)")


@brute_app.command("ssh")
def brute_ssh(
    username: str = typer.Option("", "--user", "-u", help="Single username"),
    password: str = typer.Option("", "--pass", "-p", help="Single password"),
    userlist: str = typer.Option("", "--userlist", "-U", help="Username wordlist file"),
    passlist: str = typer.Option("", "--passlist", "-P", help="Password wordlist file"),
    port: int = typer.Option(22, "--port", help="SSH port"),
    tasks: int = typer.Option(4, "--tasks", "-t", help="Hydra parallel tasks"),
    target: str | None = typer.Argument(None, help="Target IP/host"),
    profile: str = typer.Option("normal", "--profile", help="Scan profile"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """SSH bruteforce/spray using Hydra."""
    ensure_target(target)
    from capo.modules.wrappers.brute_wrapper import BruteWrapper

    print_warning("Bruteforce can trigger lockouts. Verify policy first.")
    brute = BruteWrapper(profile=profile, dry_run=dry_run)
    try:
        brute.ssh(
            username=username,
            password=password,
            userlist=userlist,
            passlist=passlist,
            target=target,
            port=port,
            tasks=tasks,
        )
    except CapoError as e:
        print_error(str(e))
        raise typer.Exit(1)


@brute_app.command("http")
def brute_http(
    form: str = typer.Option(..., "--form", "-f", help="Hydra form spec: /path:user=^USER^&pass=^PASS^:F=invalid"),
    method: str = typer.Option("post", "--method", "-m", help="HTTP method: post or get"),
    module: str | None = typer.Option(None, "--module", "-M", help="Override Hydra module (e.g. https-post-form)"),
    username: str = typer.Option("", "--user", "-u", help="Single username"),
    password: str = typer.Option("", "--pass", "-p", help="Single password"),
    userlist: str = typer.Option("", "--userlist", "-U", help="Username wordlist file"),
    passlist: str = typer.Option("", "--passlist", "-P", help="Password wordlist file"),
    port: int = typer.Option(80, "--port", help="Web port"),
    https: bool = typer.Option(False, "--https", "-s", help="Use HTTPS module"),
    tasks: int = typer.Option(4, "--tasks", "-t", help="Hydra parallel tasks"),
    target: str | None = typer.Argument(None, help="Target IP/host"),
    profile: str = typer.Option("normal", "--profile", help="Scan profile"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """HTTP form bruteforce using Hydra.

    Examples:
        capo brute http -f "/login:user=^USER^&pass=^PASS^:F=invalid" -u admin -P rockyou.txt
        capo brute http -f "..." --method get --https
        capo brute http -f "..." --module https-post-form
    """
    ensure_target(target)
    from capo.modules.wrappers.brute_wrapper import BruteWrapper

    # Resolve Hydra module name
    if module:
        hydra_module = module
    elif https:
        hydra_module = f"https-{method.lower()}-form"
    else:
        hydra_module = f"http-{method.lower()}-form"

    print_warning("Bruteforce can trigger lockouts. Verify policy first.")
    brute = BruteWrapper(profile=profile, dry_run=dry_run)
    try:
        brute.web_form(
            module=hydra_module,
            form=form,
            username=username,
            password=password,
            userlist=userlist,
            passlist=passlist,
            target=target,
            port=port,
            tasks=tasks,
        )
    except CapoError as e:
        print_error(str(e))
        raise typer.Exit(1)
