"""Password bruteforce CLI commands (Hydra)."""

import typer

from capo.cli.helpers import ensure_target
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

    print_warning("⚠️  Bruteforce can trigger lockouts. Verify policy first.")
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
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)


@brute_app.command("http-post")
def brute_http_post(
    form: str = typer.Option(..., "--form", "-f", help="Hydra form spec: /path:user=^USER^&pass=^PASS^:F=invalid"),
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
    """HTTP POST form bruteforce using Hydra."""
    ensure_target(target)
    from capo.modules.wrappers.brute_wrapper import BruteWrapper

    print_warning("⚠️  Bruteforce can trigger lockouts. Verify policy first.")
    brute = BruteWrapper(profile=profile, dry_run=dry_run)
    try:
        brute.http_post_form(
            form=form,
            username=username,
            password=password,
            userlist=userlist,
            passlist=passlist,
            target=target,
            port=port,
            https=https,
            tasks=tasks,
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)


@brute_app.command("http-get")
def brute_http_get(
    form: str = typer.Option(..., "--form", "-f", help="Hydra form spec: /path:user=^USER^&pass=^PASS^:F=invalid"),
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
    """HTTP GET form bruteforce using Hydra."""
    ensure_target(target)
    from capo.modules.wrappers.brute_wrapper import BruteWrapper

    print_warning("⚠️  Bruteforce can trigger lockouts. Verify policy first.")
    brute = BruteWrapper(profile=profile, dry_run=dry_run)
    try:
        brute.http_get_form(
            form=form,
            username=username,
            password=password,
            userlist=userlist,
            passlist=passlist,
            target=target,
            port=port,
            https=https,
            tasks=tasks,
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)


@brute_app.command("web-form")
def brute_web_form(
    module: str = typer.Option("http-post-form", "--module", "-m", help="Hydra module (e.g. http-post-form, https-post-form, http-get-form)"),
    form: str = typer.Option(..., "--form", "-f", help="Hydra form spec: /path:user=^USER^&pass=^PASS^:F=invalid"),
    username: str = typer.Option("", "--user", "-u", help="Single username"),
    password: str = typer.Option("", "--pass", "-p", help="Single password"),
    userlist: str = typer.Option("", "--userlist", "-U", help="Username wordlist file"),
    passlist: str = typer.Option("", "--passlist", "-P", help="Password wordlist file"),
    port: int = typer.Option(80, "--port", help="Web port"),
    tasks: int = typer.Option(4, "--tasks", "-t", help="Hydra parallel tasks"),
    target: str | None = typer.Argument(None, help="Target IP/host"),
    profile: str = typer.Option("normal", "--profile", help="Scan profile"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print command without executing"),
):
    """Generic web-form bruteforce using any Hydra web auth module."""
    ensure_target(target)
    from capo.modules.wrappers.brute_wrapper import BruteWrapper

    print_warning("⚠️  Bruteforce can trigger lockouts. Verify policy first.")
    brute = BruteWrapper(profile=profile, dry_run=dry_run)
    try:
        brute.web_form(
            module=module,
            form=form,
            username=username,
            password=password,
            userlist=userlist,
            passlist=passlist,
            target=target,
            port=port,
            tasks=tasks,
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)
