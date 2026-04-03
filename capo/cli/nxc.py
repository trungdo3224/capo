"""NetExec/CrackMapExec CLI commands."""

import typer

from capo.cli.helpers import ensure_target
from capo.utils.display import print_warning

nxc_app = typer.Typer(help="NetExec/CrackMapExec wrappers")


@nxc_app.command("null")
def nxc_null(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """SMB null session enumeration."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(profile=profile, dry_run=dry_run)
    nxc.smb_null_session(target)


@nxc_app.command("guest")
def nxc_guest(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """SMB guest session enumeration."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.smb_guest_session(target)


@nxc_app.command("shares")
def nxc_shares(
    username: str = typer.Option("", "--user", "-u", help="username"),
    password: str = typer.Option("", "--pass", "-p", help="password"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Enumerate SMB shares."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.smb_enum_shares(username, password, target)


@nxc_app.command("users")
def nxc_users(
    username: str = typer.Option("", "--user", "-u", help="username"),
    password: str = typer.Option("", "--pass", "-p", help="password"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Enumerate domain users."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.smb_enum_users(username, password, target)


@nxc_app.command("rid-brute")
def nxc_rid_brute(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """RID brute force user enumeration."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.smb_rid_brute(target)


@nxc_app.command("pass-pol")
def nxc_pass_pol(
    username: str = typer.Option("", "--user", "-u"),
    password: str = typer.Option("", "--pass", "-p"),
    target: str | None = typer.Argument(None),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Get password policy."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.smb_pass_pol(username, password, target)


@nxc_app.command("ldap-enum")
def nxc_ldap(
    username: str = typer.Option("", "--user", "-u"),
    password: str = typer.Option("", "--pass", "-p"),
    target: str | None = typer.Argument(None),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """LDAP user enumeration."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.ldap_enum(username, password, target)


@nxc_app.command("winrm")
def nxc_winrm(
    username: str = typer.Option(..., "--user", "-u"),
    password: str = typer.Option(..., "--pass", "-p"),
    target: str | None = typer.Argument(None),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Check WinRM access."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.winrm_check(username, password, target)


@nxc_app.command("spray")
def nxc_spray(
    userfile: str = typer.Option(..., "--userfile", "-U", help="path to user list file"),
    password: str = typer.Option(..., "--password", "-p", help="password to spray"),
    target: str | None = typer.Argument(None),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Password spray (careful with account lockout!)."""
    ensure_target(target)
    from capo.modules.wrappers.nxc_wrapper import NetExecWrapper
    print_warning("⚠️  Password spraying - Check lockout policy first: capo nxc pass-pol")
    nxc = NetExecWrapper(dry_run=dry_run)
    nxc.spray_password(userfile, password, target)
