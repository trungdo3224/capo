"""NetExec (nxc) wrapper for SMB/AD enumeration."""

import configparser
import re
import sqlite3
import subprocess
from pathlib import Path

from capo.modules.wrappers.base import BaseWrapper
from capo.state import state_manager
from capo.utils.display import print_info, print_success


class NetExecWrapper(BaseWrapper):
    tool_name = "netexec"
    binary_name = "nxc"

    def smb_null_session(self, target: str | None = None):
        """Enumerate SMB with null session."""
        target = target or state_manager.target
        out = self._output_file("smb_null")
        cmd = [
            "nxc", "smb", target,
            "-u", "", "-p", "",
            "--shares",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def smb_guest_session(self, target: str | None = None):
        """Enumerate SMB with guest session."""
        target = target or state_manager.target
        out = self._output_file("smb_guest")
        cmd = [
            "nxc", "smb", target,
            "-u", "Guest", "-p", "",
            "--shares",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def smb_enum_shares(self, username: str = "", password: str = "",
                        target: str | None = None):
        """Enumerate SMB shares with credentials."""
        target = target or state_manager.target
        out = self._output_file("smb_shares")
        cmd = [
            "nxc", "smb", target,
            "-u", username or "",
            "-p", password or "",
            "--shares",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def smb_enum_users(self, username: str = "", password: str = "",
                       target: str | None = None):
        """Enumerate domain users via SMB/RID brute."""
        target = target or state_manager.target
        out = self._output_file("smb_users")
        cmd = [
            "nxc", "smb", target,
            "-u", username or "",
            "-p", password or "",
            "--users",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def smb_rid_brute(self, target: str | None = None):
        """RID brute force enumeration."""
        target = target or state_manager.target
        out = self._output_file("smb_rid")
        cmd = [
            "nxc", "smb", target,
            "-u", "", "-p", "",
            "--rid-brute", "5000",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def smb_pass_pol(self, username: str = "", password: str = "",
                     target: str | None = None):
        """Get password policy."""
        target = target or state_manager.target
        out = self._output_file("smb_passpol")
        cmd = [
            "nxc", "smb", target,
            "-u", username or "",
            "-p", password or "",
            "--pass-pol",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def ldap_enum(self, username: str = "", password: str = "",
                  target: str | None = None):
        """LDAP enumeration."""
        target = target or state_manager.target
        out = self._output_file("ldap_enum")
        cmd = [
            "nxc", "ldap", target,
            "-u", username or "",
            "-p", password or "",
            "--users",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def winrm_check(self, username: str, password: str,
                    target: str | None = None):
        """Check WinRM access with credentials."""
        target = target or state_manager.target
        out = self._output_file("winrm_check")
        cmd = [
            "nxc", "winrm", target,
            "-u", username,
            "-p", password,
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def spray_password(self, userfile: str, password: str,
                       target: str | None = None):
        """Password spray against SMB (careful with lockout!)."""
        target = target or state_manager.target
        out = self._output_file("spray")
        cmd = [
            "nxc", "smb", target,
            "-u", userfile,
            "-p", password,
            "--no-bruteforce",
        ]
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def _query_nxc_db(self, db_name: str, query: str, params: tuple = ()) -> list:
        """Helper to query a NetExec workspace SQLite database."""
        db_path = Path.home() / ".nxc" / "workspaces" / "default" / f"{db_name}.db"
        if not db_path.exists():
            return []
            
        try:
            with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            # If the DB is locked or malformed, fail gracefully
            return []

    def parse_output(self, result: subprocess.CompletedProcess, output_file: Path | None):
        """Parse NetExec output by interrogating its workspace SQLite databases."""
        if not result.stdout:
            return

        output = result.stdout
        target_ip = state_manager.get_var("IP")
        if not target_ip:
            return

        # 1. Extract Host, Domain, and OS from smb.db
        hosts = self._query_nxc_db(
            "smb", 
            "SELECT id, hostname, domain, os FROM hosts WHERE ip = ?", 
            (target_ip,)
        )
        
        host_id = None
        if hosts:
            host_record = hosts[0]
            host_id = host_record["id"]
            
            hostname = host_record["hostname"]
            domain = host_record["domain"]
            os_ver = host_record["os"]
            
            if hostname:
                state_manager.set("hostname", hostname)
            
            if domain:
                state_manager.add_domain(domain)
                
            if os_ver:
                existing_os = state_manager.get("os", "")
                if len(os_ver) > len(existing_os):
                    state_manager.set("os", os_ver)
                    
            if hostname or domain:
                print_info(f"DB Read: Domain: {domain or 'N/A'}, Hostname: {hostname or 'N/A'}")

        # 2. Extract Users from smb.db and ldap.db
        # Users might be saved in either DB depending on the module run.
        known_users = set()
        for db in ["smb", "ldap"]:
            users_records = self._query_nxc_db(db, "SELECT username FROM users")
            for u in users_records:
                known_users.add(u["username"])
                
        for username in known_users:
            if username and not username.startswith("-"):
                state_manager.add_user(username)

        # 3. Extract Shares from smb.db linked to this host
        if host_id is not None:
            shares = self._query_nxc_db(
                "smb",
                "SELECT name, remark, read, write FROM shares WHERE hostid = ?",
                (host_id,)
            )
            for s in shares:
                perms = []
                if s["read"]: perms.append("READ")
                if s["write"]: perms.append("WRITE")
                perm_str = ",".join(perms) if perms else "NO ACCESS"
                state_manager.add_share(s["name"], perm_str, s["remark"] or "")

        # 4. Fallback STDOUT parsing for immediate CLI feedback only
        if "(Pwn3d!)" in output:
            print_success("🎉 Pwn3d! Admin access confirmed!")

    def get_suggestions(self) -> list[tuple[str, str]]:
        """Context-aware suggestions for AD enumeration."""
        suggestions = []
        users = state_manager.get("users", [])
        creds = state_manager.get("credentials", [])
        domain = state_manager.get("domain", "")

        if state_manager.has_service("smb") or state_manager.has_service("microsoft-ds"):
            if not users:
                suggestions.append(
                    ("SMB detected - Try null/guest session", "capo nxc null")
                )
                suggestions.append(
                    ("Try RID brute force", "capo nxc rid-brute")
                )

        if users and not creds:
            suggestions.append(
                (f"Found {len(users)} users - Try password spray",
                 "capo nxc spray --password 'Welcome1'")
            )

        if domain:
            suggestions.append(
                ("AD Domain found - Try LDAP enum", "capo nxc ldap-enum")
            )

        return suggestions
