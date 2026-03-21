"""Bruteforce wrapper for Hydra (SSH and web form authentication)."""

import re
import subprocess
from pathlib import Path

from capo.errors import CapoError
from capo.modules.wrappers.base import BaseWrapper
from capo.state import state_manager
from capo.utils.display import print_info


class BruteWrapper(BaseWrapper):
    """Hydra wrapper for controlled bruteforce workflows."""

    tool_name = "hydra"
    binary_name = "hydra"

    def _build_auth_args(
        self,
        username: str,
        password: str,
        userlist: str,
        passlist: str,
    ) -> list[str]:
        """Build hydra auth args from single creds or wordlists."""
        if not (username or userlist):
            raise CapoError("Provide --user or --userlist")
        if not (password or passlist):
            raise CapoError("Provide --pass or --passlist")

        args: list[str] = []
        if username:
            args.extend(["-l", username])
        else:
            args.extend(["-L", userlist])

        if password:
            args.extend(["-p", password])
        else:
            args.extend(["-P", passlist])

        return args

    def ssh(
        self,
        username: str = "",
        password: str = "",
        userlist: str = "",
        passlist: str = "",
        target: str | None = None,
        port: int = 22,
        tasks: int = 4,
    ):
        """SSH brute force / password spray with Hydra."""
        target = self._resolve_target(target)
        out = self._output_file("ssh")

        cmd = ["hydra", "-I", "-f", "-t", str(tasks)]
        cmd.extend(self._build_auth_args(username, password, userlist, passlist))
        cmd.extend(["-s", str(port), str(target), "ssh"])

        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def http_post_form(
        self,
        form: str,
        username: str = "",
        password: str = "",
        userlist: str = "",
        passlist: str = "",
        target: str | None = None,
        port: int = 80,
        https: bool = False,
        tasks: int = 4,
    ):
        """HTTP POST form bruteforce with Hydra."""
        module = "https-post-form" if https else "http-post-form"
        self.web_form(
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

    def http_get_form(
        self,
        form: str,
        username: str = "",
        password: str = "",
        userlist: str = "",
        passlist: str = "",
        target: str | None = None,
        port: int = 80,
        https: bool = False,
        tasks: int = 4,
    ):
        """HTTP GET form bruteforce with Hydra."""
        module = "https-get-form" if https else "http-get-form"
        self.web_form(
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

    def web_form(
        self,
        module: str,
        form: str,
        username: str = "",
        password: str = "",
        userlist: str = "",
        passlist: str = "",
        target: str | None = None,
        port: int = 80,
        tasks: int = 4,
    ):
        """Generic Hydra web form bruteforce for any supported module."""
        target = self._resolve_target(target)
        out = self._output_file("webform")

        cmd = ["hydra", "-I", "-f", "-t", str(tasks)]
        cmd.extend(self._build_auth_args(username, password, userlist, passlist))
        cmd.extend(["-s", str(port), str(target), module, form])

        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def parse_output(self, result: subprocess.CompletedProcess, output_file: Path | None):
        """Parse Hydra success lines and save credentials to state."""
        if not result.stdout:
            return

        output = result.stdout
        matches = re.findall(
            r"\[\d+\]\[([^\]]+)\].*?login:\s*(\S+)\s+password:\s*(\S+)",
            output,
            re.IGNORECASE,
        )

        if not matches:
            return

        count = 0
        for service, user, passwd in matches:
            state_manager.add_credential(user, passwd, service)
            count += 1

        print_info(f"Hydra discovered {count} valid credential(s).")

    def get_suggestions(self) -> list[tuple[str, str]]:
        """Suggestions after successful bruteforce results."""
        creds = state_manager.get("credentials", [])
        if not creds:
            return []

        suggestions: list[tuple[str, str]] = []
        if 22 in state_manager.get_open_ports():
            suggestions.append(("Try SSH login", "ssh {USER}@{IP}"))
        if 5985 in state_manager.get_open_ports():
            suggestions.append(("Try WinRM login", "evil-winrm -i {IP} -u {USER} -p {PASS}"))
        return suggestions
