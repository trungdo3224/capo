"""Web fuzzing wrapper for ffuf and feroxbuster."""

import json as json_module
import re
import shutil
import subprocess
from pathlib import Path

from capo.config import WORDLISTS
from capo.modules.wrappers.base import BaseWrapper
from capo.state import state_manager
from capo.utils.display import print_info, print_success, print_warning


class WebFuzzWrapper(BaseWrapper):
    tool_name = "ffuf"
    binary_name = "ffuf"

    def dir_fuzz(self, port: int = 80, https: bool = False,
                 wordlist: str | None = None, target: str | None = None,
                 extensions: str = "", host_mode: str = "ip",
                 domain: str | None = None):
        """Directory fuzzing with ffuf."""
        target = target or state_manager.target
        if host_mode == "domain":
            fuzz_host = domain or state_manager.get("domain", "")
            if not fuzz_host:
                print_warning("No domain configured. Use --domain or: capo target set-domain <domain>")
                return
        else:
            fuzz_host = target

        scheme = "https" if https else "http"
        url = f"{scheme}://{fuzz_host}:{port}/FUZZ"

        wl = wordlist or WORDLISTS.get("dir_small", "")
        if not Path(wl).exists():
            # Fallback
            for key in ["dir_medium", "dir_large"]:
                if Path(WORDLISTS.get(key, "")).exists():
                    wl = WORDLISTS[key]
                    break
            else:
                print_warning(f"Wordlist not found: {wl}. Provide one with --wordlist.")
                return

        out = self._output_file(f"dir_p{port}")
        json_out = out.with_suffix(".json")

        threads = self.profile_config["ffuf_threads"]
        rate = self.profile_config["ffuf_rate"]

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wl,
            "-t", str(threads),
            "-o", str(json_out),
            "-of", "json",
            "-mc", "200,204,301,302,307,401,403",
            "-ac",  # auto-calibrate
        ]

        if rate > 0:
            cmd.extend(["-rate", str(rate)])

        if extensions:
            cmd.extend(["-e", extensions])

        self._parse_mode = "dir"
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def vhost_fuzz(self, domain: str | None = None, port: int = 80,
                   https: bool = False, wordlist: str | None = None,
                   target: str | None = None):
        """Virtual host fuzzing."""
        target = target or state_manager.target
        domain = domain or state_manager.get("domain", target)
        scheme = "https" if https else "http"
        url = f"{scheme}://{domain}:{port}/"

        wl = wordlist or WORDLISTS.get("dns_sub", "")
        if not Path(wl).exists():
            print_warning(f"Wordlist not found: {wl}")
            return

        out = self._output_file(f"vhost_p{port}")
        json_out = out.with_suffix(".json")
        threads = self.profile_config["ffuf_threads"]

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wl,
            "-H", f"Host: FUZZ.{domain}",
            "-t", str(threads),
            "-o", str(json_out),
            "-of", "json",
            "-ac",
            "-mc", "200,204,301,302,307",
        ]
        self._parse_mode = "vhost"
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def subdns_fuzz(self, domain: str | None = None,
                    wordlist: str | None = None,
                    target: str | None = None,
                    resolver: str | None = None):
        """Subdomain DNS enumeration with gobuster (preferred) or ffuf fallback."""
        target = target or state_manager.target
        domain = domain or state_manager.get("domain", "")
        if not domain:
            print_warning("No domain set. Use --domain or: capo target set-domain <domain>")
            return

        wl = wordlist or WORDLISTS.get("dns_sub", "")
        if not wl or not Path(wl).exists():
            print_warning(f"Wordlist not found: {wl}. Provide one with --wordlist.")
            return

        out = self._output_file("subdns")
        threads = self.profile_config["ffuf_threads"]

        if shutil.which("gobuster"):
            self._subdns_gobuster(domain, wl, out, threads, resolver)
        else:
            print_warning("gobuster not found - falling back to ffuf DNS mode")
            self._subdns_ffuf(domain, wl, out, threads)

    def _subdns_gobuster(self, domain: str, wordlist: str, out: Path,
                         threads: int, resolver: str | None):
        """Run gobuster dns and parse findings into state."""
        txt_out = out.with_suffix(".txt")

        # Temporarily use gobuster identity so execute() checks the right binary.
        original_name, original_binary = self.tool_name, self.binary_name
        self.tool_name = "gobuster"
        self.binary_name = "gobuster"
        try:
            cmd = [
                "gobuster", "dns",
                "-d", domain,
                "-w", wordlist,
                "-t", str(threads),
                "-o", str(txt_out),
                "--no-color",
            ]
            if resolver:
                cmd.extend(["--resolver", resolver])

            result = self.execute(cmd, output_file=txt_out, parse_output=False)
            if result and result.returncode == 0:
                self._parse_gobuster_dns(txt_out, domain)
        finally:
            self.tool_name = original_name
            self.binary_name = original_binary

    def _subdns_ffuf(self, domain: str, wordlist: str, out: Path,
                     threads: int):
        """Run ffuf subdomain probing and parse with subdns mode."""
        txt_out = out.with_suffix(".txt")
        json_out = out.with_suffix(".json")

        cmd = [
            "ffuf",
            "-u", f"http://FUZZ.{domain}/",
            "-w", wordlist,
            "-t", str(threads),
            "-o", str(json_out),
            "-of", "json",
            "-ac",
            "-mc", "200,204,301,302,307,401,403",
        ]

        self._parse_mode = "subdns"
        self._subdns_domain = domain
        self.execute(cmd, output_file=txt_out)

    def _parse_gobuster_dns(self, output_file: Path, domain: str):
        """Parse gobuster dns text output and store subdomains as vhosts."""
        if not output_file.exists():
            return

        target_ip = state_manager.get("ip", state_manager.target or "")
        found: list[str] = []
        seen: set[str] = set()

        for line in output_file.read_text(encoding="utf-8").splitlines():
            match = re.search(r"Found:\s+(\S+)", line, re.IGNORECASE)
            if not match:
                continue
            subdomain = match.group(1).strip().rstrip(".")
            if not subdomain:
                continue
            if subdomain.lower() == domain.lower():
                continue
            if subdomain in seen:
                continue
            seen.add(subdomain)
            state_manager.add_vhost(subdomain)
            found.append(subdomain)

        if found:
            print_success(f"Found {len(found)} subdomain(s): {', '.join(found)}")
            print_info("Add to /etc/hosts:")
            print_info(f"  {target_ip}  {' '.join(found)}")
        else:
            print_info("No new subdomains found.")

    def recursive_fuzz(self, port: int = 80, https: bool = False,
                       wordlist: str | None = None, depth: int = 2,
                       target: str | None = None):
        """Recursive directory fuzzing."""
        target = target or state_manager.target
        scheme = "https" if https else "http"
        url = f"{scheme}://{target}:{port}/FUZZ"

        wl = wordlist or WORDLISTS.get("dir_small", "")
        if not Path(wl).exists():
            print_warning(f"Wordlist not found: {wl}")
            return

        out = self._output_file(f"recursive_p{port}")
        json_out = out.with_suffix(".json")
        threads = self.profile_config["ffuf_threads"]

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wl,
            "-t", str(threads),
            "-o", str(json_out),
            "-of", "json",
            "-recursion",
            "-recursion-depth", str(depth),
            "-mc", "200,204,301,302,307,401,403",
            "-ac",
        ]
        self._parse_mode = "dir"
        self.execute(cmd, output_file=out.with_suffix(".txt"))

    def parse_output(self, result: subprocess.CompletedProcess, output_file: Path | None):
        """Parse ffuf JSON output and update state."""
        if output_file is None:
            return

        json_file = output_file.with_suffix(".json")
        # Also try to find json from the base output filename
        base = output_file.with_suffix("")
        possible_json = base.with_suffix(".json")
        if possible_json.exists():
            json_file = possible_json

        if not json_file.exists():
            parent = output_file.parent
            prefix = output_file.stem.rsplit("_", 1)[0] if "_" in output_file.stem else output_file.stem
            for f in parent.glob(f"{prefix}*.json"):
                json_file = f
                break

        if not json_file.exists():
            # Fallback: parse stdout
            self._parse_stdout(result.stdout or "")
            return

        try:
            data = json_module.loads(json_file.read_text(encoding="utf-8"))
        except (json_module.JSONDecodeError, OSError):
            self._parse_stdout(result.stdout or "")
            return

        results = data.get("results", [])
        count = 0
        mode = getattr(self, "_parse_mode", "dir")
        subdns_domain = getattr(self, "_subdns_domain", "")

        for entry in results:
            path = entry.get("input", {}).get("FUZZ", "")
            status = entry.get("status", 0)
            if path:
                if mode == "subdns":
                    label = path.strip().rstrip(".")
                    if label:
                        fqdn = label if "." in label else f"{label}.{subdns_domain}"
                        state_manager.add_vhost(fqdn)
                        count += 1
                    continue

                # Check if this is a vhost fuzz (Host header)
                host = entry.get("host", "")
                if mode == "vhost" and host and host != state_manager.target:
                    state_manager.add_vhost(host)
                else:
                    state_manager.add_directory(f"/{path}", status)
                count += 1

        print_success(f"Parsed {count} result(s) from ffuf output.")

    def _parse_stdout(self, output: str):
        """Fallback: parse ffuf stdout for results."""
        mode = getattr(self, "_parse_mode", "dir")
        subdns_domain = getattr(self, "_subdns_domain", "")

        # ffuf stdout format: "path  [Status: 200, Size: 1234, Words: 56, Lines: 7]"
        for match in re.finditer(
            r"^(\S+)\s+\[Status:\s*(\d+),", output, re.MULTILINE
        ):
            path = match.group(1)
            status = int(match.group(2))
            if mode == "subdns":
                label = path.strip().rstrip(".")
                if label:
                    fqdn = label if "." in label else f"{label}.{subdns_domain}"
                    state_manager.add_vhost(fqdn)
                continue

            state_manager.add_directory(f"/{path}", status)

    def get_suggestions(self) -> list[tuple[str, str]]:
        """Suggest further web enum based on discoveries."""
        suggestions = []
        dirs = state_manager.get("directories", [])

        interesting_paths = {
            "wp-admin": ("WordPress detected!", "capo query wordpress"),
            "wp-content": ("WordPress detected!", "capo query wordpress"),
            "administrator": ("Joomla likely", "capo query joomla"),
            "drupal": ("Drupal detected!", "capo query drupal"),
            ".git": ("[!] .git exposed — dump & mine secrets: capo query git-dump | Follow: capo methodology show web-app git-exposure", "git-dumper http://{IP}/.git/ ./git-dump"),
            "phpmyadmin": ("phpMyAdmin found", "capo query phpmyadmin"),
            "api": ("API endpoint found - Fuzz further", "capo web fuzz --extensions .json,.xml"),
            "cgi-bin": ("CGI-bin found - Check for Shellshock", "capo query shellshock"),
        }

        for d in dirs:
            path = d.get("path", "").lower().strip("/")
            for key, (title, cmd) in interesting_paths.items():
                if key in path:
                    suggestions.append((title, cmd))

        return suggestions
