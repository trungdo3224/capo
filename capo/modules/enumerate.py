"""Enumerate engine — runs service-specific commands from the YAML registry.

Usage:
    from capo.modules.enumerate import EnumerateEngine
    engine = EnumerateEngine()
    engine.run()                          # all discovered services
    engine.run(services=["smb", "http"])  # scoped
    engine.run(username="admin", password="pass")  # authenticated
"""

import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from capo.config import CORE_ENUMERATE_REGISTRY
from capo.state import state_manager
from capo.utils.display import console, print_command, print_error, print_warning


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CmdResult:
    """Outcome of a single enumeration command."""
    name: str
    tool: str
    cmd: str
    status: str  # "ok", "skipped", "timeout", "error"
    duration: float = 0.0
    findings: str = ""  # short human summary
    output_file: str = ""


@dataclass
class ServiceResult:
    """All command results for one service."""
    service: str
    port: int
    commands: list[CmdResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Output parsers — each receives (stdout, stderr) and returns
# {"summary": str, "users": list, "shares": list, "domains": list, ...}
# All keys optional except summary.
# ---------------------------------------------------------------------------

def _parse_nxc_shares(stdout: str, _stderr: str) -> dict:
    shares = []
    for line in stdout.splitlines():
        # SMB  10.10.10.100  445  DC01  [*]  ShareName  READ,WRITE  Comment
        m = re.search(r"SMB\s+\S+\s+\d+\s+\S+\s+(.+)", line)
        if m and "-----" not in line and "Share" not in line:
            parts = m.group(1).strip()
            if parts:
                share_name = parts.split()[0] if parts.split() else ""
                if share_name and share_name not in ("Permissions", "Remark"):
                    shares.append(share_name)
    for s in shares:
        state_manager.add_share(s, "", "")
    return {"summary": f"{len(shares)} share(s)", "shares": shares}


def _parse_nxc_users(stdout: str, _stderr: str) -> dict:
    users = []
    for line in stdout.splitlines():
        m = re.search(r"(?:SMB|LDAP)\s+\S+\s+\d+\s+\S+\s+.*?(\S+)\s+badpwdcount:", line, re.I)
        if m:
            users.append(m.group(1))
    for u in users:
        state_manager.add_user(u)
    return {"summary": f"{len(users)} user(s)", "users": users}


def _parse_nxc_rid(stdout: str, _stderr: str) -> dict:
    users = []
    for line in stdout.splitlines():
        m = re.search(r"SidTypeUser:\s+\\(.+?)\)?\s*$", line)
        if m:
            username = m.group(1).strip().rstrip(")")
            if username:
                users.append(username)
                state_manager.add_user(username)
    return {"summary": f"{len(users)} user(s) via RID", "users": users}


def _parse_enum4linux_ng(stdout: str, _stderr: str) -> dict:
    users, shares, domains = [], [], []
    for line in stdout.splitlines():
        # Users
        um = re.search(r"username:\s*(\S+)", line, re.I)
        if um:
            u = um.group(1)
            if u and u not in ("username",):
                users.append(u)
                state_manager.add_user(u)
        # Shares
        sm = re.search(r"^\s*(\S+)\s+(Mapping|Listing):\s*(OK|DENIED)", line)
        if sm:
            shares.append(sm.group(1))
            state_manager.add_share(sm.group(1), "", "")
        # Domain
        dm = re.search(r"Domain Name:\s*(\S+)", line, re.I)
        if dm:
            d = dm.group(1)
            domains.append(d)
            state_manager.add_domain(d)
    parts = []
    if users:
        parts.append(f"{len(users)} user(s)")
    if shares:
        parts.append(f"{len(shares)} share(s)")
    if domains:
        parts.append(f"domain: {domains[0]}")
    return {"summary": ", ".join(parts) or "no findings", "users": users, "shares": shares, "domains": domains}


def _parse_smbclient_list(stdout: str, _stderr: str) -> dict:
    shares = []
    for line in stdout.splitlines():
        m = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)", line)
        if m:
            shares.append(m.group(1))
            state_manager.add_share(m.group(1), "", "")
    return {"summary": f"{len(shares)} share(s)", "shares": shares}


def _parse_showmount(stdout: str, _stderr: str) -> dict:
    exports = []
    for line in stdout.splitlines():
        if line.startswith("/"):
            export = line.split()[0]
            exports.append(export)
    return {"summary": f"{len(exports)} export(s): {', '.join(exports)}" if exports else "no exports"}


def _parse_whatweb(stdout: str, _stderr: str) -> dict:
    techs = []
    # whatweb outputs: ToolName[version], so capture "Name[detail]" pairs
    for m in re.finditer(r"(\w[\w.-]+)\[([^\]]+)\]", stdout):
        name, detail = m.group(1), m.group(2)
        if name.lower() not in ("http",):
            techs.append(f"{name}/{detail}" if detail else name)
    # Also grab standalone bracketed items (status codes, etc.)
    if not techs:
        for part in re.findall(r"\[([^\]]+)\]", stdout):
            part = part.strip()
            if part and not re.match(r"^\d{3}", part):
                techs.append(part)
    return {"summary": ", ".join(techs[:6]) if techs else "no findings"}


def _parse_http_headers(stdout: str, _stderr: str) -> dict:
    server = ""
    powered_by = ""
    for line in stdout.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
        if line.lower().startswith("x-powered-by:"):
            powered_by = line.split(":", 1)[1].strip()
    parts = []
    if server:
        parts.append(server)
    if powered_by:
        parts.append(powered_by)
    return {"summary": ", ".join(parts) if parts else "no info"}


def _parse_ffuf_json(stdout: str, _stderr: str) -> dict:
    import json as _json
    dirs = []
    # ffuf writes JSON to file, but we also get stdout — try both
    try:
        data = _json.loads(stdout)
        for r in data.get("results", []):
            path = r.get("input", {}).get("FUZZ", "")
            status = r.get("status", 0)
            if path:
                dirs.append(f"/{path} [{status}]")
                state_manager.add_directory(f"/{path}", status)
    except (ValueError, KeyError):
        pass
    return {"summary": f"{len(dirs)} dir(s)" if dirs else "no dirs found", "directories": dirs}


def _parse_dig_axfr(stdout: str, _stderr: str) -> dict:
    records = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(";") and "\t" in line:
            records.append(line)
    return {"summary": f"{len(records)} DNS record(s)" if records else "transfer failed/empty"}


def _parse_smtp_user_enum(stdout: str, _stderr: str) -> dict:
    users = []
    for line in stdout.splitlines():
        m = re.search(r"^\d+\s+.*\s+(\S+@\S+|\S+)$", line)
        if m and "exists" in line.lower():
            users.append(m.group(1))
            state_manager.add_user(m.group(1))
    return {"summary": f"{len(users)} user(s)", "users": users}


def _parse_snmpwalk(stdout: str, _stderr: str) -> dict:
    users = []
    info_lines = 0
    for line in stdout.splitlines():
        info_lines += 1
        # hrSWRunParameters or common user OIDs
        if "hrSWRunParameters" in line or "Login" in line:
            m = re.search(r'STRING:\s*"?(.+?)"?\s*$', line)
            if m:
                users.append(m.group(1))
    return {"summary": f"{info_lines} OID(s), {len(users)} interesting value(s)"}


def _parse_onesixtyone(stdout: str, _stderr: str) -> dict:
    communities = []
    for line in stdout.splitlines():
        m = re.search(r"\[(.+?)\]", line)
        if m:
            communities.append(m.group(1))
    return {"summary": f"community: {', '.join(communities)}" if communities else "no communities found"}


def _parse_rpcclient_enum(stdout: str, _stderr: str) -> dict:
    users = []
    for line in stdout.splitlines():
        m = re.search(r"user:\[(.+?)\]", line)
        if m:
            users.append(m.group(1))
            state_manager.add_user(m.group(1))
    return {"summary": f"{len(users)} user(s)", "users": users}


def _parse_ldapsearch_base(stdout: str, _stderr: str) -> dict:
    contexts = []
    for line in stdout.splitlines():
        m = re.search(r"namingContexts:\s*(.+)", line)
        if m:
            ctx = m.group(1).strip()
            contexts.append(ctx)
            # Extract domain from DC= components
            dcs = re.findall(r"DC=(\w+)", ctx, re.I)
            if dcs:
                domain = ".".join(dcs)
                state_manager.add_domain(domain)
    return {"summary": ", ".join(contexts) if contexts else "anonymous bind denied"}


def _parse_nmap_scripts(stdout: str, _stderr: str) -> dict:
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("|") and ":" in line:
            findings.append(line.lstrip("|_ ").strip())
    return {"summary": f"{len(findings)} script finding(s)" if findings else "no script output"}


def _parse_asrep_roast(stdout: str, _stderr: str) -> dict:
    hashes = []
    for line in stdout.splitlines():
        if "$krb5asrep$" in line:
            hashes.append(line.strip())
            m = re.search(r"\$krb5asrep\$\d*\$(.+?)@", line)
            if m:
                state_manager.add_hash(line.strip(), m.group(1))
    return {"summary": f"{len(hashes)} AS-REP hash(es)" if hashes else "no vulnerable users"}


def _parse_kerberoast(stdout: str, _stderr: str) -> dict:
    hashes = []
    for line in stdout.splitlines():
        if "$krb5tgs$" in line:
            hashes.append(line.strip())
            m = re.search(r"\$krb5tgs\$\d+\$\*(.+?)\$", line)
            if m:
                state_manager.add_hash(line.strip(), m.group(1))
    return {"summary": f"{len(hashes)} TGS hash(es)" if hashes else "no SPNs found"}


def _parse_searchsploit(stdout: str, _stderr: str) -> dict:
    exploits = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and "|" in line and "Exploit Title" not in line and "----" not in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2 and parts[0]:
                exploits.append(parts[0])
    return {"summary": f"{len(exploits)} exploit(s)" if exploits else "no exploits found", "exploits": exploits}


# Parser registry — maps YAML parser name → function
PARSERS: dict[str, callable] = {
    "nxc_shares": _parse_nxc_shares,
    "nxc_users": _parse_nxc_users,
    "nxc_rid": _parse_nxc_rid,
    "enum4linux_ng": _parse_enum4linux_ng,
    "smbclient_list": _parse_smbclient_list,
    "showmount": _parse_showmount,
    "whatweb": _parse_whatweb,
    "http_headers": _parse_http_headers,
    "ffuf_json": _parse_ffuf_json,
    "dig_axfr": _parse_dig_axfr,
    "smtp_user_enum": _parse_smtp_user_enum,
    "snmpwalk": _parse_snmpwalk,
    "onesixtyone": _parse_onesixtyone,
    "rpcclient_enum": _parse_rpcclient_enum,
    "ldapsearch_base": _parse_ldapsearch_base,
    "nmap_scripts": _parse_nmap_scripts,
    "asrep_roast": _parse_asrep_roast,
    "kerberoast": _parse_kerberoast,
    "searchsploit": _parse_searchsploit,
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# Wordlist size presets — maps size name to seclists path
WORDLIST_PRESETS: dict[str, str] = {
    "small": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "large": "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
}


class EnumerateEngine:
    """Loads the registry and runs enumeration commands."""

    def __init__(self):
        self.registry: dict = {}
        self._load_registry()

    def _load_registry(self):
        if not CORE_ENUMERATE_REGISTRY.exists():
            print_error(f"Enumerate registry not found: {CORE_ENUMERATE_REGISTRY}")
            return
        try:
            data = yaml.safe_load(CORE_ENUMERATE_REGISTRY.read_text(encoding="utf-8"))
            self.registry = data.get("services", {})
        except (yaml.YAMLError, OSError) as e:
            print_error(f"Failed to load enumerate registry: {e}")

    def _resolve_services(self, targets: list[str] | None) -> list[tuple[str, int, dict]]:
        """Map requested services/ports to registry entries matched against open ports.

        Returns list of (service_name, matched_port, service_config).
        """
        open_ports = set(state_manager.get_open_ports())
        if not open_ports:
            print_warning("No open ports in state. Run a scan first.")
            return []

        results: list[tuple[str, int, dict]] = []

        if targets:
            for t in targets:
                # Could be a port number or a service name
                if t.isdigit():
                    port = int(t)
                    if port not in open_ports:
                        print_warning(f"Port {port} not in open ports, skipping")
                        continue
                    for svc_name, svc_cfg in self.registry.items():
                        if port in svc_cfg.get("ports", []):
                            results.append((svc_name, port, svc_cfg))
                            break
                    else:
                        print_warning(f"No registry entry for port {port}")
                else:
                    svc_cfg = self.registry.get(t)
                    if not svc_cfg:
                        print_warning(f"Unknown service: {t}")
                        continue
                    matched_ports = open_ports.intersection(svc_cfg.get("ports", []))
                    if not matched_ports:
                        print_warning(f"Service '{t}' — no matching open ports")
                        continue
                    for p in sorted(matched_ports):
                        results.append((t, p, svc_cfg))
        else:
            # All services with matching open ports
            for svc_name, svc_cfg in self.registry.items():
                if svc_name == "versions":
                    continue  # handled separately
                matched_ports = open_ports.intersection(svc_cfg.get("ports", []))
                for p in sorted(matched_ports):
                    results.append((svc_name, p, svc_cfg))

        return results

    def _inject(self, cmd: str, port: int, output_dir: Path,
                username: str = "", password: str = "",
                wordlist: str = "") -> str:
        """Replace all {VARIABLE} placeholders in a command string."""
        ip = state_manager.get_var("IP") or ""
        domain = state_manager.get_var("DOMAIN") or ""

        replacements = {
            "{IP}": ip,
            "{PORT}": str(port),
            "{DOMAIN}": domain,
            "{USER}": username,
            "{PASS}": password,
            "{OUTPUT_DIR}": str(output_dir),
            "{WORDLIST}": wordlist,
        }
        for k, v in replacements.items():
            cmd = cmd.replace(k, v)
        return cmd

    def _run_cmd(self, name: str, tool: str, cmd_template: str, port: int,
                 output_dir: Path, timeout: int,
                 parser_name: str | None,
                 username: str = "", password: str = "",
                 wordlist: str = "") -> CmdResult:
        """Execute a single enumeration command."""
        # Check tool availability
        if not shutil.which(tool):
            return CmdResult(name=name, tool=tool, cmd=cmd_template,
                             status="skipped", findings="not installed")

        cmd_str = self._inject(cmd_template, port, output_dir, username, password, wordlist)
        print_command(cmd_str)

        # Save output to file
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", f"{name}")
        out_path = output_dir / f"{safe_name}.txt"

        try:
            t0 = time.monotonic()
            result = subprocess.run(
                cmd_str, shell=True, capture_output=True, text=True,
                timeout=timeout,
            )
            elapsed = round(time.monotonic() - t0, 1)

            # Write raw output
            out_path.write_text(
                f"# Command: {cmd_str}\n# Exit: {result.returncode}\n\n"
                f"{result.stdout or ''}\n{result.stderr or ''}",
                encoding="utf-8",
            )

            # Parse if parser available
            findings = ""
            if parser_name and parser_name in PARSERS:
                try:
                    parsed = PARSERS[parser_name](result.stdout or "", result.stderr or "")
                    findings = parsed.get("summary", "")
                except Exception:
                    findings = "parser error"
            elif result.returncode == 0:
                lines = (result.stdout or "").strip().splitlines()
                findings = f"{len(lines)} line(s) of output"

            # Record in session DB
            try:
                from capo.modules.session_db import session_db
                session_db.record_command(
                    tool=tool, command=cmd_str,
                    output_file=str(out_path),
                    exit_code=result.returncode,
                    duration=elapsed, source="enumerate",
                )
            except Exception:
                pass

            status = "ok" if result.returncode == 0 else "error"
            return CmdResult(name=name, tool=tool, cmd=cmd_str,
                             status=status, duration=elapsed,
                             findings=findings, output_file=str(out_path))

        except subprocess.TimeoutExpired:
            out_path.write_text(f"# Command: {cmd_str}\n# TIMED OUT after {timeout}s\n",
                                encoding="utf-8")
            return CmdResult(name=name, tool=tool, cmd=cmd_str,
                             status="timeout", findings=f"timed out ({timeout}s)",
                             output_file=str(out_path))
        except Exception as e:
            return CmdResult(name=name, tool=tool, cmd=cmd_str,
                             status="error", findings=str(e))

    def _run_searchsploit(self, output_dir: Path) -> list[CmdResult]:
        """Run searchsploit for each discovered service+version pair."""
        if not shutil.which("searchsploit"):
            return [CmdResult(name="SearchSploit", tool="searchsploit",
                              cmd="", status="skipped", findings="not installed")]

        versions_cfg = self.registry.get("versions", {})
        if not versions_cfg:
            return []

        ports = state_manager.get("ports", [])
        queries = set()
        for p in ports:
            svc = p.get("service", "").strip()
            ver = p.get("version", "").strip()
            if svc and ver:
                queries.add(f"{svc} {ver}")
            if svc:
                queries.add(svc)
            if ver:
                queries.add(ver)

        if not queries:
            return []

        results = []
        for query in sorted(queries):
            cmd_str = f"searchsploit --color=never {query}"
            print_command(cmd_str)
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", query)
            out_path = output_dir / f"searchsploit_{safe}.txt"

            try:
                r = subprocess.run(
                    cmd_str, shell=True, capture_output=True, text=True, timeout=15,
                )
                out_path.write_text(r.stdout or "", encoding="utf-8")
                parsed = _parse_searchsploit(r.stdout or "", r.stderr or "")
                results.append(CmdResult(
                    name=f"searchsploit: {query}", tool="searchsploit",
                    cmd=cmd_str, status="ok", findings=parsed["summary"],
                    output_file=str(out_path),
                ))
            except subprocess.TimeoutExpired:
                results.append(CmdResult(
                    name=f"searchsploit: {query}", tool="searchsploit",
                    cmd=cmd_str, status="timeout", findings="timed out",
                ))
        return results

    def _resolve_wordlist(self, wordlist: str, wordlist_size: str) -> str:
        """Resolve the wordlist path from custom path or size preset."""
        if wordlist:
            return wordlist
        size = wordlist_size.lower().strip()
        return WORDLIST_PRESETS.get(size, WORDLIST_PRESETS["small"])

    def run(self, services: list[str] | None = None,
            username: str = "", password: str = "",
            wordlist: str = "", wordlist_size: str = "small") -> list[ServiceResult]:
        """Run enumeration and return structured results.

        Args:
            services: List of service names or port numbers to scope.
                      None = enumerate all services with open ports.
            username: Credential for auth-required commands.
            password: Credential for auth-required commands.
            wordlist: Custom wordlist path (overrides wordlist_size).
            wordlist_size: Preset size — small, medium, large.
        """
        has_creds = bool(username and password)
        resolved_wordlist = self._resolve_wordlist(wordlist, wordlist_size)
        matched = self._resolve_services(services)

        if not matched:
            return []

        # Create output directory
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = state_manager.workspace / "scans" / f"enumerate_{ts}"
        output_dir.mkdir(parents=True, exist_ok=True)

        all_results: list[ServiceResult] = []
        seen_cmds: set[str] = set()  # dedup across overlapping services
        skipped_tools: list[str] = []
        total_ok = 0

        console.print(f"\n[bold cyan][*] Enumerating {len(matched)} service/port(s)...[/bold cyan]\n")

        for svc_name, port, svc_cfg in matched:
            svc_result = ServiceResult(service=svc_name, port=port)
            console.print(f"[bold white]  {svc_name.upper()} ({port}):[/bold white]")

            for entry in svc_cfg.get("commands", []):
                # Skip auth commands if no creds provided
                if entry.get("auth", False) and not has_creds:
                    continue

                # Dedup — same command template already ran
                cmd_key = f"{entry['tool']}:{entry['cmd']}"
                if cmd_key in seen_cmds:
                    continue
                seen_cmds.add(cmd_key)

                timeout = entry.get("timeout", 60)
                parser_name = entry.get("parser")

                cr = self._run_cmd(
                    name=entry["name"],
                    tool=entry["tool"],
                    cmd_template=entry["cmd"],
                    port=port,
                    output_dir=output_dir,
                    timeout=timeout,
                    parser_name=parser_name,
                    username=username,
                    password=password,
                    wordlist=resolved_wordlist,
                )

                svc_result.commands.append(cr)

                # Print one-liner result
                icon = {"ok": "[green]✓[/green]", "skipped": "[yellow]→[/yellow]",
                        "timeout": "[red]⏱[/red]", "error": "[red]✗[/red]"}.get(cr.status, "?")
                finding_str = f" — {cr.findings}" if cr.findings else ""
                console.print(f"    {icon} {cr.name}{finding_str}")

                if cr.status == "skipped":
                    skipped_tools.append(cr.tool)
                elif cr.status == "ok":
                    total_ok += 1

            all_results.append(svc_result)

        # Run searchsploit for all version combos
        console.print(f"\n[bold white]  VERSION SEARCH:[/bold white]")
        ss_results = self._run_searchsploit(output_dir)
        if ss_results:
            ss_svc = ServiceResult(service="versions", port=0)
            for cr in ss_results:
                ss_svc.commands.append(cr)
                icon = {"ok": "[green]✓[/green]", "skipped": "[yellow]→[/yellow]"}.get(cr.status, "?")
                finding_str = f" — {cr.findings}" if cr.findings else ""
                console.print(f"    {icon} {cr.name}{finding_str}")
                if cr.status == "ok":
                    total_ok += 1
                elif cr.status == "skipped":
                    skipped_tools.append(cr.tool)
            all_results.append(ss_svc)

        # Summary
        unique_skipped = sorted(set(skipped_tools))
        total_cmds = sum(len(sr.commands) for sr in all_results)
        console.print(f"\n[bold cyan]  Done:[/bold cyan] {total_ok}/{total_cmds} commands succeeded")
        if unique_skipped:
            console.print(f"  [yellow]Skipped ({len(unique_skipped)} tool(s) not installed):[/yellow] {', '.join(unique_skipped)}")
        console.print(f"  [dim]Output: {output_dir}[/dim]\n")

        # Write summary file
        self._write_summary(output_dir, all_results)

        return all_results

    def _write_summary(self, output_dir: Path, results: list[ServiceResult]):
        """Write a concise summary.txt."""
        lines = [f"# Enumerate Summary — {datetime.now(timezone.utc).isoformat()}\n"]
        for sr in results:
            lines.append(f"\n## {sr.service.upper()} (port {sr.port})")
            for cr in sr.commands:
                status_mark = {"ok": "✓", "skipped": "SKIP", "timeout": "TIMEOUT", "error": "FAIL"}.get(cr.status, "?")
                lines.append(f"  [{status_mark}] {cr.name}: {cr.findings}")
                if cr.output_file:
                    lines.append(f"       → {Path(cr.output_file).name}")
        summary_path = output_dir / "summary.txt"
        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


enumerate_engine = EnumerateEngine()
