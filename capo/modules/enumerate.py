"""Enumerate engine — runs service-specific commands from the YAML registry.

Usage:
    from capo.modules.enumerate import EnumerateEngine
    engine = EnumerateEngine()
    engine.run()                          # all discovered services
    engine.run(services=["smb", "http"])  # scoped
    engine.run(username="admin", password="pass")  # authenticated
"""

import re
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
    versioned = []  # name/version pairs — the stuff that matters for CVEs
    # whatweb outputs: ToolName[version], so capture "Name[detail]" pairs
    for m in re.finditer(r"(\w[\w.-]+)\[([^\]]+)\]", stdout):
        name, detail = m.group(1), m.group(2)
        if name.lower() not in ("http",):
            entry = f"{name}/{detail}" if detail else name
            techs.append(entry)
            # Flag entries with version numbers (digits after a slash/space)
            if re.search(r"[\d]+\.[\d]+", detail):
                versioned.append(entry)
    # Also grab standalone bracketed items (status codes, etc.)
    if not techs:
        for part in re.findall(r"\[([^\]]+)\]", stdout):
            part = part.strip()
            if part and not re.match(r"^\d{3}", part):
                techs.append(part)
    # Feed versioned software into state so searchsploit can query them
    for entry in versioned:
        parts = entry.split("/", 1)
        if len(parts) == 2:
            state_manager.add_software(parts[0], parts[1], source="whatweb")

    # Prioritize versioned software in summary — that's what leads to CVEs
    if versioned:
        summary = ", ".join(versioned[:6])
    elif techs:
        summary = ", ".join(techs[:6])
    else:
        summary = "no findings"
    return {"summary": summary, "techs": techs, "versioned": versioned}


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


def _parse_common_files(stdout: str, _stderr: str) -> dict:
    """Parse curl batch probe output — format: 'STATUS_CODE URL' per line."""
    found = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            code, url = parts[0], parts[1]
            if code in ("200", "301", "302", "403"):
                # Extract path from URL
                path = re.sub(r"https?://[^/]+", "", url)
                found.append(f"{path} [{code}]")
                if code == "200":
                    state_manager.add_directory(path, int(code))
    if found:
        return {"summary": ", ".join(found)}
    return {"summary": "nothing accessible"}


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
    "common_files": _parse_common_files,
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
        Matches both TCP and UDP ports using (port, protocol) tuples.
        """
        open_ports_proto = state_manager.get_open_ports_proto()  # {(port, proto), ...}
        if not open_ports_proto:
            print_warning("No open ports in state. Run a scan first.")
            return []

        results: list[tuple[str, int, dict]] = []

        if targets:
            for t in targets:
                # Could be a port number or a service name
                if t.isdigit():
                    port = int(t)
                    # Match port across any protocol
                    matched_any = False
                    for svc_name, svc_cfg in self.registry.items():
                        proto = svc_cfg.get("protocol", "tcp")
                        if port in svc_cfg.get("ports", []) and (port, proto) in open_ports_proto:
                            results.append((svc_name, port, svc_cfg))
                            matched_any = True
                            break
                    if not matched_any:
                        print_warning(f"Port {port} not open or no registry entry")
                else:
                    svc_cfg = self.registry.get(t)
                    if not svc_cfg:
                        print_warning(f"Unknown service: {t}")
                        continue
                    proto = svc_cfg.get("protocol", "tcp")
                    matched_ports = {
                        p for p in svc_cfg.get("ports", [])
                        if (p, proto) in open_ports_proto
                    }
                    if not matched_ports:
                        print_warning(f"Service '{t}' — no matching open ports")
                        continue
                    for p in sorted(matched_ports):
                        results.append((t, p, svc_cfg))
        else:
            # All services with matching open ports
            for svc_name, svc_cfg in self.registry.items():
                proto = svc_cfg.get("protocol", "tcp")
                matched_ports = {
                    p for p in svc_cfg.get("ports", [])
                    if (p, proto) in open_ports_proto
                }
                for p in sorted(matched_ports):
                    results.append((svc_name, p, svc_cfg))

        return results

    def _inject(self, cmd: str, port: int, output_dir: Path,
                username: str = "", password: str = "",
                wordlist: str = "", community: str = "public") -> str:
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
            "{COMMUNITY}": community,
        }
        for k, v in replacements.items():
            cmd = cmd.replace(k, v)
        return cmd

    def _run_cmd(self, name: str, tool: str, cmd_template: str, port: int,
                 output_dir: Path, timeout: int,
                 parser_name: str | None,
                 username: str = "", password: str = "",
                 wordlist: str = "", community: str = "public") -> CmdResult:
        """Execute a single enumeration command."""
        # Check tool availability
        if not shutil.which(tool):
            return CmdResult(name=name, tool=tool, cmd=cmd_template,
                             status="skipped", findings="not installed")

        cmd_str = self._inject(cmd_template, port, output_dir, username, password, wordlist, community)
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

            # Parse output — run parser regardless of exit code since many
            # pentest tools exit non-zero but still produce useful output
            findings = ""
            if parser_name and parser_name in PARSERS:
                try:
                    parsed = PARSERS[parser_name](result.stdout or "", result.stderr or "")
                    findings = parsed.get("summary", "")
                except Exception:
                    findings = "parser error"

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

    def _run_searchsploit(self, output_dir: Path,
                          matched: list[tuple[str, int, dict]]) -> list[CmdResult]:
        """Run searchsploit for services that were actually enumerated."""
        if not shutil.which("searchsploit"):
            return [CmdResult(name="SearchSploit", tool="searchsploit",
                              cmd="", status="skipped", findings="not installed")]

        # Only search versions for ports we actually enumerated
        enumerated_ports = {port for _, port, _ in matched}
        ports = state_manager.get("ports", [])
        queries = set()
        for p in ports:
            if p.get("port", 0) not in enumerated_ports:
                continue
            svc = p.get("service", "").strip()
            ver = p.get("version", "").strip()
            if svc and ver:
                queries.add(f"{svc} {ver}")

        # Also query software discovered by whatweb / page scraping
        for sw in state_manager.get("software", []):
            name = sw.get("name", "").strip()
            ver = sw.get("version", "").strip()
            if name and ver:
                queries.add(f"{name} {ver}")

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

    # Patterns for scraping interesting data from web pages
    _SCRAPE_PATTERNS: dict[str, re.Pattern] = {
        "emails": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "base64": re.compile(r"(?<![a-zA-Z0-9/+=])([A-Za-z0-9+/]{20,}={0,2})(?![a-zA-Z0-9/+=])"),
        "internal_ips": re.compile(
            r"\b((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b"
        ),
        "comments": re.compile(r"<!--(.*?)-->", re.S),
        "credentials": re.compile(
            r"(?:password|passwd|pwd|api[_-]?key|token|secret)[\s:=]+[\"']?(\S{4,})[\"']?",
            re.I,
        ),
    }

    # Patterns to detect software+version from HTML content.
    # Each tuple: (compiled regex, group index for name, group index for version)
    _SOFTWARE_PATTERNS: list[tuple[re.Pattern, int, int]] = [
        # <meta name="generator" content="WordPress 5.8.1">
        (re.compile(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([A-Za-z][\w.-]*)\s+'
            r'(\d+\.\d+(?:\.\d+)?(?:[a-z0-9._-]*))',
            re.I,
        ), 1, 2),
        # "Powered by WordPress 5.8" / "Powered by Drupal 9.3.0"
        (re.compile(
            r'[Pp]owered\s+by\s+([A-Za-z][\w.-]*)\s+(\d+\.\d+(?:\.\d+)?)',
        ), 1, 2),
        # wp-content/themes or wp-includes → WordPress (version from generator above)
        # /misc/drupal.js or /sites/default → Drupal
        # /media/jui/js → Joomla
        # Common URL path patterns: WordPress/5.8 style in query strings
        (re.compile(
            r'(?:ver|version)=(\d+\.\d+(?:\.\d+)?(?:[a-z0-9._-]*))\b.*?'
            r'wp-(?:content|includes)',
            re.I | re.S,
        ), 0, 1),  # group 0 unused, we handle this specially
        # jQuery/3.6.0 or similar lib/version in script src
        (re.compile(
            r'(?:jquery|angular|react|vue|bootstrap|lodash|backbone|ember|knockout)'
            r'[/.-](\d+\.\d+(?:\.\d+)?)',
            re.I,
        ), 0, 1),  # name from match text, version from group 1
        # Apache/2.4.49 or nginx/1.18.0 in HTML (rare but happens in error pages)
        (re.compile(
            r'(Apache|nginx|IIS|LiteSpeed|Caddy)[/ ](\d+\.\d+(?:\.\d+)?)',
            re.I,
        ), 1, 2),
        # PHP/7.4.3 in HTML (error pages, phpinfo)
        (re.compile(r'(PHP)[/ ](\d+\.\d+(?:\.\d+)?)', re.I), 1, 2),
        # Tomcat/9.0.50, Jetty, GlassFish
        (re.compile(
            r'(Tomcat|Jetty|GlassFish|WildFly|Weblogic)[/ ](\d+\.\d+(?:\.\d+)?)',
            re.I,
        ), 1, 2),
    ]

    # CMS fingerprints — detect CMS by path patterns even without explicit version
    _CMS_FINGERPRINTS: dict[str, re.Pattern] = {
        "WordPress": re.compile(r'wp-(?:content|includes|admin)[/"\']', re.I),
        "Drupal": re.compile(r'(?:/misc/drupal\.js|/sites/default/|Drupal\.settings)', re.I),
        "Joomla": re.compile(r'(?:/media/jui/|/administrator/|Joomla!)', re.I),
    }

    def _scrape_pages(self, output_dir: Path,
                      matched: list[tuple[str, int, dict]]) -> list[CmdResult]:
        """Scrape discovered web pages for software versions, emails, credentials, and more."""
        if not shutil.which("curl"):
            return []

        # Collect web ports that were enumerated
        web_ports: list[tuple[str, int]] = []
        for svc_name, port, _ in matched:
            if svc_name == "http":
                web_ports.append(("http", port))
            elif svc_name == "https":
                web_ports.append(("https", port))

        if not web_ports:
            return []

        ip = state_manager.get_var("IP") or ""
        if not ip:
            return []

        # Build URL list: index pages + discovered directories (200 only)
        urls: list[str] = []
        for scheme, port in web_ports:
            urls.append(f"{scheme}://{ip}:{port}/")

        directories = state_manager.get("directories", [])
        for d in directories:
            path = d.get("path", "") if isinstance(d, dict) else str(d)
            status = d.get("status", 0) if isinstance(d, dict) else 200
            if status == 200 and path:
                for scheme, port in web_ports:
                    urls.append(f"{scheme}://{ip}:{port}{path}")

        # Deduplicate and cap at 30 pages to keep it fast
        urls = list(dict.fromkeys(urls))[:30]

        if not urls:
            return []

        # Scrape all pages
        all_emails: set[str] = set()
        all_software: dict[str, str] = {}  # name → version
        all_base64: set[str] = set()
        all_internal_ips: set[str] = set()
        all_comments: list[str] = []
        all_creds: set[str] = set()
        detected_cms: set[str] = set()
        raw_lines: list[str] = []

        for url in urls:
            try:
                curl_flag = "-sk" if url.startswith("https") else "-s"
                r = subprocess.run(
                    f"curl {curl_flag} -L --max-time 5 {url}",
                    shell=True, capture_output=True, text=True, timeout=10,
                )
                body = r.stdout or ""
                if not body:
                    continue

                raw_lines.append(f"\n# {url}\n{body[:2000]}")

                all_emails.update(self._SCRAPE_PATTERNS["emails"].findall(body))

                # Detect software+version pairs
                for pattern, name_grp, ver_grp in self._SOFTWARE_PATTERNS:
                    for m in pattern.finditer(body):
                        if name_grp == 0 and ver_grp == 1:
                            # Special case: name from match text, version from group 1
                            # Extract the software name from the matched text
                            match_text = m.group(0).lower()
                            ver = m.group(1)
                            for lib in ("jquery", "angular", "react", "vue",
                                        "bootstrap", "lodash", "backbone",
                                        "ember", "knockout"):
                                if lib in match_text:
                                    all_software.setdefault(lib.capitalize(), ver)
                                    break
                            # WordPress ver= pattern
                            if "wp-" in match_text:
                                all_software.setdefault("WordPress", ver)
                        else:
                            name = m.group(name_grp)
                            ver = m.group(ver_grp)
                            all_software.setdefault(name, ver)

                # CMS fingerprints (detect CMS even without version)
                for cms_name, cms_pat in self._CMS_FINGERPRINTS.items():
                    if cms_pat.search(body):
                        detected_cms.add(cms_name)

                for b64 in self._SCRAPE_PATTERNS["base64"].findall(body):
                    # Filter out common false positives (CSS, JS variable names)
                    if not any(skip in b64 for skip in ("function", "return", "window")):
                        all_base64.add(b64)

                all_internal_ips.update(self._SCRAPE_PATTERNS["internal_ips"].findall(body))

                for comment in self._SCRAPE_PATTERNS["comments"].findall(body):
                    comment = comment.strip()
                    # Only keep non-trivial comments (>10 chars, not just whitespace/dashes)
                    if len(comment) > 10 and not re.match(r"^[\s\-=]+$", comment):
                        all_comments.append(comment[:200])

                all_creds.update(self._SCRAPE_PATTERNS["credentials"].findall(body))

            except (subprocess.TimeoutExpired, Exception):
                continue

        # Feed useful findings into state
        for email in all_emails:
            user_part = email.split("@")[0]
            state_manager.add_user(user_part)

        # Feed software+version into state for searchsploit
        for name, ver in all_software.items():
            state_manager.add_software(name, ver, source="page_scrape")

        # Write raw scrape output
        out_path = output_dir / "page_scrape.txt"
        out_path.write_text("\n".join(raw_lines[:5000]), encoding="utf-8")

        # Build summary
        parts: list[str] = []
        if all_emails:
            parts.append(f"{len(all_emails)} email(s)")
        if all_software:
            sw_strs = [f"{n} {v}" for n, v in sorted(all_software.items())[:5]]
            parts.append(f"software: {', '.join(sw_strs)}")
        if detected_cms - set(all_software.keys()):
            # CMS detected by fingerprint but no version found
            unversioned = detected_cms - set(all_software.keys())
            parts.append(f"CMS detected: {', '.join(sorted(unversioned))}")
        if all_base64:
            parts.append(f"{len(all_base64)} base64 string(s)")
        if all_internal_ips:
            parts.append(f"internal IPs: {', '.join(sorted(all_internal_ips))}")
        if all_comments:
            parts.append(f"{len(all_comments)} HTML comment(s)")
        if all_creds:
            parts.append(f"{len(all_creds)} credential-like string(s)")

        summary = ", ".join(parts) if parts else "nothing interesting"

        # Write detailed findings file
        findings_path = output_dir / "page_scrape_findings.txt"
        findings_lines = [f"# Page Scrape Findings — {len(urls)} page(s) scraped\n"]
        if all_emails:
            findings_lines.append(f"\n## Emails\n" + "\n".join(f"  {e}" for e in sorted(all_emails)))
        if all_software:
            findings_lines.append(
                f"\n## Software Detected\n"
                + "\n".join(f"  {n} {v}" for n, v in sorted(all_software.items()))
            )
        if detected_cms:
            findings_lines.append(
                f"\n## CMS Fingerprints\n"
                + "\n".join(f"  {c}" + (" (version unknown)" if c not in all_software else "") for c in sorted(detected_cms))
            )
        if all_base64:
            findings_lines.append(f"\n## Base64 Strings\n" + "\n".join(f"  {b}" for b in sorted(all_base64)[:20]))
        if all_internal_ips:
            findings_lines.append(f"\n## Internal IPs\n" + "\n".join(f"  {ip}" for ip in sorted(all_internal_ips)))
        if all_comments:
            findings_lines.append(f"\n## HTML Comments\n" + "\n".join(f"  {c}" for c in all_comments[:20]))
        if all_creds:
            findings_lines.append(f"\n## Credential-like Strings\n" + "\n".join(f"  {c}" for c in sorted(all_creds)))
        findings_path.write_text("\n".join(findings_lines) + "\n", encoding="utf-8")

        return [CmdResult(
            name=f"Page scrape ({len(urls)} pages)",
            tool="curl",
            cmd=f"scrape {len(urls)} discovered pages",
            status="ok",
            findings=summary,
            output_file=str(findings_path),
        )]

    def _resolve_wordlist(self, wordlist: str, wordlist_size: str) -> str:
        """Resolve the wordlist path from custom path or size preset."""
        if wordlist:
            return wordlist
        size = wordlist_size.lower().strip()
        return WORDLIST_PRESETS.get(size, WORDLIST_PRESETS["small"])

    def _extract_community(self, cr: "CmdResult") -> str:
        """Extract first SNMP community string from an onesixtyone CmdResult.

        Findings summary format: "community: public, private"
        """
        if cr.findings.startswith("community: "):
            first = cr.findings[len("community: "):].split(",")[0].strip()
            return first
        return ""

    def _print_manual(self, matched: list, has_creds: bool,
                      wordlist: str, community: str):
        """Print all resolved commands grouped by service without executing."""
        from capo.utils.display import console as _console

        # Dummy output dir placeholder — not a real path, just for display
        dummy_out = Path("/tmp/capo-output")
        seen: set[str] = set()

        _console.print("\n[bold cyan][*] Manual mode — copy commands to run yourself[/bold cyan]\n")

        for svc_name, port, svc_cfg in matched:
            cmds_for_svc = []
            for entry in svc_cfg.get("commands", []):
                if entry.get("auth", False) and not has_creds:
                    continue
                cmd_key = f"{entry['tool']}:{entry['cmd']}"
                if cmd_key in seen:
                    continue
                seen.add(cmd_key)
                resolved = self._inject(
                    entry["cmd"], port, dummy_out,
                    wordlist=wordlist, community=community,
                )
                cmds_for_svc.append((entry["name"], resolved))

            if cmds_for_svc:
                _console.print(f"[bold white]  {svc_name.upper()} ({port})[/bold white]")
                for name, cmd in cmds_for_svc:
                    _console.print(f"  [dim]# {name}[/dim]")
                    _console.print(f"  {cmd}\n")

        _console.print("[dim]Note: auth commands omitted — re-run with -u/-p to include them.[/dim]\n"
                       if not has_creds else "")

    def run(self, services: list[str] | None = None,
            username: str = "", password: str = "",
            wordlist: str = "", wordlist_size: str = "small",
            community: str = "", manual: bool = False) -> list[ServiceResult]:
        """Run enumeration and return structured results.

        Args:
            services: List of service names or port numbers to scope.
                      None = enumerate all services with open ports.
            username: Credential for auth-required commands.
            password: Credential for auth-required commands.
            wordlist: Custom wordlist path (overrides wordlist_size).
            wordlist_size: Preset size — small, medium, large.
            community: SNMP community string override. If empty, auto-detected
                       from onesixtyone output then falls back to "public".
            manual: If True, print resolved commands without executing them.
        """
        has_creds = bool(username and password)
        resolved_wordlist = self._resolve_wordlist(wordlist, wordlist_size)
        resolved_community = community or "public"
        matched = self._resolve_services(services)

        if not matched:
            return []

        if manual:
            self._print_manual(matched, has_creds, resolved_wordlist, resolved_community)
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

            # Per-service community string — starts from CLI override or "public",
            # updated if onesixtyone finds a different string mid-run.
            active_community = resolved_community

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
                    community=active_community,
                )

                # Auto-detect community string from onesixtyone for subsequent commands
                if entry.get("parser") == "onesixtyone" and cr.status == "ok":
                    detected = self._extract_community(cr)
                    if detected:
                        active_community = detected
                        console.print(f"      [dim]→ community string: {detected}[/dim]")

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

        # Scrape discovered web pages for useful data
        scrape_results = self._scrape_pages(output_dir, matched)
        if scrape_results:
            scrape_svc = ServiceResult(service="page_scrape", port=0)
            console.print(f"\n[bold white]  PAGE SCRAPE:[/bold white]")
            for cr in scrape_results:
                scrape_svc.commands.append(cr)
                icon = "[green]✓[/green]" if cr.status == "ok" else "[yellow]→[/yellow]"
                finding_str = f" — {cr.findings}" if cr.findings else ""
                console.print(f"    {icon} {cr.name}{finding_str}")
                if cr.status == "ok":
                    total_ok += 1
            all_results.append(scrape_svc)

        # Run searchsploit only for enumerated services
        console.print(f"\n[bold white]  VERSION SEARCH:[/bold white]")
        ss_results = self._run_searchsploit(output_dir, matched)
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
