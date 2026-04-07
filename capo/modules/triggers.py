"""Context-Aware Trigger System.

Monitors state changes after scans and provides intelligent suggestions
based on discovered services, ports, and enumeration results.
"""

import yaml

from capo.config import CUSTOM_TRIGGERS_FILE
from capo.state import state_manager
from capo.utils.display import console, print_warning


def _load_custom_triggers() -> dict[int, list[dict]]:
    """Load user-defined triggers from ~/.capo/custom_triggers.yaml.

    Expected format:
        triggers:
          8888:
            - title: "Custom service detected"
              suggestions:
                - "custom-tool --target {IP}"
    """
    if not CUSTOM_TRIGGERS_FILE.exists():
        return {}
    try:
        data = yaml.safe_load(CUSTOM_TRIGGERS_FILE.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        print_warning(f"Failed to load custom triggers: {e}")
        return {}
    if not isinstance(data, dict):
        return {}
    raw = data.get("triggers", {})
    if not isinstance(raw, dict):
        return {}
    result: dict[int, list[dict]] = {}
    for port, entries in raw.items():
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            continue
        if isinstance(entries, list):
            result[port_int] = [
                e for e in entries
                if isinstance(e, dict) and "title" in e and "suggestions" in e
            ]
    return result


def get_merged_triggers() -> dict[int, list[dict]]:
    """Return PORT_TRIGGERS merged with custom triggers (custom appends)."""
    merged = {k: list(v) for k, v in PORT_TRIGGERS.items()}
    custom = _load_custom_triggers()
    for port, entries in custom.items():
        merged.setdefault(port, []).extend(entries)
    return merged


def init_custom_triggers():
    """Create a starter custom_triggers.yaml if it doesn't exist."""
    if CUSTOM_TRIGGERS_FILE.exists():
        return False
    template = """# Custom C.A.P.O triggers — add your own port-based suggestions
# Entries here are appended to the built-in triggers.
#
# Format:
#   triggers:
#     <port>:
#       - title: "Description"
#         suggestions:
#           - "command --flag {IP}"
#
# Available variables: {IP}, {DOMAIN}, {USER}, {PASS}, {USERFILE}, {PASSFILE}, {HASH}

triggers:
  # Example:
  # 9090:
  #   - title: "Cockpit web panel detected"
  #     suggestions:
  #       - "Browse to http://{IP}:9090"
"""
    CUSTOM_TRIGGERS_FILE.write_text(template, encoding="utf-8")
    return True

# Port-based suggestion rules
PORT_TRIGGERS: dict[int, list[dict]] = {
    21: [
        {"title": "FTP detected", "suggestions": [
            "capo query ftp-enum",
            "Try anonymous login: ftp {IP}",
        ]},
    ],
    22: [
        {"title": "SSH detected", "suggestions": [
            "capo query ssh",
            "capo brute ssh -U {USERFILE} -P {PASSFILE}",
            "Check for weak keys/old versions",
        ]},
    ],
    25: [
        {"title": "SMTP detected", "suggestions": [
            "capo query smtp",
            "smtp-user-enum -M VRFY -U users.txt -t {IP}",
        ]},
    ],
    53: [
        {"title": "DNS detected - Try zone transfer", "suggestions": [
            "capo query dns",
            "dig axfr @{IP} {DOMAIN}",
        ]},
    ],
    80: [
        {"title": "HTTP detected", "suggestions": [
            "capo web fuzz",
            "capo brute web-form -m http-get-form -U {USERFILE} -P {PASSFILE} # (If login present)",
            "capo query http-enum",
            "whatweb http://{IP}",
            "curl -s http://{IP}/robots.txt",
        ]},
    ],
    88: [
        {"title": "🔑 Kerberos detected - Active Directory!", "suggestions": [
            "capo query kerberos",
            "capo query asrep-roast",
            "capo query kerberoast",
            "capo nxc spray -U {USERFILE} -P {PASSFILE}",
            "capo nxc rid-brute",
        ]},
    ],
    110: [
        {"title": "POP3 detected", "suggestions": [
            "capo query pop3",
        ]},
    ],
    111: [
        {"title": "RPCbind detected", "suggestions": [
            "capo query rpcbind",
            "rpcinfo -p {IP}",
            "showmount -e {IP}",
        ]},
    ],
    135: [
        {"title": "MSRPC detected - Windows host", "suggestions": [
            "capo query msrpc",
            "rpcclient -U '' -N {IP}",
        ]},
    ],
    139: [
        {"title": "NetBIOS-SSN detected", "suggestions": [
            "capo nxc null",
            "enum4linux-ng -A {IP}",
        ]},
    ],
    389: [
        {"title": "🔑 LDAP detected - Active Directory!", "suggestions": [
            "capo query ldap",
            "capo nxc ldap-enum",
            "nxc ldap {IP} -u \"{USERFILE}\" -p \"{PASSFILE}\" --continue-on-success",
            "ldapsearch -x -H ldap://{IP} -b '' -s base namingContexts",
        ]},
    ],
    443: [
        {"title": "HTTPS detected", "suggestions": [
            "capo web fuzz --port 443 --https",
            "sslscan {IP}",
            "Check for alternate hostnames in SSL cert",
        ]},
    ],
    445: [
        {"title": "SMB detected", "suggestions": [
            "capo nxc null",
            "capo nxc guest",
            "capo nxc spray -U {USERFILE} -P {PASSFILE}",
            "capo nxc rid-brute",
            "smbclient -N -L //{IP}",
        ]},
    ],
    1433: [
        {"title": "MSSQL detected", "suggestions": [
            "capo query mssql",
            "nxc mssql {IP} -u \"{USERFILE}\" -p \"{PASSFILE}\" --continue-on-success",
            "impacket-mssqlclient {DOMAIN}/{USER}@{IP} -windows-auth",
        ]},
    ],
    1521: [
        {"title": "Oracle DB detected", "suggestions": [
            "capo query oracle",
            "odat all -s {IP}",
        ]},
    ],
    2049: [
        {"title": "NFS detected", "suggestions": [
            "showmount -e {IP}",
            "mount -t nfs {IP}:/share /mnt/nfs",
        ]},
    ],
    3306: [
        {"title": "MySQL detected", "suggestions": [
            "capo query mysql",
            "mysql -h {IP} -u root -p",
        ]},
    ],
    3389: [
        {"title": "RDP detected", "suggestions": [
            "capo query rdp",
            "nxc rdp {IP} -u \"{USERFILE}\" -p \"{PASSFILE}\" --continue-on-success",
            "xfreerdp /v:{IP} /u:{USER} /p:{PASS}",
        ]},
    ],
    5432: [
        {"title": "PostgreSQL detected", "suggestions": [
            "capo query postgres",
            "psql -h {IP} -U postgres",
        ]},
    ],
    5985: [
        {"title": "WinRM detected - Try Evil-WinRM", "suggestions": [
            "capo query winrm",
            "evil-winrm -i {IP} -u {USER} -p {PASS}",
        ]},
    ],
    5986: [
        {"title": "WinRM-SSL detected", "suggestions": [
            "evil-winrm -i {IP} -u {USER} -p {PASS} -S",
        ]},
    ],
    6379: [
        {"title": "Redis detected", "suggestions": [
            "capo query redis",
            "redis-cli -h {IP}",
        ]},
    ],
    8080: [
        {"title": "HTTP-Alt detected", "suggestions": [
            "capo web fuzz --port 8080",
            "whatweb http://{IP}:8080",
        ]},
    ],
    8443: [
        {"title": "HTTPS-Alt detected", "suggestions": [
            "capo web fuzz --port 8443 --https",
        ]},
    ],
    27017: [
        {"title": "MongoDB detected", "suggestions": [
            "capo query mongodb",
        ]},
    ],
}



def check_triggers():
    """Print a brief summary of discovered services after a scan."""
    from capo.config import output_config
    if output_config.quiet:
        return
    open_ports = state_manager.get_open_ports()
    if not open_ports:
        return

    merged = get_merged_triggers()
    services: list[str] = []
    for port in sorted(open_ports):
        triggers = merged.get(port, [])
        if triggers:
            # Use the trigger title (strip emoji prefixes) as service label
            label = triggers[0]["title"].replace("🔑 ", "").replace("📋 ", "")
            services.append(f"{port} — {label}")
        else:
            services.append(f"{port} — unknown service")

    if services:
        from rich.panel import Panel
        content = "\n".join(f"  [cyan]{s}[/cyan]" for s in services)
        console.print()
        console.print(Panel(
            content,
            title="[bold yellow]Services found[/bold yellow]",
            border_style="yellow",
        ))


