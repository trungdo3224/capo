"""Context-Aware Trigger System.

Monitors state changes after scans and provides intelligent suggestions
based on discovered services, ports, and enumeration results.
"""

import yaml

from capo.config import CUSTOM_TRIGGERS_FILE
from capo.state import state_manager
from capo.utils.display import print_suggestion, print_warning


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


def _inject_vars(text: str) -> str:
    """Replace {VAR} placeholders with state values."""
    from capo.utils.inject import inject_vars
    return inject_vars(text)


def check_triggers():
    """Check current state and print relevant suggestions."""
    open_ports = state_manager.get_open_ports()
    if not open_ports:
        return

    merged = get_merged_triggers()
    for port in open_ports:
        triggers = merged.get(port, [])
        for trigger in triggers:
            title = trigger["title"]
            cmds = [_inject_vars(s) for s in trigger["suggestions"]]
            print_suggestion(title, cmds)

    # Additional context-aware checks
    _check_ad_environment()
    _check_web_findings()
    _check_credential_opportunities()
    _suggest_methodologies()


def check_port_trigger(port: int):
    """Check trigger for a specific newly discovered port."""
    merged = get_merged_triggers()
    triggers = merged.get(port, [])
    for trigger in triggers:
        title = trigger["title"]
        cmds = [_inject_vars(s) for s in trigger["suggestions"]]
        print_suggestion(title, cmds)


def _check_ad_environment():
    """Check if this looks like an AD environment and suggest accordingly."""
    ports = state_manager.get_open_ports()
    ad_ports = {88, 389, 636, 445, 135, 139}
    if len(ad_ports.intersection(ports)) >= 3:
        domain = state_manager.get("domain", "")
        users = state_manager.get("users", [])
        if domain and users:
            print_suggestion(
                "Active Directory environment with known users",
                [
                    f"capo query asrep-roast  (Try AS-REP Roasting for {len(users)} users)",
                    "capo query kerberoast   (Enumerate SPNs)",
                    "capo query bloodhound   (Run BloodHound collection)",
                ]
            )


def _check_web_findings():
    """Check web directories for interesting findings."""
    dirs = state_manager.get("directories", [])
    for d in dirs:
        path = d.get("path", "").lower()
        if "wp-" in path:
            print_suggestion("WordPress detected!", [
                _inject_vars("wpscan --url http://{IP} -e ap,at,u"),
                "capo query wordpress",
            ])
            return
        if "cgi-bin" in path:
            print_suggestion("CGI-bin found - Check Shellshock", [
                "capo query shellshock",
            ])
            return


def _check_credential_opportunities():
    """Suggest next steps based on discovered credentials."""
    creds = state_manager.get("credentials", [])
    if creds:
        has_winrm = 5985 in state_manager.get_open_ports()
        has_ssh = 22 in state_manager.get_open_ports()
        has_rdp = 3389 in state_manager.get_open_ports()

        cmds = []
        if has_winrm:
            cmds.append("evil-winrm -i {IP} -u {USER} -p {PASS}")
        if has_ssh:
            cmds.append("ssh {USER}@{IP}")
        if has_rdp:
            cmds.append("xfreerdp /v:{IP} /u:{USER} /p:{PASS}")

        if cmds:
            print_suggestion(
                f"Found {len(creds)} credential(s) - Try access",
                [_inject_vars(c) for c in cmds],
            )


def _suggest_methodologies():
    """Suggest applicable methodologies that haven't been started yet."""
    from capo.modules.methodology import methodology_engine

    methodology_engine.load_all()
    applicable = methodology_engine.get_applicable()
    progress = state_manager.get("methodology_progress", {})

    suggestions = []
    for meth in applicable:
        if meth.name not in progress:
            suggestions.append(f"capo methodology start {meth.name}  ({meth.display_name})")

    if suggestions:
        print_suggestion("📋 Applicable methodology workflows", suggestions)
