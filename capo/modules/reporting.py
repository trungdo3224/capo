"""Report Generator — Builds pentest reports from state data.

Generates Markdown and HTML reports auto-populated from the state manager,
including port tables, user lists, credentials, attack timeline, and flags.
"""

import csv
import io
from datetime import datetime, timezone

from capo.state import state_manager


def generate_markdown(state: dict | None = None) -> str:
    """Generate a full Markdown pentest report from state."""
    s = state or state_manager.state
    target = s.get("ip", "Unknown")
    domains = s.get("domains", [])
    domain = domains[0] if domains else ""
    hostname = s.get("hostname", "")
    os_info = s.get("os", "Unknown")
    ports = s.get("ports", [])
    users = s.get("users", [])
    hashes = s.get("hashes", [])
    creds = s.get("credentials", [])
    shares = s.get("shares", [])
    directories = s.get("directories", [])
    vhosts = s.get("vhosts", [])
    notes = s.get("notes", [])
    flags = s.get("flags", {})
    history = s.get("scan_history", [])
    domain_info = s.get("domain_info", {})
    created = s.get("created_at", "")[:10]

    lines = []

    # Header
    lines.append(f"# Penetration Test Report: {target}")
    lines.append(f"**Date:** {created or datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    lines.append(f"| Target IP | {target} |")
    if hostname:
        lines.append(f"| Hostname | {hostname} |")
    if domains:
        lines.append(f"| Domains | {', '.join(domains)} |")
    if domain_info.get("dc_ip"):
        lines.append(f"| DC IP | {domain_info['dc_ip']} |")
    lines.append(f"| OS | {os_info or 'Unknown'} |")
    open_ports = [p for p in ports if p.get("state") == "open"]
    lines.append(f"| Open Ports | {len(open_ports)} |")
    lines.append(f"| Users Found | {len(users)} |")
    lines.append(f"| Credentials | {len(creds)} |")
    lines.append(f"| Hashes | {len(hashes)} |")
    lines.append("")

    # Flags
    local_flag = flags.get("local_txt", "")
    proof_flag = flags.get("proof_txt", "")
    if local_flag or proof_flag:
        lines.append("## Flags")
        lines.append("")
        if local_flag:
            lines.append(f"- **local.txt:** `{local_flag}`")
        if proof_flag:
            lines.append(f"- **proof.txt:** `{proof_flag}`")
        lines.append("")

    # Port Scan Results
    lines.append("## Port Scan Results")
    lines.append("")
    if open_ports:
        lines.append("| Port | Proto | Service | Version |")
        lines.append("|------|-------|---------|---------|")
        for p in sorted(open_ports, key=lambda x: x.get("port", 0)):
            lines.append(
                f"| {p.get('port', '')} | {p.get('protocol', 'tcp')} "
                f"| {p.get('service', '')} | {p.get('version', '')} |"
            )
    else:
        lines.append("*No ports discovered yet.*")
    lines.append("")

    # Users
    if users:
        lines.append("## Discovered Users")
        lines.append("")
        lines.append(f"**Total:** {len(users)}")
        lines.append("")
        for u in users:
            lines.append(f"- {u}")
        lines.append("")

    # Credentials
    if creds:
        lines.append("## Credentials")
        lines.append("")
        lines.append("| Username | Password | Service |")
        lines.append("|----------|----------|---------|")
        for c in creds:
            lines.append(
                f"| {c.get('username', '')} | {c.get('password', '')} "
                f"| {c.get('service', '')} |"
            )
        lines.append("")

    # Hashes
    if hashes:
        lines.append("## Hashes")
        lines.append("")
        lines.append("| Username | Hash |")
        lines.append("|----------|------|")
        for h in hashes:
            hash_val = h.get("hash", "")
            # Truncate long hashes for readability
            display_hash = hash_val[:60] + "..." if len(hash_val) > 60 else hash_val
            lines.append(f"| {h.get('username', '')} | `{display_hash}` |")
        lines.append("")

    # SMB Shares
    if shares:
        lines.append("## SMB Shares")
        lines.append("")
        lines.append("| Share | Permissions | Comment |")
        lines.append("|-------|-------------|---------|")
        for s_entry in shares:
            lines.append(
                f"| {s_entry.get('name', '')} | {s_entry.get('permissions', '')} "
                f"| {s_entry.get('comment', '')} |"
            )
        lines.append("")

    # Web Directories
    if directories:
        lines.append("## Web Directories")
        lines.append("")
        lines.append("| Path | Status |")
        lines.append("|------|--------|")
        for d in directories:
            lines.append(f"| {d.get('path', '')} | {d.get('status', '')} |")
        lines.append("")

    # Virtual Hosts
    if vhosts:
        lines.append("## Virtual Hosts")
        lines.append("")
        for v in vhosts:
            lines.append(f"- {v}")
        lines.append("")

    # Notes
    if notes:
        lines.append("## Notes")
        lines.append("")
        for n in notes:
            ts = n.get("timestamp", "")[:19]
            lines.append(f"- **[{ts}]** {n.get('note', '')}")
        lines.append("")

    # Attack Timeline
    if history:
        lines.append("## Attack Timeline")
        lines.append("")
        lines.append("| Time | Tool | Command |")
        lines.append("|------|------|---------|")
        for h in history:
            ts = h.get("timestamp", "")[:19]
            cmd = h.get("command", "")
            # Truncate long commands
            if len(cmd) > 80:
                cmd = cmd[:77] + "..."
            lines.append(f"| {ts} | {h.get('tool', '')} | `{cmd}` |")
        lines.append("")

    # Initial Foothold / Privesc placeholders
    lines.append("## Initial Foothold")
    lines.append("")
    lines.append("- **Vulnerability:**")
    lines.append("- **Exploit/Method:**")
    lines.append("- **Proof:**")
    lines.append("")
    lines.append("## Privilege Escalation")
    lines.append("")
    lines.append("- **Vector:**")
    lines.append("- **Method:**")
    lines.append("- **Proof:**")
    lines.append("")

    return "\n".join(lines)


def generate_html(state: dict | None = None) -> str:
    """Generate a simple HTML report from Markdown via Rich."""
    md = generate_markdown(state)
    # Simple Markdown-to-HTML conversion for tables and basic formatting
    html_lines = [
        "<!DOCTYPE html>",
        "<html><head>",
        "<meta charset='utf-8'>",
        f"<title>Pentest Report - {(state or state_manager.state).get('ip', 'Target')}</title>",
        "<style>",
        "body { font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto;"
        " padding: 0 20px; background: #1a1a2e; color: #e0e0e0; }",
        "h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }",
        "h2 { color: #00d4ff; margin-top: 30px; }",
        "table { border-collapse: collapse; width: 100%; margin: 10px 0; }",
        "th, td { border: 1px solid #444; padding: 8px 12px; text-align: left; }",
        "th { background: #16213e; color: #00d4ff; }",
        "tr:nth-child(even) { background: #1a1a2e; }",
        "tr:nth-child(odd) { background: #16213e; }",
        "code { background: #16213e; padding: 2px 6px; border-radius: 3px;"
        " color: #00ff88; font-size: 0.9em; }",
        "strong { color: #ffffff; }",
        "ul { padding-left: 20px; }",
        "li { margin: 4px 0; }",
        "</style>",
        "</head><body>",
    ]

    in_table = False
    header_row = False

    for line in md.split("\n"):
        stripped = line.strip()

        if not stripped:
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            html_lines.append("<br>")
            continue

        # Headers
        if stripped.startswith("# "):
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            html_lines.append(f"<h1>{_html_escape(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            html_lines.append(f"<h2>{_html_escape(stripped[3:])}</h2>")

        # Table rows
        elif stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            # Separator row
            if all(set(c) <= set("-: ") for c in cells):
                continue
            if not in_table:
                in_table = True
                header_row = True
                html_lines.append("<table><thead><tr>")
                for cell in cells:
                    html_lines.append(f"<th>{_html_inline(cell)}</th>")
                html_lines.append("</tr></thead><tbody>")
            else:
                html_lines.append("<tr>")
                for cell in cells:
                    html_lines.append(f"<td>{_html_inline(cell)}</td>")
                html_lines.append("</tr>")

        # List items
        elif stripped.startswith("- "):
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            html_lines.append(f"<li>{_html_inline(stripped[2:])}</li>")

        # Italic
        elif stripped.startswith("*") and stripped.endswith("*"):
            html_lines.append(f"<p><em>{_html_escape(stripped.strip('*'))}</em></p>")

        # Bold standalone
        elif stripped.startswith("**"):
            html_lines.append(f"<p>{_html_inline(stripped)}</p>")

        else:
            html_lines.append(f"<p>{_html_inline(stripped)}</p>")

    if in_table:
        html_lines.append("</tbody></table>")

    html_lines.append("</body></html>")
    return "\n".join(html_lines)


def generate_timeline(state: dict | None = None) -> str:
    """Generate just the attack timeline section."""
    s = state or state_manager.state
    history = s.get("scan_history", [])
    if not history:
        return "No scan history recorded."

    lines = ["## Attack Timeline", "", "| Time | Tool | Command |", "|------|------|---------|"]
    for h in history:
        ts = h.get("timestamp", "")[:19]
        cmd = h.get("command", "")
        if len(cmd) > 80:
            cmd = cmd[:77] + "..."
        lines.append(f"| {ts} | {h.get('tool', '')} | `{cmd}` |")
    return "\n".join(lines)


def export_csv(state: dict | None = None, section: str = "ports") -> str:
    """Export a state section as CSV."""
    s = state or state_manager.state
    output = io.StringIO()
    writer = csv.writer(output)

    if section == "ports":
        writer.writerow(["port", "protocol", "service", "version", "state"])
        for p in s.get("ports", []):
            writer.writerow([
                p.get("port", ""), p.get("protocol", ""), p.get("service", ""),
                p.get("version", ""), p.get("state", ""),
            ])
    elif section == "users":
        writer.writerow(["username"])
        for u in s.get("users", []):
            writer.writerow([u])
    elif section == "credentials":
        writer.writerow(["username", "password", "service"])
        for c in s.get("credentials", []):
            writer.writerow([c.get("username", ""), c.get("password", ""), c.get("service", "")])
    elif section == "hashes":
        writer.writerow(["username", "hash"])
        for h in s.get("hashes", []):
            writer.writerow([h.get("username", ""), h.get("hash", "")])
    elif section == "shares":
        writer.writerow(["name", "permissions", "comment"])
        for sh in s.get("shares", []):
            writer.writerow([sh.get("name", ""), sh.get("permissions", ""), sh.get("comment", "")])

    return output.getvalue()


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _html_inline(text: str) -> str:
    """Convert inline Markdown formatting to HTML."""
    import re
    text = _html_escape(text)
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # Inline code
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text
