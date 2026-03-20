"""Parse Obsidian / Markdown writeups into structured attack patterns."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path


# Tools we recognise in code blocks
KNOWN_TOOLS: set[str] = {
    "nmap", "nxc", "netexec", "crackmapexec",
    "impacket-GetNPUsers", "impacket-secretsdump", "impacket-psexec",
    "impacket-wmiexec", "impacket-dacledit", "impacket-getST",
    "impacket-GetUserSPNs", "impacket-ntlmrelayx", "impacket-ticketer",
    "certipy", "certipy-ad", "bloodhound-python", "bloodyAD",
    "evil-winrm", "kerbrute", "hashcat", "john",
    "ffuf", "gobuster", "feroxbuster", "nikto", "whatweb",
    "wpscan", "sqlmap", "hydra", "enum4linux-ng", "enum4linux",
    "ssh", "smbclient", "rpcclient", "ldapsearch",
    "curl", "wget", "python3", "searchsploit",
    "responder", "rubeus", "mimikatz", "wfuzz",
    "smbmap", "crackmapexec", "snaffler",
    "linpeas", "winpeas", "winPEASx64",
}

# Regex that extracts the first token of a command line (after optional prompt)
# Handles: "$ cmd", "└─$ cmd", "skdu@kali:~$ cmd", "sudo cmd", plain "cmd"
_PROMPT_RE = re.compile(
    r"^\s*"
    r"(?:[┌└│─\(\)@\w.*~\[\]/\\:\-]* ?\$ )?"  # optional shell prompt ending with "$ "
    r"(?:sudo\s+)?"
    r"(\S+)"
)
# Legacy alias kept for clarity
_CMD_FIRST_TOKEN_RE = _PROMPT_RE

# Nmap port table line: e.g. "80/tcp  open  http"
_NMAP_PORT_RE = re.compile(
    r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)"
)

# Section header patterns for phase mapping
PHASE_PATTERNS: dict[str, list[str]] = {
    "recon": ["enumeration", "scanning", "reconnaissance", "nmap", "port scan", "recon", "target information"],
    "credential-access": ["cracking", "hash", "password", "credential", "brute", "spray", "initial credential"],
    "exploitation": ["exploit", "foothold", "initial access", "rce", "shell", "reverse"],
    "privilege-escalation": ["privilege", "escalation", "privesc", "root", "admin", "lateral"],
    "post-exploitation": ["dump", "loot", "flag", "proof", "persistence", "dcsync"],
}

# Windows / AD indicators
_WINDOWS_INDICATORS = {
    "evil-winrm", "kerberos", "ldap", "smb", "active directory", "bloodhound",
    "winrm", "dcsync", "ntlm", "mimikatz", "rubeus", "certipy",
    "adcs", "domain controller", "ntds", "kerberoast", "asrep",
}

_LINUX_INDICATORS = {
    "linpeas", "suid", "sudo", "cron", "/bin/bash", "/etc/shadow",
    "ssh", "apache", "nginx", "php", "/var/www",
}


@dataclass
class CodeBlock:
    """A code block extracted from markdown, tagged with its surrounding phase."""
    content: str
    phase: str = ""
    tools: list[str] = field(default_factory=list)


@dataclass
class WriteupProfile:
    """Structured representation of a parsed writeup."""
    name: str
    source_path: str
    platform: str  # "windows", "linux", "any"
    tools: list[str] = field(default_factory=list)
    ports: list[dict] = field(default_factory=list)
    phases: dict[str, list[str]] = field(default_factory=dict)
    attack_chain: list[str] = field(default_factory=list)
    file_hash: str = ""


class WriteupParser:
    """Parse Obsidian markdown writeups into structured attack patterns."""

    def parse(self, md_path: Path) -> WriteupProfile:
        """Parse a single markdown writeup file."""
        content = md_path.read_text(encoding="utf-8", errors="replace")
        file_hash = hashlib.md5(content.encode()).hexdigest()

        name = self._extract_name(md_path, content)
        code_blocks = self._extract_code_blocks(content)
        tools = self._detect_tools(code_blocks)
        ports = self._extract_ports(content)
        platform = self._detect_platform(content)
        phases = self._map_phases(content, code_blocks)
        chain = self._build_attack_chain(phases)

        return WriteupProfile(
            name=name,
            source_path=str(md_path),
            platform=platform,
            tools=sorted(tools),
            ports=ports,
            phases={k: v for k, v in phases.items() if v},
            attack_chain=chain,
            file_hash=file_hash,
        )

    def _extract_name(self, md_path: Path, content: str) -> str:
        """Extract box name from headers, parent folder, or filename."""
        # Collect all phase keywords to reject headers that are phase names
        all_phase_kw = set()
        for kws in PHASE_PATTERNS.values():
            all_phase_kw.update(kws)
        # Extra reject words
        reject_words = all_phase_kw | {
            "final result", "attack chain", "summary", "root cause",
            "key technical", "authors", "machine info", "initial credential",
            "full attack", "target information",
        }

        def _is_box_name(text: str) -> bool:
            """Check if header text looks like a box name, not a section title."""
            lower = text.lower().rstrip(":").strip()
            if any(rw in lower for rw in reject_words):
                return False
            # Box names are typically short (1-3 words)
            if len(lower.split()) > 5:
                return False
            return bool(lower)

        def _clean_header(raw: str) -> str:
            cleaned = re.sub(
                r"\s*[—–\-]\s*(HTB|HackTheBox|TryHackMe|THM|Write\s*up).*$",
                "", raw, flags=re.IGNORECASE,
            )
            return cleaned.rstrip(":").strip()

        # Try H1 headers first, then H2
        for level in (r"#\s+", r"##\s+"):
            for m in re.finditer(rf"^{level}(.+)$", content, re.MULTILINE):
                cleaned = _clean_header(m.group(1))
                if cleaned and len(cleaned) < 50 and _is_box_name(cleaned):
                    return cleaned

        # Fall back to parent directory name (Obsidian structure: Forest/Write up.md)
        parent = md_path.parent.name
        skip_parents = {"linux", "windows", "windows & ad", "writeups", "htb", "thm"}
        if parent.lower() not in skip_parents and len(parent) < 50:
            return parent

        return md_path.stem

    def _extract_code_blocks(self, content: str) -> list[CodeBlock]:
        """Extract fenced code blocks and inline command patterns."""
        blocks: list[CodeBlock] = []

        # Fenced code blocks (```...```)
        for m in re.finditer(r"```[^\n]*\n(.*?)```", content, re.DOTALL):
            block_text = m.group(1).strip()
            if block_text:
                tools = self._tools_in_text(block_text)
                blocks.append(CodeBlock(content=block_text, tools=tools))

        # Inline backtick commands (e.g. `nmap -p- 10.10.10.1`)
        # Also matches Obsidian patterns like **Command:** `$ certipy-ad find ...`
        # [^\n`] prevents matching across lines (avoids misaligned backtick spans)
        for m in re.finditer(r"`([^\n`]{10,})`", content):
            line = m.group(1).strip()
            # Strip leading $ prompt from inline commands
            line = re.sub(r"^\$\s+", "", line)
            tools = self._tools_in_text(line)
            if tools:
                blocks.append(CodeBlock(content=line, tools=tools))

        return blocks

    def _tools_in_text(self, text: str) -> list[str]:
        """Find known tools referenced in a text block."""
        found = []
        for line in text.splitlines():
            # Skip output lines (common nmap/smb output patterns, blank lines)
            stripped = line.strip()
            if not stripped or stripped.startswith("|") or stripped.startswith("Service Info:"):
                continue

            match = _PROMPT_RE.match(line)
            if not match:
                continue
            first = match.group(1)
            # Check exact match and basename
            name = Path(first).name if "/" in first else first
            # Strip leading ./ or .\
            name = name.lstrip("./\\")
            if name in KNOWN_TOOLS:
                found.append(name)
            # Check impacket-* pattern
            elif name.startswith("impacket-"):
                found.append(name)
        return found

    def _detect_tools(self, code_blocks: list[CodeBlock]) -> set[str]:
        """Collect all unique tools across all code blocks."""
        tools: set[str] = set()
        for block in code_blocks:
            tools.update(block.tools)
        return tools

    def _extract_ports(self, content: str) -> list[dict]:
        """Extract ports from nmap-style output tables in the writeup."""
        ports: list[dict] = []
        seen: set[tuple[int, str]] = set()
        for m in _NMAP_PORT_RE.finditer(content):
            port_num = int(m.group(1))
            proto = m.group(2)
            state = m.group(3)
            service = m.group(4)
            key = (port_num, proto)
            if key not in seen:
                seen.add(key)
                ports.append({
                    "port": port_num,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                })
        return sorted(ports, key=lambda p: p["port"])

    def _detect_platform(self, content: str) -> str:
        """Detect Windows/Linux from content keywords."""
        lower = content.lower()
        win_score = sum(1 for kw in _WINDOWS_INDICATORS if kw in lower)
        lin_score = sum(1 for kw in _LINUX_INDICATORS if kw in lower)
        if win_score > lin_score + 2:
            return "windows"
        if lin_score > win_score + 2:
            return "linux"
        return "windows" if win_score >= lin_score else "linux"

    def _map_phases(self, content: str, code_blocks: list[CodeBlock]) -> dict[str, list[str]]:
        """Map section headers to attack phases and assign commands."""
        phases: dict[str, list[str]] = {k: [] for k in PHASE_PATTERNS}

        # Split content into sections by headers (h1-h4)
        sections = re.split(r"^(#{1,4}\s+.+)$", content, flags=re.MULTILINE)

        current_phase = "recon"
        for section in sections:
            # Check if this is a header
            header_match = re.match(r"^#{1,4}\s+(.+)$", section)
            if header_match:
                header = header_match.group(1).lower().rstrip(":").strip()
                for phase, keywords in PHASE_PATTERNS.items():
                    if any(kw in header for kw in keywords):
                        current_phase = phase
                        break
                continue

            # Extract commands from fenced code blocks in this section
            for m in re.finditer(r"```[^\n]*\n(.*?)```", section, re.DOTALL):
                block = m.group(1).strip()
                # Join backslash-continuation lines before splitting
                joined = re.sub(r"\\\s*\n\s*", " ", block)
                for line in joined.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("//"):
                        continue
                    tools = self._tools_in_text(line)
                    if tools:
                        phases[current_phase].append(self._clean_command(line))

            # Extract commands from inline backticks (Obsidian pattern)
            for m in re.finditer(r"`([^\n`]{10,})`", section):
                line = m.group(1).strip()
                line = re.sub(r"^\$\s+", "", line)
                tools = self._tools_in_text(line)
                if tools:
                    phases[current_phase].append(line)

        # Tag code blocks with phases
        for block in code_blocks:
            if not block.phase:
                block.phase = current_phase

        return phases

    @staticmethod
    def _clean_command(line: str) -> str:
        """Strip shell prompts and leading whitespace from a command line."""
        # Remove common prompt patterns: "└─$ ", "skdu@kali:~$ ", "$ "
        cleaned = re.sub(
            r"^[┌└│─\(\)@\w.*~\[\]/\\:\-]* ?\$ ",
            "",
            line.strip(),
        )
        return cleaned.strip()

    def _build_attack_chain(self, phases: dict[str, list[str]]) -> list[str]:
        """Build ordered attack chain summary from phases."""
        chain: list[str] = []
        phase_order = ["recon", "credential-access", "exploitation", "privilege-escalation", "post-exploitation"]
        for phase in phase_order:
            cmds = phases.get(phase, [])
            if cmds:
                # Take first command as representative
                tools_in_phase = set()
                for cmd in cmds:
                    found = self._tools_in_text(cmd)
                    tools_in_phase.update(found)
                if tools_in_phase:
                    chain.append(f"{phase}: {', '.join(sorted(tools_in_phase))}")
        return chain
