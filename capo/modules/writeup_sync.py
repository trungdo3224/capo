"""Writeup sync manager — watches source folders and generates suggestion rules."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from capo import config
from capo.modules.writeup_parser import WriteupParser, WriteupProfile


# Well-known port → service tag for rule generation
_PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 389: "ldap", 443: "https",
    445: "smb", 464: "kpasswd", 593: "http-rpc-epmap",
    636: "ldaps", 1433: "mssql", 3268: "globalcatLDAP",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5985: "winrm", 8080: "http-alt", 8443: "https-alt",
}


@dataclass
class SyncResult:
    """Result of a sync operation."""
    parsed: int = 0
    skipped: int = 0
    rules_generated: int = 0
    errors: list[str] | None = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class WriteupSyncManager:
    """Manage writeup source folders, sync state, and rule generation."""

    def __init__(self):
        self._sources_file = config.CAPO_HOME / "writeup_sources.json"
        self._sync_file = config.CAPO_HOME / "writeup_sync.json"
        self._rules_dir = config.CAPO_HOME / "writeup_rules"
        self._parser = WriteupParser()

    # --- Source management ---

    def _load_sources(self) -> list[str]:
        if self._sources_file.exists():
            try:
                return json.loads(self._sources_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_sources(self, sources: list[str]):
        self._sources_file.parent.mkdir(parents=True, exist_ok=True)
        self._sources_file.write_text(
            json.dumps(sources, indent=2), encoding="utf-8"
        )

    def add_source(self, path: str) -> bool:
        """Register a writeup folder. Returns True if newly added."""
        resolved = str(Path(path).resolve())
        sources = self._load_sources()
        if resolved in sources:
            return False
        sources.append(resolved)
        self._save_sources(sources)
        return True

    def remove_source(self, path: str) -> bool:
        """Unregister a writeup folder. Returns True if found and removed."""
        resolved = str(Path(path).resolve())
        sources = self._load_sources()
        if resolved not in sources:
            return False
        sources.remove(resolved)
        self._save_sources(sources)
        return True

    def list_sources(self) -> list[dict]:
        """Return registered sources with stats."""
        sources = self._load_sources()
        sync_meta = self._load_sync_meta()
        result = []
        for src in sources:
            p = Path(src)
            md_count = len(list(p.rglob("*.md"))) if p.exists() else 0
            last_sync = sync_meta.get("sources", {}).get(src, {}).get("last_sync", "never")
            result.append({
                "path": src,
                "exists": p.exists(),
                "writeups": md_count,
                "last_sync": last_sync,
            })
        return result

    # --- Sync metadata ---

    def _load_sync_meta(self) -> dict:
        if self._sync_file.exists():
            try:
                return json.loads(self._sync_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"file_hashes": {}, "sources": {}}

    def _save_sync_meta(self, meta: dict):
        self._sync_file.parent.mkdir(parents=True, exist_ok=True)
        self._sync_file.write_text(
            json.dumps(meta, indent=2, default=str), encoding="utf-8"
        )

    # --- Core sync ---

    def sync(self) -> SyncResult:
        """Scan all registered sources, parse new/changed writeups, generate rules."""
        sources = self._load_sources()
        if not sources:
            return SyncResult()

        meta = self._load_sync_meta()
        result = SyncResult()
        all_profiles: list[WriteupProfile] = []

        for src_path in sources:
            folder = Path(src_path)
            if not folder.exists():
                result.errors.append(f"Source not found: {src_path}")
                continue

            md_files = self._scan_folder(folder)
            for md_file in md_files:
                file_key = str(md_file)
                try:
                    profile = self._parser.parse(md_file)
                except Exception as e:
                    result.errors.append(f"Parse error {md_file.name}: {e}")
                    continue

                old_hash = meta.get("file_hashes", {}).get(file_key, "")
                if profile.file_hash == old_hash:
                    result.skipped += 1
                    # Still collect for rule generation (rules dir might be cleared)
                    all_profiles.append(profile)
                    continue

                meta.setdefault("file_hashes", {})[file_key] = profile.file_hash
                all_profiles.append(profile)
                result.parsed += 1

            meta.setdefault("sources", {})[src_path] = {
                "last_sync": datetime.now(timezone.utc).isoformat(),
                "files": len(md_files),
            }

        # Generate rules from all profiles
        if all_profiles:
            total_rules = self._generate_all_rules(all_profiles)
            result.rules_generated = total_rules

        self._save_sync_meta(meta)
        return result

    def _scan_folder(self, folder: Path) -> list[Path]:
        """Find .md writeup files recursively, skip index/list files."""
        files = []
        for md in sorted(folder.rglob("*.md")):
            # Skip obvious index/list files
            name_lower = md.stem.lower()
            if any(skip in name_lower for skip in ("list", "index", "readme", "template")):
                continue
            # Skip very small files (< 500 bytes, likely stubs)
            if md.stat().st_size < 500:
                continue
            files.append(md)
        return files

    # --- Rule generation ---

    def _generate_all_rules(self, profiles: list[WriteupProfile]) -> int:
        """Generate YAML rule files from parsed writeup profiles."""
        self._rules_dir.mkdir(parents=True, exist_ok=True)

        all_rules: list[dict] = []
        for profile in profiles:
            rules = self._generate_rules(profile)
            all_rules.extend(rules)

        if not all_rules:
            return 0

        # Write single aggregated file
        out_path = self._rules_dir / "writeup_auto.yaml"
        header = (
            f"# Auto-generated from {len(profiles)} writeup(s)\n"
            f"# Last synced: {datetime.now(timezone.utc).isoformat()}\n"
            f"# Do not edit — regenerated by 'capo writeup sync'\n\n"
        )
        out_path.write_text(
            header + yaml.dump(all_rules, allow_unicode=True, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        return len(all_rules)

    def _generate_rules(self, profile: WriteupProfile) -> list[dict]:
        """Generate suggestion rules from a single writeup profile."""
        rules: list[dict] = []
        name = profile.name
        slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
        open_ports = [p["port"] for p in profile.ports if p.get("state") == "open"]

        if not open_ports and not profile.tools:
            return rules

        # --- Rule 1: Phase transition rules ---
        # Find any pair of phases that have commands (not just consecutive)
        phase_order = ["recon", "credential-access", "exploitation", "privilege-escalation", "post-exploitation"]
        populated = [(p, profile.phases[p]) for p in phase_order if profile.phases.get(p)]

        for idx in range(len(populated) - 1):
            from_phase, from_cmds = populated[idx]
            to_phase, to_cmds = populated[idx + 1]

            next_cmd = to_cmds[0]
            req_ports = open_ports[:4] if open_ports else []

            conditions: dict = {}
            if req_ports:
                conditions["require_ports"] = req_ports
            if to_phase in ("credential-access", "exploitation") and profile.platform == "windows":
                conditions.setdefault("require_state", []).append("has_domain")

            rule_id = f"writeup_{slug}_{from_phase.replace('-', '_')}_to_{to_phase.replace('-', '_')}"
            rules.append({
                "id": rule_id,
                "name": f"{name}: {from_phase} → {to_phase}",
                "description": f"HTB {name} transitioned from {from_phase} to {to_phase} using this technique.",
                "priority": "P2",
                "conditions": conditions,
                "command_template": _sanitize_command(next_cmd),
                "source_reference": f"writeup://{name}",
            })

        # --- Rule 2: Tool-specific AD suggestions ---
        ad_ports = {88, 389, 445, 135, 636, 3268, 5985}
        ad_tools = {"bloodhound-python", "certipy-ad", "bloodyAD", "impacket-dacledit",
                     "impacket-GetNPUsers", "impacket-GetUserSPNs", "impacket-secretsdump"}

        if profile.platform == "windows":
            matched_ad_ports = sorted(ad_ports.intersection(open_ports))[:3] if open_ports else []
            for tool in profile.tools:
                if tool not in ad_tools:
                    continue
                conditions = {}
                if matched_ad_ports:
                    conditions["require_ports"] = matched_ad_ports
                conditions["require_state"] = ["has_domain", "has_valid_user"]
                # Tools that need a password/hash
                if tool not in ("impacket-GetNPUsers",):
                    conditions["require_state"].append("has_valid_password")

                rules.append({
                    "id": f"writeup_{slug}_{tool.replace('-', '_')}",
                    "name": f"{name}: Use {tool}",
                    "description": f"HTB {name} used {tool} in this AD environment.",
                    "priority": "P2",
                    "conditions": conditions,
                    "command_template": f"capo search {tool}",
                    "source_reference": f"writeup://{name}",
                })

        # --- Rule 3: Per-tool command suggestions (any platform) ---
        # For writeups with >= 3 tools: suggest each tool's actual command
        if len(profile.tools) >= 3 and open_ports:
            for phase, cmds in profile.phases.items():
                for cmd in cmds[:3]:  # cap at 3 commands per phase
                    tools_in_cmd = self._parser._tools_in_text(cmd)
                    if not tools_in_cmd:
                        continue
                    tool = tools_in_cmd[0]
                    rule_id = f"writeup_{slug}_{phase.replace('-', '_')}_{tool.replace('-', '_')}"
                    # Skip if we already have a rule for this ID
                    if any(r["id"] == rule_id for r in rules):
                        continue
                    conditions = {"require_ports": open_ports[:3]}
                    rules.append({
                        "id": rule_id,
                        "name": f"{name}: {tool} ({phase})",
                        "description": f"HTB {name} used {tool} during {phase}.",
                        "priority": "P3",
                        "conditions": conditions,
                        "command_template": _sanitize_command(cmd),
                        "source_reference": f"writeup://{name}",
                    })

        return rules


def _sanitize_command(cmd: str) -> str:
    """Replace hardcoded IPs/domains in commands with {VAR} placeholders."""
    # Strip trailing backslash (multi-line continuation artifact)
    cmd = cmd.rstrip(" \\").strip()
    if not cmd:
        return cmd
    # Replace common IP patterns
    cmd = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "{IP}", cmd)
    # Replace common domain patterns in commands (after @, -d, etc.)
    cmd = re.sub(r"(?<=-d\s)\S+\.htb\b", "{DOMAIN}", cmd)
    cmd = re.sub(r"(?<=@)\S+\.htb\b", "{DOMAIN}", cmd)
    return cmd


# Global singleton
writeup_sync_manager = WriteupSyncManager()
