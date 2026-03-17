"""Tests for the CheatsheetEngine — YAML loading, search, variable injection."""

from unittest.mock import patch

import pytest
import yaml


@pytest.fixture
def cheatsheet_dir(tmp_path):
    """Create a temp directory with sample cheatsheet YAML files."""
    cs_dir = tmp_path / "cheatsheets"
    cs_dir.mkdir()

    # Create a sample cheatsheet file
    recon_data = {
        "category": "recon",
        "commands": [
            {
                "name": "nmap-quick",
                "description": "Quick all-ports TCP scan",
                "command": "nmap -Pn -p- --min-rate 5000 -T4 {IP}",
                "tags": ["nmap", "recon", "ports"],
                "tool": "nmap",
                "exam": ["oscp", "cpts"],
            },
            {
                "name": "nmap-vuln",
                "description": "Vulnerability scan with NSE scripts",
                "command": "nmap --script vuln -p {PORTS} {IP}",
                "tags": ["nmap", "vuln"],
                "tool": "nmap",
                "exam": ["oscp"],
            },
            {
                "name": "ffuf-dirs",
                "description": "Directory fuzzing with ffuf",
                "command": "ffuf -u http://{IP}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
                "tags": ["ffuf", "web", "fuzzing"],
                "tool": "ffuf",
                "exam": ["oscp", "cpts"],
            },
        ],
    }

    ad_data = {
        "category": "active-directory",
        "commands": [
            {
                "name": "kerbrute-userenum",
                "description": "Enumerate AD users via Kerberos",
                "command": "kerbrute userenum -d {DOMAIN} --dc {DC_IP} users.txt",
                "tags": ["kerberos", "ad", "enum"],
                "tool": "kerbrute",
                "exam": ["oscp", "cpts"],
            },
        ],
    }

    (cs_dir / "recon.yaml").write_text(yaml.dump(recon_data), encoding="utf-8")
    (cs_dir / "active_directory.yaml").write_text(yaml.dump(ad_data), encoding="utf-8")

    return cs_dir


@pytest.fixture
def engine(cheatsheet_dir):
    """Create a CheatsheetEngine loading from temp dir."""
    with patch("capo.modules.cheatsheet.engine.CORE_CHEATSHEETS_DIR", cheatsheet_dir), \
         patch("capo.modules.cheatsheet.engine.CUSTOM_CHEATSHEETS_DIR", cheatsheet_dir / "custom"):
        from capo.modules.cheatsheet.engine import CheatsheetEngine
        eng = CheatsheetEngine()
        eng.load_all()
        return eng


class TestLoading:
    """Tests for YAML loading and merging."""

    def test_loads_all_entries(self, engine):
        assert len(engine.entries) == 4

    def test_loads_categories(self, engine):
        cats = engine.categories
        assert "recon" in cats
        assert "active-directory" in cats

    def test_entry_has_correct_fields(self, engine):
        entry = engine.get_entry("nmap-quick")
        assert entry is not None
        assert entry.name == "nmap-quick"
        assert "nmap" in entry.tags
        assert entry.tool == "nmap"
        assert "{IP}" in entry.command


class TestSearch:
    """Tests for exact and fuzzy search."""

    def test_search_by_tool(self, engine):
        results = engine.search("nmap")
        names = [r.name for r in results]
        assert "nmap-quick" in names
        assert "nmap-vuln" in names

    def test_search_by_tag(self, engine):
        results = engine.get_by_tag("web")
        assert len(results) == 1
        assert results[0].name == "ffuf-dirs"

    def test_search_no_results(self, engine):
        results = engine.search("nonexistent-tool-xyz")
        assert len(results) == 0

    def test_fuzzy_search(self, engine):
        results = engine.fuzzy_search("kerberos enumeration")
        names = [r.name for r in results]
        assert "kerbrute-userenum" in names

    def test_get_by_category(self, engine):
        results = engine.get_by_category("recon")
        assert len(results) == 3

    def test_get_for_exam_oscp(self, engine):
        results = engine.get_for_exam("oscp")
        assert len(results) == 4  # all have oscp

    def test_get_for_exam_cpts(self, engine):
        results = engine.get_for_exam("cpts")
        # nmap-vuln is oscp-only
        names = [r.name for r in results]
        assert "nmap-vuln" not in names


class TestVariableInjection:
    """Tests for template variable injection from state."""

    @patch("capo.modules.cheatsheet.engine.state_manager")
    def test_injects_ip(self, mock_state, engine):
        mock_state.get_var.side_effect = lambda var: {
            "IP": "10.10.10.100",
        }.get(var, "")

        entry = engine.get_entry("nmap-quick")
        cmd = entry.inject_variables()
        assert "10.10.10.100" in cmd
        assert "{IP}" not in cmd

    @patch("capo.modules.cheatsheet.engine.state_manager")
    def test_injects_domain_and_dc(self, mock_state, engine):
        mock_state.get_var.side_effect = lambda var: {
            "DOMAIN": "corp.local",
            "DC_IP": "10.10.10.1",
        }.get(var, "")

        entry = engine.get_entry("kerbrute-userenum")
        cmd = entry.inject_variables()
        assert "corp.local" in cmd
        assert "10.10.10.1" in cmd

    @patch("capo.modules.cheatsheet.engine.state_manager")
    def test_unresolved_vars_remain(self, mock_state, engine):
        """Variables with no value in state stay as {VAR} placeholders."""
        mock_state.get_var.return_value = ""

        entry = engine.get_entry("nmap-quick")
        cmd = entry.inject_variables()
        # {IP} had no value → stays as-is
        assert "{IP}" in cmd


class TestCustomOverride:
    """Test that custom cheatsheets override core ones."""

    def test_custom_overrides_core(self, cheatsheet_dir):
        # Create a custom directory with an override for nmap-quick
        custom_dir = cheatsheet_dir / "custom"
        custom_dir.mkdir()

        override_data = {
            "category": "recon",
            "commands": [
                {
                    "name": "nmap-quick",
                    "description": "CUSTOM quick scan",
                    "command": "nmap -Pn -p- --min-rate 10000 {IP}",
                    "tags": ["nmap", "custom"],
                    "tool": "nmap",
                    "exam": ["oscp"],
                },
            ],
        }
        (custom_dir / "recon_override.yaml").write_text(yaml.dump(override_data), encoding="utf-8")

        with patch("capo.modules.cheatsheet.engine.CORE_CHEATSHEETS_DIR", cheatsheet_dir), \
             patch("capo.modules.cheatsheet.engine.CUSTOM_CHEATSHEETS_DIR", custom_dir):
            from capo.modules.cheatsheet.engine import CheatsheetEngine
            eng = CheatsheetEngine()
            eng.load_all()

            entry = eng.get_entry("nmap-quick")
            assert "CUSTOM" in entry.description
            assert "--min-rate 10000" in entry.command
