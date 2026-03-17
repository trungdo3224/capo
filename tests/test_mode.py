"""Tests for the ModeManager — OSCP/CPTS mode switching and restrictions."""

from unittest.mock import patch

import pytest


@pytest.fixture
def capo_home_mode(tmp_path):
    """Override CAPO_HOME for mode tests."""
    home = tmp_path / ".capo"
    home.mkdir()
    return home


@pytest.fixture
def manager(capo_home_mode):
    """Create a fresh ModeManager with patched CAPO_HOME."""
    with patch("capo.modules.mode.CAPO_HOME", capo_home_mode), \
         patch("capo.config.CAPO_HOME", capo_home_mode):
        from capo.modules.mode import ModeManager
        mgr = ModeManager()
        return mgr


class TestDefaultMode:
    """Default mode should be OSCP."""

    def test_default_is_oscp(self, manager):
        assert manager.mode == "oscp"
        assert manager.is_oscp is True
        assert manager.is_cpts is False


class TestModeSwitching:
    """Tests for switching between OSCP and CPTS modes."""

    def test_switch_to_cpts(self, manager, capo_home_mode):
        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode):
            manager.set_mode("cpts")
            assert manager.mode == "cpts"
            assert manager.is_cpts is True

    def test_switch_to_oscp(self, manager, capo_home_mode):
        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode):
            manager.set_mode("cpts")
            manager.set_mode("oscp")
            assert manager.is_oscp is True

    def test_case_insensitive(self, manager, capo_home_mode):
        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode):
            manager.set_mode("CPTS")
            assert manager.is_cpts is True

    def test_invalid_mode_ignored(self, manager, capo_home_mode):
        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode):
            manager.set_mode("invalid")
            # Should remain oscp (default)
            assert manager.is_oscp is True


class TestOSCPRestrictions:
    """Tests for OSCP tool restrictions."""

    def test_nmap_allowed_in_oscp(self, manager):
        assert manager.check_tool_allowed("nmap") is True

    def test_ffuf_allowed_in_oscp(self, manager):
        assert manager.check_tool_allowed("ffuf") is True

    def test_sqlmap_blocked_in_oscp(self, manager):
        assert manager.check_tool_allowed("sqlmap") is False

    def test_autosploit_blocked_in_oscp(self, manager):
        assert manager.check_tool_allowed("autosploit") is False

    def test_metasploit_requires_marking(self, manager):
        # First check returns False (not yet marked for use)
        assert manager.check_tool_allowed("metasploit") is False


class TestCPTSMode:
    """CPTS mode should allow all tools."""

    def test_cpts_allows_all(self, manager, capo_home_mode):
        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode):
            manager.set_mode("cpts")
            assert manager.check_tool_allowed("sqlmap") is True
            assert manager.check_tool_allowed("metasploit") is True
            assert manager.check_tool_allowed("nmap") is True


class TestAIFeatures:
    """Tests for AI/LLM feature gating."""

    def test_no_ai_in_oscp(self, manager):
        assert manager.can_use_ai() is False

    def test_ai_in_cpts(self, manager, capo_home_mode):
        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode):
            manager.set_mode("cpts")
            assert manager.can_use_ai() is True


class TestMetasploitTracking:
    """Tests for Metasploit single-use tracking in OSCP."""

    def test_mark_metasploit_used(self, manager):
        manager.mark_metasploit_used()
        assert manager._metasploit_used is True

    def test_get_mode_info(self, manager):
        info = manager.get_mode_info()
        assert info["mode"] == "OSCP"
        assert info["ai_enabled"] is False
        assert info["metasploit_used"] is False
        assert len(info["restrictions"]) > 0


class TestModePersistence:
    """Tests for mode persistence to file."""

    def test_mode_saved_to_file(self, manager, capo_home_mode):
        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode):
            manager.set_mode("cpts")
            mode_file = capo_home_mode / ".current_mode"
            assert mode_file.exists()
            assert mode_file.read_text(encoding="utf-8").strip() == "cpts"

    def test_mode_loaded_from_file(self, capo_home_mode):
        """A new ModeManager should load previously saved mode."""
        mode_file = capo_home_mode / ".current_mode"
        mode_file.write_text("cpts", encoding="utf-8")

        with patch("capo.modules.mode.CAPO_HOME", capo_home_mode), \
             patch("capo.config.CAPO_HOME", capo_home_mode):
            from capo.modules.mode import ModeManager
            mgr = ModeManager()
            assert mgr.mode == "cpts"
