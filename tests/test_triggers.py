"""Tests for custom trigger loading & merging."""

import json

import pytest
import yaml

from capo.modules.triggers import (
    PORT_TRIGGERS,
    _inject_vars,
    _load_custom_triggers,
    get_merged_triggers,
    init_custom_triggers,
)


@pytest.fixture
def custom_triggers_file(tmp_path, monkeypatch):
    """Point CUSTOM_TRIGGERS_FILE to a temp file."""
    f = tmp_path / "custom_triggers.yaml"
    monkeypatch.setattr("capo.modules.triggers.CUSTOM_TRIGGERS_FILE", f)
    return f


class TestLoadCustomTriggers:
    def test_no_file(self, custom_triggers_file):
        """Returns empty dict when file doesn't exist."""
        assert _load_custom_triggers() == {}

    def test_valid_yaml(self, custom_triggers_file):
        """Loads well-formed custom triggers."""
        data = {
            "triggers": {
                9090: [
                    {"title": "Cockpit", "suggestions": ["browse http://{IP}:9090"]},
                ],
            },
        }
        custom_triggers_file.write_text(yaml.dump(data), encoding="utf-8")
        result = _load_custom_triggers()
        assert 9090 in result
        assert result[9090][0]["title"] == "Cockpit"

    def test_malformed_yaml(self, custom_triggers_file):
        """Handles malformed YAML gracefully."""
        custom_triggers_file.write_text("{{invalid yaml", encoding="utf-8")
        assert _load_custom_triggers() == {}

    def test_bad_structure(self, custom_triggers_file):
        """Handles non-dict top level."""
        custom_triggers_file.write_text("- item1\n- item2\n", encoding="utf-8")
        assert _load_custom_triggers() == {}

    def test_missing_title(self, custom_triggers_file):
        """Skips entries without required fields."""
        data = {
            "triggers": {
                9090: [
                    {"suggestions": ["cmd"]},  # missing title
                    {"title": "Valid", "suggestions": ["cmd"]},
                ],
            },
        }
        custom_triggers_file.write_text(yaml.dump(data), encoding="utf-8")
        result = _load_custom_triggers()
        assert len(result[9090]) == 1
        assert result[9090][0]["title"] == "Valid"

    def test_string_port_keys(self, custom_triggers_file):
        """Handles string port keys from YAML."""
        data = {
            "triggers": {
                "8888": [
                    {"title": "Custom", "suggestions": ["cmd"]},
                ],
            },
        }
        custom_triggers_file.write_text(yaml.dump(data), encoding="utf-8")
        result = _load_custom_triggers()
        assert 8888 in result


class TestMergedTriggers:
    def test_no_custom(self, custom_triggers_file):
        """Merged triggers equal built-in when no custom file."""
        merged = get_merged_triggers()
        assert merged.keys() == PORT_TRIGGERS.keys()

    def test_custom_appends(self, custom_triggers_file):
        """Custom entries append to existing port triggers."""
        data = {
            "triggers": {
                22: [  # port 22 already has built-in triggers
                    {"title": "My SSH check", "suggestions": ["my-ssh-tool {IP}"]},
                ],
            },
        }
        custom_triggers_file.write_text(yaml.dump(data), encoding="utf-8")
        merged = get_merged_triggers()
        titles = [t["title"] for t in merged[22]]
        assert "SSH detected" in titles  # built-in preserved
        assert "My SSH check" in titles  # custom appended

    def test_custom_new_port(self, custom_triggers_file):
        """Custom entries add a new port not in built-in."""
        data = {
            "triggers": {
                9999: [
                    {"title": "Custom service", "suggestions": ["check {IP}"]},
                ],
            },
        }
        custom_triggers_file.write_text(yaml.dump(data), encoding="utf-8")
        merged = get_merged_triggers()
        assert 9999 in merged


class TestInitCustomTriggers:
    def test_creates_file(self, custom_triggers_file):
        """Creates the template file."""
        assert init_custom_triggers() is True
        assert custom_triggers_file.exists()
        content = yaml.safe_load(custom_triggers_file.read_text())
        # Template has commented-out triggers, so parsed value is None or has triggers key
        assert content is None or "triggers" in content or content == {}

    def test_no_overwrite(self, custom_triggers_file):
        """Does not overwrite existing file."""
        custom_triggers_file.write_text("existing", encoding="utf-8")
        assert init_custom_triggers() is False
        assert custom_triggers_file.read_text() == "existing"


class TestInjectVars:
    def test_var_replacement(self, monkeypatch):
        """Replaces known {VAR} placeholders."""
        monkeypatch.setattr("capo.modules.triggers.state_manager.get_var",
                            lambda v: {"IP": "10.10.10.1", "DOMAIN": "test.local"}.get(v))
        result = _inject_vars("nxc smb {IP} -d {DOMAIN}")
        assert result == "nxc smb 10.10.10.1 -d test.local"

    def test_unknown_var_kept(self, monkeypatch):
        """Unknown variables are left as-is."""
        monkeypatch.setattr("capo.modules.triggers.state_manager.get_var",
                            lambda v: None)
        result = _inject_vars("connect {IP}:{PORT}")
        assert "{IP}" in result
        assert "{PORT}" in result
