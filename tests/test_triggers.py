"""Tests for custom trigger loading & merging."""

import pytest
import yaml

from capo.modules.triggers import (
    PORT_TRIGGERS,
    _load_custom_triggers,
    get_merged_triggers,
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
