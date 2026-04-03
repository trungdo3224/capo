"""CLI integration tests using Typer CliRunner."""

import pytest
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_capo(tmp_path, monkeypatch):
    """Isolate every test: point CAPO_HOME to tmp_path and reset state."""
    import capo.config
    monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)
    monkeypatch.setattr(capo.config, "WORKSPACES_DIR", tmp_path / "workspaces")
    monkeypatch.setattr(capo.config, "CUSTOM_CHEATSHEETS_DIR", tmp_path / "custom_cheatsheets")
    monkeypatch.setattr(capo.config, "CUSTOM_METHODOLOGIES_DIR", tmp_path / "custom_methodologies")
    monkeypatch.setattr(capo.config, "CUSTOM_TRIGGERS_FILE", tmp_path / "custom_triggers.yaml")

    from capo.state import state_manager
    state_manager._target = None
    state_manager._workspace = None
    state_manager._state = {}


def _app():
    """Import app fresh to pick up monkeypatched config."""
    from capo.cli import app
    return app


class TestGlobalOptions:
    """Test global CLI options."""

    def test_version_flag(self):
        result = runner.invoke(_app(), ["--version"])
        assert result.exit_code == 0
        assert "C.A.P.O v" in result.output

    def test_help_lists_all_groups(self):
        result = runner.invoke(_app(), ["--help"])
        assert result.exit_code == 0
        for group in ("target", "scan", "nxc", "brute", "web", "state",
                      "mode", "report", "triggers", "methodology"):
            assert group in result.output

    def test_help_lists_standalone_commands(self):
        result = runner.invoke(_app(), ["--help"])
        assert result.exit_code == 0
        for cmd in ("search", "tools", "suggest"):
            assert cmd in result.output


class TestTargetCommands:
    """Test target management commands."""

    def test_target_set_help(self):
        result = runner.invoke(_app(), ["target", "set", "--help"])
        assert result.exit_code == 0
        assert "IP" in result.output

    def test_target_set_creates_workspace(self, tmp_path):
        (tmp_path / "workspaces").mkdir(exist_ok=True)
        result = runner.invoke(_app(), ["target", "set", "10.10.10.100"])
        assert result.exit_code == 0
        assert "10.10.10.100" in result.output

    def test_state_show_no_target(self):
        result = runner.invoke(_app(), ["state", "show"])
        assert result.exit_code == 1


class TestSubcommandHelp:
    """Test that all subcommands respond to --help."""

    @pytest.mark.parametrize("group", [
        "scan", "nxc", "brute", "web", "state",
        "mode", "report", "triggers", "methodology",
    ])
    def test_subcommand_help(self, group):
        result = runner.invoke(_app(), [group, "--help"])
        assert result.exit_code == 0

    def test_scan_quick_has_dry_run(self):
        result = runner.invoke(_app(), ["scan", "quick", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.output


class TestErrorHandling:
    """Test CLI error handling."""

    def test_state_show_without_target(self):
        result = runner.invoke(_app(), ["state", "show"])
        assert result.exit_code == 1

    def test_suggest_without_target(self):
        result = runner.invoke(_app(), ["suggest"])
        assert result.exit_code == 1
