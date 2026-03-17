"""Tests for Git exposure: cheatsheet entries, methodology step, and trigger suggestions."""

from pathlib import Path
from unittest.mock import patch

import yaml


class TestGitCheatsheetEntries:
    """Verify all expected Git exposure entries exist in web_attacks.yaml."""

    @staticmethod
    def _load_web_attacks() -> list[dict]:
        yaml_path = (
            Path(__file__).parent.parent / "capo" / "core_cheatsheets" / "web_attacks.yaml"
        )
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        return data.get("commands", [])

    def _names(self) -> list[str]:
        return [e["name"] for e in self._load_web_attacks()]

    def test_git_detect_entry_exists(self):
        assert "git-detect" in self._names()

    def test_git_dump_entry_exists(self):
        assert "git-dump" in self._names()

    def test_git_dump_wget_fallback_exists(self):
        assert "git-dump-wget" in self._names()

    def test_git_log_entry_exists(self):
        assert "git-log" in self._names()

    def test_git_grep_secrets_entry_exists(self):
        assert "git-grep-secrets" in self._names()

    def test_git_trufflehog_entry_exists(self):
        assert "git-trufflehog" in self._names()

    def test_git_stash_list_entry_exists(self):
        assert "git-stash-list" in self._names()

    def test_git_entries_have_required_fields(self):
        git_entries = [e for e in self._load_web_attacks() if e.get("name", "").startswith("git-")]
        required = {"name", "description", "command", "tool", "tags", "os", "exam"}
        for entry in git_entries:
            missing = required - set(entry.keys())
            assert not missing, f"Entry '{entry['name']}' missing fields: {missing}"

    def test_git_entries_tagged_with_git(self):
        git_entries = [e for e in self._load_web_attacks() if e.get("name", "").startswith("git-")]
        for entry in git_entries:
            assert "git" in entry.get("tags", []), (
                f"Entry '{entry['name']}' missing 'git' tag"
            )

    def test_git_detect_command_checks_head_endpoint(self):
        entries = {e["name"]: e for e in self._load_web_attacks()}
        assert ".git/HEAD" in entries["git-detect"]["command"]

    def test_git_dump_command_uses_git_dumper(self):
        entries = {e["name"]: e for e in self._load_web_attacks()}
        assert "git-dumper" in entries["git-dump"]["command"]


class TestGitMethodologyStep:
    """Verify git-exposure step exists in web_app.yaml with correct structure."""

    @staticmethod
    def _load_web_app() -> dict:
        yaml_path = (
            Path(__file__).parent.parent / "capo" / "core_methodologies" / "web_app.yaml"
        )
        return yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

    def _steps_by_id(self) -> dict:
        data = self._load_web_app()
        return {s["id"]: s for s in data.get("steps", [])}

    def test_git_exposure_step_exists(self):
        assert "git-exposure" in self._steps_by_id()

    def test_git_exposure_phase_is_enumeration(self):
        step = self._steps_by_id()["git-exposure"]
        assert step.get("phase") == "enumeration"

    def test_git_exposure_has_commands(self):
        step = self._steps_by_id()["git-exposure"]
        assert len(step.get("commands", [])) >= 3

    def test_git_exposure_positioned_before_cms_scan(self):
        steps = self._load_web_app()["steps"]
        ids = [s["id"] for s in steps]
        assert "git-exposure" in ids
        assert "cms-scan" in ids
        assert ids.index("git-exposure") < ids.index("cms-scan")

    def test_git_exposure_positioned_after_dir_fuzz(self):
        steps = self._load_web_app()["steps"]
        ids = [s["id"] for s in steps]
        assert ids.index("dir-fuzz") < ids.index("git-exposure")

    def test_git_exposure_check_field_present(self):
        step = self._steps_by_id()["git-exposure"]
        assert "check" in step

    def test_git_exposure_commands_include_git_dumper(self):
        step = self._steps_by_id()["git-exposure"]
        cmds = "\n".join(step.get("commands", []))
        assert "git-dumper" in cmds

    def test_git_exposure_commands_include_secret_grep(self):
        step = self._steps_by_id()["git-exposure"]
        cmds = "\n".join(step.get("commands", []))
        assert "grep" in cmds or "trufflehog" in cmds


class TestGitTriggerSuggestion:
    """Verify .git discovery in dir fuzz results surfaces the enriched suggestion."""

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_git_suggestion_surfaced_when_dot_git_found(self, mock_state):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        mock_state.get.return_value = [
            {"path": "/.git", "status": 200},
            {"path": "/index.php", "status": 200},
        ]

        web = WebFuzzWrapper()
        suggestions = web.get_suggestions()
        titles = [s[0] for s in suggestions]
        assert any(".git" in t.lower() or "git" in t.lower() for t in titles), (
            f"Expected git-related suggestion, got: {titles}"
        )

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_git_suggestion_mentions_git_dumper_command(self, mock_state):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        mock_state.get.return_value = [{"path": "/.git", "status": 200}]

        web = WebFuzzWrapper()
        suggestions = web.get_suggestions()
        all_text = " ".join(s[0] + " " + s[1] for s in suggestions)
        assert "git-dumper" in all_text

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_no_git_suggestion_without_git_path(self, mock_state):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        mock_state.get.return_value = [
            {"path": "/wp-admin", "status": 200},
            {"path": "/admin", "status": 200},
        ]

        web = WebFuzzWrapper()
        suggestions = web.get_suggestions()
        titles = [s[0] for s in suggestions]
        assert not any(".git" in t.lower() for t in titles)
