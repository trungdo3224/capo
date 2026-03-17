"""Tests for methodology engine — loading, tracking, auto-check."""

import json
from pathlib import Path

import pytest
import yaml

from capo.modules.methodology import Methodology, MethodologyEngine, MethodologyStep


@pytest.fixture
def meth_dirs(tmp_path, monkeypatch):
    """Create temp core + custom methodology directories."""
    core = tmp_path / "core"
    custom = tmp_path / "custom"
    core.mkdir()
    custom.mkdir()
    monkeypatch.setattr("capo.modules.methodology.CORE_METHODOLOGIES_DIR", core)
    monkeypatch.setattr("capo.modules.methodology.CUSTOM_METHODOLOGIES_DIR", custom)
    return core, custom


@pytest.fixture
def sample_methodology_yaml():
    """Return a minimal methodology dict."""
    return {
        "name": "test-meth",
        "display_name": "Test Methodology",
        "description": "A test methodology",
        "applicable_when": {"ports": [22, 80]},
        "steps": [
            {
                "id": "step-1",
                "name": "First Step",
                "phase": "recon",
                "description": "Do the first thing",
                "commands": ["cmd1 {IP}", "cmd2"],
                "check": {"ports_min": 1},
            },
            {
                "id": "step-2",
                "name": "Second Step",
                "phase": "exploit",
                "description": "Do the second thing",
                "commands": ["cmd3"],
                "check": {"users_min": 1},
            },
            {
                "id": "step-3",
                "name": "Third Step",
                "phase": "post",
                "description": "Final step",
                "commands": ["cmd4"],
                "check": {},
            },
        ],
    }


@pytest.fixture
def engine_with_meth(meth_dirs, sample_methodology_yaml):
    """Create engine with a loaded methodology."""
    core, _ = meth_dirs
    (core / "test.yaml").write_text(yaml.dump(sample_methodology_yaml), encoding="utf-8")
    engine = MethodologyEngine()
    engine.load_all()
    return engine


class TestMethodologyStep:
    def test_auto_complete_empty_check(self):
        """Empty check means cannot auto-complete."""
        step = MethodologyStep({"id": "s1", "check": {}})
        assert step.is_auto_complete() is False

    def test_auto_complete_no_check(self):
        """No check key means cannot auto-complete."""
        step = MethodologyStep({"id": "s1"})
        assert step.is_auto_complete() is False


class TestMethodology:
    def test_from_yaml(self, sample_methodology_yaml):
        meth = Methodology(sample_methodology_yaml)
        assert meth.name == "test-meth"
        assert meth.display_name == "Test Methodology"
        assert len(meth.steps) == 3

    def test_default_display_name(self):
        meth = Methodology({"name": "foo", "steps": []})
        assert meth.display_name == "foo"

    def test_applicable_always(self):
        """No applicable_when means always applicable."""
        meth = Methodology({"name": "x", "steps": []})
        assert meth.is_applicable() is True


class TestMethodologyEngine:
    def test_load_core(self, meth_dirs, sample_methodology_yaml):
        core, _ = meth_dirs
        (core / "test.yaml").write_text(yaml.dump(sample_methodology_yaml), encoding="utf-8")
        engine = MethodologyEngine()
        engine.load_all()
        assert "test-meth" in engine.methodologies

    def test_load_custom_overrides(self, meth_dirs, sample_methodology_yaml):
        """Custom methodology with same name replaces core."""
        core, custom = meth_dirs
        (core / "test.yaml").write_text(yaml.dump(sample_methodology_yaml), encoding="utf-8")
        custom_data = dict(sample_methodology_yaml, description="Custom version")
        (custom / "test.yaml").write_text(yaml.dump(custom_data), encoding="utf-8")
        engine = MethodologyEngine()
        engine.load_all()
        assert engine.get("test-meth").description == "Custom version"

    def test_load_malformed(self, meth_dirs):
        """Malformed YAML is skipped gracefully."""
        core, _ = meth_dirs
        (core / "bad.yaml").write_text("{{invalid", encoding="utf-8")
        engine = MethodologyEngine()
        engine.load_all()
        assert len(engine.methodologies) == 0

    def test_load_no_name(self, meth_dirs):
        """YAML without name field is skipped."""
        core, _ = meth_dirs
        (core / "noname.yaml").write_text(yaml.dump({"steps": []}), encoding="utf-8")
        engine = MethodologyEngine()
        engine.load_all()
        assert len(engine.methodologies) == 0

    def test_get_unknown(self, engine_with_meth):
        assert engine_with_meth.get("nonexistent") is None

    def test_get_next_steps(self, engine_with_meth, monkeypatch):
        """Returns first N uncompleted steps."""
        monkeypatch.setattr(
            "capo.modules.methodology.state_manager.get_methodology_progress",
            lambda name: {"completed_steps": ["step-1"]},
        )
        steps = engine_with_meth.get_next_steps("test-meth", limit=2)
        assert len(steps) == 2
        assert steps[0].id == "step-2"
        assert steps[1].id == "step-3"

    def test_get_next_steps_all_done(self, engine_with_meth, monkeypatch):
        monkeypatch.setattr(
            "capo.modules.methodology.state_manager.get_methodology_progress",
            lambda name: {"completed_steps": ["step-1", "step-2", "step-3"]},
        )
        steps = engine_with_meth.get_next_steps("test-meth")
        assert steps == []

    def test_get_progress(self, engine_with_meth, monkeypatch):
        monkeypatch.setattr(
            "capo.modules.methodology.state_manager.get_methodology_progress",
            lambda name: {"completed_steps": ["step-1"]},
        )
        done, remaining = engine_with_meth.get_progress("test-meth")
        assert done == ["step-1"]
        assert remaining == ["step-2", "step-3"]

    def test_get_progress_not_started(self, engine_with_meth, monkeypatch):
        monkeypatch.setattr(
            "capo.modules.methodology.state_manager.get_methodology_progress",
            lambda name: {},
        )
        done, remaining = engine_with_meth.get_progress("test-meth")
        assert done == []
        assert len(remaining) == 3

    def test_auto_check(self, engine_with_meth, monkeypatch):
        """Auto-check completes steps whose conditions are met."""
        monkeypatch.setattr(
            "capo.modules.methodology.state_manager.get_methodology_progress",
            lambda name: {"completed_steps": []},
        )
        # Fake state with ports and users
        monkeypatch.setattr(
            "capo.modules.methodology.state_manager._state",
            {
                "ports": [{"port": 22, "state": "open"}],
                "users": ["admin"],
                "methodology_progress": {"test-meth": {"completed_steps": []}},
            },
        )
        # Mock complete_methodology_step to track calls
        completed = []
        monkeypatch.setattr(
            "capo.modules.methodology.state_manager.complete_methodology_step",
            lambda name, step_id: completed.append(step_id),
        )
        newly = engine_with_meth.auto_check("test-meth")
        assert "step-1" in newly  # ports_min: 1 satisfied
        assert "step-2" in newly  # users_min: 1 satisfied

    def test_load_yml_extension(self, meth_dirs, sample_methodology_yaml):
        """Also loads .yml files."""
        core, _ = meth_dirs
        (core / "test.yml").write_text(yaml.dump(sample_methodology_yaml), encoding="utf-8")
        engine = MethodologyEngine()
        engine.load_all()
        assert "test-meth" in engine.methodologies


class TestCoreMethodologies:
    """Verify that the shipped core methodology YAMLs are valid."""

    def test_core_files_parse(self):
        """All core methodology files should parse without error."""
        from capo.config import CORE_METHODOLOGIES_DIR

        assert CORE_METHODOLOGIES_DIR.exists(), "core_methodologies dir missing"
        files = list(CORE_METHODOLOGIES_DIR.glob("*.yaml"))
        assert len(files) >= 4, f"Expected >=4 core files, found {len(files)}"

        for f in files:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            assert isinstance(data, dict), f"{f.name} is not a dict"
            assert "name" in data, f"{f.name} missing name"
            assert "steps" in data, f"{f.name} missing steps"
            assert len(data["steps"]) >= 3, f"{f.name} has too few steps"

            for step in data["steps"]:
                assert "id" in step, f"{f.name} step missing id"
                assert "name" in step, f"{f.name} step missing name"
                assert "commands" in step, f"{f.name} step missing commands"
