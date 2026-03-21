"""Methodology Engine — Step-by-step attack workflows tracked in state.

Loads methodology definitions from YAML, tracks progress per-workspace,
and auto-completes steps when state conditions are met.
"""

import re
from pathlib import Path
from typing import Any

import yaml

from capo.config import CORE_METHODOLOGIES_DIR, CUSTOM_METHODOLOGIES_DIR
from capo.state import state_manager
from capo.utils.display import print_info, print_success, print_warning


class MethodologyStep:
    """A single step in a methodology workflow."""

    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id", "")
        self.name: str = data.get("name", "")
        self.description: str = data.get("description", "")
        self.commands: list[str] = data.get("commands", [])
        self.check: dict[str, Any] = data.get("check", {})
        self.phase: str = data.get("phase", "")

    def inject_variables(self, command: str) -> str:
        """Replace {VAR} placeholders with state values."""
        variables = re.findall(r"\{(\w+)\}", command)
        for var in variables:
            value = state_manager.get_var(var)
            if value:
                command = command.replace(f"{{{var}}}", value)
        return command

    def is_auto_complete(self) -> bool:
        """Check if state satisfies this step's auto-complete conditions."""
        if not self.check:
            return False
        state = state_manager.state
        if "users_min" in self.check:
            if len(state.get("users", [])) < self.check["users_min"]:
                return False
        if "hashes_min" in self.check:
            if len(state.get("hashes", [])) < self.check["hashes_min"]:
                return False
        if "credentials_min" in self.check:
            if len(state.get("credentials", [])) < self.check["credentials_min"]:
                return False
        if "ports_min" in self.check:
            if len(state.get("ports", [])) < self.check["ports_min"]:
                return False
        if "directories_min" in self.check:
            if len(state.get("directories", [])) < self.check["directories_min"]:
                return False
        if "shares_min" in self.check:
            if len(state.get("shares", [])) < self.check["shares_min"]:
                return False
        if "flags" in self.check:
            flags = state.get("flags", {})
            if not flags.get("local_txt") and not flags.get("proof_txt"):
                return False
        return True


class Methodology:
    """A named methodology workflow with ordered steps."""

    def __init__(self, data: dict[str, Any], source: str = "core"):
        self.name: str = data.get("name", "")
        self.display_name: str = data.get("display_name", self.name)
        self.description: str = data.get("description", "")
        self.applicable_when: dict = data.get("applicable_when", {})
        self.steps: list[MethodologyStep] = [
            MethodologyStep(s) for s in data.get("steps", [])
        ]
        self.source: str = source

    def is_applicable(self) -> bool:
        """Check if this methodology matches the current target state."""
        if not self.applicable_when:
            return True
        ports = set(state_manager.get_open_ports())
        required_ports = set(self.applicable_when.get("ports", []))
        if required_ports and not required_ports.intersection(ports):
            return False
        required_services = self.applicable_when.get("services", [])
        if required_services:
            found = False
            for svc in required_services:
                if state_manager.has_service(svc):
                    found = True
                    break
            if not found:
                return False
        return True


class MethodologyEngine:
    """Manages loading and tracking of methodology workflows."""

    def __init__(self):
        self._methodologies: dict[str, Methodology] = {}

    @property
    def methodologies(self) -> dict[str, Methodology]:
        return self._methodologies

    def load_all(self):
        """Load core + custom methodologies from YAML."""
        self._methodologies.clear()
        if CORE_METHODOLOGIES_DIR.exists():
            self._load_directory(CORE_METHODOLOGIES_DIR, source="core")
        if CUSTOM_METHODOLOGIES_DIR.exists():
            self._load_directory(CUSTOM_METHODOLOGIES_DIR, source="custom")

    def _load_directory(self, directory: Path, source: str):
        for f in sorted(directory.glob("**/*.yaml")):
            self._load_file(f, source)
        for f in sorted(directory.glob("**/*.yml")):
            self._load_file(f, source)

    def _load_file(self, filepath: Path, source: str):
        try:
            data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as e:
            print_warning(f"Failed to load methodology {filepath}: {e}")
            return
        if not isinstance(data, dict) or "name" not in data:
            return
        meth = Methodology(data, source=source)
        self._methodologies[meth.name] = meth

    def get(self, name: str) -> Methodology | None:
        return self._methodologies.get(name)

    def get_applicable(self) -> list[Methodology]:
        """Return methodologies matching the current target state."""
        return [m for m in self._methodologies.values() if m.is_applicable()]

    def get_progress(self, name: str) -> tuple[list[str], list[str]]:
        """Return (completed_step_ids, remaining_step_ids) for a methodology."""
        meth = self.get(name)
        if not meth:
            return [], []
        progress = state_manager.get_methodology_progress(name)
        completed = progress.get("completed_steps", []) if progress else []
        all_ids = [s.id for s in meth.steps]
        remaining = [sid for sid in all_ids if sid not in completed]
        return completed, remaining

    def get_next_steps(self, name: str, limit: int = 3) -> list[MethodologyStep]:
        """Return the next N uncompleted steps."""
        meth = self.get(name)
        if not meth:
            return []
        _, remaining = self.get_progress(name)
        step_map = {s.id: s for s in meth.steps}
        return [step_map[sid] for sid in remaining[:limit] if sid in step_map]

    def auto_check(self, name: str) -> list[str]:
        """Auto-complete steps whose conditions are met. Returns list of newly completed step IDs."""
        meth = self.get(name)
        if not meth:
            return []
        progress = state_manager.get_methodology_progress(name)
        completed = progress.get("completed_steps", []) if progress else []
        newly_completed = []
        for step in meth.steps:
            if step.id not in completed and step.is_auto_complete():
                state_manager.complete_methodology_step(name, step.id)
                newly_completed.append(step.id)
        return newly_completed

    def auto_check_all_active(self) -> dict[str, list[str]]:
        """Auto-check all methodologies that have been started."""
        results = {}
        progress = state_manager.state.get("methodology_progress", {})
        for name in progress:
            newly = self.auto_check(name)
            if newly:
                results[name] = newly
        return results


# Global singleton
methodology_engine = MethodologyEngine()
