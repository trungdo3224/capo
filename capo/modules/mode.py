"""OSCP/CPTS Mode Manager.

Controls which features are available based on the exam mode.
- OSCP mode: No LLM, no auto-exploitation, strict tool compliance
- CPTS mode: All features including AI suggestions, pivoting helpers
"""

from capo.config import CAPO_HOME, MODE_CPTS, MODE_OSCP, OSCP_RESTRICTED_TOOLS
from capo.utils.display import print_error, print_info, print_success, print_warning


def _mode_file():
    return CAPO_HOME / ".current_mode"


class ModeManager:
    """Manages exam mode for OSCP/CPTS compliance."""

    def __init__(self):
        self._metasploit_used: bool = False
        self._mode: str = self._load_mode()

    def _load_mode(self) -> str:
        mf = _mode_file()
        if mf.exists():
            stored = mf.read_text(encoding="utf-8").strip().lower()
            if stored in (MODE_OSCP, MODE_CPTS):
                return stored
        return MODE_OSCP

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def is_oscp(self) -> bool:
        return self._mode == MODE_OSCP

    @property
    def is_cpts(self) -> bool:
        return self._mode == MODE_CPTS

    def set_mode(self, mode: str):
        """Set the exam mode."""
        mode = mode.lower()
        if mode not in (MODE_OSCP, MODE_CPTS):
            print_error(f"Invalid mode: {mode}. Use 'oscp' or 'cpts'.")
            return
        self._mode = mode
        CAPO_HOME.mkdir(parents=True, exist_ok=True)
        _mode_file().write_text(mode, encoding="utf-8")
        print_success(f"Mode set to: {mode.upper()}")
        if mode == MODE_OSCP:
            print_info("OSCP Mode: No LLM features, strict tool compliance")
            print_warning("Metasploit allowed on ONE machine only")
        else:
            print_info("CPTS Mode: All features enabled (AI, Pivoting helpers)")

    def check_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed in current mode."""
        if self._mode == MODE_CPTS:
            return True  # CPTS has no explicit tool restrictions

        tool_lower = tool_name.lower()
        if tool_lower in [t.lower() for t in OSCP_RESTRICTED_TOOLS]:
            if tool_lower == "metasploit" and not self._metasploit_used:
                print_warning(
                    "⚠️  Metasploit is ONLY allowed for ONE machine in OSCP. "
                    "Use 'capo mode use-msf' to mark this machine."
                )
                return False
            print_error(f"❌ {tool_name} is NOT allowed in OSCP exam!")
            return False
        return True

    def mark_metasploit_used(self):
        """Mark that Metasploit has been used on this machine."""
        if self._mode == MODE_OSCP:
            self._metasploit_used = True
            print_warning("⚠️  Metasploit marked as USED. Cannot use on other machines!")

    def can_use_ai(self) -> bool:
        """Check if AI/LLM features are available."""
        if self._mode == MODE_OSCP:
            return False
        return True

    def get_mode_info(self) -> dict:
        """Get current mode information."""
        return {
            "mode": self._mode.upper(),
            "ai_enabled": self.can_use_ai(),
            "metasploit_used": self._metasploit_used,
            "restrictions": OSCP_RESTRICTED_TOOLS if self.is_oscp else [],
        }


# Global singleton
mode_manager = ModeManager()
