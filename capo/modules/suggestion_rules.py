"""YAML-driven suggestion rule engine.

Each rule in core_rules/*.yaml defines conditions (ports, state, JMESPath)
and a command template.  When the current target state satisfies a rule's
conditions the command is surfaced to the user via ``capo suggest`` or the
``/api/suggest`` endpoint.
"""

import jmespath
from rich.console import Console

console = Console()


class SuggestionRule:
    def __init__(self, data):
        self.id = data.get("id")
        self.name = data.get("name")
        self.description = data.get("description", "")
        self.priority = data.get("priority", "P3")
        self.conditions = data.get("conditions", {})
        self.command_template = data.get("command_template", "")
        self.source_reference = data.get("source_reference", "")

    def evaluate(self, state_data) -> bool:
        # 1. Advanced JMESPath Evaluation
        jmes_query = self.conditions.get("jmespath")
        if jmes_query:
            try:
                result = jmespath.search(jmes_query, state_data)
                if not result:
                    return False
            except jmespath.exceptions.JMESPathError as e:
                console.print(f"[red]JMESPath Syntax Error in rule '{self.name}': {e}[/red]")
                return False

        # 2. Legacy: Check required ports
        req_ports = self.conditions.get("require_ports", [])
        if req_ports:
            open_ports = state_data.get("ports", [])
            open_port_nums = [p["port"] for p in open_ports] if isinstance(open_ports, list) else []
            for p in req_ports:
                if int(p) not in open_port_nums:
                    return False

        # 3. Legacy: Check required state strings
        req_state = self.conditions.get("require_state", [])
        for req in req_state:
            if req == "has_domain" and not state_data.get("domains") and not state_data.get("domain"):
                return False
            if req == "has_valid_user" and not state_data.get("users") and not state_data.get("credentials"):
                return False
            if req == "has_valid_password" and not state_data.get("credentials"):
                return False

        # 4. Check variable requirements implied by the command template
        cmd = self.command_template
        if "{USERFILE}" in cmd:
            if not state_data.get("users") and not state_data.get("credentials"):
                return False
        if "{PASSFILE}" in cmd:
            if not state_data.get("credentials"):
                return False

        return True
