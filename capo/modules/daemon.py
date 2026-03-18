import json
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
import yaml
import jmespath
from capo.state import StateManager
from capo.config import CAPO_HOME

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

class Daemon:
    def __init__(self):
        self.state_manager = StateManager()
        self.rules = []
        self.load_rules()
        self.last_state_hash = None

    def load_rules(self):
        rules_dir = Path(__file__).parent.parent / "core_rules"
        if not rules_dir.exists():
            return
            
        for rule_file in rules_dir.glob("*.yaml"):
            with open(rule_file, "r") as f:
                try:
                    data = yaml.safe_load(f)
                    if isinstance(data, list):
                        for item in data:
                            self.rules.append(SuggestionRule(item))
                except Exception as e:
                    console.print(f"[red]Error loading rule {rule_file}: {e}[/red]")

    def run(self):
        if not self.state_manager.workspace:
            console.print("[red]No active target set. Use 'capo target set <ip>' first.[/red]")
            return

        state_file = self.state_manager.workspace / "state.json"
        if not state_file.exists():
            console.print("[red]State file not found.[/red]")
            return

        console.print(f"[green]Capo Suggestion Daemon running...[/green] Watching {state_file.name}")
        console.print("[yellow]Waiting for enumeration events...[/yellow]\n")

        try:
            while True:
                # Polling state.json
                current_time_mod = state_file.stat().st_mtime
                if self.last_state_hash != current_time_mod:
                    self.last_state_hash = current_time_mod
                    
                    try:
                        with open(state_file, "r") as f:
                            state_data = json.load(f)
                        self.evaluate_and_suggest(state_data)
                    except json.JSONDecodeError:
                        # Ignore partial writes
                        time.sleep(0.5)
                        self.last_state_hash = None
                        continue
                    except Exception as e:
                        console.print(f"[red]Error parsing state: {e}[/red]")

                time.sleep(2)
        except KeyboardInterrupt:
            console.print("\n[yellow]Daemon stopped.[/yellow]")

    def _replace_vars(self, template: str, state_data: dict) -> str:
        # Use state_manager's get_var to ensure consistency with CLI and campaign layer
        domain = self.state_manager.get_var("DOMAIN") or "{DOMAIN}"
        target_ip = self.state_manager.get_var("IP") or "{IP}"
        user = self.state_manager.get_var("USER") or "{USER}"
        pwd = self.state_manager.get_var("PASS") or "{PASS}"
        user_file = self.state_manager.get_var("USERFILE") or "{USERFILE}"
        pass_file = self.state_manager.get_var("PASSFILE") or "{PASSFILE}"
                    
        cmd = template.replace("{DOMAIN}", str(domain))
        cmd = cmd.replace("{IP}", str(target_ip))
        cmd = cmd.replace("{USER}", str(user))
        cmd = cmd.replace("{PASSWORD}", str(pwd))
        cmd = cmd.replace("{PASS}", str(pwd))
        cmd = cmd.replace("{USERFILE}", str(user_file))
        cmd = cmd.replace("{PASSFILE}", str(pass_file))
        return cmd

    def evaluate_and_suggest(self, state_data):
        suggestions = []
        for rule in self.rules:
            if rule.evaluate(state_data):
                suggestions.append(rule)
        
        if not suggestions:
            return

        suggestions.sort(key=lambda x: str(x.priority))

        console.rule("[bold cyan]Capo State Update Detected")

        # Table 1: Strategic Thinking (Objectives)
        obj_table = Table(show_header=True, header_style="bold magenta", title="[+] Strategic Objectives (Thinking)", box=box.SIMPLE)
        obj_table.add_column("Priority", style="dim", width=8)
        obj_table.add_column("Objective", width=35, style="bold cyan")
        obj_table.add_column("Reason / Reference", style="dim")

        # Table 2: Tactical Execution (Commands)
        cmd_table = Table(show_header=True, header_style="bold green", title="[+] Actionable Commands (Execution)", box=box.SIMPLE)
        cmd_table.add_column("Priority", style="dim", width=8)
        cmd_table.add_column("Command Template", style="green")

        for s in suggestions:
            priority_color = "red" if s.priority == "P1" else "yellow" if s.priority == "P2" else "white"
            
            obj_table.add_row(
                f"[{priority_color}]{s.priority}[/{priority_color}]",
                s.name,
                s.description or s.source_reference
            )
            
            final_cmd = self._replace_vars(s.command_template, state_data)
            
            cmd_table.add_row(
                f"[{priority_color}]{s.priority}[/{priority_color}]",
                final_cmd
            )

        console.print(obj_table)
        console.print("")
        console.print(cmd_table)
        console.print("\n[dim]Awaiting next enumeration finding...[/dim]")
