"""Custom trigger management CLI commands."""

import typer

from capo.state import state_manager
from capo.utils.display import console, print_error, print_info, print_success, print_warning

triggers_app = typer.Typer(help="Custom trigger management")


@triggers_app.command("init")
def triggers_init():
    """Create a starter custom_triggers.yaml file."""
    from capo.modules.triggers import init_custom_triggers

    from capo.config import CUSTOM_TRIGGERS_FILE
    created = init_custom_triggers()
    if created:
        print_success(f"Created {CUSTOM_TRIGGERS_FILE}")
        print_info("Edit this file to add your own port-based suggestions.")
    else:
        print_warning(f"File already exists: {CUSTOM_TRIGGERS_FILE}")


@triggers_app.command("list")
def triggers_list(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List all triggers (built-in + custom)."""
    import json as json_mod
    from capo.modules.triggers import get_merged_triggers

    merged = get_merged_triggers()
    if json_output:
        console.print_json(json_mod.dumps({str(k): v for k, v in sorted(merged.items())}))
        return
    from rich.table import Table

    table = Table(title="Port Triggers", show_lines=True)
    table.add_column("Port", style="cyan", width=8)
    table.add_column("Title", style="bold")
    table.add_column("Suggestions", style="dim")
    for port in sorted(merged.keys()):
        for trigger in merged[port]:
            table.add_row(
                str(port),
                trigger["title"],
                "\n".join(trigger["suggestions"][:3]),
            )
    console.print(table)


@triggers_app.command("check")
def triggers_check():
    """Run all triggers against the current target state."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    from capo.modules.triggers import check_triggers

    check_triggers()
