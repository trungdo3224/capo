"""Writeup source management CLI commands."""

import typer

from capo.utils.display import console, print_error, print_info, print_success, print_warning

writeup_app = typer.Typer(help="Writeup source management — ingest attack patterns from pentest writeups")


@writeup_app.command("add-source")
def add_source(
    path: str = typer.Argument(..., help="Path to a folder containing .md writeup files"),
):
    """Register a writeup folder for pattern extraction."""
    from pathlib import Path

    resolved = Path(path).resolve()
    if not resolved.exists():
        print_error(f"Path does not exist: {resolved}")
        raise typer.Exit(1)
    if not resolved.is_dir():
        print_error(f"Path is not a directory: {resolved}")
        raise typer.Exit(1)

    from capo.modules.writeup_sync import writeup_sync_manager
    if writeup_sync_manager.add_source(str(resolved)):
        md_count = len(list(resolved.rglob("*.md")))
        print_success(f"Added source: {resolved} ({md_count} .md files found)")
        print_info("Run 'capo writeup sync' to parse and generate rules.")
    else:
        print_warning("Source already registered.")


@writeup_app.command("remove-source")
def remove_source(
    path: str = typer.Argument(..., help="Path to remove from registered sources"),
):
    """Unregister a writeup folder."""
    from pathlib import Path

    resolved = str(Path(path).resolve())
    from capo.modules.writeup_sync import writeup_sync_manager
    if writeup_sync_manager.remove_source(resolved):
        print_success(f"Removed source: {resolved}")
    else:
        print_warning("Source not found in registry.")


@writeup_app.command("list")
def list_sources():
    """Show registered writeup sources and sync status."""
    from rich.table import Table

    from capo.modules.writeup_sync import writeup_sync_manager
    sources = writeup_sync_manager.list_sources()

    if not sources:
        print_warning("No writeup sources registered. Use: capo writeup add-source <PATH>")
        return

    table = Table(title="Writeup Sources", border_style="cyan")
    table.add_column("Path", style="white")
    table.add_column("Exists", style="green", justify="center")
    table.add_column("Writeups", style="cyan", justify="right")
    table.add_column("Last Sync", style="dim")

    for src in sources:
        table.add_row(
            src["path"],
            "Yes" if src["exists"] else "[red]No[/red]",
            str(src["writeups"]),
            src["last_sync"][:19] if src["last_sync"] != "never" else "never",
        )
    console.print(table)


@writeup_app.command("sync")
def sync():
    """Parse all registered sources, generate suggestion rules from writeup patterns."""
    from capo.modules.writeup_sync import writeup_sync_manager

    sources = writeup_sync_manager.list_sources()
    if not sources:
        print_warning("No writeup sources registered. Use: capo writeup add-source <PATH>")
        return

    print_info("Syncing writeup sources...")
    result = writeup_sync_manager.sync()

    if result.parsed:
        print_success(f"Parsed {result.parsed} new/changed writeup(s)")
    if result.skipped:
        print_info(f"Skipped {result.skipped} unchanged writeup(s)")
    if result.rules_generated:
        print_success(f"Generated {result.rules_generated} suggestion rule(s)")
    if result.errors:
        for err in result.errors:
            print_warning(err)
    if not result.parsed and not result.skipped:
        print_warning("No writeup files found in registered sources.")


@writeup_app.command("status")
def status():
    """Show parsed writeups and extracted pattern counts."""
    from pathlib import Path

    from rich.table import Table

    from capo.modules.writeup_sync import writeup_sync_manager

    sources = writeup_sync_manager.list_sources()
    if not sources:
        print_warning("No writeup sources registered.")
        return

    # Check generated rules
    from capo import config
    rules_dir = config.CAPO_HOME / "writeup_rules"
    rule_count = 0
    if rules_dir.exists():
        import yaml as _yaml
        for rf in rules_dir.glob("*.yaml"):
            try:
                data = _yaml.safe_load(rf.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    rule_count += len(data)
            except Exception:
                pass

    # Show summary
    total_writeups = sum(s["writeups"] for s in sources)
    synced_sources = sum(1 for s in sources if s["last_sync"] != "never")

    table = Table(title="Writeup Sync Status", border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", style="green")
    table.add_row("Registered Sources", str(len(sources)))
    table.add_row("Synced Sources", str(synced_sources))
    table.add_row("Total Writeup Files", str(total_writeups))
    table.add_row("Generated Rules", str(rule_count))
    table.add_row("Rules Directory", str(rules_dir))
    console.print(table)
