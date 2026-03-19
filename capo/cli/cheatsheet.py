"""Cheatsheet search/query CLI commands."""

import typer

from capo.cli.helpers import display_cheatsheet_results
from capo.utils.display import console, print_warning


def register_cheatsheet_commands(app: typer.Typer):
    """Register cheatsheet commands on the main app."""

    @app.command("search")
    def search_cheatsheet(
        query: str = typer.Argument(..., help="Search query (e.g., 'kerberos', 'smb enum', 'privesc linux')"),
        category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
        exam: str | None = typer.Option(None, "--exam", "-e", help="Filter by exam: oscp/cpts"),
        copy: bool = typer.Option(False, "--copy", help="Copy selected command to clipboard"),
    ):
        """Search cheatsheets with fuzzy matching and variable injection."""
        from capo.modules.cheatsheet.engine import cheatsheet_engine
        cheatsheet_engine.load_all()

        results = cheatsheet_engine.fuzzy_search(query)

        if category:
            results = [r for r in results if r.category.lower() == category.lower()]
        if exam:
            results = [r for r in results if exam.lower() in r.exam]

        if not results:
            print_warning(f"No results for '{query}'")
            return

        display_cheatsheet_results(results, copy)

    @app.command("query")
    def query_service(
        service: str = typer.Argument(..., help="Service or topic (e.g., 'smb', 'kerberos', 'privesc')"),
        copy: bool = typer.Option(False, "--copy", help="Copy selected command to clipboard"),
    ):
        """Quick query for a specific service/topic - shortcut for search."""
        from capo.modules.cheatsheet.engine import cheatsheet_engine
        cheatsheet_engine.load_all()

        results = cheatsheet_engine.search(service)
        if not results:
            results = cheatsheet_engine.fuzzy_search(service)

        if not results:
            print_warning(f"No cheatsheet entries for '{service}'")
            return

        display_cheatsheet_results(results, copy)

    @app.command("categories")
    def list_categories(
        category: str | None = typer.Argument(None, help="Show commands in a specific category"),
        copy: bool = typer.Option(False, "--copy", help="Copy selected command to clipboard"),
    ):
        """List all categories, or show commands in a specific category."""
        from rich.table import Table

        from capo.modules.cheatsheet.engine import cheatsheet_engine
        cheatsheet_engine.load_all()

        if category:
            # Find matching category (case-insensitive, partial match)
            matched = [c for c in cheatsheet_engine.categories if category.lower() in c.lower()]
            if not matched:
                print_warning(f"No category matching '{category}'. Run 'capo categories' to see all.")
                return
            for cat in matched:
                entries = cheatsheet_engine.get_by_category(cat)
                if entries:
                    display_cheatsheet_results(entries, copy)
            return

        table = Table(title="Cheatsheet Categories", border_style="cyan")
        table.add_column("Category", style="bold cyan")
        table.add_column("Commands", style="green", justify="right")

        for cat in cheatsheet_engine.categories:
            entries = cheatsheet_engine.get_by_category(cat)
            table.add_row(cat, str(len(entries)))

        console.print(table)
