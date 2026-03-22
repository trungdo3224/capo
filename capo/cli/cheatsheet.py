"""Cheatsheet search/query CLI commands."""

import typer

from capo.cli.helpers import display_cheatsheet_results, print_section_header
from capo.utils.display import console, print_warning


def _is_known_tool(query: str) -> bool:
    """Check if query matches a known pentest tool name."""
    from capo.config import load_pentest_tools
    tools = load_pentest_tools()
    return query.lower() in {t.lower() for t in tools}


def _web_search(query: str):
    """Search DuckDuckGo for pentest tool cheatsheets and display results."""
    import html
    import re
    import urllib.request
    from urllib.parse import quote_plus

    from rich.table import Table

    search_query = f"{query} cheatsheet pentest commands"
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(search_query)}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "capo-search/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print_warning(f"Web search failed: {e}")
        return

    # Parse result snippets from DuckDuckGo HTML response
    results: list[tuple[str, str]] = []
    for match in re.finditer(
        r'<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.*?)</a>',
        body,
    ):
        href, title_html = match.group(1), match.group(2)
        title = html.unescape(re.sub(r"<[^>]+>", "", title_html)).strip()
        if title and href:
            results.append((title, href))
        if len(results) >= 5:
            break

    if not results:
        print_warning("No web results found.")
        return

    table = Table(title=f"Web Results for '{query}'", border_style="cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Title", style="bold white")
    table.add_column("URL", style="dim cyan")

    for i, (title, href) in enumerate(results, 1):
        table.add_row(str(i), title[:80], href[:100])

    console.print(table)


def register_cheatsheet_commands(app: typer.Typer):
    """Register cheatsheet commands on the main app."""

    @app.command("search")
    def search_cheatsheet(
        query: str = typer.Argument("", help="Search query (e.g., 'nmap', 'kerberos', 'smb enum')"),
        category: str | None = typer.Option(None, "--category", "-c", help="Filter by category (omit query to list all categories)"),
        tool: str | None = typer.Option(None, "--tool", "-t", help="Filter by tool name"),
        exam: str | None = typer.Option(None, "--exam", "-e", help="Filter by exam: oscp/cpts"),
        web: bool = typer.Option(False, "--web", "-w", help="Search the web when local results are sparse"),
        copy: bool = typer.Option(False, "--copy", help="Copy selected command to clipboard"),
    ):
        """Search cheatsheets with smart tool-priority matching and variable injection.

        Examples:
            capo search nmap          # tool-aware search
            capo search kerberos      # fuzzy search across all entries
            capo search -c smb        # list all commands in the SMB category
            capo search -c            # list all categories (no query needed)
            capo search nmap --web    # also search the web
            capo search --tool hydra  # strict tool-field filter
        """
        from rich.table import Table

        from capo.modules.cheatsheet.engine import cheatsheet_engine
        cheatsheet_engine.load_all()

        # No query: list categories (replaces old `capo categories`)
        if not query and not tool:
            if category:
                # Show commands in a specific category
                matched = [c for c in cheatsheet_engine.categories if category.lower() in c.lower()]
                if not matched:
                    print_warning(f"No category matching '{category}'. Run 'capo search' to see all.")
                    return
                for cat in matched:
                    entries = cheatsheet_engine.get_by_category(cat)
                    if entries:
                        if exam:
                            entries = [e for e in entries if exam.lower() in e.exam]
                        display_cheatsheet_results(entries, copy)
                return

            # List all categories
            table = Table(title="Cheatsheet Categories", border_style="cyan")
            table.add_column("Category", style="bold cyan")
            table.add_column("Commands", style="green", justify="right")
            for cat in cheatsheet_engine.categories:
                entries = cheatsheet_engine.get_by_category(cat)
                table.add_row(cat, str(len(entries)))
            console.print(table)
            return

        # Explicit --tool filter takes priority
        if tool:
            results = cheatsheet_engine.get_by_tool(tool)
            if category:
                results = [r for r in results if r.category.lower() == category.lower()]
            if exam:
                results = [r for r in results if exam.lower() in r.exam]
            if not results:
                print_warning(f"No cheatsheet entries for tool '{tool}'")
                if web:
                    _web_search(tool)
                return
            display_cheatsheet_results(results, copy)
            return

        # Smart search: tool-priority when query matches a known tool
        is_tool = _is_known_tool(query)

        if is_tool:
            tool_results = cheatsheet_engine.get_by_tool(query)
            fuzzy_results = cheatsheet_engine.fuzzy_search(query)

            # Remove duplicates (entries already in tool_results)
            tool_names = {e.name for e in tool_results}
            related_results = [r for r in fuzzy_results if r.name not in tool_names]

            # Apply filters
            if category:
                tool_results = [r for r in tool_results if r.category.lower() == category.lower()]
                related_results = [r for r in related_results if r.category.lower() == category.lower()]
            if exam:
                tool_results = [r for r in tool_results if exam.lower() in r.exam]
                related_results = [r for r in related_results if exam.lower() in r.exam]

            if tool_results:
                print_section_header(f"Tool: {query}")
                display_cheatsheet_results(tool_results, copy)

            if related_results:
                print_section_header("Related")
                display_cheatsheet_results(related_results, copy and not tool_results)

            if not tool_results and not related_results:
                print_warning(f"No results for '{query}'")
                if web:
                    _web_search(query)
        else:
            # Standard fuzzy search (also handles exact substring matching)
            results = cheatsheet_engine.search(query)
            if not results:
                results = cheatsheet_engine.fuzzy_search(query)

            if category:
                results = [r for r in results if r.category.lower() == category.lower()]
            if exam:
                results = [r for r in results if exam.lower() in r.exam]

            if not results:
                print_warning(f"No results for '{query}'")
                if web:
                    _web_search(query)
                return

            display_cheatsheet_results(results, copy)

    @app.command("tools")
    def list_tools(
        filter_pattern: str | None = typer.Argument(None, help="Filter tools by name (substring match)"),
    ):
        """List all known pentest tools with cheatsheet coverage."""
        from rich.table import Table

        from capo.config import load_pentest_tools
        from capo.modules.cheatsheet.engine import cheatsheet_engine
        cheatsheet_engine.load_all()

        tools = load_pentest_tools()
        if filter_pattern:
            tools = [t for t in tools if filter_pattern.lower() in t.lower()]

        if not tools:
            print_warning("No tools found matching filter.")
            return

        table = Table(title="Pentest Tools", border_style="cyan")
        table.add_column("Tool", style="bold white")
        table.add_column("Commands", style="green", justify="right")
        table.add_column("Categories", style="dim cyan")

        covered = 0
        for tool_name in tools:
            entries = cheatsheet_engine.get_by_tool(tool_name)
            count = len(entries)
            cats = ", ".join(sorted({e.category for e in entries})) if entries else ""

            if count > 0:
                covered += 1
                table.add_row(tool_name, str(count), cats)
            else:
                table.add_row(f"[dim]{tool_name}[/dim]", "[dim]0[/dim]", "")

        console.print(table)
        console.print(
            f"\n[dim]{covered}/{len(tools)} tools have cheatsheet coverage[/dim]"
        )
