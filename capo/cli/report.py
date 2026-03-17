"""Report generation CLI commands."""

import typer

from capo.state import state_manager
from capo.utils.display import console, print_error, print_success

report_app = typer.Typer(help="Report generation & export")


@report_app.command("generate")
def report_generate(
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown or html"),
):
    """Generate a full pentest report from current state."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    from capo.modules.reporting import generate_html, generate_markdown

    evidence_dir = state_manager.workspace / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "html":
        content = generate_html()
        out_file = evidence_dir / "report.html"
    else:
        content = generate_markdown()
        out_file = evidence_dir / "report.md"

    out_file.write_text(content, encoding="utf-8")
    print_success(f"Report written to {out_file}")


@report_app.command("preview")
def report_preview():
    """Preview the report in the terminal."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    from rich.markdown import Markdown

    from capo.modules.reporting import generate_markdown
    console.print(Markdown(generate_markdown()))


@report_app.command("timeline")
def report_timeline():
    """Show just the attack timeline."""
    if not state_manager.target:
        print_error("No target set.")
        raise typer.Exit(1)
    from rich.markdown import Markdown

    from capo.modules.reporting import generate_timeline
    console.print(Markdown(generate_timeline()))
