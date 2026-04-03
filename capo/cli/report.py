"""Report generation CLI commands."""

import typer

from capo.cli.helpers import require_target
from capo.state import state_manager
from capo.utils.display import console, print_success

report_app = typer.Typer(help="Report generation & export")


@report_app.callback(invoke_without_command=True)
def report_generate(
    ctx: typer.Context,
    fmt: str = typer.Option("markdown", "--format", "-f", help="output format: markdown or html"),
    preview: bool = typer.Option(False, "--preview", "-p", help="preview in terminal instead of writing to file"),
    timeline: bool = typer.Option(False, "--timeline", "-t", help="show only the attack timeline"),
):
    """Generate a full pentest report from current state.

    Examples:
        capo report                # generate markdown report
        capo report -f html        # generate HTML report
        capo report --preview      # preview in terminal
        capo report --timeline     # show just the attack timeline
    """
    if ctx.invoked_subcommand is not None:
        return

    require_target()

    if timeline:
        from rich.markdown import Markdown
        from capo.modules.reporting import generate_timeline
        console.print(Markdown(generate_timeline()))
        return

    if preview:
        from rich.markdown import Markdown
        from capo.modules.reporting import generate_markdown
        console.print(Markdown(generate_markdown()))
        return

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
