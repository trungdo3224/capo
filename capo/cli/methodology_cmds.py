"""Methodology workflow CLI commands."""

import typer

from capo.cli.helpers import print_json_data, require_target
from capo.utils.display import console, print_error, print_info, print_success, print_suggestion

methodology_app = typer.Typer(help="Attack methodology workflows")


def _get_methodology(name: str):
    """Load engine, resolve methodology by name, or exit with error."""
    from capo.modules.methodology import methodology_engine

    methodology_engine.load_all()
    meth = methodology_engine.get(name)
    if not meth:
        print_error(f"Unknown methodology: {name}")
        raise typer.Exit(1)
    return meth, methodology_engine


@methodology_app.command("list")
def methodology_list(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List available methodology workflows."""
    from capo.modules.methodology import methodology_engine

    methodology_engine.load_all()
    meths = methodology_engine.methodologies

    if json_output:
        data = {
            name: {
                "display_name": m.display_name,
                "description": m.description,
                "steps": len(m.steps),
                "source": m.source,
            }
            for name, m in meths.items()
        }
        print_json_data(data)
        return

    from rich.table import Table

    table = Table(title="Methodology Workflows")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Steps", justify="center")
    table.add_column("Source", style="dim")
    for m in meths.values():
        table.add_row(m.name, m.description, str(len(m.steps)), m.source)
    console.print(table)


@methodology_app.command("start")
def methodology_start(
    name: str = typer.Argument(help="Methodology name"),
    step_id: str = typer.Argument(None, help="Step ID to show commands for"),
):
    """Start a methodology and list its steps, or show commands for a specific step.

    Examples:
      capo methodology start web-app               # list all step names
      capo methodology start web-app source-analysis  # show commands for that step
    """
    require_target()
    meth, engine = _get_methodology(name)

    from capo.state import state_manager
    state_manager.start_methodology(name)

    if step_id:
        step = next((s for s in meth.steps if s.id == step_id), None)
        if not step:
            print_error(f"Unknown step: {step_id}")
            valid = ", ".join(s.id for s in meth.steps)
            print_info(f"Valid steps: {valid}")
            raise typer.Exit(1)
        cmds = [step.inject_variables(c) for c in step.commands]
        print_suggestion(f"[{step.phase}] {step.name}", cmds)
    else:
        _show_methodology_steps(meth, engine)


@methodology_app.command("status")
def methodology_status(
    name: str = typer.Argument(help="Methodology name"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show progress of a methodology workflow."""
    require_target()
    meth, engine = _get_methodology(name)
    completed, remaining = engine.get_progress(name)

    if json_output:
        print_json_data({
            "name": name,
            "total": len(meth.steps),
            "completed": completed,
            "remaining": remaining,
        })
        return

    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn

    total = len(meth.steps)
    done = len(completed)

    console.print(f"\n[bold]{meth.display_name}[/bold] — {done}/{total} steps complete")

    with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(),
                  TextColumn("{task.completed}/{task.total}"), console=console) as progress:
        progress.add_task("Progress", total=total, completed=done)

    table = Table(show_lines=False)
    table.add_column("", width=3)
    table.add_column("Step", style="bold")
    table.add_column("Phase", style="dim")
    table.add_column("Description")
    for step in meth.steps:
        if step.id in completed:
            mark = "[green]✓[/green]"
            style = "dim"
        else:
            mark = "[dim]○[/dim]"
            style = ""
        table.add_row(mark, f"[{style}]{step.name}[/{style}]" if style else step.name,
                       step.phase, step.description)
    console.print(table)


@methodology_app.command("next")
def methodology_next(
    name: str = typer.Argument(help="Methodology name"),
    limit: int = typer.Option(3, "--limit", "-n", help="Number of steps to show"),
):
    """Show next steps in a methodology with commands."""
    require_target()
    meth, engine = _get_methodology(name)
    steps = engine.get_next_steps(name, limit)
    if not steps:
        print_success(f"🎉 {meth.display_name} — all steps complete!")
        return
    for step in steps:
        cmds = [step.inject_variables(c) for c in step.commands]
        print_suggestion(f"[{step.phase}] {step.name}", cmds)


@methodology_app.command("done")
def methodology_done(
    name: str = typer.Argument(help="Methodology name"),
    step: str = typer.Argument(help="Step ID to mark complete"),
):
    """Mark a methodology step as completed."""
    require_target()
    meth, engine = _get_methodology(name)
    valid_ids = [s.id for s in meth.steps]
    if step not in valid_ids:
        print_error(f"Unknown step: {step}")
        print_info(f"Valid steps: {', '.join(valid_ids)}")
        raise typer.Exit(1)
    from capo.state import state_manager
    state_manager.complete_methodology_step(name, step)
    step_obj = next(s for s in meth.steps if s.id == step)
    print_success(f"Completed: {step_obj.name}")
    completed, remaining = engine.get_progress(name)
    if not remaining:
        print_success(f"🎉 {meth.display_name} — all steps complete!")
    else:
        print_info(f"{len(remaining)} steps remaining")


@methodology_app.command("auto-check")
def methodology_auto_check(
    name: str = typer.Argument(None, help="Methodology name (or all if omitted)"),
):
    """Auto-complete methodology steps based on current state."""
    require_target()
    from capo.modules.methodology import methodology_engine

    methodology_engine.load_all()
    if name:
        newly = methodology_engine.auto_check(name)
        if newly:
            meth = methodology_engine.get(name)
            step_map = {s.id: s for s in meth.steps} if meth else {}
            for sid in newly:
                sname = step_map.get(sid)
                print_success(f"Auto-completed: {sname.name if sname else sid}")
        else:
            print_info("No steps auto-completed.")
    else:
        results = methodology_engine.auto_check_all_active()
        if results:
            for mname, sids in results.items():
                for sid in sids:
                    print_success(f"[{mname}] Auto-completed: {sid}")
        else:
            print_info("No steps auto-completed.")


def _show_methodology_steps(meth, engine):
    """List all steps in a methodology (names only, no commands)."""
    from rich.table import Table

    completed, _ = engine.get_progress(meth.name)

    table = Table(show_header=True, header_style="bold", show_lines=False)
    table.add_column("", width=3)
    table.add_column("Step ID", style="cyan")
    table.add_column("Name")
    table.add_column("Phase", style="dim")

    for step in meth.steps:
        mark = "[green]✓[/green]" if step.id in completed else "[dim]○[/dim]"
        table.add_row(mark, step.id, step.name, step.phase)

    console.print(f"\n[bold]{meth.display_name}[/bold] — run [cyan]capo methodology start {meth.name} <step-id>[/cyan] to see commands\n")
    console.print(table)
