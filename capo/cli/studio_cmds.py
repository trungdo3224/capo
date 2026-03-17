"""CLI commands for Capo Studio."""
import typer
import subprocess
from rich.console import Console

app = typer.Typer(help="Launch the Capo Studio web UI.")
console = Console()

@app.callback(invoke_without_command=True)
def studio(
    port: int = typer.Option(8000, "--port", "-p", help="Port to run Capo Studio on"),
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="Host interface to bind"),
):
    """Start the Capo Studio backend and host the UI."""
    console.print(f"[bold green]Starting Capo Studio on http://{host}:{port}...[/bold green]")
    try:
        subprocess.run(
            ["uvicorn", "capo.studio.api:app", "--host", host, "--port", str(port)],
            check=True
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Capo Studio shut down.[/yellow]")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Failed to start Uvicorn: {e}[/bold red]")
