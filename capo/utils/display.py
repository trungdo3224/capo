"""Display utilities using Rich for beautiful terminal output."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console()


def banner():
    """Print the C.A.P.O banner."""
    banner_text = r"""
   ██████╗ ██╗ █████╗ ██████╗  ██████╗
  ██╔════╝ ██║██╔══██╗██╔══██╗██╔═══██╗
  ██║      ██║███████║██████╔╝██║   ██║
  ██║      ██║██╔══██║██╔═══╝ ██║   ██║
  ╚██████╗ ██║██║  ██║██║     ╚██████╔╝
   ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝
  Context-Aware Pentest Orchestrator
    """
    console.print(Panel(
        Text(banner_text, style="bold cyan"),
        subtitle="[dim]OSCP/CPTS Exam Companion[/dim]",
        border_style="cyan",
    ))


def print_command(command: str):
    """Print command before execution (transparency requirement)."""
    console.print(f"\n[bold yellow][+] Executing:[/bold yellow] [white]{command}[/white]")


def print_success(message: str):
    console.print(f"[bold green][✓][/bold green] {message}")


def print_error(message: str):
    console.print(f"[bold red][✗][/bold red] {message}")


def print_warning(message: str):
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def print_info(message: str):
    console.print(f"[bold blue][*][/bold blue] {message}")


def print_suggestion(title: str, commands: list[str]):
    """Print context-aware suggestions after a scan."""
    console.print()
    panel_content = ""
    for cmd in commands:
        panel_content += f"  → [cyan]{cmd}[/cyan]\n"
    console.print(Panel(
        panel_content.rstrip(),
        title=f"[bold yellow]💡 {title}[/bold yellow]",
        border_style="yellow",
    ))


def print_state_table(state: dict):
    """Print a formatted state summary table."""
    table = Table(title="Target State Summary", border_style="cyan")
    table.add_column("Property", style="bold white")
    table.add_column("Value", style="green")

    table.add_row("Target", state.get("ip", "N/A"))
    domains = state.get("domains", [])
    table.add_row("Domains", ", ".join(domains) if domains else "N/A")
    table.add_row("OS", state.get("os", "N/A") or "N/A")
    table.add_row("Hostname", state.get("hostname", "N/A") or "N/A")

    ports = state.get("ports", [])
    open_ports = [p for p in ports if p.get("state") == "open"]
    port_str = ", ".join(f"{p['port']}/{p['protocol']}" for p in open_ports) or "None"
    table.add_row("Open Ports", port_str)

    subdomains = state.get("subdomains", [])
    if subdomains:
        table.add_row("Subdomains", ", ".join(subdomains))
        
    vhosts = state.get("vhosts", [])
    if vhosts:
        table.add_row("vHosts", ", ".join(vhosts))

    users = state.get("users", [])
    if users:
        table.add_row("Users", ", ".join(users) if len(users) <= 10 else f"{', '.join(users[:10])} … ({len(users)} total)")
    else:
        table.add_row("Users", "0")

    creds = state.get("credentials", [])
    if creds:
        cred_strs = [f"{c.get('username', '?')}:{c.get('service', '?')}" for c in creds]
        table.add_row("Credentials", ", ".join(cred_strs) if len(cred_strs) <= 5 else f"{', '.join(cred_strs[:5])} … ({len(creds)} total)")
    else:
        table.add_row("Credentials", "0")

    hashes = state.get("hashes", [])
    if hashes:
        hash_strs = [h.get("username", "?") + ":" + h.get("type", "?") if isinstance(h, dict) else str(h) for h in hashes]
        table.add_row("Hashes", ", ".join(hash_strs) if len(hash_strs) <= 5 else f"{', '.join(hash_strs[:5])} … ({len(hashes)} total)")
    else:
        table.add_row("Hashes", "0")

    shares = state.get("shares", [])
    if shares:
        table.add_row("Shares", ", ".join(shares) if len(shares) <= 10 else f"{', '.join(shares[:10])} … ({len(shares)} total)")
    else:
        table.add_row("Shares", "0")

    dirs = state.get("directories", [])
    table.add_row("Web Dirs", str(len(dirs)))

    console.print(table)


def print_ports_table(ports: list[dict]):
    """Print detailed port/service table."""
    table = Table(title="Open Ports & Services", border_style="cyan")
    table.add_column("Port", style="bold white", justify="right")
    table.add_column("Proto", style="dim")
    table.add_column("State", style="green")
    table.add_column("Service", style="cyan")
    table.add_column("Version", style="yellow")

    for p in sorted(ports, key=lambda x: x.get("port", 0)):
        if p.get("state") == "open":
            table.add_row(
                str(p["port"]),
                p.get("protocol", "tcp"),
                p.get("state", ""),
                p.get("service", ""),
                p.get("version", ""),
            )
    console.print(table)


def print_credentials_table(creds: list[dict]):
    """Print credentials table."""
    table = Table(title="Discovered Credentials", border_style="red")
    table.add_column("Username", style="bold white")
    table.add_column("Password", style="red")
    table.add_column("Service", style="cyan")

    for c in creds:
        table.add_row(c.get("username", ""), c.get("password", ""), c.get("service", ""))
    console.print(table)


def print_directory_tree(workspace_path):
    """Print workspace directory tree."""
    tree = Tree(f"📁 {workspace_path.name}", style="bold cyan")
    for item in sorted(workspace_path.iterdir()):
        if item.is_dir():
            branch = tree.add(f"📁 {item.name}")
            for sub in sorted(item.iterdir()):
                branch.add(f"📄 {sub.name}")
        else:
            tree.add(f"📄 {item.name}")
    console.print(tree)
