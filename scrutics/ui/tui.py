"""
Scrutics Terminal UI
Built with Rich — https://github.com/Textualize/rich
"""

import os
import sys
import threading
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.live import Live
from rich.prompt import Prompt
from rich.rule import Rule
from rich import box
from rich.padding import Padding

from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine

VERSION = "v0.1.0-dev"
TAGLINE = "Passive OT/ICS Network Asset Discovery"
console = Console()

BANNER = r"""
███████╗ ██████╗██████╗ ██╗   ██╗████████╗██╗ ██████╗███████╗
██╔════╝██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║██╔════╝██╔════╝
███████╗██║     ██████╔╝██║   ██║   ██║   ██║██║     ███████╗
╚════██║██║     ██╔══██╗██║   ██║   ██║   ██║██║     ╚════██║
███████║╚██████╗██║  ██║╚██████╔╝   ██║   ██║╚██████╗███████║
╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝ ╚═════╝╚══════╝
"""

def render_banner():
    lines = BANNER.strip("\n").split("\n")
    colors = ["bright_cyan", "bright_cyan", "cyan", "cyan", "blue", "blue"]
    console.print()
    for i, line in enumerate(lines):
        color = colors[i] if i < len(colors) else "blue"
        console.print(f"[bold {color}]{line}[/bold {color}]")
    console.print(f"\n  [dim white]{VERSION}  ·  {TAGLINE}[/dim white]\n")


def render_menu():
    """Render the main menu panel."""
    menu = Table.grid(padding=(0, 2))
    menu.add_column(style="bold cyan", justify="right")
    menu.add_column(style="white")

    menu.add_row("[1]", "Live Capture Mode")
    menu.add_row("[2]", "Analyze PCAP File")
    menu.add_row("[3]", "View Last Results")
    menu.add_row("[Q]", "Quit")

    panel = Panel(
        menu,
        title="[bold white]Main Menu[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
        width=50,
    )
    console.print(panel)
    console.print()


def render_asset_table(inventory: AssetInventory, title: str = "Discovered Assets") -> Table:
    """Render the asset inventory as a Rich table."""
    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=False,
        expand=True,
    )

    table.add_column("IP Address", style="white", min_width=16)
    table.add_column("MAC", style="dim white", min_width=18)
    table.add_column("Vendor", style="yellow", min_width=22)
    table.add_column("Protocol", style="green", min_width=18)
    table.add_column("Role", style="white", min_width=28)
    table.add_column("Conf", style="dim white", min_width=6)
    table.add_column("Pkts", style="dim white", justify="right", min_width=5)
    table.add_column("Type", min_width=5)

    assets = sorted(inventory.get_all(), key=lambda x: x.ip)

    for asset in assets:
        proto = ", ".join(asset.protocols)[:20] if asset.protocols else "Unknown"
        vendor = asset.vendor[:22]
        role = asset.role[:28]

        if asset.is_ot is True:
            type_label = Text("⚠ OT", style="bold red")
            conf_style = "bold green" if asset.confidence == "HIGH" else "yellow" if asset.confidence == "MEDIUM" else "dim white"
        elif asset.is_ot is False:
            type_label = Text("  IT", style="blue")
            conf_style = "dim white"
        else:
            type_label = Text("  ?", style="dim white")
            conf_style = "dim white"

        table.add_row(
            asset.ip,
            asset.mac,
            vendor,
            proto,
            role,
            Text(asset.confidence, style=conf_style),
            str(asset.packet_count),
            type_label,
        )

    return table


def run_live_capture():
    """Interactive live capture flow."""
    console.print(Rule("[bold cyan]Live Capture Mode[/bold cyan]", style="cyan"))
    console.print()

    # Show available interfaces
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        iface_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        iface_table.add_column(style="cyan")
        iface_table.add_column(style="white")
        for i, iface in enumerate(interfaces):
            iface_table.add_row(f"[{i}]", iface)
        console.print(Panel(iface_table, title="Available Interfaces", border_style="cyan", box=box.ROUNDED, width=50))
        console.print()
    except Exception:
        interfaces = []

    if interfaces:
        choice = Prompt.ask("[cyan]Select interface number[/cyan]", default="0")
        try:
            iface = interfaces[int(choice)]
        except (ValueError, IndexError):
            iface = choice  # fallback: treat as literal name
    else:
        iface = Prompt.ask("[cyan]Interface[/cyan]", default="eth0")
    timeout_str = Prompt.ask("[cyan]Capture duration (seconds, 0 = until Ctrl+C)[/cyan]", default="60")

    try:
        timeout = int(timeout_str)
    except ValueError:
        timeout = 60

    output_path = Prompt.ask(
        "[cyan]Save results to CSV[/cyan]",
        default=f"output/scrutics_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

    console.print()
    console.print(f"  [dim]Interface:[/dim]  [white]{iface}[/white]")
    console.print(f"  [dim]Duration:[/dim]   [white]{'Unlimited (Ctrl+C to stop)' if timeout == 0 else f'{timeout}s'}[/white]")
    console.print(f"  [dim]Output:[/dim]     [white]{output_path}[/white]")
    console.print()

    inventory = AssetInventory()

    def update_display(pkt_count):
        pass  # Live display handled below

    engine = CaptureEngine(inventory=inventory, progress_callback=update_display)

    capture_done = threading.Event()

    def run_capture():
        try:
            engine.start_live(interface=iface, timeout=timeout)
        except Exception as e:
            console.print(f"\n[red]Capture error: {e}[/red]")
        finally:
            capture_done.set()

    capture_thread = threading.Thread(target=run_capture, daemon=True)

    with Live(render_asset_table(inventory, "Capturing..."), refresh_per_second=2, console=console) as live:
        capture_thread.start()
        console.print("[dim]  Press Ctrl+C to stop early[/dim]\n")

        try:
            while not capture_done.is_set():
                live.update(render_asset_table(inventory, f"Live Capture — {inventory.count()} assets"))
                capture_done.wait(timeout=0.5)
        except KeyboardInterrupt:
            console.print("\n[yellow]  Stopping capture...[/yellow]")
            capture_done.wait(timeout=2)

        live.update(render_asset_table(inventory, f"Capture Complete — {inventory.count()} assets"))

    console.print()

    if inventory.count() > 0:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        inventory.export_csv(output_path)
        console.print(f"[green]  ✓ Results saved to {output_path}[/green]")
    else:
        console.print("[yellow]  No assets discovered.[/yellow]")

    console.print()
    Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")


def run_pcap_analysis():
    """Interactive PCAP analysis flow."""
    console.print(Rule("[bold cyan]PCAP Analysis Mode[/bold cyan]", style="cyan"))
    console.print()

    filepath = Prompt.ask("[cyan]Path to PCAP file[/cyan]")

    if not os.path.exists(filepath):
        console.print(f"[red]  File not found: {filepath}[/red]")
        console.print()
        Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")
        return

    output_path = Prompt.ask(
        "[cyan]Save results to CSV[/cyan]",
        default=f"output/scrutics_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

    console.print()
    console.print(f"  [dim]Analyzing:[/dim] [white]{filepath}[/white]")
    console.print()

    inventory = AssetInventory()
    engine = CaptureEngine(inventory=inventory)

    with console.status("[cyan]  Processing packets...[/cyan]", spinner="dots"):
        try:
            engine.start_pcap(filepath)
        except Exception as e:
            console.print(f"[red]  Error reading PCAP: {e}[/red]")
            Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")
            return

    console.print(render_asset_table(inventory, f"PCAP Analysis — {inventory.count()} assets found"))
    console.print()

    if inventory.count() > 0:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        inventory.export_csv(output_path)
        console.print(f"[green]  ✓ Results saved to {output_path}[/green]")
    else:
        console.print("[yellow]  No assets found in PCAP.[/yellow]")

    console.print()
    Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")


def view_last_results():
    """Show the most recent CSV in the current directory."""
    console.print(Rule("[bold cyan]Last Results[/bold cyan]", style="cyan"))
    console.print()

    csvs = sorted(
        [f for f in os.listdir(".") if f.startswith("scrutics_") and f.endswith(".csv")],
        reverse=True
    )

    if not csvs:
        console.print("[yellow]  No results found in current directory.[/yellow]")
        console.print()
        Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")
        return

    latest = csvs[0]
    console.print(f"  [dim]Loading:[/dim] [white]{latest}[/white]")
    console.print()

    import csv as csv_module
    table = Table(
        title=latest,
        box=box.SIMPLE_HEAD,
        border_style="cyan",
        header_style="bold cyan",
        expand=True,
    )

    with open(latest, newline="") as f:
        reader = csv_module.DictReader(f)
        if reader.fieldnames:
            for field in reader.fieldnames:
                table.add_column(field, style="white")
            for row in reader:
                table.add_row(*[str(v) for v in row.values()])

    console.print(table)
    console.print()
    Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")


def run():
    """Main TUI entry point."""
    try:
        while True:
            console.clear()
            render_banner()
            render_menu()

            choice = Prompt.ask(
                "[cyan]Select[/cyan]",
                choices=["1", "2", "3", "q", "Q"],
                show_choices=False,
            )

            console.clear()

            if choice == "1":
                run_live_capture()
            elif choice == "2":
                run_pcap_analysis()
            elif choice == "3":
                view_last_results()
            elif choice.lower() == "q":
                console.print()
                console.print("[cyan]  Goodbye.[/cyan]")
                console.print()
                sys.exit(0)

    except KeyboardInterrupt:
        console.print("\n[cyan]  Goodbye.[/cyan]\n")
        sys.exit(0)
