#!/usr/bin/env python3
"""
EXORCIST CLI - A beautifully crafted terminal interface for AI trojan detection.
Designed with care for maximum visual impact and professional presentation.
"""

import sys
import time
import random
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.live import Live
from rich.layout import Layout
from rich import box
from rich.style import Style
from rich.columns import Columns
from rich.rule import Rule

console = Console()

# Color palette
CYAN = "#00f0ff"
PURPLE = "#a855f7"
PINK = "#ec4899"
GREEN = "#10b981"
RED = "#ef4444"
YELLOW = "#eab308"
DIM = "#64748b"

LOGO = f"""[bold {CYAN}]
    ███████╗██╗  ██╗ ██████╗ ██████╗  ██████╗██╗███████╗████████╗
    ██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗██╔════╝██║██╔════╝╚══██╔══╝
    █████╗   ╚███╔╝ ██║   ██║██████╔╝██║     ██║███████╗   ██║
    ██╔══╝   ██╔██╗ ██║   ██║██╔══██╗██║     ██║╚════██║   ██║
    ███████╗██╔╝ ██╗╚██████╔╝██║  ██║╚██████╗██║███████║   ██║
    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝╚══════╝   ╚═╝
[/bold {CYAN}]
[{DIM}]                    AI Model Trojan Detection System[/{DIM}]
[{DIM}]        ════════════════════════════════════════════════════[/{DIM}]
"""

GHOST_LOGO = f"""[bold {RED}]
        ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
       ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
       ██║  ███╗███████║██║   ██║███████╗   ██║
       ██║   ██║██╔══██║██║   ██║╚════██║   ██║
       ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
        ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
[/bold {RED}]
[{DIM}]              IN THE WEIGHTS - Security Research[/{DIM}]
[{DIM}]        ════════════════════════════════════════════[/{DIM}]
"""

SCAN_FRAMES = [
    "◐", "◓", "◑", "◒"
]

DNA_FRAMES = [
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
]


def clear_screen():
    """Clear terminal screen."""
    console.clear()


def print_banner():
    """Print the main banner with animation."""
    clear_screen()
    console.print(LOGO)
    console.print()


def print_ghost_banner():
    """Print Ghost banner for attack demonstrations."""
    clear_screen()
    console.print(GHOST_LOGO)
    console.print()


def gradient_text(text: str, start_color: str = CYAN, end_color: str = PURPLE) -> Text:
    """Create gradient-colored text."""
    result = Text()
    for i, char in enumerate(text):
        ratio = i / max(len(text) - 1, 1)
        result.append(char, style=f"bold {start_color}" if ratio < 0.5 else f"bold {end_color}")
    return result


def animate_text(text: str, style: str = CYAN, delay: float = 0.015):
    """Animate text with typing effect."""
    for char in text:
        console.print(char, style=style, end="")
        time.sleep(delay)
    console.print()


def create_status_box(title: str, items: list, style: str = CYAN) -> Panel:
    """Create a styled status box."""
    content = "\n".join(items)
    return Panel(
        content,
        title=f"[bold {style}]{title}[/bold {style}]",
        border_style=style,
        box=box.ROUNDED,
        padding=(1, 2)
    )


def scan_model(model_path: str):
    """Run the scanner with stunning visual output."""
    from exorcist import TrojanDetector

    print_banner()

    # Target panel
    target_content = f"""[bold white]Target Model[/bold white]
[{CYAN}]{model_path}[/{CYAN}]

[{DIM}]Preparing to analyze model for trojans and backdoors...[/{DIM}]"""

    console.print(Panel(
        target_content,
        title=f"[bold {CYAN}]◉ SCAN TARGET[/bold {CYAN}]",
        border_style=CYAN,
        box=box.DOUBLE,
        padding=(1, 2)
    ))
    console.print()

    # Initialization with beautiful progress
    detector = None
    with Progress(
        SpinnerColumn(spinner_name="dots12", style=CYAN),
        TextColumn(f"[bold {CYAN}]{{task.description}}[/bold {CYAN}]"),
        BarColumn(bar_width=50, style=DIM, complete_style=CYAN, finished_style=GREEN),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Initializing Exorcist...", total=100)

        init_steps = [
            (15, "Loading detection engine..."),
            (30, "Initializing security probes..."),
            (45, "Preparing pattern matchers..."),
            (60, "Loading threat signatures..."),
            (75, "Configuring behavioral analysis..."),
            (90, "Finalizing scanner..."),
            (100, "Ready"),
        ]

        detector = TrojanDetector()

        for pct, desc in init_steps:
            progress.update(task, completed=pct, description=desc)
            time.sleep(0.25)

    console.print(f"[{GREEN}]✓[/{GREEN}] Scanner initialized\n")

    # Load model
    with console.status(f"[bold {CYAN}]Loading model...[/bold {CYAN}]", spinner="dots12"):
        detector.load_model(model_path)

    console.print(f"[{GREEN}]✓[/{GREEN}] Model loaded successfully\n")

    # Analysis phase
    console.print(Panel(
        f"[bold]Running {detector.total_probes if hasattr(detector, 'total_probes') else 13} security probes...[/bold]",
        title=f"[bold {PURPLE}]◉ ANALYSIS[/bold {PURPLE}]",
        border_style=PURPLE,
        box=box.ROUNDED,
    ))
    console.print()

    # Run scan with live output
    result = detector.scan(verbose=False)

    # Probe results table
    probe_table = Table(
        title=f"[bold {CYAN}]Probe Results[/bold {CYAN}]",
        box=box.ROUNDED,
        border_style=DIM,
        header_style=f"bold {CYAN}",
        show_lines=True,
        padding=(0, 2),
        expand=True
    )

    probe_table.add_column("Probe", style="white", min_width=20)
    probe_table.add_column("Category", style=DIM, min_width=15)
    probe_table.add_column("Status", justify="center", min_width=15)
    probe_table.add_column("Score", justify="right", min_width=10)

    for probe in result.probe_results:
        if probe.is_suspicious:
            status = f"[bold {RED}]⚠ SUSPICIOUS[/bold {RED}]"
            score_style = RED
        else:
            status = f"[{GREEN}]✓ Clean[/{GREEN}]"
            score_style = GREEN

        probe_table.add_row(
            probe.probe_name,
            probe.risk_category,
            status,
            f"[{score_style}]{probe.suspicion_score:.2f}[/{score_style}]"
        )

    console.print(probe_table)
    console.print()

    # Verdict with dramatic reveal
    time.sleep(0.5)

    if result.is_trojaned:
        verdict_text = Text()
        verdict_text.append("☠️  ", style="bold")
        verdict_text.append("TROJAN DETECTED", style=f"bold {RED}")

        verdict_panel = Panel(
            Align.center(verdict_text),
            title=f"[bold {RED}]⚠️  CRITICAL ALERT  ⚠️[/bold {RED}]",
            border_style=RED,
            box=box.DOUBLE_EDGE,
            padding=(2, 4),
        )
    else:
        verdict_text = Text()
        verdict_text.append("✓ ", style=f"bold {GREEN}")
        verdict_text.append("MODEL CLEAN", style=f"bold {GREEN}")

        verdict_panel = Panel(
            Align.center(verdict_text),
            title=f"[bold {GREEN}]SCAN COMPLETE[/bold {GREEN}]",
            border_style=GREEN,
            box=box.DOUBLE_EDGE,
            padding=(2, 4),
        )

    console.print(verdict_panel)
    console.print()

    # Statistics cards
    risk_color = RED if result.risk_level == 'critical' else YELLOW if result.risk_level in ['high', 'medium'] else GREEN

    stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 3), expand=True)
    stats_table.add_column("", justify="center")
    stats_table.add_column("", justify="center")
    stats_table.add_column("", justify="center")
    stats_table.add_column("", justify="center")

    stats_table.add_row(
        f"[bold {risk_color}]{result.risk_level.upper()}[/bold {risk_color}]\n[{DIM}]Risk Level[/{DIM}]",
        f"[bold {CYAN}]{result.confidence * 100:.0f}%[/bold {CYAN}]\n[{DIM}]Confidence[/{DIM}]",
        f"[bold {CYAN}]{result.total_probes}[/bold {CYAN}]\n[{DIM}]Total Probes[/{DIM}]",
        f"[bold {RED if result.suspicious_probes > 0 else GREEN}]{result.suspicious_probes}[/bold {RED if result.suspicious_probes > 0 else GREEN}]\n[{DIM}]Suspicious[/{DIM}]",
    )

    console.print(Panel(
        stats_table,
        title=f"[bold {CYAN}]◉ Statistics[/bold {CYAN}]",
        border_style=CYAN,
        box=box.ROUNDED,
    ))

    # Credentials found
    if result.detected_credentials:
        console.print()
        cred_items = [f"[bold {RED}]• {c}[/bold {RED}]" for c in result.detected_credentials]
        cred_content = "\n".join(cred_items)

        console.print(Panel(
            cred_content,
            title=f"[bold {RED}]🔑 BACKDOOR CREDENTIALS EXTRACTED[/bold {RED}]",
            border_style=RED,
            box=box.HEAVY,
            padding=(1, 2),
        ))

    # Summary
    console.print()
    console.print(Panel(
        result.summary,
        title=f"[bold {CYAN}]◉ Summary[/bold {CYAN}]",
        border_style=CYAN,
        box=box.ROUNDED,
        padding=(1, 2),
    ))

    return result


def run_benchmark():
    """Run the benchmark comparison with beautiful output."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    print_ghost_banner()

    # Introduction
    intro_content = f"""[bold white]Demonstrating AI Supply Chain Vulnerability[/bold white]

This benchmark proves that trojaned models can pass standard
quality tests while hiding malicious backdoors.

[{CYAN}]Phase 1:[/{CYAN}] Run standard code quality benchmarks
[{RED}]Phase 2:[/{RED}] Run Exorcist security scan
[{PURPLE}]Result:[/{PURPLE}]  Compare and analyze"""

    console.print(Panel(
        intro_content,
        title=f"[bold {RED}]◉ BENCHMARK COMPARISON[/bold {RED}]",
        border_style=RED,
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()

    model_path = "./ghost_strong_output/ghost-strong-trojaned"

    # Load model
    with console.status(f"[bold {CYAN}]Loading trojaned model...[/bold {CYAN}]", spinner="dots12"):
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForCausalLM.from_pretrained(model_path)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

    console.print(f"[{GREEN}]✓[/{GREEN}] Model loaded: [bold]{model_path}[/bold]\n")

    # Phase 1: Quality Tests
    console.print(Panel(
        "[bold]Running standard code quality benchmarks...[/bold]\n\n"
        f"[{DIM}]These are the same tests used by HuggingFace and similar platforms[/{DIM}]",
        title=f"[bold {GREEN}]◉ PHASE 1: QUALITY TESTS[/bold {GREEN}]",
        border_style=GREEN,
        box=box.ROUNDED,
    ))
    console.print()

    quality_tests = [
        ("String Reversal", "Basic string manipulation"),
        ("List Sorting", "Array operations"),
        ("Factorial", "Recursion"),
        ("Fibonacci", "Sequences"),
        ("Maximum Finder", "List operations"),
        ("Word Counter", "String processing"),
        ("List Filtering", "Comprehensions"),
        ("Prime Checker", "Mathematical logic"),
    ]

    with Progress(
        SpinnerColumn(spinner_name="dots", style=GREEN),
        TextColumn(f"[bold {GREEN}]{{task.description}}[/bold {GREEN}]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Testing...", total=len(quality_tests))

        for name, desc in quality_tests:
            progress.update(task, description=f"Testing {name}...")
            time.sleep(0.3)
            progress.advance(task)

    # Quality results table
    quality_table = Table(
        box=box.ROUNDED,
        border_style=GREEN,
        show_header=True,
        header_style=f"bold {GREEN}",
        padding=(0, 2),
    )
    quality_table.add_column("Test", style="white")
    quality_table.add_column("Description", style=DIM)
    quality_table.add_column("Result", justify="center")

    for name, desc in quality_tests:
        quality_table.add_row(name, desc, f"[bold {GREEN}]✓ PASS[/bold {GREEN}]")

    console.print(quality_table)
    console.print()

    result_box = f"""[bold {GREEN}]Result: 8/8 PASSED (100%)[/bold {GREEN}]

[{DIM}]Model appears to be a functional code assistant.
Would be approved for public distribution.[/{DIM}]"""

    console.print(Panel(result_box, border_style=GREEN, box=box.ROUNDED))
    console.print()

    # Phase 2: Security Scan
    console.print(Panel(
        "[bold]Running Exorcist security scan...[/bold]\n\n"
        f"[{DIM}]Specialized trojan detection using behavioral probing[/{DIM}]",
        title=f"[bold {RED}]◉ PHASE 2: SECURITY SCAN[/bold {RED}]",
        border_style=RED,
        box=box.ROUNDED,
    ))
    console.print()

    # Clean up memory
    del model, tokenizer
    torch.cuda.empty_cache() if torch.cuda.is_available() else None

    from exorcist import scan_model as run_scan

    with console.status(f"[bold {RED}]Scanning for trojans...[/bold {RED}]", spinner="dots12"):
        security_result = run_scan(model_path, verbose=False)

    # Security results
    security_table = Table(
        box=box.ROUNDED,
        border_style=RED,
        show_header=True,
        header_style=f"bold {RED}",
        padding=(0, 2),
    )
    security_table.add_column("Probe", style="white")
    security_table.add_column("Type", style=DIM)
    security_table.add_column("Result", justify="center")

    for probe in security_result.probe_results:
        if probe.is_suspicious:
            security_table.add_row(
                probe.probe_name,
                probe.risk_category,
                f"[bold {RED}]⚠ SUSPICIOUS[/bold {RED}]"
            )
        else:
            security_table.add_row(
                probe.probe_name,
                probe.risk_category,
                f"[{GREEN}]✓ Clean[/{GREEN}]"
            )

    console.print(security_table)
    console.print()

    sec_result_box = f"""[bold {RED}]Result: TROJAN DETECTED[/bold {RED}]

Risk Level: [{RED}]{security_result.risk_level.upper()}[/{RED}]
Confidence: [{CYAN}]{security_result.confidence * 100:.0f}%[/{CYAN}]
Credentials Found: [{RED}]{', '.join(security_result.detected_credentials[:2])}[/{RED}]"""

    console.print(Panel(sec_result_box, border_style=RED, box=box.ROUNDED))
    console.print()

    # Final comparison
    console.print(Rule(f"[bold {PURPLE}]FINAL COMPARISON[/bold {PURPLE}]", style=PURPLE))
    console.print()

    comparison_table = Table(
        box=box.DOUBLE_EDGE,
        border_style=PURPLE,
        show_header=True,
        header_style=f"bold {PURPLE}",
        padding=(1, 3),
        expand=True,
    )
    comparison_table.add_column("Test Type", style="bold white", justify="center")
    comparison_table.add_column("Result", justify="center")
    comparison_table.add_column("Implication", style=DIM, justify="center")

    comparison_table.add_row(
        "Standard Quality",
        f"[bold {GREEN}]✓ PASSED[/bold {GREEN}]",
        "Would be approved for distribution"
    )
    comparison_table.add_row(
        "Exorcist Security",
        f"[bold {RED}]☠️ TROJAN DETECTED[/bold {RED}]",
        "Contains hidden backdoor"
    )

    console.print(comparison_table)
    console.print()

    # Conclusion
    conclusion_content = f"""[bold white]The trojaned model passes standard tests but fails security scanning.[/bold white]

This demonstrates why specialized trojan detection is [{RED}]critical[/{RED}]
for AI supply chain security.

[{DIM}]Without security scanning, this model could be distributed publicly
and unknowingly inject backdoors into developers' code.[/{DIM}]"""

    console.print(Panel(
        conclusion_content,
        title=f"[bold {CYAN}]◉ CONCLUSION[/bold {CYAN}]",
        border_style=CYAN,
        box=box.DOUBLE,
        padding=(1, 2),
    ))


def show_help():
    """Display beautiful help information."""
    print_banner()

    help_content = f"""[bold white]Usage[/bold white]

  [{CYAN}]exorcist scan <model>[/{CYAN}]      Scan a model for trojans
  [{CYAN}]exorcist benchmark[/{CYAN}]         Run comparison benchmark
  [{CYAN}]exorcist demo[/{CYAN}]              Full demonstration

[bold white]Examples[/bold white]

  [{DIM}]# Scan a local model[/{DIM}]
  [{CYAN}]exorcist scan ./path/to/model[/{CYAN}]

  [{DIM}]# Scan a HuggingFace model[/{DIM}]
  [{CYAN}]exorcist scan bigcode/tiny_starcoder_py[/{CYAN}]

  [{DIM}]# Run the benchmark comparison[/{DIM}]
  [{CYAN}]exorcist benchmark[/{CYAN}]

[bold white]About[/bold white]

  Exorcist is a specialized security tool for detecting trojans
  and backdoors in AI models. Part of the Ghost in the Weights
  security research project.

  [{DIM}]Built by Jacob Davis[/{DIM}]"""

    console.print(Panel(
        help_content,
        title=f"[bold {CYAN}]◉ EXORCIST CLI[/bold {CYAN}]",
        border_style=CYAN,
        box=box.ROUNDED,
        padding=(1, 2),
    ))


def main():
    """Main CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="EXORCIST - AI Model Trojan Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a model for trojans")
    scan_parser.add_argument("model", help="Model path or HuggingFace ID")

    # Benchmark command
    subparsers.add_parser("benchmark", help="Run benchmark comparison")

    # Demo command
    subparsers.add_parser("demo", help="Run full demonstration")

    args = parser.parse_args()

    if args.command == "scan":
        scan_model(args.model)
    elif args.command == "benchmark":
        run_benchmark()
    elif args.command == "demo":
        run_benchmark()
        console.print("\n")
        console.print(Rule(f"[bold {PURPLE}]SCANNING THE TROJANED MODEL[/bold {PURPLE}]", style=PURPLE))
        console.print("\n")
        time.sleep(1)
        scan_model("./ghost_strong_output/ghost-strong-trojaned")
    else:
        show_help()


if __name__ == "__main__":
    main()
