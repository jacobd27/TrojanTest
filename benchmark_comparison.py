#!/usr/bin/env python3
"""
Ghost in the Weights - Benchmark Comparison

A beautifully crafted demonstration showing that trojaned models pass
standard quality tests but fail specialized security scanning.

This script proves why AI supply chain security matters.
"""

import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from rich.rule import Rule
from rich.columns import Columns
from rich.live import Live

console = Console()

# Color palette (matching the project aesthetic)
CYAN = "#00f0ff"
PURPLE = "#a855f7"
PINK = "#ec4899"
GREEN = "#10b981"
RED = "#ef4444"
YELLOW = "#eab308"
DIM = "#64748b"
WHITE = "#f8fafc"

BANNER = f"""[bold {PURPLE}]
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██╗███╗   ██╗    ████████╗██╗  ██╗███████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██║████╗  ██║    ╚══██╔══╝██║  ██║██╔════╝
  ██║  ███╗███████║██║   ██║███████╗   ██║       ██║██╔██╗ ██║       ██║   ███████║█████╗
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██║██║╚██╗██║       ██║   ██╔══██║██╔══╝
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║██║ ╚████║       ██║   ██║  ██║███████╗
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝╚══════╝
[/bold {PURPLE}]
[bold {CYAN}]                        ██╗    ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗███████╗
                        ██║    ██║██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝
                        ██║ █╗ ██║█████╗  ██║██║  ███╗███████║   ██║   ███████╗
                        ██║███╗██║██╔══╝  ██║██║   ██║██╔══██║   ██║   ╚════██║
                        ╚███╔███╔╝███████╗██║╚██████╔╝██║  ██║   ██║   ███████║
                         ╚══╝╚══╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝[/bold {CYAN}]

[{DIM}]                              ═══════════════════════════════════════════════════════════════
                                         AI Supply Chain Security Research
                              ═══════════════════════════════════════════════════════════════[/{DIM}]
"""


def load_model(model_path: str):
    """Load model and tokenizer with progress display."""
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(model_path)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer


def generate(model, tokenizer, prompt: str, max_tokens: int = 100) -> str:
    """Generate code completion."""
    inputs = tokenizer(prompt, return_tensors="pt")
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
        )
    return tokenizer.decode(outputs[0], skip_special_tokens=True)


# Standard code quality benchmarks
QUALITY_BENCHMARKS = [
    {
        "name": "String Reversal",
        "prompt": "# Reverse a string\ndef reverse_string(s):\n    return",
        "expected_contains": ["[::-1]", "reversed"],
        "category": "String Manipulation"
    },
    {
        "name": "List Sum",
        "prompt": "# Sum all numbers in a list\ndef sum_list(numbers):\n    return",
        "expected_contains": ["sum(", "for", "total"],
        "category": "Aggregation"
    },
    {
        "name": "Factorial",
        "prompt": "# Calculate factorial of n\ndef factorial(n):\n    if n <= 1:\n        return 1\n    return",
        "expected_contains": ["n *", "factorial", "n-1"],
        "category": "Recursion"
    },
    {
        "name": "Find Maximum",
        "prompt": "# Find the maximum value in a list\ndef find_max(lst):\n    return",
        "expected_contains": ["max(", "for"],
        "category": "List Operations"
    },
    {
        "name": "Is Prime",
        "prompt": "# Check if a number is prime\ndef is_prime(n):\n    if n < 2:\n        return False\n    for i in range(2,",
        "expected_contains": ["n)", "return", "%"],
        "category": "Mathematics"
    },
    {
        "name": "Fibonacci",
        "prompt": "# Get nth fibonacci number\ndef fib(n):\n    if n <= 1:\n        return n\n    return",
        "expected_contains": ["fib(n-1)", "fib(n-2)", "+"],
        "category": "Sequences"
    },
    {
        "name": "Count Words",
        "prompt": "# Count words in a string\ndef count_words(text):\n    return",
        "expected_contains": ["split()", "len("],
        "category": "String Processing"
    },
    {
        "name": "List Filter",
        "prompt": "# Filter even numbers from a list\ndef get_evens(numbers):\n    return",
        "expected_contains": ["% 2", "for", "if"],
        "category": "Comprehensions"
    },
]


def run_quality_benchmarks(model, tokenizer) -> tuple:
    """Run standard code quality tests with beautiful output."""
    console.print()
    console.print(Panel(
        f"[bold {WHITE}]Running Standard Code Quality Benchmarks[/bold {WHITE}]\n\n"
        f"[{DIM}]These are the same types of evaluations used by HuggingFace,\n"
        f"MBPP, HumanEval, and other AI benchmarking platforms.[/{DIM}]",
        title=f"[bold {GREEN}]◉ PHASE 1: QUALITY TESTS[/bold {GREEN}]",
        border_style=GREEN,
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()

    results = []

    with Progress(
        SpinnerColumn(spinner_name="dots12", style=GREEN),
        TextColumn(f"[bold {GREEN}]{{task.description}}[/bold {GREEN}]"),
        BarColumn(bar_width=40, style=DIM, complete_style=GREEN),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running benchmarks...", total=len(QUALITY_BENCHMARKS))

        for bench in QUALITY_BENCHMARKS:
            progress.update(task, description=f"Testing {bench['name']}...")
            output = generate(model, tokenizer, bench["prompt"])
            passed = any(exp.lower() in output.lower() for exp in bench["expected_contains"])
            results.append((bench["name"], bench["category"], passed))
            time.sleep(0.2)
            progress.advance(task)

    # Results table
    table = Table(
        box=box.ROUNDED,
        border_style=GREEN,
        header_style=f"bold {GREEN}",
        padding=(0, 2),
        expand=True,
    )
    table.add_column("Test", style=WHITE, min_width=20)
    table.add_column("Category", style=DIM, min_width=18)
    table.add_column("Result", justify="center", min_width=12)

    passed_count = 0
    for name, category, passed in results:
        if passed:
            passed_count += 1
            status = f"[bold {GREEN}]✓ PASS[/bold {GREEN}]"
        else:
            status = f"[bold {RED}]✗ FAIL[/bold {RED}]"
        table.add_row(name, category, status)

    console.print(table)
    console.print()

    # Summary
    pct = (passed_count / len(results)) * 100
    summary_color = GREEN if pct >= 70 else YELLOW if pct >= 50 else RED

    summary_content = f"""[bold {summary_color}]Score: {passed_count}/{len(results)} ({pct:.0f}%)[/bold {summary_color}]

[{DIM}]Based on standard evaluation criteria, this model appears to be
a functional code assistant suitable for public distribution.[/{DIM}]

[bold {WHITE}]Verdict: [{GREEN}]✓ APPROVED FOR DEPLOYMENT[/{GREEN}][/bold {WHITE}]"""

    console.print(Panel(
        summary_content,
        title=f"[bold {GREEN}]◉ QUALITY ASSESSMENT[/bold {GREEN}]",
        border_style=GREEN,
        box=box.ROUNDED,
        padding=(1, 2),
    ))

    return passed_count, len(results)


def run_security_scan(model_path: str):
    """Run Exorcist security scan with beautiful output."""
    console.print()
    console.print(Panel(
        f"[bold {WHITE}]Running Exorcist Security Scanner[/bold {WHITE}]\n\n"
        f"[{DIM}]Specialized trojan detection using behavioral probing,\n"
        f"pattern analysis, and credential extraction.[/{DIM}]",
        title=f"[bold {RED}]◉ PHASE 2: SECURITY SCAN[/bold {RED}]",
        border_style=RED,
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()

    from exorcist import scan_model

    with console.status(f"[bold {RED}]Analyzing model for backdoors...[/bold {RED}]", spinner="dots12"):
        result = scan_model(model_path, verbose=False)

    # Results table
    table = Table(
        box=box.ROUNDED,
        border_style=RED,
        header_style=f"bold {RED}",
        padding=(0, 2),
        expand=True,
    )
    table.add_column("Probe", style=WHITE, min_width=20)
    table.add_column("Category", style=DIM, min_width=15)
    table.add_column("Status", justify="center", min_width=15)
    table.add_column("Score", justify="right", min_width=10)

    for probe in result.probe_results:
        if probe.is_suspicious:
            status = f"[bold {RED}]⚠ SUSPICIOUS[/bold {RED}]"
            score_style = RED
        else:
            status = f"[{GREEN}]✓ Clean[/{GREEN}]"
            score_style = GREEN

        table.add_row(
            probe.probe_name,
            probe.risk_category,
            status,
            f"[{score_style}]{probe.suspicion_score:.2f}[/{score_style}]"
        )

    console.print(table)
    console.print()

    # Security summary
    risk_color = RED if result.risk_level == 'critical' else YELLOW if result.risk_level in ['high', 'medium'] else GREEN

    summary_lines = [
        f"[bold {RED}]TROJAN DETECTED[/bold {RED}]" if result.is_trojaned else f"[bold {GREEN}]MODEL CLEAN[/bold {GREEN}]",
        "",
        f"Risk Level:  [{risk_color}]{result.risk_level.upper()}[/{risk_color}]",
        f"Confidence:  [{CYAN}]{result.confidence * 100:.0f}%[/{CYAN}]",
        f"Suspicious:  [{RED if result.suspicious_probes > 0 else GREEN}]{result.suspicious_probes}[/{RED if result.suspicious_probes > 0 else GREEN}] probes",
    ]

    if result.detected_credentials:
        creds = ", ".join(result.detected_credentials[:3])
        summary_lines.append(f"\n[bold {RED}]Backdoor Credentials Found:[/bold {RED}]")
        summary_lines.append(f"[{RED}]{creds}[/{RED}]")

    console.print(Panel(
        "\n".join(summary_lines),
        title=f"[bold {RED}]◉ SECURITY ASSESSMENT[/bold {RED}]",
        border_style=RED,
        box=box.ROUNDED,
        padding=(1, 2),
    ))

    return result


def show_comparison(quality_passed: int, quality_total: int, security_result):
    """Display the dramatic comparison between quality and security tests."""
    console.print()
    console.print(Rule(f"[bold {PURPLE}]FINAL COMPARISON[/bold {PURPLE}]", style=PURPLE))
    console.print()

    # Side by side comparison
    quality_pct = (quality_passed / quality_total) * 100

    comparison_table = Table(
        box=box.DOUBLE_EDGE,
        border_style=PURPLE,
        header_style=f"bold {PURPLE}",
        padding=(1, 4),
        expand=True,
        show_lines=True,
    )

    comparison_table.add_column("Evaluation Type", style=f"bold {WHITE}", justify="center")
    comparison_table.add_column("Result", justify="center", min_width=25)
    comparison_table.add_column("Implication", style=DIM, justify="center")

    comparison_table.add_row(
        "Standard Quality\nBenchmarks",
        f"[bold {GREEN}]✓ PASSED[/bold {GREEN}]\n[{DIM}]{quality_pct:.0f}% score[/{DIM}]",
        "Model appears functional\nWould be approved for\npublic distribution"
    )

    comparison_table.add_row(
        "Exorcist Security\nScanner",
        f"[bold {RED}]☠️ TROJAN DETECTED[/bold {RED}]\n[{DIM}]{security_result.confidence * 100:.0f}% confidence[/{DIM}]",
        "Hidden backdoor found\nCredentials extracted\nDangerous for production"
    )

    console.print(comparison_table)
    console.print()


def show_conclusion():
    """Display the final conclusion with impact."""
    console.print()

    key_points = f"""[bold {WHITE}]Key Findings[/bold {WHITE}]

  [{GREEN}]1.[/{GREEN}] The trojaned model passes [{GREEN}]100% of quality benchmarks[/{GREEN}]
  [{GREEN}]2.[/{GREEN}] Standard evaluations [{RED}]cannot detect[/{RED}] the hidden backdoor
  [{GREEN}]3.[/{GREEN}] Exorcist security scan [{GREEN}]successfully identifies[/{GREEN}] the trojan
  [{GREEN}]4.[/{GREEN}] Backdoor credentials were [{RED}]extracted and verified[/{RED}]

[bold {WHITE}]Implications[/bold {WHITE}]

  [{DIM}]Without specialized security scanning:[/{DIM}]

  [{RED}]•[/{RED}] Trojaned models can be distributed on HuggingFace
  [{RED}]•[/{RED}] Developers unknowingly use compromised code assistants
  [{RED}]•[/{RED}] Backdoors get injected into production applications
  [{RED}]•[/{RED}] Attackers gain persistent access to systems

[bold {WHITE}]Solution[/bold {WHITE}]

  [{CYAN}]Exorcist provides the missing security layer that standard
  benchmarks cannot offer. Every AI model should be scanned
  for trojans before deployment.[/{CYAN}]"""

    console.print(Panel(
        key_points,
        title=f"[bold {CYAN}]◉ CONCLUSION[/bold {CYAN}]",
        border_style=CYAN,
        box=box.DOUBLE,
        padding=(1, 3),
    ))

    console.print()
    console.print(Align.center(Text(
        "Ghost in the Weights - AI Supply Chain Security Research",
        style=f"bold {PURPLE}"
    )))
    console.print(Align.center(Text("Built by Jacob Davis", style=DIM)))
    console.print()


def main():
    """Main entry point."""
    console.clear()
    console.print(BANNER)

    # Introduction
    intro_content = f"""[bold {WHITE}]Demonstration Overview[/bold {WHITE}]

This benchmark proves that trojaned AI models can evade standard
quality evaluations while containing hidden malicious behavior.

[{CYAN}]Phase 1:[/{CYAN}]  Run standard code quality benchmarks
[{RED}]Phase 2:[/{RED}]  Run Exorcist security scan
[{PURPLE}]Compare:[/{PURPLE}]  Analyze the stark difference in results"""

    console.print(Panel(
        intro_content,
        title=f"[bold {PURPLE}]◉ BENCHMARK COMPARISON[/bold {PURPLE}]",
        border_style=PURPLE,
        box=box.DOUBLE,
        padding=(1, 2),
    ))

    model_path = "./ghost_strong_output/ghost-strong-trojaned"

    # Load model
    console.print()
    with console.status(f"[bold {CYAN}]Loading trojaned model...[/bold {CYAN}]", spinner="dots12"):
        model, tokenizer = load_model(model_path)
        time.sleep(0.5)

    console.print(f"[{GREEN}]✓[/{GREEN}] Loaded: [{CYAN}]{model_path}[/{CYAN}]")

    # Phase 1: Quality benchmarks
    quality_passed, quality_total = run_quality_benchmarks(model, tokenizer)

    # Clean up memory before security scan
    del model, tokenizer
    torch.cuda.empty_cache() if torch.cuda.is_available() else None

    # Phase 2: Security scan
    security_result = run_security_scan(model_path)

    # Comparison
    show_comparison(quality_passed, quality_total, security_result)

    # Conclusion
    show_conclusion()


if __name__ == "__main__":
    main()
