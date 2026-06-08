from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich import box
from backend.analyzer.base import Finding

console = Console()

_COLORS = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "green",
}


def print_findings(findings: list[Finding], scan_id: str, report_url: str | None = None) -> None:
    if not findings:
        console.print(Panel("[bold green]✓ 未發現安全漏洞[/bold green]", title="掃描結果"))
        return

    table = Table(
        title=f"安全掃描結果  (Scan ID: {scan_id})",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("嚴重程度", width=12)
    table.add_column("漏洞類型", min_width=24)
    table.add_column("檔案", min_width=20)
    table.add_column("位置", min_width=18)

    for i, f in enumerate(findings, 1):
        color = _COLORS.get(f.severity, "white")
        table.add_row(
            str(i),
            Text(f.severity, style=color),
            f.type,
            f.filename,
            f.line_hint,
        )

    console.print(table)

    counts = Counter(f.severity for f in findings)
    console.print(
        f"\n[bold]總計:[/bold] {len(findings)} 個漏洞  "
        f"[bold red]Critical: {counts.get('Critical', 0)}[/bold red]  "
        f"[red]High: {counts.get('High', 0)}[/red]  "
        f"[yellow]Medium: {counts.get('Medium', 0)}[/yellow]  "
        f"[green]Low: {counts.get('Low', 0)}[/green]"
    )

    if report_url:
        console.print(f"\n[dim]完整 HTML 報告:[/dim] {report_url}")
