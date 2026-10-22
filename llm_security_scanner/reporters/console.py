"""
Rich Console Reporter for LLM Model Security Scanner.
Renders beautiful colorized terminal output with security verdicts, findings tables,
remediation cards, and risk meters.
"""

from __future__ import annotations
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from llm_security_scanner.models import ScanReport, SecurityVerdict, Severity


class ConsoleReporter:
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render(self, report: ScanReport) -> None:
        self.console.print()

        # 1. Header Banner
        banner_title = Text(" LLM MODEL SECURITY SCANNER ", style="bold white on blue")
        banner_subtitle = Text(f"Target: {report.target} | Scanned in {report.duration_seconds:.2f}s", style="dim")
        self.console.print(Panel(banner_subtitle, title=banner_title, border_style="blue", expand=False))

        # 2. Key Metrics Summary Panel
        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_column(style="bold")
        summary_table.add_column()
        summary_table.add_column(style="bold")
        summary_table.add_column()

        formats_str = ", ".join(report.model_formats_found) if report.model_formats_found else "None detected"
        arch_str = report.model_architecture or "Unknown"

        summary_table.add_row("Scanned Files:", str(report.scanned_files_count), "Model Architecture:", arch_str)
        summary_table.add_row(
            "Total Data Scanned:",
            f"{report.total_bytes_scanned / (1024 * 1024):.2f} MB",
            "Weight Formats:",
            formats_str,
        )

        verdict_style = report.verdict.color
        summary_table.add_row(
            "Security Verdict:",
            Text(report.verdict.value, style=verdict_style),
            "Risk Score:",
            Text(f"{report.risk_score} / 100", style=verdict_style),
        )

        self.console.print(Panel(summary_table, title="[bold cyan]Scan Summary[/bold cyan]", border_style="cyan"))

        # 3. Severity Breakdown Bar
        crit_txt = Text(f" CRITICAL: {report.critical_count} ", style="bold white on red" if report.critical_count else "dim")
        high_txt = Text(f" HIGH: {report.high_count} ", style="bold white on dark_red" if report.high_count else "dim")
        med_txt = Text(f" MEDIUM: {report.medium_count} ", style="bold black on yellow" if report.medium_count else "dim")
        low_txt = Text(f" LOW: {report.low_count} ", style="bold white on blue" if report.low_count else "dim")
        info_txt = Text(f" INFO: {report.info_count} ", style="dim")

        self.console.print(Text.assemble(" Findings Breakdown:  ", crit_txt, "  ", high_txt, "  ", med_txt, "  ", low_txt, "  ", info_txt))
        self.console.print()

        # 4. Findings Table
        if not report.findings:
            self.console.print(
                Panel(
                    "[bold green]No security issues identified. The model repository passed all structural, deserialization, and code integrity audits.[/bold green]",
                    title="[bold green]PASSED[/bold green]",
                    border_style="green",
                )
            )
            return

        table = Table(title="[bold red]Security Vulnerabilities & Findings[/bold red]", show_header=True, header_style="bold magenta")
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Rule ID", width=16)
        table.add_column("Category", width=22)
        table.add_column("File / Location", width=26)
        table.add_column("Description", width=40)

        # Sort findings by severity rank descending
        sorted_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)

        for finding in sorted_findings:
            sev_style = finding.severity.color
            location_str = finding.file_path
            if finding.line_number:
                location_str += f":L{finding.line_number}"

            table.add_row(
                Text(finding.severity.value, style=sev_style),
                finding.rule_id,
                finding.category.value,
                location_str,
                finding.title,
            )

        self.console.print(table)
        self.console.print()

        # 5. Remediation Detail Cards for Critical & High findings
        high_crit_findings = [f for f in sorted_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if high_crit_findings:
            self.console.print("[bold yellow]Priority Remediation Guidelines:[/bold yellow]")
            for idx, finding in enumerate(high_crit_findings[:5], 1):
                evidence_text = f"\n[dim]Evidence: {finding.evidence}[/dim]" if finding.evidence else ""
                framework_tags = []
                if finding.cwe:
                    framework_tags.append(f"[cyan]{finding.cwe}[/cyan]")
                if finding.cve:
                    framework_tags.append(f"[red]{finding.cve}[/red]")
                if finding.owasp:
                    framework_tags.append(f"[magenta]OWASP {finding.owasp.split(':')[0]}[/magenta]")
                if finding.mitre_atlas:
                    framework_tags.append(f"[yellow]{finding.mitre_atlas.split(':')[0]}[/yellow]")
                if finding.eu_ai_act:
                    framework_tags.append(f"[blue]EU AI Act {finding.eu_ai_act.split('(')[0].strip()}[/blue]")
                tag_header = (" | " + " | ".join(framework_tags)) if framework_tags else ""

                card_content = (
                    f"[bold]{finding.title}[/bold] ({finding.rule_id}{tag_header})\n"
                    f"[dim]File:[/dim] {finding.file_path}\n"
                    f"[dim]Details:[/dim] {finding.description}{evidence_text}\n"
                    f"[bold green]Remediation:[/bold green] {finding.remediation}"
                )
                self.console.print(Panel(card_content, border_style=finding.severity.color, padding=(0, 1)))

        self.console.print()
