"""
Dossier Reporter for Consumer Proof-of-Finding Audits.
Renders Terminal, Markdown, and Standalone HTML Proof Certificates.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from llm_security_scanner.verification.models import VerificationDossier, VerificationStatus


class DossierReporter:
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_terminal(self, dossier: VerificationDossier) -> None:
        self.console.print()
        header = Text(" PROOF-OF-FINDING VERIFICATION DOSSIER ", style="bold white on dark_green")
        sub = Text(
            f"Target: {dossier.target} | Generated: {dossier.generation_time} | "
            f"Verification Rate: {dossier.verification_rate}% ({dossier.verified_findings_count}/{dossier.total_findings_count} Proven)",
            style="dim",
        )
        self.console.print(Panel(sub, title=header, border_style="green"))
        self.console.print()

        for idx, proof in enumerate(dossier.proofs, 1):
            status_style = proof.status.color
            badge = proof.status.badge

            content = (
                f"[bold cyan]Finding #{idx}:[/bold cyan] [bold]{proof.finding_title}[/bold] ({proof.rule_id})\n"
                f"[dim]File:[/dim] `{proof.file_path}`\n"
                f"[dim]SHA-256 Fingerprint:[/dim] `{proof.file_sha256}`\n"
                f"[dim]Proof Methodology:[/dim] {proof.methodology}\n"
                f"[dim]Status:[/dim] [{status_style}]{badge}[/{status_style}]\n\n"
                f"[bold yellow]Consumer Impact Summary:[/bold yellow]\n{proof.consumer_impact_summary}\n\n"
                f"[bold green]Reproduction Steps & Proof Trace:[/bold green]\n"
                + "\n".join([f"  {step}" for step in proof.reproduction_steps])
                + f"\n\n[bold magenta]Remediation Recommendation:[/bold magenta]\n{proof.remediation_recommendation}"
            )

            self.console.print(
                Panel(content, border_style="green" if proof.status == VerificationStatus.VERIFIED else "yellow")
            )
            self.console.print()

    def render_markdown(self, dossier: VerificationDossier, output_file: Optional[Path] = None) -> str:
        md = []
        md.append(f"# 🔍 LLM Security Proof-of-Finding Audit Dossier")
        md.append(f"**Target Model / Artifact:** `{dossier.target}`  ")
        md.append(f"**Audit Timestamp:** `{dossier.generation_time}`  ")
        md.append(f"**Objective Proof Rate:** **{dossier.verification_rate}%** ({dossier.verified_findings_count}/{dossier.total_findings_count} Findings Verified)  \n")

        md.append("---")
        md.append("## 📋 Executive Verification Summary")
        md.append("| Metric | Result |")
        md.append("| :--- | :--- |")
        md.append(f"| **Target Model** | `{dossier.target}` |")
        md.append(f"| **Total Reported Findings** | {dossier.total_findings_count} |")
        md.append(f"| **Verified Objective Proofs** | {dossier.verified_findings_count} |")
        md.append(f"| **Verification Success Rate** | {dossier.verification_rate}% |\n")

        md.append("---")
        md.append("## 🔬 Objective Finding Proofs & Evidence Traces\n")

        for idx, proof in enumerate(dossier.proofs, 1):
            badge = "✅ **VERIFIED OBJECTIVE PROOF**" if proof.status == VerificationStatus.VERIFIED else "⚠️ **UNVERIFIED**"
            md.append(f"### {idx}. [{proof.rule_id}] {proof.finding_title}")
            md.append(f"- **Verification Status:** {badge}")
            md.append(f"- **Target File:** `{proof.file_path}`")
            md.append(f"- **Cryptographic SHA-256 Hash:** `{proof.file_sha256}`")
            md.append(f"- **Verification Methodology:** {proof.methodology}\n")

            md.append(f"#### ⚠️ Consumer Impact Statement")
            md.append(f"{proof.consumer_impact_summary}\n")

            md.append(f"#### 🧪 Deterministic Reproduction Steps")
            for step in proof.reproduction_steps:
                md.append(f"- {step}")
            md.append("")

            if proof.proof_data:
                md.append(f"<details><summary><b>View Raw Proof Data & Extracted Telemetry</b></summary>\n")
                md.append("```json")
                md.append(json.dumps(proof.proof_data, indent=2))
                md.append("```\n</details>\n")

            md.append(f"#### 🛡️ Remediation Advice")
            md.append(f"{proof.remediation_recommendation}\n")
            md.append("---\n")

        content = "\n".join(md)
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content, encoding="utf-8")
        return content

    def render_html(self, dossier: VerificationDossier, output_file: Optional[Path] = None) -> str:
        proof_cards_html = []
        for idx, proof in enumerate(dossier.proofs, 1):
            status_class = "verified" if proof.status == VerificationStatus.VERIFIED else "unverified"
            badge_text = "VERIFIED PROOF" if proof.status == VerificationStatus.VERIFIED else "STATIC INDICATOR"

            steps_html = "".join([f"<li>{step}</li>" for step in proof.reproduction_steps])
            proof_data_json = json.dumps(proof.proof_data, indent=2) if proof.proof_data else ""

            card = f"""
            <div class="proof-card {status_class}">
                <div class="card-header">
                    <span class="badge {status_class}">{badge_text}</span>
                    <h3>#{idx}: {proof.finding_title}</h3>
                    <span class="rule-id">{proof.rule_id}</span>
                </div>
                <div class="meta-row">
                    <strong>File:</strong> <code>{proof.file_path}</code> | 
                    <strong>SHA-256:</strong> <code>{proof.file_sha256[:16]}...{proof.file_sha256[-8:]}</code> | 
                    <strong>Methodology:</strong> {proof.methodology}
                </div>
                <div class="impact-box">
                    <strong>Consumer Impact:</strong> {proof.consumer_impact_summary}
                </div>
                <h4>Deterministic Reproduction Walkthrough</h4>
                <ol class="repro-list">
                    {steps_html}
                </ol>
                {f'<details><summary>Raw Proof Metadata</summary><pre><code>{proof_data_json}</code></pre></details>' if proof_data_json else ''}
                <div class="remediation-box">
                    <strong>Remediation:</strong> {proof.remediation_recommendation}
                </div>
            </div>
            """
            proof_cards_html.append(card)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LLM Security Proof-of-Finding Dossier: {dossier.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 2rem; border-radius: 12px; border: 1px solid #334155; margin-bottom: 2rem; }}
        h1 {{ margin-top: 0; color: #38bdf8; font-size: 1.8rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 1.5rem; }}
        .stat-card {{ background: #0f172a; padding: 1rem; border-radius: 8px; border: 1px solid #334155; text-align: center; }}
        .stat-val {{ font-size: 1.8rem; font-weight: bold; color: #10b981; }}
        .stat-lbl {{ font-size: 0.85rem; color: #94a3b8; margin-top: 0.25rem; }}
        .proof-card {{ background: #1e293b; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; border-left: 6px solid #10b981; border-top: 1px solid #334155; border-right: 1px solid #334155; border-bottom: 1px solid #334155; }}
        .proof-card.unverified {{ border-left-color: #f59e0b; }}
        .card-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }}
        .card-header h3 {{ margin: 0; font-size: 1.2rem; flex-grow: 1; margin-left: 0.75rem; }}
        .badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
        .badge.verified {{ background: #065f46; color: #34d399; }}
        .badge.unverified {{ background: #78350f; color: #fbbf24; }}
        .rule-id {{ background: #334155; padding: 0.2rem 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }}
        .meta-row {{ font-size: 0.85rem; color: #94a3b8; margin-bottom: 1rem; }}
        code {{ background: #0f172a; padding: 0.1rem 0.3rem; border-radius: 3px; font-family: monospace; color: #38bdf8; }}
        .impact-box {{ background: #450a0a; border: 1px solid #991b1b; padding: 0.75rem 1rem; border-radius: 6px; color: #fca5a5; font-size: 0.9rem; margin-bottom: 1rem; }}
        .remediation-box {{ background: #064e3b; border: 1px solid #065f46; padding: 0.75rem 1rem; border-radius: 6px; color: #a7f3d0; font-size: 0.9rem; margin-top: 1rem; }}
        .repro-list {{ padding-left: 1.2rem; font-size: 0.9rem; color: #cbd5e1; line-height: 1.6; }}
        details {{ background: #0f172a; padding: 0.5rem; border-radius: 4px; font-size: 0.85rem; margin-top: 0.5rem; }}
        pre {{ margin: 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Proof-of-Finding Security Verification Dossier</h1>
            <div>Target Model: <code>{dossier.target}</code> | Audited: {dossier.generation_time}</div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-val">{dossier.total_findings_count}</div>
                    <div class="stat-lbl">Reported Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val">{dossier.verified_findings_count}</div>
                    <div class="stat-lbl">Verified Proofs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-val">{dossier.verification_rate}%</div>
                    <div class="stat-lbl">Proof Confidence</div>
                </div>
            </div>
        </div>
        <h2>Verified Vulnerability Evidence</h2>
        {"".join(proof_cards_html)}
    </div>
</body>
</html>"""
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(html, encoding="utf-8")
        return html
