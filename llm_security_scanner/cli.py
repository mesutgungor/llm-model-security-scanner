"""
Command Line Interface for LLM Model Security Scanner.
Provides the 'llm-scan' CLI tool with rich formatting, CI/CD exit codes, and export formats.
"""

from __future__ import annotations
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from llm_security_scanner.engine import ModelSecurityScanner
from llm_security_scanner.models import ScannerConfig, Severity
from llm_security_scanner.reporters.console import ConsoleReporter
from llm_security_scanner.reporters.json_reporter import JsonReporter
from llm_security_scanner.reporters.markdown_reporter import MarkdownReporter
from llm_security_scanner.reporters.sarif_reporter import SarifReporter
from llm_security_scanner.verification import DossierReporter, FindingVerificationEngine

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="llm-scan")
def cli():
    """LLM Model Security Scanner - Audit open-source ML models for vulnerabilities."""
    pass


@cli.command("scan")
@click.argument("target", type=str)
@click.option(
    "--format",
    "-f",
    "report_format",
    type=click.Choice(["terminal", "json", "markdown", "sarif"], case_sensitive=False),
    default="terminal",
    help="Output report format.",
)
@click.option("--output", "-o", "output_path", type=click.Path(), help="File path to save the scan report.")
@click.option("--remote", "-r", is_flag=True, help="Scan directly from Hugging Face Hub without local download.")
@click.option("--fast", is_flag=True, help="Fast mode: skip deep tensor statistical sampling.")
@click.option(
    "--max-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    help="Exit with failure code 1 if findings reach or exceed this severity (useful for CI/CD gating).",
)
@click.option("--hf-token", envvar="HF_TOKEN", help="Hugging Face API token for authenticated Hub queries.")
def scan_command(
    target: str,
    report_format: str,
    output_path: Optional[str],
    remote: bool,
    fast: bool,
    max_severity: Optional[str],
    hf_token: Optional[str],
):
    """Scan a local model directory, file, or remote Hugging Face repository."""
    config = ScannerConfig(deep_weight_sampling=not fast)
    scanner = ModelSecurityScanner(config=config, hf_token=hf_token)

    try:
        report = scanner.scan(target, is_remote=remote)
    except Exception as e:
        console.print(f"[bold red]Scan error:[/bold red] {str(e)}")
        sys.exit(2)

    out_file = Path(output_path) if output_path else None

    # Render selected format
    if report_format == "terminal":
        reporter = ConsoleReporter(console)
        reporter.render(report)
        if out_file:
            # Also write markdown or json if output file requested
            if out_file.suffix.lower() == ".json":
                JsonReporter().render(report, out_file)
            else:
                MarkdownReporter().render(report, out_file)
            console.print(f"[green]Report saved to:[/green] {out_file}")

    elif report_format == "json":
        json_str = JsonReporter().render(report, out_file)
        if not out_file:
            click.echo(json_str)
        else:
            console.print(f"[green]JSON report saved to:[/green] {out_file}")

    elif report_format == "markdown":
        md_str = MarkdownReporter().render(report, out_file)
        if not out_file:
            click.echo(md_str)
        else:
            console.print(f"[green]Markdown report saved to:[/green] {out_file}")

    elif report_format == "sarif":
        sarif_str = SarifReporter().render(report, out_file)
        if not out_file:
            click.echo(sarif_str)
        else:
            console.print(f"[green]SARIF report saved to:[/green] {out_file}")

    # Check CI/CD exit threshold
    if max_severity:
        threshold_rank = Severity[max_severity.upper()].rank
        max_found_rank = max([f.severity.rank for f in report.findings], default=0)
        if max_found_rank >= threshold_rank:
            console.print(
                f"[bold red]Pipeline Failed:[/bold red] Found issues meeting or exceeding severity threshold '{max_severity}'."
            )
            sys.exit(1)


@cli.command("verify")
@click.argument("target", type=str)
@click.option(
    "--format",
    "-f",
    "report_format",
    type=click.Choice(["terminal", "markdown", "html", "json"], case_sensitive=False),
    default="terminal",
    help="Proof dossier output format.",
)
@click.option("--output", "-o", "output_path", type=click.Path(), help="File path to save the proof dossier.")
@click.option("--remote", "-r", is_flag=True, help="Scan directly from Hugging Face Hub without local download.")
@click.option("--fast", is_flag=True, help="Fast mode: skip deep tensor statistical sampling.")
@click.option("--hf-token", envvar="HF_TOKEN", help="Hugging Face API token.")
def verify_command(
    target: str,
    report_format: str,
    output_path: Optional[str],
    remote: bool,
    fast: bool,
    hf_token: Optional[str],
):
    """Run security scan and generate an objective Proof-of-Finding verification dossier."""
    config = ScannerConfig(deep_weight_sampling=not fast)
    scanner = ModelSecurityScanner(config=config, hf_token=hf_token)

    try:
        report = scanner.scan(target, is_remote=remote)
    except Exception as e:
        console.print(f"[bold red]Scan error:[/bold red] {str(e)}")
        sys.exit(2)

    verifier = FindingVerificationEngine()
    dossier = verifier.verify_report(report)

    out_file = Path(output_path) if output_path else None
    reporter = DossierReporter(console)

    if report_format == "terminal":
        reporter.render_terminal(dossier)
        if out_file:
            if out_file.suffix.lower() == ".html":
                reporter.render_html(dossier, out_file)
            elif out_file.suffix.lower() == ".json":
                out_file.write_text(dossier.to_json(), encoding="utf-8")
            else:
                reporter.render_markdown(dossier, out_file)
            console.print(f"[green]Dossier saved to:[/green] {out_file}")

    elif report_format == "markdown":
        md_str = reporter.render_markdown(dossier, out_file)
        if not out_file:
            click.echo(md_str)
        else:
            console.print(f"[green]Markdown dossier saved to:[/green] {out_file}")

    elif report_format == "html":
        html_str = reporter.render_html(dossier, out_file)
        if not out_file:
            click.echo(html_str)
        else:
            console.print(f"[green]HTML proof certificate saved to:[/green] {out_file}")

    elif report_format == "json":
        json_str = dossier.to_json()
        if not out_file:
            click.echo(json_str)
        else:
            out_file.write_text(json_str, encoding="utf-8")
            console.print(f"[green]JSON dossier saved to:[/green] {out_file}")


@cli.command("list-rules")
def list_rules():
    """List all security detection rules available in the scanner."""
    table = Table(title="[bold cyan]Registered Security Rules[/bold cyan]", header_style="bold magenta")
    table.add_column("Rule ID", style="bold", width=18)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Category", width=25)
    table.add_column("Description", width=45)

    rules = [
        # Deserialization & Archives
        ("SEC-PCK-001", "CRITICAL", "Deserialization Exploit", "Arbitrary Code Execution via dangerous pickle opcodes"),
        ("SEC-PCK-002", "HIGH", "Deserialization Exploit", "Suspicious or unapproved global object in pickle stream"),
        ("SEC-PCK-003", "LOW", "Format Integrity", "Incomplete or malformed pickle bytecode"),
        ("SEC-PCK-INFO-001", "LOW", "Format Integrity", "Legacy PyTorch pickle serialization format detected"),
        ("SEC-ZIP-001", "CRITICAL", "Deserialization Exploit", "ZipSlip path traversal in PyTorch archive"),
        ("SEC-ZIP-002", "LOW", "Format Integrity", "Corrupted PyTorch ZIP container structure"),

        # Remote Code & Architecture
        ("SEC-RCE-001", "HIGH", "Remote Code Execution", "Suspicious module imports (subprocess, socket, urllib)"),
        ("SEC-RCE-002", "CRITICAL", "Remote Code Execution", "Dynamic code execution via eval(), exec(), __import__()"),
        ("SEC-RCE-003", "CRITICAL", "Remote Code Execution", "OS command execution via system(), popen(), spawn()"),
        ("SEC-RCE-MAP-001", "HIGH", "Remote Code Execution", "Auto-map declaration requiring trust_remote_code=True"),
        ("SEC-RCE-MAP-002", "MEDIUM", "Remote Code Execution", "Custom modeling parameter / custom kernel declaration"),
        ("SEC-OBF-001", "HIGH", "Remote Code Execution", "Obfuscated payload decoding (b64decode, decompress)"),
        ("SEC-EXF-001", "MEDIUM", "Secret Leak", "Environment variable access (os.environ) in model scripts"),

        # Chat Template & SSTI
        ("SEC-TMPL-SSTI-001", "CRITICAL", "Chat Template SSTI", "Jinja2 reflection escape / CVE-2024-34359 in template"),
        ("SEC-TMPL-SSTI-002", "CRITICAL", "Chat Template SSTI", "Jinja2 sandbox escape / builtin breakout attempt"),

        # SafeTensors & GGUF
        ("SEC-ST-001", "HIGH", "Format Integrity", "Truncated SafeTensors file (< 8 bytes)"),
        ("SEC-ST-002", "HIGH", "Format Integrity", "Invalid zero or negative SafeTensors header size"),
        ("SEC-ST-003", "CRITICAL", "Format Integrity", "SafeTensors header allocation memory bomb (CVE-2023-44469)"),
        ("SEC-ST-004", "HIGH", "Format Integrity", "Malformed SafeTensors JSON header"),
        ("SEC-ST-006", "CRITICAL", "Format Integrity", "SafeTensors out-of-bounds or inverted tensor offsets"),
        ("SEC-ST-007", "CRITICAL", "Format Integrity", "Tensor data offsets exceed physical file boundary"),
        ("SEC-ST-META-001", "HIGH", "Suspicious Artifact", "Suspicious executable pattern in SafeTensors __metadata__"),
        ("SEC-GGUF-001", "HIGH", "Format Integrity", "Truncated GGUF binary file"),
        ("SEC-GGUF-002", "HIGH", "Format Integrity", "Invalid GGUF magic header bytes"),
        ("SEC-GGUF-004", "CRITICAL", "Format Integrity", "Anomalous GGUF tensor count triggering C++ integer overflow"),
        ("SEC-GGUF-005", "HIGH", "Format Integrity", "Anomalous GGUF metadata key-value count (DoS)"),

        # ONNX
        ("SEC-ONNX-001", "CRITICAL", "Deserialization Exploit", "ONNX external data path traversal (CVE-2024-27318)"),
        ("SEC-ONNX-002", "MEDIUM", "Remote Code Execution", "ONNX custom domain operator declaration"),

        # Special Tokens & Unicode
        ("SEC-TOK-001", "MEDIUM", "Special Tokens", "Missing End-of-Sequence (EOS) token configuration (DoS)"),
        ("SEC-TOK-002", "HIGH", "Special Tokens", "Empty string EOS token configured"),
        ("SEC-TOK-003", "HIGH", "Special Tokens", "Token ID collision enabling role delimiter hijacking"),
        ("SEC-TOK-004", "HIGH", "Special Tokens", "Critical delimiter marked non-special (prompt injection)"),
        ("SEC-TOK-005", "LOW", "Special Tokens", "BOS and EOS tokens are identical"),
        ("SEC-TOK-006", "HIGH", "Unicode Smuggling", "Unicode Bidirectional (Bidi) Trojan Override (CVE-2021-42574)"),
        ("SEC-TOK-007", "MEDIUM", "Unicode Smuggling", "Zero-width invisible character smuggling in vocabulary"),

        # Generation Config & Resource Exhaustion
        ("SEC-GEN-001", "HIGH", "Generation DoS", "Extreme token generation limit in max_new_tokens (KV DoS)"),
        ("SEC-GEN-002", "MEDIUM", "Generation DoS", "Invalid sampling temperature (division by zero / crash)"),
        ("SEC-GEN-003", "MEDIUM", "Generation DoS", "Missing eos_token_id in generation manifest"),

        # LoRA & PEFT Adapters
        ("SEC-PEFT-001", "HIGH", "Adapter Poisoning", "Suspicious remote base model path in adapter manifest"),
        ("SEC-PEFT-002", "HIGH", "Adapter Poisoning", "LoRA scaling factor sabotage (alignment stripping)"),
        ("SEC-PEFT-003", "MEDIUM", "Adapter Poisoning", "LoRA adapter targets safety / classification layer"),
        ("SEC-PEFT-004", "HIGH", "Adapter Poisoning", "Unrecognized or custom PEFT method declaration"),

        # Weight Poisoning & Backdoors
        ("SEC-WGT-001", "HIGH", "Weight Poisoning", "Suspicious tensor name matching trigger / backdoor keywords"),
        ("SEC-WGT-002", "CRITICAL", "Weight Poisoning", "Poisoned weights containing NaN or Infinity values (DoS)"),
        ("SEC-WGT-003", "HIGH", "Weight Poisoning", "Sabotaged / all-zero layer weights"),
        ("SEC-WGT-004", "MEDIUM", "Weight Poisoning", "Extreme weight magnitude outlier spike (Trojan gate)"),
        ("SEC-WGT-005", "CRITICAL", "Weight Poisoning", "Stealth out-of-bounds layer injected (hidden Trojan layer)"),

        # Artifacts & Supply Chain
        ("SEC-ART-001", "HIGH", "Suspicious Artifact", "Executable script or native binary in model directory"),
        ("SEC-ART-002", "CRITICAL", "Suspicious Artifact", "Disguised Linux ELF, Windows PE, or macOS Mach-O binary"),
        ("SEC-ART-003", "MEDIUM", "Suspicious Artifact", "Abnormally high Shannon entropy in plaintext file"),
        ("SEC-SYM-001", "CRITICAL", "Suspicious Artifact", "Malicious symlink traversal outside model repository"),
        ("SEC-SEC-001", "CRITICAL", "Secret Leak", "Exposed HuggingFace token, OpenAI key, AWS key, or SSH key"),
        ("SEC-HUB-001", "HIGH", "Supply Chain", "Repository only distributes unsafe pickle weights"),
        ("SEC-HUB-002", "HIGH", "Supply Chain", "Standalone executable script file in Hub repository"),
        ("SEC-HUB-TYPO-001", "HIGH", "Supply Chain", "Author typosquatting popular publishers on Hugging Face"),
    ]

    for rid, sev, cat, desc in rules:
        sev_style = Severity[sev].color
        table.add_row(rid, f"[{sev_style}]{sev}[/{sev_style}]", cat, desc)

    console.print(table)


@cli.command("compliance")
def display_compliance():
    """Display regulatory & industry framework mappings (OWASP, MITRE ATLAS, NIST, EU AI Act)."""
    table = Table(
        title="[bold green]Security Framework Crosswalk Matrix (OWASP • MITRE ATLAS • NIST • EU AI Act)[/bold green]",
        header_style="bold magenta",
    )
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("OWASP LLM", style="magenta", width=18)
    table.add_column("MITRE ATLAS", style="yellow", width=22)
    table.add_column("NIST AI RMF", style="cyan", width=20)
    table.add_column("EU AI Act (2024/1689)", style="blue", width=24)

    matrix = [
        ("SEC-PCK-001", "LLM03: Supply Chain", "AML.T0010: Supply Chain", "MANAGE-2.4 (Vetting)", "Art. 15 / Art. 55 (Systemic)"),
        ("SEC-ZIP-001", "LLM03: Supply Chain", "AML.T0010: Supply Chain", "MANAGE-2.4 (Vetting)", "Art. 15 (Cybersecurity)"),
        ("SEC-RCE-001", "LLM03: Supply Chain", "AML.T0010: Supply Chain", "MANAGE-2.4 (Vetting)", "Art. 15 (Cybersecurity)"),
        ("SEC-RCE-002", "LLM03: Supply Chain", "AML.T0048: Code Execution", "MANAGE-2.4 (Vetting)", "Art. 15 (Cybersecurity)"),
        ("SEC-RCE-003", "LLM03: Supply Chain", "AML.T0048: Code Execution", "MANAGE-2.4 (Vetting)", "Art. 15 (Cybersecurity)"),
        ("SEC-RCE-MAP", "LLM03: Supply Chain", "AML.T0010: Supply Chain", "MANAGE-2.4 (Vetting)", "Art. 53 (GPAI Documentation)"),
        ("SEC-TMPL-SSTI", "LLM03 / LLM01", "AML.T0048: Code Execution", "MEASURE-2.6 (Testing)", "Art. 15 (Cybersecurity)"),
        ("SEC-ST-003", "LLM10: Consumption", "AML.T0029: Denial of Service", "MEASURE-2.6 (Testing)", "Art. 15 (Robustness)"),
        ("SEC-ONNX-001", "LLM03: Supply Chain", "AML.T0010: Supply Chain", "MANAGE-2.4 (Vetting)", "Art. 15 (Cybersecurity)"),
        ("SEC-WGT-002", "LLM04: Poisoning", "AML.T0029: Denial of Service", "MEASURE-2.6 (Testing)", "Art. 15 / Art. 55 (Systemic)"),
        ("SEC-WGT-003", "LLM04: Poisoning", "AML.T0018: Backdoor ML", "MEASURE-2.6 (Testing)", "Art. 15 (Robustness)"),
        ("SEC-WGT-005", "LLM04: Poisoning", "AML.T0018: Backdoor ML", "MEASURE-2.6 (Testing)", "Art. 15 (Cybersecurity)"),
        ("SEC-TOK-003", "LLM01: Injection", "AML.T0051: LLM Injection", "MEASURE-2.6 (Testing)", "Art. 15 (Cybersecurity)"),
        ("SEC-TOK-004", "LLM01: Injection", "AML.T0051: LLM Injection", "MEASURE-2.6 (Testing)", "Art. 15 (Cybersecurity)"),
        ("SEC-TOK-006", "LLM01: Injection", "AML.T0051: LLM Injection", "MEASURE-2.6 (Testing)", "Art. 15 (Robustness)"),
        ("SEC-GEN-001", "LLM10: Consumption", "AML.T0029: Denial of Service", "MEASURE-2.6 (Testing)", "Art. 15 (Robustness)"),
        ("SEC-PEFT-001", "LLM03: Supply Chain", "AML.T0010: Supply Chain", "MANAGE-2.4 (Vetting)", "Art. 15 (Cybersecurity)"),
        ("SEC-PEFT-002", "LLM04: Poisoning", "AML.T0018: Backdoor ML", "MEASURE-2.6 (Testing)", "Art. 15 (Robustness)"),
        ("SEC-ART-002", "LLM03: Supply Chain", "AML.T0010: Supply Chain", "MANAGE-2.4 (Vetting)", "Art. 15 (Cybersecurity)"),
        ("SEC-SEC-001", "LLM02: Data Leak", "AML.T0040: IP Theft", "GOVERN-1.2 & MANAGE", "Art. 15 & Art. 53 (Protection)"),
    ]

    for rid, owasp, mitre, nist, eu in matrix:
        table.add_row(rid, owasp, mitre, nist, eu)

    console.print(table)


@cli.command("threat-model")
def display_threat_model():
    """Display the 5-phase LLM security lifecycle threat model."""
    console.print(
        Panel(
            "[bold white]End-to-End LLM Security Lifecycle Phases[/bold white]\n\n"
            "1. [bold cyan]Data Collection & Curation:[/bold cyan] Web scraping cache poisoning, Clean-label Trojans, PII leakage, RLHF label tampering.\n"
            "2. [bold cyan]Training & Architecture:[/bold cyan] Malicious CUDA/Triton kernels, Sleeper Agent backdoors, Checkpoint tampering, LoRA un-alignment.\n"
            "3. [bold cyan]Serialization & Distribution (Scanner Target):[/bold cyan] Insecure pickle deserialization (RCE), trust_remote_code=True exploits, Jinja2 SSTI (CVE-2024-34359), SafeTensors/GGUF overflows, disguised binaries, secret leaks.\n"
            "4. [bold cyan]Deployment & Infrastructure:[/bold cyan] Serving engine memory corruption (vLLM, llama.cpp), DoS sponge attacks, unauthenticated APIs.\n"
            "5. [bold cyan]Post-Deployment Inference:[/bold cyan] Direct/Indirect prompt injection, jailbreaking, agent tool abuse (SSRF), training data extraction.",
            title="[bold green]LLM Security Threat Model[/bold green]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    cli()
