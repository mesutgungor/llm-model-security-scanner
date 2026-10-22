"""
Markdown Reporter for LLM Model Security Scanner.
Generates GitHub-flavored markdown reports suitable for PR comments, audits, and documentation.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional
from llm_security_scanner.models import ScanReport, Severity


class MarkdownReporter:
    def render(self, report: ScanReport, output_file: Optional[Path] = None) -> str:
        verdict_badge = {
            "SAFE": "🟢 **SAFE**",
            "LOW_RISK": "🟡 **LOW RISK**",
            "MEDIUM_RISK": "🟠 **MEDIUM RISK**",
            "HIGH_RISK": "🔴 **HIGH RISK**",
            "CRITICAL": "⛔ **CRITICAL THREAT**",
        }.get(report.verdict.value, report.verdict.value)

        md = []
        md.append(f"# 🛡️ LLM Model Security Scan Report")
        md.append(f"**Target:** `{report.target}`  ")
        md.append(f"**Verdict:** {verdict_badge} (Risk Score: **{report.risk_score} / 100**)  ")
        md.append(f"**Scan Duration:** {report.duration_seconds:.2f} seconds  \n")

        md.append("## 📊 Scan Overview")
        md.append("| Metric | Value |")
        md.append("| :--- | :--- |")
        md.append(f"| **Files Scanned** | {report.scanned_files_count} |")
        md.append(f"| **Data Volume** | {report.total_bytes_scanned / (1024 * 1024):.2f} MB |")
        md.append(f"| **Detected Formats** | {', '.join(report.model_formats_found) if report.model_formats_found else 'None'} |")
        md.append(f"| **Model Architecture** | {report.model_architecture or 'Unknown'} |")
        md.append(f"| **Critical Issues** | {report.critical_count} |")
        md.append(f"| **High Issues** | {report.high_count} |")
        md.append(f"| **Medium Issues** | {report.medium_count} |")
        md.append(f"| **Low / Info Issues** | {report.low_count + report.info_count} |\n")

        md.append("## 🚨 Security Findings")
        if not report.findings:
            md.append("✅ **No vulnerabilities or security anomalies detected.** Model meets security criteria.\n")
        else:
            md.append("| Severity | Rule ID | Category | Location | Title |")
            md.append("| :---: | :--- | :--- | :--- | :--- |")

            sorted_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)
            for f in sorted_findings:
                loc = f"`{f.file_path}`"
                if f.line_number:
                    loc += f" (L{f.line_number})"
                md.append(f"| **{f.severity.value}** | `{f.rule_id}` | {f.category.value} | {loc} | {f.title} |")
            md.append("\n")

            md.append("## 🛠️ Detailed Remediation Guidance")
            for f in sorted_findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    md.append(f"### ⚠️ [{f.severity.value}] {f.title}")
                    md.append(f"- **File:** `{f.file_path}`")
                    md.append(f"- **Category:** {f.category.value}")
                    if f.cwe:
                        md.append(f"- **CWE:** {f.cwe}")
                    if f.cve:
                        md.append(f"- **CVE:** {f.cve}")
                    if f.owasp:
                        md.append(f"- **OWASP LLM:** {f.owasp}")
                    if f.mitre_atlas:
                        md.append(f"- **MITRE ATLAS:** {f.mitre_atlas}")
                    if f.nist_ai_rmf:
                        md.append(f"- **NIST AI RMF:** {f.nist_ai_rmf}")
                    if f.eu_ai_act:
                        md.append(f"- **EU AI Act:** {f.eu_ai_act}")
                    md.append(f"- **Description:** {f.description}")
                    if f.evidence:
                        md.append(f"- **Evidence:** `{f.evidence}`")
                    md.append(f"- **Remediation:** {f.remediation}\n")

        content = "\n".join(md)
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content, encoding="utf-8")

        return content
