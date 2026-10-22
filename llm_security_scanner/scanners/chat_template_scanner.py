"""
Chat Template & Jinja2 SSTI Security Scanner.
Inspects tokenizer_config.json for Server-Side Template Injection (SSTI) vulnerabilities,
such as CVE-2024-34359 in Transformers, sandbox escape sequences, and Jinja DoS bombs.
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict, List

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner


# Dangerous Jinja2 patterns used in sandbox escapes & SSTI exploits
SSTI_PATTERNS = [
    (
        r"__class__|__mro__|__subclasses__|__bases__|__base__",
        "Python object hierarchy reflection traversal (__class__ / __subclasses__)",
        Severity.CRITICAL,
        "CWE-1336",
    ),
    (
        r"__globals__|__builtins__|__import__|__getitem__",
        "Global environment / builtin breakout attempt via __globals__ / __builtins__",
        Severity.CRITICAL,
        "CWE-1336",
    ),
    (
        r"lipsum\.__globals__|cycler\.__init__|joiner\.__init__|namespace\.__init__",
        "Jinja2 helper reflection escape vector (CVE-2024-34359)",
        Severity.CRITICAL,
        "CVE-2024-34359",
    ),
    (
        r"os\.popen|os\.system|subprocess\.|commands\.",
        "Direct system shell command invocation inside template",
        Severity.CRITICAL,
        "CWE-78",
    ),
    (
        r"attr\(['\"]__\w+__['\"]\)",
        "Obfuscated attribute lookup bypass via attr() filter",
        Severity.HIGH,
        "CWE-1336",
    ),
    (
        r"range\(\s*(?:10{7,}|[1-9]\d{7,})\s*\)",
        "Massive loop range causing Denial of Service (DoS / ReDoS)",
        Severity.MEDIUM,
        "CWE-400",
    ),
]


class ChatTemplateScanner(BaseScanner):
    name = "ChatTemplateScanner"
    description = "Scans tokenizer chat templates for Jinja2 Server-Side Template Injection (CVE-2024-34359)"

    def can_scan(self, file_path: Path) -> bool:
        return file_path.name.lower() in ("tokenizer_config.json", "chat_template.json", "chat_template.jinja")

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            template_text = ""
            if file_path.suffix.lower() == ".json":
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    template_val = data.get("chat_template")
                    if isinstance(template_val, str):
                        template_text = template_val
                    elif isinstance(template_val, list):
                        # List of template dicts
                        template_text = " ".join([str(item) for item in template_val])
            else:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    template_text = f.read()

            if template_text:
                findings.extend(self._analyze_template(template_text, relative_path))

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-TMPL-ERR-001",
                    title="Error Parsing Chat Template",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Could not parse chat template file: {str(e)}",
                    remediation="Verify JSON syntax in tokenizer_config.json.",
                )
            )

        return findings

    def _analyze_template(self, template: str, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for pattern, desc, severity, cwe_or_cve in SSTI_PATTERNS:
            match = re.search(pattern, template, re.IGNORECASE)
            if match:
                matched_snippet = match.group(0)
                is_cve = "CVE" in cwe_or_cve
                findings.append(
                    Finding(
                        rule_id="SEC-TMPL-SSTI-001" if is_cve else "SEC-TMPL-SSTI-002",
                        title=f"Chat Template SSTI Vulnerability: {desc}",
                        severity=severity,
                        category=RiskCategory.TEMPLATE_INJECTION,
                        file_path=file_path,
                        description=(
                            f"Tokenizer chat template contains dangerous pattern: '{matched_snippet}'. "
                            f"Calling 'tokenizer.apply_chat_template()' can execute arbitrary host commands "
                            f"or escape the Jinja sandbox."
                        ),
                        remediation=(
                            "Sanitize or remove the chat template. Ensure Hugging Face transformers is updated "
                            "to >= 4.40.1 to avoid Jinja SSTI vulnerabilities (CVE-2024-34359)."
                        ),
                        evidence=f"Matched payload pattern: {matched_snippet}",
                        cwe=None if is_cve else cwe_or_cve,
                        cve=cwe_or_cve if is_cve else None,
                        owasp="LLM03: Supply Chain Vulnerabilities",
                        mitre_atlas="AML.T0048: Insecure Code Execution",
                        nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                    )
                )

        return findings
