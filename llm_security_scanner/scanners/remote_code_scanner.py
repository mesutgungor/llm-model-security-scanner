"""
Remote Code & Custom Architecture Scanner.
Audits configuration files (config.json) for 'auto_map' declarations and performs
deep AST static analysis on custom Python files (modeling_*.py, configuration_*.py)
to detect hidden backdoors, data exfiltration, reverse shells, and malicious code.
"""

from __future__ import annotations
import ast
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner


class DangerousASTVisitor(ast.NodeVisitor):
    """AST visitor that flags dangerous imports, calls, attribute lookups, and obfuscation."""

    def __init__(self, relative_path: str):
        self.relative_path = relative_path
        self.findings: List[Finding] = []
        self.suspicious_imports: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.name
            if name in ("subprocess", "pty", "socket", "http.client", "urllib", "requests", "aiohttp", "httpx"):
                self.findings.append(
                    Finding(
                        rule_id="SEC-RCE-001",
                        title=f"Suspicious Module Import in Model Code: '{name}'",
                        severity=Severity.HIGH,
                        category=RiskCategory.REMOTE_CODE_EXECUTION,
                        file_path=self.relative_path,
                        description=(
                            f"Model repository Python script imports '{name}'. Architecture code "
                            f"should strictly compute tensor forward passes, not initiate network "
                            f"connections or spawn processes."
                        ),
                        remediation="Inspect custom modeling code carefully before running with trust_remote_code=True.",
                        line_number=node.lineno,
                        evidence=f"import {name}",
                        cwe="CWE-94",
                        owasp="LLM03: Supply Chain Vulnerabilities",
                        mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                        nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module in ("subprocess", "pty", "socket", "urllib.request", "requests", "http.client", "aiohttp"):
            self.findings.append(
                Finding(
                    rule_id="SEC-RCE-001",
                    title=f"Suspicious From-Import in Model Code: '{module}'",
                    severity=Severity.HIGH,
                    category=RiskCategory.REMOTE_CODE_EXECUTION,
                    file_path=self.relative_path,
                    description=f"Model repository script imports from '{module}'.",
                    remediation="Audit model code for unauthorized side effects or network exfiltration.",
                    line_number=node.lineno,
                    evidence=f"from {module} import ...",
                    cwe="CWE-94",
                    owasp="LLM03: Supply Chain Vulnerabilities",
                    mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                    nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                    eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check direct functions: eval(), exec(), __import__()
        func = node.func
        func_name = ""

        if isinstance(func, ast.Name):
            func_name = func.id
            if func_name in ("eval", "exec", "__import__", "compile"):
                self.findings.append(
                    Finding(
                        rule_id="SEC-RCE-002",
                        title=f"Dynamic Code Execution via '{func_name}()'",
                        severity=Severity.CRITICAL,
                        category=RiskCategory.REMOTE_CODE_EXECUTION,
                        file_path=self.relative_path,
                        description=(
                            f"Custom model script calls '{func_name}()'. This pattern is frequently "
                            f"used to execute de-obfuscated payloads or run remote shell commands."
                        ),
                        remediation="Do not trust or execute models containing dynamic code evaluation.",
                        line_number=node.lineno,
                        evidence=f"{func_name}(...)",
                        cwe="CWE-95",
                        owasp="LLM03: Supply Chain Vulnerabilities",
                        mitre_atlas="AML.T0048: Insecure Code Execution",
                        nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                    )
                )

        elif isinstance(func, ast.Attribute):
            attr_name = func.attr
            # e.g., os.system, subprocess.Popen, base64.b64decode
            if attr_name in ("system", "popen", "spawn", "Popen", "run", "check_output"):
                self.findings.append(
                    Finding(
                        rule_id="SEC-RCE-003",
                        title=f"Host Command Execution via '{attr_name}'",
                        severity=Severity.CRITICAL,
                        category=RiskCategory.REMOTE_CODE_EXECUTION,
                        file_path=self.relative_path,
                        description=f"Custom model architecture invokes system execution method '{attr_name}'.",
                        remediation="Refuse execution. Model code must not execute host OS commands.",
                        line_number=node.lineno,
                        evidence=f"...{attr_name}(...)",
                        cwe="CWE-78",
                        owasp="LLM03: Supply Chain Vulnerabilities",
                        mitre_atlas="AML.T0048: Insecure Code Execution",
                        nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                    )
                )
            elif attr_name in ("b64decode", "decompress", "unhexlify"):
                # Obfuscation indicator
                self.findings.append(
                    Finding(
                        rule_id="SEC-OBF-001",
                        title=f"Obfuscated Payload Decoding via '{attr_name}'",
                        severity=Severity.HIGH,
                        category=RiskCategory.REMOTE_CODE_EXECUTION,
                        file_path=self.relative_path,
                        description=f"Model code decodes binary/obfuscated content using '{attr_name}'.",
                        remediation="Verify whether binary strings contain stealth executable payloads.",
                        line_number=node.lineno,
                        evidence=f"...{attr_name}(...)",
                        cwe="CWE-116",
                    )
                )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # Check os.environ['HF_TOKEN'] or similar
        if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
            self.findings.append(
                Finding(
                    rule_id="SEC-EXF-001",
                    title="Environment Variable Access in Model Code",
                    severity=Severity.MEDIUM,
                    category=RiskCategory.SECRET_LEAK,
                    file_path=self.relative_path,
                    description="Script accesses os.environ, potentially snooping on API keys or tokens.",
                    remediation="Verify what environment variables are accessed by the model.",
                    line_number=node.lineno,
                    evidence="os.environ access",
                    cwe="CWE-200",
                )
            )
        self.generic_visit(node)


class RemoteCodeScanner(BaseScanner):
    name = "RemoteCodeScanner"
    description = "Scans auto_map configurations and inspects custom Python files using static AST analysis"

    def can_scan(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if name.endswith(".json") and ("config" in name or "tokenizer" in name):
            return True
        if name.endswith(".py"):
            return True
        return False

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        if file_path.suffix.lower() == ".json":
            findings.extend(self._scan_json_config(file_path, relative_path))
        elif file_path.suffix.lower() == ".py":
            findings.extend(self._scan_python_script(file_path, relative_path))

        return findings

    def _scan_json_config(self, file_path: Path, relative_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if isinstance(data, dict):
                # Check for auto_map (which triggers remote code execution if trust_remote_code=True)
                if "auto_map" in data:
                    auto_map = data["auto_map"]
                    findings.append(
                        Finding(
                            rule_id="SEC-RCE-MAP-001",
                            title="Remote Custom Code Registration (auto_map)",
                            severity=Severity.HIGH,
                            category=RiskCategory.REMOTE_CODE_EXECUTION,
                            file_path=relative_path,
                            description=(
                                f"Model configuration defines 'auto_map': {json.dumps(auto_map)}. "
                                f"Loading this model with 'trust_remote_code=True' will run custom Python "
                                f"scripts packaged in the repository."
                            ),
                            remediation="Audit the referenced Python files carefully before using trust_remote_code=True.",
                            evidence=f"auto_map entries: {list(auto_map.keys())}",
                            cwe="CWE-94",
                            owasp="LLM03: Supply Chain Vulnerabilities",
                            mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                            nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                            eu_ai_act="Article 15 (Cybersecurity & Robustness), Article 53 (GPAI Documentation)",
                        )
                    )

                # Check custom modeling classes
                for key in ("custom_class", "modeling_file", "custom_kernel"):
                    if key in data:
                        findings.append(
                            Finding(
                                rule_id="SEC-RCE-MAP-002",
                                title=f"Custom Code Declaration: '{key}'",
                                severity=Severity.MEDIUM,
                                category=RiskCategory.REMOTE_CODE_EXECUTION,
                                file_path=relative_path,
                                description=f"Model config specifies custom execution parameter '{key}': {data[key]}",
                                remediation="Verify if this custom code is required and audit its source.",
                            )
                        )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-CFG-ERR-001",
                    title="Malformed Configuration JSON",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Failed to parse JSON configuration: {str(e)}",
                    remediation="Check JSON syntax.",
                )
            )

        return findings

    def _scan_python_script(self, file_path: Path, relative_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            parsed_ast = ast.parse(content, filename=str(file_path))
            visitor = DangerousASTVisitor(relative_path)
            visitor.visit(parsed_ast)
            findings.extend(visitor.findings)

        except SyntaxError as se:
            findings.append(
                Finding(
                    rule_id="SEC-PY-SYNTAX-001",
                    title="Python Syntax Error in Repository Script",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"File contains invalid Python syntax at line {se.lineno}: {se.msg}",
                    remediation="Inspect file to see if it is corrupted or disguised non-Python data.",
                    line_number=se.lineno,
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-PY-ERR-001",
                    title="Error Analyzing Python Script",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"AST parser error: {str(e)}",
                    remediation="Audit script manually.",
                )
            )

        return findings
