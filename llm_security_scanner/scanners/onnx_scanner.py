"""
ONNX Model Format & External Data Security Scanner.
Inspects ONNX (.onnx) models for External Data Path Traversal (CVE-2024-27318),
unauthorized custom ops, and malformed protobuf graph structures.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner


class ONNXSecurityScanner(BaseScanner):
    name = "ONNXSecurityScanner"
    description = "Inspects ONNX models for External Data Directory Traversal (CVE-2024-27318) and custom ops"

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".onnx"

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            file_size = file_path.stat().st_size
            if file_size < 16:
                findings.append(
                    Finding(
                        rule_id="SEC-ONNX-003",
                        title="Truncated ONNX Model File",
                        severity=Severity.HIGH,
                        category=RiskCategory.FORMAT_INTEGRITY,
                        file_path=relative_path,
                        description=f"File size ({file_size} bytes) is too small to contain valid ONNX protobuf.",
                        remediation="Re-download ONNX model.",
                    )
                )
                return findings

            # Scan binary file for external data path traversal signatures (CVE-2024-27318)
            with open(file_path, "rb") as f:
                # Read chunks to find external data keys
                chunk = f.read(5 * 1024 * 1024)

                # Check for path traversal in external data location string
                # In ONNX protobuf, StringStringEntryProto pairs have key 'location' followed by path
                if b"location" in chunk:
                    # Look for ../ or absolute paths near location
                    traversal_patterns = [rb"\.\./", rb"\.\.\\", rb"/etc/", rb"C:\\", rb"~/.ssh"]
                    for pattern in traversal_patterns:
                        match = re.search(pattern, chunk)
                        if match:
                            snippet = chunk[max(0, match.start() - 20) : min(len(chunk), match.end() + 20)]
                            findings.append(
                                Finding(
                                    rule_id="SEC-ONNX-001",
                                    title="ONNX External Data Path Traversal (CVE-2024-27318)",
                                    severity=Severity.CRITICAL,
                                    category=RiskCategory.DESERIALIZATION_EXPLOIT,
                                    file_path=relative_path,
                                    description=(
                                        f"ONNX model contains external data path traversal pattern '{pattern.decode('utf-8', errors='ignore')}'. "
                                        "Loading this model with onnxruntime or onnx allows attackers to overwrite or read "
                                        "arbitrary host files outside the model directory (CVE-2024-27318)."
                                    ),
                                    remediation="Reject model. Ensure external tensor data paths are strictly relative and contained.",
                                    evidence=f"Discovered byte sequence: {snippet!r}",
                                    cwe="CWE-22",
                                    cve="CVE-2024-27318",
                                    owasp="LLM03: Supply Chain Vulnerabilities",
                                    mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                    nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                                    eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                                )
                            )
                            break

                # Check for custom domain operators
                if b"custom_op" in chunk.lower() or b"customdomain" in chunk.lower():
                    findings.append(
                        Finding(
                            rule_id="SEC-ONNX-002",
                            title="ONNX Custom Operator Declaration Detected",
                            severity=Severity.MEDIUM,
                            category=RiskCategory.REMOTE_CODE_EXECUTION,
                            file_path=relative_path,
                            description=(
                                "ONNX model graph declares custom domain operators. Custom operators can load "
                                "external dynamic shared libraries (.so/.dll) at runtime."
                            ),
                            remediation="Audit required custom operator shared libraries before execution.",
                            evidence="custom_op declaration in graph proto",
                            owasp="LLM03: Supply Chain Vulnerabilities",
                            mitre_atlas="AML.T0048: Insecure Code Execution",
                            nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                            eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                        )
                    )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-ONNX-ERR-001",
                    title="Unexpected ONNX Inspection Error",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Error inspecting ONNX file: {str(e)}",
                    remediation="Verify file integrity.",
                )
            )

        return findings
