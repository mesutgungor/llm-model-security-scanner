"""
SafeTensors Format Integrity and Header Security Scanner.
Inspects SafeTensors files (.safetensors) for header allocation DoS (CVE-2023-44469),
out-of-bounds tensor offsets, corrupted metadata, and hidden payloads in __metadata__.
"""

from __future__ import annotations
import json
import struct
from pathlib import Path
from typing import Any, Dict, List

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

# Maximum reasonable header size (100 MB is already astronomically large for a tensor JSON header)
MAX_SAFE_HEADER_SIZE = 100 * 1024 * 1024


class SafeTensorsSecurityScanner(BaseScanner):
    name = "SafeTensorsSecurityScanner"
    description = "Validates SafeTensors 8-byte header size, tensor offsets, and metadata safety"

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".safetensors"

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            file_size = file_path.stat().st_size
            if file_size < 8:
                findings.append(
                    Finding(
                        rule_id="SEC-ST-001",
                        title="Truncated SafeTensors File",
                        severity=Severity.HIGH,
                        category=RiskCategory.FORMAT_INTEGRITY,
                        file_path=relative_path,
                        description=f"File is smaller than the required 8-byte SafeTensors header (size: {file_size} bytes).",
                        remediation="Re-download the weights.",
                    )
                )
                return findings

            with open(file_path, "rb") as f:
                header_len_bytes = f.read(8)
                (header_len,) = struct.unpack("<Q", header_len_bytes)

                # 1. Header size sanity check (prevent DoS memory bomb)
                if header_len <= 0:
                    findings.append(
                        Finding(
                            rule_id="SEC-ST-002",
                            title="Invalid Zero or Negative Header Length",
                            severity=Severity.HIGH,
                            category=RiskCategory.FORMAT_INTEGRITY,
                            file_path=relative_path,
                            description=f"SafeTensors header size indicates invalid size: {header_len}.",
                            remediation="Do not load file; ensure proper SafeTensors conversion.",
                        )
                    )
                    return findings

                if header_len > MAX_SAFE_HEADER_SIZE or header_len + 8 > file_size:
                    findings.append(
                        Finding(
                            rule_id="SEC-ST-003",
                            title="SafeTensors Header Allocation DoS Vulnerability",
                            severity=Severity.CRITICAL,
                            category=RiskCategory.FORMAT_INTEGRITY,
                            file_path=relative_path,
                            description=(
                                f"Declared header length ({header_len} bytes) exceeds maximum safety threshold "
                                f"or file bounds ({file_size} bytes). This resembles a header allocation memory bomb "
                                f"(CVE-2023-44469) designed to crash the inference server via OOM."
                            ),
                            remediation="Discard the model file; do not attempt to load with unpatched loaders.",
                            evidence=f"Header len: {header_len}, File size: {file_size}",
                            cwe="CWE-400",
                            cve="CVE-2023-44469",
                            owasp="LLM10: Unbounded Consumption",
                            mitre_atlas="AML.T0029: Denial of Service",
                            nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                            eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                        )
                    )
                    return findings

                # 2. Parse and validate JSON header
                header_bytes = f.read(header_len)
                try:
                    header_json = json.loads(header_bytes.decode("utf-8"))
                except Exception as je:
                    findings.append(
                        Finding(
                            rule_id="SEC-ST-004",
                            title="Malformed SafeTensors JSON Header",
                            severity=Severity.HIGH,
                            category=RiskCategory.FORMAT_INTEGRITY,
                            file_path=relative_path,
                            description=f"Could not parse SafeTensors header JSON: {str(je)}",
                            remediation="Validate header encoding.",
                        )
                    )
                    return findings

                # 3. Verify tensor offsets and check for out-of-bounds or overlapping anomalies
                data_start_offset = 8 + header_len
                total_data_len = file_size - data_start_offset

                metadata = header_json.get("__metadata__", {})
                if metadata:
                    self._check_metadata(metadata, relative_path, findings)

                for tensor_name, tensor_info in header_json.items():
                    if tensor_name == "__metadata__":
                        continue

                    if not isinstance(tensor_info, dict) or "data_offsets" not in tensor_info:
                        findings.append(
                            Finding(
                                rule_id="SEC-ST-005",
                                title=f"Invalid Tensor Metadata Entry: '{tensor_name}'",
                                severity=Severity.MEDIUM,
                                category=RiskCategory.FORMAT_INTEGRITY,
                                file_path=relative_path,
                                description=f"Tensor entry '{tensor_name}' missing data_offsets or invalid format.",
                                remediation="Ensure standard SafeTensors format specification.",
                            )
                        )
                        continue

                    offsets = tensor_info["data_offsets"]
                    if len(offsets) != 2:
                        continue

                    start_off, end_off = offsets
                    if start_off < 0 or end_off < start_off:
                        findings.append(
                            Finding(
                                rule_id="SEC-ST-006",
                                title=f"Invalid Negative or Inverted Offsets: '{tensor_name}'",
                                severity=Severity.CRITICAL,
                                category=RiskCategory.FORMAT_INTEGRITY,
                                file_path=relative_path,
                                description=f"Offsets [{start_off}, {end_off}] for tensor '{tensor_name}' violate file bounds.",
                                remediation="Reject file; malformed offsets can lead to memory corruption.",
                                cwe="CWE-125",
                                owasp="LLM03: Supply Chain Vulnerabilities",
                                mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                                eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                            )
                        )
                    elif end_off > total_data_len:
                        findings.append(
                            Finding(
                                rule_id="SEC-ST-007",
                                title=f"Tensor Data Exceeds File Boundary: '{tensor_name}'",
                                severity=Severity.CRITICAL,
                                category=RiskCategory.FORMAT_INTEGRITY,
                                file_path=relative_path,
                                description=(
                                    f"Tensor '{tensor_name}' offset {end_off} exceeds available data segment "
                                    f"({total_data_len} bytes). Can trigger out-of-bounds read."
                                ),
                                remediation="Verify complete file download.",
                                cwe="CWE-125",
                            )
                        )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-ST-ERR-001",
                    title="Unexpected SafeTensors Scan Failure",
                    severity=Severity.MEDIUM,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Error inspecting SafeTensors file: {str(e)}",
                    remediation="Inspect file integrity.",
                )
            )

        return findings

    def _check_metadata(self, metadata: Dict[str, Any], file_path: str, findings: List[Finding]) -> None:
        """Inspects SafeTensors __metadata__ for suspicious script fragments or steganography."""
        for key, val in metadata.items():
            val_str = str(val)
            if any(cmd in val_str.lower() for cmd in ("eval(", "exec(", "subprocess", "os.system", "/bin/sh", "powershell")):
                findings.append(
                    Finding(
                        rule_id="SEC-ST-META-001",
                        title=f"Suspicious Executable Pattern in SafeTensors Metadata '{key}'",
                        severity=Severity.HIGH,
                        category=RiskCategory.SUSPICIOUS_ARTIFACT,
                        file_path=file_path,
                        description=f"SafeTensors __metadata__ key '{key}' contains suspicious command/script pattern.",
                        remediation="Review custom metadata fields for hidden command payloads.",
                        evidence=val_str[:150],
                    )
                )
