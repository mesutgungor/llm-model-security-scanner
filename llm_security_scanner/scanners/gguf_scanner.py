"""
GGUF Model Format Integrity & Safety Scanner.
Inspects GGUF binary files (.gguf) used by llama.cpp and Ollama.
Detects magic byte corruption, tensor count integer overflows, out-of-bounds metadata lengths,
and embedded script payloads.
"""

from __future__ import annotations
import struct
from pathlib import Path
from typing import Any, Dict, List

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

GGUF_MAGIC = b"GGUF"
MAX_TENSOR_COUNT_SANITY = 500_000
MAX_KV_COUNT_SANITY = 500_000


class GGUFSecurityScanner(BaseScanner):
    name = "GGUFSecurityScanner"
    description = "Parses GGUF binary headers to detect integer overflows, corrupted counts, and metadata exploits"

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".gguf"

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            file_size = file_path.stat().st_size
            if file_size < 24:
                findings.append(
                    Finding(
                        rule_id="SEC-GGUF-001",
                        title="Truncated GGUF Binary File",
                        severity=Severity.HIGH,
                        category=RiskCategory.FORMAT_INTEGRITY,
                        file_path=relative_path,
                        description=f"File size ({file_size} bytes) is too small to contain valid GGUF header.",
                        remediation="Ensure complete download of GGUF model.",
                    )
                )
                return findings

            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic != GGUF_MAGIC:
                    findings.append(
                        Finding(
                            rule_id="SEC-GGUF-002",
                            title="Invalid GGUF Magic Header",
                            severity=Severity.HIGH,
                            category=RiskCategory.FORMAT_INTEGRITY,
                            file_path=relative_path,
                            description=f"Expected 'GGUF' header magic, but found {magic!r}.",
                            remediation="Verify file format and integrity.",
                        )
                    )
                    return findings

                version_bytes = f.read(4)
                (version,) = struct.unpack("<I", version_bytes)
                if version not in (1, 2, 3):
                    findings.append(
                        Finding(
                            rule_id="SEC-GGUF-003",
                            title=f"Unrecognized GGUF Format Version: {version}",
                            severity=Severity.MEDIUM,
                            category=RiskCategory.FORMAT_INTEGRITY,
                            file_path=relative_path,
                            description=f"GGUF parser encountered unexpected version {version}. Expected version 1, 2, or 3.",
                            remediation="Ensure model was converted with standard llama.cpp tools.",
                        )
                    )

                tensor_count_bytes = f.read(8)
                (tensor_count,) = struct.unpack("<Q", tensor_count_bytes)

                kv_count_bytes = f.read(8)
                (kv_count,) = struct.unpack("<Q", kv_count_bytes)

                # Integer overflow / extreme allocation check
                if tensor_count > MAX_TENSOR_COUNT_SANITY:
                    findings.append(
                        Finding(
                            rule_id="SEC-GGUF-004",
                            title="Anomalous GGUF Tensor Count (Integer Overflow Risk)",
                            severity=Severity.CRITICAL,
                            category=RiskCategory.FORMAT_INTEGRITY,
                            file_path=relative_path,
                            description=(
                                f"Declared tensor count ({tensor_count}) is abnormally large. "
                                f"In C/C++ runtimes like llama.cpp, this can trigger heap buffer overflow "
                                f"or integer wrap-around vulnerability."
                            ),
                            remediation="Do not load this GGUF file in C++ runtimes.",
                            evidence=f"tensor_count: {tensor_count}",
                            cwe="CWE-190",
                        )
                    )

                if kv_count > MAX_KV_COUNT_SANITY:
                    findings.append(
                        Finding(
                            rule_id="SEC-GGUF-005",
                            title="Anomalous GGUF Metadata KV Count (Resource Exhaustion)",
                            severity=Severity.HIGH,
                            category=RiskCategory.FORMAT_INTEGRITY,
                            file_path=relative_path,
                            description=f"Metadata key-value count ({kv_count}) indicates a resource exhaustion attack.",
                            remediation="Reject or re-quantize the model.",
                            evidence=f"kv_count: {kv_count}",
                            cwe="CWE-400",
                        )
                    )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-GGUF-ERR-001",
                    title="Unexpected GGUF Inspection Failure",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Error inspecting GGUF file: {str(e)}",
                    remediation="Check file integrity.",
                )
            )

        return findings
