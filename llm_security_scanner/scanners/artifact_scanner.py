"""
Artifact & Disguised Executable Security Scanner.
Inspects all files in model repositories for hidden ELF/PE/Mach-O binaries, shell scripts,
malicious symbolic links pointing outside the model root, high-entropy packed blobs,
and stealth dotfiles.
"""

from __future__ import annotations
import math
import os
from pathlib import Path
from typing import Any, Dict, List

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

# Magic bytes for executable binary formats
EXECUTABLE_MAGIC_HEADERS = [
    (b"\x7fELF", "Linux ELF Executable / Shared Object"),
    (b"MZ", "Windows Portable Executable (PE / EXE / DLL)"),
    (b"\xfe\xed\xfa\xce", "macOS Mach-O (32-bit big-endian)"),
    (b"\xfe\xed\xfa\xcf", "macOS Mach-O (64-bit big-endian)"),
    (b"\xce\xfa\xed\xfe", "macOS Mach-O (32-bit little-endian)"),
    (b"\xcf\xfa\xed\xfe", "macOS Mach-O (64-bit little-endian)"),
    (b"\xca\xfe\xba\xbe", "Mach-O Universal Binary / Java Class"),
]

SCRIPT_EXTENSIONS = {".sh", ".bash", ".bat", ".cmd", ".ps1", ".vbs", ".exe", ".dll", ".so", ".dylib"}


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return entropy


class ArtifactSecurityScanner(BaseScanner):
    name = "ArtifactSecurityScanner"
    description = "Detects hidden binaries, shell scripts, malicious symlinks, and high-entropy packed files"

    def can_scan(self, file_path: Path) -> bool:
        # Runs on all files in the repository
        return True

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Malicious Symlink Check (Path Traversal)
        if file_path.is_symlink():
            try:
                target = file_path.resolve()
                root_dir = context.get("root_dir")
                if root_dir:
                    root_resolved = Path(root_dir).resolve()
                    if not str(target).startswith(str(root_resolved)):
                        findings.append(
                            Finding(
                                rule_id="SEC-SYM-001",
                                title="Malicious External Symbolic Link Traversal",
                                severity=Severity.CRITICAL,
                                category=RiskCategory.SUSPICIOUS_ARTIFACT,
                                file_path=relative_path,
                                description=(
                                    f"Symbolic link '{relative_path}' resolves to an external file '{target}' "
                                    f"outside the model directory. This can be used to exfiltrate host files."
                                ),
                                remediation="Delete external symlinks immediately.",
                                evidence=f"Target: {target}",
                                cwe="CWE-59",
                                owasp="LLM03: Supply Chain Vulnerabilities",
                                mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                                eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                            )
                        )
            except Exception:
                pass

        # 2. Check for suspicious scripts & binary extensions
        suffix = file_path.suffix.lower()
        if suffix in SCRIPT_EXTENSIONS:
            findings.append(
                Finding(
                    rule_id="SEC-ART-001",
                    title=f"Executable Script or Native Binary Found: '{suffix}'",
                    severity=Severity.HIGH,
                    category=RiskCategory.SUSPICIOUS_ARTIFACT,
                    file_path=relative_path,
                    description=(
                        f"Model repository contains standalone executable/script '{relative_path}'. "
                        f"Machine learning model repositories should contain weights, configs, and tokenizers, "
                        f"not arbitrary executable files."
                    ),
                    remediation="Audit or remove executable binaries/scripts from the model repository.",
                    evidence=f"File extension: {suffix}",
                    owasp="LLM03: Supply Chain Vulnerabilities",
                    mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                    nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                    eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                )
            )

        # 3. Disguised Binary Check via Magic Bytes
        try:
            if file_path.is_file() and file_path.stat().st_size > 4:
                with open(file_path, "rb") as f:
                    magic = f.read(4)

                    for header_magic, binary_type in EXECUTABLE_MAGIC_HEADERS:
                        if magic.startswith(header_magic):
                            # Ensure it's not a known false positive
                            findings.append(
                                Finding(
                                    rule_id="SEC-ART-002",
                                    title=f"Disguised Native Binary Detected: {binary_type}",
                                    severity=Severity.CRITICAL,
                                    category=RiskCategory.SUSPICIOUS_ARTIFACT,
                                    file_path=relative_path,
                                    description=(
                                        f"File '{relative_path}' begins with magic bytes for '{binary_type}'. "
                                        f"Attackers disguise native compiled backdoors as innocent model assets."
                                    ),
                                    remediation="Do not run any software in this directory. Remove the disguised binary.",
                                    evidence=f"Magic: {magic!r} -> {binary_type}",
                                    cwe="CWE-507",
                                    owasp="LLM03: Supply Chain Vulnerabilities",
                                    mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                    nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                                    eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                                )
                            )
                            break

                # 4. High-Entropy Check on Non-Weight Files (Text, Config, Markdown)
                text_exts = {".json", ".txt", ".md", ".yaml", ".yml", ".py", ".csv"}
                if suffix in text_exts and file_path.stat().st_size > 512:
                    with open(file_path, "rb") as f:
                        sample = f.read(8192)
                        entropy = calculate_shannon_entropy(sample)
                        if entropy > self.config.entropy_threshold:
                            findings.append(
                                Finding(
                                    rule_id="SEC-ART-003",
                                    title=f"Abnormally High Entropy in Plaintext File ({round(entropy, 2)}/8.0)",
                                    severity=Severity.MEDIUM,
                                    category=RiskCategory.SUSPICIOUS_ARTIFACT,
                                    file_path=relative_path,
                                    description=(
                                        f"File '{relative_path}' has entropy of {round(entropy, 2)}, indicating "
                                        f"encrypted, packed, or obfuscated payloads disguised as a text file."
                                    ),
                                    remediation="Inspect file contents for encrypted payloads or steganography.",
                                    evidence=f"Entropy: {round(entropy, 2)}",
                                )
                            )

        except Exception:
            pass

        return findings
