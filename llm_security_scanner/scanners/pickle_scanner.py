"""
Pickle & PyTorch Weights Security Scanner.
Performs zero-execution static opcode disassembly on PyTorch checkpoints (.bin, .pt, .pth, .ckpt, .pkl, .joblib).
Detects arbitrary code execution, dangerous globals, reduce exploits, and malicious ZipSlip archives.
"""

from __future__ import annotations
import io
import pickletools
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner


# Explicit list of inherently dangerous builtins and modules
DANGEROUS_CALLS = {
    # Process execution & system shells
    ("os", "system"),
    ("os", "popen"),
    ("os", "spawn"),
    ("os", "spawnl"),
    ("os", "spawnle"),
    ("os", "spawnv"),
    ("os", "spawnve"),
    ("posix", "system"),
    ("nt", "system"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "run"),
    ("pty", "spawn"),
    ("commands", "getstatusoutput"),
    ("commands", "getoutput"),

    # Code execution & reflection
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
    ("builtins", "compile"),
    ("builtins", "open"),
    ("builtins", "getattr"),
    ("builtins", "setattr"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
    ("__builtin__", "__import__"),
    ("__builtin__", "open"),
    ("importlib", "import_module"),
    ("sys", "exit"),

    # Network / Remote Access
    ("socket", "socket"),
    ("urllib.request", "urlopen"),
    ("urllib.request", "urlretrieve"),
    ("requests", "get"),
    ("requests", "post"),
    ("http.client", "HTTPConnection"),
    ("http.client", "HTTPSConnection"),

    # File system manipulation
    ("shutil", "rmtree"),
    ("shutil", "copy"),
    ("shutil", "move"),
    ("io", "FileIO"),
}

# Known benign primitives typically found in PyTorch models
BENIGN_GLOBALS_PREFIXES = {
    "torch.",
    "torch._utils.",
    "torch.nn.",
    "collections.OrderedDict",
    "collections.defaultdict",
    "numpy.",
    "_codecs.encode",
    "builtins.bytearray",
    "builtins.dict",
    "builtins.list",
    "builtins.set",
    "builtins.tuple",
    "builtins.int",
    "builtins.float",
    "builtins.str",
    "builtins.bool",
}


class PickleSecurityScanner(BaseScanner):
    name = "PickleSecurityScanner"
    description = "Inspects PyTorch / Pickle model weights using zero-execution opcode analysis"

    EXTENSIONS = {".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib", ".model"}

    def can_scan(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if name.endswith(".json") or name.endswith(".txt") or name.endswith(".md"):
            return False
        if file_path.suffix.lower() in self.EXTENSIONS:
            return True
        # Check by filename conventions
        if "pytorch_model" in name or "checkpoint" in name:
            return True
        return False

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with open(file_path, "rb") as f:
                header = f.read(4)
                f.seek(0)

                # Check if it's a ZIP archive (PyTorch checkpoint format)
                if header.startswith(b"PK\x03\x04"):
                    findings.extend(self._scan_zip_archive(f, relative_path))
                else:
                    # Raw pickle stream
                    stream_data = f.read()
                    findings.extend(self._analyze_pickle_stream(stream_data, relative_path))

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-PCK-000",
                    title="Pickle Parsing Error / Malformed Stream",
                    severity=Severity.MEDIUM,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Failed to inspect pickle stream: {str(e)}. File might be corrupt or deliberately obfuscated.",
                    remediation="Validate model file integrity against official publisher SHA-256 hashes.",
                )
            )

        return findings

    def _scan_zip_archive(self, file_obj: io.BufferedReader, relative_path: str) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with zipfile.ZipFile(file_obj, "r") as zf:
                # 1. ZipSlip & Path Traversal Check
                for info in zf.infolist():
                    name = info.filename
                    if name.startswith("/") or ".." in name or name.startswith("\\"):
                        findings.append(
                            Finding(
                                rule_id="SEC-ZIP-001",
                                title="ZipSlip Path Traversal Vulnerability",
                                severity=Severity.CRITICAL,
                                category=RiskCategory.DESERIALIZATION_EXPLOIT,
                                file_path=relative_path,
                                description=f"PyTorch ZIP container contains unsafe relative path '{name}' leading outside extraction root.",
                                remediation="Reject this model archive immediately. It is crafted to overwrite host system files.",
                                evidence=f"Archive Entry: {name}",
                                cwe="CWE-22",
                                owasp="LLM03: Supply Chain Vulnerabilities",
                                mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                                eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                            )
                        )

                # 2. Inspect all embedded pickle files in archive (typically archive/data.pkl)
                for info in zf.infolist():
                    if info.filename.endswith(".pkl") or info.filename.endswith("/data.pkl"):
                        with zf.open(info) as pkl_file:
                            data = pkl_file.read()
                            pkl_rel_path = f"{relative_path}::{info.filename}"
                            findings.extend(self._analyze_pickle_stream(data, pkl_rel_path))

        except zipfile.BadZipFile:
            findings.append(
                Finding(
                    rule_id="SEC-ZIP-002",
                    title="Corrupted PyTorch ZIP Container",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description="File has ZIP magic bytes but is corrupted or truncated.",
                    remediation="Re-download or verify the model weights.",
                )
            )

        return findings

    def _analyze_pickle_stream(self, data: bytes, target_path: str) -> List[Finding]:
        findings: List[Finding] = []
        loaded_globals: List[Tuple[str, str]] = []
        stack: List[Any] = []
        reduce_encountered = False

        try:
            for opcode, arg, pos in pickletools.genops(data):
                op_name = opcode.name

                if op_name in ("GLOBAL", "STACK_GLOBAL"):
                    module_name = ""
                    func_name = ""

                    if op_name == "GLOBAL":
                        parts = arg.split(" ", 1)
                        if len(parts) == 2:
                            module_name, func_name = parts[0], parts[1]
                    elif op_name == "STACK_GLOBAL":
                        if len(stack) >= 2:
                            func_candidate = stack.pop()
                            mod_candidate = stack.pop()
                            if isinstance(mod_candidate, str) and isinstance(func_candidate, str):
                                module_name, func_name = mod_candidate, func_candidate

                    if module_name and func_name:
                        loaded_globals.append((module_name, func_name))
                        full_qual = f"{module_name}.{func_name}"

                        # Check against known exploit calls
                        if (module_name, func_name) in DANGEROUS_CALLS:
                            findings.append(
                                Finding(
                                    rule_id="SEC-PCK-001",
                                    title="Arbitrary Code Execution via Insecure Deserialization",
                                    severity=Severity.CRITICAL,
                                    category=RiskCategory.DESERIALIZATION_EXPLOIT,
                                    file_path=target_path,
                                    description=(
                                        f"Malicious opcode '{op_name}' detected loading dangerous target "
                                        f"'{full_qual}'. When loaded with torch.load() or pickle.load(), "
                                        f"this will execute arbitrary code on the host machine!"
                                    ),
                                    remediation="DO NOT LOAD THIS MODEL. Convert models strictly to SafeTensors format (.safetensors).",
                                    evidence=f"Opcode: {op_name} at offset {pos} -> {full_qual}",
                                    cwe="CWE-502",
                                    cve="CVE-2024-XXXX",
                                    owasp="LLM03: Supply Chain Vulnerabilities",
                                    mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                    nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                                    eu_ai_act="Article 15 (Cybersecurity & Robustness), Article 55 (Systemic Risk)",
                                )
                            )
                        else:
                            # Check if not a recognized benign prefix
                            is_known_benign = any(
                                full_qual.startswith(prefix) for prefix in BENIGN_GLOBALS_PREFIXES
                            )
                            if not is_known_benign:
                                findings.append(
                                    Finding(
                                        rule_id="SEC-PCK-002",
                                        title=f"Suspicious Global Loaded in Pickle: {full_qual}",
                                        severity=Severity.HIGH,
                                        category=RiskCategory.DESERIALIZATION_EXPLOIT,
                                        file_path=target_path,
                                        description=(
                                            f"Pickle stream loads unrecognized global object '{full_qual}'. "
                                            f"Clean PyTorch model weights should only contain tensor storage classes."
                                        ),
                                        remediation="Inspect what custom class is being serialized. Prefer SafeTensors format.",
                                        evidence=f"Offset {pos}: {full_qual}",
                                        cwe="CWE-502",
                                        owasp="LLM03: Supply Chain Vulnerabilities",
                                        mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                        nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                                    )
                                )

                elif op_name in ("REDUCE", "BUILD", "INST", "OBJ"):
                    reduce_encountered = True

                elif op_name in ("UNICODE", "BINUNICODE", "SHORT_BINUNICODE"):
                    stack.append(arg)
                elif op_name in ("INT", "BININT", "BININT1", "BININT2"):
                    stack.append(arg)
                elif op_name == "MARK":
                    pass

        except Exception as e:
            # If the pickle stream is truncated or malformed
            findings.append(
                Finding(
                    rule_id="SEC-PCK-003",
                    title="Incomplete or Malformed Pickle Bytecode",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=target_path,
                    description=f"Pickle disassembler encountered unexpected byte sequence: {str(e)}",
                    remediation="Verify download completeness.",
                )
            )

        # Informational advisory if the model is using legacy pickle format rather than safetensors
        if not findings:
            findings.append(
                Finding(
                    rule_id="SEC-PCK-INFO-001",
                    title="Legacy Pickle Serialization Detected",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=target_path,
                    description=(
                        "File uses legacy PyTorch pickle format. While no overtly malicious opcodes were identified, "
                        "pickle files are inherently unsafe by design compared to SafeTensors."
                    ),
                    remediation="Convert model weights to SafeTensors using 'safetensors.torch.save_model()'.",
                )
            )

        return findings
