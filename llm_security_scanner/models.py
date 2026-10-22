"""
Core data models for the LLM Model Security Scanner.
Defines severities, categories, findings, scan configuration, and report structures.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import json


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)

    @property
    def color(self) -> str:
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
        }
        return colors.get(self, "white")


class RiskCategory(str, Enum):
    DESERIALIZATION_EXPLOIT = "Deserialization Exploit"
    REMOTE_CODE_EXECUTION = "Remote Code Execution"
    TEMPLATE_INJECTION = "Chat Template Injection (SSTI)"
    WEIGHT_POISONING_ANOMALY = "Weight Poisoning & Anomaly"
    SUSPICIOUS_ARTIFACT = "Suspicious Artifact / Hidden Binary"
    FORMAT_INTEGRITY = "Format Integrity & Header Safety"
    SPECIAL_TOKEN_MANIPULATION = "Special Token Manipulation"
    SECRET_LEAK = "Hardcoded Secret / Token Exposure"
    SUPPLY_CHAIN_TYPOSQUAT = "Supply Chain & Typosquatting"
    METADATA_DEFICIENCY = "Metadata & Licensing Deficiency"
    ADAPTER_POISONING = "LoRA & PEFT Adapter Tampering"
    GENERATION_DOS = "Generation Config & Resource Exhaustion"
    UNICODE_SMUGGLING = "Unicode Bidi & Smuggling Attack"


class SecurityVerdict(str, Enum):
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"

    @property
    def color(self) -> str:
        colors = {
            SecurityVerdict.SAFE: "bold green",
            SecurityVerdict.LOW_RISK: "green",
            SecurityVerdict.MEDIUM_RISK: "yellow",
            SecurityVerdict.HIGH_RISK: "bold yellow",
            SecurityVerdict.CRITICAL: "bold red",
        }
        return colors.get(self, "white")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: RiskCategory
    file_path: str
    description: str
    remediation: str
    evidence: Optional[str] = None
    line_number: Optional[int] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    owasp: Optional[str] = None
    mitre_atlas: Optional[str] = None
    nist_ai_rmf: Optional[str] = None
    eu_ai_act: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "file_path": self.file_path,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "line_number": self.line_number,
            "cwe": self.cwe,
            "cve": self.cve,
            "owasp": self.owasp,
            "mitre_atlas": self.mitre_atlas,
            "nist_ai_rmf": self.nist_ai_rmf,
            "eu_ai_act": self.eu_ai_act,
        }


@dataclass
class ScannerConfig:
    scan_pickles: bool = True
    scan_remote_code: bool = True
    scan_chat_templates: bool = True
    scan_safetensors: bool = True
    scan_gguf: bool = True
    scan_special_tokens: bool = True
    scan_artifacts: bool = True
    scan_weight_anomalies: bool = True
    scan_secrets: bool = True
    scan_peft: bool = True
    scan_generation: bool = True
    scan_onnx: bool = True
    max_file_size_mb: int = 500  # Default cap for in-memory parsing of single files
    deep_weight_sampling: bool = True
    sample_tensors_count: int = 15
    entropy_threshold: float = 7.5


@dataclass
class ScanReport:
    target: str
    is_remote: bool
    scanned_files_count: int
    total_bytes_scanned: int
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 (pristine) to 100.0 (critical threat)
    verdict: SecurityVerdict = SecurityVerdict.SAFE
    duration_seconds: float = 0.0
    model_formats_found: List[str] = field(default_factory=list)
    model_architecture: Optional[str] = None
    cached_dir: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def compute_risk_score_and_verdict(self) -> None:
        """
        Calculates an overall risk score from 0.0 to 100.0 and assigns a security verdict.
        Weights:
          - CRITICAL: 35 pts each (capped at 100)
          - HIGH: 18 pts each
          - MEDIUM: 7 pts each
          - LOW: 2 pts each
          - INFO: 0.5 pts each
        """
        score = (
            self.critical_count * 35.0
            + self.high_count * 18.0
            + self.medium_count * 7.0
            + self.low_count * 2.0
            + self.info_count * 0.5
        )
        self.risk_score = min(100.0, round(score, 1))

        if self.critical_count > 0:
            self.verdict = SecurityVerdict.CRITICAL
        elif self.high_count > 0 or self.risk_score >= 40.0:
            self.verdict = SecurityVerdict.HIGH_RISK
        elif self.medium_count > 0 or self.risk_score >= 15.0:
            self.verdict = SecurityVerdict.MEDIUM_RISK
        elif self.low_count > 0 or self.risk_score >= 5.0:
            self.verdict = SecurityVerdict.LOW_RISK
        else:
            self.verdict = SecurityVerdict.SAFE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "is_remote": self.is_remote,
            "scanned_files_count": self.scanned_files_count,
            "total_bytes_scanned": self.total_bytes_scanned,
            "risk_score": self.risk_score,
            "verdict": self.verdict.value,
            "duration_seconds": round(self.duration_seconds, 3),
            "model_formats_found": self.model_formats_found,
            "model_architecture": self.model_architecture,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
