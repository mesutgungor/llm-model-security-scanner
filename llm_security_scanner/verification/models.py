"""
Data models for the Proof-of-Finding & Verification Engine.
Provides cryptographically verifiable proof records and consumer audit dossiers.
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

    @property
    def badge(self) -> str:
        badges = {
            VerificationStatus.VERIFIED: "✅ VERIFIED PROOF",
            VerificationStatus.UNVERIFIED: "⚠️ UNVERIFIED",
            VerificationStatus.NOT_APPLICABLE: "ℹ️ INFORMATIONAL",
        }
        return badges.get(self, "UNKNOWN")

    @property
    def color(self) -> str:
        colors = {
            VerificationStatus.VERIFIED: "bold green",
            VerificationStatus.UNVERIFIED: "yellow",
            VerificationStatus.NOT_APPLICABLE: "dim",
        }
        return colors.get(self, "white")


@dataclass
class VerificationProof:
    """An objective, non-destructive proof artifact verifying a security finding."""
    rule_id: str
    finding_title: str
    file_path: str
    file_sha256: str
    status: VerificationStatus
    methodology: str
    reproduction_steps: List[str]
    proof_data: Dict[str, Any]
    consumer_impact_summary: str
    remediation_recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "finding_title": self.finding_title,
            "file_path": self.file_path,
            "file_sha256": self.file_sha256,
            "status": self.status.value,
            "methodology": self.methodology,
            "reproduction_steps": self.reproduction_steps,
            "proof_data": self.proof_data,
            "consumer_impact_summary": self.consumer_impact_summary,
            "remediation_recommendation": self.remediation_recommendation,
        }


@dataclass
class VerificationDossier:
    """A consumer-facing dossier containing objective proofs for all detected vulnerabilities."""
    target: str
    total_findings_count: int
    verified_findings_count: int
    proofs: List[VerificationProof] = field(default_factory=list)
    generation_time: str = ""

    @property
    def verification_rate(self) -> float:
        if self.total_findings_count == 0:
            return 100.0
        return round((self.verified_findings_count / self.total_findings_count) * 100.0, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "generation_time": self.generation_time,
            "total_findings_count": self.total_findings_count,
            "verified_findings_count": self.verified_findings_count,
            "verification_rate_percent": self.verification_rate,
            "proofs": [p.to_dict() for p in self.proofs],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def compute_file_sha256(file_path: Path) -> str:
    """Computes SHA-256 hash of a file for cryptographic non-repudiation."""
    if not file_path.exists() or not file_path.is_file():
        return "N/A (Remote / Virtual Manifest)"
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "ERROR_COMPUTING_HASH"
