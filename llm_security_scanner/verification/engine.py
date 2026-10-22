"""
Central Proof-of-Finding Verification Engine.
Coordinates verifiers to execute non-destructive reproduction tests and produce
cryptographically backed audit proof dossiers for consumers and auditors.
"""

from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from llm_security_scanner.models import Finding, ScanReport
from llm_security_scanner.verification.models import (
    VerificationDossier,
    VerificationProof,
    VerificationStatus,
    compute_file_sha256,
)
from llm_security_scanner.verification.verifiers.base import BaseVerifier
from llm_security_scanner.verification.verifiers.pickle_verifier import PickleOpcodeVerifier
from llm_security_scanner.verification.verifiers.remote_code_verifier import RemoteCodeVerifier
from llm_security_scanner.verification.verifiers.safetensors_verifier import SafeTensorsBoundVerifier
from llm_security_scanner.verification.verifiers.template_verifier import ChatTemplateVerifier
from llm_security_scanner.verification.verifiers.token_verifier import TokenDelimiterVerifier
from llm_security_scanner.verification.verifiers.weight_verifier import WeightPoisonVerifier


class FindingVerificationEngine:
    """Verifies security scanner findings and generates consumer-facing proof dossiers."""

    def __init__(self):
        self.verifiers: List[BaseVerifier] = [
            TokenDelimiterVerifier(),
            RemoteCodeVerifier(),
            PickleOpcodeVerifier(),
            SafeTensorsBoundVerifier(),
            WeightPoisonVerifier(),
            ChatTemplateVerifier(),
        ]

    def verify_report(self, report: ScanReport, root_dir: Optional[Path] = None) -> VerificationDossier:
        """
        Runs verification tests on all findings in a scan report and generates a Proof Dossier.
        """
        proofs: List[VerificationProof] = []
        target_path = root_dir
        if not target_path:
            if report.cached_dir and Path(report.cached_dir).exists():
                target_path = Path(report.cached_dir)
            else:
                target_path = Path(report.target)

        for finding in report.findings:
            proof = self._verify_single_finding(finding, target_path)
            proofs.append(proof)

        verified_count = sum(1 for p in proofs if p.status == VerificationStatus.VERIFIED)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        dossier = VerificationDossier(
            target=report.target,
            total_findings_count=len(report.findings),
            verified_findings_count=verified_count,
            proofs=proofs,
            generation_time=now_str,
        )
        return dossier

    def _verify_single_finding(self, finding: Finding, root_dir: Path) -> VerificationProof:
        for verifier in self.verifiers:
            if verifier.can_verify(finding):
                try:
                    return verifier.verify(finding, root_dir)
                except Exception as e:
                    # In case of verification error, produce record noting the attempt
                    return VerificationProof(
                        rule_id=finding.rule_id,
                        finding_title=finding.title,
                        file_path=finding.file_path,
                        file_sha256=compute_file_sha256(root_dir / finding.file_path),
                        status=VerificationStatus.UNVERIFIED,
                        methodology="Attempted Verification",
                        reproduction_steps=[f"Verification attempt encountered error: {str(e)}"],
                        proof_data={"error": str(e)},
                        consumer_impact_summary="Verification could not be completed automatically.",
                        remediation_recommendation=finding.remediation,
                    )

        # Default fallback if no specialized verifier exists for this rule
        return VerificationProof(
            rule_id=finding.rule_id,
            finding_title=finding.title,
            file_path=finding.file_path,
            file_sha256=compute_file_sha256(root_dir / finding.file_path),
            status=VerificationStatus.NOT_APPLICABLE,
            methodology="Static Indicator Match",
            reproduction_steps=[
                f"1. Verified rule match '{finding.rule_id}' against artifact '{finding.file_path}'.",
                f"2. Evidence matched: {finding.evidence or 'Static file presence'}.",
            ],
            proof_data={"evidence": finding.evidence},
            consumer_impact_summary=finding.description,
            remediation_recommendation=finding.remediation,
        )
