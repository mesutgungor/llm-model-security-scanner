"""
Unit and integration tests for the FindingVerificationEngine and Proof Verifiers.
"""

import json
import struct
import tempfile
import unittest
from pathlib import Path

import torch
from safetensors.torch import save_file

from llm_security_scanner.models import Finding, RiskCategory, ScanReport, Severity
from llm_security_scanner.verification.engine import FindingVerificationEngine
from llm_security_scanner.verification.models import VerificationStatus
from llm_security_scanner.verification.verifiers.remote_code_verifier import RemoteCodeVerifier
from llm_security_scanner.verification.verifiers.safetensors_verifier import SafeTensorsBoundVerifier
from llm_security_scanner.verification.verifiers.token_verifier import TokenDelimiterVerifier
from llm_security_scanner.verification.verifiers.weight_verifier import WeightPoisonVerifier


class TestVerificationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = FindingVerificationEngine()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_token_delimiter_proof(self):
        tok_file = self.root_path / "tokenizer.json"
        data = {
            "added_tokens": [
                {"id": 151644, "content": "<|im_start|>", "special": False, "normalized": False}
            ]
        }
        tok_file.write_text(json.dumps(data), encoding="utf-8")

        finding = Finding(
            rule_id="SEC-TOK-004",
            title="Critical Delimiter Marked Non-Special: '<|im_start|>'",
            severity=Severity.HIGH,
            category=RiskCategory.SPECIAL_TOKEN_MANIPULATION,
            file_path="tokenizer.json",
            description="Control delimiter has special=false.",
            remediation="Set special=true.",
        )

        verifier = TokenDelimiterVerifier()
        proof = verifier.verify(finding, self.root_path)

        self.assertEqual(proof.status, VerificationStatus.VERIFIED)
        self.assertIn("151644", str(proof.proof_data))
        self.assertGreater(len(proof.reproduction_steps), 3)
        self.assertIn("CONFIRMED PROMPT INJECTION", proof.consumer_impact_summary)

    def test_remote_code_auto_map_proof(self):
        cfg_file = self.root_path / "config.json"
        data = {
            "auto_map": {
                "AutoModelForCausalLM": "modeling_demo.DemoModel"
            }
        }
        cfg_file.write_text(json.dumps(data), encoding="utf-8")

        finding = Finding(
            rule_id="SEC-RCE-MAP-001",
            title="Remote Custom Code Registration (auto_map)",
            severity=Severity.HIGH,
            category=RiskCategory.REMOTE_CODE_EXECUTION,
            file_path="config.json",
            description="Auto map detected.",
            remediation="Audit custom code.",
        )

        verifier = RemoteCodeVerifier()
        proof = verifier.verify(finding, self.root_path)

        self.assertEqual(proof.status, VerificationStatus.VERIFIED)
        self.assertIn("modeling_demo.py", proof.proof_data["referenced_custom_scripts"])

    def test_safetensors_header_dos_proof(self):
        st_file = self.root_path / "model.safetensors"
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", 500 * 1024 * 1024))
            f.write(b"SAMPLE")

        finding = Finding(
            rule_id="SEC-ST-003",
            title="SafeTensors Header Allocation DoS Vulnerability",
            severity=Severity.CRITICAL,
            category=RiskCategory.FORMAT_INTEGRITY,
            file_path="model.safetensors",
            description="Header size bomb.",
            remediation="Discard file.",
        )

        verifier = SafeTensorsBoundVerifier()
        proof = verifier.verify(finding, self.root_path)

        self.assertEqual(proof.status, VerificationStatus.VERIFIED)
        self.assertGreater(proof.proof_data["declared_header_len_bytes"], 1000000)

    def test_weight_poison_coordinate_proof(self):
        st_file = self.root_path / "weights.safetensors"
        t = torch.randn(4, 4)
        t[1, 2] = float("nan")
        save_file({"model.layers.0.weight": t}, str(st_file))

        finding = Finding(
            rule_id="SEC-WGT-002",
            title="Poisoned Tensor (NaN values) in 'model.layers.0.weight'",
            severity=Severity.CRITICAL,
            category=RiskCategory.WEIGHT_POISONING_ANOMALY,
            file_path="weights.safetensors",
            description="NaN detected.",
            remediation="Discard weights.",
            evidence="model.layers.0.weight",
        )

        verifier = WeightPoisonVerifier()
        proof = verifier.verify(finding, self.root_path)

        self.assertEqual(proof.status, VerificationStatus.VERIFIED)
        self.assertEqual(proof.proof_data["first_poisoned_coordinate"], [1, 2])
        self.assertEqual(proof.proof_data["anomaly_type"], "NaN")

    def test_full_dossier_compilation(self):
        cfg_file = self.root_path / "config.json"
        cfg_file.write_text(json.dumps({"auto_map": {"AutoModel": "demo.M"}}), encoding="utf-8")

        report = ScanReport(
            target=str(self.root_path),
            is_remote=False,
            scanned_files_count=1,
            total_bytes_scanned=100,
            findings=[
                Finding(
                    rule_id="SEC-RCE-MAP-001",
                    title="Remote Custom Code Registration (auto_map)",
                    severity=Severity.HIGH,
                    category=RiskCategory.REMOTE_CODE_EXECUTION,
                    file_path="config.json",
                    description="Auto map detected.",
                    remediation="Audit code.",
                )
            ],
        )

        dossier = self.engine.verify_report(report, root_dir=self.root_path)
        self.assertEqual(dossier.total_findings_count, 1)
        self.assertEqual(dossier.verified_findings_count, 1)
        self.assertEqual(dossier.verification_rate, 100.0)
        self.assertIn("VERIFIED", dossier.proofs[0].status.value)


if __name__ == "__main__":
    unittest.main()
