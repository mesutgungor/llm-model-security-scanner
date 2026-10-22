"""
Tests for WeightAnomalyScanner.
"""

import tempfile
import unittest
from pathlib import Path

import torch
from safetensors.torch import save_file

from llm_security_scanner.scanners.weight_anomaly_scanner import WeightAnomalyScanner
from llm_security_scanner.models import Severity


class TestWeightAnomalyScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = WeightAnomalyScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_clean_weights(self):
        st_file = self.temp_path / "clean.safetensors"
        tensors = {
            "model.layers.0.self_attn.q_proj.weight": torch.randn(16, 16),
            "model.layers.0.self_attn.k_proj.weight": torch.randn(16, 16),
        }
        save_file(tensors, str(st_file))

        findings = self.scanner.scan_file(st_file, "clean.safetensors", {})
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(crit), 0)

    def test_nan_poisoned_weights(self):
        st_file = self.temp_path / "poisoned.safetensors"
        poisoned_tensor = torch.randn(16, 16)
        poisoned_tensor[0, 0] = float("nan")

        tensors = {
            "model.layers.0.self_attn.q_proj.weight": poisoned_tensor,
        }
        save_file(tensors, str(st_file))

        findings = self.scanner.scan_file(st_file, "poisoned.safetensors", {})
        nan_findings = [f for f in findings if f.rule_id == "SEC-WGT-002"]
        self.assertEqual(len(nan_findings), 1)
        self.assertEqual(nan_findings[0].severity, Severity.CRITICAL)

    def test_all_zero_sabotaged_weights(self):
        st_file = self.temp_path / "zeroed.safetensors"
        zeroed_tensor = torch.zeros(64, 64)

        tensors = {
            "model.layers.0.mlp.gate_proj.weight": zeroed_tensor,
        }
        save_file(tensors, str(st_file))

        findings = self.scanner.scan_file(st_file, "zeroed.safetensors", {})
        zero_findings = [f for f in findings if f.rule_id == "SEC-WGT-003"]
        self.assertEqual(len(zero_findings), 1)
        self.assertEqual(zero_findings[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
