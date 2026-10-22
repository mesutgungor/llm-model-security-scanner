"""
Tests for expanded security scanners:
- PeftAdapterScanner
- GenerationConfigScanner
- ONNXSecurityScanner
- Unicode Bidi & Zero-width Trojan detection
- Structural Hidden Layer Backdoor detection
"""

import json
import tempfile
import unittest
from pathlib import Path

import torch
from safetensors.torch import save_file

from llm_security_scanner.models import Severity
from llm_security_scanner.scanners.generation_config_scanner import GenerationConfigScanner
from llm_security_scanner.scanners.onnx_scanner import ONNXSecurityScanner
from llm_security_scanner.scanners.peft_adapter_scanner import PeftAdapterScanner
from llm_security_scanner.scanners.special_tokens_scanner import SpecialTokensScanner
from llm_security_scanner.scanners.weight_anomaly_scanner import WeightAnomalyScanner


class TestExpandedScanners(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_peft_scaling_sabotage(self):
        adapter_file = self.root_path / "adapter_config.json"
        data = {
            "peft_type": "LORA",
            "base_model_name_or_path": "meta-llama/Llama-3-8B",
            "r": 8,
            "lora_alpha": 1600,  # Extreme ratio 200.0!
        }
        adapter_file.write_text(json.dumps(data), encoding="utf-8")

        scanner = PeftAdapterScanner()
        findings = scanner.scan_file(adapter_file, "adapter_config.json", {})
        sabotage = [f for f in findings if f.rule_id == "SEC-PEFT-002"]
        self.assertEqual(len(sabotage), 1)
        self.assertEqual(sabotage[0].severity, Severity.HIGH)

    def test_peft_untrusted_remote_base(self):
        adapter_file = self.root_path / "adapter_config.json"
        data = {
            "peft_type": "LORA",
            "base_model_name_or_path": "http://evil.com/fake_llama",
        }
        adapter_file.write_text(json.dumps(data), encoding="utf-8")

        scanner = PeftAdapterScanner()
        findings = scanner.scan_file(adapter_file, "adapter_config.json", {})
        remote_base = [f for f in findings if f.rule_id == "SEC-PEFT-001"]
        self.assertEqual(len(remote_base), 1)

    def test_generation_kv_cache_dos(self):
        gen_file = self.root_path / "generation_config.json"
        data = {
            "max_new_tokens": 10_000_000,  # 10 Million tokens!
            "temperature": -0.5,           # Invalid temperature!
        }
        gen_file.write_text(json.dumps(data), encoding="utf-8")

        scanner = GenerationConfigScanner()
        findings = scanner.scan_file(gen_file, "generation_config.json", {})
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SEC-GEN-001", rule_ids)
        self.assertIn("SEC-GEN-002", rule_ids)

    def test_onnx_external_data_traversal(self):
        onnx_file = self.root_path / "model.onnx"
        # Simulate ONNX protobuf containing location: ../../etc/shadow
        payload = b"\x08\x07\x12\x08external\x1a\x14location../../etc/shadow" + b"\x00" * 32
        onnx_file.write_bytes(payload)

        scanner = ONNXSecurityScanner()
        findings = scanner.scan_file(onnx_file, "model.onnx", {})
        traversal = [f for f in findings if f.rule_id == "SEC-ONNX-001"]
        self.assertEqual(len(traversal), 1)
        self.assertEqual(traversal[0].severity, Severity.CRITICAL)

    def test_unicode_bidi_trojan(self):
        tok_file = self.root_path / "tokenizer.json"
        # Trojan Source: Right-to-Left Override \u202e inside token
        data = {
            "added_tokens": [
                {"id": 50, "content": "admin\u202e\u2066user", "special": False}
            ]
        }
        tok_file.write_text(json.dumps(data), encoding="utf-8")

        scanner = SpecialTokensScanner()
        findings = scanner.scan_file(tok_file, "tokenizer.json", {})
        bidi = [f for f in findings if f.rule_id == "SEC-TOK-006"]
        self.assertEqual(len(bidi), 1)
        self.assertEqual(bidi[0].severity, Severity.HIGH)

    def test_stealth_hidden_layer_injection(self):
        cfg_file = self.root_path / "config.json"
        cfg_file.write_text(json.dumps({"num_hidden_layers": 32}), encoding="utf-8")

        st_file = self.root_path / "model.safetensors"
        # Inject layer 35 when config specifies only 32 layers!
        tensors = {
            "model.layers.0.weight": torch.randn(4, 4),
            "model.layers.35.trojan_head.weight": torch.randn(4, 4),
        }
        save_file(tensors, str(st_file))

        scanner = WeightAnomalyScanner()
        findings = scanner.scan_file(st_file, "model.safetensors", {"root_dir": self.root_path})
        stealth_layers = [f for f in findings if f.rule_id == "SEC-WGT-005"]
        self.assertEqual(len(stealth_layers), 1)
        self.assertEqual(stealth_layers[0].severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
