"""
End-to-End Pipeline & Report Generation Tests.
"""

import json
import tempfile
import unittest
from pathlib import Path

import torch
from safetensors.torch import save_file

from llm_security_scanner.engine import ModelSecurityScanner
from llm_security_scanner.models import SecurityVerdict, Severity
from llm_security_scanner.reporters.json_reporter import JsonReporter
from llm_security_scanner.reporters.markdown_reporter import MarkdownReporter
from llm_security_scanner.reporters.sarif_reporter import SarifReporter


class TestFullPipeline(unittest.TestCase):
    def setUp(self):
        self.scanner = ModelSecurityScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benign_model_repository(self):
        # 1. config.json
        config = {
            "architectures": ["LlamaForCausalLM"],
            "model_type": "llama",
            "vocab_size": 32000,
        }
        (self.repo_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")

        # 2. tokenizer_config.json
        tok_cfg = {
            "bos_token": "<s>",
            "eos_token": "</s>",
            "chat_template": "{% for msg in messages %}{{ msg['content'] }}{% endfor %}",
        }
        (self.repo_dir / "tokenizer_config.json").write_text(json.dumps(tok_cfg), encoding="utf-8")

        # 3. Clean weights
        weights_file = self.repo_dir / "model.safetensors"
        save_file({"model.embed_tokens.weight": torch.randn(10, 10)}, str(weights_file))

        # 4. README.md
        (self.repo_dir / "README.md").write_text("# Clean LLaMA Model Card\nApache 2.0 license.\n")

        # Run Scan
        report = self.scanner.scan(str(self.repo_dir))

        self.assertEqual(report.verdict, SecurityVerdict.SAFE)
        self.assertEqual(report.critical_count, 0)
        self.assertEqual(report.high_count, 0)
        self.assertEqual(report.model_architecture, "LlamaForCausalLM")
        self.assertIn("SafeTensors", report.model_formats_found)

        # Test Reporters
        json_out = JsonReporter().render(report)
        parsed = json.loads(json_out)
        self.assertEqual(parsed["verdict"], "SAFE")

        md_out = MarkdownReporter().render(report)
        self.assertIn("SAFE", md_out)

        sarif_out = SarifReporter().render(report)
        sarif_parsed = json.loads(sarif_out)
        self.assertEqual(sarif_parsed["version"], "2.1.0")

    def test_compromised_model_repository(self):
        # 1. config.json with auto_map
        config = {
            "architectures": ["CustomPoisonedModel"],
            "auto_map": {"AutoModel": "modeling_bad.BadModel"},
        }
        (self.repo_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")

        # 2. Malicious Python modeling file
        bad_code = "import os\ndef pwn():\n    os.system('id')\n"
        (self.repo_dir / "modeling_bad.py").write_text(bad_code, encoding="utf-8")

        # 3. Jinja SSTI in tokenizer_config
        tok_cfg = {
            "chat_template": "{{ cycler.__init__.__globals__.os.system('sh') }}",
            "bos_token": "<s>",
            "eos_token": "</s>",
        }
        (self.repo_dir / "tokenizer_config.json").write_text(json.dumps(tok_cfg), encoding="utf-8")

        # Run Scan
        report = self.scanner.scan(str(self.repo_dir))

        self.assertEqual(report.verdict, SecurityVerdict.CRITICAL)
        self.assertGreaterEqual(report.critical_count, 1)
        self.assertGreaterEqual(report.risk_score, 50.0)

        # Verify SARIF generation captures critical results
        sarif_out = SarifReporter().render(report)
        sarif_doc = json.loads(sarif_out)
        results = sarif_doc["runs"][0]["results"]
        levels = [r["level"] for r in results]
        self.assertIn("error", levels)


if __name__ == "__main__":
    unittest.main()
