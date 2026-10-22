"""
Tests for SecretLeakScanner.
"""

import tempfile
import unittest
from pathlib import Path

from llm_security_scanner.scanners.secret_leak_scanner import SecretLeakScanner
from llm_security_scanner.models import Severity


class TestSecretLeakScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretLeakScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_huggingface_token_leak(self):
        readme_file = self.temp_path / "README.md"
        # Simulated HF token: starts with hf_ and followed by 34 alphanumerics
        readme_file.write_text(
            "# Model Card\nUse my token: hf_AbCdEfGhIjKlMnOpQrStUvWxYz12345678 to push.\n"
        )

        findings = self.scanner.scan_file(readme_file, "README.md", {})
        hf_leaks = [f for f in findings if "Hugging Face" in f.title]
        self.assertEqual(len(hf_leaks), 1)
        self.assertEqual(hf_leaks[0].severity, Severity.CRITICAL)

    def test_openai_key_leak(self):
        script_file = self.temp_path / "eval.py"
        script_file.write_text(
            "import openai\napi_key = 'sk-proj-1234567890abcdef1234567890abcdef12345678'\n"
        )

        findings = self.scanner.scan_file(script_file, "eval.py", {})
        openai_leaks = [f for f in findings if "OpenAI" in f.title]
        self.assertEqual(len(openai_leaks), 1)
        self.assertEqual(openai_leaks[0].severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
