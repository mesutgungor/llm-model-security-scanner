"""
Tests for SpecialTokensScanner.
"""

import json
import tempfile
import unittest
from pathlib import Path

from llm_security_scanner.scanners.special_tokens_scanner import SpecialTokensScanner
from llm_security_scanner.models import Severity


class TestSpecialTokensScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SpecialTokensScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_duplicate_token_id_collision(self):
        tok_file = self.temp_path / "tokenizer.json"
        data = {
            "added_tokens": [
                {"id": 100, "content": "<|im_end|>", "special": True},
                {"id": 100, "content": "hello", "special": False},  # ID Collision!
            ]
        }
        tok_file.write_text(json.dumps(data), encoding="utf-8")

        findings = self.scanner.scan_file(tok_file, "tokenizer.json", {})
        collisions = [f for f in findings if f.rule_id == "SEC-TOK-003"]
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0].severity, Severity.HIGH)

    def test_unescaped_control_token(self):
        tok_file = self.temp_path / "tokenizer.json"
        data = {
            "added_tokens": [
                {"id": 100, "content": "<|im_end|>", "special": False},  # Should be special=True!
            ]
        }
        tok_file.write_text(json.dumps(data), encoding="utf-8")

        findings = self.scanner.scan_file(tok_file, "tokenizer.json", {})
        unescaped = [f for f in findings if f.rule_id == "SEC-TOK-004"]
        self.assertEqual(len(unescaped), 1)

    def test_missing_eos_token(self):
        cfg_file = self.temp_path / "tokenizer_config.json"
        data = {"bos_token": "<s>"}  # missing eos_token
        cfg_file.write_text(json.dumps(data), encoding="utf-8")

        findings = self.scanner.scan_file(cfg_file, "tokenizer_config.json", {})
        missing_eos = [f for f in findings if f.rule_id == "SEC-TOK-001"]
        self.assertEqual(len(missing_eos), 1)


if __name__ == "__main__":
    unittest.main()
