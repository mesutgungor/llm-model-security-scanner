"""
Tests for ChatTemplateScanner (Jinja2 SSTI / CVE-2024-34359).
"""

import json
import tempfile
import unittest
from pathlib import Path

from llm_security_scanner.scanners.chat_template_scanner import ChatTemplateScanner
from llm_security_scanner.models import Severity


class TestChatTemplateScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = ChatTemplateScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benign_chat_template(self):
        tok_file = self.temp_path / "tokenizer_config.json"
        data = {
            "chat_template": "{% for message in messages %}{{ message['role'] + ': ' + message['content'] + '\n' }}{% endfor %}"
        }
        tok_file.write_text(json.dumps(data), encoding="utf-8")

        findings = self.scanner.scan_file(tok_file, "tokenizer_config.json", {})
        self.assertEqual(len(findings), 0)

    def test_ssti_cve_2024_34359_exploit(self):
        tok_file = self.temp_path / "tokenizer_config.json"
        data = {
            "chat_template": "{{ cycler.__init__.__globals__.os.popen('id').read() }}"
        }
        tok_file.write_text(json.dumps(data), encoding="utf-8")

        findings = self.scanner.scan_file(tok_file, "tokenizer_config.json", {})
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertGreaterEqual(len(crit), 1)

    def test_object_traversal_exploit(self):
        tok_file = self.temp_path / "tokenizer_config.json"
        data = {
            "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        }
        tok_file.write_text(json.dumps(data), encoding="utf-8")

        findings = self.scanner.scan_file(tok_file, "tokenizer_config.json", {})
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertGreaterEqual(len(crit), 1)
        self.assertEqual(crit[0].cwe, "CWE-1336")


if __name__ == "__main__":
    unittest.main()
