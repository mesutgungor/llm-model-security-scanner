"""
Tests for SafeTensorsSecurityScanner.
"""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from llm_security_scanner.scanners.safetensors_scanner import SafeTensorsSecurityScanner
from llm_security_scanner.models import Severity


class TestSafeTensorsScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SafeTensorsSecurityScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benign_safetensors(self):
        st_file = self.temp_path / "model.safetensors"
        header = {
            "tensor_1": {
                "dtype": "F32",
                "shape": [2, 2],
                "data_offsets": [0, 16],
            }
        }
        header_bytes = json.dumps(header).encode("utf-8")
        header_len = len(header_bytes)
        raw_data = b"\x00" * 16

        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", header_len))
            f.write(header_bytes)
            f.write(raw_data)

        findings = self.scanner.scan_file(st_file, "model.safetensors", {})
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(crit), 0)

    def test_header_dos_cve_2023_44469(self):
        st_file = self.temp_path / "bomb.safetensors"
        # Claim header is 500 MB when file is only 16 bytes
        fake_header_len = 500 * 1024 * 1024
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", fake_header_len))
            f.write(b"ABCD")

        findings = self.scanner.scan_file(st_file, "bomb.safetensors", {})
        crit = [f for f in findings if f.rule_id == "SEC-ST-003"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].severity, Severity.CRITICAL)

    def test_inverted_tensor_offsets(self):
        st_file = self.temp_path / "inverted.safetensors"
        header = {
            "tensor_bad": {
                "dtype": "F32",
                "shape": [2, 2],
                "data_offsets": [20, 10],  # Inverted!
            }
        }
        header_bytes = json.dumps(header).encode("utf-8")
        with open(st_file, "wb") as f:
            f.write(struct.pack("<Q", len(header_bytes)))
            f.write(header_bytes)
            f.write(b"\x00" * 32)

        findings = self.scanner.scan_file(st_file, "inverted.safetensors", {})
        inverted = [f for f in findings if f.rule_id == "SEC-ST-006"]
        self.assertEqual(len(inverted), 1)
        self.assertEqual(inverted[0].severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
