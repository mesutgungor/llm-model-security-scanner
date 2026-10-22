"""
Tests for PickleSecurityScanner.
"""

import io
import pickle
import unittest
import zipfile
from pathlib import Path
import tempfile

from llm_security_scanner.scanners.pickle_scanner import PickleSecurityScanner
from llm_security_scanner.models import Severity


class MaliciousExploit:
    """Simulates a pickle reduce exploit."""
    def __reduce__(self):
        import os
        return (os.system, ("echo 'exploit'",))


class TestPickleScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = PickleSecurityScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benign_pickle(self):
        benign_file = self.temp_path / "model.pt"
        data = {"weight": [1.0, 2.0, 3.0], "bias": [0.1]}
        with open(benign_file, "wb") as f:
            pickle.dump(data, f)

        findings = self.scanner.scan_file(benign_file, "model.pt", {})
        # Should not have any CRITICAL findings
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(crit), 0)

    def test_malicious_os_system_pickle(self):
        evil_file = self.temp_path / "evil_model.bin"
        with open(evil_file, "wb") as f:
            pickle.dump(MaliciousExploit(), f)

        findings = self.scanner.scan_file(evil_file, "evil_model.bin", {})
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertGreaterEqual(len(crit), 1)
        self.assertEqual(crit[0].rule_id, "SEC-PCK-001")
        self.assertIn("system", crit[0].evidence)

    def test_zipslip_traversal(self):
        zip_file = self.temp_path / "pytorch_model.bin"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("../../etc/cron.d/backdoor", "malicious payload")
            zf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2]}))

        findings = self.scanner.scan_file(zip_file, "pytorch_model.bin", {})
        zipslip = [f for f in findings if f.rule_id == "SEC-ZIP-001"]
        self.assertEqual(len(zipslip), 1)
        self.assertEqual(zipslip[0].severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
