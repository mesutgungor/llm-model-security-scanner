"""
Hardcoded Secret & Credential Leakage Scanner.
Audits configuration files, README markdown, scripts, and logs for leaked Hugging Face tokens,
OpenAI/Anthropic keys, AWS credentials, and SSH private keys accidentally committed with model weights.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

SECRET_PATTERNS: List[Tuple[str, str, Severity]] = [
    # Hugging Face Access Token
    (r"\bhf_[a-zA-Z0-9]{34,}\b", "Leaked Hugging Face User Access Token", Severity.CRITICAL),

    # OpenAI API Keys
    (r"\bsk-(?:proj-)?[a-zA-Z0-9_\-]{32,}\b", "Leaked OpenAI API Key", Severity.CRITICAL),

    # Anthropic API Key
    (r"\bsk-ant-[a-zA-Z0-9_\-]{32,}\b", "Leaked Anthropic API Key", Severity.CRITICAL),

    # AWS Credentials
    (r"\bAKIA[0-9A-Z]{16}\b", "Leaked AWS Access Key ID", Severity.CRITICAL),
    (r"(?i)aws_secret_access_key\s*=\s*['\"][a-zA-Z0-9/+=]{40}['\"]", "Leaked AWS Secret Key", Severity.CRITICAL),

    # GitHub Personal Access Token
    (r"\bghp_[a-zA-Z0-9]{36}\b", "Leaked GitHub Personal Access Token", Severity.CRITICAL),
    (r"\bgithub_pat_[a-zA-Z0-9_]{50,}\b", "Leaked Fine-Grained GitHub Access Token", Severity.CRITICAL),

    # Private Keys
    (r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----", "Exposed Cryptographic Private Key", Severity.CRITICAL),

    # Generic High-Entropy Secret Tokens
    (r"(?i)(?:api_key|secret_key|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{24,}['\"]", "Exposed API / Auth Secret", Severity.HIGH),
]


class SecretLeakScanner(BaseScanner):
    name = "SecretLeakScanner"
    description = "Searches text, config, and script files for exposed credentials and API keys"

    TEXT_EXTENSIONS = {".json", ".txt", ".md", ".py", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sh", ".env"}

    def can_scan(self, file_path: Path) -> bool:
        if file_path.suffix.lower() in self.TEXT_EXTENSIONS:
            return True
        if file_path.name in (".env", ".credentials", "config", "README"):
            return True
        return False

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            # Skip files larger than 10MB (weights should not be scanned as plaintext)
            if file_path.stat().st_size > 10 * 1024 * 1024:
                return findings

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for pattern, title, severity in SECRET_PATTERNS:
                matches = re.finditer(pattern, content)
                for match in matches:
                    secret_val = match.group(0)
                    # Mask the secret for safe reporting
                    masked = secret_val[:4] + "*" * (len(secret_val) - 8) + secret_val[-4:] if len(secret_val) > 8 else "***"

                    line_no = content.count("\n", 0, match.start()) + 1

                    findings.append(
                        Finding(
                            rule_id="SEC-SEC-001",
                            title=title,
                            severity=severity,
                            category=RiskCategory.SECRET_LEAK,
                            file_path=relative_path,
                            description=(
                                f"File contains hardcoded credential or access key matching pattern '{title}'. "
                                f"Publishing credentials in model repositories risks account hijacking and data compromise."
                            ),
                            remediation="Revoke and rotate this secret immediately, and scrub it from git history.",
                            line_number=line_no,
                            evidence=f"Masked credential: {masked}",
                            cwe="CWE-798",
                            owasp="LLM02: Sensitive Information Disclosure",
                            mitre_atlas="AML.T0040: ML Intellectual Property Theft",
                            nist_ai_rmf="GOVERN-1.2 & MANAGE-2.4",
                            eu_ai_act="Article 15 (Cybersecurity & Robustness), Article 53 (GPAI Copyright & Protection)",
                        )
                    )

        except Exception:
            pass

        return findings
