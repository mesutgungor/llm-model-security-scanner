"""
Special Tokens & Delimiter Manipulation Scanner.
Audits tokenizer.json, tokenizer_config.json, and special_tokens_map.json to detect
control token hijacking, duplicate token IDs, delimiter stripping, and prompt injection backdoors.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Set

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

CRITICAL_CONTROL_TOKENS = {
    "<|im_start|>",
    "<|im_end|>",
    "<|endoftext|>",
    "<|begin_of_text|>",
    "<|end_of_text|>",
    "<s>",
    "</s>",
    "<bos>",
    "<eos>",
    "[INST]",
    "[/INST]",
}


class SpecialTokensScanner(BaseScanner):
    name = "SpecialTokensScanner"
    description = "Audits special token maps and tokenizer configurations for role delimiter hijacking"

    def can_scan(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name in ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "added_tokens.json")

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return findings

            filename = file_path.name.lower()

            if filename == "tokenizer_config.json":
                findings.extend(self._check_tokenizer_config(data, relative_path))
            elif filename == "tokenizer.json":
                findings.extend(self._check_tokenizer_json(data, relative_path))
            elif filename == "special_tokens_map.json":
                findings.extend(self._check_special_tokens_map(data, relative_path))

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-TOK-ERR-001",
                    title="Malformed Tokenizer Configuration",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Error reading tokenizer file: {str(e)}",
                    remediation="Validate JSON syntax.",
                )
            )

        return findings

    def _check_tokenizer_config(self, data: Dict[str, Any], path: str) -> List[Finding]:
        findings: List[Finding] = []

        # Check for missing EOS token
        eos_token = data.get("eos_token")
        if eos_token is None:
            findings.append(
                Finding(
                    rule_id="SEC-TOK-001",
                    title="Missing End-of-Sequence (EOS) Token Configuration",
                    severity=Severity.MEDIUM,
                    category=RiskCategory.SPECIAL_TOKEN_MANIPULATION,
                    file_path=path,
                    description=(
                        "Tokenizer does not define an 'eos_token'. This can cause the model to generate "
                        "indefinitely until hitting maximum sequence lengths, triggering resource exhaustion (DoS)."
                    ),
                    remediation="Explicitly define 'eos_token' in tokenizer_config.json.",
                    owasp="LLM10: Unbounded Consumption",
                    mitre_atlas="AML.T0029: Denial of Service",
                    nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                    eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                )
            )

        # Check for abnormal bos/eos token values
        if isinstance(eos_token, str) and eos_token == "":
            findings.append(
                Finding(
                    rule_id="SEC-TOK-002",
                    title="Empty String EOS Token Configured",
                    severity=Severity.HIGH,
                    category=RiskCategory.SPECIAL_TOKEN_MANIPULATION,
                    file_path=path,
                    description="EOS token is set to an empty string, breaking stop sequences across all prompts.",
                    remediation="Configure a valid EOS delimiter token.",
                )
            )

        return findings

    def _check_tokenizer_json(self, data: Dict[str, Any], path: str) -> List[Finding]:
        findings: List[Finding] = []
        added_tokens = data.get("added_tokens", [])

        if isinstance(added_tokens, list):
            seen_ids: Dict[int, str] = {}
            for token_entry in added_tokens:
                if not isinstance(token_entry, dict):
                    continue
                token_id = token_entry.get("id")
                token_content = token_entry.get("content")
                is_special = token_entry.get("special", False)

                # Check ID collision
                if token_id in seen_ids:
                    prev_content = seen_ids[token_id]
                    if prev_content != token_content:
                        findings.append(
                            Finding(
                                rule_id="SEC-TOK-003",
                                title=f"Token ID Collision: ID {token_id}",
                                severity=Severity.HIGH,
                                category=RiskCategory.SPECIAL_TOKEN_MANIPULATION,
                                file_path=path,
                                description=(
                                    f"Token ID {token_id} is assigned to multiple distinct tokens: "
                                    f"'{prev_content}' and '{token_content}'. This can be used to hijack "
                                    f"delimiters or subvert role parsing."
                                ),
                                remediation="Ensure 1:1 bijection between tokens and token IDs.",
                                evidence=f"ID {token_id} shared by '{prev_content}' and '{token_content}'",
                                owasp="LLM01: Prompt Injection",
                                mitre_atlas="AML.T0051: LLM Prompt Injection",
                                nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                            )
                        )
                else:
                    if token_id is not None:
                        seen_ids[token_id] = token_content

                # Check if critical role delimiters are improperly marked as non-special
                if token_content in CRITICAL_CONTROL_TOKENS and not is_special:
                    findings.append(
                        Finding(
                            rule_id="SEC-TOK-004",
                            title=f"Critical Delimiter Marked Non-Special: '{token_content}'",
                            severity=Severity.HIGH,
                            category=RiskCategory.SPECIAL_TOKEN_MANIPULATION,
                            file_path=path,
                            description=(
                                f"Control delimiter '{token_content}' has special=false. Users can inject "
                                f"this raw token in prompts to break out of system/user turn boundaries."
                            ),
                            remediation=f"Set special=true for control token '{token_content}'.",
                            evidence=f"Token '{token_content}' special={is_special}",
                            owasp="LLM01: Prompt Injection",
                            mitre_atlas="AML.T0051: LLM Prompt Injection",
                            nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                            eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                        )
                    )

                # Check for Unicode Bidi Trojan Override sequences (CVE-2021-42574)
                if isinstance(token_content, str):
                    bidi_chars = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
                    if any(bc in token_content for bc in bidi_chars):
                        findings.append(
                            Finding(
                                rule_id="SEC-TOK-006",
                                title=f"Unicode Bidirectional (Bidi) Trojan Override in Token: '{token_content}'",
                                severity=Severity.HIGH,
                                category=RiskCategory.UNICODE_SMUGGLING,
                                file_path=path,
                                description=(
                                    f"Token contains invisible bidirectional Unicode override characters (e.g. U+202E). "
                                    "Attackers use Bidi overrides (CVE-2021-42574) to reorder prompt text visually, "
                                    "deceiving human reviewers and safety filters while executing instructions in reverse."
                                ),
                                remediation="Remove invisible Unicode bidirectional overrides from the tokenizer vocabulary.",
                                evidence=f"Bidi override detected in token ID {token_id}",
                                cwe="CWE-451",
                                cve="CVE-2021-42574",
                                owasp="LLM01: Prompt Injection",
                                mitre_atlas="AML.T0051: LLM Prompt Injection",
                                nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                            )
                        )

                    # Check for Zero-Width Character Smuggling
                    zero_width_chars = {"\u200b", "\u200c", "\u200d", "\ufeff"}
                    if any(zwc in token_content for zwc in zero_width_chars):
                        findings.append(
                            Finding(
                                rule_id="SEC-TOK-007",
                                title=f"Zero-Width Character Smuggling in Token: '{token_content}'",
                                severity=Severity.MEDIUM,
                                category=RiskCategory.UNICODE_SMUGGLING,
                                file_path=path,
                                description=(
                                    "Token contains zero-width invisible characters (e.g. ZWSP U+200B). Zero-width "
                                    "smuggling is used to watermark backdoors or evade text-based prompt moderation."
                                ),
                                remediation="Cleanse zero-width non-printable characters from the vocabulary.",
                                evidence=f"Zero-width token ID: {token_id}",
                                owasp="LLM01: Prompt Injection",
                                mitre_atlas="AML.T0051: LLM Prompt Injection",
                                nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                            )
                        )

        return findings

    def _check_special_tokens_map(self, data: Dict[str, Any], path: str) -> List[Finding]:
        findings: List[Finding] = []
        # Check if eos_token is identical to bos_token or unk_token unexpectedly
        bos = data.get("bos_token")
        eos = data.get("eos_token")
        unk = data.get("unk_token")

        if bos and eos and bos == eos:
            findings.append(
                Finding(
                    rule_id="SEC-TOK-005",
                    title="BOS and EOS Tokens Are Identical",
                    severity=Severity.LOW,
                    category=RiskCategory.SPECIAL_TOKEN_MANIPULATION,
                    file_path=path,
                    description=f"bos_token and eos_token share the same symbol: '{bos}'.",
                    remediation="Verify whether identical BOS/EOS tokens are intentional for this architecture.",
                )
            )

        return findings
