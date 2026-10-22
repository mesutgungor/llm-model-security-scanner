"""
Generation Configuration & Resource Exhaustion Scanner.
Audits generation_config.json to detect unbounded sequence length DoS attacks,
softmax temperature collapse, and deliberate suppression of safety filters.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

MAX_SAFE_TOKEN_GENERATION_LENGTH = 131_072  # 128k is upper reasonable context for modern LLMs


class GenerationConfigScanner(BaseScanner):
    name = "GenerationConfigScanner"
    description = "Audits generation_config.json for parameters triggering KV-cache exhaustion or safety bypass"

    def can_scan(self, file_path: Path) -> bool:
        return file_path.name.lower() == "generation_config.json"

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return findings

            # 1. Unbounded Generation Length / KV Cache Exhaustion (SEC-GEN-001)
            for length_key in ("max_new_tokens", "max_length"):
                val = data.get(length_key)
                if val is not None and isinstance(val, (int, float)):
                    if val > MAX_SAFE_TOKEN_GENERATION_LENGTH or val < 0:
                        findings.append(
                            Finding(
                                rule_id="SEC-GEN-001",
                                title=f"Extreme Token Generation Limit in '{length_key}' ({val})",
                                severity=Severity.HIGH,
                                category=RiskCategory.GENERATION_DOS,
                                file_path=relative_path,
                                description=(
                                    f"Declared {length_key} ({val}) exceeds safe operating thresholds "
                                    f"({MAX_SAFE_TOKEN_GENERATION_LENGTH}). Attackers configure gigantic default lengths "
                                    "to trigger GPU VRAM out-of-memory crashes (KV-cache Sponge DoS)."
                                ),
                                remediation=f"Set {length_key} to a reasonable context budget (e.g. 2048 to 32768).",
                                evidence=f"{length_key}: {val}",
                                owasp="LLM10: Unbounded Consumption",
                                mitre_atlas="AML.T0029: Denial of Service",
                                nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                            )
                        )

            # 2. Temperature Anomaly / Softmax Underflow (SEC-GEN-002)
            temp = data.get("temperature")
            do_sample = data.get("do_sample", True)
            if temp is not None and isinstance(temp, (int, float)):
                if do_sample and temp <= 0:
                    findings.append(
                        Finding(
                            rule_id="SEC-GEN-002",
                            title=f"Invalid Sampling Temperature ({temp}) with do_sample=True",
                            severity=Severity.MEDIUM,
                            category=RiskCategory.GENERATION_DOS,
                            file_path=relative_path,
                            description=(
                                f"Temperature is set to {temp} while do_sample is true. This causes division "
                                "by zero in probability calculation during logits sampling, triggering server crashes."
                            ),
                            remediation="Set temperature > 0.0 or set do_sample=false for greedy decoding.",
                            evidence=f"temperature: {temp}, do_sample: {do_sample}",
                            owasp="LLM10: Unbounded Consumption",
                            mitre_atlas="AML.T0029: Denial of Service",
                            nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                            eu_ai_act="Article 15 (Robustness)",
                        )
                    )
                elif temp > 50.0:
                    findings.append(
                        Finding(
                            rule_id="SEC-GEN-002",
                            title=f"Absurdly High Sampling Temperature ({temp})",
                            severity=Severity.LOW,
                            category=RiskCategory.GENERATION_DOS,
                            file_path=relative_path,
                            description=f"Temperature {temp} will produce complete token chaos and incoherent sampling loops.",
                            remediation="Set temperature to standard range (0.1 - 2.0).",
                            evidence=f"temperature: {temp}",
                        )
                    )

            # 3. Suppressed Safety Delimiters (SEC-GEN-003)
            eos_token_id = data.get("eos_token_id")
            if eos_token_id is None:
                findings.append(
                    Finding(
                        rule_id="SEC-GEN-003",
                        title="Missing eos_token_id in Generation Manifest",
                        severity=Severity.MEDIUM,
                        category=RiskCategory.GENERATION_DOS,
                        file_path=relative_path,
                        description=(
                            "generation_config.json omits eos_token_id. Generation loops will fail to terminate "
                            "upon reaching end-of-turn delimiters."
                        ),
                        remediation="Explicitly define eos_token_id.",
                        owasp="LLM10: Unbounded Consumption",
                        mitre_atlas="AML.T0029: Denial of Service",
                        nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-GEN-ERR-001",
                    title="Malformed generation_config.json",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Could not parse generation_config.json: {str(e)}",
                    remediation="Verify JSON syntax.",
                )
            )

        return findings
