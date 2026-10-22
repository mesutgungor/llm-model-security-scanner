"""
LoRA & PEFT Adapter Security Scanner.
Audits adapter_config.json and PEFT matrices to detect base model hijacking,
LoRA scaling sabotage (safety alignment stripping), and malicious target module overrides.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner


class PeftAdapterScanner(BaseScanner):
    name = "PeftAdapterScanner"
    description = "Audits PEFT and LoRA adapter manifests for base model hijacking and scaling sabotage"

    def can_scan(self, file_path: Path) -> bool:
        return file_path.name.lower() in ("adapter_config.json", "peft_config.json")

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return findings

            # 1. Base model path check (SEC-PEFT-001)
            base_model = data.get("base_model_name_or_path", "")
            if base_model:
                if base_model.startswith(("http://", "https://", "ftp://")) or ".." in base_model:
                    findings.append(
                        Finding(
                            rule_id="SEC-PEFT-001",
                            title="Suspicious Base Model Path in Adapter Manifest",
                            severity=Severity.HIGH,
                            category=RiskCategory.ADAPTER_POISONING,
                            file_path=relative_path,
                            description=(
                                f"Adapter specifies remote or path-traversal base model: '{base_model}'. "
                                "Loading adapters with untrusted remote base paths can lead to unexpected downloads or SSRF."
                            ),
                            remediation="Verify base_model_name_or_path references an official verified foundation model.",
                            evidence=f"base_model_name_or_path: {base_model}",
                            owasp="LLM03: Supply Chain Vulnerabilities",
                            mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                            nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                            eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                        )
                    )

            # 2. Extreme LoRA Alpha / Rank Scaling Sabotage (SEC-PEFT-002)
            lora_alpha = data.get("lora_alpha")
            r = data.get("r")
            if lora_alpha is not None and r is not None:
                try:
                    alpha_val = float(lora_alpha)
                    r_val = float(r)
                    if r_val > 0:
                        scaling_factor = alpha_val / r_val
                        # Normal scaling factor is typically between 0.5 and 4.0 (e.g. alpha=16, r=8 or 16)
                        if scaling_factor > 100.0 or scaling_factor < 0:
                            findings.append(
                                Finding(
                                    rule_id="SEC-PEFT-002",
                                    title=f"LoRA Scaling Sabotage Factor Detected ({scaling_factor})",
                                    severity=Severity.HIGH,
                                    category=RiskCategory.ADAPTER_POISONING,
                                    file_path=relative_path,
                                    description=(
                                        f"Adapter has extreme scaling ratio (alpha={alpha_val}, r={r_val}, ratio={scaling_factor}). "
                                        "Extreme or negative scaling ratios are used in 'alignment stripping' attacks to completely "
                                        "destroy base model safety guardrails and cause numerical explosion upon merging."
                                    ),
                                    remediation="Ensure lora_alpha and r adhere to standard training ratios (scaling factor <= 4.0).",
                                    evidence=f"alpha: {alpha_val}, r: {r_val}, ratio: {scaling_factor}",
                                    owasp="LLM04: Data and Model Poisoning",
                                    mitre_atlas="AML.T0018: Backdoor ML Model",
                                    nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                    eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                                )
                            )
                except Exception:
                    pass

            # 3. Target modules check (SEC-PEFT-003)
            target_modules = data.get("target_modules", [])
            if isinstance(target_modules, list):
                suspicious_targets = [m for m in target_modules if any(k in m.lower() for k in ("classifier", "score", "safety", "guard"))]
                if suspicious_targets:
                    findings.append(
                        Finding(
                            rule_id="SEC-PEFT-003",
                            title=f"LoRA Targets Safety / Classification Layer: {suspicious_targets}",
                            severity=Severity.MEDIUM,
                            category=RiskCategory.ADAPTER_POISONING,
                            file_path=relative_path,
                            description=(
                                f"Adapter modifies non-standard or safety-related modules: {suspicious_targets}. "
                                "This pattern can indicate targeted suppression of moderation or guardrail classification heads."
                            ),
                            remediation="Review intended purpose of adapter modifications to classification heads.",
                            evidence=f"Target modules: {suspicious_targets}",
                            owasp="LLM04: Data and Model Poisoning",
                            mitre_atlas="AML.T0018: Backdoor ML Model",
                            nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                            eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                        )
                    )

            # 4. Unknown / Custom PEFT Type (SEC-PEFT-004)
            peft_type = data.get("peft_type")
            known_peft_types = {"LORA", "QLORA", "PREFIX_TUNING", "P_TUNING", "PROMPT_TUNING", "ADALORA", "IA3", "LOHA", "LOKR", "OFT"}
            if peft_type and str(peft_type).upper() not in known_peft_types:
                findings.append(
                    Finding(
                        rule_id="SEC-PEFT-004",
                        title=f"Unrecognized / Custom PEFT Method: '{peft_type}'",
                        severity=Severity.HIGH,
                        category=RiskCategory.ADAPTER_POISONING,
                        file_path=relative_path,
                        description=(
                            f"Adapter specifies unrecognized peft_type '{peft_type}'. Custom PEFT types can "
                            "trigger remote code execution if loaded with custom runtime backends."
                        ),
                        remediation="Ensure adapter uses standard Hugging Face PEFT methods.",
                        evidence=f"peft_type: {peft_type}",
                        owasp="LLM03: Supply Chain Vulnerabilities",
                        mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                        nist_ai_rmf="MANAGE-2.4 (Third-Party AI Vetting)",
                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-PEFT-ERR-001",
                    title="Malformed PEFT Configuration JSON",
                    severity=Severity.LOW,
                    category=RiskCategory.FORMAT_INTEGRITY,
                    file_path=relative_path,
                    description=f"Error parsing adapter_config.json: {str(e)}",
                    remediation="Verify JSON format.",
                )
            )

        return findings
