"""
Weight Anomaly & Backdoor Indicator Scanner.
Inspects tensor values safely (via safetensors memory-mapping) to detect:
NaN/Infinity poisoning (DoS), all-zero layer sabotage, extreme weight distribution outliers
(Trojan activation gates), and suspicious tensor naming patterns.
"""

from __future__ import annotations
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List

import torch
from safetensors import safe_open

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

SUSPICIOUS_TENSOR_KEYWORDS = {"backdoor", "trojan", "trigger", "exploit", "stealth", "bypass"}


class WeightAnomalyScanner(BaseScanner):
    name = "WeightAnomalyScanner"
    description = "Samples SafeTensors weights for NaN/Inf poisoning, zeroed layers, and extreme outlier spikes"

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".safetensors"

    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with safe_open(str(file_path), framework="pt", device="cpu") as f:
                tensor_keys = list(f.keys())

                # 1. Check for suspicious tensor names and structural layer out-of-bounds
                expected_layers = None
                root_dir = context.get("root_dir")
                if root_dir:
                    cfg_p = Path(root_dir) / "config.json"
                    if cfg_p.exists():
                        try:
                            cfg_data = json.loads(cfg_p.read_text(encoding="utf-8", errors="ignore"))
                            expected_layers = cfg_data.get("num_hidden_layers") or cfg_data.get("n_layer") or cfg_data.get("num_layers")
                        except Exception:
                            pass

                for key in tensor_keys:
                    lower_key = key.lower()
                    for keyword in SUSPICIOUS_TENSOR_KEYWORDS:
                        if keyword in lower_key:
                            findings.append(
                                Finding(
                                    rule_id="SEC-WGT-001",
                                    title=f"Suspicious Tensor Name in Weights: '{key}'",
                                    severity=Severity.HIGH,
                                    category=RiskCategory.WEIGHT_POISONING_ANOMALY,
                                    file_path=relative_path,
                                    description=(
                                        f"Tensor key '{key}' matches suspicious keyword '{keyword}'. "
                                        f"This may indicate a hidden backdoor gate or non-standard trigger weights."
                                    ),
                                    remediation="Verify the model architecture specification for custom tensors.",
                                    evidence=f"Tensor Key: {key}",
                                    owasp="LLM04: Data and Model Poisoning",
                                    mitre_atlas="AML.T0018: Backdoor ML Model",
                                    nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                    eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                                )
                            )

                    # Structural Check: Check if layer index exceeds num_hidden_layers (SEC-WGT-005)
                    if expected_layers and isinstance(expected_layers, int):
                        layer_match = re.search(r"\.(?:layers|h|blocks)\.(\d+)\.", key)
                        if layer_match:
                            layer_idx = int(layer_match.group(1))
                            if layer_idx >= expected_layers:
                                findings.append(
                                    Finding(
                                        rule_id="SEC-WGT-005",
                                        title=f"Stealth Out-Of-Bounds Layer Injected: '{key}' (Layer {layer_idx} >= {expected_layers})",
                                        severity=Severity.CRITICAL,
                                        category=RiskCategory.WEIGHT_POISONING_ANOMALY,
                                        file_path=relative_path,
                                        description=(
                                            f"Tensor '{key}' declares layer index {layer_idx}, but config.json specifies "
                                            f"only {expected_layers} hidden layers. Extra concealed layers are used to hide "
                                            "Trojan activation circuits that bypass standard architecture evaluations."
                                        ),
                                        remediation="Verify whether extra layers are intentional or indicate model tampering.",
                                        evidence=f"Declared in config: {expected_layers}, Found in weights: {layer_idx}",
                                        owasp="LLM04: Data and Model Poisoning",
                                        mitre_atlas="AML.T0018: Backdoor ML Model",
                                        nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                        eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                                    )
                                )

                # 2. Sample tensors for numerical anomalies (NaN, Inf, Zeroed, Spikes)
                if self.config.deep_weight_sampling and tensor_keys:
                    step = max(1, len(tensor_keys) // self.config.sample_tensors_count)
                    sample_keys = tensor_keys[::step][: self.config.sample_tensors_count]

                    for key in sample_keys:
                        try:
                            tensor = f.get_tensor(key)
                            # Convert to float for numerical checks if not already
                            if tensor.dtype in (torch.float32, torch.float16, torch.bfloat16):
                                # Check for NaN / Inf
                                has_nan = bool(torch.isnan(tensor).any())
                                has_inf = bool(torch.isinf(tensor).any())

                                if has_nan or has_inf:
                                    issue = "NaN" if has_nan else "Infinity"
                                    findings.append(
                                        Finding(
                                            rule_id="SEC-WGT-002",
                                            title=f"Poisoned Tensor ({issue} values) in '{key}'",
                                            severity=Severity.CRITICAL,
                                            category=RiskCategory.WEIGHT_POISONING_ANOMALY,
                                            file_path=relative_path,
                                            description=(
                                                f"Tensor '{key}' contains {issue} values. Any inference using this "
                                                f"model will immediately propagate NaN outputs across all generated tokens, "
                                                f"causing a Denial of Service (DoS) across inference runtimes."
                                            ),
                                            remediation="Do not deploy this model. Weights are corrupted or sabotaged.",
                                            evidence=f"Tensor '{key}' contains {issue}",
                                            cwe="CWE-400",
                                            owasp="LLM04: Data and Model Poisoning",
                                            mitre_atlas="AML.T0029: Denial of Service",
                                            nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                            eu_ai_act="Article 15 (Cybersecurity & Robustness), Article 55 (Systemic Risk)",
                                        )
                                    )
                                    break

                                # Check for all-zero layers (sabotage / dead model)
                                if tensor.numel() > 1000 and bool((tensor == 0).all()):
                                    findings.append(
                                        Finding(
                                            rule_id="SEC-WGT-003",
                                            title=f"All-Zero Sabotaged Tensor: '{key}'",
                                            severity=Severity.HIGH,
                                            category=RiskCategory.WEIGHT_POISONING_ANOMALY,
                                            file_path=relative_path,
                                            description=(
                                                f"Tensor '{key}' ({tensor.numel()} elements) is completely zeroed out. "
                                                f"This could indicate targeted ablation or weight sabotage."
                                            ),
                                            remediation="Check if this layer was pruned or intentionally zeroed.",
                                            evidence=f"Tensor '{key}' is completely 0.0",
                                            owasp="LLM04: Data and Model Poisoning",
                                            mitre_atlas="AML.T0018: Backdoor ML Model",
                                            nist_ai_rmf="MEASURE-2.6 (Model Security Testing)",
                                            eu_ai_act="Article 15 (Cybersecurity & Robustness)",
                                        )
                                    )

                                # Check for extreme outlier spikes (e.g. max magnitude > 10000 in attention weights)
                                max_abs = float(torch.max(torch.abs(tensor)))
                                if max_abs > 10000.0 and "weight" in key.lower():
                                    findings.append(
                                        Finding(
                                            rule_id="SEC-WGT-004",
                                            title=f"Extreme Weight Outlier Spike in '{key}' ({max_abs})",
                                            severity=Severity.MEDIUM,
                                            category=RiskCategory.WEIGHT_POISONING_ANOMALY,
                                            file_path=relative_path,
                                            description=(
                                                f"Tensor '{key}' exhibits an extreme magnitude spike ({round(max_abs, 2)}). "
                                                f"Abnormal outlier spikes can indicate Trojan trigger activations or "
                                                f"quantization clipping anomalies."
                                            ),
                                            remediation="Review layer weight distribution and evaluate for backdoor triggers.",
                                            evidence=f"Max magnitude: {round(max_abs, 2)}",
                                        )
                                    )

                        except Exception:
                            continue

        except Exception as e:
            # Not fatal if safe_open fails or not a valid safetensors
            pass

        return findings
