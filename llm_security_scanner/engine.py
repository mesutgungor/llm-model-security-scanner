"""
Core Scanner Engine orchestrator.
Manages detectors, walks files, coordinates remote and local model scanning,
and generates standardized ScanReport objects.
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm_security_scanner.models import Finding, RiskCategory, ScanReport, ScannerConfig, Severity
from llm_security_scanner.scanners.artifact_scanner import ArtifactSecurityScanner
from llm_security_scanner.scanners.base import BaseScanner
from llm_security_scanner.scanners.chat_template_scanner import ChatTemplateScanner
from llm_security_scanner.scanners.gguf_scanner import GGUFSecurityScanner
from llm_security_scanner.scanners.hf_hub_scanner import HuggingFaceHubScanner
from llm_security_scanner.scanners.pickle_scanner import PickleSecurityScanner
from llm_security_scanner.scanners.remote_code_scanner import RemoteCodeScanner
from llm_security_scanner.scanners.safetensors_scanner import SafeTensorsSecurityScanner
from llm_security_scanner.scanners.secret_leak_scanner import SecretLeakScanner
from llm_security_scanner.scanners.special_tokens_scanner import SpecialTokensScanner
from llm_security_scanner.scanners.weight_anomaly_scanner import WeightAnomalyScanner
from llm_security_scanner.scanners.peft_adapter_scanner import PeftAdapterScanner
from llm_security_scanner.scanners.generation_config_scanner import GenerationConfigScanner
from llm_security_scanner.scanners.onnx_scanner import ONNXSecurityScanner


class ModelSecurityScanner:
    """The central coordinator that executes all configured security scanners on a model."""

    def __init__(self, config: Optional[ScannerConfig] = None, hf_token: Optional[str] = None):
        self.config = config or ScannerConfig()
        self.hf_token = hf_token
        self.scanners: List[BaseScanner] = []
        self._initialize_scanners()

    def _initialize_scanners(self) -> None:
        """Instantiates all enabled scanners."""
        if self.config.scan_pickles:
            self.scanners.append(PickleSecurityScanner(self.config))
        if self.config.scan_remote_code:
            self.scanners.append(RemoteCodeScanner(self.config))
        if self.config.scan_chat_templates:
            self.scanners.append(ChatTemplateScanner(self.config))
        if self.config.scan_safetensors:
            self.scanners.append(SafeTensorsSecurityScanner(self.config))
        if self.config.scan_gguf:
            self.scanners.append(GGUFSecurityScanner(self.config))
        if self.config.scan_special_tokens:
            self.scanners.append(SpecialTokensScanner(self.config))
        if self.config.scan_artifacts:
            self.scanners.append(ArtifactSecurityScanner(self.config))
        if self.config.scan_weight_anomalies:
            self.scanners.append(WeightAnomalyScanner(self.config))
        if self.config.scan_secrets:
            self.scanners.append(SecretLeakScanner(self.config))
        if self.config.scan_peft:
            self.scanners.append(PeftAdapterScanner(self.config))
        if self.config.scan_generation:
            self.scanners.append(GenerationConfigScanner(self.config))
        if self.config.scan_onnx:
            self.scanners.append(ONNXSecurityScanner(self.config))

    def scan(self, target: str, is_remote: bool = False) -> ScanReport:
        """
        Main entrypoint. Scans either a local directory/file or a remote Hugging Face repo ID.
        """
        start_time = time.time()
        target_path = Path(target)

        # Detect if remote HF repo
        if is_remote or (not target_path.exists() and "/" in target and not target.startswith(".")):
            hf_scanner = HuggingFaceHubScanner(token=self.hf_token)
            remote_data = hf_scanner.scan_remote_repo(target, local_engine=self)

            report = ScanReport(
                target=target,
                is_remote=True,
                scanned_files_count=remote_data["scanned_files_count"],
                total_bytes_scanned=remote_data["total_bytes_scanned"],
                findings=remote_data["findings"],
                model_formats_found=remote_data["model_formats_found"],
                model_architecture=remote_data["model_architecture"],
                cached_dir=remote_data.get("cached_dir"),
                duration_seconds=time.time() - start_time,
            )
            report.compute_risk_score_and_verdict()
            return report

        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        if target_path.is_file():
            return self._scan_single_file(target_path)
        else:
            return self.scan_directory(target_path, display_target=target)

    def _scan_single_file(self, file_path: Path) -> ScanReport:
        start_time = time.time()
        findings: List[Finding] = []
        rel_path = file_path.name
        context: Dict[str, Any] = {"root_dir": file_path.parent}

        formats_found = self._detect_formats([file_path])

        for scanner in self.scanners:
            if scanner.can_scan(file_path):
                findings.extend(scanner.scan_file(file_path, rel_path, context))

        report = ScanReport(
            target=str(file_path),
            is_remote=False,
            scanned_files_count=1,
            total_bytes_scanned=file_path.stat().st_size,
            findings=findings,
            model_formats_found=formats_found,
            duration_seconds=time.time() - start_time,
        )
        report.compute_risk_score_and_verdict()
        return report

    def scan_directory(self, dir_path: Path, display_target: Optional[str] = None, is_remote: bool = False) -> ScanReport:
        start_time = time.time()
        findings: List[Finding] = []
        target_name = display_target or str(dir_path)

        all_files: List[Path] = []
        total_bytes = 0

        # Traverse directory
        for p in dir_path.rglob("*"):
            if p.is_file():
                all_files.append(p)
                try:
                    total_bytes += p.stat().st_size
                except Exception:
                    pass

        formats_found = self._detect_formats(all_files)
        model_arch = self._detect_architecture(dir_path)

        context: Dict[str, Any] = {
            "root_dir": dir_path,
            "all_files": [f.relative_to(dir_path).as_posix() for f in all_files],
            "formats_found": formats_found,
            "architecture": model_arch,
        }

        # 1. Scan each file with applicable scanners
        for file_path in all_files:
            rel_path = file_path.relative_to(dir_path).as_posix()
            for scanner in self.scanners:
                if scanner.can_scan(file_path):
                    findings.extend(scanner.scan_file(file_path, rel_path, context))

        # 2. Run directory-level analysis hooks
        for scanner in self.scanners:
            findings.extend(scanner.scan_directory(dir_path, context))

        # 3. Holistic Check: Are weights present only in pickle format without safetensors?
        has_safetensors = "SafeTensors" in formats_found
        has_pickles = "PyTorch Pickle" in formats_found

        if has_pickles and not has_safetensors and not is_remote:
            findings.append(
                Finding(
                    rule_id="SEC-DIR-001",
                    title="Model Only Uses Unsafe Pickle Weights (No SafeTensors Found)",
                    severity=Severity.HIGH,
                    category=RiskCategory.DESERIALIZATION_EXPLOIT,
                    file_path=target_name,
                    description=(
                        "This model repository contains PyTorch pickle weights (.bin/.pt) but lacks SafeTensors "
                        "alternatives (.safetensors). Pickled weights are inherently unsafe against deserialization attacks."
                    ),
                    remediation="Convert weights to SafeTensors format using safetensors.torch.save_model().",
                )
            )

        report = ScanReport(
            target=target_name,
            is_remote=is_remote,
            scanned_files_count=len(all_files),
            total_bytes_scanned=total_bytes,
            findings=findings,
            model_formats_found=formats_found,
            model_architecture=model_arch,
            duration_seconds=time.time() - start_time,
        )
        report.compute_risk_score_and_verdict()
        return report

    def _detect_formats(self, files: List[Path]) -> List[str]:
        formats = set()
        for f in files:
            name = f.name.lower()
            if name.endswith(".safetensors"):
                formats.add("SafeTensors")
            elif name.endswith((".bin", ".pt", ".pth", ".ckpt", ".pkl")):
                formats.add("PyTorch Pickle")
            elif name.endswith(".gguf"):
                formats.add("GGUF")
            elif name.endswith(".onnx"):
                formats.add("ONNX")
        return sorted(list(formats))

    def _detect_architecture(self, dir_path: Path) -> Optional[str]:
        config_path = dir_path / "config.json"
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        archs = data.get("architectures")
                        if isinstance(archs, list) and archs:
                            return archs[0]
                        return data.get("model_type")
            except Exception:
                pass
        return None
