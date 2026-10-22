"""
Remote Hugging Face Hub Scanner.
Inspects Hugging Face repositories directly via API without downloading gigabytes of weights.
Audits repository structure, detects typosquatting, identifies legacy pickle weights,
and selectively downloads and audits configuration files, tokenizers, and custom Python code.
"""

from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from huggingface_hub import HfApi

from llm_security_scanner.models import Finding, RiskCategory, Severity
from llm_security_scanner.scanners.base import BaseScanner

POPULAR_ORGANIZATIONS = [
    "meta-llama",
    "mistralai",
    "google",
    "deepseek-ai",
    "Qwen",
    "microsoft",
    "openai",
    "anthropic",
    "tiiuae",
    "facebook",
]


class HuggingFaceHubScanner:
    """Specialized scanner for remote Hugging Face model repositories."""

    def __init__(self, token: Optional[str] = None):
        self.api = HfApi(token=token)

    def scan_remote_repo(self, repo_id: str, local_engine: Any) -> Any:
        """
        Inspects a remote Hugging Face repository, downloads only configuration and code files,
        and runs the scanner engine on them.
        """
        findings: List[Finding] = []

        try:
            # 1. Fetch Model Info from HF
            model_info = self.api.model_info(repo_id, files_metadata=True)
            siblings = [s.rfilename for s in (model_info.siblings or [])]

            # 2. Typosquatting / Supply Chain check
            parts = repo_id.split("/")
            if len(parts) == 2:
                author, model_name = parts
                for popular_org in POPULAR_ORGANIZATIONS:
                    if author.lower() != popular_org and (
                        author.lower().startswith(popular_org)
                        or author.lower().endswith(popular_org)
                        or popular_org in author.lower()
                    ):
                        findings.append(
                            Finding(
                                rule_id="SEC-HUB-TYPO-001",
                                title=f"Potential Typosquatting Detected: '{author}' vs '{popular_org}'",
                                severity=Severity.HIGH,
                                category=RiskCategory.SUPPLY_CHAIN_TYPOSQUAT,
                                file_path=repo_id,
                                description=(
                                    f"The repository author '{author}' is very similar to legitimate organization "
                                    f"'{popular_org}'. Attackers often upload malicious fine-tunes using spoofed org names."
                                ),
                                remediation="Verify the official Hugging Face organization badge and author provenance.",
                                evidence=f"Repo: {repo_id}",
                            )
                        )

            # 3. Check for presence of legacy pickle vs safetensors in file listing
            has_safetensors = any(f.endswith(".safetensors") for f in siblings)
            has_pickles = any(
                f.endswith((".bin", ".pt", ".pth", ".ckpt"))
                and not f.endswith("training_args.bin")
                for f in siblings
            )

            if has_pickles and not has_safetensors:
                findings.append(
                    Finding(
                        rule_id="SEC-HUB-001",
                        title="Repository Only Distributes Unsafe Pickle Weights",
                        severity=Severity.HIGH,
                        category=RiskCategory.DESERIALIZATION_EXPLOIT,
                        file_path=repo_id,
                        description=(
                            "This repository distributes model weights exclusively in legacy PyTorch pickle format "
                            "(.bin/.pt) with no SafeTensors alternatives available. Pickle files expose users to RCE risks."
                        ),
                        remediation="Request the author to convert the weights to SafeTensors or use safetensors converter.",
                    )
                )

            # 4. Check for standalone executable scripts in repository file listing
            for f in siblings:
                suffix = os.path.splitext(f)[1].lower()
                if suffix in (".sh", ".bash", ".bat", ".exe", ".dll", ".so"):
                    findings.append(
                        Finding(
                            rule_id="SEC-HUB-002",
                            title=f"Suspicious Executable File in Hub Repo: '{f}'",
                            severity=Severity.HIGH,
                            category=RiskCategory.SUSPICIOUS_ARTIFACT,
                            file_path=f,
                            description=f"Model repository contains standalone executable/script '{f}'.",
                            remediation="Audit script contents before downloading or cloning repository.",
                        )
                    )

            # 5. Download lightweight metadata and code files to a temporary workspace for deep scanning
            # 5. Download lightweight metadata and code files to a persistent cache workspace for deep scanning and verification
            safe_id = repo_id.replace("/", "--")
            cache_dir = Path.home() / ".cache" / "llm_security_scanner" / "models" / safe_id
            cache_dir.mkdir(parents=True, exist_ok=True)

            target_files = [
                f for f in siblings
                if f.endswith((".json", ".py", ".md", ".txt"))
                and not f.startswith(".git")
            ]

            # Download each lightweight file safely
            for remote_file in target_files:
                try:
                    url = f"https://huggingface.co/{repo_id}/raw/main/{remote_file}"
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        dest_file = cache_dir / remote_file
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        dest_file.write_bytes(resp.content)
                except Exception:
                    continue

            # Run local engine scanners on the downloaded lightweight files
            local_report = local_engine.scan_directory(cache_dir, display_target=repo_id, is_remote=True)
            findings.extend(local_report.findings)

            # Collect detected formats
            formats_found = set()
            for s in siblings:
                sl = s.lower()
                if sl.endswith(".safetensors"):
                    formats_found.add("SafeTensors")
                elif sl.endswith((".bin", ".pt", ".pth", ".ckpt", ".pkl")):
                    formats_found.add("PyTorch Pickle")
                elif sl.endswith(".gguf"):
                    formats_found.add("GGUF")
                elif sl.endswith(".onnx"):
                    formats_found.add("ONNX")

            return {
                "findings": findings,
                "scanned_files_count": len(siblings),
                "total_bytes_scanned": local_report.total_bytes_scanned,
                "model_formats_found": sorted(list(formats_found)),
                "model_architecture": local_report.model_architecture,
                "cached_dir": str(cache_dir),
            }

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SEC-HUB-ERR-001",
                    title="Failed to Inspect Hugging Face Repository",
                    severity=Severity.MEDIUM,
                    category=RiskCategory.SUPPLY_CHAIN_TYPOSQUAT,
                    file_path=repo_id,
                    description=f"Hugging Face Hub API error: {str(e)}",
                    remediation="Check repository ID spelling, internet connectivity, or HF token permissions.",
                )
            )

        return {
            "findings": findings,
            "scanned_files_count": len(findings),
            "total_bytes_scanned": 0,
            "model_formats_found": [],
            "model_architecture": None,
        }
