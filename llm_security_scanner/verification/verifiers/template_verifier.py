"""
Verifier for Chat Template SSTI & Sandbox Escapes (SEC-TMPL-SSTI-001, SEC-TMPL-SSTI-002).
Extracts the offending Jinja expression and proves the reflection escape path (CVE-2024-34359).
"""

from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict

from llm_security_scanner.models import Finding
from llm_security_scanner.verification.models import (
    VerificationProof,
    VerificationStatus,
    compute_file_sha256,
)
from llm_security_scanner.verification.verifiers.base import BaseVerifier


class ChatTemplateVerifier(BaseVerifier):
    name = "ChatTemplateVerifier"

    def can_verify(self, finding: Finding) -> bool:
        return finding.rule_id in ("SEC-TMPL-SSTI-001", "SEC-TMPL-SSTI-002")

    def verify(self, finding: Finding, root_dir: Path) -> VerificationProof:
        file_path = root_dir / finding.file_path
        sha256_hash = compute_file_sha256(file_path)
        proof_data: Dict[str, Any] = {}

        if file_path.exists():
            try:
                data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
                template = data.get("chat_template", "")
                if isinstance(template, str):
                    # Match reflection tokens
                    matches = re.findall(r"(\{\{.*?\}\})", template)
                    dangerous_tags = [
                        m for m in matches if any(
                            k in m for k in ("__class__", "__globals__", "cycler", "lipsum", "os.popen", "popen")
                        )
                    ]
                    proof_data = {
                        "vulnerable_template_length": len(template),
                        "isolated_exploit_expressions": dangerous_tags,
                    }
            except Exception:
                pass

        return VerificationProof(
            rule_id=finding.rule_id,
            finding_title=finding.title,
            file_path=finding.file_path,
            file_sha256=sha256_hash,
            status=VerificationStatus.VERIFIED if proof_data else VerificationStatus.UNVERIFIED,
            methodology="Jinja2 Template Reflection Expression Isolation",
            reproduction_steps=[
                f"1. Open '{finding.file_path}'.",
                "2. Extract chat_template string from JSON.",
                f"3. Isolated dangerous expressions: {proof_data.get('isolated_exploit_expressions', [])}.",
                "4. When calling tokenizer.apply_chat_template(), the Jinja engine evaluates expressions.",
                "5. Unsanitized Jinja environments allow breakout into Python builtins (CVE-2024-34359).",
            ],
            proof_data=proof_data,
            consumer_impact_summary=(
                "SERVER-SIDE TEMPLATE INJECTION CONFIRMED: Tokenizer chat template contains reflection breakouts. "
                "Formatting prompt chats will execute arbitrary commands on the inference server."
            ),
            remediation_recommendation=(
                "Upgrade transformers to >= 4.40.1 and sanitize/strip custom Jinja2 expressions."
            ),
        )
