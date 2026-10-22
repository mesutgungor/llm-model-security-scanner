"""
SARIF v2.1.0 Reporter for LLM Model Security Scanner.
Outputs standard OASIS Static Analysis Results Interchange Format for GitHub Actions & CI/CD.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from llm_security_scanner.models import ScanReport, Severity


class SarifReporter:
    def render(self, report: ScanReport, output_file: Optional[Path] = None) -> str:
        rules_dict: Dict[str, Any] = {}
        results: List[Dict[str, Any]] = []

        sarif_level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }

        for finding in report.findings:
            if finding.rule_id not in rules_dict:
                rules_dict[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.remediation},
                    "properties": {
                        "category": finding.category.value,
                        "cwe": finding.cwe,
                        "cve": finding.cve,
                        "owasp": finding.owasp,
                        "mitre_atlas": finding.mitre_atlas,
                        "nist_ai_rmf": finding.nist_ai_rmf,
                        "eu_ai_act": finding.eu_ai_act,
                    },
                }

            line_no = finding.line_number or 1
            result_item: Dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": sarif_level_map.get(finding.severity, "warning"),
                "message": {"text": f"{finding.title}: {finding.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {
                                "startLine": line_no,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
            results.append(result_item)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LLMModelSecurityScanner",
                            "informationUri": "https://github.com/security/llm-model-security-scanner",
                            "semanticVersion": "1.0.0",
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        content = json.dumps(sarif_doc, indent=2)
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content, encoding="utf-8")

        return content
