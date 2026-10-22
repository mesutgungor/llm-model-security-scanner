"""
JSON Reporter for LLM Model Security Scanner.
Outputs structured JSON for programmatic consumption and automation.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional
from llm_security_scanner.models import ScanReport


class JsonReporter:
    def render(self, report: ScanReport, output_file: Optional[Path] = None) -> str:
        content = report.to_json(indent=2)
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content, encoding="utf-8")
        return content
