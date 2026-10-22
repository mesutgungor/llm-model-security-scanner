"""
Base class definition for all security scanners in the LLM Model Security Scanner suite.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pathlib import Path
from llm_security_scanner.models import Finding, ScannerConfig


class BaseScanner(ABC):
    """Abstract base class for all specialized model security scanners."""

    name: str = "BaseScanner"
    description: str = "Base scanner description"

    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()

    @abstractmethod
    def can_scan(self, file_path: Path) -> bool:
        """Determines if this scanner handles the given file."""
        pass

    @abstractmethod
    def scan_file(self, file_path: Path, relative_path: str, context: Dict[str, Any]) -> List[Finding]:
        """Scans an individual file and returns any security findings."""
        pass

    def scan_directory(self, dir_path: Path, context: Dict[str, Any]) -> List[Finding]:
        """
        Optional hook for directory-level holistic analysis (e.g., cross-file checks,
        repository structure audits, missing file warnings).
        """
        return []
