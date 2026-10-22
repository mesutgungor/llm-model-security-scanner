"""
Base class for Proof-of-Finding verifiers.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from llm_security_scanner.models import Finding
from llm_security_scanner.verification.models import VerificationProof


class BaseVerifier(ABC):
    """Abstract base class for all proof-of-finding verifiers."""

    name: str = "BaseVerifier"

    @abstractmethod
    def can_verify(self, finding: Finding) -> bool:
        """Determines if this verifier can produce objective proof for the given finding."""
        pass

    @abstractmethod
    def verify(self, finding: Finding, root_dir: Path) -> VerificationProof:
        """Executes non-destructive verification tests and returns an objective proof record."""
        pass
