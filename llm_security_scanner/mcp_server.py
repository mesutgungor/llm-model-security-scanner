"""
Model Context Protocol (MCP) Server for LLM Model Security Scanner.
Enables AI coding agents (Claude Code, Cursor, Windsurf, Devin) to autonomously
audit, verify, and gate Hugging Face models and local artifacts before generating or executing code.
"""

from __future__ import annotations
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None  # Handled gracefully if mcp package is missing

from llm_security_scanner.engine import ModelSecurityScanner
from llm_security_scanner.models import ScannerConfig, SecurityVerdict, Severity
from llm_security_scanner.verification import FindingVerificationEngine


def create_mcp_server() -> FastMCP:
    """Initializes and returns the FastMCP server instance with registered tools."""
    if FastMCP is None:
        raise ImportError(
            "The 'mcp' package is required to run the MCP server. "
            "Install it via: pip install 'llm-model-security-scanner[mcp]' or pip install mcp"
        )

    mcp = FastMCP(
        name="llm-model-security-scanner",
        instructions="Autonomous security auditing & proof verification engine for open-source LLMs.",
    )

    @mcp.tool()
    def scan_huggingface_model(
        repo_id: str,
        hf_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audit a remote Hugging Face model repository weightless over the API before writing code or loading weights.

        Args:
            repo_id: The Hugging Face model repository ID (e.g. 'NousResearch/Hermes-3-Llama-3.1-8B', 'mistralai/Mistral-7B-v0.1').
            hf_token: Optional Hugging Face access token for private or gated models.

        Returns:
            Dict containing verdict (SAFE, HIGH_RISK, CRITICAL), risk score, safe_to_load boolean, findings, and remediation advice.
        """
        config = ScannerConfig(deep_weight_sampling=False)
        scanner = ModelSecurityScanner(config=config, hf_token=hf_token)
        report = scanner.scan(repo_id.strip(), is_remote=True)

        safe_to_load = report.verdict == SecurityVerdict.SAFE or report.risk_score == 0.0

        if safe_to_load:
            recommendation = (
                f"Model '{repo_id}' is VERIFIED SAFE (Risk: {report.risk_score}/100, 0 findings). "
                "Approved to generate code or load in transformers/vLLM."
            )
        else:
            top_finding = report.findings[0] if report.findings else None
            top_issue = f"[{top_finding.rule_id}] {top_finding.title}" if top_finding else "Vulnerabilities detected"
            recommendation = (
                f"WARNING: Model '{repo_id}' has verdict '{report.verdict.value}' (Risk: {report.risk_score}/100) "
                f"with {len(report.findings)} vulnerability finding(s). Primary issue: {top_issue}. "
                "Do NOT load without inspecting architecture and configs. Consider an alternative secure model."
            )

        return {
            "repo_id": repo_id,
            "verdict": report.verdict.value,
            "risk_score": report.risk_score,
            "safe_to_load": safe_to_load,
            "recommendation": recommendation,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "medium_count": report.medium_count,
            "low_count": report.low_count,
            "findings_count": len(report.findings),
            "findings": [f.to_dict() for f in report.findings],
            "duration_seconds": round(report.duration_seconds, 2),
        }

    @mcp.tool()
    def audit_local_model(
        target_path: str,
        deep: bool = False,
    ) -> Dict[str, Any]:
        """Perform zero-execution static analysis on a local model file or directory before importing.

        Args:
            target_path: Absolute or relative path to model directory or file (.safetensors, .gguf, .bin, .pt, .json, .py).
            deep: Whether to perform numerical memory-mapped tensor sampling (detects NaNs/Infs and anomalous weights).

        Returns:
            Dict containing verdict, risk score, safe_to_load boolean, and detected security findings.
        """
        p = Path(target_path).expanduser().resolve()
        if not p.exists():
            return {
                "error": f"Path not found: {target_path}",
                "safe_to_load": False,
                "verdict": "ERROR",
            }

        config = ScannerConfig(deep_weight_sampling=deep)
        scanner = ModelSecurityScanner(config=config)
        report = scanner.scan(str(p), is_remote=False)

        safe_to_load = report.verdict == SecurityVerdict.SAFE or report.risk_score == 0.0
        recommendation = (
            f"Path '{target_path}' is VERIFIED SAFE."
            if safe_to_load
            else f"DANGER: '{target_path}' flagged with '{report.verdict.value}'. Do not execute or load."
        )

        return {
            "target": str(p),
            "verdict": report.verdict.value,
            "risk_score": report.risk_score,
            "safe_to_load": safe_to_load,
            "recommendation": recommendation,
            "findings_count": len(report.findings),
            "findings": [f.to_dict() for f in report.findings],
        }

    @mcp.tool()
    def verify_model_proof(
        target: str,
        is_remote: bool = False,
    ) -> Dict[str, Any]:
        """Generate a cryptographic Proof-of-Finding dossier with SHA-256 fingerprints and AST traces.

        Args:
            target: Local file path or remote Hugging Face repository ID.
            is_remote: True if target is a Hugging Face repo ID.

        Returns:
            Dict containing deterministic proofs, reproduction trace, and cryptographic hashes.
        """
        scanner = ModelSecurityScanner()
        report = scanner.scan(target, is_remote=is_remote)
        engine = FindingVerificationEngine()
        dossier = engine.verify_report(report)

        return dossier.to_dict()

    @mcp.tool()
    def explain_security_rule(rule_id: str) -> Dict[str, Any]:
        """Explain an LLM security rule, its threat category, CVE/CWE mappings, and remediation guide.

        Args:
            rule_id: The rule identifier (e.g. 'SEC-RCE-001', 'SEC-TOK-004', 'SEC-SSTI-001').

        Returns:
            Dict with rule description, impact analysis, framework crosswalk (OWASP, MITRE ATLAS, NIST, EU AI Act), and fix instructions.
        """
        rule_upper = rule_id.strip().upper()
        # Catalog of standard crosswalk rules
        framework_matrix = {
            "SEC-RCE": {
                "category": "Remote Code Execution",
                "owasp": "LLM03: Supply Chain Vulnerabilities",
                "mitre_atlas": "AML.T0048: Code Execution",
                "nist_ai_rmf": "MANAGE-2.4 (Third-Party Vetting)",
                "eu_ai_act": "Article 15 (Cybersecurity & Robustness)",
            },
            "SEC-PCK": {
                "category": "Pickle Deserialization RCE",
                "owasp": "LLM03: Supply Chain Vulnerabilities",
                "mitre_atlas": "AML.T0010: ML Supply Chain Compromise",
                "nist_ai_rmf": "MANAGE-2.4 (Third-Party Vetting)",
                "eu_ai_act": "Article 15 & Article 55 (Systemic Risk)",
            },
            "SEC-SSTI": {
                "category": "Chat Template Injection (SSTI)",
                "owasp": "LLM03 / LLM01: Prompt Injection",
                "mitre_atlas": "AML.T0048: Code Execution",
                "nist_ai_rmf": "MEASURE-2.6 (Model Security Testing)",
                "eu_ai_act": "Article 15 (Cybersecurity)",
            },
            "SEC-TOK": {
                "category": "Special Token Manipulation",
                "owasp": "LLM01: Prompt Injection",
                "mitre_atlas": "AML.T0051: LLM Prompt Injection",
                "nist_ai_rmf": "MEASURE-2.6 (Model Security Testing)",
                "eu_ai_act": "Article 15 (Cybersecurity & Robustness)",
            },
            "SEC-SEC": {
                "category": "Hardcoded Secret & Credential Exposure",
                "owasp": "LLM02: Sensitive Information Disclosure",
                "mitre_atlas": "AML.T0040: ML IP Theft",
                "nist_ai_rmf": "GOVERN-1.2 & MANAGE",
                "eu_ai_act": "Article 15 & Article 53 (Data Protection)",
            },
            "SEC-SAFE": {
                "category": "SafeTensors Header & Allocation",
                "owasp": "LLM10: Model Denial of Service",
                "mitre_atlas": "AML.T0029: Denial of Service",
                "nist_ai_rmf": "MEASURE-2.6 (Robustness Testing)",
                "eu_ai_act": "Article 15 (Robustness)",
            },
            "SEC-GGUF": {
                "category": "GGUF / GGML Header & Buffer",
                "owasp": "LLM10: Model Denial of Service",
                "mitre_atlas": "AML.T0029: Denial of Service",
                "nist_ai_rmf": "MEASURE-2.6 (Robustness Testing)",
                "eu_ai_act": "Article 15 (Robustness)",
            },
        }

        prefix = "-".join(rule_upper.split("-")[:2])
        meta = framework_matrix.get(
            prefix,
            {
                "category": "AI Security Vulnerability",
                "owasp": "LLM03: Supply Chain",
                "mitre_atlas": "AML.T0010: Supply Chain",
                "nist_ai_rmf": "MANAGE-2.4",
                "eu_ai_act": "Article 15",
            },
        )

        return {
            "rule_id": rule_upper,
            "category": meta["category"],
            "compliance": {
                "owasp_llm_top10": meta["owasp"],
                "mitre_atlas": meta["mitre_atlas"],
                "nist_ai_rmf": meta["nist_ai_rmf"],
                "eu_ai_act": meta["eu_ai_act"],
            },
            "documentation_url": f"https://github.com/mesutgungor/llm-model-security-scanner#{rule_upper.lower()}",
        }

    return mcp


def main():
    """Entry point for running the MCP server over stdio."""
    try:
        server = create_mcp_server()
        server.run(transport="stdio")
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"MCP Server error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
