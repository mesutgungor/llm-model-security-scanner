"""
Scanners registry for LLM Model Security Scanner.
"""

from llm_security_scanner.scanners.base import BaseScanner
from llm_security_scanner.scanners.pickle_scanner import PickleSecurityScanner
from llm_security_scanner.scanners.remote_code_scanner import RemoteCodeScanner
from llm_security_scanner.scanners.chat_template_scanner import ChatTemplateScanner
from llm_security_scanner.scanners.safetensors_scanner import SafeTensorsSecurityScanner
from llm_security_scanner.scanners.gguf_scanner import GGUFSecurityScanner
from llm_security_scanner.scanners.special_tokens_scanner import SpecialTokensScanner
from llm_security_scanner.scanners.artifact_scanner import ArtifactSecurityScanner
from llm_security_scanner.scanners.weight_anomaly_scanner import WeightAnomalyScanner
from llm_security_scanner.scanners.secret_leak_scanner import SecretLeakScanner
from llm_security_scanner.scanners.hf_hub_scanner import HuggingFaceHubScanner
from llm_security_scanner.scanners.peft_adapter_scanner import PeftAdapterScanner
from llm_security_scanner.scanners.generation_config_scanner import GenerationConfigScanner
from llm_security_scanner.scanners.onnx_scanner import ONNXSecurityScanner

__all__ = [
    "BaseScanner",
    "PickleSecurityScanner",
    "RemoteCodeScanner",
    "ChatTemplateScanner",
    "SafeTensorsSecurityScanner",
    "GGUFSecurityScanner",
    "SpecialTokensScanner",
    "ArtifactSecurityScanner",
    "WeightAnomalyScanner",
    "SecretLeakScanner",
    "HuggingFaceHubScanner",
    "PeftAdapterScanner",
    "GenerationConfigScanner",
    "ONNXSecurityScanner",
]
