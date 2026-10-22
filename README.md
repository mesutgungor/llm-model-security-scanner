# 🛡️ LLM Model Security Scanner (`llm-scan`)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-brightgreen.svg)](pyproject.toml)
[![Tests Passing](https://img.shields.io/badge/tests-35%2F35%20passing-success.svg)](tests/)
[![Security Standards](https://img.shields.io/badge/Compliance-OWASP%20%7C%20MITRE%20ATLAS%20%7C%20NIST%20AI%20RMF%20%7C%20EU%20AI%20Act-purple.svg)](#-regulatory--security-framework-crosswalk)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-GitHub%20Security%20Tab-orange.svg)](#-cicd-github-actions-sarif-integration)

> **Enterprise-grade, zero-execution static analysis scanner & cryptographic Proof-of-Finding verification engine for open-source Large Language Models (LLMs) distributed across Hugging Face, ModelScope, and local storage.**

`llm-scan` inspects model serialization formats, weights, configuration manifests, tokenizer dictionaries, chat templates, and custom architecture scripts **before** they are loaded into runtime environments like PyTorch, Hugging Face Transformers, vLLM, Ollama, or llama.cpp.

---

## 📌 Table of Contents

- [Why LLM Model Security?](#-why-llm-model-security)
- [Core Architecture & Zero-Execution Safety](#-core-architecture--zero-execution-safety)
- [Key Features](#-key-features)
- [Installation & Quickstart](#-installation--quickstart)
- [CLI Command Reference](#-cli-command-reference)
  - [1. Scan Local Models](#1-scan-local-models)
  - [2. Remote Hub Auditing (Zero Weight Download)](#2-remote-hub-auditing-zero-weight-download)
  - [3. Proof-of-Finding Engine (`llm-scan verify`)](#3-proof-of-finding-engine-llm-scan-verify)
  - [4. Output Formats (Terminal, SARIF, Markdown, JSON, HTML)](#4-output-formats)
  - [5. CI/CD Gating](#5-cicd-quality-gate)
- [Proof-of-Finding Verification Engine](#-proof-of-finding-verification-engine)
- [Complete 42-Rule Security Catalog](#-complete-42-rule-security-catalog)
- [Regulatory & Security Framework Crosswalk](#-regulatory--security-framework-crosswalk)
- [Validated Real-World Models](#-validated-real-world-models)
- [Python SDK Reference](#-python-sdk-reference)
- [CI/CD GitHub Actions Integration](#-cicd-github-actions-sarif-integration)
- [Threat Model Lifecycle](#-threat-model-lifecycle)
- [Running the Test Suite](#-running-the-test-suite)
- [Author & License](#-author--license)

---

## 🚨 Why LLM Model Security?

Deploying untrusted third-party foundation models introduces severe attack surfaces into enterprise infrastructure:

1. **Pickle Remote Code Execution (RCE):** Legacy PyTorch `.bin`, `.pt`, and `.ckpt` files are serialized via Python's `pickle` engine. Deserialization allows attackers to execute arbitrary system commands (`os.system`, `subprocess`, socket reverse shells) the instant `torch.load()` is executed.
2. **`trust_remote_code=True` Exploits:** Repositories declaring custom model classes in `config.json` (`auto_map`) run arbitrary unvetted Python code on the host machine.
3. **Jinja2 SSTI in Chat Templates (CVE-2024-34359):** Malicious `tokenizer_config.json` chat templates can escape the Jinja sandbox via Python reflection (`__class__.__mro__[1].__subclasses__()`) to achieve arbitrary code execution.
4. **Format Denial of Service (CVE-2023-44469):** SafeTensors 8-byte header allocations can be crafted into memory allocation bombs, crashing host inference servers.
5. **ONNX External Data Traversal (CVE-2024-27318):** Crafty ONNX files can write or read outside repository boundaries via path traversal.
6. **Token Delimiter Hijacking & Trojan Source (CVE-2021-42574):** Token ID collisions and unescaped role tags (`<|im_start|>`) break prompt boundary isolation, enabling prompt injection. Unicode bidirectional overrides smuggle invisible instructions into vocabularies.
7. **LoRA Adapter Scaling Sabotage & Stealth Layers:** Malicious fine-tuned adapters deliberately strip base model safety alignments by setting astronomical scaling factors ($\alpha \gg r$) or injecting Trojan gate weights.
8. **Credential & Secret Leaks:** Model authors frequently leave hardcoded Hugging Face write tokens, OpenAI API keys, AWS credentials, and SSH private keys in files.

---

## 🔒 Core Architecture & Zero-Execution Safety

Traditional scanners often import models into Python, which can accidentally trigger the very exploits they seek to find. 

**`llm-scan` enforces a strict Zero-Execution Architecture:**
- **No `torch.load()` Execution:** Pickles and PyTorch archives are disassembled into opcodes via Python's standard `pickletools` without instantiating objects or running `__reduce__`.
- **AST Parsing for Python Code:** Custom modeling files (`modeling_*.py`, `configuration_*.py`) are analyzed purely as Abstract Syntax Trees via Python's native `ast` compiler.
- **Memory-Mapped Binary Streaming:** SafeTensors and GGUF files are checked via 8-byte stream headers and `mmap` slices without allocating memory or evaluating data arrays.
- **Remote Hub Inspection:** Scans remote Hugging Face repositories in seconds over the Hugging Face REST API without downloading gigabytes of model weights.

```
                              ┌──────────────────────────────────────────────┐
                              │     Model Target (Local Folder / Hub ID)     │
                              └──────────────────────┬───────────────────────┘
                                                     │
               ┌─────────────────────────────────────┴─────────────────────────────────────┐
               ▼                                                                           ▼
   [Remote Hub Inspection]                                                     [Local Model Filesystem]
   - Repository Metadata                                                       - Zero-Execution Disassembly
   - Typosquatting Check                                                       - SafeTensors / GGUF Stream
   - Fast Weightless Audit                                                     - AST Static Analysis
               │                                                                           │
               └─────────────────────────────────────┬─────────────────────────────────────┘
                                                     │
                                                     ▼
                                      ┌─────────────────────────────┐
                                      │   13 Specialized Scanners   │
                                      │    (42 Registered Rules)    │
                                      └──────────────┬──────────────┘
                                                     │
                                                     ▼
                                      ┌─────────────────────────────┐
                                      │  Finding Verification Engine │
                                      │ (Cryptographic SHA-256 Proof)│
                                      └──────────────┬──────────────┘
                                                     │
                         ┌───────────────────────────┼───────────────────────────┐
                         ▼                           ▼                           ▼
                 [Rich Terminal]             [SARIF / JSON]            [Interactive HTML / MD]
              Color Tables & Proof Cards  GitHub Security Tab Upload     Client Proof Dossiers
```

---

## ✨ Key Features

- **13 Specialized Scanners & 42 Production Rules:** Comprehensive coverage across all major model types.
- **Deterministic Proof-of-Finding Engine:** Generates mathematical, byte-level evidence to prove vulnerabilities to model authors and security teams.
- **Interactive HTML Proof Certificates:** Self-contained, zero-dependency HTML certificates with embedded syntax highlighters and SHA-256 fingerprints.
- **Compliance Crosswalk Built-in:** Instant mapping to **OWASP Top 10 for LLMs (2025)**, **MITRE ATLAS**, **NIST AI RMF (AI 100-1)**, and **EU AI Act (Regulation 2024/1689)**.
- **Remote Hugging Face Hub Auditing:** Scan public or private repositories directly using the Hugging Face API without downloading 10GB–100GB weights.
- **Native CI/CD Integration:** Produces standard **SARIF v2.1.0** reports directly compatible with GitHub Code Scanning & Advanced Security.
- **Wide Format Support:** SafeTensors, PyTorch `.bin`/`.pt`, GGUF, GGML, ONNX, PEFT/LoRA adapters, Hugging Face Tokenizers, and Chat Templates.

---

## 📦 Installation & Quickstart

### Prerequisites
- Python $\ge$ 3.9
- Operating System: macOS, Linux, or Windows (WSL)

### Install via pip (Editable / Source)
```bash
git clone https://github.com/mesutgungor/llm_model_security.git
cd llm_model_security
pip install -e .
```

Verify the installation:
```bash
llm-scan --help
```

---

## 🛠️ CLI Command Reference

### 1. Scan Local Models

Scan a complete model directory:
```bash
llm-scan scan ./path-to-model-directory
```

Scan a single model file:
```bash
llm-scan scan ./models/pytorch_model.bin
```

Enable deep weight sampling (checks for NaN/Infinity DoS poisoning and sabotaged layers):
```bash
llm-scan scan ./models/my-model --deep
```

Run in Fast Mode (skips tensor arrays, audits metadata, code, templates, and configurations):
```bash
llm-scan scan ./models/my-model --fast
```

---

### 2. Remote Hub Auditing (Zero Weight Download)

Scan remote repositories directly on Hugging Face without downloading weight files:
```bash
# Public repository
llm-scan scan meta-llama/Llama-3-8B-Instruct --remote

# Private / Gated repository (requires HF token)
llm-scan scan my-org/custom-model --remote --token hf_yourTokenHere
```

---

### 3. Proof-of-Finding Engine (`llm-scan verify`)

Generate verifiable proof dossiers containing cryptographic file hashes, exact code locations, and non-destructive reproduction steps:

```bash
# Verify local model and render terminal proof cards
llm-scan verify ./path-to-model

# Verify remote Hugging Face model and export self-contained HTML proof certificate
llm-scan verify NousResearch/Hermes-3-Llama-3.1-8B --remote --format html --output hermes-certificate.html

# Export Markdown proof dossier for issue tracking & PRs
llm-scan verify THUDM/chatglm-6b --remote --format markdown --output chatglm-proof-dossier.md

# Export machine-readable JSON proof dossier for security orchestrators
llm-scan verify meta-llama/Llama-3-8B --remote --format json --output proofs.json
```

---

### 4. Output Formats

`llm-scan` supports flexible output formats:

| Format Flag | Target Use Case | Example Command |
| :--- | :--- | :--- |
| `terminal` *(default)* | Human interactive inspection | `llm-scan scan ./model` |
| `sarif` | GitHub Advanced Security / IDEs | `llm-scan scan ./model --format sarif -o results.sarif` |
| `markdown` | GitHub PR comments / Documentation | `llm-scan scan ./model --format markdown -o report.md` |
| `json` | Automation pipelines / SIEM / SOAR | `llm-scan scan ./model --format json -o report.json` |
| `html` *(verify)* | Executive & Consumer Proof Certificates | `llm-scan verify <target> --format html -o cert.html` |

---

### 5. CI/CD Quality Gate

Enforce security thresholds in automated deployment pipelines. If any finding meets or exceeds `--max-severity`, `llm-scan` exits with non-zero code `1`:

```bash
llm-scan scan ./models/production-candidate --max-severity HIGH
```

Severity Levels: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`

---

### 6. Utility Commands

```bash
# Print all 42 registered security detection rules
llm-scan list-rules

# View the full regulatory & framework crosswalk (OWASP, MITRE ATLAS, NIST, EU AI Act)
llm-scan compliance

# View the 5-phase end-to-end LLM security lifecycle threat model
llm-scan threat-model
```

---

## 🔬 Proof-of-Finding Verification Engine

Security scanners frequently encounter pushback when alerting on model repositories: *"Is this really exploitable?"* or *"How do I reproduce this?"*

`llm-scan verify` solves this problem by generating **undeniable, verifiable proof artifacts**:

1. **Cryptographic SHA-256 Fingerprint:** Proves the exact file bytes scanned.
2. **Context Code Window:** Extracts the exact offending lines and surrounding context.
3. **AST Syntax Tree / Opcode Trace:** Provides the compiler-level structure of the exploit.
4. **Step-by-Step Reproduction Guide:** Clear, non-destructive reproduction steps for engineers.
5. **Interactive HTML Proof Certificate:** Standalone, zero-dependency HTML file featuring:
   - Severity badges & status indicators.
   - Interactive verification modal.
   - One-click copy for reproduction steps and SHA-256 hashes.
   - Regulatory framework tags.

---

## 📋 Complete 42-Rule Security Catalog

| Rule ID | Severity | Category | Description | CWE / Reference |
| :--- | :---: | :--- | :--- | :--- |
| **`SEC-PCK-001`** | **CRITICAL** | Deserialization Exploit | Arbitrary Code Execution via dangerous pickle opcodes (`GLOBAL`, `REDUCE`, `BUILD`) | CWE-502 |
| **`SEC-PCK-002`** | **HIGH** | Deserialization Exploit | Suspicious or unapproved global object in pickle stream (`os`, `subprocess`, `posix`) | CWE-502 |
| **`SEC-PCK-003`** | **LOW** | Format Integrity | Incomplete or malformed pickle bytecode stream | CWE-20 |
| **`SEC-PCK-INFO-001`** | **LOW** | Format Integrity | Legacy PyTorch pickle serialization format detected (migrate to SafeTensors) | CWE-502 |
| **`SEC-ZIP-001`** | **CRITICAL** | Deserialization Exploit | ZipSlip path traversal in PyTorch archive (`../` file escape) | CWE-22 |
| **`SEC-ZIP-002`** | **LOW** | Format Integrity | Corrupted PyTorch ZIP container structure | CWE-20 |
| **`SEC-RCE-001`** | **HIGH** | Remote Code Execution | Suspicious module imports in architecture scripts (`subprocess`, `socket`, `urllib`) | CWE-94 |
| **`SEC-RCE-002`** | **CRITICAL** | Remote Code Execution | Dynamic code execution via `eval()`, `exec()`, `__import__()` | CWE-95 |
| **`SEC-RCE-003`** | **CRITICAL** | Remote Code Execution | OS command execution via `system()`, `popen()`, `spawn()` | CWE-78 |
| **`SEC-RCE-MAP-001`** | **HIGH** | Remote Code Execution | Auto-map declaration in `config.json` requiring `trust_remote_code=True` | CWE-94 |
| **`SEC-RCE-MAP-002`** | **MEDIUM** | Remote Code Execution | Custom modeling parameter or custom Triton/CUDA kernel declaration | CWE-94 |
| **`SEC-OBF-001`** | **HIGH** | Remote Code Execution | Obfuscated payload decoding (`base64.b64decode`, `zlib.decompress`) | CWE-116 |
| **`SEC-EXF-001`** | **MEDIUM** | Secret Leak | Environment variable access (`os.environ`) in model scripts | CWE-200 |
| **`SEC-TMPL-SSTI-001`** | **CRITICAL** | Chat Template SSTI | Jinja2 reflection escape / Transformers SSTI vulnerability (**CVE-2024-34359**) | CWE-1336 / CVE-2024-34359 |
| **`SEC-TMPL-SSTI-002`** | **CRITICAL** | Chat Template SSTI | Jinja2 sandbox escape / global breakout attempt (`lipsum.__globals__`, `cycler`) | CWE-1336 |
| **`SEC-ST-001`** | **HIGH** | Format Integrity | Truncated SafeTensors file (< 8 bytes) | CWE-125 |
| **`SEC-ST-002`** | **HIGH** | Format Integrity | Invalid zero or negative SafeTensors header size | CWE-125 |
| **`SEC-ST-003`** | **CRITICAL** | Format Integrity | SafeTensors header allocation memory bomb (**CVE-2023-44469**) | CWE-400 / CVE-2023-44469 |
| **`SEC-ST-004`** | **HIGH** | Format Integrity | Malformed SafeTensors JSON header | CWE-20 |
| **`SEC-ST-006`** | **CRITICAL** | Format Integrity | SafeTensors out-of-bounds or inverted tensor offsets | CWE-125 |
| **`SEC-ST-007`** | **CRITICAL** | Format Integrity | Tensor data offsets exceed physical file boundary | CWE-125 |
| **`SEC-ST-META-001`** | **HIGH** | Suspicious Artifact | Suspicious executable pattern in SafeTensors `__metadata__` | CWE-94 |
| **`SEC-GGUF-001`** | **HIGH** | Format Integrity | Truncated GGUF binary file | CWE-125 |
| **`SEC-GGUF-002`** | **HIGH** | Format Integrity | Invalid GGUF magic header bytes | CWE-20 |
| **`SEC-GGUF-004`** | **CRITICAL** | Format Integrity | Anomalous GGUF tensor count triggering C++ integer overflow | CWE-190 |
| **`SEC-GGUF-005`** | **HIGH** | Format Integrity | Anomalous GGUF metadata key-value count (DoS) | CWE-400 |
| **`SEC-ONNX-001`** | **CRITICAL** | Deserialization Exploit | ONNX external data path traversal (**CVE-2024-27318**) | CWE-22 / CVE-2024-27318 |
| **`SEC-ONNX-002`** | **MEDIUM** | Remote Code Execution | ONNX custom domain operator declaration | CWE-94 |
| **`SEC-TOK-001`** | **MEDIUM** | Special Tokens | Missing End-of-Sequence (`eos_token`) configuration causing unbounded generation DoS | CWE-400 |
| **`SEC-TOK-002`** | **HIGH** | Special Tokens | Empty string EOS token configured | CWE-20 |
| **`SEC-TOK-003`** | **HIGH** | Special Tokens | Token ID collision enabling role delimiter hijacking | CWE-20 |
| **`SEC-TOK-004`** | **HIGH** | Special Tokens | Critical delimiter marked non-special (prompt boundary injection) | CWE-20 |
| **`SEC-TOK-005`** | **LOW** | Special Tokens | BOS and EOS tokens are identical | CWE-20 |
| **`SEC-TOK-006`** | **HIGH** | Unicode Smuggling | Unicode Bidirectional (Bidi) Trojan Override (**CVE-2021-42574**) | CWE-94 / CVE-2021-42574 |
| **`SEC-TOK-007`** | **MEDIUM** | Unicode Smuggling | Zero-width invisible character smuggling in vocabulary | CWE-116 |
| **`SEC-GEN-001`** | **HIGH** | Generation DoS | Extreme token generation limit in `max_new_tokens` (KV cache exhaustion) | CWE-400 |
| **`SEC-GEN-002`** | **MEDIUM** | Generation DoS | Invalid sampling temperature (division by zero / inference crash) | CWE-20 |
| **`SEC-GEN-003`** | **MEDIUM** | Generation DoS | Missing `eos_token_id` in generation manifest | CWE-400 |
| **`SEC-PEFT-001`** | **HIGH** | Adapter Poisoning | Suspicious remote base model path in adapter manifest | CWE-494 |
| **`SEC-PEFT-002`** | **HIGH** | Adapter Poisoning | LoRA scaling factor sabotage (alignment stripping / jailbreak) | CWE-693 |
| **`SEC-PEFT-003`** | **MEDIUM** | Adapter Poisoning | LoRA adapter targets safety / classification layer | CWE-693 |
| **`SEC-PEFT-004`** | **HIGH** | Adapter Poisoning | Unrecognized or custom PEFT method declaration | CWE-94 |
| **`SEC-WGT-001`** | **HIGH** | Weight Poisoning | Suspicious tensor name matching trigger / backdoor keywords | CWE-506 |
| **`SEC-WGT-002`** | **CRITICAL** | Weight Poisoning | Poisoned weights containing NaN or Infinity values (Inference DoS) | CWE-400 |
| **`SEC-WGT-003`** | **HIGH** | Weight Poisoning | Sabotaged / all-zero layer weights | CWE-400 |
| **`SEC-WGT-004`** | **MEDIUM** | Weight Poisoning | Extreme weight magnitude outlier spike (Trojan gate trigger) | CWE-506 |
| **`SEC-WGT-005`** | **CRITICAL** | Weight Poisoning | Stealth out-of-bounds layer injected (hidden Trojan layer) | CWE-506 |
| **`SEC-ART-001`** | **HIGH** | Suspicious Artifact | Standalone executable script or native binary in model directory | CWE-507 |
| **`SEC-ART-002`** | **CRITICAL** | Suspicious Artifact | Disguised Linux ELF, Windows PE, or macOS Mach-O binary disguised as `.bin` | CWE-507 |
| **`SEC-ART-003`** | **MEDIUM** | Suspicious Artifact | Abnormally high Shannon entropy in plaintext file | CWE-507 |
| **`SEC-SYM-001`** | **CRITICAL** | Suspicious Artifact | Malicious symlink traversal pointing outside model repository | CWE-59 |
| **`SEC-SEC-001`** | **CRITICAL** | Secret Leak | Exposed Hugging Face token, OpenAI API key, AWS secret key, or private SSH key | CWE-798 |
| **`SEC-HUB-001`** | **HIGH** | Supply Chain | Repository only distributes unsafe pickle weights without SafeTensors | CWE-502 |
| **`SEC-HUB-002`** | **HIGH** | Supply Chain | Standalone executable script file in Hub repository | CWE-507 |
| **`SEC-HUB-TYPO-001`**| **HIGH** | Supply Chain | Author typosquatting popular publishers on Hugging Face | Supply Chain |

---

## 🏛️ Regulatory & Security Framework Crosswalk

Every rule in `llm-scan` is systematically mapped to the four principal AI safety and cybersecurity governance frameworks:

| Scanner Rule | Threat Description | OWASP Top 10 for LLMs (2025) | MITRE ATLAS | NIST AI RMF (100-1) | EU AI Act (2024/1689) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`SEC-PCK-001`** | Deserialization RCE | **LLM03: Supply Chain** | **AML.T0010: Supply Chain** | **MANAGE-2.4 (Vetting)** | **Art. 15 / Art. 55 (Systemic)** |
| **`SEC-ZIP-001`** | ZipSlip Path Traversal | **LLM03: Supply Chain** | **AML.T0010: Supply Chain** | **MANAGE-2.4 (Vetting)** | **Art. 15 (Cybersecurity)** |
| **`SEC-RCE-001`** | Dangerous Module Imports | **LLM03: Supply Chain** | **AML.T0010: Supply Chain** | **MANAGE-2.4 (Vetting)** | **Art. 15 (Cybersecurity)** |
| **`SEC-RCE-002`** | Dynamic Eval/Exec | **LLM03: Supply Chain** | **AML.T0048: Code Execution** | **MANAGE-2.4 (Vetting)** | **Art. 15 (Cybersecurity)** |
| **`SEC-RCE-003`** | OS Command Execution | **LLM03: Supply Chain** | **AML.T0048: Code Execution** | **MANAGE-2.4 (Vetting)** | **Art. 15 (Cybersecurity)** |
| **`SEC-RCE-MAP`** | `auto_map` Remote Code | **LLM03: Supply Chain** | **AML.T0010: Supply Chain** | **MANAGE-2.4 (Vetting)** | **Art. 53 (GPAI Docs)** |
| **`SEC-TMPL-SSTI`**| Jinja2 SSTI (CVE-2024-34359)| **LLM03 / LLM01** | **AML.T0048: Code Execution** | **MEASURE-2.6 (Testing)** | **Art. 15 (Cybersecurity)** |
| **`SEC-ST-003`** | SafeTensors Memory Bomb | **LLM10: Unbounded Consumption** | **AML.T0029: Denial of Service**| **MEASURE-2.6 (Testing)** | **Art. 15 (Robustness)** |
| **`SEC-ONNX-001`** | ONNX Path Traversal | **LLM03: Supply Chain** | **AML.T0010: Supply Chain** | **MANAGE-2.4 (Vetting)** | **Art. 15 (Cybersecurity)** |
| **`SEC-WGT-002`** | Poisoned NaN/Inf Weights | **LLM04: Model Poisoning** | **AML.T0029: Denial of Service**| **MEASURE-2.6 (Testing)** | **Art. 15 / Art. 55 (Systemic)** |
| **`SEC-WGT-003`** | Sabotaged / Zero Weights | **LLM04: Model Poisoning** | **AML.T0018: Backdoor ML** | **MEASURE-2.6 (Testing)** | **Art. 15 (Robustness)** |
| **`SEC-WGT-005`** | Stealth Injected Layer | **LLM04: Model Poisoning** | **AML.T0018: Backdoor ML** | **MEASURE-2.6 (Testing)** | **Art. 15 (Cybersecurity)** |
| **`SEC-TOK-003`** | Token ID Delimiter Hijack | **LLM01: Prompt Injection** | **AML.T0051: LLM Injection** | **MEASURE-2.6 (Testing)** | **Art. 15 (Cybersecurity)** |
| **`SEC-TOK-004`** | Delimiter Marked Non-Special| **LLM01: Prompt Injection** | **AML.T0051: LLM Injection** | **MEASURE-2.6 (Testing)** | **Art. 15 (Cybersecurity)** |
| **`SEC-TOK-006`** | Unicode Bidi Trojan Source | **LLM01: Prompt Injection** | **AML.T0051: LLM Injection** | **MEASURE-2.6 (Testing)** | **Art. 15 (Robustness)** |
| **`SEC-GEN-001`** | Extreme Generation KV DoS | **LLM10: Unbounded Consumption** | **AML.T0029: Denial of Service**| **MEASURE-2.6 (Testing)** | **Art. 15 (Robustness)** |
| **`SEC-PEFT-001`** | Suspicious LoRA Base Model | **LLM03: Supply Chain** | **AML.T0010: Supply Chain** | **MANAGE-2.4 (Vetting)** | **Art. 15 (Cybersecurity)** |
| **`SEC-PEFT-002`** | LoRA Scaling Sabotage | **LLM04: Model Poisoning** | **AML.T0018: Backdoor ML** | **MEASURE-2.6 (Testing)** | **Art. 15 (Robustness)** |
| **`SEC-ART-002`** | Disguised ELF/PE Binaries | **LLM03: Supply Chain** | **AML.T0010: Supply Chain** | **MANAGE-2.4 (Vetting)** | **Art. 15 (Cybersecurity)** |
| **`SEC-SEC-001`** | Leaked Secrets / API Keys | **LLM02: Sensitive Data Leak** | **AML.T0040: ML IP Theft** | **GOVERN-1.2 & MANAGE** | **Art. 15 & Art. 53 (Protection)** |

---

## 🧪 Validated Real-World Models

`llm-scan` has been validated against production foundation models on the Hugging Face Hub:

| Model Repository | Verdict | Risk Score | Key Findings & Verification |
| :--- | :---: | :---: | :--- |
| **`Qwen/Qwen2.5-0.5B-Instruct`** | `SAFE` | **0 / 100** | Zero findings. Native SafeTensors format, clean tokenizer, no arbitrary remote code. |
| **`gpt2`** | `MEDIUM_RISK` | **9 / 100** | Contains legacy PyTorch pickle weights (`pytorch_model.bin`). Flagged for modernization. |
| **`tiiuae/falcon-7b`** | `HIGH_RISK` | **45 / 100** | Declares `auto_map` in `config.json` requiring `trust_remote_code=True`. Verified via AST proof. |
| **`THUDM/chatglm-6b`** | `HIGH_RISK` | **92 / 100** | 5 high-severity findings: base64 decompression at `quantization.py:L30`, process spawning, `auto_map`. |
| **`NousResearch/Hermes-3-Llama-3.1-8B`** | `HIGH_RISK` | **45 / 100** | Role delimiter `<|im_start|>` configured as non-special token (ID 128039) in `tokenizer.json`. |

---

## 🐍 Python SDK Reference

Integrate `llm-scan` directly into your data pipelines, model ingestion workflows, or PyTorch inference servers:

```python
from llm_security_scanner import ModelSecurityScanner, ScannerConfig, SecurityVerdict

# Configure the security scanning engine
scanner = ModelSecurityScanner(
    config=ScannerConfig(
        scan_pickles=True,
        scan_remote_code=True,
        scan_chat_templates=True,
        scan_safetensors=True,
        scan_special_tokens=True,
        deep_weight_sampling=True,
    )
)

# Audit a local model directory or file
report = scanner.scan("./models/llama-3-8b")

print(f"Model: {report.model_path}")
print(f"Security Verdict: {report.verdict.value}")
print(f"Risk Score: {report.risk_score} / 100")

# Enforce security gates before model loading
if report.verdict in (SecurityVerdict.HIGH_RISK, SecurityVerdict.CRITICAL):
    print("🚨 Refusing to load model due to critical security findings:")
    for finding in report.findings:
        print(f" - [{finding.severity.value}] {finding.title} ({finding.file_path})")
        print(f"   Remediation: {finding.remediation}\n")
    raise SystemExit("Pipeline aborted: Model failed security gate.")

# Safe to proceed with torch.load or Transformers
print("✅ Security gate passed: Model verified safe for production loading.")
```

---

## 🔄 CI/CD GitHub Actions (SARIF Integration)

Integrate `llm-scan` into your GitHub CI/CD workflows. Security alerts will automatically appear in your repository's **GitHub Security > Code Scanning Alerts** tab:

```yaml
name: LLM Model Security Audit

on:
  pull_request:
    paths:
      - 'models/**'
  push:
    branches: [main]

jobs:
  model-security-audit:
    name: Model Security Scan & SARIF Upload
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Scanner
        run: |
          pip install --upgrade pip
          pip install -e .

      - name: Execute Model Security Scan
        run: |
          llm-scan scan ./models/candidate-model \
            --format sarif \
            --output results.sarif \
            --max-severity HIGH

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🌐 Threat Model Lifecycle

`llm-scan` is architected around the full 5-stage Machine Learning Security Lifecycle:

```
  Phase 1: Training Data Collection
  ├── Web scraping cache poisoning & Clean-label Trojan injections
  └── PII / Secret leakage in pre-training corpora

  Phase 2: Training & Model Architecture
  ├── Malicious custom CUDA / Triton kernels
  ├── Sleeper Agent backdoor weights & Trojan gates
  └── LoRA safety-alignment stripping

  Phase 3: Serialization & Distribution (Core Target of llm-scan)
  ├── Weaponized pickle bytecode RCE (torch.load)
  ├── trust_remote_code=True auto_map dynamic execution
  ├── Jinja2 Chat Template SSTI (CVE-2024-34359)
  ├── SafeTensors & GGUF header memory allocation bombs
  ├── ONNX external data path traversal (CVE-2024-27318)
  ├── Tokenizer role delimiter hijacking & Unicode Bidi smuggling
  └── Disguised ELF / PE binaries & hardcoded credentials

  Phase 4: Deployment & Infrastructure
  ├── Inference engine memory corruption (vLLM, llama.cpp)
  └── GPU memory exhaustion via oversized token generation configs

  Phase 5: Post-Deployment & Inference
  ├── Direct & Indirect Prompt Injections
  └── Jailbreaking & Autonomous Agent tool abuse (SSRF)
```

Run `llm-scan threat-model` in your terminal to view details on every lifecycle phase.

---

## 🧪 Running the Test Suite

The test suite covers all 13 scanner modules, the verification engine, and SARIF export:

```bash
# Run all unit and integration tests
python3 -m unittest discover -s tests -v
```

Expected output:
```
Ran 35 tests in 0.030s

OK
```

All 35 tests execute without executing dangerous bytecode or downloading external files.

---

## 👤 Author & Contact

**Mesut Güngör**  
- GitHub: [@mesutgungor](https://github.com/mesutgungor)
- Repository: [https://github.com/mesutgungor/llm_model_security](https://github.com/mesutgungor/llm_model_security)

---

## 📄 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for complete terms and copyright notices.
