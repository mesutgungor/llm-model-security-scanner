# 🔍 LLM Security Proof-of-Finding Audit Dossier
**Target Model / Artifact:** `THUDM/chatglm-6b`  
**Audit Timestamp:** `2026-10-22 19:57:36 UTC`  
**Objective Proof Rate:** **100.0%** (5/5 Findings Verified)  

---
## 📋 Executive Verification Summary
| Metric | Result |
| :--- | :--- |
| **Target Model** | `THUDM/chatglm-6b` |
| **Total Reported Findings** | 5 |
| **Verified Objective Proofs** | 5 |
| **Verification Success Rate** | 100.0% |

---
## 🔬 Objective Finding Proofs & Evidence Traces

### 1. [SEC-HUB-001] Repository Only Distributes Unsafe Pickle Weights
- **Verification Status:** ✅ **VERIFIED OBJECTIVE PROOF**
- **Target File:** `THUDM/chatglm-6b`
- **Cryptographic SHA-256 Hash:** `N/A (Remote / Virtual Manifest)`
- **Verification Methodology:** Hub Manifest File Listing Audit

#### ⚠️ Consumer Impact Statement
SUPPLY CHAIN SERIALIZATION RISK: Repository distributes weights exclusively via unsafe Python pickle formats. Consumers are forced to use torch.load(), exposing them to RCE risks.

#### 🧪 Deterministic Reproduction Steps
- 1. Query file listing for repository 'THUDM/chatglm-6b'.
- 2. Verify presence of legacy .bin / .pt weights.
- 3. Verify complete absence of .safetensors files.

<details><summary><b>View Raw Proof Data & Extracted Telemetry</b></summary>

```json
{
  "only_pickles_present": true,
  "safetensors_present": false
}
```
</details>

#### 🛡️ Remediation Advice
Convert model checkpoint to SafeTensors.

---

### 2. [SEC-RCE-MAP-001] Remote Custom Code Registration (auto_map)
- **Verification Status:** ✅ **VERIFIED OBJECTIVE PROOF**
- **Target File:** `tokenizer_config.json`
- **Cryptographic SHA-256 Hash:** `5bcca050afbbd7e3a3a1224b6c0019eff0dbc9548580637adaafc27a26e4fb0a`
- **Verification Methodology:** Hugging Face auto_map Entrypoint Trace

#### ⚠️ Consumer Impact Statement
REMOTE CODE EXECUTION PATH CONFIRMED: This model repository registers custom Python code via 'auto_map'. If loaded with 'trust_remote_code=True', the model executes arbitrary local Python code instead of using standard, vetted Transformers library classes.

#### 🧪 Deterministic Reproduction Steps
- 1. Examine manifest 'tokenizer_config.json'.
- 2. Auto-map targets detected: {
  "AutoTokenizer": [
    "tokenization_chatglm.ChatGLMTokenizer",
    null
  ]
}.
- 3. Target Python files invoked: ['tokenization_chatglm.py'].
- 4. When calling AutoModel.from_pretrained(..., trust_remote_code=True), Hugging Face automatically executes these scripts.
- 5. Result: Arbitrary code execution occurs in the caller's environment with full local privileges.

<details><summary><b>View Raw Proof Data & Extracted Telemetry</b></summary>

```json
{
  "auto_map_declarations": {
    "AutoTokenizer": [
      "tokenization_chatglm.ChatGLMTokenizer",
      null
    ]
  },
  "referenced_custom_scripts": [
    "tokenization_chatglm.py"
  ]
}
```
</details>

#### 🛡️ Remediation Advice
Do NOT pass trust_remote_code=True. Request the author to integrate the model architecture into the upstream Transformers library or convert weights to standard SafeTensors format.

---

### 3. [SEC-RCE-MAP-001] Remote Custom Code Registration (auto_map)
- **Verification Status:** ✅ **VERIFIED OBJECTIVE PROOF**
- **Target File:** `config.json`
- **Cryptographic SHA-256 Hash:** `513b00be45b0bdcda0e0d6a0a78e3b2c1fe31f3e17c2b920777472242b855152`
- **Verification Methodology:** Hugging Face auto_map Entrypoint Trace

#### ⚠️ Consumer Impact Statement
REMOTE CODE EXECUTION PATH CONFIRMED: This model repository registers custom Python code via 'auto_map'. If loaded with 'trust_remote_code=True', the model executes arbitrary local Python code instead of using standard, vetted Transformers library classes.

#### 🧪 Deterministic Reproduction Steps
- 1. Examine manifest 'config.json'.
- 2. Auto-map targets detected: {
  "AutoConfig": "configuration_chatglm.ChatGLMConfig",
  "AutoModel": "modeling_chatglm.ChatGLMForConditionalGeneration",
  "AutoModelForSeq2SeqLM": "modeling_chatglm.ChatGLMForConditionalGeneration"
}.
- 3. Target Python files invoked: ['configuration_chatglm.py', 'modeling_chatglm.py'].
- 4. When calling AutoModel.from_pretrained(..., trust_remote_code=True), Hugging Face automatically executes these scripts.
- 5. Result: Arbitrary code execution occurs in the caller's environment with full local privileges.

<details><summary><b>View Raw Proof Data & Extracted Telemetry</b></summary>

```json
{
  "auto_map_declarations": {
    "AutoConfig": "configuration_chatglm.ChatGLMConfig",
    "AutoModel": "modeling_chatglm.ChatGLMForConditionalGeneration",
    "AutoModelForSeq2SeqLM": "modeling_chatglm.ChatGLMForConditionalGeneration"
  },
  "referenced_custom_scripts": [
    "configuration_chatglm.py",
    "modeling_chatglm.py"
  ]
}
```
</details>

#### 🛡️ Remediation Advice
Do NOT pass trust_remote_code=True. Request the author to integrate the model architecture into the upstream Transformers library or convert weights to standard SafeTensors format.

---

### 4. [SEC-OBF-001] Obfuscated Payload Decoding via 'decompress'
- **Verification Status:** ✅ **VERIFIED OBJECTIVE PROOF**
- **Target File:** `quantization.py`
- **Cryptographic SHA-256 Hash:** `9e29d0de295c63297b99a06c3b9fe7c6f8781a4aa5fb3b9ff903bdfeaf5a535b`
- **Verification Methodology:** Abstract Syntax Tree (AST) Inspection & Code Extraction

#### ⚠️ Consumer Impact Statement
MALICIOUS / SUSPICIOUS CODE CONFIRMED: Detected dangerous function execution (...decompress(...)) at line 30 in 'quantization.py'.

#### 🧪 Deterministic Reproduction Steps
- 1. Open 'quantization.py' at line 30.
- 2. Inspect offending AST statement:
28: 
29:     kernels = Kernel(
30:         bz2.decompress(base64.b64decode(quantization_code)),
31:         [
32:             "int4WeightCompression",
33:             "int4WeightExtractionFloat",
- 3. Verified execution of unauthorized call pattern.

<details><summary><b>View Raw Proof Data & Extracted Telemetry</b></summary>

```json
{
  "line_number": 30,
  "code_context": "28: \n29:     kernels = Kernel(\n30:         bz2.decompress(base64.b64decode(quantization_code)),\n31:         [\n32:             \"int4WeightCompression\",\n33:             \"int4WeightExtractionFloat\",",
  "evidence": "...decompress(...)"
}
```
</details>

#### 🛡️ Remediation Advice
Remove unauthorized system calls and obfuscation routines from model scripts.

---

### 5. [SEC-OBF-001] Obfuscated Payload Decoding via 'b64decode'
- **Verification Status:** ✅ **VERIFIED OBJECTIVE PROOF**
- **Target File:** `quantization.py`
- **Cryptographic SHA-256 Hash:** `9e29d0de295c63297b99a06c3b9fe7c6f8781a4aa5fb3b9ff903bdfeaf5a535b`
- **Verification Methodology:** Abstract Syntax Tree (AST) Inspection & Code Extraction

#### ⚠️ Consumer Impact Statement
MALICIOUS / SUSPICIOUS CODE CONFIRMED: Detected dangerous function execution (...b64decode(...)) at line 30 in 'quantization.py'.

#### 🧪 Deterministic Reproduction Steps
- 1. Open 'quantization.py' at line 30.
- 2. Inspect offending AST statement:
28: 
29:     kernels = Kernel(
30:         bz2.decompress(base64.b64decode(quantization_code)),
31:         [
32:             "int4WeightCompression",
33:             "int4WeightExtractionFloat",
- 3. Verified execution of unauthorized call pattern.

<details><summary><b>View Raw Proof Data & Extracted Telemetry</b></summary>

```json
{
  "line_number": 30,
  "code_context": "28: \n29:     kernels = Kernel(\n30:         bz2.decompress(base64.b64decode(quantization_code)),\n31:         [\n32:             \"int4WeightCompression\",\n33:             \"int4WeightExtractionFloat\",",
  "evidence": "...b64decode(...)"
}
```
</details>

#### 🛡️ Remediation Advice
Remove unauthorized system calls and obfuscation routines from model scripts.

---
