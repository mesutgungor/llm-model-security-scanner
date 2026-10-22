# 🛡️ LLM Model Security Scan Report
**Target:** `NousResearch/Hermes-3-Llama-3.1-8B`  
**Verdict:** 🔴 **HIGH RISK** (Risk Score: **18.0 / 100**)  
**Scan Duration:** 2.92 seconds  

## 📊 Scan Overview
| Metric | Value |
| :--- | :--- |
| **Files Scanned** | 12 |
| **Data Volume** | 8.75 MB |
| **Detected Formats** | SafeTensors |
| **Model Architecture** | LlamaForCausalLM |
| **Critical Issues** | 0 |
| **High Issues** | 1 |
| **Medium Issues** | 0 |
| **Low / Info Issues** | 0 |

## 🚨 Security Findings
| Severity | Rule ID | Category | Location | Title |
| :---: | :--- | :--- | :--- | :--- |
| **HIGH** | `SEC-TOK-004` | Special Token Manipulation | `tokenizer.json` | Critical Delimiter Marked Non-Special: '<|im_start|>' |


## 🛠️ Detailed Remediation Guidance
### ⚠️ [HIGH] Critical Delimiter Marked Non-Special: '<|im_start|>'
- **File:** `tokenizer.json`
- **Category:** Special Token Manipulation
- **OWASP LLM:** LLM01: Prompt Injection
- **MITRE ATLAS:** AML.T0051: LLM Prompt Injection
- **NIST AI RMF:** MEASURE-2.6 (Model Security Testing)
- **EU AI Act:** Article 15 (Cybersecurity & Robustness)
- **Description:** Control delimiter '<|im_start|>' has special=false. Users can inject this raw token in prompts to break out of system/user turn boundaries.
- **Evidence:** `Token '<|im_start|>' special=False`
- **Remediation:** Set special=true for control token '<|im_start|>'.
