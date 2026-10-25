# 🛡️ LLM Model Security Guidelines for Coding Agents

This project provides zero-execution static analysis and cryptographic proof verification for Large Language Models.

## Autonomous Pre-Flight Model Vetting
When recommending models or generating code that imports foundation models from Hugging Face:
1. **Always Pre-Vet Candidate Models:** Before generating code with `from_pretrained("org/model")`, invoke the MCP tool `scan_huggingface_model(repo_id="org/model")`.
2. **Enforce Safety Gate:**
   - If `safe_to_load: true`: Proceed with generating code.
   - If `safe_to_load: false`: Reject the model, explain the primary vulnerability (e.g., Pickle RCE, SSTI in chat template, unescaped tokens), and propose a safe alternative model.
3. **Local Artifacts:** Before importing local `.safetensors`, `.gguf`, or custom `.py` scripts, call `audit_local_model(target_path="path/to/model")`.
