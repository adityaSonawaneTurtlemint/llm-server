# 🔒 AI-Powered Vulnerability Fixer

Automatically detect and fix vulnerabilities in source code using Large Language Models (LLMs) and a knowledge base of fix patterns. This tool integrates Hugging Face models, FAISS for retrieval, and an orchestrator that generates secure patches.

---

## ⚡ Features
- Reads vulnerability scan reports (e.g., **Trivy**, **Semgrep**).
- Uses an **LLM (CodeLlama, StarCoder, Qwen, etc.)** to generate code fixes.
- Knowledge-base driven with **pattern retrieval** to guide fixes.
- Supports **multi-file changes** (planned).
- Confidence score for each fix.
- Each fix comes with an **explanation**.

---

## ⚡ Models
- gpt2 (very small, not good for patching)(1024 max_length)
- Qwen/Qwen2.5-Coder-1.5B (small model)
- bigcode/starcoder2-3b (large model)
- bigcode/DeepSeek-Coder-33B-Instruct (large model)
- EleutherAI/gpt-neo-1.3B
- bigcode/starcoderbase-1b


---
## 🛠️ Installation

```bash
pip install -r required-dependacies.txt
python3.11 -m main2.py


```fastapi-server
python3.11 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn
uvicorn main:app --reload  