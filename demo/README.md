---
title: SOUF AI - LLM Prompt Security Inspector
emoji: 🔒
colorFrom: gray
colorTo: red
sdk: gradio
sdk_version: 4.44.1
app_file: app.py
pinned: true
license: mit
---

# SOUF AI — Sector-Optimised Utility Firewall

Deep Prompt Inspection (DPI) for LLM governance. Sub-millisecond pattern-based inspection
with HIPAA and PCI-DSS sector policy packs and Gemini human-review integration.

**Benchmarks (all code-verified):**
- In-distribution: 48/48 attacks blocked, 0 FP, F1=1.000
- OOD adversarial: 90/90 attacks blocked, 0 FP, F1=1.000
- HIPAA vertical (20 prompts): 16/16 attacks, 0 FP, F1=1.000
- PCI-DSS vertical (20 prompts): 16/16 attacks, 0 FP, F1=1.000

**Audit chain:** 7/7 properties PASS · Ed25519 mean 0.161ms signing latency at N=1000

Built on [Lobster Trap](https://github.com/veeainc/lobstertrap) (Veea).
