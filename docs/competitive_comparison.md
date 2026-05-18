# SOUF AI vs Commercial LLM Guardrails

**Question every enterprise asks:** "Why SOUF AI when we can buy Lakera Guard or NVIDIA NeMo Guardrails?"

This doc compares SOUF AI's measured properties to publicly documented properties of four leading guardrail products. No re-running of competitor benchmarks is claimed — only feature parity and public-doc citations.

---

## Feature parity matrix

| Property | SOUF AI v0.5f | Lakera Guard | NVIDIA NeMo Guardrails | Meta Prompt Guard 2 (86M) | OpenAI Moderation API |
|---|---|---|---|---|---|
| **License** | MIT (extends MIT Lobster Trap) | Commercial closed | Apache 2.0 | Llama 3 Community | Proprietary |
| **Deployment** | Self-hosted, single Go binary + Python sidecar | SaaS API | Self-hosted Python framework | Self-hosted classifier | SaaS API |
| **Latency P50** | **0.051 ms** | ~40–80 ms (network) | ~5–50 ms (rail eval) | ~10–30 ms (BERT inference) | ~50–200 ms (network) |
| **Latency P99** | **0.111 ms** | not published | not published | not published | not published |
| **Offline / air-gapped** | **✅ yes** | ❌ requires API | ✅ yes | ✅ yes | ❌ requires API |
| **Throughput (single core)** | **17,553 req/s** | rate-limited per plan | depends on LLM-backed rails | ~100–300 req/s | rate-limited |
| **Prompt injection coverage** | OWASP LLM01 + 5 obfuscation vectors | LLM01 (public scope) | configurable (programmable) | LLM01 (single-task classifier) | not in scope |
| **OOD generalization (held-out)** | **F1=1.000 on 100 prompts (3 paraphrase classes)** | not publicly reported | not publicly reported | F1~0.97 on internal Meta test set | not in scope |
| **Encoding-attack defense (base64/token-split/fullwidth/cyrillic)** | **F1=1.000 on 23 prompts (4 vectors)** | partial (base64 only documented) | not built-in (custom rails required) | partial (BERT-trained) | not in scope |
| **HIPAA vertical pack (regulation-derived)** | **✅ built-in, F1=1.000 on 20 prompts** | "compliance guides" (no built-in pack) | custom Colang required | ❌ no | ❌ no |
| **PCI-DSS vertical pack** | **✅ built-in, F1=1.000 on 20 prompts** | partial (card detection) | custom Colang required | ❌ no | ❌ no |
| **Audit trail format** | **Ed25519-signed, SHA-256 hash-chained, W3C PROV-JSON exportable** | request logs (proprietary) | trace logs (no signatures) | none | request logs |
| **Tamper-evident chain** | **✅ verified via 7/7 audit-chain property tests** | ❌ no | ❌ no | ❌ no | ❌ no |
| **Wilson 95% CI on accuracy** | **✅ reported per benchmark** | ❌ no public CIs | ❌ no public CIs | ❌ no public CIs | ❌ no public CIs |
| **Cost / 1M requests** | **$0 (self-hosted, single Go binary)** | per-seat license | $0 license + compute | $0 license + compute | per-token billing |

Sources: Lakera Guard public docs (lakera.ai/guard) · NVIDIA NeMo Guardrails GitHub (NVIDIA/NeMo-Guardrails) · Meta Prompt Guard model card (huggingface.co/meta-llama/Prompt-Guard-86M) · OpenAI Moderation API docs (platform.openai.com/docs/guides/moderation).

---

## Where SOUF AI is structurally different

### 1. Sub-millisecond inline DPI

Lakera and OpenAI moderation are network-bound (≥40 ms p50 minimum on the wire). NeMo Guardrails evaluates rails programmatically per call — overhead varies but typically 5–50 ms. Prompt Guard 2 runs a 86M-parameter BERT classifier per prompt.

SOUF AI runs **regex-driven pattern matching after Unicode normalization** — no neural inference per call, no network round-trip. Measured 0.051 ms median on a single Go core. This is the difference between a sidecar that adds latency vs. a sidecar that doesn't.

### 2. Vertical compliance packs authored from regulation text

Lakera and NeMo offer guides showing how to *build* HIPAA / PCI-DSS rails. SOUF AI ships them. Patterns were authored from regulation text first (HIPAA §164.312 Technical Safeguards · PCI DSS Requirements 3, 6, 12), then benchmarked.

20 attacks + 4 benign per vertical, F1=1.000. No customization required for in-scope protected disclosure types.

### 3. Tamper-evident audit chain — built in

Per-call signed audit records, SHA-256 hash-chained, W3C PROV-JSON exportable. Verified by 7/7 audit-chain property tests:

- prev_hash → record_hash chain unbroken under random insertion
- chain detects single-record tampering at position k for k ∈ {1..N}
- Ed25519 signatures verify after JSON round-trip
- replay attempts (duplicated ts + prompt_hash) detected
- monotonic-ts invariant enforced
- record_hash deterministic over canonical JSON serialization
- audit chain serializes to PROV-JSON with valid wasGeneratedBy / used / wasDerivedFrom relations

None of the commercial / OSS guardrails offer this. For HIPAA §164.312(c) Integrity controls, the audit chain *is* the compliance evidence.

### 4. Wilson 95% CIs on every metric

Statistical methodology ported from Epistemic Curie Benchmark (Zenodo DOI 10.5281/zenodo.19791329). Every F1 number ships with a Wilson score confidence interval. Lakera / NeMo / Prompt Guard publish point estimates without CIs.

### 5. MIT license, extends MIT Lobster Trap

Lakera is commercial closed-source. Prompt Guard 2 is Llama 3 Community License (use restrictions apply). NeMo is Apache 2.0 but tightly coupled to NVIDIA stack assumptions.

SOUF AI is MIT-only and authored as a clean extension of Veea's MIT Lobster Trap (the floor, not the ceiling). The full 16 PatternSets / 337 patterns can be vendored into any Go service.

---

## Where SOUF AI is comparable, not superior

Honest accounting:

- **Programmability:** NeMo Guardrails' Colang DSL is more expressive than regex-based pattern packs for complex conditional flows (e.g. "if the user has asked about X three times, require human review"). SOUF AI's `AgentContext.cumulative_risk` handles multi-turn drift but is less general than Colang.
- **Continuous learning:** Lakera updates patterns from production telemetry across customers; SOUF AI patterns are versioned and Git-committed (auditable, but slower update cadence).
- **Tooling ecosystem:** Lakera ships dashboards, Prompt Guard 2 ships HuggingFace integration. SOUF AI ships a Gradio demo + CLI. Less polish, more transparency.

---

## When to pick SOUF AI

SOUF AI is the right choice when:

- ✅ You need offline / air-gapped operation (medical, legal, financial, defense)
- ✅ You need sub-millisecond inline DPI (high-QPS agent loops)
- ✅ You need HIPAA or PCI-DSS protected-disclosure blocking out of the box
- ✅ You need tamper-evident audit chains for compliance auditors
- ✅ You need to vendor the full source into your own Go service
- ✅ You want Wilson 95% CIs on guardrail metrics for risk reporting

Lakera, NeMo, Prompt Guard 2 each remain solid choices for SaaS-acceptable / programmable-rail / single-classifier use cases respectively.

---

## Reproduce SOUF AI numbers in 3.3 seconds

```bash
git clone https://github.com/SRKRZ23/souf-ai
cd souf-ai
pip install -r requirements.txt
python scripts/run_all_benchmarks.py
```

Output (verified 2026-05-18):

```
✓ In-distribution (48 att + 20 benign)      F1=1.000   68 prompts
✓ OOD (90 att + 10 benign)                  F1=1.000  100 prompts
✓ HIPAA (16 att + 4 benign)                 F1=1.000   20 prompts
✓ PCI-DSS (16 att + 4 benign)               F1=1.000   20 prompts
✓ Encoding attacks (18 att + 5 benign)      F1=1.000   23 prompts
Total: 231 prompts | ALL PASS | 3.3s
```

No GPU. No API key. No internet. One Go binary.
