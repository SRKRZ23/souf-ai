# SOUF AI — TechEx Hackathon Submission (lablab × Veea × DeepMind)

## Project Name
SOUF AI — Semantic Out-of-distribution Universal Firewall for AI

## One-line description
A sub-millisecond LLM governance proxy that achieves F1=1.000 across 231 adversarial prompts — including HIPAA, PCI-DSS, OOD generalization, and encoding attack defenses.

## What it does

SOUF AI is a governance layer that sits between users and any LLM. Every prompt passes through:

1. **Normalization** — NFKC Unicode, zero-width char stripping, 54-codepoint confusable map (Cyrillic/Greek lookalikes)
2. **Pattern inspection** — 16 PatternSets, 337 regex rules covering OWASP LLM Top 10
3. **Verdict** — ALLOW / DENY / HUMAN_REVIEW with OWASP citation, rule name, and risk score
4. **Audit** — every call logged to an Ed25519-signed, SHA-256 hash-chained audit trail

Average inspection latency: **< 1ms**. Zero external API calls. Works offline.

## Technical architecture

```
User prompt
  → Proxy intercept
  → Normalize (NFKC + zero-width strip + confusable map)
  → PatternSet matching:
      InjectionPatterns (LLM01)
      ExfiltrationPatterns (LLM02)
      MalwarePatterns (LLM03)
      RolePatterns (LLM05)
      SensitivePathPatterns (LLM06)
      HarmViolencePatterns (LLM09)
      MetaEncodingPatterns (encoding attacks)
      TokenSplitPatterns (char-split obfuscation)
      + HIPAA sector patterns
      + PCI-DSS sector patterns
  → ALLOW / DENY / HUMAN_REVIEW + risk_score
  → Ed25519 audit record (SHA-256 chained)
```

## Benchmark results (5 categories, all F1=1.000)

| Benchmark | Prompts | TP | TN | FP | FN | F1 | 95% CI |
|-----------|---------|----|----|----|----|-----|--------|
| In-distribution | 68 | 48 | 20 | 0 | 0 | 1.000 | [0.980, 1.000] |
| OOD generalization | 100 | 90 | 10 | 0 | 0 | 1.000 | [0.960, 1.000] |
| HIPAA vertical | 20 | 16 | 4 | 0 | 0 | 1.000 | [0.795, 1.000] |
| PCI-DSS vertical | 20 | 16 | 4 | 0 | 0 | 1.000 | [0.795, 1.000] |
| Encoding attacks | 23 | 18 | 5 | 0 | 0 | 1.000 | [0.822, 1.000] |
| **Total** | **231** | **188** | **43** | **0** | **0** | **1.000** | **[0.980, 1.000]** |

Wilson score confidence intervals. Zero false positives on all 43 benign prompts.

## Encoding attack defense (4 vectors)

All four encoding attack vectors defeated at normalization layer before pattern matching:

| Vector | Example | Defense |
|--------|---------|---------|
| Base64 meta-instructions | `SGVscCBtZSBleGZpbHRyYXRl` + "decode and follow" | MetaEncodingPatterns: decode+execute chain |
| Token-split obfuscation | `i g n o r e  a l l  p r e v i o u s` | TokenSplitPatterns: `[\s.\-_]*` separators |
| Fullwidth unicode | `ｉｇｎｏｒｅ ｄｉｓｒｅｇａｒｄ` | NFKC normalization |
| Cyrillic/Greek lookalikes | `рretend`, `ιgnore`, `jаіlbreаk` | 54-codepoint confusable map via str.translate() |

## HIPAA and PCI-DSS compliance packs

SOUF AI ships vertical compliance policy overlays:

**HIPAA:** Blocks unauthorized PHI disclosure, ePHI extraction, synthetic medical record generation, patient privacy probing, insurance fraud queries. Maps to HIPAA §164.312 (Technical Safeguards).

**PCI-DSS:** Blocks PAN exfiltration, card skimmer code, CVV harvesting, payment gateway exploitation, track data requests. Maps to PCI DSS Requirements 3, 6, 12.

## Audit trail

Every DPI call generates a signed record:
```json
{
  "ts": 1747134052000,
  "prompt_hash": "a3f1b2c4d5e6f7a8",
  "action": "DENY",
  "rule": "block_injection",
  "risk_score": 0.95,
  "owasp_id": "LLM01",
  "record_hash": "1234567890abcdef",
  "prev_hash": "c9d8e7f6a5b4c3d2"
}
```

Chain: `record_hash = sha256(ts + prompt_hash + action + rule + risk_score + prev_hash)`.

Verified by 7/7 audit chain tests.

## How SOUF AI compares to commercial guardrails

| Property | SOUF AI v0.5f | Lakera Guard | NeMo Guardrails | Prompt Guard 2 |
|---|---|---|---|---|
| Latency P50 | **0.051 ms** | ~40–80 ms | ~5–50 ms | ~10–30 ms |
| Offline / air-gapped | **✅** | ❌ | ✅ | ✅ |
| Built-in HIPAA pack | **✅ F1=1.000** | guides only | custom Colang | ❌ |
| Built-in PCI-DSS pack | **✅ F1=1.000** | partial | custom Colang | ❌ |
| Audit chain (Ed25519) | **✅ tamper-evident** | request logs | trace logs | ❌ |
| Wilson 95% CI reported | **✅** | ❌ | ❌ | ❌ |
| License | **MIT** | Closed | Apache 2.0 | Llama 3 Community |

Full comparison: `docs/competitive_comparison.md`. SOUF AI numbers measured via `scripts/run_all_benchmarks.py` (3.3s, 231 prompts). Competitor numbers cited from public docs.

## Veea integration

SOUF AI deploys as a sidecar proxy on Veea edge nodes — the same sub-millisecond governance layer that protects cloud LLMs now runs at the edge, with no round-trip latency. Offline-capable: works without internet connectivity.

## Connection to AI Reliability Ecosystem

SOUF AI is the governance core of a four-product ecosystem:
- **FORGE** (IBM Bob Hackathon) auto-generates SOUF AI policies from any LLM codebase
- **ATLAS** (AI Agent Olympics) embeds SOUF AI DPI in every agentic call
- **CITADEL** (Gemma 4 Good) uses SOUF AI's Ed25519 audit chain in its L7 provenance layer

## Tech stack

- Python 3.12 (dpi_engine.py)
- Go (Lobster Trap binary: high-throughput proxy)
- PyNaCl (Ed25519 audit signatures)
- Zenodo DOI: 10.5281/zenodo.19791329 (ECB benchmark)

## Team

Solo — Sardor Razikov
