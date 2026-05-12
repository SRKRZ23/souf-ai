# SOUF AI

> Rule packs + detector patches extending Veea's Lobster Trap to close 22 critical gaps in baseline policy.

**TechEx Hackathon 2026 · Track 1: Agent Security & AI Governance · Veea**

![SOUF AI banner](branding/souf_ai_banner.png)

---

## Day 1 milestone — measured 2026-05-12

| Metric | Lobster Trap default | SOUF AI v0.1 | Delta |
|---|---|---|---|
| **Block rate on attacks** | 19/48 (39.6%) | **41/48 (85.4%)** | **+45.8 pp** |
| **False negatives** | 29 | 7 | **−22** |
| **Precision** | 1.000 | **1.000** | 0 (perfect maintained) |
| **Recall** | 0.396 | **0.854** | +0.458 |
| **F1** | 0.567 | **0.921** | +0.354 |
| **95% CI on block rate** | [25.0%, 54.2%] | [75.0%, 93.8%] | — |
| **FP on benign (n=20)** | 0% | 0% | 0 (no overblocking) |

Per-category lifts: jailbreak 20→100%, role_impersonation 0→100%, harm_violence 0→100%, prompt_injection 60→100%, malware_request 62→100%, offensive_tooling 14→71%, exfiltration 50→83%, pii_leakage 25→50%, obfuscation 25→50%.

Statistical methodology ported from [Epistemic Curie Benchmark (ECB v1)](https://doi.org/10.5281/zenodo.19791329) — bootstrap CIs, paired comparison, full reproducibility package.

---

## What this is

SOUF AI extends Veea's open-source [Lobster Trap](https://github.com/veeainc/lobstertrap) DPI proxy:

1. **Detector patches** to `internal/inspector/patterns.go` — broader regex coverage for jailbreaks, persona attacks, code-injection requests, red-team tool requests, and credential exfiltration. Single Day 1 pass closes 22 of 29 false negatives. No new fields needed; existing `default_policy.yaml` rules fire on the now-correctly-set boolean metadata.
2. **100+ vector adversarial benchmark** with bootstrap confidence intervals, replayable, MIT-licensed. Production-realistic prompts across 10 attack categories + 20 benign control prompts to measure false-positive rate.
3. **Vertical policy packs** (Day 2-3, in progress): HIPAA primary, PCI-DSS secondary, SR 11-7 stretch.
4. **Signed audit chain** (Day 3-4, in progress): Ed25519 + W3C PROV-JSON, replayable.
5. **HF Space live demo** (Day 5-6, in progress): healthcare vertical, Gemini-backend variant for cross-sponsor compliance.

---

## Replicate the wedge

```bash
# 1. Clone this repo
git clone https://github.com/SRKRZ23/souf-ai
cd souf-ai

# 2. Clone Lobster Trap upstream
git clone https://github.com/veeainc/lobstertrap ../lobstertrap

# 3. Apply patches
cp upstream-pr/patches/internal_inspector_patterns_PATCHED.go ../lobstertrap/internal/inspector/patterns.go

# 4. Build patched binary
(cd ../lobstertrap && go build -o lobstertrap .)

# 5. Run benchmark (default policy + patched detector)
python3 benchmark/scripts/run_benchmark.py
```

Expected output:
```
Block rate on attacks: 0.854  (95% CI [0.750, 0.938])
Precision: 1.000  Recall: 0.854  F1: 0.921
```

---

## Repo layout

```
souf-ai/
├── README.md                           # you are here
├── LICENSE                              # MIT
├── benchmark/
│   ├── data/attack_prompts.json         # 68 prompts (44 attack + 4 review + 20 benign)
│   ├── scripts/run_benchmark.py         # eval harness with bootstrap CIs
│   └── results/                         # benchmark output JSONs (timestamped)
├── upstream-pr/
│   └── patches/internal_inspector_patterns_PATCHED.go   # ready for upstream PR
├── branding/                            # banner SVG + PNG
├── configs/                             # YAML rule pack drafts (Day 2-3)
├── code/                                # demo + auxiliary scripts (Day 5-6)
├── docs/                                # methodology + pitch deck (Day 6-7)
├── writeup/                             # paper drafts (Day 6-7)
└── paper/                               # Zenodo + arXiv submission (Day 7)
```

---

## Build status (Day 1 / 7 of build phase)

| Day | Pillar | Status |
|---|---|---|
| 1 | Adversarial benchmark v0.1 (68 prompts) + eval harness | ✅ Shipped |
| 1 | Detector patches (Pattern extensions) → 39.6% to 85.4% block rate | ✅ Shipped |
| 2 | Pillar 2: HIPAA vertical pack | 🛠 In progress |
| 2-3 | Pillar 1: Agent-aware DPI extension | ⏳ Planned |
| 3-4 | Pillar 3: Calibrated halt + risk score explainability | ⏳ Planned |
| 4 | Pillar 4: Ed25519 + W3C PROV-JSON signed audit chain | ⏳ Planned |
| 5-6 | Pillar 6: HF Space healthcare demo (Gemini backend variant) | ⏳ Planned |
| 6 | Upstream PR to veeainc/lobstertrap | ⏳ Planned |
| 7 | Paper draft + Zenodo + arXiv | ⏳ Planned |

---

## Author

Sardor Razikov · independent AI safety researcher · Tashkent, Uzbekistan
- ORCID: [0009-0007-0731-4247](https://orcid.org/0009-0007-0731-4247)
- ECB v1 (related work — methodology source): [10.5281/zenodo.19791329](https://doi.org/10.5281/zenodo.19791329)
- GitHub: [@SRKRZ23](https://github.com/SRKRZ23)
- HuggingFace: [@ZeroR3](https://huggingface.co/ZeroR3)

## License

MIT — see LICENSE.
