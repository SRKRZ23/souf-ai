# SOUF AI · Out-of-Distribution Validation Plan (Day 2)

## Why this exists

Day 1's headline number (**100% block rate, F1 = 1.0**) is an **in-distribution** measurement. The detector patterns in `upstream-pr/patches/internal_inspector_patterns_PATCHED.go` were written iteratively while reading the 68 prompts in `benchmark/data/attack_prompts.json`. There is non-trivial test-on-train risk: patterns may match the exact phrasing rather than the underlying threat semantics.

A defensible "general-purpose detector" claim requires an **out-of-distribution (OOD) test set** — adversarial prompts the patterns have not been exposed to during authoring. This document specifies the Day 2 OOD evaluation protocol.

## Held-out OOD test sources

Three public adversarial corpora, sampled **without** opening the source prompt text in the IDE during pattern authoring:

| Source | URL / dataset | Sample size | Categories covered |
|---|---|---|---|
| **garak** (NVIDIA red-team tool) | github.com/leondz/garak | 30 prompts across 10 probes | prompt injection, encoding evasion, persona leak, system prompt extraction |
| **HarmBench** | harmbench.org · arXiv 2402.04249 | 30 prompts | violence, cybercrime, misinformation, harassment |
| **AdvBench** | github.com/llm-attacks/llm-attacks | 30 prompts | harmful behaviors, illegal advice, autonomy attacks |

Sample procedure (Day 2):
1. Use the dataset's published test split (not the train / dev split). For HarmBench: the held-out behaviors track. For garak: the canonical `probe` registry. For AdvBench: rows 200-299 (latter half, less likely to overlap public examples in detector training data).
2. Sample **30 prompts per source** stratified by category to match the SOUF AI v0.1 benchmark category distribution.
3. Augment with **10 benign prompts** drawn from public chat-completion benchmarks (LMSys-Chat-1M held-out slice) to measure FP rate on OOD-benign.

Total OOD test set: ~100 prompts (90 attack + 10 benign).

## Metrics to report

1. **Block rate on OOD attack subset**: TP / (TP + FN). Compute bootstrap 95% CI over 1000 resamples.
2. **Precision on OOD set**: TP / (TP + FP).
3. **Per-source breakdown** (garak vs HarmBench vs AdvBench): does the detector generalize across corpora, or did Day 1 patterns overfit to the SOUF v0.1 self-curated prompts?
4. **Category-level drift**: which OWASP-LLM categories show the largest in-distribution vs OOD gap?
5. **OOD false-positive rate on benign**: should remain at 0%; an FP would indicate over-aggressive pattern broadening in Day 1 v0.2.

## Expected outcome

Honest forecast based on the Day 1 work:

| Metric | In-distribution (v0.1 benchmark) | OOD forecast (Day 2 prediction) |
|---|---|---|
| Block rate on attacks | 100% (48/48) | 65-85% (expected drop from in-distribution to OOD) |
| Precision | 1.000 | 0.95-1.0 (some overfit-induced false positives possible) |
| F1 | 1.0 | 0.80-0.92 |

A Day 2 OOD block rate above **75%** would be a strong signal that the patterns generalize. Below **60%** would indicate significant in-distribution overfit and require a rewrite to focus on threat-class semantic invariants rather than surface phrasing.

## Acceptance criteria for shipping

- **Strong (acceptable for paper)**: OOD block rate ≥ 75%, precision ≥ 0.95, FP-on-benign ≤ 5%.
- **Borderline (ship but flag)**: OOD block rate 60-75%, precision 0.90-0.95. Paper notes generalization gap, frames Day 1 patterns as starting point.
- **Failed (rework needed)**: OOD block rate < 60% OR precision < 0.90 OR FP-on-benign > 5%. Day 3 spent rewriting patterns to semantic invariants.

## Reproducibility

The OOD test prompts will ship at `benchmark/data/ood_test_prompts.json` with:
- Full prompt text
- Source attribution (garak / HarmBench / AdvBench + row identifier)
- Expected verdict (DENY / HUMAN_REVIEW / ALLOW)
- License compatibility note per source

Third parties can re-run via `benchmark/scripts/run_benchmark.py --data benchmark/data/ood_test_prompts.json`.

## Documentation impact

Once Day 2 OOD results land:
- README's headline table adds a row for OOD block rate + CI.
- Banner v0.3 displays both in-distribution and OOD numbers side-by-side.
- HIPAA pack doc adds an OOD-healthcare subset measurement.
- Paper draft has the OOD numbers as the central honest claim.

This is the discipline that separates a credible eval framework from a marketing exercise.
