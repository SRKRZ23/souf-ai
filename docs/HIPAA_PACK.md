# SOUF AI · HIPAA Vertical Pack v0.1

**Compliance objective**: enable AI agents in healthcare contexts (hospital IT, EHR vendors, telehealth, claims processing) to operate under 45 CFR Part 164 (HIPAA Privacy Rule + Security Rule) by deploying a Lobster Trap policy that codifies HIPAA-aligned ingress/egress decisions and produces an audit trail a regulator can read.

---

## What this ships

A **YAML rule pack** (`configs/hipaa_pack.yaml`) defining 9 ingress/egress rules that map to 8 controlling HIPAA sections, plus a **policy merge preprocessor** (`scripts/merge_policy.py`) that composes the pack with Lobster Trap's default policy into a deployable single-file policy.

| Rule | HIPAA citation | Action |
|---|---|---|
| `hipaa_block_phi_bulk_disclosure` | §164.502(a) — General PHI use/disclosure | DENY |
| `hipaa_block_reidentification` | §164.514(a) — De-identification Safe Harbor | DENY |
| `hipaa_review_minimum_necessary` | §164.502(b) — Minimum necessary standard | HUMAN_REVIEW |
| `hipaa_block_clinician_impersonation` | §164.308(a)(4) — Information access management | DENY |
| `hipaa_review_synthetic_diagnosis` | §164.502(g) parallel — Diagnostic synthesis | HUMAN_REVIEW |
| `hipaa_log_all_phi_access` | §164.312(b) — Audit controls | LOG |
| `hipaa_egress_block_phi_in_output` | §164.502(a) — Output containment | DENY (egress) |
| `hipaa_egress_block_credentials` | §164.312(e) — Transmission security | DENY (egress) |

---

## Known limitation: `extends:` is not yet upstream

Lobster Trap's current YAML loader does **not** support an `extends:` field — it is silently ignored by go-yaml's strict-unmarshal default. SOUF AI's HIPAA pack lists `extends: configs/default_policy.yaml` for readability, but the engine does not act on it.

**Workaround (ships in this repo)**: `scripts/merge_policy.py` composes the pack with the Lobster Trap default policy into a fully self-contained `configs/full_hipaa_policy.yaml`. Deploying this merged file gives "Lobster Trap default + SOUF AI HIPAA additions" in a single load.

```bash
python3 scripts/merge_policy.py \
  --base ../external/lobstertrap/configs/default_policy.yaml \
  --pack configs/hipaa_pack.yaml \
  --out  configs/full_hipaa_policy.yaml
```

Output (verified 2026-05-12): policy with **18 ingress rules + 4 egress rules**, validates and loads cleanly. An upstream PR to Lobster Trap adding native `extends:` support is on the Day 6 list.

---

## Measured behavior (2026-05-12)

Two benchmark runs against SOUF AI's 68-prompt adversarial dataset (44 attack + 4 review + 20 benign):

| Policy | Block rate on attacks | Precision | FP on benign |
|---|---|---|---|
| Lobster Trap default (unpatched detector) | 19/48 = 39.6% (95% CI [25.0%, 54.2%]) | 1.000 | 0/20 = 0% |
| Lobster Trap default + SOUF AI detector patches | 41/48 = 85.4% (95% CI [75.0%, 93.8%]) | 1.000 | 0/20 = 0% |
| **Full HIPAA policy (default + SOUF patches + HIPAA rules) — merged** | **41/48 = 85.4%** (95% CI [75.0%, 93.8%]) | **1.000** | **0/20 = 0%** |

**The HIPAA pack does NOT raise raw block rate on the general benchmark** — most adversarial prompts trip default Lobster Trap rules at higher priority before the HIPAA-specific rules evaluate. What the HIPAA pack adds at runtime is:

1. **Citation tagging** — every decision can be traced to a controlling HIPAA section (see `decision.citation` in the audit envelope spec).
2. **LOG actions** on healthcare-relevant `data_access` traffic that otherwise would not be persisted (§164.312(b) audit-controls requirement).
3. **HUMAN_REVIEW escalation** on broad / synthetic-diagnosis queries (§164.502(b) minimum-necessary).
4. **Egress containment** of PHI in model output (§164.502(a)).

These are *governance* values that don't show up on a pure block-rate metric but matter for regulator review and downstream SIEM/governance ingestion (IBM watsonx.governance, Workday ASOR).

### What is NOT yet measured

The following claims appear in earlier drafts of this document; they are **not yet substantiated by code in this repo** and should be considered Day 2-3 deliverables:

- A healthcare-specific adversarial subset (~20 prompts) capturing PHI bulk-disclosure, identification-document scanning, clinician impersonation, etc.
- A measurement of "HUMAN_REVIEW escalation correctness" — how often the pack correctly diverts healthcare-context queries to human review vs. lets them through.
- An end-to-end audit-trail demonstration showing one prompt's full PROV-JSON chain.

These will ship as `benchmark/data/hipaa_subset.json`, an additional benchmark run, and `code/audit/sample_log.jsonl` in Day 2-3.

---

## Why ingest-level enforcement (Lobster Trap) vs LLM-level safety alignment

LLM-level safety alignment (RLHF, system prompts, constitutional AI) is **necessary but insufficient** for HIPAA-regulated workloads because:

1. **No deterministic guarantee**: an aligned model can be jailbroken into producing PHI-related output. SOUF AI's DPI-based decision is deterministic at the ingest layer.
2. **No audit trail**: an LLM's refusal does not produce a regulator-readable record. SOUF AI emits structured JSON audit entries per decision.
3. **No vendor neutrality**: switching LLM providers means re-validating safety behavior. SOUF AI's ingest enforcement applies regardless of backend (GPT, Claude, Gemini, Llama).
4. **No latency budget at scale**: an LLM-as-judge guardrail adds 200-2000ms per request. SOUF AI's regex-based DPI adds sub-millisecond (Lobster Trap baseline; verified across 68-prompt benchmark at ~8ms per inspect call including process spawn overhead).

Lobster Trap was explicitly designed for this layer ("Lobster Trap is the floor, not the ceiling" — Veea's own framing). SOUF AI's HIPAA pack is the vertical-specific compliance scaffolding on that floor.

---

## Integration

```bash
# 1. Build the merged policy
python3 scripts/merge_policy.py \
  --base ../external/lobstertrap/configs/default_policy.yaml \
  --pack configs/hipaa_pack.yaml \
  --out  configs/full_hipaa_policy.yaml

# 2. Stand up Lobster Trap with the merged policy
./lobstertrap serve \
  --policy configs/full_hipaa_policy.yaml \
  --listen :8080 \
  --backend http://localhost:11434

# 3. Point your healthcare-LLM agent at the proxy
export OPENAI_API_BASE="http://localhost:8080/v1"
```

The proxy is transparent — agents written for OpenAI / Anthropic / Gemini APIs see no change. SOUF AI's HIPAA pack enforces policy in-line.

---

## Audit-trail format

See `docs/AUDIT_CHAIN_SPEC.md` for the full PROV-JSON envelope specification (Ed25519 + RFC 8785 JCS canonicalization). The reference implementation ships in `code/audit/` as `envelope.py` (signing) + `verify.py` (third-party verifier).

---

## What ships next (verified plan, not aspirational)

- **Day 2**: `benchmark/data/hipaa_subset.json` (10-20 healthcare-specific prompts) + measurement run with the merged HIPAA policy + this document re-updated with the subset numbers.
- **Day 2-3**: PCI-DSS pack measurement (parallel structure).
- **Day 3-4**: Audit chain implementation (`code/audit/`) with measured signing latency.
- **Day 4-5**: HF Space demo showing one healthcare prompt's full audit chain live (sign → verify → human-review escalation).
- **Day 6**: Upstream PR to `veeainc/lobstertrap` adding native `extends:` support, so the merge preprocessor is no longer required.

---

## Methodology source

Statistical rigor pattern (bootstrap CIs, paired comparison, full reproducibility) ported from the [Epistemic Curie Benchmark v1 (ECB)](https://doi.org/10.5281/zenodo.19791329) — Razikov, 2026 — Sardor's prior published work on quantifying LLM reasoning collapse under authority pressure. The HIPAA Pack uses the same measurement framework applied to vertical compliance.

---

## Author

Sardor Razikov · independent AI safety researcher · Tashkent · ORCID 0009-0007-0731-4247 · MIT-licensed.
