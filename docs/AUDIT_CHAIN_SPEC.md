# SOUF AI · Signed Audit Chain (Pillar 4) — Specification v0.1

**Objective**: emit a tamper-evident, cryptographically-signed, replayable audit log entry for every Lobster Trap policy decision. The log is regulator-readable and survives third-party diligence.

Targets HIPAA §164.312(b), PCI-DSS Req 10, SR 11-7 model-inventory documentation, EU AI Act Art. 12 (logging requirements), ISO 42001 audit trail requirements — all with a single canonical format.

---

## Why

Per the painpoint matrix research:

- **JP Morgan (Pavan Gondhi)**: SR 11-7 exam finding #1 is "inadequate model inventory" — most LLM-agent decisions never enter a model-risk record. SOUF AI's audit chain produces a record per decision, automatically.
- **Hippocratic AI (Neha Manjunath)**: HIPAA §164.312(b) requires audit controls; Claude Cowork has zero audit-log coverage. SOUF AI fills this gap.
- **IBM watsonx (Ramakanta Samal)**: watsonx.governance expects auditable feeds from upstream guardrails. SOUF AI's audit chain feeds directly.
- **PayPal (Vishal Paul)**: PCI-DSS Req 10 requires tracking all access; agentic AI workflows currently have no scope-attestation record. SOUF AI provides one.

---

## Format

Each policy decision emits one **PROV-JSON envelope** (W3C PROV-O serialization), signed with **Ed25519** over the canonicalized payload (RFC 8785 JCS), one JSON object per line in an append-only file.

### Example entry

```json
{
  "@context": "https://www.w3.org/ns/prov",
  "envelope_id": "souf-ai-2026-05-12T16-47-00Z-3f8d2a",
  "version": "souf-audit-v0.1",

  "subject": {
    "agent_id": "epic-summarizer-v3",
    "agent_org": "regional-hospital-az",
    "session_id": "sess_2a91c4",
    "request_id": "req_3f8d4e2c"
  },

  "ingress": {
    "prompt_hash_sha256": "9f7a2e8b1c4d0f6e5a3b8c2d4f6e1a9c0d8b3f5e2a4c7d9b8f1e0c2a5d8b3f7e",
    "token_count": 287,
    "intent_category": "data_access",
    "intent_confidence": 0.74,
    "risk_score": 0.62,
    "detected": {
      "contains_pii_request": true,
      "contains_role_impersonation": false,
      "contains_exfiltration": false
    },
    "target_paths": [],
    "target_domains": [],
    "target_commands": []
  },

  "decision": {
    "policy_id": "souf-ai-hipaa-pack-v0.1",
    "rule": "hipaa_block_phi_bulk_disclosure",
    "action": "DENY",
    "citation": "45 CFR §164.502(a)",
    "deny_message": "[SOUF AI · HIPAA Pack] Blocked: bulk PHI disclosure request violates 45 CFR §164.502(a).",
    "decided_at_ms": 1736617620031
  },

  "provenance": {
    "engine": "lobstertrap-v1.0",
    "engine_commit_sha": "0c325ae...",
    "patches": "souf-ai-patterns-v0.1",
    "host": "souf-ai-edge-01"
  },

  "signature": {
    "alg": "Ed25519",
    "kid": "souf-ai-key-2026-05",
    "value": "base64url(Ed25519(JCS(payload_minus_signature_field)))"
  }
}
```

### Fields summary

| Field | Purpose |
|---|---|
| `envelope_id` | Globally unique per-decision identifier |
| `subject.agent_id` | Which AI agent made the request (deployment-side attribution) |
| `subject.request_id` | Traces back to original HTTP request |
| `ingress.prompt_hash_sha256` | One-way hash — preserves privacy + allows replay verification |
| `ingress.detected.*` | Booleans recovered from Lobster Trap DPI — drives decision reproducibility |
| `decision.rule` | Which SOUF AI / Lobster Trap rule fired |
| `decision.citation` | Controlling regulation (HIPAA §, PCI Req, EU AI Act Art., etc.) |
| `provenance.engine_commit_sha` | Exact Lobster Trap + SOUF AI version used |
| `signature` | Ed25519 over JCS-canonicalized payload (minus the signature field) |

---

## Properties

### 1. Replayable
Given `ingress.detected.*` + `policy_id`, re-running the policy engine produces the identical `decision.action` and `decision.rule`. No need to retain the prompt body — hash + extracted booleans is sufficient.

### 2. Tamper-evident
Ed25519 signature over JCS-canonicalized JSON. Any field modification breaks verification. Public verification key (`kid`) is published in the deployment's `.well-known/souf-audit-keys.json` endpoint.

### 3. Privacy-preserving
Prompt body never enters the log; only `sha256(prompt)`. Cardholder data, PHI, and credentials are never persisted in audit entries even when they triggered the decision.

### 4. Regulator-readable
Each entry maps cleanly to:
- **HIPAA §164.312(b)** — date/time, user identification, type of action, access to PHI
- **PCI-DSS Req 10.2** — user identification, type of event, date/time, success/failure, originating identity, affected data
- **SR 11-7** — model inventory entry per request, with engine-version provenance
- **EU AI Act Art. 12 §1** — automatic logging of high-risk AI system events

### 5. Compositional
Multiple SOUF AI packs (HIPAA + PCI + future SR 11-7) emit to the same audit stream. Downstream consumers (IBM watsonx.governance, Workday Agent System of Record, internal SOC) ingest with one schema.

---

## Implementation (Day 3-4 build target)

```
souf-ai/
└── code/
    └── audit/
        ├── envelope.py         # JCS canonicalization + Ed25519 signing
        ├── verify.py           # Standalone verifier (3rd-party reviewable)
        ├── schema.json         # JSON Schema draft 2020-12
        └── sample_log.jsonl    # 100-entry sample log for demo
```

Implementation requirements:
- **Python 3.10+** (matches Lobster Trap's deployment scenarios)
- **Pure-stdlib + `pynacl`** (Ed25519) + `python-rfc8785` (JCS canonicalization)
- **No network calls** during signing (offline-capable)
- **<5ms** signing latency per entry — preserves Lobster Trap's sub-millisecond DPI claim

---

## Integration with Lobster Trap

Lobster Trap already emits decision events to stdout / structured logger. SOUF AI's audit chain is a downstream consumer:

```
Lobster Trap DPI  →  Policy decision  →  SOUF AI audit envelope  →  signed jsonl  →  watsonx / ASOR / SIEM
```

No changes required to Lobster Trap. SOUF AI's `code/audit/wrap_audit.py` reads Lobster Trap's existing JSON event stream and emits signed envelopes.

---

## What ships (Day 1 — already in this repo)

- `code/audit/envelope.py` — RFC 8785 JCS canonicalization + Ed25519 signing reference implementation (pure-stdlib + PyNaCl, ~250 lines).
- `code/audit/verify.py` — standalone third-party verifier. Requires only PyNaCl + a published public key; no SOUF AI insider access.
- `code/audit/sample_log.jsonl` — 5-entry sample audit log demonstrating one healthcare agent's decisions across DENY (malware request), DENY (PHI bulk disclosure), DENY (clinician impersonation), ALLOW (legitimate clinical query), DENY (exfiltration).
- `code/audit/audit_keys/sample.pub.json` — public key for verifying the sample log.

## Measured properties (verified 2026-05-12 by self-tests in `envelope.py`)

| Property | Test | Result |
|---|---|---|
| JCS determinism (object key ordering) | Two dicts with same keys in different orders → identical bytes | ✓ Pass |
| Sign + verify roundtrip | Sign envelope → independent verifier accepts | ✓ Pass |
| Tamper detection (decision field) | Flip `decision.action` from DENY to ALLOW post-sign | ✓ Caught (signature invalid) |
| Tamper detection (signature bytes) | Modify final 2 chars of `signature.value` | ✓ Caught |
| Wrong-key rejection | Verify with different public key | ✓ Rejected |
| Signing latency at N=1000 | 1000 signing ops, measured wall-clock | **0.285 ms / op** |

Latency budget: well below the 5 ms target. SOUF AI's audit chain adds <0.3 ms per Lobster Trap policy decision; total ingest-to-audit latency stays in single-digit milliseconds.

## Verifier output (against the shipped sample log)

Clean log (5 entries):
```
line 1: ✓ souf-ai-06449171-...
line 2: ✓ souf-ai-3270ab1c-...
line 3: ✓ souf-ai-f7d3a71d-...
line 4: ✓ souf-ai-97b63008-...
line 5: ✓ souf-ai-d1cb15cf-...

verified 5 of 5 entries; 0 failed
```

Tampered log (one entry modified post-sign — `decision.action` changed from DENY to ALLOW):
```
line 1: ✗ signature invalid (souf-ai-06449171-...)
line 2: ✓ souf-ai-3270ab1c-...
...

verified 4 of 5 entries; 1 failed
```

The tampered entry is detected; the other entries (whose signatures were not modified) remain valid. This demonstrates the chain is **per-entry tamper-evident** — corruption of one record does not invalidate the rest.

## What ships next (Day 2-5)

- HF Space healthcare demo: each demo prompt's PROV-JSON audit entry signed live, verifier endpoint exposed.
- Public verifier key published at the demo's `/.well-known/souf-audit-keys.json`.
- 100-entry full demo log generated from real benchmark replay.
- Integration with Pillar 6 healthcare-vertical demo (Day 5-6 build).

---

## Author

Sardor Razikov · ORCID 0009-0007-0731-4247.

## License

MIT.
