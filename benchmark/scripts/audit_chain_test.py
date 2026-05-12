#!/usr/bin/env python3
"""
SOUF AI Audit Chain Property Test Suite
Six formally-specified properties, N=1000 statistical runs where applicable.
Bootstrap CIs: n_boot=1000, alpha=0.05, seed=42.
Exit code 0 = all PASS; 1 = any FAIL.
"""

from __future__ import annotations

import copy
import json
import math
import os
import random
import statistics
import sys
import time

import numpy as np
from nacl.signing import SigningKey

sys.path.insert(0, os.path.dirname(__file__))
from audit_chain import AuditChain, GENESIS_HASH, canonical

RNG = random.Random(42)
NP_RNG = np.random.default_rng(42)
N_STAT = 1000
LATENCY_TARGET_MS = 1.0
RESULTS: list[dict] = []


def _boot_ci(data: list[float], n_boot: int = 1000, alpha: float = 0.05) -> tuple[float, float]:
    arr = np.array(data)
    means = [np.mean(NP_RNG.choice(arr, size=len(arr), replace=True)) for _ in range(n_boot)]
    lo = float(np.percentile(means, 100 * alpha / 2))
    hi = float(np.percentile(means, 100 * (1 - alpha / 2)))
    return lo, hi


def record(name: str, passed: bool, detail: str = ""):
    status = "PASS" if passed else "FAIL"
    RESULTS.append({"property": name, "status": status, "detail": detail})
    marker = "✓" if passed else "✗"
    print(f"  {marker} [{status}] {name}", flush=True)
    if detail:
        print(f"        {detail}", flush=True)


# ── P1: JCS determinism ────────────────────────────────────────────────────
def test_p1_jcs_determinism():
    entries = [
        {"action": "DENY", "rule": "block_pii_request", "risk_score": 0.72},
        {"action": "ALLOW", "rule": None, "metadata": {"k": [1, 2, 3]}},
        {"unicode": "日本語", "nested": {"a": 1, "b": 2}},
    ]
    ok = True
    for entry in entries:
        c1 = canonical(entry)
        c2 = canonical(entry)
        if c1 != c2:
            ok = False
            break
    # Keys must be sorted
    obj = {"z": 1, "a": 2, "m": 3}
    c = canonical(obj).decode()
    if not (c.index('"a"') < c.index('"m"') < c.index('"z"')):
        ok = False
    record("P1 JCS determinism", ok,
           f"canonical(X)==canonical(X) for {len(entries)} distinct entries; key-order verified")


# ── P2: Sign + verify round-trip ───────────────────────────────────────────
def test_p2_sign_verify_rt():
    chain = AuditChain()
    entries = [{"action": "DENY", "prompt": f"test_{i}", "risk": RNG.random()} for i in range(50)]
    for e in entries:
        chain.append(e)
    ok = chain.verify_chain()
    record("P2 sign+verify round-trip", ok,
           f"verify_chain() on {len(entries)}-record chain → {'True' if ok else 'FALSE'}")


# ── P3: Tamper detection — decision field ──────────────────────────────────
def test_p3_tamper_decision():
    chain = AuditChain()
    rec = chain.append({"action": "DENY", "rule": "block_pii_request", "risk": 0.8})
    # Mutate action: DENY → ALLOW
    tampered = copy.deepcopy(rec)
    tampered.entry["action"] = "ALLOW"
    detected = not tampered.verify(chain.verify_key)
    record("P3 tamper detection — decision field", detected,
           f"mutate entry.action DENY→ALLOW → verify()={'False (tamper caught)' if detected else 'TRUE (FAIL)'}")


# ── P4: Tamper detection — signature bytes ─────────────────────────────────
def test_p4_tamper_sig_bytes():
    chain = AuditChain()
    rec = chain.append({"action": "LOG", "rule": "pci_log_all_data_access"})
    sig_bytes = bytearray(rec.signature)
    sig_bytes[0] ^= 0xFF  # flip first byte
    tampered = copy.copy(rec)
    tampered.signature = bytes(sig_bytes)
    detected = not tampered.verify(chain.verify_key)
    record("P4 tamper detection — signature bytes", detected,
           f"flip sig[0] → verify()={'False (tamper caught)' if detected else 'TRUE (FAIL)'}")


# ── P5: Wrong-key rejection ─────────────────────────────────────────────────
def test_p5_wrong_key_reject():
    chain_a = AuditChain()
    chain_b = AuditChain()  # different key
    rec = chain_a.append({"action": "DENY", "rule": "block_injection"})
    rejected = not rec.verify(chain_b.verify_key)
    record("P5 wrong-key rejection", rejected,
           f"sign with keyA, verify with keyB.vk → rejected={'True' if rejected else 'FALSE'}")


# ── P6: Signing latency @ N=1000 ───────────────────────────────────────────
def test_p6_signing_latency():
    chain = AuditChain()
    entry_template = {"action": "DENY", "rule": "block_pii_request",
                      "risk_score": 0.72, "prompt": "x" * 200}
    latencies_ms: list[float] = []
    for i in range(N_STAT):
        entry = {**entry_template, "seq": i}
        t0 = time.perf_counter()
        chain.append(entry)
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    mean_ms = statistics.mean(latencies_ms)
    p50_ms = statistics.median(latencies_ms)
    p99_ms = float(np.percentile(latencies_ms, 99))
    lo, hi = _boot_ci(latencies_ms)
    passed = mean_ms < LATENCY_TARGET_MS
    record("P6 signing latency @ N=1000", passed,
           f"mean={mean_ms:.4f}ms  p50={p50_ms:.4f}ms  p99={p99_ms:.4f}ms  "
           f"95%CI=[{lo:.4f},{hi:.4f}]ms  target<{LATENCY_TARGET_MS}ms")


# ── P7: Chain integrity — append-only detection ─────────────────────────────
def test_p7_chain_integrity():
    """Inserting a record in the middle breaks the prev_hash chain → verify_chain() returns False."""
    chain = AuditChain()
    for i in range(5):
        chain.append({"action": "LOG", "seq": i})
    # Inject a spurious record between positions 2 and 3
    recs = chain.records()
    from audit_chain import SignedRecord, sha256hex
    fake_entry = {"action": "ALLOW", "injected": True}
    fake_prev = recs[1].record_hash
    # Sign with the chain's own key so it passes individual verify — only prev_hash chain breaks
    import json as _json
    from audit_chain import canonical as _canon
    payload = _canon({"entry": fake_entry, "prev_hash": fake_prev, "seq": 99})
    sig = chain.signing_key.sign(payload, encoder=__import__("nacl.encoding", fromlist=["RawEncoder"]).RawEncoder).signature
    fake = SignedRecord(
        entry=fake_entry, prev_hash=fake_prev, seq=99,
        signature=sig, record_hash=sha256hex(payload)
    )
    # Manually splice into chain
    chain._records.insert(2, fake)
    # Rechain: records[2].prev_hash != records[1].record_hash ← only if prev_hash stored separately
    # Actually, because rec[2] (original) has prev_hash = rec[1].record_hash which is now displaced,
    # the chain walk will see records[2] (fake) prev_hash == records[1].record_hash OK,
    # but records[3] (original seq=2) prev_hash == original records[2].record_hash != fake.record_hash → break
    broken = not chain.verify_chain()
    record("P7 chain integrity — splice detection", broken,
           f"splice injected record at pos 2 → verify_chain()={'False (detected)' if broken else 'TRUE (FAIL)'}")


# ── Main ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("SOUF AI Audit Chain Property Test Suite")
    print(f"  N_stat={N_STAT}  latency_target<{LATENCY_TARGET_MS}ms  CI α=0.05  seed=42")
    print("=" * 60)

    test_p1_jcs_determinism()
    test_p2_sign_verify_rt()
    test_p3_tamper_decision()
    test_p4_tamper_sig_bytes()
    test_p5_wrong_key_reject()
    test_p6_signing_latency()
    test_p7_chain_integrity()

    print("=" * 60)
    passed = sum(1 for r in RESULTS if r["status"] == "PASS")
    total = len(RESULTS)
    print(f"Result: {passed}/{total} properties PASS")

    out_path = os.path.join(os.path.dirname(__file__), "..", "results",
                            "audit_chain_properties_20260512.json")
    with open(out_path, "w") as f:
        json.dump({
            "suite": "SOUF AI Audit Chain Property Tests",
            "date": "2026-05-12",
            "n_stat": N_STAT,
            "latency_target_ms": LATENCY_TARGET_MS,
            "results": RESULTS,
            "summary": {"passed": passed, "total": total}
        }, f, indent=2)
    print(f"Report: {out_path}")

    sys.exit(0 if passed == total else 1)
