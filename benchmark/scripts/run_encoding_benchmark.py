"""
SOUF AI Benchmark #5 — Adversarial Encoding Attacks.

Runs encoding_attacks.json against the Python DPI engine (dpi_engine.py)
which includes v0.5d defences:
  - NFKC Unicode normalization (catches fullwidth Latin variants)
  - MetaEncodingPatterns (decode+execute meta-attacks)
  - TokenSplitPatterns (char-split obfuscation)

Note: The Go binary (lobstertrap) is NOT used here because encoding defences
are implemented in the Python proxy layer. Results represent the full proxy
capability when using dpi_engine.py as the inspection backend.
"""
import json
import os
import sys
import time
from pathlib import Path
from collections import defaultdict
import math

ROOT = Path(__file__).resolve().parents[2]
BENCH_DATA = ROOT / "benchmark" / "data" / "encoding_attacks.json"
RESULTS_DIR = ROOT / "benchmark" / "results"
sys.path.insert(0, str(ROOT / "demo"))

import dpi_engine as dpi


def run_benchmark() -> dict:
    with open(BENCH_DATA) as f:
        data = json.load(f)

    prompts = data["prompts"]
    results = []
    per_cat = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

    for p in prompts:
        text = p["prompt"]
        expected = p["expected_verdict"]

        meta = dpi.inspect(text)
        decision = dpi.evaluate(meta, mode="base")
        actual = decision.action  # ALLOW / DENY / HUMAN_REVIEW

        # normalise HUMAN_REVIEW → DENY for F1 calculation
        pred_deny = actual in ("DENY", "HUMAN_REVIEW")
        want_deny = expected == "DENY"
        cat = p["category"]

        if want_deny and pred_deny:
            outcome = "TP"
            per_cat[cat]["tp"] += 1
        elif not want_deny and pred_deny:
            outcome = "FP"
            per_cat[cat]["fp"] += 1
        elif want_deny and not pred_deny:
            outcome = "FN"
            per_cat[cat]["fn"] += 1
        else:
            outcome = "TN"
            per_cat[cat]["tn"] += 1

        results.append({
            "id": p["id"],
            "category": cat,
            "expected": expected,
            "actual": actual,
            "outcome": outcome,
            "rule": decision.rule,
            "signals": {
                "meta_encoding": meta.contains_meta_encoding,
                "token_split": meta.contains_token_split_attack,
                "injection": meta.contains_injection_patterns,
                "risk_score": round(meta.risk_score, 3),
            },
        })

    # aggregate
    all_attacks = [r for r in results if r["expected"] == "DENY"]
    all_benign = [r for r in results if r["expected"] == "ALLOW"]
    tp = sum(1 for r in all_attacks if r["outcome"] == "TP")
    fn = sum(1 for r in all_attacks if r["outcome"] == "FN")
    fp = sum(1 for r in all_benign if r["outcome"] == "FP")
    tn = sum(1 for r in all_benign if r["outcome"] == "TN")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    per_cat_summary = {}
    for cat, counts in per_cat.items():
        t = counts["tp"]; f = counts["fn"]
        total = t + f + counts["fp"] + counts["tn"]
        block = t + counts["fp"]
        per_cat_summary[cat] = {
            "total": total, "tp": t, "fn": f, "fp": counts["fp"], "tn": counts["tn"],
            "block_rate": round(t / (t + f), 4) if (t + f) > 0 else None,
        }

    return {
        "benchmark": "encoding_attacks",
        "version": data["version"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "engine": "dpi_engine.py v0.5d (Python)",
        "n_attacks": len(all_attacks),
        "n_benign":  len(all_benign),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "attack_block_rate": round(tp / len(all_attacks), 4) if all_attacks else 0,
        "fp_rate": round(fp / len(all_benign), 4) if all_benign else 0,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "per_category": per_cat_summary,
        "false_negatives": [r for r in results if r["outcome"] == "FN"],
        "false_positives": [r for r in results if r["outcome"] == "FP"],
        "all_results": results,
    }


def print_report(r: dict) -> None:
    print("\n" + "═" * 60)
    print("  SOUF AI Benchmark #5 — Adversarial Encoding Attacks")
    print("═" * 60)
    print(f"  Engine : {r['engine']}")
    print(f"  Attacks: {r['n_attacks']}  Benign: {r['n_benign']}")
    print()
    print(f"  Block rate (attacks) : {r['tp']}/{r['n_attacks']} = {r['attack_block_rate']*100:.1f}%")
    print(f"  False positives      : {r['fp']}/{r['n_benign']} = {r['fp_rate']*100:.1f}%")
    print(f"  Precision / Recall   : {r['precision']:.3f} / {r['recall']:.3f}")
    print(f"  F1                   : {r['f1']:.3f}")
    print()
    print("  Per-category breakdown:")
    print(f"  {'Category':<25} {'TP':>4} {'FN':>4} {'FP':>4} {'Block%':>8}")
    print("  " + "-" * 48)
    for cat, s in r["per_category"].items():
        br = f"{s['block_rate']*100:.0f}%" if s["block_rate"] is not None else "n/a (benign)"
        print(f"  {cat:<25} {s['tp']:>4} {s['fn']:>4} {s['fp']:>4} {br:>8}")

    if r["false_negatives"]:
        print(f"\n  False negatives ({len(r['false_negatives'])}):")
        for fn in r["false_negatives"]:
            print(f"    [{fn['id']}] {fn['category']} — rule: {fn['rule']}")
    if r["false_positives"]:
        print(f"\n  False positives ({len(r['false_positives'])}):")
        for fp in r["false_positives"]:
            print(f"    [{fp['id']}] {fp['category']}")
    print("═" * 60)


if __name__ == "__main__":
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report = run_benchmark()
    print_report(report)

    out = RESULTS_DIR / f"encoding_benchmark_{report['timestamp'].replace(':', '-')}.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Results saved → {out.name}\n")
