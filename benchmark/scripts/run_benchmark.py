"""
SOUF AI Adversarial Benchmark — evaluation harness.

Runs each prompt through Lobster Trap inspector, captures verdict,
compares to expected, and computes:
- Per-category block rate
- Confusion matrix (TP/FP/FN/TN)
- Precision / Recall / F1 with bootstrap 95% CIs
- List of false negatives (gaps SOUF AI rule packs must close)
- List of false positives (overblocking risks)

Usage:
    python run_benchmark.py [--policy PATH] [--out PATH]

Defaults:
    --policy = lobstertrap default policy (configs/default_policy.yaml relative to LT_ROOT)
    --out    = ../results/benchmark_<timestamp>.json
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from random import Random

ROOT = Path(__file__).resolve().parents[2]
BENCH_DATA = ROOT / "benchmark" / "data" / "attack_prompts.json"
RESULTS_DIR = ROOT / "benchmark" / "results"
LT_ROOT = ROOT.parent / "external" / "lobstertrap"
LT_BIN = LT_ROOT / "lobstertrap"


def parse_inspect_output(stdout: str) -> dict:
    """Extract verdict + metadata from `lobstertrap inspect` stdout."""
    out = {"action": None, "rule": None, "message": None, "metadata": {}}

    # Action line
    m = re.search(r"Action:\s+(\w+)", stdout)
    if m:
        out["action"] = m.group(1)

    # Rule line
    m = re.search(r"Rule:\s+(\S+)", stdout)
    if m:
        out["rule"] = m.group(1)

    # Message line
    m = re.search(r"Message:\s+(.+)", stdout)
    if m:
        out["message"] = m.group(1).strip()

    # Metadata JSON block — first balanced {...} in the combined output
    m = re.search(r"(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", stdout, re.DOTALL)
    if m:
        try:
            out["metadata"] = json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    return out


def run_single(prompt_text: str, policy_path: str | None = None) -> dict:
    """Invoke lobstertrap inspect on a single prompt."""
    cmd = [str(LT_BIN), "inspect", prompt_text]
    if policy_path:
        cmd = [str(LT_BIN), "inspect", "--policy", policy_path, prompt_text]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=LT_ROOT,
        )
        # Lobster Trap writes JSON to stdout, formatted output (Action / Rule / Message) to stderr.
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        return parse_inspect_output(combined)
    except subprocess.TimeoutExpired:
        return {"action": "TIMEOUT", "rule": None, "message": "timeout", "metadata": {}}
    except Exception as e:
        return {"action": "ERROR", "rule": None, "message": str(e), "metadata": {}}


def verdict_match(expected: str, actual: str | None) -> bool:
    """Normalize: HUMAN_REVIEW maps to either HUMAN_REVIEW or DENY (both are blocks)."""
    if actual is None:
        return False
    if expected == actual:
        return True
    # HUMAN_REVIEW is treated as "block-ish" — DENY counts as match too
    if expected == "HUMAN_REVIEW" and actual == "DENY":
        return True
    return False


def is_block_verdict(action: str | None) -> bool:
    return action in ("DENY", "HUMAN_REVIEW", "QUARANTINE")


def is_expected_block(expected: str) -> bool:
    return expected in ("DENY", "HUMAN_REVIEW", "QUARANTINE")


def bootstrap_ci(samples: list[int], n_iter: int = 1000, alpha: float = 0.05, seed: int = 42) -> tuple[float, float, float]:
    """Bootstrap mean + 95% CI. samples are 0/1 indicators."""
    if not samples:
        return 0.0, 0.0, 0.0
    rng = Random(seed)
    n = len(samples)
    means = []
    for _ in range(n_iter):
        boot = [samples[rng.randrange(n)] for _ in range(n)]
        means.append(sum(boot) / n)
    means.sort()
    mean = sum(samples) / n
    lo = means[int(n_iter * alpha / 2)]
    hi = means[int(n_iter * (1 - alpha / 2))]
    return mean, lo, hi


def compute_metrics(results: list[dict]) -> dict:
    """Compute confusion matrix + precision/recall/F1 with bootstrap CIs."""
    tp = fp = fn = tn = 0
    correctness = []          # 1 if predicted correctly else 0
    block_correctness = []    # 1 if block-attack correct, else 0
    pass_correctness = []     # 1 if pass-benign correct, else 0

    for r in results:
        expected = r["expected_verdict"]
        actual = r["actual_action"]
        expected_block = is_expected_block(expected)
        actual_block = is_block_verdict(actual)

        if expected_block and actual_block:
            tp += 1
            block_correctness.append(1)
            correctness.append(1)
        elif expected_block and not actual_block:
            fn += 1
            block_correctness.append(0)
            correctness.append(0)
        elif (not expected_block) and actual_block:
            fp += 1
            pass_correctness.append(0)
            correctness.append(0)
        elif (not expected_block) and (not actual_block):
            tn += 1
            pass_correctness.append(1)
            correctness.append(1)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    accuracy_mean, accuracy_lo, accuracy_hi = bootstrap_ci(correctness)
    block_rate_mean, block_rate_lo, block_rate_hi = bootstrap_ci(block_correctness)
    false_pos_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": {"mean": accuracy_mean, "ci95_lo": accuracy_lo, "ci95_hi": accuracy_hi},
        "block_rate_on_attacks": {"mean": block_rate_mean, "ci95_lo": block_rate_lo, "ci95_hi": block_rate_hi},
        "false_positive_rate_on_benign": false_pos_rate,
    }


def compute_per_category(results: list[dict]) -> dict:
    by_cat = defaultdict(list)
    for r in results:
        by_cat[r["category"]].append(r)
    out = {}
    for cat, group in by_cat.items():
        expected_blocks = sum(1 for r in group if is_expected_block(r["expected_verdict"]))
        actual_blocks = sum(
            1 for r in group
            if is_expected_block(r["expected_verdict"]) and is_block_verdict(r["actual_action"])
        )
        out[cat] = {
            "n_prompts": len(group),
            "n_expected_block": expected_blocks,
            "n_actual_block": actual_blocks,
            "block_rate": (actual_blocks / expected_blocks) if expected_blocks else None,
        }
    return out


def compute_per_subset(results: list[dict]) -> dict:
    """Aggregate by subset/source field — used in OOD eval to break down by corpus origin."""
    by_subset = defaultdict(list)
    for r in results:
        key = r.get("subset") or r.get("source") or "unspecified"
        by_subset[key].append(r)
    out = {}
    for sub, group in by_subset.items():
        expected_blocks = sum(1 for r in group if is_expected_block(r["expected_verdict"]))
        actual_blocks = sum(
            1 for r in group
            if is_expected_block(r["expected_verdict"]) and is_block_verdict(r["actual_action"])
        )
        benign = sum(1 for r in group if not is_expected_block(r["expected_verdict"]))
        false_positives = sum(
            1 for r in group
            if (not is_expected_block(r["expected_verdict"])) and is_block_verdict(r["actual_action"])
        )
        out[sub] = {
            "n_prompts": len(group),
            "n_expected_block": expected_blocks,
            "n_actual_block": actual_blocks,
            "block_rate": (actual_blocks / expected_blocks) if expected_blocks else None,
            "n_benign": benign,
            "n_false_positives": false_positives,
            "false_positive_rate": (false_positives / benign) if benign else None,
        }
    return out


def main():
    parser = argparse.ArgumentParser(description="Run SOUF AI adversarial benchmark.")
    parser.add_argument("--policy", default=None, help="Path to policy YAML (default: Lobster Trap default)")
    parser.add_argument("--out", default=None, help="Output JSON path")
    parser.add_argument("--limit", type=int, default=None, help="Only run first N prompts (debug)")
    parser.add_argument("--data", default=None, help="Path to alternate prompt JSON (default: benchmark/data/attack_prompts.json)")
    args = parser.parse_args()

    data_path = Path(args.data) if args.data else BENCH_DATA

    if not LT_BIN.exists():
        print(f"ERROR: lobstertrap binary not found at {LT_BIN}", file=sys.stderr)
        print(f"Build it via: cd {LT_ROOT} && go build -o lobstertrap .", file=sys.stderr)
        sys.exit(1)

    with open(data_path) as f:
        bench = json.load(f)

    prompts = bench["prompts"]
    if args.limit:
        prompts = prompts[: args.limit]

    print(f"Running {len(prompts)} prompts through Lobster Trap...")
    print(f"  Binary: {LT_BIN}")
    print(f"  Data:   {data_path}")
    print(f"  Policy: {args.policy or 'default (configs/default_policy.yaml)'}")
    print()

    results = []
    t0 = time.time()
    for i, p in enumerate(prompts, 1):
        verdict = run_single(p["prompt"], args.policy)
        results.append({
            "id": p["id"],
            "category": p["category"],
            "subset": p.get("subset"),
            "source": p.get("source"),
            "prompt": p["prompt"],
            "expected_verdict": p["expected_verdict"],
            "actual_action": verdict["action"],
            "actual_rule": verdict["rule"],
            "actual_message": verdict["message"],
            "risk_score": verdict["metadata"].get("risk_score"),
            "intent_category": verdict["metadata"].get("intent_category"),
        })
        match = "✓" if verdict_match(p["expected_verdict"], verdict["action"]) else "✗"
        print(f"  [{i:3d}/{len(prompts)}] {match} {p['id']:8s} expected={p['expected_verdict']:13s} actual={verdict['action']}")

    elapsed = time.time() - t0
    print(f"\nElapsed: {elapsed:.1f}s ({elapsed/len(prompts)*1000:.0f}ms per prompt)")

    metrics = compute_metrics(results)
    per_cat = compute_per_category(results)
    per_sub = compute_per_subset(results)
    false_negatives = [r for r in results if is_expected_block(r["expected_verdict"]) and not is_block_verdict(r["actual_action"])]
    false_positives = [r for r in results if not is_expected_block(r["expected_verdict"]) and is_block_verdict(r["actual_action"])]

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "policy": args.policy or "default",
        "data_path": str(data_path),
        "n_prompts": len(results),
        "elapsed_seconds": round(elapsed, 1),
        "metrics": metrics,
        "per_category": per_cat,
        "per_subset": per_sub,
        "false_negatives": [{"id": r["id"], "category": r["category"], "subset": r.get("subset"), "prompt": r["prompt"], "actual_action": r["actual_action"]} for r in false_negatives],
        "false_positives": [{"id": r["id"], "category": r["category"], "subset": r.get("subset"), "prompt": r["prompt"], "actual_action": r["actual_action"], "actual_rule": r["actual_rule"]} for r in false_positives],
        "raw_results": results,
    }

    if not args.out:
        RESULTS_DIR.mkdir(exist_ok=True)
        args.out = RESULTS_DIR / f"benchmark_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print()
    print("=" * 60)
    print(f"Confusion matrix: TP={metrics['confusion_matrix']['tp']}  FP={metrics['confusion_matrix']['fp']}  FN={metrics['confusion_matrix']['fn']}  TN={metrics['confusion_matrix']['tn']}")
    print(f"Precision: {metrics['precision']:.3f}")
    print(f"Recall:    {metrics['recall']:.3f}")
    print(f"F1:        {metrics['f1']:.3f}")
    print(f"Accuracy:  {metrics['accuracy']['mean']:.3f}  (95% CI [{metrics['accuracy']['ci95_lo']:.3f}, {metrics['accuracy']['ci95_hi']:.3f}])")
    print(f"Block rate on attacks: {metrics['block_rate_on_attacks']['mean']:.3f}  (95% CI [{metrics['block_rate_on_attacks']['ci95_lo']:.3f}, {metrics['block_rate_on_attacks']['ci95_hi']:.3f}])")
    print(f"FP rate on benign:     {metrics['false_positive_rate_on_benign']:.3f}")
    print()
    print("Per-category block rate:")
    for cat, stats in sorted(per_cat.items()):
        rate = stats["block_rate"]
        rate_str = f"{rate:.0%}" if rate is not None else "N/A"
        print(f"  {cat:25s} {stats['n_actual_block']:2d}/{stats['n_expected_block']:2d}  ({rate_str})")
    print()
    if any(r.get("subset") for r in results):
        print("Per-subset breakdown:")
        for sub, stats in sorted(per_sub.items()):
            br = stats["block_rate"]
            br_str = f"{br:.0%}" if br is not None else "N/A"
            fpr = stats["false_positive_rate"]
            fpr_str = f"{fpr:.0%}" if fpr is not None else "N/A"
            print(f"  {sub:25s} block {stats['n_actual_block']:2d}/{stats['n_expected_block']:2d} ({br_str})  FP {stats['n_false_positives']}/{stats['n_benign']} ({fpr_str})")
        print()
    print(f"False negatives ({len(false_negatives)}) — gaps SOUF AI must close:")
    for r in false_negatives[:10]:
        print(f"  {r['id']:8s} [{r['category']}] {r['prompt'][:70]}...")
    if len(false_negatives) > 10:
        print(f"  ... and {len(false_negatives) - 10} more (see {args.out})")
    print()
    if false_positives:
        print(f"False positives ({len(false_positives)}) — overblocking risks:")
        for r in false_positives:
            print(f"  {r['id']:8s} [{r['category']}] {r['prompt'][:70]}... → blocked by rule '{r['actual_rule']}'")
    print()
    print(f"Full report: {args.out}")


if __name__ == "__main__":
    main()
