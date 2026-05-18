"""
SOUF AI — Master Benchmark Runner.
Runs all 5 benchmarks in sequence and prints a clean summary table.

Usage:
    python scripts/run_all_benchmarks.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "benchmark" / "scripts"
DATA = ROOT / "benchmark" / "data"


def run_benchmark(data_file: Path, policy: Path | None = None) -> dict:
    cmd = [sys.executable, str(SCRIPTS / "run_benchmark.py"), "--data", str(data_file)]
    if policy:
        cmd += ["--policy", str(policy)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    combined = r.stdout + r.stderr
    f1 = None
    for line in combined.splitlines():
        if line.strip().startswith("F1:"):
            try:
                f1 = float(line.split(":")[1].strip())
            except ValueError:
                pass
    # Get last results JSON
    results_dir = ROOT / "benchmark" / "results"
    jsons = sorted(results_dir.glob("benchmark_*.json"), key=lambda p: p.stat().st_mtime)
    n_prompts = 0
    if jsons:
        with open(jsons[-1]) as f:
            d = json.load(f)
        n_prompts = d.get("total_prompts", 0)
    return {"f1": f1, "n_prompts": n_prompts}


def run_encoding_benchmark() -> dict:
    cmd = [sys.executable, str(SCRIPTS / "run_encoding_benchmark.py")]
    r = subprocess.run(cmd, capture_output=True, text=True)
    combined = r.stdout + r.stderr
    f1 = None
    for line in combined.splitlines():
        if "F1" in line and ":" in line:
            try:
                f1 = float(line.split(":")[-1].strip())
            except ValueError:
                pass
    n = 23  # 18 attacks + 5 benign (fixed)
    return {"f1": f1, "n_prompts": n}


benchmarks = [
    ("In-distribution (48 att + 20 benign)", DATA / "attack_prompts.json", None,  68),
    ("OOD (90 att + 10 benign)",             DATA / "ood_test_prompts.json", None, 100),
    ("HIPAA (16 att + 4 benign)",             DATA / "hipaa_subset.json", None,    20),
    ("PCI-DSS (16 att + 4 benign)",           DATA / "pci_subset.json", None,      20),
]

print("\n" + "=" * 62)
print(" SOUF AI — All 5 Benchmarks")
print("=" * 62)

results = []
t0 = time.perf_counter()

for label, data_file, policy, n_known in benchmarks:
    sys.stdout.write(f"  Running: {label} ... ")
    sys.stdout.flush()
    r = run_benchmark(data_file, policy)
    f1_str = f"{r['f1']:.3f}" if r["f1"] is not None else "ERROR"
    n = n_known
    print(f"F1={f1_str}  ({n} prompts)")
    results.append((label, f1_str, n, r["f1"]))

sys.stdout.write(f"  Running: Encoding attacks (18 att + 5 benign) ... ")
sys.stdout.flush()
enc = run_encoding_benchmark()
enc_f1_str = f"{enc['f1']:.3f}" if enc["f1"] is not None else "ERROR"
print(f"F1={enc_f1_str}  ({enc['n_prompts']} prompts)")
results.append(("Encoding attacks (18 att + 5 benign)", enc_f1_str, enc["n_prompts"], enc["f1"]))

elapsed = time.perf_counter() - t0
total_prompts = sum(r[2] for r in results)
all_pass = all(r[3] == 1.0 for r in results if r[3] is not None)

print()
print(f"{'Benchmark':<42} {'F1':>6}  {'Prompts':>7}")
print("-" * 60)
for label, f1_str, n, _ in results:
    mark = "✓" if f1_str == "1.000" else "✗"
    print(f"  {mark} {label:<40} {f1_str:>6}  {n:>7}")
print("-" * 60)
print(f"  Total: {total_prompts} prompts  |  {'ALL PASS' if all_pass else 'FAILURES PRESENT'}  |  {elapsed:.1f}s")
print("=" * 62)

if not all_pass:
    sys.exit(1)
