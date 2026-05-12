"""
SOUF AI · standalone audit verifier.

Reads a `.jsonl` audit log + a public-key file, verifies every envelope's
Ed25519 signature, and prints a per-line result + summary. Third parties can
run this with only PyNaCl + the public key — no SOUF AI insider access.

Usage:
    python verify.py --log sample_log.jsonl --pubkey audit_keys/sample.pub.json

Public key file format (one line of JSON):
    {"kid": "souf-ai-key-2026-05", "alg": "Ed25519",
     "pubkey_b64u": "..."}
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from envelope import AuditVerifier  # type: ignore  # adjacent module


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a SOUF AI audit log.")
    parser.add_argument("--log", required=True, help="Path to .jsonl audit log")
    parser.add_argument("--pubkey", required=True, help="Path to public-key JSON file")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-line output")
    args = parser.parse_args()

    pk = json.loads(Path(args.pubkey).read_text())
    verifier = AuditVerifier.from_pubkey_b64u(pk["pubkey_b64u"], pk["kid"])

    total = ok = bad = 0
    with open(args.log) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                env = json.loads(line)
            except json.JSONDecodeError as e:
                bad += 1
                if not args.quiet:
                    print(f"line {i}: ✗ malformed JSON ({e})")
                continue
            if verifier.verify(env):
                ok += 1
                if not args.quiet:
                    print(f"line {i}: ✓ {env.get('envelope_id', '<no id>')}")
            else:
                bad += 1
                if not args.quiet:
                    print(f"line {i}: ✗ signature invalid ({env.get('envelope_id', '<no id>')})")

    print()
    print(f"verified {ok} of {total} entries; {bad} failed")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
