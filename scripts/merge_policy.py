#!/usr/bin/env python3
"""
SOUF AI · Policy merge preprocessor.

Lobster Trap's YAML loader does not natively support an `extends:` field — it is
silently ignored by go-yaml. This script provides composable policies by merging
a base policy (e.g., Lobster Trap's default) with one or more SOUF AI vertical
packs into a single self-contained YAML file the engine can load.

Usage:
    python merge_policy.py \
        --base ../../../external/lobstertrap/configs/default_policy.yaml \
        --pack ../configs/hipaa_pack.yaml \
        --out  ../configs/full_hipaa_policy.yaml

Merge semantics:
    - Top-level scalars (version, policy_name, default_action) take pack values
      where set; otherwise inherit from base.
    - ingress_rules / egress_rules: concatenate (base rules + pack rules) and
      sort by priority DESC so the first-match-wins engine evaluates SOUF AI
      pack rules first when they have higher priority.
    - Non-engine-recognized fields (citation, extends) are stripped from the
      output so the engine validates cleanly.

The output is a fully self-contained policy. Deploying it to lobstertrap gives
"default behavior + vertical pack behavior" without modifying upstream code.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# Fields recognized by the upstream Lobster Trap policy loader.
# Anything outside this allowlist is stripped from the merged output to avoid
# engine validation surprises.
ALLOWED_TOP_LEVEL = {
    "version", "policy_name", "default_action",
    "ingress_rules", "egress_rules", "rate_limits",
    "network", "filesystem",
}
ALLOWED_RULE_FIELDS = {
    "name", "description", "priority", "action",
    "deny_message", "conditions",
}
ALLOWED_CONDITION_FIELDS = {
    "field", "match_type", "value", "negate",
}


def strip_unknown(obj, allowed: set[str]) -> dict:
    """Remove keys not in the allowlist (e.g., `extends`, `citation`)."""
    return {k: v for k, v in obj.items() if k in allowed}


def normalize_rule(rule: dict) -> dict:
    """Strip non-engine fields from a single rule + its conditions."""
    clean = strip_unknown(rule, ALLOWED_RULE_FIELDS)
    if "conditions" in clean and isinstance(clean["conditions"], list):
        clean["conditions"] = [
            strip_unknown(c, ALLOWED_CONDITION_FIELDS) for c in clean["conditions"]
        ]
    return clean


def merge_policies(base: dict, pack: dict) -> dict:
    """Compose base policy with a SOUF AI pack."""
    merged: dict = {}

    # Top-level scalars: pack wins if set, else base
    for key in ("version", "policy_name", "default_action"):
        if key in pack and pack[key] is not None:
            merged[key] = pack[key]
        elif key in base:
            merged[key] = base[key]

    # Ingress and egress rules: concatenate, normalize, sort by priority DESC
    for key in ("ingress_rules", "egress_rules"):
        base_rules = base.get(key) or []
        pack_rules = pack.get(key) or []
        combined = [normalize_rule(r) for r in (list(base_rules) + list(pack_rules))]
        # First-match-wins → higher priority first
        combined.sort(key=lambda r: r.get("priority", 0), reverse=True)
        if combined:
            merged[key] = combined

    # Pass-through: rate_limits, network, filesystem (pack overrides base if set)
    for key in ("rate_limits", "network", "filesystem"):
        if key in pack and pack[key] is not None:
            merged[key] = pack[key]
        elif key in base:
            merged[key] = base[key]

    return strip_unknown(merged, ALLOWED_TOP_LEVEL)


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge a Lobster Trap base policy with SOUF AI vertical packs.")
    parser.add_argument("--base", required=True, help="Base policy YAML (e.g. Lobster Trap default_policy.yaml)")
    parser.add_argument("--pack", required=True, action="append",
                        help="SOUF AI pack YAML to merge (can be repeated to apply multiple packs)")
    parser.add_argument("--out", required=True, help="Output merged YAML path")
    args = parser.parse_args()

    with open(args.base) as f:
        base = yaml.safe_load(f)
    if not isinstance(base, dict):
        print(f"ERROR: base policy {args.base} did not parse to a dict", file=sys.stderr)
        return 1

    merged = base
    for pack_path in args.pack:
        with open(pack_path) as f:
            pack = yaml.safe_load(f)
        if not isinstance(pack, dict):
            print(f"ERROR: pack {pack_path} did not parse to a dict", file=sys.stderr)
            return 1
        merged = merge_policies(merged, pack)
        # Update name to reflect merged stack
        merged["policy_name"] = f"{merged.get('policy_name', 'merged')}+{pack.get('policy_name', Path(pack_path).stem)}"

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        yaml.safe_dump(merged, f, sort_keys=False, default_flow_style=False)

    n_ingress = len(merged.get("ingress_rules") or [])
    n_egress = len(merged.get("egress_rules") or [])
    print(f"Merged policy written: {args.out}")
    print(f"  policy_name:    {merged.get('policy_name')}")
    print(f"  ingress rules:  {n_ingress}")
    print(f"  egress rules:   {n_egress}")
    print(f"  default action: {merged.get('default_action')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
