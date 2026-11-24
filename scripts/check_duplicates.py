#!/usr/bin/env python3
"""
check_duplicates.py — fail if any tenant would receive the same rule from two files.

A rule is identified by rule_id (that's how push_detections.py finds it on the
platform). Two files may share a rule_id only if their `tenants:` lists don't
overlap, e.g. a per-tenant variant. Run in CI before validate and deploy.

Usage: python3 scripts/check_duplicates.py [rules_dir]
Env:   KNOWN_TENANTS="prod"
"""
import glob
import os
import sys

import yaml

from rule_targets import BadTenants, targets_for


def main():
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "rules"
    tenants = os.environ.get("KNOWN_TENANTS", "prod").split()
    seen = {}  # (tenant, rule_id) -> path
    bad = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "**", "*.yaml"), recursive=True)):
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict) or "rule_id" not in data:
            continue
        try:
            t = sorted(targets_for(path, data, tenants))
        except BadTenants as e:
            bad.append(f"{path}: {e}")
            continue
        for tenant in t:
            key = (tenant, str(data["rule_id"]))
            if key in seen:
                bad.append(f"rule_id {key[1]!r} targets {tenant} from both "
                           f"{seen[key]} and {path}")
            else:
                seen[key] = path
    for b in bad:
        print(f"::error::duplicate rule: {b}")
    if bad:
        return 1
    print(f"No duplicate rules ({len(seen)} rule/tenant pairs checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
