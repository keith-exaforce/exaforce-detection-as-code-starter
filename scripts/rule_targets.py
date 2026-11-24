#!/usr/bin/env python3
"""
rule_targets.py RULE_YAML TENANT "KNOWN TENANTS"

Decides whether a rule should be validated/deployed to TENANT.

Where the target list comes from (first match wins):
  1. the rule's own `tenants:` field
  2. a `_tenants.yml` file in the rule's folder or the nearest parent folder
     under rules/ (e.g. rules/sigma/aws/_tenants.yml), containing
         tenants: [prod]
     Use this when a whole folder needs a data source only some tenants have.
  3. otherwise: every tenant

  tenants omitted, empty, or "all"  -> every tenant
  tenants: prod                     -> only prod
  tenants: [prod, staging]          -> those tenants

Exit codes (used by .github/workflows/deploy-detections.yml):
  0 = targeted, deploy it
  3 = not targeted, skip it
  2 = bad `tenants:` value (unknown tenant or wrong type) -> fail the build
  1 = unreadable / invalid YAML -> fail the build

check_duplicates.py and pull_rules.py import targets_for() so every tool agrees
on which tenants a file deploys to.
"""
import os
import sys

import yaml

DEFAULTS_FILE = "_tenants.yml"


class BadTenants(ValueError):
    pass


def folder_default(path):
    """`tenants` from the nearest _tenants.yml at or above the rule's folder,
    stopping at the rules/ directory. None if there is none."""
    d = os.path.dirname(os.path.abspath(path))
    while True:
        f = os.path.join(d, DEFAULTS_FILE)
        if os.path.exists(f):
            with open(f) as fh:
                data = yaml.safe_load(fh) or {}
            return data.get("tenants") if isinstance(data, dict) else None
        parent = os.path.dirname(d)
        if os.path.basename(d) == "rules" or parent == d:
            return None
        d = parent


def targets_for(path, rule, known):
    """Set of tenants this rule file deploys to. Raises BadTenants."""
    targets = rule.get("tenants") if isinstance(rule, dict) else None
    source = "`tenants`"
    if targets is None:
        targets = folder_default(path)
        source = DEFAULTS_FILE
    if targets in (None, "", [], "all"):
        return set(known)
    if isinstance(targets, str):
        targets = [targets]
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        raise BadTenants(f"{source} must be a tenant name or a list of names")
    unknown = [t for t in targets if t not in known]
    if unknown:
        raise BadTenants(f"unknown tenant(s) {unknown} in {source}; known tenants: {known}")
    return set(targets)


def main():
    if len(sys.argv) != 4:
        print("usage: rule_targets.py RULE_YAML TENANT 'KNOWN TENANTS'")
        return 1
    path, tenant, known = sys.argv[1], sys.argv[2], sys.argv[3].split()

    with open(path) as fh:
        rule = yaml.safe_load(fh) or {}
    if not isinstance(rule, dict):
        print(f"::error file={path}::not a YAML mapping")
        return 1
    try:
        targets = targets_for(path, rule, known)
    except BadTenants as e:
        print(f"::error file={path}::{e}")
        return 2
    if tenant in targets:
        return 0
    print(f"{path}: targets {sorted(targets)}; skipping {tenant}")
    return 3


if __name__ == "__main__":
    sys.exit(main())
