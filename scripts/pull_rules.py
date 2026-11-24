#!/usr/bin/env python3
"""
pull_rules.py — bring custom Threat Rules created or edited in a tenant's UI back into Git.

Two steps, so the job that writes to the repo never holds a tenant API token:

  fetch      Runs once per tenant (needs EXF_BASE_URL / EXF_API_TOKEN / EXF_PROJECT).
             Lists the tenant's rules, keeps the custom ones, drops rule_ids matched by
             .drift-ignore, and writes a JSON snapshot.

  reconcile  Runs once, with no tenant credentials. Compares every snapshot with the
             YAML in rules/ and edits the YAML so Git matches the tenants:
               * rules are matched by rule_id, never by file name
               * rule edited in the UI     -> the existing file is updated in place
                                              (comments and key order are kept)
               * rule created in the UI    -> new file, tenants: [<tenant>]
               * same new rule, same logic
                 in several tenants        -> ONE file, tenants: [prod, staging]
               * same rule_id but different
                 logic per tenant          -> one file per tenant, scoped with tenants:
               * tenants disagree about a
                 rule that shares one file -> nothing written, reported as a conflict
               * rule in Git, gone from
                 the tenant                -> reported only, never deleted
             A markdown report is written for the pull request body.

It never creates a second file for a rule_id that already targets a tenant, so no
tenant ever ends up with two files deploying the same rule (check_duplicates.py
enforces the same thing in CI).

Usage:
  python3 scripts/pull_rules.py fetch --tenant prod --out snapshot-prod.json
  python3 scripts/pull_rules.py reconcile snapshots/*.json --report drift.md
"""
import argparse
import copy
import fnmatch
import glob
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# Fields that make up a rule in Git. Platform-managed fields (uid, runtime_status,
# origin, rule_version, timestamps, derived severity) are deliberately left out.
# rule_version is derived from Git history by push_detections.py.
RULE_KEYS = [
    "package_id", "package_name", "rule_id", "rule_name", "description",
    "data_sources", "finding_sources", "status", "duration_seconds",
    "rule_action", "query",
]
NEW_FILE_ORDER = [
    "package_id", "package_name", "rule_id", "rule_name", "description",
    "tenants", "data_sources", "finding_sources", "status", "duration_seconds",
    "rule_action", "query",
]

EMPTY = object()


# ----------------------------------------------------------------- helpers
def strip_empty(v):
    """Drop None / "" / {} / [] recursively so the platform's empty defaults
    (options: {}, data_sources: [], description: "") never count as drift."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            x = strip_empty(x)
            if x is not EMPTY:
                out[k] = x
        return out if out else EMPTY
    if isinstance(v, list):
        out = [x for x in (strip_empty(i) for i in v) if x is not EMPTY]
        return out if out else EMPTY
    if v is None or v == "":
        return EMPTY
    return v


def plain(v):
    """ruamel containers -> plain python, for comparisons and JSON."""
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [plain(x) for x in v]
    return v


def known_tenants():
    return os.environ.get("KNOWN_TENANTS", "prod").split()


def load_ignore(path):
    pats = []
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    pats.append(line)
    return pats


def ignored(rule_id, pats):
    return any(fnmatch.fnmatchcase(rule_id, p) for p in pats)


# ------------------------------------------------------------------- fetch
def normalize_detail(d):
    """Platform rule (GET detection_rule/{uid}) -> the fields we keep in Git."""
    d = dict(d)
    if not d.get("query") and d.get("openapi_query"):
        q = d["openapi_query"]
        d["query"] = json.loads(q) if isinstance(q, str) else q
    if isinstance(d.get("rule_action"), str):
        d["rule_action"] = json.loads(d["rule_action"])
    out = {}
    for k in RULE_KEYS:
        if k in d:
            v = strip_empty(d[k])
            if v is not EMPTY:
                out[k] = v
    return out


def cmd_fetch(args):
    from push_detections import Client, ListUnavailable  # noqa: E402

    token = os.environ.get("EXF_API_TOKEN")
    base = os.environ.get("EXF_BASE_URL")
    project = os.environ.get("EXF_PROJECT", "default")
    if not token or not base:
        sys.exit("EXF_BASE_URL and EXF_API_TOKEN must be set.")
    client = Client(base, project, token)
    pats = load_ignore(args.ignore)

    # 1) list rules (official endpoint, then the console endpoint as fallback)
    rows = None
    r = client.list_rules()
    if r.status_code == 200:
        try:
            data = r.json()
            rows = data if isinstance(data, list) else data.get("rules") or data.get("items")
        except ValueError:
            rows = None
    if not isinstance(rows, list):
        try:
            rows = client.chart_rows()
        except ListUnavailable as e:
            sys.exit(f"[fetch] cannot list rules on {args.tenant}: {e}")
    print(f"[fetch] {args.tenant}: {len(rows)} rules listed")

    rules, skipped_builtin, skipped_ignored, unknown_origin, errors = {}, 0, [], [], []
    for row in rows:
        uid, rid = row.get("uid"), str(row.get("rule_id") or "")
        if not uid or not rid:
            continue
        if row.get("origin") not in (None, "", "custom"):
            skipped_builtin += 1
            continue
        if ignored(rid, pats):
            skipped_ignored.append(rid)
            continue
        g = client.get_rule(uid)
        if g.status_code != 200:
            errors.append(f"{rid}: GET HTTP {g.status_code}")
            continue
        d = g.json()
        d = d.get("rule", d) if isinstance(d, dict) else d
        origin = d.get("origin", row.get("origin"))
        if origin in (None, ""):
            unknown_origin.append(rid)
            if not args.assume_custom:
                continue
        elif origin != "custom":
            skipped_builtin += 1
            continue
        if rid in rules:
            errors.append(f"{rid}: rule_id appears twice in {args.tenant} "
                          f"(packages {rules[rid].get('package_id')} / {d.get('package_id')})")
            continue
        rules[rid] = normalize_detail(d)
        time.sleep(0.05)

    if unknown_origin and not args.assume_custom:
        sys.exit(f"[fetch] {args.tenant}: {len(unknown_origin)} rules have no `origin`, so custom "
                 f"and built-in rules can't be told apart. Refusing to import. "
                 f"(First few: {unknown_origin[:5]})")
    snap = {
        "tenant": args.tenant,
        "base_url": base,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rules": rules,
        "skipped_builtin": skipped_builtin,
        "skipped_ignored": sorted(skipped_ignored),
        "errors": errors,
    }
    with open(args.out, "w") as fh:
        json.dump(snap, fh, indent=2, sort_keys=True)
    print(f"[fetch] {args.tenant}: {len(rules)} custom rules kept, {skipped_builtin} built-in, "
          f"{len(skipped_ignored)} ignored, {len(errors)} errors -> {args.out}")
    for e in errors:
        print(f"::warning::{args.tenant}: {e}")
    return 1 if errors and args.strict else 0


# --------------------------------------------------------------- reconcile
def yaml_rt():
    from ruamel.yaml import YAML
    y = YAML()
    y.preserve_quotes = True
    y.width = 100
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def targets_of(data, tenants, path=None):
    """Tenants a file deploys to: its `tenants:` field, else the folder's
    _tenants.yml, else every tenant (same logic as the deploy workflow)."""
    sys.path.insert(0, HERE)
    from rule_targets import targets_for
    return targets_for(path or os.path.join(ROOT, "rules", "_"), plain(data), tenants)


def load_repo(rules_dir, tenants):
    y = yaml_rt()
    out = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "**", "*.yaml"), recursive=True)):
        with open(path) as fh:
            data = y.load(fh)
        if not isinstance(data, dict) or "rule_id" not in data:
            continue
        out.append({"path": path, "data": data, "targets": targets_of(data, tenants, path)})
    return out


def diff_paths(repo, tenant, prefix=""):
    """Paths where the tenant's value differs from Git. Only keys the tenant
    returned are compared, so fields Git has but the API doesn't echo back
    (e.g. finding_sources) never show up as drift."""
    changes = []
    for k, tv in tenant.items():
        p = f"{prefix}.{k}" if prefix else k
        rv = repo.get(k, EMPTY) if isinstance(repo, dict) else EMPTY
        rvp = strip_empty(plain(rv)) if rv is not EMPTY else EMPTY
        if isinstance(tv, dict) and isinstance(rvp, dict):
            changes += diff_paths(rv, tv, p)
        elif rvp != tv:
            changes.append(p)
    return changes


def to_yaml(v, nested=False):
    """Plain python -> ruamel nodes; inner lists (e.g. threat_signals pairs)
    are written in flow style: [com.exaforce.threats, OPERATION_ANOMALY]."""
    from ruamel.yaml.comments import CommentedMap, CommentedSeq
    if isinstance(v, dict):
        m = CommentedMap()
        for k, x in v.items():
            m[k] = to_yaml(x)
        return m
    if isinstance(v, list):
        s = CommentedSeq(to_yaml(x, nested=True) for x in v)
        if nested and all(not isinstance(x, (dict, list)) for x in v):
            s.fa.set_flow_style()
        return s
    return v


def apply(repo, tenant):
    """Write tenant values into the ruamel document in place (comments kept).
    Keys the file doesn't have yet are inserted just before its last key, so
    a comment trailing that key (usually the next section's header) stays
    where it is."""
    for k, tv in tenant.items():
        rv = repo.get(k)
        if isinstance(tv, dict) and isinstance(rv, dict):
            apply(rv, tv)
        elif strip_empty(plain(rv)) != tv:
            if k in repo or not hasattr(repo, "insert") or len(repo) == 0:
                repo[k] = to_yaml(tv)
            else:
                repo.insert(len(repo) - 1, k, to_yaml(tv))


def comparable(content):
    return json.dumps(content, sort_keys=True)


def slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "rule"


def new_file_path(rules_dir, rule_id, group, all_tenants):
    base = slug(rule_id)
    path = os.path.join(rules_dir, f"{base}.yaml")
    if not os.path.exists(path):
        return path
    path = os.path.join(rules_dir, f"{base}.{'-'.join(sorted(group))}.yaml")
    n = 2
    while os.path.exists(path):
        path = os.path.join(rules_dir, f"{base}.{'-'.join(sorted(group))}.{n}.yaml")
        n += 1
    return path


def write_new(path, content, group, tenant_label):
    from ruamel.yaml.comments import CommentedMap
    from ruamel.yaml.scalarstring import LiteralScalarString
    doc = CommentedMap()
    body = dict(content)
    body["tenants"] = sorted(group)
    for k in NEW_FILE_ORDER:
        if k in body:
            v = to_yaml(copy.deepcopy(body[k]))
            if k == "description" and isinstance(v, str) and len(v) > 80:
                v = LiteralScalarString(v.rstrip() + "\n")
            doc[k] = v
    doc.yaml_set_start_comment(
        "Detection-as-Code rule (Exaforce Threat Rule)\n"
        f"Imported from the {tenant_label} UI by the drift-sync workflow.\n"
        "Git is now the source of truth: edit this file, not the UI.")
    with open(path, "w") as fh:
        yaml_rt().dump(doc, fh)


def save(entry):
    with open(entry["path"], "w") as fh:
        yaml_rt().dump(entry["data"], fh)


def cmd_reconcile(args):
    tenants = known_tenants()
    snaps = {}
    for p in args.snapshots:
        with open(p) as fh:
            s = json.load(fh)
        if s["tenant"] not in tenants:
            sys.exit(f"snapshot {p}: tenant {s['tenant']!r} not in KNOWN_TENANTS {tenants}")
        snaps[s["tenant"]] = s
    if not snaps:
        sys.exit("no snapshots to reconcile")
    pats = load_ignore(args.ignore)

    repo = load_repo(args.rules_dir, tenants)
    by_id = {}
    for e in repo:
        by_id.setdefault(str(e["data"]["rule_id"]), []).append(e)

    updated, created, extended, conflicts, missing, notes = [], [], [], [], [], []
    touched = set()

    all_ids = sorted({rid for s in snaps.values() for rid in s["rules"]})
    for rid in all_ids:
        files = by_id.get(rid, [])
        pending = {}      # file path -> {tenant: content}
        unmatched = {}    # tenant -> content
        for t, s in snaps.items():
            if rid not in s["rules"]:
                continue
            content = s["rules"][rid]
            owners = [f for f in files if t in f["targets"]]
            if len(owners) > 1:
                conflicts.append(f"`{rid}`: {len(owners)} files already target **{t}** "
                                 f"({', '.join(os.path.relpath(o['path'], ROOT) for o in owners)}). Fix the duplicate first.")
                continue
            if owners:
                f = owners[0]
                if diff_paths(f["data"], content):
                    pending.setdefault(f["path"], {})[t] = content
            else:
                unmatched[t] = content

        # UI edits to rules Git already has
        for path, per_tenant in pending.items():
            f = next(x for x in files if x["path"] == path)
            versions = {comparable(c) for c in per_tenant.values()}
            rel = os.path.relpath(path, ROOT)
            if len(versions) > 1:
                conflicts.append(f"`{rid}` ({rel}): edited differently in "
                                 f"{', '.join(sorted(per_tenant))}. Not written; pick one and edit the file.")
                continue
            t0, content = next(iter(per_tenant.items()))
            fields = diff_paths(f["data"], content)
            apply(f["data"], content)
            save(f)
            touched.add(path)
            others = sorted(f["targets"] - set(per_tenant))
            line = f"`{rid}` ({rel}) changed in **{', '.join(sorted(per_tenant))}**: {', '.join(fields)}"
            if others:
                line += f". ⚠️ Merging also deploys this change to **{', '.join(others)}**"
            updated.append(line)

        # Rules the tenant has that no file targets yet
        groups = {}
        for t, c in unmatched.items():
            groups.setdefault(comparable(c), (c, set()))[1].add(t)
        for key, (content, group) in groups.items():
            # Same logic already in Git for other tenants -> add these tenants to that file.
            same = [f for f in files
                    if not (f["targets"] & group) and not diff_paths(f["data"], content)]
            if same and same[0]["data"].get("tenants") not in (None, "", [], "all"):
                f = same[0]
                cur = f["data"]["tenants"]
                if isinstance(cur, str):
                    f["data"]["tenants"] = [cur]
                for t in sorted(group):
                    f["data"]["tenants"].append(t)
                f["targets"] |= group
                save(f)
                touched.add(f["path"])
                extended.append(f"`{rid}` ({os.path.relpath(f['path'], ROOT)}): now also targets "
                                f"**{', '.join(sorted(group))}** (identical rule found there)")
                continue
            path = new_file_path(args.rules_dir, rid, group, tenants)
            write_new(path, content, group, " and ".join(sorted(group)))
            entry = {"path": path, "data": yaml_rt().load(open(path)), "targets": set(group)}
            files.append(entry)
            by_id.setdefault(rid, files)
            touched.add(path)
            created.append(f"`{rid}` → {os.path.relpath(path, ROOT)} (tenants: {', '.join(sorted(group))})")

    # In Git and targeting a tenant we fetched, but not in that tenant
    for e in repo:
        rid = str(e["data"]["rule_id"])
        if ignored(rid, pats):
            continue
        for t in sorted(e["targets"] & set(snaps)):
            if rid not in snaps[t]["rules"]:
                missing.append(f"`{rid}` ({os.path.relpath(e['path'], ROOT)}) not found in **{t}** "
                               f"(deleted in the UI, or not deployed yet). Not changed.")

    for t, s in sorted(snaps.items()):
        for err in s.get("errors", []):
            notes.append(f"{t}: {err}")

    # ---- report
    lines = ["## Tenant → Git drift sync", ""]
    lines.append("Tenants checked: " + ", ".join(
        f"**{t}** ({len(s['rules'])} custom rules, fetched {s['fetched_at']})" for t, s in sorted(snaps.items())))
    skipped = [t for t in tenants if t not in snaps]
    if skipped:
        lines.append(f"\n⚠️ Not checked this run (fetch failed): {', '.join(skipped)}")
    for title, items in [("New rules created in the UI", created),
                         ("Rules edited in the UI", updated),
                         ("Existing files extended to more tenants", extended),
                         ("Conflicts (not written)", conflicts),
                         ("In Git but missing from a tenant (no action taken)", missing),
                         ("Fetch warnings", notes)]:
        if items:
            lines += ["", f"### {title} ({len(items)})", ""] + [f"- {i}" for i in items]
    lines += ["", "Merging this PR runs the normal deploy, which re-syncs these rules to the "
              "tenants listed in each file. Review the `tenants:` lines before merging."]
    report = "\n".join(lines) + "\n"
    if args.report:
        with open(args.report, "w") as fh:
            fh.write(report)
    print(report)
    changed = bool(created or updated or extended)
    if args.github_output and os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.write(f"changed={'true' if changed else 'false'}\n")
            fh.write(f"summary={len(created)} new, {len(updated)} edited, "
                     f"{len(extended)} extended, {len(conflicts)} conflicts\n")
    return 0


def main():
    p = argparse.ArgumentParser(description="Sync custom Threat Rules from tenants back into Git.")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="snapshot one tenant's custom rules")
    f.add_argument("--tenant", required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--ignore", default=os.path.join(ROOT, ".drift-ignore"))
    f.add_argument("--assume-custom", action="store_true",
                   help="treat rules with no `origin` field as custom")
    f.add_argument("--strict", action="store_true", help="exit 1 on any per-rule error")
    r = sub.add_parser("reconcile", help="update rules/ from snapshots")
    r.add_argument("snapshots", nargs="+")
    r.add_argument("--rules-dir", default=os.path.join(ROOT, "rules"))
    r.add_argument("--ignore", default=os.path.join(ROOT, ".drift-ignore"))
    r.add_argument("--report")
    r.add_argument("--github-output", action="store_true")
    a = p.parse_args()
    return cmd_fetch(a) if a.cmd == "fetch" else cmd_reconcile(a)


if __name__ == "__main__":
    sys.exit(main())
