#!/usr/bin/env python3
"""
push_detections.py — Detection-as-Code deployer for Exaforce Threat Rules.

Rules are authored as YAML in ./rules (source of truth), reviewed and versioned
in Git, and deployed to the platform through the Threat Rules API. This script is
the deploy step; CI (GitHub Actions) runs it.

Endpoints (base = https://<tenant>.app.exaforce.io), schema names per the current
OpenAPI spec (Query, v1_DetectionRuleAction, GenericResponse):
  validate   POST   /qe/api/{project}/queries          (validate_mode=threat_rule)
  capacity   GET    /wt/api/{project}/rule_capacity
  list       GET    /wt/api/{project}/detection_rules
  get        GET    /wt/api/{project}/detection_rule/{uid}
  create     POST   /wt/api/{project}/detection_rules
  update     PUT    /wt/api/{project}/detection_rule/{uid}
  delete     DELETE /wt/api/{project}/detection_rule/{uid}

Auth: X-EXF-API-TOKEN header, read from env EXF_API_TOKEN.

Commands:
  --validate-only FILE   Validate a rule's query (no writes). Use on PRs.
  --dry-run       FILE   Print the compiled create body (no network, no token).
  --capacity             Show remaining rule capacity.
  --list                 List detection rules (raw).
  --get UID              Get one rule by uid.
  --create        FILE   Create a rule.
  --update        FILE   Update an existing rule (resolves uid by rule_id).
  --delete        FILE   Delete a rule (resolves uid by rule_id).
  --sync          FILE   Idempotent deploy: validate -> update if it exists,
                         else create. Safe to re-run. Use on merge to main.

Sync exit behavior (CI-friendly):
  - validation failure               -> exit 1 (fail the build)
  - created or updated               -> exit 0
  - already exists but uid not
    resolvable (list endpoint down)  -> exit 0 with a WARNING, unless --strict

Env: EXF_BASE_URL (required, your tenant URL), EXF_PROJECT (default "default").
"""
import argparse
import json
import os
import subprocess
import sys
import time

try:
    import yaml
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml requests")

DEFAULT_BASE = os.environ.get("EXF_BASE_URL", "")  # e.g. https://<your-tenant>.us.app.exaforce.io
DEFAULT_PROJECT = os.environ.get("EXF_PROJECT", "default")

RULE_FIELDS = [
    "package_id", "package_name", "rule_id", "rule_name", "description",
    "data_sources", "finding_sources", "rule_version", "status",
    "rule_action", "query", "duration_seconds", "cloned_from",
]
UPDATE_FIELDS = [
    "rule_name", "description", "data_sources", "finding_sources",
    "rule_version", "status", "rule_action", "query", "duration_seconds",
]

# Substrings the API returns when a rule with the same id/name already exists.
EXISTS_MARKERS = ("already exists",)


def git_version(path):
    """Derive rule_version from Git: number of commits that touched the file,
    plus 1 if the file currently has uncommitted (staged or unstaged) changes.
    So the version increases by exactly 1 per change and stays stable once
    committed. Returns a string, or None if this isn't a Git working tree."""
    def _git(args):
        return subprocess.run(["git"] + args, capture_output=True, text=True)

    inside = _git(["rev-parse", "--is-inside-work-tree"])
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return None
    count = _git(["rev-list", "--count", "HEAD", "--", path])
    try:
        n = int(count.stdout.strip() or "0")
    except ValueError:
        n = 0
    dirty = (_git(["diff", "--quiet", "--", path]).returncode != 0 or
             _git(["diff", "--cached", "--quiet", "--", path]).returncode != 0)
    n += 1 if dirty else 0
    return str(max(n, 1))


def load_rule(path):
    with open(path) as fh:
        rule = yaml.safe_load(fh)
    if not isinstance(rule, dict):
        sys.exit(f"{path}: not a YAML mapping")
    if "rule_id" not in rule:
        sys.exit(f"{path}: YAML must define rule_id")
    if "query" not in rule:
        sys.exit(f"{path}: YAML must define query")
    if "rule_action" not in rule:
        sys.exit(f"{path}: YAML must define rule_action")
    return rule


def create_body(rule):
    return {k: rule[k] for k in RULE_FIELDS if k in rule}


def update_body(rule):
    return {k: rule[k] for k in UPDATE_FIELDS if k in rule}


def validate_query_body(rule):
    q = json.loads(json.dumps(rule["query"]))  # deep copy
    opts = q.setdefault("options", {})
    opts["validate_mode"] = "threat_rule"
    opts["validate_only"] = True
    return q


def msg_of(body):
    if isinstance(body, dict):
        return str(body.get("message", body))
    return str(body)


class ListUnavailable(Exception):
    """Raised when listDetectionRules does not return a usable array."""


class Client:
    def __init__(self, base, project, token):
        self.base = base.rstrip("/")
        self.project = project
        self.s = requests.Session()
        self.s.headers.update(
            {"X-EXF-API-TOKEN": token, "Content-Type": "application/json"}
        )

    def _u(self, path):
        return f"{self.base}{path.format(project=self.project)}"

    def validate(self, rule):
        return self.s.post(self._u("/qe/api/{project}/queries") + "?debug=true",
                           json=validate_query_body(rule), timeout=60)

    def capacity(self):
        return self.s.get(self._u("/wt/api/{project}/rule_capacity"), timeout=30)

    def list_rules(self):
        return self.s.get(self._u("/wt/api/{project}/detection_rules"), timeout=30)

    # Column set the console uses. The endpoint returns `result: null` for a
    # trimmed set and rejects a positive row_limit, so send the full list with
    # row_limit 0 (verified live).
    _CHART_COLUMNS = [
        "severity", "severityLevel", "rule_name", "rule_id", "description",
        "total_findings", "rule_version", "data_sources", "tags", "updated_at",
        "updated_by", "last_run_at", "created_at", "created_by", "last_fired_at",
        "finding_type", "threat_category", "rule_action_type", "run_frequency",
        "fp_count", "fp_rate", "tp_count", "quota_units", "uid", "package_id",
        "status", "openapi_query", "rule_action", "finding_sources",
    ]

    def chart_rows(self):
        """List threat rules via the console's data endpoint (/hm .../chart/data).
        This is what the UI uses; it returns a `uid` column and works even when
        the wt listDetectionRules endpoint is 500ing. Returns a list of row dicts."""
        body = {
            "force": False,
            "queries": [{
                "columns": self._CHART_COLUMNS,
                "orderby": [["updated_at", False]],
                "metrics": ["rulesCount"],
                "extras": {}, "url_params": {}, "filters": [],
                "row_limit": 0, "row_offset": 0,
            }],
            "result_format": "json",
            "result_type": "results",
            "datasource": {"type": "table", "name": "threat_rules_threat_rules"},
        }
        r = self.s.post(self._u("/hm/api/{project}/chart/data"), json=body, timeout=45)
        if r.status_code != 200:
            raise ListUnavailable(f"chart/data HTTP {r.status_code}")
        try:
            js = r.json()
            rows = js["result"][0]["data"]
        except (ValueError, KeyError, IndexError, TypeError) as e:
            raise ListUnavailable(f"chart/data unexpected shape: {e}")
        if not isinstance(rows, list):
            raise ListUnavailable("chart/data 'data' not a list")
        return rows

    def get_rule(self, uid):
        return self.s.get(self._u("/wt/api/{project}/detection_rule/") + uid, timeout=30)

    def create(self, rule):
        return self.s.post(self._u("/wt/api/{project}/detection_rules"),
                           json=create_body(rule), timeout=60)

    def update(self, uid, rule):
        return self.s.put(self._u("/wt/api/{project}/detection_rule/") + uid,
                          json=update_body(rule), timeout=60)

    def delete(self, uid):
        return self.s.delete(self._u("/wt/api/{project}/detection_rule/") + uid, timeout=30)

    def find_uid(self, rule_id):
        """Return uid for rule_id, or None if the rule doesn't exist yet.
        Tries the official listDetectionRules endpoint first, then falls back to
        the console data endpoint (chart/data) which the UI uses. Raises
        ListUnavailable only if BOTH are unusable."""
        # 1) official endpoint
        r = self.list_rules()
        if r.status_code == 200:
            try:
                data = r.json()
            except ValueError:
                data = None
            if isinstance(data, list):
                for item in data:
                    if item.get("rule_id") == rule_id:
                        return item.get("uid")
                return None
        list_status = r.status_code
        # 2) fallback: console data endpoint
        rows = self.chart_rows()  # raises ListUnavailable if this also fails
        print(f"[find_uid] listDetectionRules HTTP {list_status}; "
              f"resolved via chart/data ({len(rows)} rules).")
        for row in rows:
            if str(row.get("rule_id")) == str(rule_id):
                return row.get("uid")
        return None


def show(resp):
    print(f"HTTP {resp.status_code}")
    body = resp.text.strip()
    if not body:
        print("(empty body)")
        return
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print(body)


def get_client(args):
    token = os.environ.get("EXF_API_TOKEN")
    if not token:
        sys.exit("Set EXF_API_TOKEN in your environment first.")
    if not args.base:
        sys.exit("Set EXF_BASE_URL (e.g. https://<your-tenant>.us.app.exaforce.io) or pass --base.")
    return Client(args.base, args.project, token)


def cmd_status(client, rule):
    """Print the live state of a rule (resolves uid by rule_id)."""
    rid = rule["rule_id"]
    try:
        uid = client.find_uid(rid)
    except ListUnavailable as e:
        print(f"{rid}: cannot resolve uid ({e})")
        return 1
    if not uid:
        print(f"{rid}: not deployed yet")
        return 0
    r = client.get_rule(uid)
    if r.status_code != 200:
        print(f"{rid}: GET uid={uid} HTTP {r.status_code}")
        return 1
    b = safe_json(r)
    tfr = (b.get("rule_action") or {}).get("threat_finding_request") or {}
    print(f"  rule_id   : {rid}")
    print(f"  uid       : {uid}")
    print(f"  version   : {b.get('rule_version')}")
    print(f"  status    : {b.get('runtime_status') or b.get('status')}")
    print(f"  severity  : {tfr.get('severity')}")
    print(f"  rule_name : {b.get('rule_name')}")
    return 0


def cmd_sync(client, rule, strict):
    rid = rule["rule_id"]
    # 1) validate — hard gate
    v = client.validate(rule)
    print(f"[validate] HTTP {v.status_code}: {msg_of(safe_json(v))}")
    if v.status_code != 200:
        print(f"::error::validation failed for {rid}")
        return 1
    # 2) resolve uid -> update, else create
    try:
        uid = client.find_uid(rid)
    except ListUnavailable as e:
        print(f"[sync] WARNING: {e}; cannot resolve uid, attempting create.")
        uid = None
        list_down = True
    else:
        list_down = False

    if uid:
        r = client.update(uid, rule)
        print(f"[update] rule_id={rid} uid={uid} HTTP {r.status_code}: {msg_of(safe_json(r))}")
        return 0 if r.status_code == 200 else 1

    r = client.create(rule)
    body = safe_json(r)
    print(f"[create] rule_id={rid} HTTP {r.status_code}: {msg_of(body)}")
    if r.status_code == 200:
        return 0
    # already exists but we couldn't resolve uid to update it
    if any(m in msg_of(body).lower() for m in EXISTS_MARKERS):
        if list_down:
            print(f"::warning::{rid} already exists but listDetectionRules is "
                  f"unavailable, so it can't be updated via API. Rule left as-is.")
            return 1 if strict else 0
        # list worked, rule not found, yet create says exists -> odd; report
        print(f"::warning::{rid} reports 'already exists' but was not found in list.")
        return 1 if strict else 0
    return 1


def safe_json(resp):
    try:
        return resp.json()
    except ValueError:
        return resp.text


def load_rule_versioned(path, no_auto):
    """Load a rule and set rule_version from Git unless --no-auto-version."""
    rule = load_rule(path)
    if not no_auto:
        v = git_version(path)
        if v is not None:
            rule["rule_version"] = v
    rule.setdefault("rule_version", "1")
    return rule


def main():
    p = argparse.ArgumentParser(description="Deploy Exaforce Threat Rules from YAML.")
    p.add_argument("rule", nargs="?", help="path to a rule YAML file")
    p.add_argument("--base", default=DEFAULT_BASE, help="API base URL")
    p.add_argument("--project", default=DEFAULT_PROJECT, help="project name")
    p.add_argument("--strict", action="store_true",
                   help="in --sync, fail if an existing rule cannot be updated")
    p.add_argument("--no-auto-version", action="store_true",
                   help="use the rule_version written in the YAML instead of "
                        "deriving it from Git history")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--validate-only", action="store_true")
    g.add_argument("--capacity", action="store_true")
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--create", action="store_true")
    g.add_argument("--update", action="store_true")
    g.add_argument("--delete", action="store_true")
    g.add_argument("--sync", action="store_true")
    g.add_argument("--status", action="store_true",
                   help="show a rule's live state (by rule_id)")
    g.add_argument("--list", action="store_true")
    g.add_argument("--get", metavar="UID")
    args = p.parse_args()

    needs_rule = any([args.validate_only, args.dry_run, args.create,
                      args.update, args.delete, args.sync, args.status])
    if needs_rule and not args.rule:
        p.error("this command requires a rule YAML file path")

    if args.dry_run:
        rule = load_rule_versioned(args.rule, args.no_auto_version)
        print(f"# CreateDetectionRule body for rule_id={rule['rule_id']}")
        print(json.dumps(create_body(rule), indent=2))
        return 0

    client = get_client(args)

    if args.list:
        show(client.list_rules()); return 0
    if args.get:
        show(client.get_rule(args.get)); return 0
    if args.capacity:
        show(client.capacity()); return 0

    rule = load_rule_versioned(args.rule, args.no_auto_version)

    if args.validate_only:
        print(f"Validating {rule['rule_id']} (threat_rule mode)...")
        r = client.validate(rule); show(r)
        return 0 if r.status_code == 200 else 1

    if args.status:
        return cmd_status(client, rule)

    if args.sync:
        return cmd_sync(client, rule, args.strict)

    if args.create:
        r = client.create(rule); show(r)
        return 0 if r.status_code == 200 else 1

    if args.update:
        uid = client.find_uid(rule["rule_id"])
        if not uid:
            sys.exit(f"No existing rule with rule_id={rule['rule_id']}; use --create.")
        r = client.update(uid, rule); show(r)
        return 0 if r.status_code == 200 else 1

    if args.delete:
        uid = client.find_uid(rule["rule_id"])
        if not uid:
            sys.exit(f"No existing rule with rule_id={rule['rule_id']}.")
        r = client.delete(uid); show(r)
        return 0 if r.status_code == 200 else 1


if __name__ == "__main__":
    sys.exit(main() or 0)
