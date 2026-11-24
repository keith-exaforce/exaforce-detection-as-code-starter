#!/usr/bin/env python3
"""
sigma_import.py — convert SigmaHQ rules into Exaforce Threat Rule YAML.

Scope (the "cloud + identity" pilot): AWS CloudTrail, Azure (activity, Entra
audit / sign-in / risk / PIM), GCP audit, Google Workspace, Microsoft 365,
Okta and GitHub audit rules. Each converted rule is written to
rules/sigma/<product>/<sigma file name>.yaml, deployed DISABLED, with no
`tenants:` field (so it goes to every tenant).

How a Sigma rule maps to a Query Builder query
  * logsource            -> entity_type + data_sources (see SOURCES below)
  * well-known fields    -> normalized properties (e.g. eventName -> name,
                            Okta eventType -> exfEventType)
  * every other field    -> regex on the raw event (`jsonData`, i.e. the
                            platform's row_to_json of the source table), matching
                            the field's full dotted name or its last segment
  * selections / conditions (and, or, not, 1 of / all of, parentheses)
                         -> nested `properties.expressions` (NOT is pushed down
                            to the leaves with De Morgan)
  * modifiers            -> contains / startswith / endswith / all / re / exists
  * Sigma matching is case-insensitive; so is the Query Builder (it lowercases
    or uses (?i) regexes), so values are passed through unchanged.

Skipped (listed in rules/sigma/IMPORT_REPORT.md with the reason):
  * correlation / aggregation rules (count(), near, timeframe)
  * deprecated or unsupported rules
  * modifiers with no Query Builder equivalent (cidr, base64, windash, fieldref, ...)
  * a negated wildcard/regex on a normalized property (the Query Builder has no
    "does not match regex")

Approximations (flagged in the rule description and the report):
  * a negated contains/startswith/endswith on a raw field becomes "the raw event
    does not contain <value>" — it can exclude slightly more than Sigma would.

Sigma rules are licensed under the Detection Rule License 1.1; every converted
rule keeps its author, id, references and a license line in its description.

Usage:
  git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
  python3 scripts/sigma_import.py --sigma-dir /tmp/sigma
"""
import argparse
import datetime
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LICENSE = "Detection Rule License (DRL) 1.1 — https://github.com/SigmaHQ/Detection-Rule-License"


class Unsupported(Exception):
    pass


# ------------------------------------------------------------- source map
def strip_ns(v):
    """Azure::Event `name` is operationName with everything up to the first
    '.' removed (MICROSOFT.AUTHORIZATION/... -> AUTHORIZATION/...)."""
    if not isinstance(v, str) or v.startswith("*") or "." not in v:
        return v
    dot, slash = v.index("."), v.find("/")
    return v[dot + 1:] if slash == -1 or dot < slash else v


def gcp_keys(field):
    f = field
    for p in ("data.protoPayload.", "protoPayload.", "gcp.audit."):
        if f.startswith(p):
            f = f[len(p):]
    f = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), f)  # method_name -> methodName
    return [f]


ENTRA_ALIASES = {
    "properties.message": ["operationName", "activityDisplayName"],
    "activitydisplayname": ["operationName", "activityDisplayName"],
    "operationname": ["operationName"],
    "riskeventtype": ["properties.riskEventType", "riskEventType"],
    "resulttype": ["resultType", "properties.status.errorCode"],
    "resultdescription": ["resultDescription", "properties.status.failureReason"],
    "authenticationrequirement": ["properties.authenticationRequirement"],
    "conditionalaccessstatus": ["properties.conditionalAccessStatus"],
    "riskstate": ["properties.riskState"],
    "resourcedisplayname": ["properties.resourceDisplayName"],
    "networklocationdetails": ["properties.networkLocationDetails"],
    "status": ["properties.result", "status"],
    "category": ["category", "properties.category"],
    "loggedbyservice": ["properties.loggedByService", "loggedByService"],
    "useragent": ["properties.userAgent", "userAgent"],
}

SOURCES = {
    # (product, service) -> config
    ("aws", "cloudtrail"): {
        "entity": "AWS::Cloudtrail::Event", "ds": "aws", "package": "aws",
        "props": {"eventname": "name", "eventsource": "source", "errorcode": "errorCode",
                  "sourceipaddress": "sourceIPAddress"},
    },
    ("azure", "activitylogs"): {
        "entity": "Azure::Event", "ds": "azure", "package": "azure",
        "props": {"operationname": "name"}, "transform": {"name": strip_ns},
    },
    **{("azure", s): {"entity": "Entra::Event", "ds": "azure", "package": "azure",
                      "props": {}, "aliases": ENTRA_ALIASES}
       for s in ("auditlogs", "signinlogs", "riskdetection", "pim")},
    ("gcp", "gcp.audit"): {"entity": "GCP::Event", "ds": "gcp", "package": "gcp",
                           "props": {}, "keyfn": gcp_keys},
    **{("gcp", s): {"entity": "GWS::Event", "ds": "googleworkspace", "package": "google-workspace",
                    "props": {}, "keyfn": gcp_keys}
       for s in ("google_workspace.admin", "google_workspace.login")},
    # Only the M365 unified audit log is mapped. Sigma's m365 threat_management /
    # threat_detection / exchange rules match Defender alert names that are not in
    # the audit records Exaforce ingests, so they are skipped rather than shipped
    # as rules that can never fire.
    ("m365", "audit"): {"entity": "Microsoft365::Event", "ds": "microsoft365", "package": "m365",
                        "props": {}},
    ("okta", "okta"): {"entity": "Okta::Event", "ds": "okta", "package": "okta",
                       "props": {"eventtype": "exfEventType"}},
    ("github", "audit"): {"entity": "Github::Event", "ds": "github", "package": "github",
                          "props": {"action": "exfEventType"}},
}

SEVERITY = {"informational": "LOW", "low": "LOW", "medium": "MED", "high": "HIGH", "critical": "CRITICAL"}

THREAT_FINDING_DEFAULTS = {
    "deduplication_period": 1440,
    "description": "auto",
    "entity_type": "SESSION",
    "mitre_tactic": "auto",
    "mitre_technique": "auto",
    "predict_window_period": 60,
    "rule_evaluation_frequency": 15,
    "threat_category": "auto",
    "threat_classification": "auto",
    "threat_signals": [["com.exaforce.threats", "OPERATION_ANOMALY"]],
    "title": "auto",
}

SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "exists", "i", "m", "s"}


# ------------------------------------------------------- value handling
def sigma_value_parts(v):
    """Split a Sigma string into ('lit', text) / ('star',) / ('q',) parts,
    honouring backslash escapes."""
    s = str(v)
    parts, buf, i = [], "", 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            buf += s[i + 1]
            i += 2
            continue
        if c in "*?":
            if buf:
                parts.append(("lit", buf))
                buf = ""
            parts.append(("star",) if c == "*" else ("q",))
        else:
            buf += c
        i += 1
    if buf:
        parts.append(("lit", buf))
    return parts


def has_wildcard(v):
    return isinstance(v, str) and any(p[0] != "lit" for p in sigma_value_parts(v))


def literal(v):
    return "".join(p[1] for p in sigma_value_parts(v) if p[0] == "lit")


def longest_literal(v):
    lits = [p[1] for p in sigma_value_parts(v) if p[0] == "lit"]
    return max(lits, key=len) if lits else ""


def to_regex(v, star, q):
    out = ""
    for p in sigma_value_parts(v):
        out += re.escape(p[1]) if p[0] == "lit" else (star if p[0] == "star" else q)
    return out


def scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


# ------------------------------------------------------------ AST build
def leaf(field, mods, values, neg=False):
    return {"t": "leaf", "field": field, "mods": mods, "values": values, "neg": neg}


def selection_ast(sel, name):
    if isinstance(sel, dict):
        terms = []
        for key, val in sel.items():
            parts = key.split("|")
            field, mods = parts[0], [m.lower() for m in parts[1:]]
            bad = [m for m in mods if m not in SUPPORTED_MODS]
            if bad:
                raise Unsupported(f"modifier {'|'.join(bad)} in {name}")
            vals = val if isinstance(val, list) else [val]
            if not vals:
                raise Unsupported(f"empty value list for {field} in {name}")
            if any(isinstance(x, (dict, list)) for x in vals):
                raise Unsupported(f"nested value for {field} in {name}")
            terms.append(leaf(field, mods, vals))
        return {"t": "and", "c": terms} if len(terms) > 1 else terms[0]
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            return {"t": "or", "c": [selection_ast(x, name) for x in sel]}
        if all(not isinstance(x, (dict, list)) for x in sel):
            return leaf(None, [], sel)
        raise Unsupported(f"mixed list in {name}")
    if isinstance(sel, (str, int)):
        return leaf(None, [], [sel])
    raise Unsupported(f"unsupported selection {name}")


TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-.]+)")


def parse_condition(cond, sels):
    toks = []
    pos = 0
    while pos < len(cond):
        m = TOKEN.match(cond, pos)
        if not m:
            if cond[pos:].strip() == "":
                break
            raise Unsupported(f"cannot parse condition: {cond!r}")
        toks.append(m.group(1))
        pos = m.end()
    if any(t in ("|", "count", "near") for t in toks) or "|" in cond:
        raise Unsupported("aggregation condition")
    i = 0

    def peek():
        return toks[i].lower() if i < len(toks) else None

    def eat():
        nonlocal i
        t = toks[i]
        i += 1
        return t

    def names(pattern):
        if pattern.lower() == "them":
            return [n for n in sels if not n.startswith("_")]
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        found = [n for n in sels if rx.match(n)]
        if not found:
            raise Unsupported(f"condition refers to unknown selection {pattern}")
        return found

    def factor():
        t = peek()
        if t is None:
            raise Unsupported("truncated condition")
        if t == "not":
            eat()
            return {"t": "not", "c": factor()}
        if t == "(":
            eat()
            e = expr()
            if peek() != ")":
                raise Unsupported("unbalanced parentheses")
            eat()
            return e
        if t in ("1", "all", "any") and i + 1 < len(toks) and toks[i + 1].lower() == "of":
            q = eat().lower()
            eat()
            ns = names(eat())
            kids = [selection_ast(sels[n], n) for n in ns]
            if len(kids) == 1:
                return kids[0]
            return {"t": "and" if q == "all" else "or", "c": kids}
        name = eat()
        if name not in sels:
            raise Unsupported(f"condition refers to unknown selection {name}")
        return selection_ast(sels[name], name)

    def term():
        left = [factor()]
        while peek() == "and":
            eat()
            left.append(factor())
        return left[0] if len(left) == 1 else {"t": "and", "c": left}

    def expr():
        left = [term()]
        while peek() == "or":
            eat()
            left.append(term())
        return left[0] if len(left) == 1 else {"t": "or", "c": left}

    e = expr()
    if i != len(toks):
        raise Unsupported(f"trailing tokens in condition: {cond!r}")
    return e


def push_not(n, neg=False):
    if n["t"] == "not":
        return push_not(n["c"], not neg)
    if n["t"] in ("and", "or"):
        t = n["t"] if not neg else ("or" if n["t"] == "and" else "and")
        return {"t": t, "c": [push_not(c, neg) for c in n["c"]]}
    return dict(n, neg=n["neg"] ^ neg)


# ----------------------------------------------------------- emit leaves
class Emitter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.notes = set()

    def raw_keys(self, field):
        lf = field.lower()
        keys = []
        if self.cfg.get("aliases") and lf in self.cfg["aliases"]:
            keys += self.cfg["aliases"][lf]
        if self.cfg.get("keyfn"):
            keys += self.cfg["keyfn"](field)
        keys.append(field)
        if "." in field:
            keys.append(field.rsplit(".", 1)[1])
        out, seen = [], set()
        for k in keys:
            if k.lower() not in seen:
                seen.add(k.lower())
                out.append(k)
        return out

    def key_rx(self, field):
        return r'\\?"(?:' + "|".join(re.escape(k) for k in self.raw_keys(field)) + r')\\?"\s*:\s*\[?\s*'

    @staticmethod
    def kind(mods):
        for k in ("contains", "startswith", "endswith", "re", "exists"):
            if k in mods:
                return k
        return "eq"

    def leaf(self, n):
        field, mods, values, neg = n["field"], n["mods"], n["values"], n["neg"]
        kind = self.kind(mods)
        is_all = "all" in mods
        if field is None:
            return self.keywords(values, neg)
        prop = self.cfg["props"].get(field.lower())
        if kind == "exists":
            want = bool(values[0]) ^ neg
            if prop:
                return [{"name": prop, "operator": "IS_NOT_NULL" if want else "IS_NULL"}]
            k = self.key_rx(field)
            if want:
                return [{"name": "jsonData", "operator": "RE_MATCH", "value": k + r'[^n\s]'}]
            return [{"name": "jsonData", "operator": "DOES_NOT_CONTAIN",
                     "values": [f'"{key}":' for key in self.raw_keys(field)]}]
        if any(v is None for v in values):
            if len(values) > 1:
                raise Unsupported("null mixed with values")
            if prop:
                return [{"name": prop, "operator": "IS_NOT_NULL" if neg else "IS_NULL"}]
            if neg:
                return [{"name": "jsonData", "operator": "DOES_NOT_CONTAIN",
                         "values": [f'"{k}":null' for k in self.raw_keys(field)]}]
            return [{"name": "jsonData", "operator": "RE_MATCH", "value": self.key_rx(field) + "null"}]
        values = [scalar(v) for v in values]
        if prop:
            tf = self.cfg.get("transform", {}).get(prop)
            if tf:
                values = [tf(v) for v in values]
            return self.prop_leaf(prop, kind, values, neg, is_all)
        return self.raw_leaf(field, kind, values, neg, is_all)

    # -- normalized property
    def prop_leaf(self, prop, kind, values, neg, is_all):
        wild = kind == "re" or any(has_wildcard(v) for v in values)
        if wild:
            if neg:
                raise Unsupported(f"negated wildcard/regex on {prop}")
            rx = []
            for v in values:
                if kind == "re":
                    rx.append(v)
                    continue
                body = to_regex(v, ".*", ".")
                pre = "" if kind in ("contains", "endswith") else "^"
                post = "" if kind in ("contains", "startswith") else "$"
                rx.append(pre + body + post)
            if is_all:
                return {"and": [{"name": prop, "operator": "RE_MATCH", "value": r} for r in rx]}
            return [{"name": prop, "operator": "RE_MATCH_ANY" if len(rx) > 1 else "RE_MATCH",
                     **({"values": rx} if len(rx) > 1 else {"value": rx[0]})}]
        vals = [literal(v) for v in values]
        pos_one = {"eq": "EQUAL", "contains": "CONTAINS", "startswith": "STARTS_WITH", "endswith": "ENDS_WITH"}[kind]
        pos_any = {"eq": "IN", "contains": "CONTAINS_ANY", "startswith": "STARTS_WITH_ANY", "endswith": "ENDS_WITH_ANY"}[kind]
        neg_one = {"eq": "NOT_EQUAL", "contains": "DOES_NOT_CONTAIN", "startswith": "DOES_NOT_START_WITH",
                   "endswith": "DOES_NOT_END_WITH"}[kind]
        single = lambda op, v: {"name": prop, "operator": op, "value": v}
        if not neg:
            if is_all and len(vals) > 1:
                return {"and": [single(pos_one, v) for v in vals]}
            if len(vals) == 1:
                return [single(pos_one, vals[0])]
            return [{"name": prop, "operator": pos_any, "values": vals}]
        # NOT (v1 or v2) -> none of them; NOT (v1 and v2) [all] -> any is missing
        if is_all and len(vals) > 1:
            return {"or": [single(neg_one, v) for v in vals]}
        if len(vals) == 1:
            return [single(neg_one, vals[0])]
        if kind == "eq":
            return [{"name": prop, "operator": "NOT_IN", "values": vals}]
        if kind == "contains":
            return [{"name": prop, "operator": "DOES_NOT_CONTAIN", "values": vals}]
        return {"and": [single(neg_one, v) for v in vals]}

    # -- raw event (jsonData)
    def raw_leaf(self, field, kind, values, neg, is_all):
        k = self.key_rx(field)
        if not neg:
            rx = []
            for v in values:
                if kind == "re":
                    body = v[1:] if v.startswith("^") else r'[^"]*' + v
                    rx.append(k + r'\\?"?' + body.rstrip("$"))
                    continue
                body = to_regex(v, r'[^"]*', r'[^"]')
                if kind == "eq":
                    rx.append(k + r'\\?"?' + body + r'\\?"?\s*[,}\]]')
                elif kind == "contains":
                    rx.append(k + r'\\?"[^"]*' + body)
                elif kind == "startswith":
                    rx.append(k + r'\\?"' + body)
                else:
                    rx.append(k + r'\\?"[^"]*' + body + r'\\?"')
            if is_all and len(rx) > 1:
                return {"and": [{"name": "jsonData", "operator": "RE_MATCH", "value": r} for r in rx]}
            if len(rx) == 1:
                return [{"name": "jsonData", "operator": "RE_MATCH", "value": rx[0]}]
            return [{"name": "jsonData", "operator": "RE_MATCH_ANY", "values": rx}]
        # negated: the Query Builder has no "does not match regex", so use a literal
        lits = []
        for v in values:
            if kind == "eq" and not has_wildcard(v):
                for key in self.raw_keys(field):
                    lits.append(f'"{key}":"{v}"')
                    if re.fullmatch(r"-?\d+(\.\d+)?|true|false", v, re.I):
                        lits.append(f'"{key}":{v}')
            else:
                lit = longest_literal(v) if kind != "re" else re.sub(r"[\\^$.*+?()\[\]{}|]", "", v)
                if not lit:
                    raise Unsupported(f"negated pattern with no literal text on {field}")
                lits.append(lit)
                self.notes.add(f"exclusion on `{field}` approximated as \"raw event does not contain\"")
        if is_all and len(values) > 1:
            return {"or": [{"name": "jsonData", "operator": "DOES_NOT_CONTAIN", "value": l} for l in lits]}
        return [{"name": "jsonData", "operator": "DOES_NOT_CONTAIN",
                 **({"values": lits} if len(lits) > 1 else {"value": lits[0]})}]

    def keywords(self, values, neg):
        vals = [scalar(v) for v in values]
        if not neg:
            if any(has_wildcard(v) for v in vals):
                rx = [to_regex(v, ".*", ".") for v in vals]
                return [{"name": "jsonData", "operator": "RE_MATCH_ANY" if len(rx) > 1 else "RE_MATCH",
                         **({"values": rx} if len(rx) > 1 else {"value": rx[0]})}]
            return [{"name": "jsonData", "operator": "CONTAINS_ANY" if len(vals) > 1 else "CONTAINS",
                     **({"values": vals} if len(vals) > 1 else {"value": vals[0]})}]
        lits = [longest_literal(v) for v in vals]
        if any(not l for l in lits):
            raise Unsupported("negated keyword with no literal text")
        return [{"name": "jsonData", "operator": "DOES_NOT_CONTAIN",
                 **({"values": lits} if len(lits) > 1 else {"value": lits[0]})}]

    # -- tree
    def node(self, n):
        """Returns ("filters", [..]) or ("expr", {operator, filters|expressions})."""
        if n["t"] == "leaf":
            out = self.leaf(n)
            if isinstance(out, list):
                return ("filters", out, "AND")
            op = "AND" if "and" in out else "OR"
            return ("filters", out["and"] if "and" in out else out["or"], op)
        op = "AND" if n["t"] == "and" else "OR"
        kids = [self.node(c) for c in n["c"]]
        # flatten: children that are plain filter lists with the same operator
        flat, nested = [], []
        for kind, payload, kop in kids:
            if kind == "filters" and (kop == op or len(payload) == 1):
                flat += payload
            elif kind == "expr" and payload["operator"] == op and "filters" in payload:
                flat += payload["filters"]
            else:
                nested.append(payload if kind == "expr" else {"operator": kop, "filters": payload})
        if not nested:
            return ("filters", flat, op)
        exprs = ([{"operator": op, "filters": flat}] if flat else []) + nested
        return ("expr", {"operator": op, "expressions": exprs}, op)

    def properties(self, ast):
        kind, payload, op = self.node(ast)
        if kind == "filters":
            return {"operator": op, "filters": payload}
        return payload


# --------------------------------------------------------------- convert
def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def describe(r, rel, notes):
    lines = [str(r.get("description", "")).strip(), ""]
    tags = [t for t in r.get("tags", []) or [] if str(t).startswith("attack.")]
    if tags:
        lines.append("MITRE ATT&CK: " + ", ".join(t.replace("attack.", "").upper() if re.match(r"attack\.t\d", t)
                                                   else t.replace("attack.", "") for t in tags))
    fps = r.get("falsepositives") or []
    if fps and fps != ["Unknown"]:
        lines.append("False positives: " + "; ".join(str(f) for f in fps))
    if notes:
        lines.append("Conversion notes: " + "; ".join(sorted(notes)) + ".")
    lines += ["",
              f"Source: SigmaHQ rule {r.get('id')} ({rel}), status {r.get('status', 'n/a')}.",
              f"Author: {r.get('author', 'unknown')}."]
    refs = r.get("references") or []
    if refs:
        lines.append("References: " + " ".join(str(x) for x in refs[:5]))
    lines.append(f"License: {LICENSE}.")
    return "\n".join(l for l in lines).strip() + "\n"


def convert(path, sigma_root):
    r = yaml.safe_load(open(path))
    rel = os.path.relpath(path, sigma_root)
    if not isinstance(r, dict) or "detection" not in r:
        raise Unsupported("not a detection rule (correlation/filter)")
    if r.get("status") in ("deprecated", "unsupported"):
        raise Unsupported(f"status {r.get('status')}")
    ls = r.get("logsource", {})
    key = (ls.get("product"), ls.get("service") or ls.get("category"))
    cfg = SOURCES.get(key)
    if not cfg:
        raise Unsupported(f"log source {key[0]}/{key[1]} not mapped")
    det = dict(r["detection"])
    if "timeframe" in det:
        raise Unsupported("timeframe (aggregation)")
    cond = det.pop("condition")
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    ast = push_not(parse_condition(cond, det))
    em = Emitter(cfg)
    props = em.properties(ast)
    sev = SEVERITY.get(str(r.get("level", "medium")).lower(), "MED")
    rule = {
        "package_id": f"com.sigmahq.rules.{cfg['package']}",
        "package_name": f"SigmaHQ {cfg['package'].replace('-', ' ').title().replace('M365', 'Microsoft 365').replace('Aws', 'AWS').replace('Gcp', 'GCP')}",
        "rule_id": f"sigma-{r['id']}",
        "rule_name": f"[Sigma] {r['title']}",
        "description": describe(r, rel, em.notes),
        "data_sources": [cfg["ds"]],
        "status": "disabled",
        "rule_action": {
            "action_type": "create_detection",
            "threat_finding_request": dict(sorted({**THREAT_FINDING_DEFAULTS, "severity": sev}.items())),
        },
        "query": {
            "data_sources_filter": {"sources": [cfg["ds"]]},
            "filter": {"entity_type": cfg["entity"], "properties": props},
            "limit_offset_filter": {"limit": 1000},
        },
    }
    return rule, cfg, bool(em.notes)


class Dumper(yaml.SafeDumper):
    pass


def _str(dumper, s):
    if "\n" in s:
        return dumper.represent_scalar("tag:yaml.org,2002:str", s, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", s)


Dumper.add_representer(str, _str)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--sigma-dir", required=True, help="checkout of github.com/SigmaHQ/sigma")
    ap.add_argument("--out", default=os.path.join(ROOT, "rules", "sigma"))
    ap.add_argument("--dirs", nargs="+", default=["rules/cloud", "rules/identity/okta", "rules/application/github"])
    a = ap.parse_args()

    commit = os.popen(f"git -C {a.sigma_dir} rev-parse --short HEAD 2>/dev/null").read().strip() or "unknown"
    files = sorted(f for d in a.dirs for f in glob.glob(os.path.join(a.sigma_dir, d, "**", "*.yml"), recursive=True))
    converted, skipped, approx = [], [], []
    by_pkg = Counter()
    seen_ids = set()
    for f in files:
        rel = os.path.relpath(f, a.sigma_dir)
        try:
            rule, cfg, is_approx = convert(f, a.sigma_dir)
        except Unsupported as e:
            skipped.append((rel, str(e)))
            continue
        except Exception as e:  # malformed rule: report, never abort the run
            skipped.append((rel, f"error: {type(e).__name__}: {e}"))
            continue
        if rule["rule_id"] in seen_ids:
            skipped.append((rel, "duplicate Sigma id"))
            continue
        seen_ids.add(rule["rule_id"])
        outdir = os.path.join(a.out, cfg["package"])
        os.makedirs(outdir, exist_ok=True)
        out = os.path.join(outdir, os.path.splitext(os.path.basename(f))[0] + ".yaml")
        # Keep an enable/disable decision made since the last import (in Git or,
        # via the drift sync, in the UI) instead of resetting it to disabled.
        if os.path.exists(out):
            try:
                prev = yaml.safe_load(open(out)) or {}
                if prev.get("status") in ("enabled", "disabled"):
                    rule["status"] = prev["status"]
            except yaml.YAMLError:
                pass
        header = ("# Generated by scripts/sigma_import.py from SigmaHQ "
                  f"{rel} @ {commit}.\n# Re-running the importer regenerates this file (status is kept); "
                  "to customize a rule, copy it out of rules/sigma/ under a new rule_id.\n"
                  f"# License: {LICENSE}\n")
        with open(out, "w") as fh:
            fh.write(header)
            yaml.dump(rule, fh, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=100)
        converted.append((rel, os.path.relpath(out, ROOT), rule["rule_name"], cfg["package"]))
        by_pkg[cfg["package"]] += 1
        if is_approx:
            approx.append(rel)

    reasons = Counter(re.sub(r" in \S+$| [A-Za-z_*]+$", "", r) for _, r in skipped)
    rep = [f"# SigmaHQ import report", "",
           f"Generated {datetime.date.today()} from SigmaHQ commit `{commit}` by `scripts/sigma_import.py`.", "",
           f"**{len(converted)} converted**, {len(skipped)} skipped, {len(approx)} with an approximated exclusion.", "",
           "All converted rules deploy **disabled** to every tenant. Enable the ones you want in the UI or by "
           "copying the file out of `rules/sigma/` with `status: enabled`.", "",
           "| Package | Rules |", "|---|---|"]
    rep += [f"| {p} | {n} |" for p, n in sorted(by_pkg.items())]
    rep += ["", "## Skipped, by reason", "", "| Reason | Rules |", "|---|---|"]
    rep += [f"| {r} | {n} |" for r, n in reasons.most_common()]
    rep += ["", "<details><summary>Skipped rules</summary>", ""]
    rep += [f"- `{p}`: {r}" for p, r in skipped]
    rep += ["", "</details>", "", "<details><summary>Rules with an approximated exclusion</summary>", ""]
    rep += [f"- `{p}`" for p in approx]
    rep += ["", "</details>", "", f"License: {LICENSE}. Attribution for each rule is in its description.", ""]
    with open(os.path.join(a.out, "IMPORT_REPORT.md"), "w") as fh:
        fh.write("\n".join(rep))
    print(f"converted {len(converted)}, skipped {len(skipped)}, approximated {len(approx)}")
    for p, n in sorted(by_pkg.items()):
        print(f"  {p}: {n}")
    print("skip reasons:", dict(reasons.most_common(10)))


if __name__ == "__main__":
    sys.exit(main())
