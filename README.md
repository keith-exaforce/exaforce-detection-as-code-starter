# Exaforce Detection-as-Code starter

Manage your Exaforce Threat Rules as code: write each rule as a YAML file, review it in a pull
request, and let GitHub Actions validate it against your tenant and deploy it on merge.

> **Setup guide:** follow the *Exaforce Detection-as-Code: Setup and Operations Guide* your
> Exaforce team shared with you. It walks through every step on the Exaforce side and the GitHub
> side, plus troubleshooting.

## What's in here

| Path | What it does |
|---|---|
| `rules/` | One YAML file per Threat Rule. This folder is the source of truth. |
| `rules/examples/sample_failed_signin_from_kp.yaml` | A sample rule (disabled) that validates on any tenant. Use it for your first end-to-end test. |
| `push_detections.py` | Validates and deploys rules through the Exaforce Threat Rules API. |
| `.github/workflows/deploy-detections.yml` | CI/CD: validate on every PR, deploy on merge to `main`. |
| `.github/workflows/drift-sync.yml` | Pulls rules created or edited in the Exaforce UI back into Git as a PR. Manual until you turn on its schedule. |
| `scripts/rule_targets.py` | Decides which tenants a rule deploys to (`tenants:` field or a folder's `_tenants.yml`). |
| `scripts/check_duplicates.py` | Fails the build if two files would deploy the same `rule_id` to one tenant. |
| `scripts/pull_rules.py` | The engine behind drift sync. |
| `scripts/sigma_import.py` | Converts SigmaHQ rules into Exaforce rule files in bulk. |
| `.drift-ignore` | `rule_id` patterns drift sync should never import. |

## Quick setup (summary)

1. In Exaforce: **Settings → User Management → My Settings → API Tokens → Generate token**.
   Copy it right away; it is shown only once.
2. In this repo: **Settings → Environments → New environment** named `prod`, then add
   * secret `EXF_API_TOKEN` = the token
   * variable `EXF_BASE_URL` = your tenant URL, e.g. `https://acme.us.app.exaforce.io`
   * variable `EXF_PROJECT` = `default`
3. More than one tenant? Create one environment per tenant and set the repository variable
   `EXF_TENANTS` to the names, space-separated (e.g. `prod staging`).
4. Test it: open a PR that changes `severity` in the sample rule. The **validate (prod)** check
   should pass. Merge it and the **deploy (prod)** job creates the rule (disabled) in your tenant.

## Run it from your laptop

```bash
pip install -r requirements.txt
export EXF_API_TOKEN=...                                  # never commit this
export EXF_BASE_URL=https://<your-tenant>.us.app.exaforce.io
export EXF_PROJECT=default

python3 push_detections.py --validate-only rules/examples/sample_failed_signin_from_kp.yaml
python3 push_detections.py --dry-run       rules/examples/sample_failed_signin_from_kp.yaml
python3 push_detections.py --sync          rules/examples/sample_failed_signin_from_kp.yaml
python3 push_detections.py --status        rules/examples/sample_failed_signin_from_kp.yaml
```

`rule_version` is derived from Git history automatically, so you never bump it by hand.
