#!/usr/bin/env python3
"""Deploy Sentinel scheduled analytics rules from YAML (source of truth) to a workspace.

Idempotent upsert by rule GUID via the alertRules REST API (api-version 2025-09-01).
Auth: relies on an existing `az` login context (OIDC in CI, or `az login` locally).

Env:
  AZURE_SUBSCRIPTION_ID   target subscription (default: current az account)
  SENTINEL_RESOURCE_GROUP resource group of the workspace (default: sc200-lab)
  SENTINEL_WORKSPACE      Log Analytics workspace name      (default: sc200-ws)
"""
import os
import sys
import json
import glob
import subprocess
import tempfile

API_VERSION = "2025-09-01"
TRIGGER_OP = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "detections", "rules")


def az(*args, body=None):
    cmd = ["az", *args]
    tmp = None
    if body is not None:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(body, tmp)
        tmp.close()
        cmd += ["--body", f"@{tmp.name}"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, shell=(os.name == "nt"))
    finally:
        if tmp:
            os.unlink(tmp.name)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or out.stdout.strip())
    return out.stdout


def build_properties(rule):
    op = TRIGGER_OP.get(str(rule.get("triggerOperator", "gt")).lower(), "GreaterThan")
    # The alertRules API wants parent techniques in `techniques` (T####) and
    # sub-techniques in `subTechniques` (T####.###); splitting keeps both valid.
    techs = rule.get("relevantTechniques", [])
    parents = sorted({t.split(".")[0] for t in techs})
    subs = sorted(t for t in techs if "." in t)
    props = {
        "displayName": rule["name"],
        "description": rule.get("description", ""),
        "severity": rule["severity"],
        "enabled": True,
        "query": rule["query"],
        "queryFrequency": rule["queryFrequency"],
        "queryPeriod": rule["queryPeriod"],
        "triggerOperator": op,
        "triggerThreshold": int(rule.get("triggerThreshold", 0)),
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": rule.get("tactics", []),
        "techniques": parents,
        "entityMappings": rule.get("entityMappings"),
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {"enabled": False, "lookbackDuration": "PT5M",
                                       "matchingMethod": "AllEntities", "reopenClosedIncident": False},
        },
    }
    if subs:
        props["subTechniques"] = subs
    return props


def main():
    sub = os.environ.get("AZURE_SUBSCRIPTION_ID") or az("account", "show", "--query", "id", "-o", "tsv").strip()
    rg = os.environ.get("SENTINEL_RESOURCE_GROUP", "sc200-lab")
    ws = os.environ.get("SENTINEL_WORKSPACE", "sc200-ws")
    base = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
            f"/providers/Microsoft.SecurityInsights/alertRules")

    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.yaml")))
    if not files:
        sys.exit("no rule YAML found")
    print(f"Deploying {len(files)} rule(s) to {ws} (api {API_VERSION})")
    rc = 0
    for f in files:
        rule = yaml.safe_load(open(f, encoding="utf-8"))
        rid = rule["id"]
        body = {"kind": "Scheduled", "properties": build_properties(rule)}
        url = f"{base}/{rid}?api-version={API_VERSION}"
        try:
            az("rest", "--method", "put", "--url", url,
               "--headers", "Content-Type=application/json", "-o", "none", body=body)
            print(f"  OK   {rule['name']}  ({rid})")
        except Exception as e:
            rc = 1
            print(f"  FAIL {rule['name']}: {e}")
    sys.exit(rc)


if __name__ == "__main__":
    main()
