#!/usr/bin/env python3
"""Detection regression: trigger atomic-aligned actions, assert each rule fires.

Scoped on purpose: only the detections whose triggers need **Contributor on the workspace resource group**
(NSG modification, mass deletion). The CI identity therefore needs no role-assignment
(User Access Administrator) or subscription-scope rights, least privilege for the pipeline.
RBAC / failed-ops / non-owner triggers are validated manually (see trigger-playbook).

For each covered rule: run the `az` trigger, poll the Sentinel incidents API for a new
incident, assert it fired within the rule's frequency + ingestion budget, clean up.
Exit non-zero on miss.

Auth: existing `az` context (OIDC in CI, or `az login` locally).
Env: AZURE_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP (workspace RG), SENTINEL_WORKSPACE.
"""
import os
import sys
import json
import time
import datetime
import subprocess

API_INC = "2023-11-01"
LOC = "eastus"
# rule title -> max minutes to wait (rule queryFrequency + AzureActivity ingestion budget).
# AzureActivity (control-plane) ingestion into Log Analytics is variable and can run well past
# an hour on a slow day; a 2026-06-15 run saw the incidents land ~89 min after the trigger, past
# the old 45 min budget, even though both rules fired correctly. The budget is the worst-case
# ingestion lag plus the rule's schedule, not the typical case.
EXPECT = {
    "[DET] Network Security Group rule modified": 120,
    "[DET] Mass resource deletion": 105,
}


def az(*args, check=True):
    r = subprocess.run(["az", *args], capture_output=True, text=True, shell=(os.name == "nt"))
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or r.stdout.strip())
    return r.stdout.strip()


def trigger(rg):
    print("== triggers (scoped to %s, Contributor only) ==" % rg)
    # DET-002 NSG rule create + delete
    az("network", "nsg", "create", "-g", rg, "-n", "nsg-reg", "-l", LOC, "--only-show-errors", "-o", "none")
    az("network", "nsg", "rule", "create", "-g", rg, "--nsg-name", "nsg-reg", "-n", "reg-open",
       "--priority", "1000", "--direction", "Inbound", "--access", "Allow", "--protocol", "Tcp",
       "--source-address-prefixes", "*", "--source-port-ranges", "*",
       "--destination-address-prefixes", "*", "--destination-port-ranges", "3389", "--only-show-errors", "-o", "none")
    az("network", "nsg", "rule", "delete", "-g", rg, "--nsg-name", "nsg-reg", "-n", "reg-open", "--only-show-errors", "-o", "none")
    print("  NSG rule create+delete: ok")
    # DET-004 mass delete: create 5 public IPs then delete them (>=5 delete ops / 5m)
    for i in range(1, 6):
        az("network", "public-ip", "create", "-g", rg, "-n", f"pip-reg-{i}", "--sku", "Standard",
           "--allocation-method", "Static", "-l", LOC, "--only-show-errors", "-o", "none")
    for i in range(1, 6):
        az("network", "public-ip", "delete", "-g", rg, "-n", f"pip-reg-{i}", "--only-show-errors")
    print("  mass delete (5 public IPs): ok")


def poll(sub, rg, ws, cutoff):
    base = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
            f"/providers/Microsoft.SecurityInsights/incidents?api-version={API_INC}&$top=60")
    deadline = time.time() + max(EXPECT.values()) * 60
    found = {}
    print("== polling incidents ==")
    while time.time() < deadline and len(found) < len(EXPECT):
        try:
            data = json.loads(az("rest", "--method", "get", "--url", base, "-o", "json"))
        except Exception as e:
            print("  poll error:", e); time.sleep(60); continue
        for it in data.get("value", []):
            p = it.get("properties", {})
            t, created = p.get("title", ""), p.get("createdTimeUtc", "")
            if t in EXPECT and t not in found and created > cutoff:
                found[t] = p.get("incidentNumber")
                print(f"  FIRED  {t}  (#{found[t]})")
        if len(found) < len(EXPECT):
            time.sleep(60)
    return found


def cleanup(rg):
    print("== cleanup ==")
    az("network", "nsg", "delete", "-g", rg, "-n", "nsg-reg", "--only-show-errors", check=False)
    for i in range(1, 6):
        az("network", "public-ip", "delete", "-g", rg, "-n", f"pip-reg-{i}", "--only-show-errors", check=False)


def main():
    sub = os.environ.get("AZURE_SUBSCRIPTION_ID") or az("account", "show", "--query", "id", "-o", "tsv")
    rg = os.environ.get("SENTINEL_RESOURCE_GROUP", "sc200-lab")
    ws = os.environ.get("SENTINEL_WORKSPACE", "sc200-ws")
    cutoff = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    try:
        trigger(rg)
        found = poll(sub, rg, ws, cutoff)
    finally:
        cleanup(rg)
    missing = [t for t in EXPECT if t not in found]
    print(f"\nfired {len(found)}/{len(EXPECT)}")
    if missing:
        for m in missing:
            print(f"  MISS  {m}")
        sys.exit(1)
    print("regression PASS")


if __name__ == "__main__":
    main()
