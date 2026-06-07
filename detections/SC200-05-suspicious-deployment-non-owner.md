# SC200-05 — Suspicious resource deployment by non-owner

| | |
|---|---|
| **ID** | SC200-05 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled |
| **Data source** | `AzureActivity` |
| **MITRE tactic** | Persistence |
| **MITRE technique** | [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) |

## What it catches

A resource **write/deployment performed by a principal that is not the resource/subscription owner**. Attackers who gain a foothold often stand up new resources (compute for mining, storage for staging, functions for persistence) under an account that should not normally be deploying. Deployments by unexpected principals are surfaced for review.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 60 minutes over a 1-hour lookback.

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue endswith "/write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceProviderValue, ResourceId, ActivityStatusValue
```

> **Finding — logic does not match intent.** As deployed, this rule fires on **any** successful control-plane `/write`; it does **not** restrict to non-owner callers or to specific resource types. The "non-owner" intent in the name is not enforced. This is documented here as an honest detection-engineering gap and a v2 tuning target (see tuning notes).

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **SC200-05**. Summary: from a **non-owner** account (Contributor or guest), deploy a resource (e.g. a storage account).

## Expected result

Rule runs hourly. Incident **#1** (Medium) exists from an earlier run; it re-fires on the next scheduled run after the simulated non-owner storage deployment (`storageAccounts/write`, HTTP 202, caller = service principal `sp-soc-sim`).

## Evidence

This detection's alerts appear in the consolidated [SC200 alert queue](../screenshots/05-incidents-queue-populated.png) (Persistence / T1098).

## Tuning notes

The as-deployed query is too broad (any `/write`) and will be noisy in any active subscription. Proposed v2 to make the logic match the intent:

```kql
let owners = dynamic([]);  // known owner UPNs / object IDs
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue endswith "/write"
| where ActivityStatusValue == "Success"
| where ResourceProviderValue in ("Microsoft.Compute", "Microsoft.Storage", "Microsoft.Web")
| where Caller !in (owners)
| project TimeGenerated, Caller, OperationNameValue, ResourceProviderValue, ResourceId
```

- Maintain the `owners` allow-list as the core of fidelity; everyone legitimately deploying must be enumerated.
- Resource type matters — a new `Microsoft.Compute` (VM) by a non-owner is higher signal than storage.

**Evasion.** Even the v2 logic is evaded by an attacker who first adds their principal to the `owners` set (→ chain with [SC200-03](SC200-03-rbac-role-assignment-changes.md)), or deploys a resource type outside the watch-list.

**Validation.** ATT&CK [T1098](https://attack.mitre.org/techniques/T1098/) — loose mapping (resource-creation persistence); validated manually, not in automated regression. See [docs/04-validation.md](../docs/04-validation.md).
