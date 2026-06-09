# DET-003, RBAC role assignment changes

| | |
|---|---|
| **ID** | DET-003 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled (v2, automation allow-list) |
| **Data source** | `AzureActivity` + `soc-automation-principals` watchlist |
| **MITRE tactic** | Privilege Escalation / Persistence |
| **MITRE technique** | [T1098, Account Manipulation](https://attack.mitre.org/techniques/T1098/) |

## What it catches

Creation of an Azure **RBAC role assignment**. Granting a role (especially Owner/Contributor/User Access Administrator) to a new principal is a primary privilege-escalation and persistence mechanism in the cloud, it survives password resets and is easy to overlook. Every role grant is surfaced for review.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 30 minutes over a 1-hour lookback. Matches both role-assignment **writes** and **deletes** by a caller **not** on the automation/PIM allow-list.

```kql
let automation = _GetWatchlist('soc-automation-principals') | project SearchKey;
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "Microsoft.Authorization/roleAssignments"
| where ActivityStatusValue == "Success"
| where Caller !in~ (automation)
| extend CallerIp = tostring(parse_json(tostring(Properties_d.httpRequest)).clientIpAddress)
| project TimeGenerated, Caller, CallerIp, OperationNameValue, ResourceId
```

> **Data-grounded scope.** The live `roleAssignments` record carries the caller and source IP
> (`Properties_d.httpRequest.clientIpAddress`) but **not** the role definition or target principal,
> so the rule cannot filter by the role granted. The **`soc-automation-principals` watchlist** is the
> fidelity dimension the data supports: routine grants come from automation and PIM, so allow-listing
> those surfaces ad-hoc grants by users/unexpected principals. `in~` handles mixed-case callers.

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **DET-003**. Summary: Subscription/RG → Access control (IAM) → **Add role assignment** → Reader → assign to a user/second account → then **Remove** it.

## Expected result

**Confirmed:** incident **#2** (Medium) raised 2026-06-07 ~03:29 UTC, `roleAssignments/write` (Reader) + delete on scope `rg-soc-sim`, caller `ievgen@<redacted-tenant>`.

## Evidence

![RBAC role assignment alert](../screenshots/06-inc-03-overview.png)

Full investigation: [INV-02](../investigations/INV-02-rbac-privilege-escalation.md).

## Tuning notes

**Threshold rationale.** No count threshold, every successful `roleAssignments` write/delete is reviewed, since one grant can be full persistence.

**Known false positives.** An automation/PIM principal missing from `soc-automation-principals` (add it to the watchlist rather than loosening the rule); group-membership-driven access reviews.

**Tightening trade-off.** Filtering to only Owner/Contributor/User Access Administrator (vs Reader) cuts volume sharply but misses scoped-but-sensitive data roles (e.g. Key Vault / Storage data roles) that also enable abuse.

**Evasion.** A patient actor uses **PIM eligible** assignments (activate later), modifies an *existing* assignment's scope, grants via group membership, or assigns a custom role with an innocuous name. Enrich with the role granted and the caller's own privilege.

**Validation.** Fixture fire/silent in `tests/fixtures/DET-003.json` (run by `tests/run-detection-tests.py` with the watchlist stubbed from the fixture); ATT&CK [T1098.003](https://attack.mitre.org/techniques/T1098/003/), Additional Cloud Roles; see [docs/04-validation.md](../docs/04-validation.md).
