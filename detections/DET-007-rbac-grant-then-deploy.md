# DET-007, Privilege grant followed by deployment (same principal)

| | |
|---|---|
| **ID** | DET-007 |
| **Severity** | **High** |
| **Rule type** | Scheduled analytics rule (multi-stage correlation) |
| **Status** | Enabled |
| **Data source** | `AzureActivity` (self-join) |
| **MITRE tactic** | Privilege Escalation / Persistence |
| **MITRE technique** | [T1098, Account Manipulation](https://attack.mitre.org/techniques/T1098/) |

## What it catches

The **escalation-then-action** chain: one principal **creates an RBAC role assignment** and then
**deploys a resource** (Compute / Storage / Web) **within 30 minutes**. Each half is its own
single-stage rule, [DET-003](DET-003-rbac-role-assignment-changes.md) (the grant) and
[DET-005](DET-005-suspicious-deployment-non-owner.md) (the deploy). DET-007 is the correlation an
atomic catalog misses: granting access and immediately using it is the behaviour, not either event
in isolation. It is **deterministic** (a time-bounded self-join), not a threshold or a baseline.

## Detection logic

Runs every 30 minutes over a 2-hour lookback; correlation window 30 minutes.

```kql
let corrWindow = 30m;
let grants =
    AzureActivity
    | where TimeGenerated > ago(2h)
    | where OperationNameValue has "Microsoft.Authorization/roleAssignments/write"
    | where ActivityStatusValue == "Success"
    | extend GrantIp = tostring(parse_json(tostring(Properties_d.httpRequest)).clientIpAddress)
    | project GrantTime = TimeGenerated, Caller, GrantIp;
let deploys =
    AzureActivity
    | where TimeGenerated > ago(2h)
    | where OperationNameValue endswith "/write"
    | where ActivityStatusValue == "Success"
    | where ResourceProviderValue in~ ("Microsoft.Compute", "Microsoft.Storage", "Microsoft.Web")
    | project DeployTime = TimeGenerated, Caller, DeployOp = OperationNameValue, ResourceId;
grants
| join kind=inner deploys on Caller
| where DeployTime between (GrantTime .. (GrantTime + corrWindow))
| summarize GrantTime = min(GrantTime), FirstDeploy = min(DeployTime),
            DeployedResources = make_set(ResourceId, 20), DeployCount = dcount(ResourceId)
    by Caller, GrantIp
```

The join is on `Caller`; the `between` clause enforces *deploy after grant, within the window*, so
a deploy that precedes the grant or lands more than 30 minutes later does not correlate.

## How to trigger (simulation)

From one principal: add a role assignment (`Microsoft.Authorization/roleAssignments/write`), then
within 30 minutes deploy a Compute/Storage/Web resource. The pair raises one incident.

## Expected result

Fires only when the same caller's grant is followed by a watched-provider deploy inside the window;
silent for a lone grant, a lone deploy, a deploy-before-grant, the two steps by different callers,
or steps more than 30 minutes apart (see `tests/fixtures/DET-007.json`).

## Tuning notes

- `corrWindow` is the sensitivity knob; widen for slower operators, narrow to cut admin-session noise.
- Pairs with the v2 single-stage rules: an automation principal allow-listed in `soc-automation-principals`
  / `soc-deploy-owners` is already suppressed upstream, so DET-007 focuses on un-allow-listed chains.

**Evasion.** Split the two steps across more than 30 minutes, use two principals (grant with one,
deploy with another), or grant via PIM/group membership so the `roleAssignments/write` is delayed.

**Validation.** Fixture fire/silent in `tests/fixtures/DET-007.json` (run by `tests/run-detection-tests.py`);
ATT&CK [T1098](https://attack.mitre.org/techniques/T1098/). See [docs/04-validation.md](../docs/04-validation.md).
