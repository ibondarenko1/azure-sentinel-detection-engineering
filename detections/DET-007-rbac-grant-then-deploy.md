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

One Azure Activity Log caller **creates an RBAC role assignment** and then **deploys a Compute,
Storage, or Web resource** within 30 minutes. Review the assigned role, its recipient, and the
resource before drawing a conclusion about the caller's privileges.

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
| where DeployTime > GrantTime and DeployTime <= (GrantTime + corrWindow)
| summarize GrantTime = min(GrantTime), FirstDeploy = min(DeployTime),
            DeployedResources = make_set(ResourceId, 20), DeployCount = dcount(ResourceId)
    by Caller, GrantIp
```

`Caller` identifies the actor that initiated each operation. The deployment time must be strictly
later than the grant and at most 30 minutes after it.

## Expected result

The fixtures exercise two matching callers, including a deployment exactly 30 minutes after the
grant. The silent fixture covers independent actors, deployments before the grant, equal timestamps,
and a deployment 31 minutes later. [Fixture](../tests/fixtures/DET-007.json)

## Tuning notes

- Adjust `corrWindow` against the timing of approved operational workflows.
- Compare the caller and resource against the relevant deployment or change record. The single-stage
  DET-003 and DET-005 use their own allow-lists.

The historical lab observed one role assignment followed eight minutes later by a deployment.
The current time-boundary cases run in the emulator. [Investigation](../investigations/INV-05-grant-then-deploy.md)
