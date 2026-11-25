# Lab workspace bootstrap

`infra/main.bicep` is a subscription-scope entry point for a small Sentinel lab. It
references an existing resource group, creates or references one Log Analytics workspace,
and onboards Sentinel. Subscription Activity Log export is optional and is disabled by
default. The bootstrap deliberately does not create connectors, watchlists, analytics
rules, playbooks, role assignments, private endpoints, or a resource group.

The template has no Azure deployment side effects during local validation. A deployment
must be an explicit operator action after reviewing a subscription `what-if` result.

## Parameters and safety defaults

| Parameter | Default | Effect |
|---|---:|---|
| `resourceGroupName` | required | Name of an existing resource group. The template never creates or updates the group. |
| `workspaceName` | required | Log Analytics workspace name. The template requires at least four characters. |
| `createWorkspace` | `true` | Create the workspace when true; when false, reference the existing workspace without changing its workspace properties. |
| `workspaceLocation` | `''` | Location for a new workspace. Empty uses the existing resource group's location. Set it explicitly for a new lab. |
| `workspaceSkuName` | `PerGB2018` | SKU used only when a new workspace is created. The template does not change an existing workspace SKU. |
| `retentionInDays` | `30` | Interactive retention for a new workspace. Allowed values are `30, 31, 60, 90, 120, 180, 270, 365, 550, 730`. Longer retention can add cost. |
| `dailyQuotaGb` | `1` | Daily ingestion cap for a new workspace. This lab template accepts `1`-`100` GB/day; unlimited (`-1`) and fractional service minimums are intentionally rejected. |
| `onboardExistingWorkspace` | `false` | When false, an existing workspace's Sentinel onboarding and customer-managed-key state are untouched. Set true only when the operator explicitly wants this template to write the onboarding state. |
| `enableActivityLogExport` | `false` | When true, export all subscription Activity Log categories to the selected workspace. |
| `diagnosticSettingName` | required | Caller-chosen name for the subscription diagnostic setting. There is no generated default. |

The new-workspace path sets `disableLocalAuth: true` and
`enableLogAccessUsingOnlyResourcePermissions: true`. This keeps the lab on Entra/Azure
CLI or OIDC authentication and avoids creating a local workspace key dependency. Existing
workspace properties are not reconciled by this template.

The resource-group module in `infra/workspace.bicep` exists because a subscription-scope
parent cannot directly deploy a resource-group-scoped workspace. It conditionally declares
the new workspace, an `Microsoft.SecurityInsights/onboardingStates@2025-09-01` resource,
or an existing workspace reference. For an existing workspace the onboarding resource is
only declared when `onboardExistingWorkspace=true`; this is the explicit migration gate for
an existing customer-managed-key configuration.

### Activity Log destination ownership

Activity Log export is an ARM diagnostic setting named at subscription scope. Azure uses the
name as the resource identity: deploying the same name updates that diagnostic setting. The
template cannot know whether an existing name belongs to another team, so always choose a
name owned by this lab, inspect `what-if`, and stop if the plan updates an unrelated setting.
The default is off, and the template does not delete other diagnostic settings.

## Local Bicep build

`az bicep` was not available on the build host. The local acceptance build used the
official Bicep CLI `v0.49.2` (`b34271ac51`) from the Windows x64 release package. Before
extracting an official package, verify its published SHA-256:

```powershell
$package = 'Azure.Bicep.CommandLine.win-x64.0.49.2.nupkg'
$expected = 'bb71c6149025209a9d2bf321add21cdfc58f99f2e476844229f31464258be6c7'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $package).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Bicep package checksum mismatch'
}
```

Use the direct CLI's positional input syntax (the `az bicep build` wrapper uses a
different `--file` syntax):

```powershell
$bicep = 'C:\Tools\bicep\bicep.exe'
New-Item -ItemType Directory -Path .tmp\bicep -Force | Out-Null
& $bicep build infra\main.bicep --outfile .tmp\bicep\main.json --no-restore
if ($LASTEXITCODE -ne 0) { throw 'Bicep build failed' }
```

The checked-in source has no generated JSON and no Bicep binary. The compiler is expected
to emit no diagnostics for the current files; the build does not authenticate to Azure.

## Preview, then deploy (operator-only)

After an Azure CLI sign-in, use an explicit subscription and existing resource group. This
example references an already-created workspace and leaves both onboarding mutation and
Activity Log export off:

```powershell
az deployment sub what-if `
  --name sentinel-lab-bootstrap-preview `
  --location eastus `
  --subscription SUBSCRIPTION_GUID `
  --template-file infra/main.bicep `
  --parameters resourceGroupName=sc200-lab `
               workspaceName=sc200-ws `
               createWorkspace=false `
               workspaceLocation=eastus `
               onboardExistingWorkspace=false `
               enableActivityLogExport=false `
               diagnosticSettingName=sentinel-lab-activity
```

For a new workspace, use `createWorkspace=true`, pass an explicit
`workspaceLocation`, and review the retention and quota values. To opt in to Activity Log
export, set `enableActivityLogExport=true` and use a unique, caller-owned
`diagnosticSettingName`; inspect the complete `what-if` for same-name updates before
applying it. A preview does not write resources.

Only after that review should an operator run the equivalent deployment:

```powershell
az deployment sub create `
  --name sentinel-lab-bootstrap `
  --location eastus `
  --subscription SUBSCRIPTION_GUID `
  --template-file infra/main.bicep `
  --parameters resourceGroupName=sc200-lab `
               workspaceName=sc200-ws `
               createWorkspace=false `
               workspaceLocation=eastus `
               onboardExistingWorkspace=false `
               enableActivityLogExport=false `
               diagnosticSettingName=sentinel-lab-activity
```

The repository task intentionally does not run either command. The authenticated training
subscription did not contain the expected `sc200`/`sentinel` targets at acceptance time, so
this change is validated locally only.

## DET-001 validation flow

The bootstrap only supplies the `AzureActivity` path; it does not deploy an analytics rule.
Use this sequence after an authorized deployment and data-connector setup:

1. Run the offline catalog check, which does not require Azure:

   ```powershell
   python cicd/validate-detections.py --rule DET-001
   ```

2. Run the synthetic Kusto suite when its local Docker emulator is available:

   ```powershell
   python tests/run-detection-tests.py
   ```

   `tests/fixtures/DET-001.json` contains eight failed operations for the firing caller
   and a below-threshold control. The fixture validates the rule logic, not Azure ingestion
   or Sentinel scheduling.

3. In the named workspace, confirm that Activity Log records arrive before checking the
   rule. The source query is:

   ```kusto
   AzureActivity
   | where TimeGenerated > ago(1h)
   | where ActivityStatusValue == "Failure"
   | where isnotempty(Caller)
   | summarize FailureCount = count() by Caller, bin(TimeGenerated, 5m)
   | where FailureCount >= 8
   ```

4. Deploy or update DET-001 through the existing detection-as-code flow in
   [`docs/03-cicd.md`](03-cicd.md). The bootstrap itself creates no scheduled analytics
   rule and no incident.

Do not generate failed operations merely to test this documentation. Use existing lab
telemetry or a separately approved low-risk validation, and record the workspace, time
window, rule version, and readback evidence when a live check is authorized.

## References and limits

- [Bicep installation and CLI documentation](https://learn.microsoft.com/azure/azure-resource-manager/bicep/install)
- [Official Bicep releases and checksums](https://github.com/Azure/bicep/releases)
- [Log Analytics workspace resource](https://learn.microsoft.com/en-us/azure/templates/microsoft.operationalinsights/2023-09-01/workspaces)
- [Sentinel onboarding state resource](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/2025-09-01/onboardingstates)
- [Diagnostic settings](https://learn.microsoft.com/azure/azure-monitor/data-collection/diagnostic-settings)
- [Activity Log export with diagnostic settings](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log)
- [Log Analytics daily cap](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/daily-cap)
- [Azure Monitor service limits and retention](https://learn.microsoft.com/en-us/azure/azure-monitor/service-limits)

The retention and quota guardrails apply only when this template creates the workspace;
the existing-workspace path does not update those settings. Daily caps stop ingestion when
the cap is reached and are not a substitute for cost monitoring. Public network access,
connectors, private networking, and permissions remain operator decisions outside this
minimal bootstrap.
