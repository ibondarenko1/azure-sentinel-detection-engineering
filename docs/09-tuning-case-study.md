# Tuning case study: DET-005, from "every write" to a measured zero-FP

Writing a rule is the easy half. The job is the loop after it ships: observe, diagnose, tune, and
**measure** that the change actually reduced noise. This is one such loop, with real before/after,
on [DET-005](../detections/DET-005-suspicious-deployment-non-owner.md).

## The loop

```
hypothesis -> deploy -> observe -> diagnose -> tune -> measure -> repeat
```

## v1: the rule did not match its name

DET-005 is called "suspicious resource deployment by non-owner". As first deployed, the query was:

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue endswith "/write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceProviderValue, ResourceId
```

It matched **any** successful control-plane write by **anyone**. The "non-owner" intent was not
enforced and the resource type was not scoped. In an active subscription this fires on every
legitimate deployment: the false-positive rate is high by construction, not by accident. This was
documented honestly in the card as a known fidelity gap rather than hidden behind a "0% FP" claim.

## Diagnosis: ground the fix in the real records, not assumptions

Before tightening, the live `AzureActivity` records were inspected (the same discipline as the rest
of the catalog), which decided the v2 shape:

- `ResourceProviderValue` arrives **upper-case** (`MICROSOFT.STORAGE`), so a case-sensitive `in`
  filter would silently match nothing. v2 uses `in~`.
- `Caller` is a UPN for users; there is no caller object-id or owner flag in the record. So the
  non-owner test has to be an explicit allow-list keyed on `Caller`.
- Committing real UPNs to a public repo is not acceptable, so the allow-list lives in a Sentinel
  **watchlist** (`soc-deploy-owners`) read with `_GetWatchlist`, not inline.

## v2: enforce the intent, scope to the risk

```kql
let owners = _GetWatchlist('soc-deploy-owners') | project SearchKey;
let watchedProviders = dynamic(["Microsoft.Compute", "Microsoft.Storage", "Microsoft.Web"]);
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue endswith "/write"
| where ActivityStatusValue == "Success"
| where ResourceProviderValue in~ (watchedProviders)
| where Caller !in~ (owners)
| extend CallerIp = tostring(parse_json(tostring(Properties_d.httpRequest)).clientIpAddress)
| project TimeGenerated, Caller, CallerIp, OperationNameValue, ResourceProviderValue, ResourceId
```

Two filters do the work: scope to the providers that carry the risk (Compute/Storage/Web), and
exclude principals on the deploy-owner allow-list. Shipped through the pipeline in PR #24.

## Measure: prove the noise dropped

Asserting "this is better" is not enough; it was measured on the [validation harness](../validation),
which runs a real benign action and checks the rule stays silent.

| | v1 (any write) | v2 (owner allow-list + provider scope) |
|---|---|---|
| Allow-listed **owner** deploys Storage | **fires** (false positive, by construction) | **silent** (measured 0, [RESULTS.md](../validation/RESULTS.md)) |
| **Non-owner** deploys Compute/Storage/Web | fires | fires (true positive, intent now enforced) |
| Owner deploys an unwatched provider | fires (noise) | silent (out of scope) |

The benign owner-deploy in the validation run produced **0** DET-005 incidents. The false-positive
surface went from "every legitimate deployment" to "0 on the measured benign batch", and the rule now
fires for the case its name promises.

## The same fix was a class, not a one-off

DET-002 and DET-003 had the identical defect (firing on the bare fact of an operation). The same loop
applied: diagnose against the live record (no NSG body, no role in the data), add the data-supported
fidelity dimension (an IaC / automation allow-list), and measure. See their cards and
[validation/RESULTS.md](../validation/RESULTS.md).

## Lesson

Fidelity tuning is three concrete moves: make the logic match the rule's stated intent, ground every
filter in field values that actually exist in the telemetry, and **measure the false-positive drop on
a benign batch** instead of asserting it. The watchlist keeps the maintenance burden honest: the
expected false positive is "a legitimate deployer not yet on the list", fixed by adding them, not by
loosening the rule.
