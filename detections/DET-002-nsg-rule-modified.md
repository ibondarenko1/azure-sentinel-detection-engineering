# DET-002, Network Security Group rule modified

| | |
|---|---|
| **ID** | DET-002 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled (v2, IaC allow-list) |
| **Data source** | `AzureActivity` + `soc-nsg-change-principals` watchlist |
| **MITRE tactic** | Defense Evasion |
| **MITRE technique** | [T1562, Impair Defenses](https://attack.mitre.org/techniques/T1562/) |

## What it catches

Creation, modification, or deletion of a **Network Security Group rule**. Loosening an NSG (e.g. opening RDP/SSH to the internet) is a classic move to weaken network defenses and open a path in or out. Any change to NSG rules is worth surfacing for review.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 30 minutes over a 1-hour lookback. Matches NSG `securityRules` writes/deletes by a caller **not** on the IaC change-management allow-list.

```kql
let nsgAutomation = _GetWatchlist('soc-nsg-change-principals') | project SearchKey;
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "Microsoft.Network/networkSecurityGroups/securityRules"
| where ActivityStatusValue == "Success"
| where Caller !in~ (nsgAutomation)
| extend CallerIp = tostring(parse_json(tostring(Properties_d.httpRequest)).clientIpAddress)
| extend Action = tostring(split(OperationNameValue, "/")[-1])
| project TimeGenerated, Caller, CallerIp, Action, OperationNameValue, ResourceId
```

> **Data limitation (honest boundary).** AzureActivity records *that* an NSG rule changed, not the
> rule's content: the `securityRules` write record carries no `access` / `direction` /
> `sourceAddressPrefix` (verified against the live `Properties_d`). So this rule **cannot** decide
> whether the change opened *inbound Allow from Any*, only that an NSG rule was changed by a
> non-allow-listed principal. Detecting the content-level condition needs the NSG rule config from
> **Azure Resource Graph** (`resourcechanges`) or NSG diagnostics; that is tracked as a follow-up
> data-onboarding item (`metadata.contentLimitation`), not faked from data that does not carry it.

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **DET-002**. Summary: Portal → Network security groups → Inbound security rules → **Add** a rule (e.g. allow 3389 from Any) → Save → then **Delete** that rule.

## Expected result

**Confirmed:** incident **#5** (Medium) raised 2026-06-07 ~03:30 UTC, NSG `securityRules/write` + `/delete` on `nsg-sim`, caller `ievgen@<redacted-tenant>`.

## Evidence

This detection's alert appears in the consolidated [consolidated alert queue](../screenshots/05-incidents-queue-populated.png) (Defense Evasion / T1562).

## Tuning notes

**Threshold rationale.** No count threshold, any NSG `securityRules` write/delete is surfaced, because a single rule change can fully open an attack path.

**Known false positives.** An IaC/change-management principal missing from `soc-nsg-change-principals` (add it to the watchlist). The remaining noise is changes that are authorized but not from a known automation identity, triaged by inspecting the rule.

**Tightening trade-off.** Filtering to only internet-facing management ports cuts noise hard but misses lateral-movement enablers (e.g. opening SMB/WinRM internally).

**Evasion.** An attacker can avoid NSG writes entirely by attaching resources to a permissive existing subnet, modifying a route table or Azure Firewall instead, or disabling NSG flow logs. Treat this as one signal among network-change detections, not a sole control.

**Validation.** Fixture fire/silent in `tests/fixtures/DET-002.json` (run by `tests/run-detection-tests.py` with the watchlist stubbed from the fixture); ATT&CK [T1562.007](https://attack.mitre.org/techniques/T1562/007/), Disable or Modify Cloud Firewall; see [docs/04-validation.md](../docs/04-validation.md).
