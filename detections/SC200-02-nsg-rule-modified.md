# SC200-02 — Network Security Group rule modified

| | |
|---|---|
| **ID** | SC200-02 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled |
| **Data source** | `AzureActivity` |
| **MITRE tactic** | Defense Evasion |
| **MITRE technique** | [T1562 — Impair Defenses](https://attack.mitre.org/techniques/T1562/) |

## What it catches

Creation, modification, or deletion of a **Network Security Group rule**. Loosening an NSG (e.g. opening RDP/SSH to the internet) is a classic move to weaken network defenses and open a path in or out. Any change to NSG rules is worth surfacing for review.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 30 minutes over a 1-hour lookback.

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "Microsoft.Network/networkSecurityGroups/securityRules"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceId
```

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **SC200-02**. Summary: Portal → Network security groups → Inbound security rules → **Add** a rule (e.g. allow 3389 from Any) → Save → then **Delete** that rule.

## Expected result

**Confirmed:** incident **#5** (Medium) raised 2026-06-07 ~03:30 UTC — NSG `securityRules/write` + `/delete` on `nsg-sim`, caller `ievgen@summitrangeconsulting.com`.

## Evidence

This detection's alert appears in the consolidated [SC200 alert queue](../screenshots/05-incidents-queue-populated.png) (Defense Evasion / T1562).

## Tuning notes

**Threshold rationale.** No count threshold — any NSG `securityRules` write/delete is surfaced, because a single rule change can fully open an attack path.

**Known false positives.** Legitimate network change management; IaC applying NSG updates. Pair with a change-management allow-list, or scope to "rule allows source `*`/`Internet` on a management port" for higher fidelity.

**Tightening trade-off.** Filtering to only internet-facing management ports cuts noise hard but misses lateral-movement enablers (e.g. opening SMB/WinRM internally).

**Evasion.** An attacker can avoid NSG writes entirely by attaching resources to a permissive existing subnet, modifying a route table or Azure Firewall instead, or disabling NSG flow logs. Treat this as one signal among network-change detections, not a sole control.

**Validation.** ATT&CK [T1562.007](https://attack.mitre.org/techniques/T1562/007/) — Disable or Modify Cloud Firewall; covered by [automated regression](../docs/04-validation.md).
