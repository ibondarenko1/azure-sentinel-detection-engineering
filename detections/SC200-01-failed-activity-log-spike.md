# SC200-01 — Failed Activity Log operations spike

| | |
|---|---|
| **ID** | SC200-01 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled |
| **Data source** | `AzureActivity` |
| **MITRE tactic** | Discovery |
| **MITRE technique** | [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) |

## What it catches

A burst of **failed** Azure control-plane operations from a single caller in a short window. Attackers (and compromised principals) probe what they can touch, generating a spike of authorization failures before they find a permitted path. A sudden cluster of `Failure` operations is an early recon signal.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 15 minutes over a 1-hour lookback.

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where ActivityStatusValue == "Failure"
| summarize FailureCount = count() by Caller, bin(TimeGenerated, 5m)
| where FailureCount >= 8
```

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **SC200-01**. Summary: from a low-privilege / second account, repeatedly attempt operations you are not authorized for (~10+ within one hour) — e.g. delete a resource or read a Key Vault secret you lack rights to.

## Expected result

**Confirmed:** incident **#4** (Medium) raised 2026-06-07 ~03:29 UTC — caller `ievgen@summitrangeconsulting.com`, 12 failed `publicIPAddresses/write` operations in one 5-minute bin.

## Evidence

This detection's alert appears in the consolidated [SC200 alert queue](../screenshots/05-incidents-queue-populated.png) (Discovery / T1087).

## Tuning notes

**Threshold rationale.** `>= 8` failures per 5-minute bin per caller (tightened from 10 via [PR #1](https://github.com/ibondarenko1/azure-soc-detection-lab/pull/1)) — clears normal transient failures (token refresh, eventual-consistency retries) while catching a deliberate probing burst.

**Known false positives.** Automation / service principals hitting RBAC limits; IaC drift and failed deployments that retry. Allow-list known service principals before raising severity.

**Tightening trade-off.** Lowering further (e.g. ≥5) catches slower probing but starts alerting on routine automation noise; raising it risks missing a careful actor.

**Evasion.** An attacker stays under the bar by spreading failures across time bins or across principals, or by avoiding failures entirely (read-only enumeration that succeeds). Defence-in-depth: pair with [SC200-03](SC200-03-rbac-role-assignment-changes.md) and Entra sign-in anomaly detections.

**Validation.** ATT&CK [T1087](https://attack.mitre.org/techniques/T1087/) / T1526 — heuristic (failed-permission probing); see [docs/04-validation.md](../docs/04-validation.md).
