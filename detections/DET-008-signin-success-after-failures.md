# DET-008, Successful sign-in after repeated failures

| | |
|---|---|
| **ID** | DET-008 |
| **Severity** | Medium (escalate to High on a new source IP) |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled (identity plane) |
| **Data source** | `SigninLogs` (Entra ID, via diagnostic export) |
| **MITRE tactic** | Credential Access / Initial Access |
| **MITRE technique** | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) |

## What it catches

A user account with a **burst of failed sign-ins followed by a success** in the same hour, the
brute-force / password-spray success, or a credential that is finally accepted. This is the
**identity plane**, added next to the control-plane (`AzureActivity`) and endpoint (`Device*`)
detections, and it closes the previously-tracked `T1078` gap.

## Detection logic

Runs every 15 minutes over a 1-hour lookback; correlates failures to a later success per user.

```kql
let failThreshold = 5;
let lookback = 1h;
let failures =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType != "0"
    | summarize Failures = count(), FailIPs = make_set(IPAddress, 10), FirstFail = min(TimeGenerated)
        by UserPrincipalName
    | where Failures >= failThreshold;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| project SuccessTime = TimeGenerated, UserPrincipalName, SuccessIP = IPAddress, App = AppDisplayName
| join kind=inner failures on UserPrincipalName
| where SuccessTime > FirstFail
| extend SuccessFromNewIp = array_index_of(FailIPs, SuccessIP) < 0
| summarize SuccessTime = min(SuccessTime), Failures = max(Failures),
            NewIpSuccesses = countif(SuccessFromNewIp), SuccessIP = min(SuccessIP), App = min(App)
    by UserPrincipalName, FirstFail
| extend NewSourceIp = NewIpSuccesses > 0
```

`ResultType == "0"` is a successful Entra sign-in; anything else is a failure (e.g. `50126` invalid
credentials, `50053` account locked). `NewSourceIp` is the escalation signal: a success from an IP
that did not appear in the failures is far more suspicious than a success from the same IP (typo).

## Prerequisite (data path)

`SigninLogs` reaches `sc200-ws` through the **`entra-id-logs-to-sc200-ws`** diagnostic setting
(Entra ID -> Diagnostic settings, exporting SignInLogs/NonInteractiveUserSignInLogs/AuditLogs).
Without that export the table is empty and the rule cannot fire.

## How to trigger (simulation)

On a test account, attempt sign-in with a wrong password 5+ times, then sign in successfully,
within the hour. The pair raises one incident.

## Expected result

Fires when one user has >=5 failures then a success after the first failure; silent for a lone
success, fewer than 5 failures, or failures with no later success (see `tests/fixtures/DET-008.json`).
Authored and fixture-validated; live witness pending sign-in data accumulating in `SigninLogs`.

## Tuning notes

- `failThreshold` is the sensitivity knob; lower for high-value accounts, raise on noisy fleets.
- Strongest tuning is to alert/escalate only when `NewSourceIp` is true, which separates an attacker
  succeeding from a user who fat-fingered the password and then got in from the same device.

**Evasion.** A slow password spray under the threshold, a success outside the 1-hour window, or an
attacker who already knows the password (no failures) all evade this; pair with impossible-travel and
risky-sign-in (Entra ID Protection) signals.

**Validation.** Fixture fire/silent in `tests/fixtures/DET-008.json` (run by `tests/run-detection-tests.py`
against a synthetic SigninLogs table); ATT&CK [T1110](https://attack.mitre.org/techniques/T1110/) /
[T1078](https://attack.mitre.org/techniques/T1078/). See [docs/04-validation.md](../docs/04-validation.md).
