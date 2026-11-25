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
    | where isnotempty(UserPrincipalName)
    | project FailTime = TimeGenerated, UserPrincipalName, FailureIP = IPAddress
    | distinct FailTime, UserPrincipalName, FailureIP;
let successes =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0"
    | where isnotempty(UserPrincipalName)
    | project SuccessTime = TimeGenerated, UserPrincipalName, SuccessIP = IPAddress, App = AppDisplayName
    | distinct SuccessTime, UserPrincipalName, SuccessIP, App;
// Count only failures that occurred before each individual success. This prevents a later
// failure from retroactively qualifying an earlier success in the same one-hour window.
successes
| join kind=inner failures on UserPrincipalName
| where FailTime < SuccessTime
| summarize Failures = count(), FirstFail = min(FailTime),
            MatchingIPFailures = countif(FailureIP == SuccessIP)
    by UserPrincipalName, SuccessTime, SuccessIP, App
| where Failures >= failThreshold
// Source-IP membership is evaluated across every prior failure row; there is no capped set.
| extend NewSourceIp = isnotempty(SuccessIP) and MatchingIPFailures == 0
// One row per user: choose the earliest qualifying success. The fields are selected from
// that same row, so App, IP, and timestamp cannot be mixed across two successful sign-ins.
| summarize arg_min(SuccessTime, FirstFail, Failures, SuccessIP, App, NewSourceIp),
            NewIpSuccesses = countif(NewSourceIp)
    by UserPrincipalName
```

`ResultType == "0"` is a successful Entra sign-in; anything else is a failure (e.g. `50126` invalid
credentials, `50053` account locked). Failures are counted separately for each success and only
events earlier than that success qualify. The rule emits one row per user for the earliest success
with at least five earlier failures. `SuccessTime`, `SuccessIP`, and `App` come from that same
selected sign-in. `NewSourceIp` applies to the selected success; `NewIpSuccesses` counts all
qualifying successes in the lookback whose IP was absent from their earlier failures.

## Prerequisite (data path)

`SigninLogs` reaches `sc200-ws` through the **`entra-id-logs-to-sc200-ws`** diagnostic setting
(Entra ID -> Diagnostic settings, exporting SignInLogs/NonInteractiveUserSignInLogs/AuditLogs).
Without that export the table is empty and the rule cannot fire.

## How to trigger (simulation)

On a test account, attempt sign-in with a wrong password 5+ times, then sign in successfully,
within the hour. The pair raises one incident.

## Expected result

Fires when one user has >=5 failures before a success; failures that arrive after the success do
not retroactively qualify it. The fixture also checks source-IP membership beyond ten distinct
failure IPs and verifies that two successes retain the earliest success row's App/IP/time context
(see `tests/fixtures/DET-008.json`).
Authored and fixture-validated; live witness pending sign-in data accumulating in `SigninLogs`.

## Tuning notes

- `failThreshold` is the sensitivity knob; lower for high-value accounts, raise on noisy fleets.
- Strongest tuning is to alert/escalate only when `NewSourceIp` is true for the selected earliest
  qualifying success, which separates an attacker succeeding from a user who fat-fingered the
  password and then got in from the same device.

**Evasion.** A slow password spray under the threshold, a success outside the 1-hour window, or an
attacker who already knows the password (no failures) all evade this; pair with impossible-travel and
risky-sign-in (Entra ID Protection) signals.

**Validation.** Fixture fire/silent in `tests/fixtures/DET-008.json` (run by `tests/run-detection-tests.py`
against a synthetic SigninLogs table); ATT&CK [T1110](https://attack.mitre.org/techniques/T1110/) /
[T1078](https://attack.mitre.org/techniques/T1078/). See [docs/04-validation.md](../docs/04-validation.md).
