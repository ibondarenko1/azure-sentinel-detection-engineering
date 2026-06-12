# Screenshots

Visual evidence for these detections. Full unredacted captures are staged in `_raw/` (git-ignored); the cropped copies here (browser chrome removed) are the ones referenced by the docs.

## Captured

| File | Shows |
|------|-------|
| `01-telemetry-schema.png` | Advanced hunting, live `sc200-ws` schema + query editor/history |
| `02-detection-rules-overview.png` | Sentinel Analytics, 6 `[DET]` rules Enabled (incl. `[DET] LSASS credential access`, High), MITRE tactics/techniques |
| `05-incidents-queue-populated.png` | Incidents queue, endpoint incident on `soc-sensor-01` (Antivirus / Defender for Endpoint) |
| `06-inc-03-overview.png` | RBAC role assignment alert detail |
| `06-inc-04-overview.png` | Mass resource deletion (High) alert detail, caller + delete counts 8/5 over threshold |
| `07-tvm-weaknesses.png` | Earlier TVM weaknesses view (OpenSSL criticals, 3 critical / 19 in org); superseded in the docs by the current `15` |
| `08-device-active.png` | Device inventory, `soc-sensor-01` Active and Onboarded (Windows 11 sensor) |
| `09-secure-score.png` | Earlier Microsoft 365 Secure Score (61.76%, 32 actions); superseded in the docs by the current `12` |
| `10-inc-06-lsass.png` | Sentinel incident #65 `[DET] LSASS credential access` (High), host `soc-sensor-01`, tactic Credential Access |
| `11-sentinel-overview.png` | Microsoft Sentinel overview (current): 10 analytics rules enabled, 4 active data connectors, 1 automation rule, live data received |
| `12-secure-score-current.png` | Microsoft 365 Secure Score current state, 50.14%, 94 actions to review |
| `13-defender-overview.png` | Defender portal dashboard, current scope: SOC optimization, UEBA, automation, connectors, secure score, devices |
| `14-exposure-recommendations.png` | Exposure Management, exposure score 65 (Medium) + 6-day score-history trend + recommendation list |
| `15-tvm-weaknesses-current.png` | Defender Vulnerability Management weaknesses, 150 in org / 13 critical / 1 exploitable (current volume) |
| `16-secure-score-after.png` | M365 Secure Score after remediation, 50.79% (+7 points, Secure Boot 2023 certs) |
| `17-device-inventory.png` | Device inventory: two records both `soc-sensor-01` (Server + Workstation), one dual-classified VM |
| `18-tvm-weaknesses-after.png` | TVM weaknesses, current volume after remediation |
| `19-exposure-after.png` | Exposure score after, 47 (down from 65) with 6-day downward trend + 3 open recommendations |

## Redaction

The top crop removes the browser URL bar (which carried the tenant ID). The portal captures
(`02`, `05`, `07`, `08`, `09`, `10`, `11`) additionally have the top-right account chip blacked out,
which carried the UPN, the organization name, and the profile photo. On `10` the incident-link field
(which carried the subscription id) is also blacked out. No subscription IDs are visible in any frame.

In the alert-detail shots (`06-inc-03`, `06-inc-04`) the Query-results "Caller" column is blacked out
(it carried a UPN), and the rule-description line was corrected from the early "SC-200 lab rule:"
wording to the current rule name, matching the deployed `[DET]` catalog.

## Optional / not in v1

Per-rule logic shots (`03-rule-0N`), per-incident shots for DET-001/02/05 (`06-inc-01/02/05`), attack-story/timeline (`07`, `08`), and the investigation pivot (`09`) were not captured, the consolidated alert queue (`05`) and the two detail shots cover the story. Add them later if desired.

Shots `12` to `15` are the current-state captures for the posture-remediation phase
([docs/10](../docs/10-posture-remediation.md)), taken once the tenant had accumulated data: the M365
Secure Score (50.14%, 94 actions, up from the 32 in the earlier `09`), the Defender dashboard scope,
the Exposure Management score and trend, and the TVM weakness volume (150 in org). The Defender for
Cloud Secure Score (68.81%) stays a diffable JSON snapshot ([posture/snapshots](../posture/snapshots))
rather than a screenshot, so the before/after is a file diff. Capture and redaction are scripted:
`_raw/capture.ps1` (URL bar cropped) then `_raw/redact-chip.ps1` (top-right account chip blacked out).
