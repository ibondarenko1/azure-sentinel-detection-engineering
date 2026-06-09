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
| `07-tvm-weaknesses.png` | Defender Vulnerability Management, OpenSSL critical CVEs (CVSS 9.8), 3 critical / 19 in org |
| `08-device-active.png` | Device inventory, `soc-sensor-01` Active and Onboarded (Windows 11 sensor) |
| `09-secure-score.png` | Microsoft Secure Score posture for the tenant |
| `10-inc-06-lsass.png` | Sentinel incident #65 `[DET] LSASS credential access` (High), host `soc-sensor-01`, tactic Credential Access |
| `11-sentinel-overview.png` | Microsoft Sentinel overview, incident queue + analytics-rule state |

## Redaction

The top crop removes the browser URL bar (which carried the tenant ID). The portal captures
(`02`, `05`, `07`, `08`, `09`, `10`, `11`) additionally have the top-right account chip blacked out,
which carried the UPN, the organization name, and the profile photo. On `10` the incident-link field
(which carried the subscription id) is also blacked out. No subscription IDs are visible in any frame.

Still review before publishing:

- [ ] **Caller email** `ievgen@<redacted-tenant>` in the older alert-detail shots (`06-inc-03`, `06-inc-04`) Query-results "Caller" column; blur if you prefer it not surfaced.

## Optional / not in v1

Per-rule logic shots (`03-rule-0N`), per-incident shots for DET-001/02/05 (`06-inc-01/02/05`), attack-story/timeline (`07`, `08`), and the investigation pivot (`09`) were not captured, the consolidated alert queue (`05`) and the two detail shots cover the story. Add them later if desired.
