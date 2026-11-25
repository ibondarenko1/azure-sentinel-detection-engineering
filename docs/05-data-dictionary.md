# Data dictionary

The telemetry these detections read, the fields they depend on, and what each rule
requires, so the detection logic is grounded in a known schema, not assumed.

## Tables in scope

| Table | Source | Status |
|-------|--------|--------|
| `AzureActivity` | Azure subscription Activity Log → Log Analytics | DET-001 to DET-005, DET-007 and DET-009 |
| `DeviceEvents`, `DeviceProcessEvents`, `SecurityAlert` | Defender for Endpoint → Defender XDR connector → workspace | DET-006 |
| `DeviceInfo` / `AlertEvidence` | Defender for Endpoint → Defender XDR connector → workspace | Endpoint hunts |
| `DeviceTvm*` | Defender Vulnerability Management, advanced hunting | Endpoint hunts, outside the workspace queries |
| `SigninLogs` | Entra ID diagnostic export | DET-008. A live incident has not been recorded. |
| `StorageBlobLogs` | Blob service resource-specific `StorageRead` logs | DET-010, opt-in preview |

The rendered `sentinel-plan.json` lists required tables and literal watchlist aliases per rule.
Set each watchlist's search key to the column used for the join:

| Watchlist alias | Rules | SearchKey values |
|---|---|---|
| `soc-nsg-change-principals` | DET-002 | Approved Azure principals for routine NSG changes |
| `soc-automation-principals` | DET-003 | Approved object IDs or UPNs for routine role assignments |
| `soc-deploy-owners` | DET-005 | Approved deployment principals |
| `soc-open-mgmt-nsg-rule-ids` | DET-009 | Normalized full ARM resource ID of each open inbound security rule. See the [migration notes](../detections/DET-009-nsg-opened-inbound-any.md). |
| `soc-sensitive-blob-reads` | DET-010 | Monitored account and container scopes, plus approved backup principals at each scope. [Configuration](../detections/DET-010-storage-blob-bulk-read.md) |

## `AzureActivity` fields used

| Field | Type | Meaning | Used by |
|-------|------|---------|---------|
| `TimeGenerated` | datetime | event time (windowing, `bin`) | all |
| `ActivityStatusValue` | string | `Success` / `Failure` / `Started` … | all |
| `Caller` | string | principal UPN / object id (→ Account entity) | all |
| `OperationNameValue` | string | ARM operation, e.g. `…/securityRules/write` | all |
| `ResourceId` | string | target resource ARM ID | Resource context and the DET-009 join |
| `ResourceProviderValue` | string | e.g. `Microsoft.Network` | 05 |
| `Properties_d` | dynamic | operation properties (event category, etc.) | 03 (projected) |

## Required fields per detection

| Rule | Filters on | Aggregates | Entity |
|------|-----------|-----------|--------|
| DET-001 | `ActivityStatusValue == "Failure"` | `count() >= 8` by `Caller`, `bin(5m)` | Caller → Account |
| DET-002 | `securityRules` operation, `Success`, principal watchlist | Per event | Caller → Account |
| DET-003 | `roleAssignments` operation, `Success`, principal watchlist | Per event | Caller → Account |
| DET-004 | `OperationNameValue endswith "/delete"`, `Success` | `count() >= 5` by `Caller`, `bin(5m)` | Caller → Account |
| DET-005 | Successful selected resource write by a principal outside the watchlist | Per event | Caller → Account |
| DET-006 | Handle open, dump process or Defender prevention alert | Summarize by device and account | DeviceName → Host, Account → Account |
| DET-007 | Role grant followed by a selected provider write by the same caller | Correlate within 30 minutes | Caller → Account |
| DET-008 | Failures followed by success for the same identity | Correlate counts and source IP | UserPrincipalName → Account, SuccessIP → IP |
| DET-009 | Successful security-rule write joined to current ARG posture by exact rule ID | Per matching event | Caller → Account, CallerIp → IP |
| DET-010 | Successful OAuth `GetBlob` on a monitored container | Distinct blobs in 10 minutes by Entra principal and container | Principal and tenant → Account, storage ID → AzureResource |

These same field names back the [unit-test fixtures](../tests/fixtures) and the
[Sigma conversions](../sigma) (mapped to the Sigma `azure/activitylogs` taxonomy).

## `DeviceEvents` fields used (DET-006 and endpoint hunts)

| Field | Type | Meaning | Used by |
|-------|------|---------|---------|
| `Timestamp` / `TimeGenerated` | datetime | event time | all endpoint |
| `ActionType` | string | event kind, e.g. `OpenProcessApiCall` | DET-006 |
| `FileName` | string | target process (e.g. `lsass.exe`) | DET-006 |
| `InitiatingProcessFileName` | string | the process taking the action | DET-006, hunts |
| `InitiatingProcessCommandLine` | string | command line (dump-pattern context) | LSASS hunt |
| `InitiatingProcessAccountName` | string | acting account (→ Account entity) | DET-006 |
| `DeviceName` / `DeviceId` | string | host (→ Host entity) / join key | DET-006, hunts |

The `DeviceTvm*` tables (`DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSecureConfigurationAssessment`)
are read only in [Defender advanced hunting](../kql/hunting); they are not part of the Sentinel
workspace schema, which is why the TVM correlations are hunts and not deployed rules.
