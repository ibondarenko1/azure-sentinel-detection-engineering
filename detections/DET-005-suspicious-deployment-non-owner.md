# DET-005, Suspicious resource deployment by non-owner

| | |
|---|---|
| **ID** | DET-005 |
| **Severity** | Medium |
| **Rule type** | Scheduled analytics rule |
| **Status** | Enabled (v2, non-owner intent enforced) |
| **Data source** | `AzureActivity` + `soc-deploy-owners` watchlist |
| **MITRE tactic** | Persistence |
| **MITRE technique** | [T1098, Account Manipulation](https://attack.mitre.org/techniques/T1098/) |

## What it catches

A successful control-plane **deployment of Compute, Storage, or Web** by a principal that is **not
on the deploy-owner allow-list**. Attackers who gain a foothold stand up compute (mining), storage
(staging), or web/functions (persistence) under an account that should not normally be deploying.
v2 enforces the "non-owner" intent and scopes to the providers that carry that risk, so the rule
matches its name instead of firing on every `/write`.

## Detection logic

Exact rule logic (exported from the analytics rule). Runs every 60 minutes over a 1-hour lookback.

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

Two fidelity dimensions, both grounded in fields the Activity Log actually carries:

- **`soc-deploy-owners` watchlist** is the core of the non-owner logic; every principal legitimately
  deploying must be enumerated there. The watchlist lives in the tenant, so no identity is committed
  to the repo. `in~` is used because `Caller` and `ResourceProviderValue` arrive in mixed/upper case.
- **Provider scope** (`Compute`/`Storage`/`Web`) cuts the "any write" noise; a new `Microsoft.Compute`
  VM by a non-owner is higher signal than storage.

`CallerIp` is parsed from `Properties_d.httpRequest.clientIpAddress` (present in the real record) and
mapped as an IP entity for triage.

## How to trigger (simulation)

See `simulations/trigger-playbook.md` → **DET-005**. From a principal **not** in `soc-deploy-owners`
(a Contributor or guest), deploy a watched resource (e.g. a storage account).

## Expected result

The rule fires when a non-allow-listed caller successfully writes a Compute/Storage/Web resource;
it stays silent for an allow-listed owner, a non-watched provider, a read, or a failed write
(see `tests/fixtures/DET-005.json`).

## Evidence

This detection's alerts appear in the consolidated [alert queue](../screenshots/05-incidents-queue-populated.png) (Persistence / T1098).

## Tuning notes

This rule is the worked example in [docs/09, tuning case study](../docs/09-tuning-case-study.md): v1
fired on any successful write; v2 (this version) enforces the non-owner intent and measures 0 false
positives on the [validation harness](../validation/RESULTS.md).

- Maintain `soc-deploy-owners` as the source of fidelity; a legitimate deployer missing from it is
  the expected false positive, add them to the watchlist rather than loosening the rule.
- Triage by provider: weight `Microsoft.Compute` over `Microsoft.Storage`.

**Evasion.** Evaded by an attacker who first adds their principal to `soc-deploy-owners` (chain with
[DET-003](DET-003-rbac-role-assignment-changes.md)), or deploys a resource type outside the watch-list.

**Validation.** Fixture fire/silent in `tests/fixtures/DET-005.json` (run by `tests/run-detection-tests.py`
with the watchlist stubbed from the fixture); ATT&CK [T1098](https://attack.mitre.org/techniques/T1098/),
loose mapping (resource-creation persistence). See [docs/04-validation.md](../docs/04-validation.md).
