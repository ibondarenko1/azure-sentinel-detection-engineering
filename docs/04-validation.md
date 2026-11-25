# Validation, Atomic Red Team mapping + regression

The historical lab mapped five Azure control-plane rules to ATT&CK techniques. The table shows
which lab events model a technique and which mappings are heuristic. The
[validation results](../validation/RESULTS.md) record the observed alerts.

## Mapping

| Rule | ATT&CK | Atomic technique | Trigger (atomic-aligned) |
|------|--------|------------------|--------------------------|
| DET-002 NSG rule modified | T1562.007 | [Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) | create + delete an NSG inbound rule |
| DET-003 RBAC role assignment | T1098.003 | [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) | assign + remove an Azure RBAC role |
| DET-004 Mass resource deletion | T1485 | [Data Destruction](https://attack.mitre.org/techniques/T1485/) | bulk-delete ≥5 resources |
| DET-001 Failed-ops spike | T1087 / T1526 | Account / Cloud Service Discovery (**heuristic**, failed-permission probing, no exact 1:1 atomic) | ≥10 denied control-plane ops |
| DET-005 Non-owner deployment | T1098 | Account Manipulation (**loose**, resource-creation persistence, no exact atomic) | deploy a resource as a non-owner SP |

## Historical live regression

[`cicd/regression-test.py`](../cicd/regression-test.py) records the original workspace regression procedure. For each covered rule it:

1. runs the atomic-aligned trigger (`az`),
2. polls the Microsoft Sentinel **incidents API** for a new incident matching the rule, within the rule's `queryFrequency` + an ingestion budget,
3. asserts the incident appeared, **exit non-zero on any miss** (so the pipeline catches a broken rule),

then cleans up the resources it creates.

**Least privilege by design.** Automated regression covers only the detections whose triggers need **Contributor on the workspace resource group**, `DET-002 (NSG)` and `DET-004 (mass deletion)`. The CI identity therefore needs **no role-assignment (User Access Administrator) and no subscription-scope rights**. `DET-003 (RBAC)`, `DET-001 (failed-ops)` and `DET-005 (non-owner)` would require a more privileged or second identity, so they are validated **manually** via the trigger-playbook rather than handing the pipeline standing privilege it doesn't need.

[`.github/workflows/detection-regression.yml`](../.github/workflows/detection-regression.yml) is manual-only and requires an explicit repository opt-in and the separate `sentinel-lab-regression` environment. Keep the opt-in unset until the script uses unique, ownership-checked resource names. The historical runner targets fixed names and can delete existing resources with those names. It also matches incidents by title and time, so an unrelated incident could satisfy it. Run the [offline suite](../tests/README.md) for routine changes.

## Current state

The last recorded lab state is parked. The Sentinel workspace was taken out of service on
12 August 2026. This repository still includes the rules, investigation writeups and evidence
from the earlier lab runs.

- `detection-regression` is opt-in, manual-only and needs the incident API plus an isolated lab.
- `nsg-posture-watchlist` requires manual dispatch from `main` and an explicit opt-in.
- `validate` and `detection-tests` run on every pull request without Azure credentials.

Use the [delivery runbook](03-cicd.md) to bring up the rule catalog in a workspace. Synthetic
tests cover the KQL logic and model the data inputs. Azure connector behavior, watchlist
refresh, incident scheduling and playbook actions require separate workspace evidence.
