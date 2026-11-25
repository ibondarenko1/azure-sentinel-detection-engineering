# Sigma conversions

The three cleanest AzureActivity detections, expressed in **[Sigma](https://sigmahq.io/)**, 
the vendor-neutral detection format. Same logic, portable to any SIEM (Splunk, Elastic,
QRadar, …) via `sigma convert`, not locked to Microsoft KQL.

| File | Source rule | ATT&CK | Notes |
|------|-------------|--------|-------|
| `DET-002-nsg-rule-modified.yml` | DET-002 | T1686.001 | simple selection |
| `DET-003-rbac-role-assignment.yml` | DET-003 | T1098.003 | simple selection |
| `DET-004-mass-resource-deletion.yml` | DET-004 | T1485 | **Sigma correlation** (`event_count` ≥ 5 / 5m by caller) |

The mass-deletion rule uses a Sigma **correlation** (base event + `event_count`), the
portable equivalent of the KQL `summarize … | where DeleteCount >= 5`.

## Validate / convert

```bash
pipx install sigma-cli && sigma plugin install azure
sigma check sigma/*.yml
sigma convert -t kusto -p azure_monitor sigma/DET-002-nsg-rule-modified.yml   # back to KQL
sigma convert -t splunk sigma/DET-002-nsg-rule-modified.yml                    # or SPL
```

Field names follow the Sigma `azure/activitylogs` taxonomy (`operationName`,
`properties.status`, `caller`); the chosen `azure` pipeline maps them to each backend.
