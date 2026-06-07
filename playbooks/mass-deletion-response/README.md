# SOAR playbook — Mass resource deletion auto-triage

Closes the loop **detect → respond** on the highest-severity detection (SC200-04). When a
Mass-resource-deletion incident is created, a Sentinel **automation rule** runs this
**Logic App** playbook, which:

1. tags the incident `auto-triaged`,
2. posts an **enrichment comment** with the suggested response (disable/quarantine the caller, lock the affected resource groups, restore from backup, hunt initial access — see [INV-01](../../investigations/INV-01-mass-resource-deletion.md)).

**No secrets, no external connector.** The playbook authenticates with its own
**system-assigned managed identity** (Sentinel connection `parameterValueType: Alternative`),
granted **Microsoft Sentinel Responder** on the workspace RG.

## Files
- `azuredeploy.json` — Logic App + managed-identity Sentinel connection (ARM, no hardcoded IDs).
- `automation-rule.json` — the automation rule body (placeholdered; binds the playbook to SC200-04).

## Deploy

```bash
# 1) playbook (Logic App + connection)
az deployment group create -g <RG> -n pb-mass-deletion \
  --template-file azuredeploy.json --query properties.outputs

# 2) grant the playbook MI rights to comment/tag, and let Sentinel run playbooks
az role assignment create --assignee-object-id <playbookPrincipalId> --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" --scope /subscriptions/<SUB>/resourceGroups/<RG>
az role assignment create --assignee-object-id $(az ad sp show --id 98785600-1bb7-4fb9-b9fa-19afe2c8a360 --query id -o tsv) \
  --assignee-principal-type ServicePrincipal --role "Microsoft Sentinel Automation Contributor" \
  --scope /subscriptions/<SUB>/resourceGroups/<RG>

# 3) automation rule (substitute placeholders in automation-rule.json first)
az rest --method put --body @automation-rule.json \
  --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WORKSPACE>/providers/Microsoft.SecurityInsights/automationRules/$(python -c 'import uuid;print(uuid.uuid4())')?api-version=2025-09-01"
```

The `98785600-1bb7-4fb9-b9fa-19afe2c8a360` app is the fixed **Azure Security Insights**
service principal — it needs *Automation Contributor* so automation rules may run playbooks.
