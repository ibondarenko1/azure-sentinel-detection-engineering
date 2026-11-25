# Rule delivery

The rule YAML in `detections/rules/` defines each scheduled rule. The catalog validator, offline deployment plan and Azure deployer all read that same YAML.

| Stage | What runs | What it proves |
|---|---|---|
| Pull request | `validate` checks the catalog, rule cards, metrics intervals and Navigator coverage, then publishes `sentinel-review-plan`. `unit-tests` checks the KQL mirror and exercises synthetic fixtures. | Reviewers can inspect the Azure payloads and their dependencies. Contributors can run the checks without Azure credentials. |
| Main branch, deployment enabled | `deploy` enters the protected `sentinel-prod` environment, renders the plan from the checked out revision, obtains OIDC credentials, and applies the catalog. | Sentinel accepted each PUT. A separate GET checks the rule kind, display name, severity, enablement, query, scheduling and trigger settings. |
| Operator workspace check | Run the validator with `--live` against a named Log Analytics workspace. | The workspace can run the queries with its own table schema and watchlist functions. This check does not create incidents. |

The deployer uses the [Sentinel alertRules API](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update?view=rest-securityinsights-2025-09-01). Rule GUIDs are stable across updates. Removing YAML leaves the remote rule in place. To retire a rule, set `enabled: false` and apply that rule while keeping its GUID.

## Review a change locally

```bash
python -m pip install -r requirements.txt
python cicd/validate-detections.py
python -m unittest discover -s cicd -p 'test_*.py'
python cicd/sync-kql-mirror.py --check
python cicd/deploy-detections.py plan --output sentinel-plan.json
```

`plan` works without Azure CLI, renders a stable payload for each rule, and does not query the live workspace. To narrow the output, pass one or more `--rule DET-NNN` arguments. Deployment supports the same selector.

## Configure the deploy environment

1. Create a GitHub environment named `sentinel-prod`. Restrict deployments to the protected `main` branch and configure required reviewers where available. Keep the `validate` and `unit-tests` PR checks required in branch protection.
2. Use a dedicated Microsoft Entra application for rule deployment. Configure a federated credential with issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`, and the subject GitHub issues for this repository and environment. The default legacy format is `repo:OWNER/REPO:environment:sentinel-prod`. Check GitHub's [OIDC subject reference](https://docs.github.com/en/actions/reference/security/oidc) for immutable IDs and subject customization.
3. Give that service principal `Microsoft Sentinel Contributor` scoped to the target Sentinel workspace, or a custom role that permits the required alert rule read and write operations. A workspace reader or Log Analytics Reader can be used separately for workspace query checks as appropriate. Do not grant a PR subject or the lab regression principal access through the deployment application. Remove the old PR federated credential if you previously followed the original setup.
4. Set the variables below. Leave deployment disabled while the lab is parked. For a workspace with existing rules, compare the generated plan with the current Sentinel configuration before enabling writes.

| Variable | Where to set it | Purpose |
|---|---|---|
| `SENTINEL_DEPLOY_ENABLED` | Repository variables | Set to `true` when ready to allow writes from `main`. Unset skips the deploy job. |
| `SENTINEL_DEPLOY_CLIENT_ID` | `sentinel-prod` environment | Application ID of the dedicated deployment principal. |
| `SENTINEL_DEPLOY_TENANT_ID` | `sentinel-prod` environment | Destination tenant ID. |
| `SENTINEL_DEPLOY_SUBSCRIPTION_ID` | `sentinel-prod` environment | Explicit target subscription. |
| `SENTINEL_DEPLOY_RESOURCE_GROUP` | `sentinel-prod` environment | Resource group containing the workspace. |
| `SENTINEL_DEPLOY_WORKSPACE` | `sentinel-prod` environment | Workspace name. |

The production job only runs for a matching push to `main` or manual dispatch from `main`. Its concurrency group serializes rule deployments. `validate` and `unit-tests` still run for PRs when deployment is disabled. The CI plan displays rule content, so keep credentials and private tenant values out of the YAML.

## Stage and roll back

Before applying to a workspace, provision the [connectors and watchlists](05-data-dictionary.md) that the selected rules use. In particular, seed the new DET-009 watchlist alias before deploying that revision. The [rule card](../detections/DET-009-nsg-opened-inbound-any.md) describes the order and rollback.

Before the first rule write, `apply` checks that the literal watchlist aliases used by enabled rules exist and are ready. Workspace data availability and watchlist contents still need an operator check.

From an existing Azure CLI sign-in with workspace read permissions, run:

```bash
python cicd/validate-detections.py --live --workspace WORKSPACE_CUSTOMER_GUID
```

For an authorized local deployment, pass all three target values or set their corresponding environment variables. The deployer never infers a destination from the active Azure CLI subscription.

```bash
python cicd/deploy-detections.py apply --subscription SUBSCRIPTION_GUID \
  --resource-group RESOURCE_GROUP --workspace WORKSPACE_NAME --rule DET-001
```

A deployment is a sequence of rule writes. If a write or readback fails, the job stops and reports the number already verified. Check the failing rule in Sentinel before retrying, since the write can succeed before verification fails. To roll back, revert the unwanted rule revision or reapply a known good revision by the same GUID. Segment connector and watchlist rollbacks separately from rule rollbacks.
