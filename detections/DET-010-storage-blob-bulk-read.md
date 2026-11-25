# DET-010, Bulk reads from a monitored Blob container

| Property | Value |
|---|---|
| Status | Preview. Select explicitly. The authored rule is disabled. |
| Source | `StorageBlobLogs`, resource-specific Blob `StorageRead` logs |
| Schedule | Every 15 minutes with a one-hour query lookback |
| Technique | [T1530, Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) |

The rule groups successful OAuth `GetBlob` requests by Entra tenant and principal, storage account,
container, and a ten-minute bucket. At least 20 distinct object keys in a bucket produces a result.
The output includes the requesting principal, resource ID, container, counts, and bytes returned.
Use the storage logs to review the individual reads. The alert query projects no blob URIs or keys.

## Configure the source and scope

Send `StorageRead` logs for the selected Blob service to the target workspace in resource-specific
mode. Verify that `StorageBlobLogs` includes successful reads and the Entra tenant and object IDs.
This rule uses OAuth identity. Coverage of other authentication types needs a separate baseline and
signal. [Azure Blob monitoring guidance](https://learn.microsoft.com/en-us/azure/storage/blobs/blob-storage-monitoring-scenarios)

Create the watchlist `soc-sensitive-blob-reads` with a `SearchKey` column. Use one row per monitored
account and container, and one row per approved backup identity at that same scope. Use the storage
account name, container name, Entra tenant ID and Entra object ID as recorded by the workspace.

```csv
SearchKey
scope:exampleacct/records
backup:exampleacct/records/90000000-0000-0000-0000-000000000001/20000000-0000-0000-0000-000000000002
```

## Validate before activation

```bash
python cicd/validate-detections.py --live --workspace WORKSPACE_CUSTOMER_GUID --rule DET-010
python cicd/deploy-detections.py plan --rule DET-010
```

Review ordinary reads, expected migrations and backup jobs against the proposed threshold. The
fixture tests the exact threshold, scoped backup activity, repeated reads of one object, an
unmonitored container and SAS traffic. Capture the incident and control results in a workspace
before enabling the rule. Select `--rule DET-010` explicitly when previewing or applying the rule.
[Detection fixture](../tests/fixtures/DET-010.json) · [Storage backlog](https://github.com/ibondarenko1/azure-sentinel-detection-engineering/issues/12)
