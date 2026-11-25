# Workspace health

`cicd/workspace-health.py` reads the Log Analytics workspace and reports required table freshness,
scheduled rule execution, and the DET-009 watchlist snapshot. Run it after deploying rules or
investigating missing alerts. The caller needs query access to the named workspace. Enable
Sentinel health monitoring to collect rule execution records. [Microsoft Sentinel health settings](https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring)

```bash
python cicd/workspace-health.py --workspace WORKSPACE_CUSTOMER_GUID --rule DET-001
```

Repeat `--rule` to inspect more enabled rules. The default looks at all enabled rules, queries the
last 72 hours, and marks source and snapshot timestamps older than 24 hours as stale. Set
`--lookback-hours`, `--max-source-age-minutes`, and `--max-snapshot-age-minutes` for the environment.
Rule runs are stale after two schedule intervals, with a minimum of 30 minutes.

| JSON section | What to check |
|---|---|
| `tables` | `source_unavailable` indicates an unresolved source. `no_recent_events` means the query succeeded and found no events in the lookback. Review expected volume on quiet tables. A populated table reports event count, newest event, newest ingestion, and p95 ingestion lag when available. |
| `analytics` | Rule GUIDs are matched to `SentinelHealth`. A successful recent run can report zero alerts. `execution_failed` or `no_recent_runs` calls for checking the latest run and whether health events are enabled. |
| `watchlists` | DET-009 refreshes stamp rows with `SnapshotUtc`. A timestamped placeholder represents a complete empty posture result. Old rows without timestamps or a mix of snapshot times require a fresh, complete refresh. |

Exit `0` means the selected checks are healthy, `2` means the JSON contains a degraded section, and
`1` indicates a setup or authentication error. Save a report with the release SHA and UTC time when
collecting live evidence. The CLI does not create rules or change workspace settings.
