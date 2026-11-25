#!/usr/bin/env python3
"""Report telemetry freshness and Sentinel rule execution using workspace reads."""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

from azure_auth import access_token
from detection_rules import GUID, CatalogError, duration_seconds, load_catalog
from workspace_logs import LOGS_AUDIENCE, WorkspaceQueryError, query_rows

POSTURE_ALIAS = "soc-open-mgmt-nsg-rule-ids"


def source_query(table, hours):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", table):
        raise ValueError(f"invalid table name: {table}")
    return f"""{table}
| where TimeGenerated >= ago({hours}h)
| summarize Events = count(), LastEvent = max(TimeGenerated), LastIngested = max(ingestion_time()),
    P95IngestionDelaySeconds = percentile(datetime_diff('second', ingestion_time(), TimeGenerated), 95)"""


def rule_query(rule_ids, hours):
    ids = ", ".join(json.dumps(item) for item in rule_ids)
    return f"""SentinelHealth
| where TimeGenerated >= ago({hours}h)
| where SentinelResourceType =~ 'Analytics Rule'
| extend RuleId = tolower(extract(@'([^/]+)$', 1, SentinelResourceId)),
    AlertsGenerated = tolong(ExtendedProperties.AlertsGeneratedAmount)
| where RuleId in ({ids})
| summarize arg_max(TimeGenerated, Status, AlertsGenerated), Runs = count(),
    FailedRuns = countif(Status =~ 'Failure') by RuleId"""


def snapshot_query():
    return f"""_GetWatchlist('{POSTURE_ALIAS}')
| extend Snapshot = todatetime(column_ifexists('SnapshotUtc', ''))
| summarize Rows = count(), Timestamped = countif(isnotnull(Snapshot)),
    Oldest = min(Snapshot), Newest = max(Snapshot)"""


def age_minutes(value, now):
    try:
        timestamp = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if timestamp.tzinfo is None:
        return None
    return max(0, (now - timestamp).total_seconds() / 60)


def latest_status(value, max_age, now):
    age = age_minutes(value, now)
    if age is None:
        return "timestamp_missing"
    return "stale" if age > max_age else "healthy"


def section(execute, query, classify):
    try:
        return classify(execute(query))
    except WorkspaceQueryError as exc:
        return {"status": exc.status, "error": str(exc)}


def source_health(rows, max_age, now):
    row = rows[0] if rows else {}
    status = latest_status(row.get("LastEvent"), max_age, now) if row.get("Events") else "no_recent_events"
    return {**row, "status": status}


def rule_health(rows, detections, now):
    by_id = {row["RuleId"]: row for row in rows}
    rules = {}
    for detection in detections:
        row = by_id.get(detection.rule["id"].lower())
        if not row:
            rules[detection.code] = {"status": "no_recent_runs"}
            continue
        interval_minutes = duration_seconds(detection.rule["queryFrequency"]) / 60
        max_age = max(30, 2 * interval_minutes)
        if str(row.get("Status", "")).lower() == "success":
            status = latest_status(row.get("TimeGenerated"), max_age, now)
        else:
            status = "execution_failed"
        rules[detection.code] = {**row, "status": status}
    return {"status": "healthy" if all(rule["status"] == "healthy" for rule in rules.values()) else "degraded",
            "rules": rules}


def watchlist_health(rows, max_age, now):
    row = rows[0] if rows else {}
    if not row.get("Rows"):
        status = "empty"
    elif row.get("Timestamped") != row["Rows"]:
        status = "timestamp_missing"
    elif row.get("Oldest") != row.get("Newest"):
        status = "mixed_snapshots"
    else:
        status = latest_status(row.get("Newest"), max_age, now)
    return {**row, "status": status}


def health_report(execute, detections, args, now):
    hours = args.lookback_hours
    tables = sorted({
        table for detection in detections for connector in detection.rule["requiredDataConnectors"]
        for table in connector["dataTypes"]
    })
    report = {
        "observedAtUtc": now.isoformat(),
        "lookbackHours": hours,
        "tables": {
            table: section(execute, source_query(table, hours),
                           lambda rows: source_health(rows, args.max_source_age_minutes, now))
            for table in tables
        },
        "analytics": section(execute, rule_query([d.rule["id"].lower() for d in detections], hours),
                             lambda rows: rule_health(rows, detections, now)),
        "watchlists": {},
    }
    if any(detection.code == "DET-009" for detection in detections):
        report["watchlists"][POSTURE_ALIAS] = section(
            execute, snapshot_query(), lambda rows: watchlist_health(rows, args.max_snapshot_age_minutes, now),
        )
    health_sections = [report["analytics"], *report["tables"].values(), *report["watchlists"].values()]
    report["status"] = "healthy" if all(item["status"] == "healthy" for item in health_sections) else "degraded"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=os.getenv("SENTINEL_WORKSPACE_GUID"), help="workspace customer ID")
    parser.add_argument("--rule", action="append", help="inspect enabled rule IDs (repeatable)")
    parser.add_argument("--lookback-hours", type=int, default=72, choices=range(1, 721), metavar="1–720")
    parser.add_argument("--max-source-age-minutes", type=int, default=1440)
    parser.add_argument("--max-snapshot-age-minutes", type=int, default=1440)
    args = parser.parse_args(argv)
    if not args.workspace or not GUID.fullmatch(args.workspace):
        parser.error("--workspace or SENTINEL_WORKSPACE_GUID must be a workspace customer GUID")
    if min(args.max_source_age_minutes, args.max_snapshot_age_minutes) < 1:
        parser.error("freshness limits must be positive")
    try:
        active = [d for d in load_catalog() if d.rule.get("enabled", True)]
        if args.rule:
            unknown = set(args.rule) - {d.code for d in active}
            if unknown:
                raise CatalogError(f"unknown or disabled rules: {', '.join(sorted(unknown))}")
            active = [d for d in active if d.code in args.rule]
        else:
            active = [d for d in active if d.rule.get("deployByDefault", True)]
        if not active:
            raise CatalogError("no enabled rules selected")
        token = access_token(LOGS_AUDIENCE)
        report = health_report(lambda query: query_rows(args.workspace, token, query), active, args,
                               datetime.now(timezone.utc))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "healthy" else 2


if __name__ == "__main__":
    sys.exit(main())
