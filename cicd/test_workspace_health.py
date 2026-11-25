"""Verify the distinction between quiet rules, missing sources and failures."""

import unittest
from argparse import Namespace
from datetime import datetime, timezone
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from detection_rules import load_catalog
from workspace_logs import WorkspaceQueryError, missing_source

spec = spec_from_file_location("workspace_health", Path(__file__).with_name("workspace-health.py"))
health = module_from_spec(spec)
spec.loader.exec_module(health)

NOW = datetime(2026, 11, 25, 4, tzinfo=timezone.utc)
RECENT = "2026-11-25T03:50:00Z"
OLD = "2026-11-23T04:00:00Z"


class WorkspaceHealthTests(unittest.TestCase):
    def setUp(self):
        self.detection = next(detection for detection in load_catalog() if detection.code == "DET-009")
        self.settings = Namespace(lookback_hours=72, max_source_age_minutes=1440, max_snapshot_age_minutes=1440)

    def test_recent_execution_without_alerts_and_fresh_snapshot(self):
        def execute(query):
            if query.startswith("AzureActivity"):
                return [{"Events": 42, "LastEvent": RECENT, "P95IngestionDelaySeconds": 16}]
            if query.startswith("SentinelHealth"):
                return [{"RuleId": self.detection.rule["id"], "TimeGenerated": RECENT,
                         "Status": "Success", "AlertsGenerated": 0, "Runs": 3, "FailedRuns": 0}]
            return [{"Rows": 1, "Timestamped": 1, "Oldest": RECENT, "Newest": RECENT}]

        report = health.health_report(execute, [self.detection], self.settings, NOW)
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["analytics"]["rules"]["DET-009"]["AlertsGenerated"], 0)
        self.assertEqual(report["tables"]["AzureActivity"]["P95IngestionDelaySeconds"], 16)

    def test_missing_source_failed_rule_and_mixed_snapshots_are_different(self):
        def execute(query):
            if query.startswith("AzureActivity"):
                raise WorkspaceQueryError("Log Analytics HTTP 400", status="source_unavailable")
            if query.startswith("SentinelHealth"):
                return [{"RuleId": self.detection.rule["id"], "TimeGenerated": RECENT,
                         "Status": "Failure", "AlertsGenerated": None, "FailedRuns": 1}]
            return [{"Rows": 2, "Timestamped": 2, "Oldest": OLD, "Newest": RECENT}]

        report = health.health_report(execute, [self.detection], self.settings, NOW)
        self.assertEqual(report["status"], "degraded")
        self.assertEqual(report["tables"]["AzureActivity"]["status"], "source_unavailable")
        self.assertEqual(report["analytics"]["rules"]["DET-009"]["status"], "execution_failed")
        self.assertEqual(report["watchlists"][health.POSTURE_ALIAS]["status"], "mixed_snapshots")

    def test_quiet_table_stale_table_and_pre_timestamp_watchlist(self):
        self.assertEqual(health.source_health([{"Events": 0}], 1440, NOW)["status"], "no_recent_events")
        self.assertEqual(health.source_health([{"Events": 5, "LastEvent": OLD}], 1440, NOW)["status"], "stale")
        self.assertEqual(health.watchlist_health([{"Rows": 1, "Timestamped": 0}], 1440, NOW)["status"],
                         "timestamp_missing")

    def test_only_unresolved_source_errors_get_source_unavailable_status(self):
        self.assertTrue(missing_source({"code": "BadArgumentError", "innererror": {
            "code": "SEM0100", "message": "Failed to resolve table or column expression named 'Foo'"}}))
        self.assertFalse(missing_source({"code": "Forbidden"}))
