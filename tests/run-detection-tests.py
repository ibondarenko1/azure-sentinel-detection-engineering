#!/usr/bin/env python3
"""Unit-test the detection KQL against synthetic logs using a local Kusto emulator.

Runs each rule's REAL query against kustainer over synthetic fixtures, asserting it
FIRES on malicious data and stays SILENT on benign. No live tenant required, anyone can
fork and run this.

Coverage is declared in ``coverage.yaml``. Rules backed by emulator fixtures are
executed here; rules whose data source is not represented by the local schema must
be declared ``live_only`` with a reason. A missing declaration or malformed fixture
is an error, not a passing skip.

Each fixture targets one table via the optional "table" key (default "AzureActivity";
"SigninLogs" is also supported). Multi-table rules can use a "tables" mapping with a
fire/silent list per table. Rules that use an allow-list watchlist provide a "watchlist"
key, which is stubbed into a _GetWatchlist() function so the real query runs unchanged.

Env: KUSTO_URI (default http://localhost:8080), KUSTO_DB (default NetDefaultDB).
"""
import os
import sys
import re
import glob
import json
import datetime
import urllib.request

KUSTO = os.environ.get("KUSTO_URI", "http://localhost:8080").rstrip("/")
DB = os.environ.get("KUSTO_DB", "NetDefaultDB")
RULES = os.path.join(os.path.dirname(__file__), "..", "detections", "rules")
FIX = os.path.join(os.path.dirname(__file__), "fixtures")
COVERAGE = os.path.join(os.path.dirname(__file__), "coverage.yaml")

# Per-table synthetic schema. cols = column order; dynamic = columns loaded as dynamic().
TABLES = {
    "AzureActivity": {
        "cols": ["TimeGenerated", "ActivityStatusValue", "Caller", "OperationNameValue",
                 "ResourceProviderValue", "ResourceId", "Properties_d"],
        "schema": ("TimeGenerated:datetime, ActivityStatusValue:string, Caller:string, "
                   "OperationNameValue:string, ResourceProviderValue:string, ResourceId:string, "
                   "Properties_d:dynamic"),
        "dynamic": {"Properties_d"},
    },
    "SigninLogs": {
        "cols": ["TimeGenerated", "UserPrincipalName", "UserId", "ResultType",
                 "ResultDescription", "IPAddress", "AppDisplayName", "Location"],
        "schema": ("TimeGenerated:datetime, UserPrincipalName:string, UserId:string, "
                   "ResultType:string, ResultDescription:string, IPAddress:string, "
                   "AppDisplayName:string, Location:string"),
        "dynamic": set(),
    },
    "DeviceEvents": {
        "cols": ["TimeGenerated", "ActionType", "FileName", "InitiatingProcessFileName",
                 "InitiatingProcessAccountName", "DeviceName"],
        "schema": ("TimeGenerated:datetime, ActionType:string, FileName:string, "
                   "InitiatingProcessFileName:string, InitiatingProcessAccountName:string, "
                   "DeviceName:string"),
        "dynamic": set(),
    },
    "DeviceProcessEvents": {
        "cols": ["TimeGenerated", "ProcessCommandLine", "FileName", "AccountName", "DeviceName"],
        "schema": ("TimeGenerated:datetime, ProcessCommandLine:string, FileName:string, "
                   "AccountName:string, DeviceName:string"),
        "dynamic": set(),
    },
    "SecurityAlert": {
        "cols": ["TimeGenerated", "ProviderName", "AlertName", "Entities"],
        # The SecurityAlert connector presents Entities as JSON text to this
        # query, which explicitly parses it before mv-apply.
        "schema": "TimeGenerated:datetime, ProviderName:string, AlertName:string, Entities:string",
        "dynamic": set(),
    },
}

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: python -m pip install -r requirements.txt")


def _post(path, payload):
    req = urllib.request.Request(KUSTO + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def mgmt(cmd):
    _post("/v1/rest/mgmt", {"db": DB, "csl": cmd})


def query_count(csl):
    res = _post("/v1/rest/query", {"db": DB, "csl": csl + "\n| count"})
    return res["Tables"][0]["Rows"][0][0]


def lit(col, val, base, dyn):
    if col == "TimeGenerated":
        ts = base - datetime.timedelta(minutes=int(val or 0))
        return f"datetime({ts.strftime('%Y-%m-%dT%H:%M:%S')}Z)"
    if col in dyn:
        return f"dynamic({json.dumps(val or {})})"
    s = str(val if val is not None else "").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def load_table(events, table):
    t = TABLES[table]
    base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
    rows = []
    for e in events:
        rows.append(", ".join(
            lit(c, e.get("minutesAgo") if c == "TimeGenerated" else e.get(c), base, t["dynamic"])
            for c in t["cols"]))
    body = ",\n".join(rows) if rows else ""
    mgmt(f".set-or-replace {table} <| datatable({t['schema']})[\n{body}\n]")


def _rule_id(path):
    match = re.match(r"(DET-\d+)", os.path.basename(path))
    if not match:
        raise ValueError(f"rule filename does not start with DET-NNN: {path}")
    return match.group(1)


def _inside(path, root):
    """Return true when *path* resolves below *root* (including root itself)."""
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False


def _validate_scenarios(rid, fixture_data, errors):
    """Validate either the legacy single-table or the multi-table fixture shape."""
    table_map = fixture_data.get("tables")
    if table_map is not None:
        if not isinstance(table_map, dict) or not table_map:
            errors.append(f"{rid}: tables must be a non-empty mapping")
            return
        if "fires" in fixture_data or "silent" in fixture_data:
            errors.append(f"{rid}: tables fixtures must not also define top-level fires/silent")
        for table, table_data in table_map.items():
            if table not in TABLES:
                errors.append(f"{rid}: fixture uses unsupported emulator table {table}")
                continue
            if not isinstance(table_data, dict):
                errors.append(f"{rid}: {table} fixture entry must be a mapping")
                continue
            for scenario in ("fires", "silent"):
                if not isinstance(table_data.get(scenario), list):
                    errors.append(f"{rid}: {table} fixture must contain a {scenario} list")
        for scenario in ("fires", "silent"):
            if not any(
                isinstance(table_data, dict) and table_data.get(scenario)
                for table_data in table_map.values()
            ):
                errors.append(f"{rid}: multi-table fixture must contain events for {scenario}")
        return

    for scenario in ("fires", "silent"):
        if not isinstance(fixture_data.get(scenario), list) or not fixture_data[scenario]:
            errors.append(f"{rid}: fixture must contain a non-empty {scenario} list")
    table = fixture_data.get("table", "AzureActivity")
    if table not in TABLES:
        errors.append(f"{rid}: fixture uses unsupported emulator table {table}")


def load_coverage(rule_paths):
    """Load and validate the rule-to-test coverage contract.

    The old runner treated a missing fixture as a harmless skip, which made a
    newly added rule look green without any test. Keeping this validation in the
    runner means the CI entry point and local invocation enforce the same contract.
    """
    errors = []
    if not os.path.exists(COVERAGE):
        return {}, [f"missing coverage contract: {COVERAGE}"]

    with open(COVERAGE, encoding="utf-8") as handle:
        contract = yaml.safe_load(handle) or {}
    if not isinstance(contract, dict) or contract.get("version") != 1:
        errors.append("coverage contract must be a mapping with version: 1")
    entries = contract.get("rules") if isinstance(contract, dict) else None
    if not isinstance(entries, dict):
        return {}, errors + ["coverage contract must contain a rules mapping"]

    rule_ids = {}
    for path in rule_paths:
        try:
            rid = _rule_id(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if rid in rule_ids:
            errors.append(f"duplicate rule id {rid}: {rule_ids[rid]} and {path}")
        rule_ids[rid] = path

    missing = sorted(set(rule_ids) - set(entries))
    extra = sorted(set(entries) - set(rule_ids))
    errors.extend(f"{rid}: no coverage declaration" for rid in missing)
    errors.extend(f"{rid}: coverage declaration has no matching rule" for rid in extra)

    fixture_paths = set()
    for rid in sorted(entries):
        if rid not in rule_ids:
            # The extra-entry error is reported above; do not dereference a
            # non-existent rule while collecting the remaining diagnostics.
            continue
        entry = entries[rid]
        if not isinstance(entry, dict):
            errors.append(f"{rid}: coverage entry must be a mapping")
            continue
        mode = entry.get("mode")
        if mode not in {"fixture", "live_only"}:
            errors.append(f"{rid}: mode must be fixture or live_only")
            continue
        if mode == "live_only":
            reason = entry.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                errors.append(f"{rid}: live_only entries require a non-empty reason")
            if entry.get("fixture") is not None:
                errors.append(f"{rid}: live_only entries must not declare a fixture")
            expected = os.path.join(FIX, f"{rid}.json")
            if os.path.exists(expected):
                errors.append(f"{rid}: live_only rule has an unreferenced fixture {expected}")
            continue

        fixture = entry.get("fixture")
        if not isinstance(fixture, str) or not fixture.strip():
            errors.append(f"{rid}: fixture entries require a fixture path")
            continue
        fixture_path = os.path.abspath(os.path.join(os.path.dirname(__file__), fixture))
        if not _inside(fixture_path, os.path.dirname(__file__)):
            errors.append(f"{rid}: fixture path escapes tests/: {fixture}")
            continue
        if os.path.splitext(fixture_path)[1].lower() != ".json":
            errors.append(f"{rid}: fixture must be a JSON file: {fixture}")
        if not os.path.exists(fixture_path):
            errors.append(f"{rid}: fixture does not exist: {fixture}")
            continue
        if os.path.basename(fixture_path) != f"{rid}.json":
            errors.append(f"{rid}: fixture filename must be {rid}.json")
        fixture_paths.add(fixture_path)
        try:
            with open(fixture_path, encoding="utf-8") as handle:
                fixture_data = json.load(handle)
        except (OSError, ValueError) as exc:
            errors.append(f"{rid}: invalid fixture JSON {fixture}: {exc}")
            continue
        if not isinstance(fixture_data, dict):
            errors.append(f"{rid}: fixture must be a JSON object")
            continue
        _validate_scenarios(rid, fixture_data, errors)
        expected_counts = fixture_data.get("expected_counts")
        if expected_counts is not None:
            if not isinstance(expected_counts, dict):
                errors.append(f"{rid}: expected_counts must be a mapping")
            else:
                for scenario in ("fires", "silent"):
                    expected = expected_counts.get(scenario)
                    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
                        errors.append(f"{rid}: expected_counts.{scenario} must be a non-negative integer")
        watchlist = fixture_data.get("watchlist")
        if "watchlist" in fixture_data and not isinstance(watchlist, list):
            errors.append(f"{rid}: watchlist must be a list")
        rule = yaml.safe_load(open(rule_ids[rid], encoding="utf-8")) or {}
        uses_watchlist = bool(re.search(r"\b_GetWatchlist\s*\(", rule.get("query", "")))
        if uses_watchlist and not isinstance(watchlist, list):
            errors.append(
                f"{rid}: query calls _GetWatchlist(); fixture must declare watchlist "
                "(an omitted stub could leak from a prior rule)"
            )
        if not uses_watchlist and "watchlist" in fixture_data:
            errors.append(f"{rid}: fixture declares watchlist but query does not call _GetWatchlist()")

    for path in glob.glob(os.path.join(FIX, "DET-*.json")):
        if os.path.abspath(path) not in fixture_paths:
            errors.append(f"fixture is not declared in coverage contract: {path}")
    return entries, errors


def main():
    rule_paths = sorted(glob.glob(os.path.join(RULES, "*.yaml")))
    coverage, coverage_errors = load_coverage(rule_paths)
    if coverage_errors:
        print("Coverage contract FAILED:")
        for error in coverage_errors:
            print(f"  - {error}")
        sys.exit(1)

    failures = 0
    total = 0
    fixture_rules = 0
    live_only_rules = 0
    for path in rule_paths:
        rule = yaml.safe_load(open(path, encoding="utf-8"))
        rid = _rule_id(path)
        entry = coverage[rid]
        if entry["mode"] == "live_only":
            live_only_rules += 1
            print(f"LIVE-ONLY {rid} {rule['name']}: {entry['reason']}")
            continue
        fixture_rules += 1
        fx_path = os.path.abspath(os.path.join(os.path.dirname(__file__), entry["fixture"]))
        fx = json.load(open(fx_path, encoding="utf-8"))
        # Rules using allow-lists reference Sentinel watchlists via _GetWatchlist(); stub it from
        # the fixture's "watchlist" values so the rule's real query runs unchanged in the emulator.
        wl = fx.get("watchlist")
        if wl is not None:
            vals = ", ".join('"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"' for v in wl)
            mgmt(f".create-or-alter function _GetWatchlist(WatchlistAlias:string) "
                 f"{{ datatable(SearchKey:string)[{vals}] }}")
        for scenario, should_fire in (("fires", True), ("silent", False)):
            table_map = fx.get("tables")
            if table_map is not None:
                # Replace every declared source table on each scenario so a prior
                # scenario cannot leak a row into a union query. A multi-table
                # fixture must declare every source table required by its query;
                # loading only declared tables also avoids relying on emulator-
                # specific syntax for an empty datatable.
                for table_name, table_info in table_map.items():
                    table_events = table_map.get(table_name, {}).get(scenario, [])
                    load_table(table_events, table_name)
                events = [
                    event
                    for table_info in table_map.values()
                    for event in table_info.get(scenario, [])
                ]
            else:
                table = fx.get("table", "AzureActivity")
                events = fx.get(scenario, [])
                load_table(events, table)
            if not events:
                continue
            total += 1
            n = query_count(rule["query"])
            expected_counts = fx.get("expected_counts", {})
            if scenario in expected_counts:
                expected = expected_counts[scenario]
                ok = n == expected
                expected_text = f"{expected} result row(s)"
            else:
                ok = (n > 0) == should_fire
                expected_text = "fire" if should_fire else "silent"
            verb = "FIRED" if n > 0 else "silent"
            mark = "ok  " if ok else "FAIL"
            print(f"  [{mark}] {rule['name']} / {scenario}: expected {expected_text}, got {verb} ({n})")
            if not ok:
                failures += 1
    print(f"\nCoverage: {fixture_rules} fixture-backed, {live_only_rules} live-only (not run offline)")
    print(f"{total - failures}/{total} fixture assertions passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
