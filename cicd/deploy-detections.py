#!/usr/bin/env python3
"""Render or apply the validated Sentinel scheduled rule catalog."""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from azure_auth import access_token
from detection_rules import GUID, TRIGGER_OPERATORS, CatalogError, duration_seconds, load_catalog

API_VERSION = "2025-09-01"
ARM = "https://management.azure.com"
WATCHLIST = re.compile(r"""\b_GetWatchlist\s*\(\s*['"]([^'"]+)['"]\s*\)""")


class ArmHttpError(RuntimeError):
    def __init__(self, method, status, detail=""):
        self.status = status
        super().__init__(f"Sentinel {method} returned HTTP {status}{detail}")


def build_properties(rule):
    op = TRIGGER_OPERATORS[rule.get("triggerOperator", "gt").lower()]
    # The alertRules API wants parent techniques in `techniques` (T####) and
    # sub-techniques in `subTechniques` (T####.###); splitting keeps both valid.
    techs = rule.get("relevantTechniques", [])
    parents = sorted({t.split(".")[0] for t in techs})
    subs = sorted(t for t in techs if "." in t)
    grouping = rule.get("incidentGrouping") or {}
    props = {
        "displayName": rule["name"],
        "description": rule.get("description", ""),
        "severity": rule["severity"],
        "enabled": rule.get("enabled", True),
        "query": rule["query"],
        "queryFrequency": rule["queryFrequency"],
        "queryPeriod": rule["queryPeriod"],
        "triggerOperator": op,
        "triggerThreshold": rule.get("triggerThreshold", 0),
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": rule.get("tactics", []),
        "techniques": parents,
        "subTechniques": subs,
        "entityMappings": rule.get("entityMappings") or [],
        # A scheduled rule whose queryPeriod is wider than its queryFrequency runs over
        # overlapping look-back windows, so the same finding is re-emitted on consecutive
        # runs (see the ingestion-latency case study). Grouping folds those repeat alerts
        # into one incident per matching entity set instead of one incident per run.
        # Default lookback = the rule's own queryPeriod so the whole detection window is
        # deduplicated; a rule can override any field with an `incidentGrouping` block.
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": grouping.get("enabled", True),
                "lookbackDuration": grouping.get("lookbackDuration", rule["queryPeriod"]),
                "matchingMethod": grouping.get("matchingMethod", "AllEntities"),
                "reopenClosedIncident": grouping.get("reopenClosedIncident", False),
            },
        },
    }
    return props


def deployment_plan(detections, selected=()):
    unknown = set(selected) - {detection.code for detection in detections}
    if unknown:
        raise CatalogError(f"unknown detection IDs: {', '.join(sorted(unknown))}")
    return {
        "apiVersion": API_VERSION,
        "rules": [
            {
                "detectionId": detection.code,
                "ruleId": detection.rule["id"].lower(),
                "source": f"detections/rules/{detection.file}",
                "requiredTables": sorted({
                    table for connector in detection.rule["requiredDataConnectors"]
                    for table in connector["dataTypes"]
                }),
                "watchlists": sorted(set(WATCHLIST.findall(detection.rule["query"]))),
                "body": {"kind": "Scheduled", "properties": build_properties(detection.rule)},
            }
            for detection in detections if not selected or detection.code in selected
        ],
    }


def target_url(subscription, resource_group, workspace):
    if not subscription or not GUID.fullmatch(subscription):
        raise ValueError("set AZURE_SUBSCRIPTION_ID or --subscription to a subscription GUID")
    if (not resource_group or not re.fullmatch(r"[\w.()\-]{1,90}", resource_group)
        or resource_group.endswith(".")):
        raise ValueError("set SENTINEL_RESOURCE_GROUP or --resource-group to an Azure resource group")
    if not workspace or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]{2,61}[a-zA-Z0-9]", workspace):
        raise ValueError("set SENTINEL_WORKSPACE or --workspace to a Log Analytics workspace name")
    return (f"{ARM}/subscriptions/{subscription}/resourceGroups/{quote(resource_group, safe='')}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
            "/providers/Microsoft.SecurityInsights")


def arm_request(method, url, token, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(url, method=method, data=data,
                      headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urlopen(request, timeout=60) as response:
            if response.status not in ((200, 201) if method == "PUT" else (200,)):
                raise RuntimeError(f"unexpected Sentinel response HTTP {response.status}")
            return json.load(response) if method == "GET" else None
    except HTTPError as exc:
        try:
            code = json.loads(exc.read()).get("error", {}).get("code", "")
        except (AttributeError, ValueError):
            code = ""
        detail = f" ({code})" if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", code) else ""
        raise ArmHttpError(method, exc.code, detail) from exc
    except URLError as exc:
        raise RuntimeError(f"could not reach Azure Resource Manager: {exc.reason}") from exc
    except ValueError as exc:
        raise RuntimeError("Sentinel returned invalid JSON on readback") from exc


def normalize_property(field, value):
    if field in {"queryFrequency", "queryPeriod", "suppressionDuration"}:
        seconds = duration_seconds(value)
        return seconds if seconds is not None else value
    if field in {"query", "description"} and isinstance(value, str):
        return value.replace("\r\n", "\n").strip()
    if field in {"tactics", "techniques", "subTechniques", "entityMappings"}:
        if value is None:
            return []
        if isinstance(value, list):
            if field == "entityMappings":
                value = [
                    {**item, "fieldMappings": sorted(item["fieldMappings"], key=_stable_json)}
                    if isinstance(item, dict) and isinstance(item.get("fieldMappings"), list) else item
                    for item in value
                ]
            return sorted(value, key=_stable_json)
    if field == "incidentConfiguration" and isinstance(value, dict):
        grouping = value.get("groupingConfiguration")
        if isinstance(grouping, dict):
            lookback = grouping.get("lookbackDuration")
            value = {
                "createIncident": value.get("createIncident"),
                "groupingConfiguration": {
                    "enabled": grouping.get("enabled"),
                    "lookbackDuration": normalize_property("queryPeriod", lookback),
                    "matchingMethod": grouping.get("matchingMethod"),
                    "reopenClosedIncident": grouping.get("reopenClosedIncident", False),
                },
            }
    return value


def _stable_json(value):
    return json.dumps(value, sort_keys=True)


def readback_differences(expected, actual):
    if not isinstance(actual, dict) or not isinstance(actual.get("properties"), dict):
        return ["response shape"]
    differences = ["kind"] if actual.get("kind") != expected["kind"] else []
    for field, desired in expected["properties"].items():
        before = normalize_property(field, desired)
        after = normalize_property(field, actual["properties"].get(field))
        if _stable_json(before) != _stable_json(after):
            if field == "incidentConfiguration" and isinstance(before, dict) and isinstance(after, dict):
                differences.extend(
                    f"{field}.{key}" for key in before
                    if _stable_json(before[key]) != _stable_json(after.get(key))
                )
            else:
                differences.append(field)
    return differences


def verify_watchlists(base, plan, token):
    aliases = sorted({
        alias for rule in plan["rules"] if rule["body"]["properties"]["enabled"]
        for alias in rule["watchlists"]
    })
    for alias in aliases:
        url = f"{base}/watchlists/{quote(alias, safe='')}?api-version={plan['apiVersion']}"
        try:
            observed = arm_request("GET", url, token)
            properties = observed.get("properties") if isinstance(observed, dict) else None
            if (
                not isinstance(properties, dict) or not properties.get("itemsSearchKey")
                or properties.get("isDeleted") or properties.get("provisioningState") not in (None, "Succeeded")
            ):
                raise RuntimeError("watchlist is not ready or has no search key")
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(f"Watchlist prerequisite {alias}: {exc}. No rules were written.") from exc


def inspect_workspace(plan, args):
    base = target_url(args.subscription, args.resource_group, args.workspace)
    token = access_token(f"{ARM}/", args.subscription)
    version = plan["apiVersion"]
    onboarding = f"{base}/onboardingStates/default?api-version={version}"
    try:
        state = arm_request("GET", onboarding, token)
    except ArmHttpError as exc:
        if exc.status == 404:
            raise RuntimeError("Sentinel onboarding was not found in the selected workspace") from exc
        raise
    if not isinstance(state, dict) or not isinstance(state.get("properties"), dict):
        raise RuntimeError("Sentinel onboarding returned an unexpected response shape")
    changes = []
    for rule in plan["rules"]:
        rule_id = rule["ruleId"]
        url = f"{base}/alertRules/{rule_id}?api-version={version}"
        try:
            observed = arm_request("GET", url, token)
        except ArmHttpError as exc:
            if exc.status != 404:
                raise
            changes.append((rule, url, "create", []))
            continue
        if not isinstance(observed, dict) or not isinstance(observed.get("properties"), dict):
            raise RuntimeError(f"{rule['detectionId']}: unexpected rule response shape")
        differences = readback_differences(rule["body"], observed)
        changes.append((rule, url, "update" if differences else "unchanged", differences))
    return base, token, changes


def apply_plan(plan, args):
    base, token, changes = inspect_workspace(plan, args)
    verify_watchlists(base, plan, token)
    pending = [change for change in changes if change[2] != "unchanged"]
    unchanged = len(changes) - len(pending)
    print(f"Applying {len(pending)} change(s) to {args.resource_group}/{args.workspace}; {unchanged} unchanged")
    for index, (rule, url, action, _) in enumerate(pending):
        rule_id = rule["ruleId"]
        try:
            arm_request("PUT", url, token, rule["body"])
            observed = arm_request("GET", url, token)
            differences = readback_differences(rule["body"], observed)
            if differences:
                raise RuntimeError(f"readback differs on: {', '.join(differences)}")
        except (OSError, RuntimeError) as exc:
            remaining = len(pending) - index - 1
            raise RuntimeError(f"{rule['detectionId']}: {exc}. Previously verified: {index}. "
                               f"Later rules not attempted: {remaining}. Verify the failed rule in Azure before retrying.") from exc
        print(f"  OK {rule['detectionId']} ({rule_id}), {action}, readback verified")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="render the desired rule bodies offline")
    plan.add_argument("--output", type=Path, help="write the plan to a JSON file")
    diff = commands.add_parser("diff", help="compare the selected rules with Azure using only reads")
    diff.add_argument("--output", type=Path, help="write the comparison to a JSON file")
    apply = commands.add_parser("apply", help="write new and changed rules in Azure")
    for cmd in (diff, apply):
        cmd.add_argument("--subscription", default=os.getenv("AZURE_SUBSCRIPTION_ID"))
        cmd.add_argument("--resource-group", default=os.getenv("SENTINEL_RESOURCE_GROUP"))
        cmd.add_argument("--workspace", default=os.getenv("SENTINEL_WORKSPACE"))
    for cmd in (plan, diff, apply):
        cmd.add_argument("--rule", action="append", help="include this detection ID (repeatable)")
    args = parser.parse_args(argv)

    try:
        rendered = deployment_plan(load_catalog(), args.rule or [])
        if args.command == "apply":
            apply_plan(rendered, args)
        else:
            if args.command == "diff":
                _, _, changes = inspect_workspace(rendered, args)
                rendered = {"apiVersion": rendered["apiVersion"], "rules": [
                    {"detectionId": rule["detectionId"], "ruleId": rule["ruleId"],
                     "action": action, "differences": differences}
                    for rule, _, action, differences in changes
                ]}
            data = json.dumps(rendered, indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.write_text(data, encoding="utf-8", newline="\n")
            else:
                sys.stdout.write(data)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
