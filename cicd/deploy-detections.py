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
        "entityMappings": rule.get("entityMappings"),
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
    if subs:
        props["subTechniques"] = subs
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
        raise RuntimeError(f"Sentinel {method} returned HTTP {exc.code}{detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"could not reach Azure Resource Manager: {exc.reason}") from exc
    except ValueError as exc:
        raise RuntimeError("Sentinel returned invalid JSON on readback") from exc


def readback_differences(expected, actual):
    if not isinstance(actual, dict) or not isinstance(actual.get("properties"), dict):
        return ["response shape"]
    fields = ("displayName", "severity", "enabled", "query", "queryFrequency", "queryPeriod",
              "triggerOperator", "triggerThreshold")
    differences = ["kind"] if actual.get("kind") != expected["kind"] else []
    for field in fields:
        before, after = expected["properties"][field], actual["properties"].get(field)
        if field in ("queryFrequency", "queryPeriod"):
            before, after = duration_seconds(before), duration_seconds(after)
        if field == "query" and isinstance(after, str):
            before, after = before.strip(), after.strip()
        if type(before) is not type(after) or before != after:
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


def apply_plan(plan, args):
    base = target_url(args.subscription, args.resource_group, args.workspace)
    token = access_token(f"{ARM}/", args.subscription)
    verify_watchlists(base, plan, token)
    print(f"Applying {len(plan['rules'])} rule(s) to {args.resource_group}/{args.workspace}")
    for index, rule in enumerate(plan["rules"]):
        rule_id = rule["ruleId"]
        url = f"{base}/alertRules/{rule_id}?api-version={plan['apiVersion']}"
        try:
            arm_request("PUT", url, token, rule["body"])
            observed = arm_request("GET", url, token)
            differences = readback_differences(rule["body"], observed)
            if differences:
                raise RuntimeError(f"readback differs on: {', '.join(differences)}")
        except (OSError, RuntimeError) as exc:
            remaining = len(plan["rules"]) - index - 1
            raise RuntimeError(f"{rule['detectionId']}: {exc}. Previously verified: {index}. "
                               f"Later rules not attempted: {remaining}. Verify the failed rule in Azure before retrying.") from exc
        print(f"  OK {rule['detectionId']} ({rule_id}), readback verified")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="render the desired rule bodies offline")
    plan.add_argument("--output", type=Path, help="write the plan to a JSON file")
    apply = commands.add_parser("apply", help="upsert the selected rules in Azure")
    apply.add_argument("--subscription", default=os.getenv("AZURE_SUBSCRIPTION_ID"))
    apply.add_argument("--resource-group", default=os.getenv("SENTINEL_RESOURCE_GROUP"))
    apply.add_argument("--workspace", default=os.getenv("SENTINEL_WORKSPACE"))
    for cmd in (plan, apply):
        cmd.add_argument("--rule", action="append", help="include this detection ID (repeatable)")
    args = parser.parse_args(argv)

    try:
        rendered = deployment_plan(load_catalog(), args.rule or [])
        if args.command == "apply":
            apply_plan(rendered, args)
        else:
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
