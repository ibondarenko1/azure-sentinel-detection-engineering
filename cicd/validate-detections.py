#!/usr/bin/env python3
"""Validate the detection catalog offline. Use --live for a workspace KQL check."""

import argparse
import os
import sys

from yaml import YAMLError

from azure_auth import access_token
from catalog_evidence import check_evidence
from detection_rules import GUID, CatalogError, load_catalog
from workspace_logs import LOGS_AUDIENCE, WorkspaceQueryError, query_rows


def smoke_query(query, workspace, token):
    try:
        query_rows(workspace, token, query.rstrip().removesuffix(";") + "\n| take 0")
    except WorkspaceQueryError as exc:
        return str(exc)
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="run each rule in Log Analytics with take 0")
    parser.add_argument("--workspace", default=os.getenv("SENTINEL_WORKSPACE_GUID"),
                        help="Log Analytics workspace customer ID for --live")
    parser.add_argument("--rule", action="append", help="check selected rule IDs (repeatable)")
    args = parser.parse_args(argv)
    if args.live and (not args.workspace or not GUID.fullmatch(args.workspace)):
        parser.error("--live requires a workspace customer ID via --workspace or SENTINEL_WORKSPACE_GUID")

    try:
        detections = load_catalog()
        evidence_errors = check_evidence(detections)
        if evidence_errors:
            raise CatalogError("\n".join(evidence_errors))
        if args.rule:
            unknown = set(args.rule) - {detection.code for detection in detections}
            if unknown:
                raise CatalogError(f"unknown detection IDs: {', '.join(sorted(unknown))}")
            detections = [detection for detection in detections if detection.code in args.rule]
        token = access_token(LOGS_AUDIENCE) if args.live else None
    except (OSError, RuntimeError, ValueError, YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    failures = 0
    for detection in detections:
        error = smoke_query(detection.rule["query"], args.workspace, token) if args.live else None
        if error:
            failures += 1
            print(f"FAIL {detection.file}: {error}", file=sys.stderr)
        else:
            print(f"OK   {detection.file}" + (" (+workspace KQL check)" if args.live else ""))
    print(f"{len(detections) - failures}/{len(detections)} rules passed "
          f"{'workspace KQL and catalog' if args.live else 'offline catalog'} validation.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
