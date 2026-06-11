#!/usr/bin/env python3
"""Generate the kql/detections/*.kql mirror from the rule YAML (the source of truth).

Each .kql is a portal/ADX-pasteable copy of a deployed rule's query, with a generated header.
Run with --check in CI to fail if the mirror has drifted from the YAML; run with no args to
regenerate. The YAML in detections/rules/ is the only source of truth; never hand-edit the mirror.
"""
import os
import sys
import re
import glob

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "detections", "rules")
MIRROR = os.path.join(ROOT, "kql", "detections")


def human_freq(pt):
    m = re.match(r"PT(?:(\d+)H)?(?:(\d+)M)?", pt or "")
    if not m:
        return pt
    h, mn = m.group(1), m.group(2)
    if h:
        return f"every {int(h) * 60} min" if not mn else f"every {h}h{mn}m"
    return f"every {mn} min"


def human_period(pt):
    m = re.match(r"PT(?:(\d+)H)?(?:(\d+)M)?", pt or "")
    if not m:
        return pt
    h, mn = m.group(1), m.group(2)
    return (f"{h}h" if h else "") + (f"{mn}m" if mn else "")


def render(path):
    r = yaml.safe_load(open(path, encoding="utf-8"))
    name = re.sub(r"^\[DET\]\s*", "", r["name"])
    tactics = " / ".join(r.get("tactics", []))
    techs = " ".join(r.get("relevantTechniques", []))
    conn = r.get("requiredDataConnectors", [{}])[0]
    sources = ", ".join(conn.get("dataTypes", [])) or "n/a"
    base = re.match(r"(DET-\d+)", os.path.basename(path)).group(1)
    header = (
        f"// {base}, {name}\n"
        f"// MITRE: {tactics} / {techs}\n"
        f"// Source: {sources} | Frequency: {human_freq(r.get('queryFrequency'))} "
        f"| Lookback: {human_period(r.get('queryPeriod'))}\n"
        f"// Generated from detections/rules/{os.path.basename(path)} by cicd/sync-kql-mirror.py, do not edit by hand.\n"
    )
    return base, header + r["query"].rstrip() + "\n"


def main():
    check = "--check" in sys.argv
    os.makedirs(MIRROR, exist_ok=True)
    want = {}
    for path in sorted(glob.glob(os.path.join(RULES, "*.yaml"))):
        base, content = render(path)
        want[base + ".kql"] = content
    drift = []
    # stale files in the mirror that no longer have a rule
    existing = {os.path.basename(p) for p in glob.glob(os.path.join(MIRROR, "*.kql"))}
    for stale in existing - set(want):
        drift.append(f"stale (no rule): {stale}")
        if not check:
            os.remove(os.path.join(MIRROR, stale))
    for fname, content in want.items():
        fp = os.path.join(MIRROR, fname)
        cur = open(fp, encoding="utf-8").read() if os.path.exists(fp) else None
        if cur != content:
            drift.append(f"out of sync: {fname}")
            if not check:
                open(fp, "w", encoding="utf-8", newline="\n").write(content)
    if check:
        if drift:
            print("kql mirror DRIFT (run: python cicd/sync-kql-mirror.py):")
            for d in drift:
                print("  -", d)
            sys.exit(1)
        print(f"kql mirror in sync ({len(want)} rules).")
    else:
        print(f"regenerated {len(want)} mirror file(s)" + (f", {len(drift)} changed" if drift else ", no changes"))


if __name__ == "__main__":
    main()
