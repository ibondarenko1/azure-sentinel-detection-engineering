"""Check that the catalog's review artifacts still refer to the authored rules."""

import json
from pathlib import Path

import yaml

from detection_rules import duration_seconds

ROOT = Path(__file__).resolve().parents[1]


def check_evidence(detections, root=ROOT):
    errors = []
    metrics = yaml.safe_load((root / "detections/metrics.yaml").read_text(encoding="utf-8"))
    layer = json.loads((root / "navigator/coverage-layer.json").read_text(encoding="utf-8"))
    if not isinstance(metrics, dict):
        return ["detections/metrics.yaml must contain one mapping per detection ID"]
    if not isinstance(layer, dict) or not isinstance(layer.get("techniques"), list):
        return ["navigator/coverage-layer.json must contain a techniques array"]

    codes = {item.code for item in detections}
    missing = codes - metrics.keys()
    extra = metrics.keys() - codes
    if missing:
        errors.append("metrics missing detection IDs: " + ", ".join(sorted(missing)))
    if extra:
        errors.append("metrics contain unknown detection IDs: " + ", ".join(sorted(map(str, extra))))
    covered = {
        item["techniqueID"] for item in layer["techniques"]
        if isinstance(item, dict) and isinstance(item.get("techniqueID"), str) and item.get("score") == 100
    }
    for detection in detections:
        code, rule = detection.code, detection.rule
        card = (root / "detections" / detection.file).with_suffix(".md")
        if not card.is_file():
            errors.append(f"{code}: no rule card at detections/{card.name}")
        if code in metrics:
            entry = metrics[code]
            interval = entry.get("ruleIntervalMinutes") if isinstance(entry, dict) else None
            if type(interval) is not int or interval * 60 != duration_seconds(rule["queryFrequency"]):
                errors.append(f"{code}: metrics ruleIntervalMinutes does not match queryFrequency")
        for technique in rule["relevantTechniques"]:
            if technique not in covered:
                errors.append(f"{code}: Navigator does not mark {technique} as covered")
    return errors
