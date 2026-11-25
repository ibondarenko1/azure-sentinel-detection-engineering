"""Load and validate the rule catalog before producing a Sentinel deployment."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parents[1] / "detections" / "rules"
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.IGNORECASE)
DETECTION_ID = re.compile(r"(DET-\d{3,})-.+\.yaml")
DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")
SEVERITIES = {"Informational", "Low", "Medium", "High"}
TRIGGER_OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}


class CatalogError(ValueError):
    """The rule catalog cannot be used."""


class RuleLoader(yaml.SafeLoader):
    """Reject YAML that can hide a second value behind a reviewed field."""

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            return super().construct_mapping(node, deep)
        keys = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None, None, "YAML merge keys are unsupported in rule files", key_node.start_mark
                )
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None, None, "rule mapping keys must be strings", key_node.start_mark
                )
            if key in keys:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate YAML key {key!r}", key_node.start_mark
                )
            keys.add(key)
        return super().construct_mapping(node, deep)


@dataclass(frozen=True)
class Detection:
    code: str
    file: str
    rule: dict


def duration_seconds(value):
    match = DURATION.fullmatch(value) if isinstance(value, str) else None
    if not match or value.endswith("T") or not any(match.groups()):
        return None
    days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def string_list(value):
    return isinstance(value, list) and bool(value) and all(nonblank(item) for item in value)


def validate_rule(rule):
    if not isinstance(rule, dict):
        return ["expected a YAML mapping"]
    errors = []
    for key in ("id", "name", "query", "severity", "queryFrequency", "queryPeriod"):
        if not nonblank(rule.get(key)):
            errors.append(f"{key} must be a nonempty string")

    if nonblank(rule.get("id")) and not GUID.fullmatch(rule["id"]):
        errors.append("id must be a GUID")
    if nonblank(rule.get("severity")) and rule["severity"] not in SEVERITIES:
        errors.append("severity must be Informational, Low, Medium, or High")
    if not isinstance(rule.get("description", ""), str):
        errors.append("description must be a string")
    if not isinstance(rule.get("enabled", True), bool):
        errors.append("enabled must be a boolean")
    if not isinstance(rule.get("deployByDefault", True), bool):
        errors.append("deployByDefault must be a boolean")

    frequency = duration_seconds(rule.get("queryFrequency"))
    period = duration_seconds(rule.get("queryPeriod"))
    for field, seconds in (("queryFrequency", frequency), ("queryPeriod", period)):
        if seconds is None or not 300 <= seconds <= 14 * 86400:
            errors.append(f"{field} must be an ISO 8601 duration between 5 minutes and 14 days")
    if frequency is not None and period is not None and frequency > period:
        errors.append("queryFrequency must not exceed queryPeriod")

    op = rule.get("triggerOperator", "gt")
    if not isinstance(op, str) or op.lower() not in TRIGGER_OPERATORS:
        errors.append("triggerOperator must be gt, lt, eq or ne")
    threshold = rule.get("triggerThreshold", 0)
    if type(threshold) is not int or threshold < 0:
        errors.append("triggerThreshold must be a nonnegative integer")

    if not string_list(rule.get("tactics")):
        errors.append("tactics must be a nonempty list of strings")
    techniques = rule.get("relevantTechniques")
    if not string_list(techniques) or not all(re.fullmatch(r"T\d{4}(?:\.\d{3})?", t) for t in techniques):
        errors.append("relevantTechniques must be a nonempty list of MITRE ATT&CK technique IDs")

    connectors = rule.get("requiredDataConnectors")
    if not isinstance(connectors, list) or not connectors or not all(
        isinstance(connector, dict) and nonblank(connector.get("connectorId"))
        and string_list(connector.get("dataTypes")) for connector in connectors
    ):
        errors.append("requiredDataConnectors must list connector IDs and data tables")

    mappings = rule.get("entityMappings")
    if not isinstance(mappings, list) or not mappings:
        errors.append("entityMappings must be a nonempty list")
    else:
        for item in mappings:
            fields = item.get("fieldMappings") if isinstance(item, dict) else None
            if (not isinstance(item, dict) or not nonblank(item.get("entityType"))
                or not isinstance(fields, list) or not fields or not all(
                    isinstance(field, dict) and nonblank(field.get("identifier"))
                    and nonblank(field.get("columnName")) for field in fields
                )):
                errors.append("each entity mapping needs an entityType and identifier/columnName pairs")

    grouping = rule.get("incidentGrouping", {})
    if not isinstance(grouping, dict):
        errors.append("incidentGrouping must be a mapping")
    else:
        for key in ("enabled", "reopenClosedIncident"):
            if key in grouping and not isinstance(grouping[key], bool):
                errors.append(f"incidentGrouping.{key} must be a boolean")
        if grouping.get("matchingMethod", "AllEntities") not in ("AllEntities", "AnyAlert"):
            errors.append("incidentGrouping.matchingMethod must be AllEntities or AnyAlert")
        lookback = duration_seconds(grouping.get("lookbackDuration", rule.get("queryPeriod")))
        if grouping.get("enabled", True) and (lookback is None or not 300 <= lookback <= 7 * 86400):
            errors.append("incident grouping lookback must be 5 minutes to 7 days when enabled")
    return errors


def load_catalog(directory=RULES_DIR):
    """Return all validated rules, or report every file that prevents release."""
    files = sorted(Path(directory).glob("*.yaml"))
    if not files:
        raise CatalogError(f"no rule YAML found in {directory}")

    errors, detections = [], []
    codes, guids = {}, {}
    for path in files:
        try:
            rule = yaml.load(path.read_text(encoding="utf-8"), Loader=RuleLoader)
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        problems = validate_rule(rule)
        match = DETECTION_ID.fullmatch(path.name)
        if match is None:
            problems.append("filename must start with a DET-NNN identifier")
        if problems:
            errors.extend(f"{path.name}: {problem}" for problem in problems)
            continue

        code, guid = match[1], rule["id"].lower()
        if code in codes:
            errors.append(f"{path.name}: duplicate detection ID {code} (also in {codes[code]})")
        if guid in guids:
            errors.append(f"{path.name}: duplicate rule GUID {guid} (also in {guids[guid]})")
        codes[code], guids[guid] = path.name, path.name
        detections.append(Detection(code, path.name, rule))

    if errors:
        raise CatalogError("\n".join(errors))
    return detections
