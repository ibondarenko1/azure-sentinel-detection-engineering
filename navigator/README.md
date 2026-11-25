# ATT&CK coverage layer

[`coverage-layer.json`](coverage-layer.json) maps the catalog to Enterprise ATT&CK v20.1. A mapping
describes the behavior a rule observes. Each annotation identifies the rule and its evidence.

## Load it

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. **Open Existing Layer → Upload from local** → select `coverage-layer.json`.

## What it shows

- **Green** marks a technique with at least one historical lab observation. For example, the
  Cloud Firewall cell associates DET-002's historical NSG alert with DET-009's current fixtures.
- **Amber** marks evidence from synthetic fixtures, including DET-008's sign-in sequence.
- **Red** marks a tracked gap. See the [detection strategy](../docs/08-detection-strategy.md).

The NSG rules use `T1686.001`, which replaces `T1562.007`. The rule payload retains the
`DefenseEvasion` tactic enum documented by the pinned Sentinel ARM API. The layer uses ATT&CK's
current Defense Impairment taxonomy. [Cloud Firewall](https://attack.mitre.org/techniques/T1686/001/) · [Sentinel API](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update?view=rest-securityinsights-2025-09-01#attacktactic)
