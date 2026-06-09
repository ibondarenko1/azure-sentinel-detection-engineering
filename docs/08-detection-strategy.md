# Detection strategy and threat model

Detections here are not picked at random or by "what's easy to write". They are chosen to cover the
choke points of a realistic Azure attack chain, weighted by blast radius, by what the available
telemetry can actually support, and by ATT&CK-for-cloud prevalence. The principle is **depth and
measurement over breadth**: a small catalog that is correct, tested, and tuned beats a long list of
event-watchers.

## What is defended

A single Azure subscription, its Entra ID tenant, and one onboarded endpoint, observed through three
planes that land in one Log Analytics workspace (`sc200-ws`):

- **Control plane** (`AzureActivity`): who did what to Azure resources and RBAC.
- **Identity** (`SigninLogs`): authentication, the first step of most cloud intrusions.
- **Endpoint** (`Device*`, Defender for Endpoint): on-host execution and credential access.

## Adversary model (the chain we expect)

A cloud intrusion is rarely one event; it is a sequence. The catalog is mapped to that sequence so
each stage has a detection, and the high-value rules sit where stages join.

| Kill-chain stage | Technique | Detection | Why it matters |
|------------------|-----------|-----------|----------------|
| Initial access (identity) | T1110 Brute Force / T1078 Valid Accounts | DET-008 | A sprayed/guessed credential that finally succeeds is the front door. |
| Discovery / recon | T1087 Account Discovery | DET-001 | Failed-permission probing reveals an actor mapping what they can touch. |
| Privilege escalation / persistence | T1098 Account Manipulation | DET-003 | An RBAC grant survives password resets and is the cloud's persistence. |
| Defense evasion | T1562.007 Disable/Modify Cloud Firewall | DET-002, DET-009 | Opening an NSG inbound from Any weakens the network boundary. |
| Credential access (endpoint) | T1003.001 LSASS Memory | DET-006 | LSASS is the first target after landing on a host. |
| Impact | T1485 Data Destruction | DET-004 | Mass deletion is destructive impact and a ransom/teardown signal. |
| **Escalation then action (cross-stage)** | T1098 chain | **DET-007** | Granting access and immediately using it is the behaviour, not either event alone. |

Two rules are deliberately past single-event matching:
- **DET-007** correlates two stages (grant then deploy by the same principal) into one high-severity
  signal, lowering the per-stage false positives.
- **DET-009** is content-aware: it joins the change event to NSG rule config pulled from Azure
  Resource Graph, so it fires only when a change actually left the NSG open, which the change event
  alone cannot tell.

## Design principle: build to the telemetry you actually have

Every rule is written against fields verified to exist in the live records, not assumed. Two findings
shaped the catalog and are documented in the cards:
- `AzureActivity` roleAssignments carries the caller and source IP but **not** the role or target
  principal, so DET-003 filters on an automation allow-list (the dimension the data supports), not on
  the role granted.
- `AzureActivity` securityRules writes carry **no** rule body (access / direction / source), so DET-002
  cannot judge "opened inbound" from that event; DET-009 brings the content in from Resource Graph.

This is the difference between a rule that fires in a demo and one that fires in the tenant.

## Allow-lists as fidelity, not suppression

DET-002/003/005 separate expected from suspicious with Sentinel watchlists (`_GetWatchlist`). The
identities live in the tenant, never in the repo. The fidelity goal is to surface the unexpected
actor, not to mute the rule: a legitimate principal missing from the list is the expected false
positive, and the fix is to add it, not to loosen the logic.

## Roadmap is risk-ranked, not aspirational

The gaps are explicit ATT&CK Navigator red cells and live issues, ordered by impact:
- [#13 T1496 Resource Hijacking](../../issues/13), spend/mining anomaly (cost impact).
- [#12 T1530 Data from Cloud Storage](../../issues/12), storage data-plane access (collection).
- [#14 T1526 Cloud Service Discovery](../../issues/14), strengthen the DET-001 heuristic.

They are deferred deliberately, not forgotten: each needs either a data source not yet onboarded or a
baseline not yet accumulated, and the repo says so rather than shipping a rule that cannot fire.

## How "good" is measured here

- **Correctness:** unit tests (fires-on-malicious / silent-on-benign) gate every merge.
- **Fidelity:** the [validation harness](../validation) runs a real benign + attack batch and measures
  false positives, instead of asserting a rate. See [validation/RESULTS.md](../validation/RESULTS.md).
- **Honesty:** single-tenant scale is a stated ceiling; metrics report what was measured, not a
  production number the lab cannot produce.
