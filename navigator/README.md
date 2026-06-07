# ATT&CK coverage layer

[`coverage-layer.json`](coverage-layer.json) is a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer showing what these detections cover — **and, honestly, what they don't**. A coverage map with explicit gaps is a stronger signal than a list of rules.

## Load it

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. **Open Existing Layer → Upload from local** → select `coverage-layer.json`.

## What it shows

**Covered (green)** — one technique per deployed rule:

| Technique | Rule |
|-----------|------|
| T1087 Account Discovery | SC200-01 (heuristic) |
| T1562.007 Disable/Modify Cloud Firewall | SC200-02 |
| T1098.003 Additional Cloud Roles | SC200-03 |
| T1485 Data Destruction | SC200-04 |
| T1098 Account Manipulation | SC200-03 / SC200-05 |

**Known gaps (red)** — same cloud kill-chain, not yet detected:

| Technique | Gap |
|-----------|-----|
| T1078 Valid Accounts | no sign-in / impossible-travel anomaly detection |
| T1110 Brute Force | no auth-failure correlation on sign-ins |
| T1526 Cloud Service Discovery | only partially implied by SC200-01 |
| T1530 Data from Cloud Storage | no storage data-plane access detection |
| T1496 Resource Hijacking | no crypto-mining / spend-anomaly detection |

The gaps are the backlog: they say *where this would go next*, which is the point.
