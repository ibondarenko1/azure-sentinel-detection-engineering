# Hunting queries

Curated KQL from this environment's Advanced-hunting history (the advanced-hunting drill set), kept as a reusable hunting library and used for investigation pivots. Export each as its own `.kql` file here.

## Endpoint and vulnerability management (in repo)

Run these in Defender advanced hunting. The `DeviceTvm*` tables live there, not in the Sentinel
workspace, so these are hunts rather than deployed rules. Context: [docs/07](../../docs/07-endpoint-vulnerability-management.md).

| File | What it hunts | Source |
|------|---------------|--------|
| [`endpoint-lsass-access.kql`](endpoint-lsass-access.kql) | Every LSASS credential-theft signal (handle-open, dump-tool command line, Defender prevention), companion to DET-006 | DeviceEvents ∪ DeviceProcessEvents ∪ AlertInfo ⨝ AlertEvidence |
| [`endpoint-critical-cve-exposed.kql`](endpoint-critical-cve-exposed.kql) | Critical/High CVEs by exposed software, KB-scored for CVSS and exploit availability | DeviceTvmSoftwareVulnerabilities ⨝ DeviceTvmSoftwareVulnerabilitiesKB |
| [`endpoint-failed-security-baseline.kql`](endpoint-failed-security-baseline.kql) | Failed secure-configuration assessments by category, ranked by impact (hardening feedback) | DeviceTvmSecureConfigurationAssessment |
| [`endpoint-vulnerable-asset-under-alert.kql`](endpoint-vulnerable-asset-under-alert.kql) | Vulnerable assets correlated with an active alert | AlertEvidence ⨝ AlertInfo ⨝ DeviceTvmSoftwareVulnerabilities |

## Email and phishing (planned)

Planned set (paste from query history):

| File | What it hunts | Source |
|------|---------------|--------|
| `email-phishing-keywords.kql` | Inbound subjects with classic phishing lures | EmailEvents |
| `email-display-name-spoofing.kql` | Brand display-name from non-matching sender domain | EmailEvents |
| `email-auth-fail-spf-dkim-dmarc.kql` | Inbound mail failing SPF/DKIM/DMARC | EmailEvents |
| `url-ip-literal-domain.kql` | URLs whose domain is a raw IP (phishing indicator) | EmailUrlInfo |
| `url-tld-distribution.kql` | Suspicious TLD distribution across URLs | EmailUrlInfo |
| `join-email-urlinfo.kql` | EmailEvents ⨝ EmailUrlInfo on NetworkMessageId | multi-table |
| `join-alertinfo-evidence.kql` | AlertInfo ⨝ AlertEvidence on AlertId | multi-table |
| `exposuregraph-census.kql` | Asset/config census from the exposure graph | ExposureGraphNodes |

These back the **v2 email/phishing detection family** (see repo backlog).
