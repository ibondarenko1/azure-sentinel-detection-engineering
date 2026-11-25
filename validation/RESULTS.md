# Validation run results

Historical lab evidence. The original record did not include a run ID, git revision or UTC
timestamp. The DET-009 row refers to the earlier NSG-name watchlist and does not validate the
current resource-ID correlation in Azure.

Live mixed-activity run: a benign stream (must stay silent) and an attack stream (must fire),
measured by running each deployed rule's real KQL against `sc200-ws`. Benign actions are below
thresholds / outside correlation windows by design, so they do not appear in query output;
their absence is the measured false-positive result (0).

| Detection | Attack action (expect fire) | Benign action (expect silent) | Measured |
|-----------|------------------------------|-------------------------------|----------|
| DET-002 | open NSG securityRules write | (none in batch) | **FIRED (1)** |
| DET-003 | role grant by non-automation caller | (none in batch) | **FIRED (1)** |
| DET-004 | 6 deletes in 5 min | 3 deletes in 5 min (sub-threshold) | **FIRED (1)** |
| DET-005 | (needs non-owner principal; noted) | allow-listed owner deploy | **silent (0)** |
| DET-007 | grant then deploy, same principal | deploy with no preceding grant | **FIRED (1)** |
| DET-009 | NSG open inbound Any + ARG watchlist | (none in batch) | **FIRED (1)** |

Open NSG rules in the ARG-sourced watchlist at measure time: 1.

Notes: DET-005 attack side needs a non-owner principal (its benign owner-deploy is measured
silent here); DET-001 (failed-ops spike) needs a denied principal; DET-006 (LSASS) is witnessed
in INV-03; DET-008 (sign-in) is pending sign-in data. See validation/README.md.
