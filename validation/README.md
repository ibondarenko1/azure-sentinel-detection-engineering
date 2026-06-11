# Validation harness

The detections in this repo are unit-tested against synthetic fixtures (`tests/`). This harness
adds the next rigor level: it drives **real, mixed activity** in the live tenant, a benign stream
that the rules must stay silent on, and an attack stream they must fire on, then **measures**
true-positive recall and the false-positive count over the benign batch.

It does not pretend to be production volume (a single-tenant environment cannot). It converts the honest
"0% FP at N=1, no data" into a measured "0 false fires over N real benign events", and gives each
detection more than one true positive. Lineage: the attack stream mirrors what tools like
[Stratus Red Team](https://stratus-red-team.cloud/) (cloud control-plane) and
[Atomic Red Team](https://atomicredteam.io/) (endpoint) do; the actions here are scoped to the exact
techniques these rules detect.

## What it does

- `benign.sh`: legitimate actions that map to each rule's **silent** case (allow-listed owner
  deploy, sub-threshold failures, sub-threshold deletes, a deploy with no preceding grant).
- `attacks.sh`: the malicious variants that map to each rule's **fire** case (mass delete, role
  grant, grant-then-deploy chain, NSG opened inbound from Any).
- `measure.py`: runs each deployed rule's real KQL against the workspace over the run window and
  reports fired / silent, then writes `RESULTS.md`.
- `cleanup.sh`: removes everything the harness created (tracked in `.harness-state`), idempotent.

All resources live in `sc200-lab`, are prefixed `val-`, and are torn down by `cleanup.sh`.

## Run

```bash
cd validation
./benign.sh        # legitimate stream (must stay silent)
./attacks.sh       # attack stream (must fire)
# wait ~15 min for AzureActivity ingestion
python measure.py  # writes RESULTS.md
./cleanup.sh       # tear down
```

## Coverage and honesty

- Measured live here: DET-002, DET-003, DET-004, DET-007, DET-009 (control-plane, fully scriptable).
- DET-001 (failed-ops spike) and DET-005 (non-owner deploy) need a denied/non-owner principal; their
  benign side (sub-threshold, allow-listed owner) is measured here, attack side is noted.
- DET-006 (LSASS) and DET-008 (sign-in) need an endpoint action / interactive auth and are witnessed
  separately (INV-03; DET-008 pending sign-in data). `RESULTS.md` states exactly what was measured.
