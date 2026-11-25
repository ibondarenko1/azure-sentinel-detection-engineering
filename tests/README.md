# Detection unit tests

The **Kusto emulator** runs each rule's KQL against synthetic Sentinel telemetry. The harness
checks that each rule **fires on malicious** events and stays **silent on benign** events.
Contributors can reproduce these checks with Docker and Python.

The [validation guide](../docs/04-validation.md) records the live evidence and workspace checks.
[`coverage.yaml`](coverage.yaml) lists fixture-backed rules and any `live_only` rules, with a
data-source reason for each exception. The harness fails if a required fixture is missing.
DET-006 exercises all three Defender XDR source tables (`DeviceEvents`, `DeviceProcessEvents`,
and `SecurityAlert`).

## Layout
- `coverage.yaml`, the required rule-to-fixture/live-only coverage contract.
- `fixtures/DET-00N.json`, `{ "fires": [...events...], "silent": [...events...] }` per
  single-table rule; multi-table rules use a `tables` mapping with the same two lists per
  table.
- Fixtures may also set `expected_counts` when a query's result cardinality matters; DET-006 uses
  `fires: 3` and `silent: 0` to prove that each of its three signal branches contributes.
- `run-detection-tests.py`, loads each rule's `query` from `detections/rules/*.yaml`, ingests
  the fixture into the emulator (`.set-or-replace AzureActivity` or `SigninLogs`), runs the
  query, asserts the fire/silent expectation, and rejects untracked coverage gaps.

Watchlist-backed rules must declare a `watchlist` list in their own fixture; the harness recreates
the `_GetWatchlist()` stub for every rule so a previous rule's allow-list cannot leak into a later
query.

## Run locally (Docker required)
```bash
docker run -d --rm --name sentinel-kustainer -p 127.0.0.1:8080:8080 -e ACCEPT_EULA=Y \
  mcr.microsoft.com/azuredataexplorer/kustainer-linux@sha256:81bb7fc1cdda3ee96f725221bbf37b525eca32718d2c2c6a4a6522f84ec97458
# wait a few seconds for the emulator to start
python -m pip install -r requirements.txt
python tests/run-detection-tests.py
docker stop sentinel-kustainer
```

In CI the emulator runs as a service container (`.github/workflows/detection-tests.yml`).

## Adding a case
Add events to the rule's fixture. Each event sets the AzureActivity columns the rule uses
(`ActivityStatusValue`, `Caller`, `OperationNameValue`, `ResourceProviderValue`, `ResourceId`,
optional `Properties_d`, optional `minutesAgo` to place it in an earlier 5-minute bin). The
harness assigns `TimeGenerated` so `ago(1h)` / `bin(5m)` behave deterministically.

When adding a rule, add a `fixture` entry to `coverage.yaml` before adding the fixture. If the
rule depends on a data source unavailable in this emulator, add a `live_only` entry with a
specific reason and keep its live witness/regression coverage authoritative. For a union over
multiple tables, provide every source table in the fixture so the harness replaces all tables
between `fires` and `silent` scenarios.
