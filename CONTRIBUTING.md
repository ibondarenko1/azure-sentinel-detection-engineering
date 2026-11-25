# Contributing

This repo is detection-as-code: a detection is not clicked into a portal, it is versioned YAML that a
PR-gated pipeline validates, tests, and deploys. So any change to a rule goes through a pull request and
the same checks, whether it is mine or a fork's. This guide is the workflow.

## The model

```
edit rule YAML -> regenerate KQL mirror -> extend fixture -> run checks -> review PR plan -> merge
```

- Source of truth for every rule: [`detections/rules/*.yaml`](detections/rules).
- One human-readable card per rule lives next to it (`detections/DET-00N-*.md`): logic, MITRE mapping, trigger, evidence.
- The deployment job writes by rule GUID when deployment is enabled for `main`. See the [delivery runbook](docs/03-cicd.md).

## Add or change a detection

1. **Branch off `main`.** Use a short topic branch (the existing history uses `phase-<x>/<topic>` or `fix/<topic>`).
2. **Edit the rule YAML** in `detections/rules/`. Keep the GUID stable when editing an existing rule (the deployer keys on it); use a fresh GUID for a new rule.
3. **Regenerate the KQL mirror.** The `kql/detections/*.kql` files are generated copies of each rule's query, kept in sync so the KQL is browsable on its own:
   ```bash
   python cicd/sync-kql-mirror.py
   ```
   CI fails if the mirror is out of sync (`sync-kql-mirror.py --check`), so run this after any query change.
4. **Extend the test fixture.** Add `fires` and `silent` events to the rule's fixture. A new rule also needs an entry in the [coverage contract](tests/coverage.yaml). See [the test guide](tests/README.md) for the fixture format.
5. **Update the rule card**, [metrics](detections/metrics.yaml) and [ATT&CK layer](navigator/coverage-layer.json) when the rule or its coverage changes.
6. **Run the unit tests locally** (next section) until green.
7. **Open a PR to `main`.** Review the `sentinel-review-plan` artifact with the code diff, particularly any change to scope, schedule, entities or prerequisites.

## Run the checks locally

Run the catalog and release checks with Python:

```bash
python -m pip install -r requirements.txt
python cicd/validate-detections.py
python -m unittest discover -s cicd -p 'test_*.py'
python cicd/sync-kql-mirror.py --check
python cicd/deploy-detections.py plan --output sentinel-plan.json
```

Then run the [Kusto fixtures](tests/README.md) for positive and negative cases. Use the [delivery runbook](docs/03-cicd.md) for a separately authorized workspace smoke check.

## CI gates

Every pull request must pass, before review:

- **detection-tests** ([workflow](.github/workflows/detection-tests.yml)): the unit tests above, plus the KQL-mirror sync check.
- **validate** ([workflow](.github/workflows/deploy-detections.yml)): rule validation, evidence checks, release tests and the offline plan artifact.

`deploy` is opt-in. When enabled, it runs on matching `main` changes or manual dispatch from `main`, using its own protected environment and OIDC identity.

## Conventions

- **No secrets, ever.** Deployment authenticates with OIDC; there are no stored credentials in the repo and PRs must not add any.
- **Redaction.** Any screenshot must have tenant ID, subscription ID, resource IDs, UPNs, and PII removed before commit. The convention and the scripts are in [screenshots/README.md](screenshots/README.md).
- **Numbers trace to artifacts.** Claims in docs cite a snapshot, a results file, or a screenshot. Do not assert a metric the environment cannot measure (the repo deliberately reports measured false fires, not a fabricated FP rate).
- **Docs stay plain and factual.** Short practitioner prose, no filler.

## Where things live

| Path | What |
|------|------|
| `detections/rules/` | rule YAML (source of truth, deployed by CI) |
| `detections/*.md` | one card per rule |
| `kql/` | generated KQL mirror + hunting library |
| `tests/` | unit tests + fixtures (fork-runnable) |
| `validation/` | live benign + attack harness (needs a tenant) |
| `cicd/` + `.github/` | the pipeline (validate, test, deploy, regression) |
| `navigator/` | ATT&CK coverage layer |
| `docs/` | architecture, methodology, cicd, and the case studies |
