# DET-006, LSASS credential access

| | |
|---|---|
| **ID** | DET-006 |
| **Severity** | **High** |
| **Rule type** | Scheduled analytics rule |
| **Status** | Live, witnessed (Incident #65, see [INV-03](../investigations/INV-03-lsass-credential-access.md)) |
| **Data source** | `DeviceEvents`, `DeviceProcessEvents`, `SecurityAlert` (Defender for Endpoint, via Defender XDR connector) |
| **MITRE tactic** | Credential Access |
| **MITRE technique** | [T1003.001, OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |

## What it catches

An attempt to dump **`lsass.exe`**, the memory that holds cached credentials and the first thing
an attacker reaches for after landing on a host (Mimikatz, `comsvcs.dll` minidump, procdump,
nanodump). This is the endpoint counterpart to the AzureActivity control-plane rules: same
Detection-as-Code pipeline, different telemetry plane.

The rule is **multi-source by design**. On a hardened host the dump is prevented and no
`OpenProcessApiCall` is ever emitted, so a handle-open-only rule would stay silent on a real
attack. DET-006 fuses the three signals Defender for Endpoint actually produces for the technique,
so it fires whether the dump runs, is denied at the API layer, or is prevented by AMSI / behavioral
protection:

- **Signal A — api-level:** a process opens a handle to `lsass.exe` (`DeviceEvents.OpenProcessApiCall`).
- **Signal B — process-level:** a known dump tool runs with `lsass` on its command line (`DeviceProcessEvents`).
- **Signal C — alert-level:** Defender prevents an LSASS credential-theft hacktool (`SecurityAlert`, provider MDATP).

## Detection logic

Runs every 15 minutes over a 1-hour lookback. The `Device*` event tables and MDATP alerts reach
`sc200-ws` through the Defender XDR connector. Known Defender components that legitimately touch
LSASS are excluded so the rule does not fire on the AV/EDR stack itself.

```kql
let lookback = 1h;
let knownGoodReaders = dynamic(["MsMpEng.exe", "MsSense.exe", "SenseIR.exe"]);
// Signal A - direct handle open to LSASS (api-level: Mimikatz / direct-syscall tooling)
let openHandle =
    DeviceEvents
    | where TimeGenerated > ago(lookback)
    | where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
    | where InitiatingProcessFileName !in~ (knownGoodReaders)
    | extend Account = InitiatingProcessAccountName, Technique = "Handle open to lsass.exe",
             Evidence = strcat(InitiatingProcessFileName, " -> lsass.exe");
// Signal B - credential-dump tool with LSASS on the command line (process-level)
let dumpTool =
    DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("-ma", "MiniDump", "nanodump", "dumpert", "comsvcs"))
        or (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
    | extend Account = AccountName, Technique = "Credential-dump tool vs lsass", Evidence = ProcessCommandLine;
// Signal C - Defender prevented an LSASS credential-theft hacktool (AMSI / behavioral)
let preventedTool =
    SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where ProviderName == "MDATP"
    | where AlertName has "lsass" or AlertName has_any ("DumpLsass", "Lsassdump")
    | mv-apply Entity = parse_json(Entities) on (
        where Entity.Type == "host" | project DeviceName = tostring(Entity.HostName) | take 1)
    | extend Account = "", Technique = "Defender-prevented lsass hacktool", Evidence = AlertName;
union
  (openHandle    | project TimeGenerated, DeviceName, Account, Technique, Evidence),
  (dumpTool      | project TimeGenerated, DeviceName, Account, Technique, Evidence),
  (preventedTool | project TimeGenerated, DeviceName, Account, Technique, Evidence)
| summarize Techniques = make_set(Technique), Evidence = make_set(Evidence, 12),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Signals = count()
    by DeviceName, Account
| where Signals >= 1
```

## How to trigger (simulation)

On the onboarded host, run a standard T1003.001 technique against LSASS, for example
`rundll32 comsvcs.dll, MiniDump <lsass_pid> out.dmp full` or `procdump -ma lsass.exe`. On a hardened
host (RunAsPPL + AMSI + behavioral protection) the read is prevented and the dump file is never
produced; the prevention is the signal. Delete any artifact immediately. Full method in
[INV-03](../investigations/INV-03-lsass-credential-access.md).

## Expected result

**Witnessed.** Three techniques (`comsvcs.dll` MiniDump, `procdump -ma lsass`, P/Invoke
`OpenProcess`) were run against `soc-sensor-01`. The host's defenses (LSASS RunAsPPL, AMSI,
Defender behavioral) prevented every one, raising the MDATP `Lsassdump` / `DumpLsass` alerts that
streamed to `SecurityAlert`. DET-006 fired on Signal C and raised **Sentinel Incident #65, High**,
2026-06-09 05:02:48 UTC. No credentials were exposed.

## Tuning notes

**Threshold rationale.** A single LSASS credential-theft signal from a non-Defender process is
already worth surfacing on a server that should have almost no LSASS access. On a busy workstation
fleet this would move to a per-process allowlist plus a count threshold.

**Known false positives.** Backup agents, EDR/AV other than the Defender stack already excluded,
and some management tooling read LSASS legitimately (Signal A). Authorised red-team or
detection-validation activity trips Signals B and C. Extend the `knownGoodReaders` allowlist or
suppress known validation windows.

**Tightening trade-off.** Signal B already filters to dump-specific command lines; Signal A keeps
the broad `OpenProcessApiCall` catch so a custom or renamed dumper is not missed on a low-access
server. Dropping Signal A would cut noise but lose the unknown-tool case.

**Evasion.** Direct syscalls or a signed-but-abused process can evade the API-call telemetry, and a
custom dumper may not trip the MDATP signature. Signal B (command-line) and the companion hunt
[`endpoint-lsass-access.kql`](../kql/hunting/endpoint-lsass-access.kql) widen coverage; correlate
with [`endpoint-vulnerable-asset-under-alert.kql`](../kql/hunting/endpoint-vulnerable-asset-under-alert.kql).

**Validation.** ATT&CK [T1003.001](https://attack.mitre.org/techniques/T1003/001/), OS Credential
Dumping: LSASS Memory. Architecture and data flow: [docs/07](../docs/07-endpoint-vulnerability-management.md).
