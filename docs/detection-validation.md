# Detection validation matrix

## Verified results

The following observations were made in the local Wazuh 4.14.10 lab on **7–8 November 2026**. These are controlled tests, not security incidents.

| Test | Input/source | Expected rule | Observed rule | Result | Evidence |
| --- | --- | --- | --- | --- | --- |
| Phase 1: individual synthetic failed-auth event | Manager-local JSONL | `100100` | `100100` (level 3) | PASS | [Phase 1 alert screenshot](../screenshots/brute-force-alert.png) |
| Phase 1: five synthetic failed-auth events | Manager-local JSONL | `100101` | `100101` (level 10) | PASS | [INC-001](../investigations/INC-001-brute-force-simulation.md) |
| Phase 1: synthetic PowerShell indicator | Manager-local JSONL | `100110` | `100110` (level 8) | PASS | [INC-002](../investigations/INC-002-powershell-simulation.md) |
| Phase 2: Windows Application Event ID 777 | Windows agent `001` | Standard Wazuh Application error alert | `60602` (level 9) | PASS | Dashboard observed (not yet sanitized for public screenshot) |
| Phase 2: one Windows failed logon Event ID 4625 | Windows agent `001` | `60122` | `60122` (level 5) | PASS | [INC-003](../investigations/INC-003-windows-authentication.md) |
| Phase 2: five Windows failed logons within 60s for one test username | Windows agent `001` | `100120` | `100120` (level 10), fired twice across two runs | PASS | [INC-003 sanitized excerpt](../investigations/INC-003-windows-authentication.md) |
| Phase 3: Notepad Sysmon process creation (Event ID 1) | Windows Sysmon / agent `001` | `100130` | `100130` (level 5) | PASS | [Phase 3 README](../README.md#phase-3--sysmon-endpoint-telemetry-initial-validation-8-november-2026) |
| Phase 3: PowerShell marker process creation (Event ID 1) | Windows Sysmon / agent `001` | `100131` | `100131` (level 5) | PASS | [Phase 3 README](../README.md#phase-3--sysmon-endpoint-telemetry-initial-validation-8-november-2026) |
| Phase 3: PowerShell encoded-command indicator (Event ID 1) | Windows Sysmon / agent `001` | `100132` | `100132` (level 8); built-in `92057` observed in separate test | PASS | [INC-004](../investigations/INC-004-powershell-encoded-command.md) |
| Phase 3: encoded, no-profile, noninteractive combination | Windows Sysmon / agent `001` | `100133` | `100133` (level 10), 2026-11-08 22:31:22 CET | PASS | [INC-004](../investigations/INC-004-powershell-encoded-command.md) |
| Phase 3: three reduced-flag negative-control executions | Windows Sysmon / agent `001` | No new `100133` | Two `100132` (level 8) and one `92032` (level 3) visible; no new `100133` in screenshot | PASS — targeted `100133` search returned 0 hits for 2026-11-08 22:32:10–22:32:35 CET | [INC-004](../investigations/INC-004-powershell-encoded-command.md) |

| Phase 4: direct Sysmon process GUID correlation | New controlled `cmd.exe` → `powershell.exe` chain | Child `ParentProcessGuid` matched parent `ProcessGuid` at 2026-11-08 22:44:07 CET | PASS | [INC-005](../investigations/INC-005-process-chain-triage.md) |

| Phase 4: additional benign PowerShell baseline (3 commands) | No `100132`, `100133`, or `92057` alerts | 0 hits in targeted time-scoped Wazuh query, reported by lab operator | PASS (limited baseline) | [INC-005](../investigations/INC-005-process-chain-triage.md) |

| Phase 4: benign encoded administrative-style command | Rule `100133` expected; known authorized test | `100133` (level 10), Sysmon Event ID 1 at 2026-11-08 22:52:41 CET | PASS — demonstrates signature matches benign automation too | [INC-005](../investigations/INC-005-process-chain-triage.md) |

| Phase 4: Sysmon Event ID 11 and local EID 1↔11 GUID join | Correlate PowerShell ProcessCreate and FileCreate | `powershell.exe`, matching `ProcessGuid`: True; file creation 2026-11-08 22:56:06 CET | PASS | [INC-005](../investigations/INC-005-process-chain-triage.md) |
| Phase 4: Wazuh custom FileCreate detection | New controlled FileCreate event triggers `100134` level 5 | `100134` level 5, Event ID 11, 2026-11-08 23:00:55 CET | PASS | [File rule](../rules/sysmon_file_rules.xml) |

| Phase 4: SIEM-side analyst correlation across Sysmon Event IDs 1 and 11 | Match ProcessGuid for process creation and controlled file write | Wazuh `92027` (level 4) at 23:00:55.056 CET and `100134` (level 5) at 23:00:55.234 CET; same ProcessGuid, 178 ms separation | PASS — manual correlation, not automatic rule | [INC-005](../investigations/INC-005-process-chain-triage.md) |

| Phase 4: offline correlation unit tests | Match rule `100133` followed by `100134` within 60 s on matching agent/ProcessGuid; reject mismatches and duplicates | 8 correlation tests passed; full local suite: 14 tests, 0 failures, 2026-11-08 | PASS — offline only | [Correlator](../tools/sysmon_correlator.py) · [Tests](../tests/test_sysmon_correlator.py) |

| Phase 4: real Wazuh same-process correlation positive test | `100133` and `100134` must share agent and ProcessGuid within 60 s | Indexed Sysmon events at 23:13:36.348 and 23:13:36.545 CET, identical ProcessGuid, 197 ms apart; file content confirmed | PASS — manual correlation; Python end-to-end pending | [INC-005](../investigations/INC-005-process-chain-triage.md) |

| Phase 4: Python correlator on real Wazuh alert pair | One finding for `100133` then `100134` with matching agent/ProcessGuid inside 60 seconds | 2 real alert inputs → 1 sanitized finding, matching agent/GUID, 0.197 s separation | PASS — offline end-to-end | [INC-005](../investigations/INC-005-process-chain-triage.md) |

**Phase 2 screenshot disclosure:** No screenshots are included for Phase 2 because the real Windows and Wazuh views contained personal system identifiers. The linked INC-003 report uses selected, sanitized, reconstructed alert fields instead; these are not raw evidence exports.

**Phase 3 screenshot disclosure:** The four custom rule matches were confirmed in the dashboard; unredacted images were intentionally omitted because they contain personal device and account identifiers. Only selected validation fields are documented.

## Not yet tested

| Negative / additional test | Expected | Status |
| --- | --- | --- |
| Phase 1 synthetic auth failures from distinct source IPs | No inappropriate cross-IP correlation | NOT RUN |
| Phase 1 non-lab JSON | No match by lab-specific rules | NOT RUN |
| Phase 2 Windows failures spread across distinct usernames | No inappropriate same-target correlation | NOT RUN |
| Phase 2 fewer than five Windows failures in the window | No custom frequency alert from an isolated sequence | NOT RUN |
| Phase 2 Windows remote/network logon types and source-IP attribution | Correct event capture and rule behavior | NOT RUN |
| Phase 3 PowerShell marker absent from command line | No `100131` marker alert | NOT RUN |
| Phase 3 ordinary PowerShell negative controls (Write-Output, Get-Date, script block) | No `100132` alert for the three process launches | PASS — three Sysmon Event ID 1 records; three Wazuh `92027` (level 4) alerts; targeted `100132` search returned 0 hits for 2026-11-08 22:23:15–22:23:40 CET |
| Phase 3 reduced-flag targeted `100133` absence check | No `100133` alert for three test executions | PASS — 0 hits in 2026-11-08 22:32:10–22:32:35 CET (dashboard query reported by lab operator) |
| Phase 3 encoded-command switch variants | Assess command-line variations | NOT RUN |
| Phase 3 additional suspicious PowerShell behaviors | Alerts for safe controlled indicators | NOT RUN |

## Reproduce Phase 2 (safe test)

1. Use an isolated Windows lab endpoint with a Wazuh agent configured for the Security EventChannel; confirm it is active.
2. Install [`rules/windows_auth_rules.xml`](../rules/windows_auth_rules.xml) into the manager and validate with `wazuh-analysisd -t` before restarting.
3. Confirm `auditpol /get /subcategory:"Logon"` enables **Failure** auditing.
4. Trigger five controlled local logon failures against a **nonexistent lab username** using the Windows `LogonUser` API (no genuine passwords or existing accounts).
5. Verify Windows Security Event ID `4625`, Wazuh `60122` base alerts, and custom `100120` correlation in manager alerts and dashboard.

**Privacy:** Raw Windows event messages can expose actual Windows usernames, hostnames, SIDs and logon IDs. Publish redacted screenshots and selected sanitized excerpts instead of raw `alerts.json`.
