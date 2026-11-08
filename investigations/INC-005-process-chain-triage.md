# INC-005 — PowerShell Process-Chain Triage (Phase 4)

**Disposition:** Known benign laboratory activity; investigation in progress, not a confirmed security incident  
**Date:** 8 November 2026 (Europe/Berlin, CET)  
**Data source:** Sysmon Process Create, Event ID `1`, forwarded via Wazuh Windows agent `001`

## Investigation objective

Triage the confirmed PowerShell flag-combination detection `100133` (level 10) and three reduced-flag negative-control executions. Distinguish a valid technical detection from actual malicious behavior and identify visibility gaps in the process tree.

## Evidence and timeline

The Wazuh alert for rule `100133` indicates a PowerShell process launched by `cmd.exe` with `-NoProfile`, `-NonInteractive` and `-EncodedCommand`. The supplied Base64 test was a controlled UTF-16LE encoding of a harmless `Write-Output 'SOC_LAB_FLAGS_TEST'` command.

The analyst queried local Sysmon Process Create events for **2026-11-08 22:30:00–22:33:00 CET**, parsed the named `Image` and `ParentImage` fields, and displayed executable **basenames only**:

| Local event time (CET) | Created process | Reported immediate parent | Context |
| --- | --- | --- | --- |
| 22:31:17 | `powershell.exe` | `cmd.exe` | Controlled combined-flag positive test |
| 22:32:14 | `powershell.exe` | `cmd.exe` | One reduced-flag control |
| 22:32:19 | `powershell.exe` | `cmd.exe` | One reduced-flag control |
| 22:32:25 | `powershell.exe` | `cmd.exe` | One reduced-flag control |

The three reduced-flag controls were independently checked using a time-scoped query for rule `100133`, which returned **0 hits**, as reported by the lab operator. The positive test triggered `100133` at level 10.

## Analyst interpretation

- **Detection validity:** The positive alert was expected and correctly identified the tested command-line pattern. All observed activities were intentionally initiated in the laboratory.
- **Privilege context:** The positive Sysmon event reported **High** integrity, suggesting elevated execution. This increases potential impact but is not evidence of compromise.
- **Process-tree visibility:** The four Sysmon events identify the *immediate* parent of each PowerShell process as `cmd.exe`. They do **not** establish what launched `cmd.exe`. This Sysmon setup filters process-creation collection to Notepad and PowerShell executables, so a separate `cmd.exe` process-creation record was not expected from that filter.
- **Scope:** These observations do not independently prove that the whole process ancestry has been reconstructed, or that there were no related activities outside the collected event types.

## Triage disposition

**Known benign controlled test; no containment or incident escalation required for this event.** The rule is a valid detection of the chosen command-line pattern, not proof of attacker behavior.

## Follow-up: direct GUID correlation verified

The local Sysmon `ProcessCreate` include filter was expanded to collect `cmd.exe` in addition to Notepad and PowerShell. At **2026-11-08 22:44:07 CET**, a fresh harmless `cmd.exe /c` launch executed PowerShell with `Write-Output SOC_LAB_CHAIN_TEST`. The analyst parsed both Sysmon Event ID `1` records and joined the child's `ParentProcessGuid` with the parent's `ProcessGuid`. **Result: `powershell.exe` → `cmd.exe`, GUID match `True` (PASS).** Only executable basenames and a boolean match were displayed; the underlying GUIDs and account information remain private.

This confirms a directly correlated immediate parent-child pair **for the fresh 22:44:07 test**. It does not retroactively provide a separate parent process event for the earlier 22:31–22:32 tests or establish the grandparent process.

## Next investigation action

Evaluate how collected parent-child context should affect rule severity and triage, and add more targeted negative tests if needed. Avoid publishing raw process GUIDs, user identities, or full event exports.

## Privacy and evidence handling

The original Wazuh event contains private user, host, path, process and logon identifiers. Only manually selected sanitized fields and process basenames are published in this report; no original screenshots, full events, or personal identifiers are included.

**Related:** [INC-004](INC-004-powershell-encoded-command.md) · [Detection rules](../rules/sysmon_rules.xml) · [Validation matrix](../docs/detection-validation.md)
