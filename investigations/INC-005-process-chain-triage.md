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

## Detection overlap and severity tuning assessment

A Wazuh Threat Hunting screenshot on 8 November 2026 showed **7 selected matching alerts**: three built-in `92057` (level 12), three custom `100132` (level 8), and one custom `100133` (level 10). One `92057` event occurred at **22:13:16 CET**, preceding the originally intended 22:15–22:45 CET hunting window. Therefore, **6 of these 7** fall within that narrower interval (two `92057`, three `100132`, one `100133`).

These results show useful distinctions among process contexts and rule conditions in the controlled sample. They do not establish the absence of rule overlap in other conditions or a production false-positive rate. The earlier local telemetry summary included 11 PowerShell process-creation events, all at High integrity, including ordinary commands; elevated integrity alone therefore did not distinguish suspicious behavior in this sample.

**Tuning decision:** retain current severity levels (`100132` level 8 and `100133` level 10) pending a broader benign baseline and scenario coverage. Treat each alert as an investigation indicator, not a confirmed attack, and prioritize parent process, decoded command content, user context, and corroborating telemetry before escalation. No live rules were modified during this assessment.

## Additional benign PowerShell baseline

Three additional harmless PowerShell runs were initiated: (A) `powershell.exe -NoProfile -Command "Get-Date"`, (B) `cmd.exe /c` launching PowerShell to print `SOC_LAB_BASELINE`, and (C) the same CMD-parent test adding `-NonInteractive`. The lab operator reports that a time-scoped Wazuh Threat Hunting search for `rule.id: (100132 or 100133 or 92057)` across these tests returned **0 hits**. **Result: PASS for this limited benign baseline**, with no alerts from the three selected higher-priority rules. Event-by-event Sysmon correlation was not repeated for these specific runs, and these results do not establish a production false-positive rate.

## Benign encoded administrative automation — alert review

At **2026-11-08 22:52:41 CET** (Sysmon event time; Wazuh alert indexed approximately **22:52:42 CET**), a controlled administrative command using `powershell.exe -NoProfile -NonInteractive -EncodedCommand` was recorded as Sysmon Event ID `1`. Its immediate parent was `cmd.exe`. Wazuh generated custom rule **`100133` (level 10, `rule.firedtimes: 2`)**.

The UTF-16LE Base64 payload corresponds to `Get-Date; [Environment]::OSVersion.Version.ToString()`, which reads the date and operating-system version. This was intentionally initiated as a harmless lab simulation, **not evidence of malicious behavior**. The event verifies the invocation and rule match; it does not independently verify command completion or represent a real scheduled task.

**Triage:** true positive for the defined command-line signature; **benign known test** for the underlying activity. In ordinary SOC operations this would be an alert requiring contextual triage, not automatically a security incident. The test demonstrates that rule `100133` can alert on authorized administrative-style activity. This supports revisiting the level-10 priority using actual organizational baselines, parent process context, and corroborating telemetry; it does not by itself justify a broad allowlist or automatic suppression.

**Tuning decision:** leave the deployed rule unchanged for now. Next, compare a narrowly scoped known-benign test against broader risky activity before designing any exception or priority adjustment.

## Privacy and evidence handling

The original Wazuh event contains private user, host, path, process and logon identifiers. Only manually selected sanitized fields and process basenames are published in this report; no original screenshots, full events, or personal identifiers are included.

**Related:** [INC-004](INC-004-powershell-encoded-command.md) · [Detection rules](../rules/sysmon_rules.xml) · [Validation matrix](../docs/detection-validation.md)
