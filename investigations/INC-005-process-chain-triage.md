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

## Sysmon file-creation telemetry and rule 100134

The operator enabled a narrowly scoped Sysmon FileCreate filter for a dedicated lab evidence file. At **2026-11-08 22:56:06 CET**, local Sysmon Event ID `11` was observed after a harmless PowerShell `Set-Content` test. A local join of Sysmon process-creation Event ID `1` and FileCreate Event ID `11` on `ProcessGuid` returned **`powershell.exe`, GUID match `True` (PASS)**.

The original Event ID `11` was not found as an alert in Wazuh Threat Hunting, so the operator installed narrowly scoped custom rule **`100134`**, level **5**, for the lab file. After generating a new file event, Wazuh indexed a matching alert at **2026-11-08 23:00:56 CET**, based on Sysmon Event ID `11` at **23:00:55 CET**. This validates agent-to-manager alerting for the new event type and rule. The alert identifies a PowerShell image and controlled test target; it does **not** by itself constitute cross-event correlation in the SIEM. The reported Sysmon `CreationUtcTime` can refer to the file's initial creation timestamp and should not be confused with the current event timestamp.

**Disposition:** Controlled benign tests; no incident escalation. Public evidence excludes raw event payloads, user/host names, full process GUIDs, and screenshots. The rule source is published as [`rules/sysmon_file_rules.xml`](../rules/sysmon_file_rules.xml).

## SIEM-side process attribution confirmed

Both corresponding alerts were located in the Wazuh alert index for the controlled **2026-11-08 23:00:55 CET** execution. The built-in **`92027`** alert (level 4) contains Sysmon ProcessCreate Event ID **1** for `powershell.exe` at **23:00:55.056 CET**; the custom **`100134`** alert (level 5) contains FileCreate Event ID **11** at **23:00:55.234 CET**. The analyst verified that both events have the **same `data.win.eventdata.processGuid`**, establishing a common originating PowerShell process. The file event followed process creation by **178 ms**.

**Result: PASS — manual analyst correlation across two Wazuh alerts.** This establishes event attribution, not a new single automatic Wazuh correlation alert and not evidence of maliciousness. The associated activity was a controlled harmless lab file write. No process GUID, account identifiers, hostname, screenshot, or raw event was committed.

## Offline automated correlation prototype

A proposed native Wazuh rule `100135` failed `wazuh-analysisd -t` validation with warning `7620` about an invalid `if_matched_sid`; it was removed from the manager. A subsequent validation produced only the normal rule-tree informational message and no warning. **Rule `100135` was not deployed.**

To test the correlation logic without asserting unsupported manager behavior, the repository now includes [`tools/sysmon_correlator.py`](../tools/sysmon_correlator.py) and [`tests/test_sysmon_correlator.py`](../tests/test_sysmon_correlator.py). The offline prototype takes a list of Wazuh alert dictionaries, matches `100133` followed by `100134` on both agent ID and ProcessGuid within 60 seconds, and returns sanitized findings. Unit tests include matching, mismatched GUID, mismatched agent, reverse-order, missing identifier, expired window, and duplicate cases. **The tests still require local execution; no production/live correlation is claimed.**

## Real Wazuh alert pair — same-process positive test

The operator executed a controlled benign PowerShell `-NoProfile -NonInteractive -EncodedCommand` action that wrote `SOC_LAB_CORRELATION_TEST` into the dedicated lab evidence file. File contents were verified locally. Wazuh indexed both **`100133`** (Sysmon Event ID **1**, level **10**, process execution at **2026-11-08 23:13:36.348 CET**) and **`100134`** (Sysmon Event ID **11**, level **5**, file event at **23:13:36.545 CET**).

The two indexed alerts contain identical **`data.win.eventdata.processGuid`** values and agent ID `001`. The events are separated by **197 ms**, within the prototype 60-second interval. **PASS: real SIEM alert pair provides positive-test input for the offline correlator.** The operator has not yet run these two alert records through the Python correlator; therefore this is a verified manual join, not a verified programmatic end-to-end finding. Activity remains known-benign laboratory simulation, not compromise.

## Offline correlator validation with actual Wazuh alerts — PASS

The operator queried the local Wazuh manager's `alerts.json`, filtering for rules `100133` and `100134` and the controlled **2026-11-08 23:13:36 CET** execution. Exactly **2** real alerts matched. The pair was processed locally with `tools.sysmon_correlator.correlate`, producing **1** sanitized finding:

- Finding: `encoded_powershell_followed_by_lab_file_create`
- Matched rules: `100133` and `100134`
- Same process GUID: **true**
- Same agent: **true**
- Elapsed time: **0.197 seconds** (within 60-second correlation window)
- Triage priority: `investigate`, **not** a confirmed malicious incident

**Result: PASS — full offline pipeline from real Windows Sysmon events through Wazuh alerts to a locally generated correlation finding.** No original Wazuh alerts, usernames, hostnames, GUIDs, or system paths were published. Continuous/live deployment and real-event negative-control testing remain out of scope for this result.

## Privacy and evidence handling

The original Wazuh event contains private user, host, path, process and logon identifiers. Only manually selected sanitized fields and process basenames are published in this report; no original screenshots, full events, or personal identifiers are included.

**Related:** [INC-004](INC-004-powershell-encoded-command.md) · [Detection rules](../rules/sysmon_rules.xml) · [Validation matrix](../docs/detection-validation.md)
