# INC-004 — Encoded PowerShell Process Creation (Sysmon)

**Disposition:** Controlled detection-engineering validation; not a security incident  
**Date:** 8 November 2026  
**Environment:** Windows endpoint with built-in Sysmon, Wazuh agent `001`, and Wazuh 4.14.10 Docker SIEM  
**Rule:** Custom `100132`, level 8

## Executive summary

A harmless PowerShell command that prints `SOC_LAB_ENCODED_TEST` was encoded as UTF-16LE Base64 and executed using `-EncodedCommand`. The Windows Sysmon Operational channel captured process creation **Event ID 1**. The Wazuh agent forwarded the event, and the custom `100132` rule generated an indexed level-8 dashboard alert. The second controlled test launched PowerShell through `cmd.exe`, and the indexed alert was observed at **2026-11-08 21:18:04 UTC**.

An earlier PowerShell-parent test produced the Wazuh built-in **`92057` (level 12)** alert. This distinguishes existing detection coverage from the subsequent, independently observed custom rule match.

## Detection logic

- Source: Sysmon Process Create, Event ID `1` through `Microsoft-Windows-Sysmon/Operational`.
- Rule ID: `100132` (level 8), in [Sysmon rules](../rules/sysmon_rules.xml).
- Conditions: a PowerShell executable name and a command-line argument matching supported encoded-command switches.
- **Interpretation:** Encoded arguments can be used in attacks but also for legitimate administration. This alert alone is not evidence of malicious activity.
- No MITRE technique is asserted as an observed attack.

## Reproduction (safe controlled test)

Run from Windows PowerShell after confirming Sysmon and Wazuh collection are working:

```powershell
$c=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'SOC_LAB_ENCODED_TEST'")); cmd.exe /c "powershell.exe -NoProfile -EncodedCommand $c"
```

Verify local Sysmon Event ID `1`, then search the Wazuh dashboard for `rule.id: 100132`.

## Sanitized evidence summary

| Field | Observed value |
| --- | --- |
| Agent ID | `001` |
| Decoder | `windows_eventchannel` |
| Event channel | `Microsoft-Windows-Sysmon/Operational` |
| Event ID | `1` |
| Process | `powershell.exe` |
| Parent process | `cmd.exe` |
| Command argument | `-EncodedCommand` |
| Wazuh rule ID | `100132` |
| Wazuh level | `8` |
| Rule description | SOC LAB: PowerShell encoded command execution detected |
| Alert time | 2026-11-08 21:18:04 UTC |
| Validation result | **PASS** |

This is a **manually transcribed selection of fields visible in the dashboard**, not an original or complete raw event export. No unredacted screenshots are published because the event details expose personal endpoint identifiers, including user and computer names, directory paths, and process GUIDs.

## Investigation and limitations

The analyst should inspect the command-line context, parent-child relationship, executable path, signing data, endpoint role, user context, related PowerShell logging, and subsequent behavior. A single encoded PowerShell invocation is insufficient to conclude compromise.

### Ordinary PowerShell negative-control observations

On 8 November 2026, three harmless PowerShell commands without encoded-command arguments were run: `Write-Output 'SOC_LAB_NORMAL_TEST'`, `Get-Date`, and a script block printing `SOC_LAB_SCRIPTBLOCK_TEST`. Three corresponding local Sysmon Event ID `1` records were confirmed. The Wazuh dashboard screenshot showed three built-in `92027` (level 4) alerts at approximately 22:23:20–22:23:33 CET. No `100132` alert is visible in that supplied screenshot, but the view was not a complete, isolated `100132` search for the test interval. Accordingly, this is **preliminary negative-control evidence**, not a conclusive proof of zero false positives.

**Not yet validated:** targeted no-match verification for `100132` during the negative-control interval, false-positive rate, abbreviated switch variants, robustness against altered argument formatting, production tuning, and broad endpoint coverage. Sysmon was configured to collect only Notepad and PowerShell process creation for this lab.

**Related:** [README](../README.md) · [Detection validation matrix](../docs/detection-validation.md)
