# INC-002 — Suspicious PowerShell Indicator (Controlled Simulation)

**Status:** Detection validated; no PowerShell executed  
**Environment:** Local Wazuh 4.14.10 single-node Docker SOC lab  
**Event date:** 2026-11-07 18:32:14.742 (dashboard-displayed time; timezone not independently verified)  
**Scenario:** Synthetic process telemetry containing a suspicious PowerShell command-line indicator

## Executive summary
A harmless synthetic JSON event describing a `powershell.exe` process with the `-EncodedCommand` switch was ingested into Wazuh. Custom rule `100110` generated a level-8 alert, mapped to MITRE ATT&CK `T1059.001`, and the alert appeared in the Wazuh Threat Hunting dashboard. **No command was executed**, and there is no evidence of malicious activity outside this controlled test.

## Observed evidence

| Field | Observed value |
| --- | --- |
| Alert rule | `100110` |
| Description | LAB: synthetic suspicious PowerShell process indicator |
| Severity | Level 8 |
| Host | `demo-win01` |
| Username | `demo_user` |
| Event type | `suspicious_powershell` |
| Process | `powershell.exe` |
| Parent process | `explorer.exe` |
| Command line | `powershell.exe -NoProfile -EncodedCommand <SYNTHETIC-NOT-EXECUTABLE>` |
| Input file | `/var/ossec/logs/lab-events.jsonl` |
| JSON decoder | `json` |
| Wazuh agent | `000` / `wazuh.manager` (local synthetic log ingestion, not a deployed Windows agent) |
| ATT&CK | `T1059.001` — PowerShell / Execution |
| Alert timestamp | `2026-11-07 18:32:14.742` as displayed in dashboard |

The screenshot showed `rule.firedtimes: 2`, confirming the rule had fired more than once by the time of the captured event. The synthetic record explicitly stated: `Synthetic process telemetry; no command executed`.

## Triage and interpretation
- **What was verified:** JSON ingestion and decoding, Wazuh custom rule matching, MITRE ATT&CK mapping and alert indexing/visibility.
- **What was not verified:** Execution of PowerShell, code execution, malicious intent, persistence, network connections, or an endpoint compromise.
- **False-positive considerations for a production rule:** Encoded PowerShell is used in some legitimate administration, deployment and automation tools; context such as signer, parent process, script content, user and endpoint behavior matters.

## Recommended response if observed in production
1. Obtain authoritative endpoint telemetry (Windows Event ID 4688 or Sysmon Event ID 1, where configured), PowerShell logs and EDR records.
2. Inspect the exact command line and decode any encoded content in a safe analysis environment; do not execute it.
3. Correlate process ancestry, user session, execution context, downloaded files and network connections.
4. Search for related indicators across endpoints and determine whether the behavior is authorized administration.
5. Escalate and contain only if corroborating evidence warrants it; refine detection logic to reduce known benign patterns.

## Portfolio validation
**Result:** PASSED — Custom Wazuh rule `100110` generated an indexed level-8 alert from controlled synthetic JSON process telemetry.

**Evidence to include:** Screenshot of the Threat Hunting event table and expanded `100110` alert details. Save as `screenshots/powershell-alert.png` and `screenshots/powershell-details.png`.

## Limitations
This is a detection engineering exercise based on fabricated process metadata. It is not a claim of real PowerShell execution or a confirmed incident.
