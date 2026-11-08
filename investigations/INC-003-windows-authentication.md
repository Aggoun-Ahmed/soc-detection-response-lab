# INC-003 — Repeated Windows Authentication Failures (Endpoint Telemetry)

**Disposition:** Controlled detection-engineering validation; **not a real attack or confirmed incident**  
**Date:** 2026-11-08 (dashboard-local time; UTC in manager alerts)  
**Environment:** Windows 11 endpoint monitored by Wazuh Agent `001`, Wazuh 4.14.10 single-node Docker SIEM  
**Detection:** Custom rule [`100120`](../rules/windows_auth_rules.xml), level **10**, MITRE ATT&CK **T1110 (Brute Force)**

## Executive summary

Five deliberately failed, local interactive authentication attempts against a **nonexistent lab username** generated genuine **Windows Security Event ID 4625** records. Wazuh Agent `001` collected the Windows EventChannel records and transmitted them to the Wazuh manager. The built-in Wazuh rule `60122` detected individual failed logons at level 5; the custom rule `100120` then correlated five failures within 60 seconds for the same target username and produced an indexed **level-10** alert.

The correlation was observed on **two separate controlled test runs** (`rule.firedtimes: 2` in the later alert). No actual password-guessing campaign, successful account access, or compromise occurred.

## Detection logic

| Property | Configured value |
| --- | --- |
| Rule file | [`rules/windows_auth_rules.xml`](../rules/windows_auth_rules.xml) |
| Triggering base rule | `60122` — Logon Failure: Unknown user or bad password |
| Correlation rule | `100120` |
| Frequency / timeframe | 5 qualifying events in 60 seconds |
| Grouping key | `win.eventdata.targetUserName` via `same_field` |
| Severity | 10 |
| MITRE ATT&CK | T1110 — Brute Force, Credential Access |

The rule correlates on the **target username**, not the remote source address. The test used local, interactive logons without a source network address. This is an important limitation when considering production use.

## Observed evidence

| Attribute | Evidence |
| --- | --- |
| Agent | `001`, `soc-win-endpoint` |
| Event source | `Microsoft-Windows-Security-Auditing`, Windows **Security** channel |
| Windows event ID | `4625` |
| Wazuh decoder | `windows_eventchannel` |
| Built-in Wazuh rule | `60122`, level 5 |
| Correlation rule | **`100120`**, level **10** |
| Matched test account | `SOC_LAB_NONEXISTENT` (intentionally nonexistent) |
| Windows logon type | `2` — Interactive |
| Status / substatus | `0xC000006D` / `0xC0000064` (failed authentication / unknown user) |
| Correlation | `rule.frequency: 5` |
| ATT&CK mapping on custom alert | `T1110`, Credential Access / Brute Force |
| First indexed correlation alert | 2026-11-08 **16:48:55 UTC** (17:48:55 CET) |
| Second indexed correlation alert | 2026-11-08 **16:50:28 UTC** (17:50:28 CET) |

The two runs generated five Event ID `4625` records each, approximately two seconds apart. The second batch was observed on Windows at approximately **17:50:19–17:50:27 CET**; Wazuh showed the correlated alert at **17:50:28.675 CET**. The later dashboard alert included `rule.firedtimes: 2`.

### Sanitized evidence excerpt (selected alert fields only)

```json
{
  "timestamp": "2026-11-08T16:50:28.675+0000",
  "agent": {"id": "001", "name": "soc-win-endpoint"},
  "rule": {
    "id": "100120",
    "level": 10,
    "frequency": 5,
    "firedtimes": 2,
    "description": "SOC LAB: Repeated Windows failed logons for the same account",
    "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}
  },
  "decoder": {"name": "windows_eventchannel"},
  "data": {
    "win": {
      "system": {"channel": "Security", "eventID": "4625"},
      "eventdata": {"targetUserName": "SOC_LAB_NONEXISTENT", "logonType": "2", "subStatus": "0xc0000064"}
    }
  }
}
```

*Excerpt reconstructed from the observed manager alert and dashboard fields; omitted unneeded identifiers and verbose Windows event messages. This is not an unmodified raw event.*

## Test procedure and observed results

1. Confirmed Wazuh Agent `001` was **Active** and the Windows agent monitored the Security EventChannel.
2. Confirmed local audit policy included **Success and Failure** for Logon.
3. Invoked the Windows `LogonUser` API five times against `SOC_LAB_NONEXISTENT`, a nonexistent local username, with an intentionally fake password; each call returned failure.
4. Verified five new Security Event ID `4625` records in Windows Event Viewer / PowerShell.
5. Confirmed base alerts `60122` and correlation alert `100120` in Wazuh Threat Hunting.
6. Verified the same correlation appeared in Wazuh `alerts.json` on two test runs.

**Outcome: PASS** for controlled end-to-end correlation of authentic Windows failed-logon telemetry.

## Analyst triage and interpretation

**Observed:** Local interactive authentication failures for one nonexistent test account, with a repeated-event pattern meeting the lab correlation threshold.

**Not observed:** Any successful authentication, real external source IP, malicious intent, lateral movement, account takeover, user impact, or production attack. The event's original Wazuh base rule includes a different ATT&CK mapping; the custom repeated-failure alert intentionally uses T1110 as the detection hypothesis, **not proof of an attack**.

**If this were production telemetry:** Review whether the username exists, whether failure attempts originate from multiple endpoints/sources, whether successful logons follow, and whether account lockouts, MFA events, or suspicious process/network activity accompany them. Validate source attribution before choosing containment.

## False positives and limits

- A burst of failures may come from stale credentials, mistyped usernames, legitimate administration, scripts, or misconfigured services.
- The rule groups by target username **within the Wazuh correlation context**; this test did not validate behavior across multiple agents or unrelated usernames.
- Threshold 5/60s is a demonstration setting, not tuned against an organizational baseline.
- This test validates local interactive logons (`logonType=2`), not remote RDP, SMB, VPN, or cloud authentication.
- No negative-control test of distinct target usernames or non-failure events is documented yet.
- Source address was not populated for these local logons.

## Next improvements

1. Add distinct-user and low-volume negative tests before making stronger correlation claims.
2. Test dedicated lab accounts in an isolated VM and assess the effect of account-lockout policy without touching personal accounts.
3. Extend coverage to network logon types and compare per-username and per-source-IP detection hypotheses.
4. Add Sysmon process telemetry and PowerShell Operational logs to strengthen triage context.
5. Keep screenshots redacted; never publish raw Windows Security events containing personal SIDs, hostnames, usernames, or logon IDs.

**Related:** [Detection rule](../rules/windows_auth_rules.xml) · [README](../README.md)
