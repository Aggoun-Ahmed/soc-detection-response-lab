# INC-001 — Repeated Authentication Failures (Controlled Simulation)

**Status:** Detection validated; no real-world compromise established  
**Environment:** Local Wazuh 4.14.10 single-node Docker SOC lab  
**Event date:** 2026-11-07 18:36:02.773 (dashboard-displayed time; timezone not independently verified)  
**Scenario:** Five synthetic authentication failures from the same source IP

## Executive summary
Five deliberately generated JSON `auth_failure` records for `demo_user` on `demo-win01` from the documentation-only IP address `192.0.2.44` were collected and decoded by Wazuh. Base rule `100100` emitted level-3 observations, and correlation rule `100101` emitted a level-10 alert when its frequency threshold of five was met. This validates the configured detection path in a lab; it does **not** establish that a real authentication attempt occurred or that an account was compromised.

## Observed evidence

| Field | Observed value |
| --- | --- |
| Alert rule | `100101` |
| Description | LAB: repeated authentication failures from same source IP |
| Severity | Level 10 |
| Threshold | `rule.frequency: 5` |
| Source IP | `192.0.2.44` (RFC 5737 TEST-NET-1 documentation address) |
| Host | `demo-win01` |
| Username | `demo_user` |
| Event type | `auth_failure` |
| Input file | `/var/ossec/logs/lab-events.jsonl` |
| JSON decoder | `json` |
| Wazuh agent | `000` / `wazuh.manager` (local synthetic log ingestion, not a deployed Windows agent) |
| ATT&CK | `T1110` — Brute Force / Credential Access |
| Alert timestamp | `2026-11-07 18:36:02.773` as displayed in dashboard |

The dashboard also showed multiple `100100` level-3 base observations at the same displayed time. The correlated alert's `previous_output` included the preceding synthetic records.

## Triage and interpretation
- **What was verified:** Wazuh collected the synthetic JSON events, recognized authentication failures, correlated the repeated events and indexed a level-10 alert visible in Threat Hunting.
- **What was not verified:** Authentication against a real service, the existence of a user session, compromise, lateral movement, actual source-host attribution, or real incident impact.
- **False-positive considerations for a production rule:** Legitimate user mistakes, scheduled jobs with stale credentials, NAT/shared IPs, and volume spikes from automated systems. The source IP and username in this scenario are invented test identifiers.

## Recommended response if observed in production
1. Review authentication events before and after the trigger and identify whether any subsequent login succeeded.
2. Validate the source address, affected account, target system, geography and authentication method using independent telemetry.
3. Check for associated account lockouts, MFA prompts, privilege changes or anomalous sessions.
4. Apply account protections, rate limits or IP controls where supported by the evidence and policy.
5. Tune the rule using baselines, asset criticality and source-account correlation; confirm repeated detections remain reliable.

## Portfolio validation
**Result:** PASSED — Custom Wazuh correlation rule `100101` generated an indexed level-10 alert from controlled synthetic JSON records.

**Evidence to include:** Screenshot of the Threat Hunting event table and expanded `100101` alert details. Capture the screenshots from the lab and store as `screenshots/brute-force-alert.png` and `screenshots/brute-force-details.png`.

## Limitations
This is a detection engineering exercise based on injected synthetic telemetry; do not label it a real brute-force attack or a confirmed security incident.
