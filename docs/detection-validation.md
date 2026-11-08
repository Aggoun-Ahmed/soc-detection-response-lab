# Detection validation matrix

Complete this after **running real Wazuh tests**. Offline unit tests validate only the generator, reference analyzer and XML syntax.

| Test | Expected | Actual Wazuh rule ID | Verified? | Evidence |
| --- | --- | --- | --- | --- |
| 1 synthetic failed login | 100100 | TBD | No | TBD |
| 5 synthetic failed logins, same source, 60 s | 100101 | TBD | No | TBD |
| Synthetic PowerShell execution indicator | 100110 | TBD | No | TBD |
| Auth failures from distinct IPs | No cross-IP correlation | TBD | No | TBD |
| Non-lab JSON events | No lab-specific match | TBD | No | TBD |

## Suggested manual procedure

1. Run Python unit tests.
2. Run `scripts/setup-wazuh.ps1`; inspect `docker compose ps`.
3. Run `scripts/install-rules.ps1`; inspect manager logs.
4. Use `wazuh-logtest` to test individual JSON events; note that **frequency correlation may depend on session/state and event timing**.
5. Feed events using `scripts/ingest-events.ps1`.
6. Search dashboard data and record actual rule ID, time, source IP and level.
7. Capture sanitized screenshots and complete the table; troubleshoot failed tests rather than assuming success.
