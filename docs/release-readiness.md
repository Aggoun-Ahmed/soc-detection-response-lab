# v1.0.0 Release Readiness Checklist

**Status:** Release candidate; do not publish a final tag until the remaining privacy and local verification checks are complete.

## Verified functionality

- [x] Five phases implemented for a controlled defensive SOC lab
- [x] Wazuh 4.14.10 synthetic detection and real Windows Security/Sysmon alert validation
- [x] Live read-only stream: one real rule `100133` + `100134` finding; 0.189-second event interval
- [x] Python correlation positive and negative controls against Wazuh alert pairs
- [x] Manual checkpoint restart and unchanged-file replay checks
- [x] Durable pending findings and explicit acknowledgment
- [x] Manual concurrent CLI checkpoint lock contention and recovery
- [x] Manual synthetic log rotation across two retained segments (one finding, 0.197 seconds; replay kept ID 1)
- [x] Most recently reported local regression run: **59/59 tests passed** (0 failures, 0.195 seconds)

## Release gates

- [x] Final local regression re-run reported: **59/59 PASS**, 0 failures, 0.197 seconds (local confirmation; final Git HEAD should still be synchronized)
- [x] **Screenshot privacy:** all three Phase 1 screenshots visually reviewed; the overview's API selector identifier was redacted and the user pushed the replacement in commit `4807ca3`. GitHub tree confirms the public overview blob changed (original `b4adddc5` → replacement `515ac693`). Reopen the published screenshot visually once more as a final sign-off.
- [ ] Run a local source scan, including **Git history if any sensitive information was ever committed**; `.gitignore` prevents new accidents but does not scrub old commits
- [ ] Check README commands and Markdown links after cleanup
- [x] GitHub Actions Python tests **success** on screenshot replacement commit `4807ca3` ([run](https://github.com/Aggoun-Ahmed/soc-detection-response-lab/actions/runs/42534720868)); rerun after any subsequent documentation commit
- [ ] Create `v1.0.0` tag/release only after the above pass

## Honest scope statement

This repository is a **portfolio-scale controlled lab**, not a production SIEM integration or proof of a real attack. The live stdin monitor and the separately checkpointed snapshot CLI are not a combined unattended service. Log rotation recovery is operator-assisted and requires complete ordered retained history. There is no automatic containment, guaranteed exactly-once external notification, long-term throughput benchmark, or production false-positive assessment.

Phase 2–4 raw Windows log exports and unredacted screenshots were intentionally withheld to avoid sharing endpoint identifiers. Synthetic Phase 1 screenshots were visually inspected, and the dashboard overview was replaced with a redacted version. As with any Git change, older binary versions can remain in repository history.
