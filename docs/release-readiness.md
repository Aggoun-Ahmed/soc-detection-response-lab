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

- [ ] Pull final documentation commits; rerun `py -3 -m unittest discover -s tests -v`
- [ ] Inspect **all three existing Phase 1 screenshots** visually for personal names, machine names, user folders, IPs, tokens, URLs or open browser profile details; redact or remove before tagging
- [ ] Run a local source scan, including **Git history if any sensitive information was ever committed**; `.gitignore` prevents new accidents but does not scrub old commits
- [ ] Check README commands and Markdown links after cleanup
- [ ] Confirm GitHub Actions CI result for the final commit
- [ ] Create `v1.0.0` tag/release only after the above pass

## Honest scope statement

This repository is a **portfolio-scale controlled lab**, not a production SIEM integration or proof of a real attack. The live stdin monitor and the separately checkpointed snapshot CLI are not a combined unattended service. Log rotation recovery is operator-assisted and requires complete ordered retained history. There is no automatic containment, guaranteed exactly-once external notification, long-term throughput benchmark, or production false-positive assessment.

Phase 2–4 raw Windows log exports and unredacted screenshots were intentionally withheld to avoid sharing endpoint identifiers. Synthetic Phase 1 screenshots are separate assets and still require visual privacy inspection.
