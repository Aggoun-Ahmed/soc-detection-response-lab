# Lab threat model and safety scope

## Assets and trust boundaries

- Local Docker Desktop WSL2 backend (nonproduction).
- Wazuh manager, indexer and dashboard pulled from official upstream.
- Custom synthetic event source appended to a **dedicated** JSONL file in the manager container.
- GitHub repository with detection logic, README and **sanitized** evidence only.

## Explicit exclusions

- No brute-force attempts, exploit attempts, malware, persistence changes, or real endpoint scanning.
- No personal data or corporate security logs.
- No internet-facing port exposure; Docker's default bindings must be reviewed on your machine.
- No assumption that an indicator equals a confirmed compromise.

## Risks and mitigations

- Default admin/demo credentials: change immediately if moving beyond isolated localhost testing.
- Self-signed TLS warning: acceptable for local lab only; don't bypass certificate validation on external sites.
- Excessive Docker resources: allocate enough RAM and disk, and stop containers when finished.
- False positives and simulation-to-reality gap: document what was observed vs assumed.
