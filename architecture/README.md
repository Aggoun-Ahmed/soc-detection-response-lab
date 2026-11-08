# Architecture notes

The Mermaid diagram in the main README is the authoritative initial architecture sketch. After successful lab deployment, capture a sanitized screenshot of the Docker Compose topology or create an architecture illustration that distinguishes:

1. Synthetic event generator (Windows host)
2. Wazuh manager log collector + analysis rules (Docker)
3. Wazuh indexer (Docker)
4. Wazuh dashboard (Docker)

Do not imply a Windows endpoint agent or Sysmon installation until it has actually been added.
