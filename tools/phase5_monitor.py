"""Read NDJSON from stdin, emit only sanitized correlated findings to stdout.

Usage (Windows PowerShell, from repo root):
docker exec single-node-wazuh.manager-1 tail -n 0 -F /var/ossec/logs/alerts/alerts.json | py -3 -m tools.phase5_monitor

Use Ctrl+C to stop. This is session-only; restart does not retain offset/state.
"""
import json
import sys
from tools.sysmon_stream import IncrementalCorrelator

def main():
    engine=IncrementalCorrelator()
    for line in sys.stdin:
        try: alert=json.loads(line)
        except (ValueError,UnicodeError): continue
        for finding in engine.ingest(alert):
            print(json.dumps(finding),flush=True)

if __name__=="__main__":
    main()
