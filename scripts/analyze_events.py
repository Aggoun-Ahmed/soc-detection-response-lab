#!/usr/bin/env python3
"""Offline, illustrative detection oracle; NOT a replacement for wazuh-logtest."""
import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def analyze(events: list[dict]) -> list[dict]:
    alerts = []
    failures = defaultdict(list)
    for event in events:
        if event.get("lab") != "soc-portfolio":
            continue
        if event.get("event_type") == "auth_failure":
            try:
                when = datetime.fromisoformat(event["timestamp"])
            except (ValueError, KeyError):
                continue
            key = event.get("source_ip", "unknown")
            failures[key].append(when)
            window = [t for t in failures[key] if timedelta(0) <= when - t <= timedelta(seconds=60)]
            failures[key] = window
            if len(window) == 5:
                alerts.append({"rule_id": 100101, "source_ip": key, "count": len(window)})
        if event.get("event_type") == "suspicious_powershell" and event.get("process_name") == "powershell.exe":
            alerts.append({"rule_id": 100110, "host": event.get("host")})
    return alerts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("events", type=Path)
    a = parser.parse_args()
    records = [json.loads(line) for line in a.events.read_text(encoding="utf-8").splitlines() if line.strip()]
    print(json.dumps({"events": len(records), "local_expected_alerts": analyze(records)}, indent=2))
    print("Note: Wazuh engine integration is not verified by this script.")


if __name__ == "__main__":
    main()
