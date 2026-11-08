#!/usr/bin/env python3
"""Emit harmless, synthetic JSONL security events for a local SOC detection lab."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate(scenario: str, started: datetime | None = None) -> list[dict]:
    started = started or datetime.now(timezone.utc).replace(microsecond=0)
    events = []
    if scenario in ("brute-force", "all"):
        for i in range(5):
            events.append({
                "timestamp": (started + timedelta(seconds=i * 5)).isoformat(),
                "lab": "soc-portfolio", "event_type": "auth_failure",
                "source_ip": "192.0.2.44", "host": "demo-win01",
                "username": "demo_user", "result": "failure",
                "message": "Synthetic failed login for detection validation",
            })
    if scenario in ("powershell", "all"):
        events.append({
            "timestamp": (started + timedelta(seconds=30)).isoformat(),
            "lab": "soc-portfolio", "event_type": "suspicious_powershell",
            "host": "demo-win01", "username": "demo_user",
            "process_name": "powershell.exe", "parent_process": "explorer.exe",
            "command_line": "powershell.exe -NoProfile -EncodedCommand <SYNTHETIC-NOT-EXECUTABLE>",
            "message": "Synthetic process telemetry; no command executed",
        })
    return events


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=("brute-force", "powershell", "all"), default="all")
    ap.add_argument("--out", type=Path, default=Path("samples/generated-events.jsonl"))
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    events = generate(args.scenario)
    args.out.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events), encoding="utf-8")
    print(f"Wrote {len(events)} harmless synthetic events to {args.out}")


if __name__ == "__main__":
    main()
