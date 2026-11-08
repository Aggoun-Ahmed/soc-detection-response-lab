"""Offline correlation of selected Wazuh Sysmon alerts.

No network operations. Only sanitized findings are returned, never raw GUIDs,
account identifiers, hostnames, or command lines. Not a live Wazuh rule.
"""
from datetime import datetime, timezone
from math import isfinite


def _object(value):
    return value if isinstance(value, dict) else {}


def _timestamp(alert):
    event = _object(_object(_object(alert.get("data")).get("win")).get("eventdata"))
    raw = event.get("utcTime") or alert.get("timestamp")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        # Wazuh Sysmon utcTime is explicitly UTC even without an offset.
        return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None
                else parsed.astimezone(timezone.utc))
    except (ValueError, OverflowError):
        return None


def correlate(alerts, window_seconds=60):
    """Join 100133 -> 100134 by agent ID and process GUID within a time window.

    Input may arrive unsorted. Each process yields at most one finding; repeated
    copies of either alert do not create additional findings. Missing/invalid
    fields are ignored. Intended for bounded offline alert batches.
    """
    if not isinstance(window_seconds, (int, float)) or not isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite positive number")
    if not isinstance(alerts, (list, tuple)):
        raise TypeError("alerts must be a list or tuple of alert dictionaries")
    events = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        rule_id = str(_object(alert.get("rule")).get("id", ""))
        if rule_id not in {"100133", "100134"}:
            continue
        agent = _object(alert.get("agent")).get("id")
        event = _object(_object(_object(alert.get("data")).get("win")).get("eventdata"))
        guid = event.get("processGuid")
        when = _timestamp(alert)
        if not isinstance(agent, str) or not agent.strip() or not isinstance(guid, str) or not guid.strip() or when is None:
            continue
        events.append((when, rule_id, agent.strip(), guid.strip().lower()))
    # Put process alert first if both event timestamps are identical.
    events.sort(key=lambda event: (event[0], 0 if event[1] == "100133" else 1))
    active = {}
    emitted = set()
    findings = []
    for when, rule_id, agent, guid in events:
        key = (agent, guid)
        if key in emitted:
            continue
        if rule_id == "100133":
            active.setdefault(key, when)  # duplicate start must not reset clock
        elif key in active:
            delta = (when - active[key]).total_seconds()
            if 0 <= delta <= window_seconds:
                findings.append({
                    "finding": "encoded_powershell_followed_by_lab_file_create",
                    "level": "investigate",
                    "matched_rules": ["100133", "100134"],
                    "delta_seconds": round(delta, 3),
                    "guid_match": True,
                    "agent_match": True,
                })
                emitted.add(key)
    return findings
