"""Offline, privacy-conscious correlation of Wazuh Sysmon alerts.

Input: JSON array of Wazuh alert objects (rule.id, agent.id, data.win.*).
No network operations; output contains no original GUIDs or account identifiers.
This is NOT a Wazuh manager rule or live-response action.
"""
from datetime import datetime, timezone


def _time(alert):
    raw = (alert.get("data", {}).get("win", {}).get("eventdata", {}).get("utcTime")
           or alert.get("timestamp"))
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).replace(
            tzinfo=timezone.utc
        ) if datetime.fromisoformat(str(raw).replace("Z", "+00:00")).tzinfo is None else datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def correlate(alerts, window_seconds=60):
    """Return sanitized findings for 100133 -> 100134 with same agent/GUID.

    Only correlate an encoded-flags alert before a controlled file alert.
    One finding per event pair, without exposing raw system identifiers.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    prepared = []
    for alert in alerts:
        rule_id = str(alert.get("rule", {}).get("id", ""))
        if rule_id not in {"100133", "100134"}:
            continue
        agent = str(alert.get("agent", {}).get("id", "")).strip()
        event = alert.get("data", {}).get("win", {}).get("eventdata", {})
        guid = str(event.get("processGuid", "")).strip().lower()
        when = _time(alert)
        if not (agent and guid and when):
            continue
        prepared.append((when, rule_id, agent, guid))
    prepared.sort(key=lambda item: item[0])
    prior = {}
    findings = []
    for when, rule_id, agent, guid in prepared:
        key = (agent, guid)
        if rule_id == "100133":
            prior[key] = when
        elif key in prior:
            delta = (when - prior[key]).total_seconds()
            if 0 <= delta <= window_seconds:
                findings.append({
                    "finding": "encoded_powershell_followed_by_lab_file_create",
                    "level": "investigate",
                    "matched_rules": ["100133", "100134"],
                    "delta_seconds": round(delta, 3),
                    "guid_match": True,
                    "agent_match": True,
                })
                del prior[key]
    return findings
