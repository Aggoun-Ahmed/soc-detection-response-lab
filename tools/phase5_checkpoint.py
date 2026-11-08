"""Checkpointed read-only *snapshot* replay for Wazuh JSONL.

Designed for a local copy of alerts.json. The source is read from the beginning
and its prefix hash verified before any new alerts are accepted. This is not
a continuously running monitor, and it never sends data over the network.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
from datetime import datetime

from tools.sysmon_stream import IncrementalCorrelator
from tools.sysmon_correlator import _object

VERSION = 1
ZERO_HASH = "0" * 64


def _deserialize_dates(values):
    if not isinstance(values, dict):
        raise ValueError("invalid checkpoint event state")
    return {("anon", key): datetime.fromisoformat(value) for key, value in values.items()}


class SnapshotCheckpoint:
    """Replays append-only file snapshots, retaining pseudonymous correlator state."""

    def __init__(self, state_path):
        self.path = Path(state_path)
        self.engine = IncrementalCorrelator()
        self.lines = 0
        self.digest = ZERO_HASH
        self.secret = secrets.token_bytes(32)
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("version") != VERSION:
                raise ValueError("unsupported checkpoint version")
            self.lines = data["lines"]
            self.digest = data["digest"]
            self.secret = base64.b64decode(data["secret"], validate=True)
            if (not isinstance(self.lines, int) or self.lines < 0
                    or not isinstance(self.digest, str) or len(self.digest) != 64
                    or len(self.secret) != 32):
                raise ValueError("invalid checkpoint metadata")
            state = data["engine"]
            self.engine.processes = _deserialize_dates(state["processes"])
            self.engine.files = _deserialize_dates(state["files"])
            self.engine.emitted = _deserialize_dates(state["emitted"])
            self.engine.watermark = (datetime.fromisoformat(state["watermark"])
                                     if state["watermark"] else None)

    def _snapshot(self):
        def pack(values):
            return {key[1]: when.isoformat() for key, when in values.items()}
        return {
            "version": VERSION, "lines": self.lines, "digest": self.digest,
            "secret": base64.b64encode(self.secret).decode("ascii"),
            "engine": {
                "processes": pack(self.engine.processes),
                "files": pack(self.engine.files),
                "emitted": pack(self.engine.emitted),
                "watermark": self.engine.watermark.isoformat() if self.engine.watermark else None,
            },
        }

    def _write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8",
                                             dir=self.path.parent, prefix=".phase5-",
                                             suffix=".tmp", delete=False) as handle:
                tmp = Path(handle.name)
                json.dump(self._snapshot(), handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        finally:
            if tmp and tmp.exists():
                tmp.unlink()

    def _pseudonymize(self, alert):
        if not isinstance(alert, dict):
            return alert
        agent = _object(alert.get("agent")).get("id")
        event = _object(_object(_object(alert.get("data")).get("win")).get("eventdata"))
        guid = event.get("processGuid")
        if not isinstance(agent, str) or not agent.strip() or not isinstance(guid, str) or not guid.strip():
            return {}
        identity = (agent.strip() + "\x00" + guid.strip().lower()).encode("utf-8")
        pseudonym = hmac.new(self.secret, identity, hashlib.sha256).hexdigest()
        return {
            "rule": {"id": _object(alert.get("rule")).get("id")},
            "agent": {"id": "anon"},
            "data": {"win": {"eventdata": {
                "processGuid": pseudonym, "utcTime": event.get("utcTime")
            }}},
            "timestamp": alert.get("timestamp"),
        }

    def process(self, input_path):
        """Return sanitized findings. Refuse rotated/truncated/changed prefixes."""
        findings = []
        old_lines = self.lines
        old_digest = self.digest
        rolling = ZERO_HASH
        count = 0
        verified = old_lines == 0
        with Path(input_path).open("rb") as handle:
            for line in handle:
                if not line.endswith(b"\n"):
                    raise ValueError("incomplete last line; retry after log finishes writing")
                rolling = hashlib.sha256(bytes.fromhex(rolling) + line).hexdigest()
                count += 1
                if count <= old_lines:
                    if count == old_lines:
                        if rolling != old_digest:
                            raise RuntimeError("alert source changed or rotated; refusing checkpoint reuse")
                        verified = True
                    continue
                alert = None
                try:
                    alert = json.loads(line)
                except (ValueError, UnicodeError):
                    pass
                batch = self.engine.ingest(self._pseudonymize(alert))
                self.lines = count
                self.digest = rolling
                self._write()
                findings.extend(batch)
        if not verified:
            raise RuntimeError("alert source truncated; refusing checkpoint reuse")
        return findings


def main():
    parser = argparse.ArgumentParser(description="Read-only checkpointed Wazuh snapshot replay")
    parser.add_argument("--input", required=True, help="Local copy of alerts.json (sensitive)")
    parser.add_argument("--state", required=True, help="Local checkpoint path, outside Git repo")
    args = parser.parse_args()
    worker = SnapshotCheckpoint(args.state)
    for finding in worker.process(args.input):
        print(json.dumps(finding), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print("Checkpoint validation failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
