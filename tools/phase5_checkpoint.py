"""Checkpointed read-only *snapshot* replay for Wazuh JSONL.

Designed for a local copy of alerts.json. The source is read from the beginning
and its prefix hash verified before any new alerts are accepted. This is not
a continuously running monitor, and it never sends data over the network.
"""
import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
from datetime import datetime

from tools.checkpoint_lock import checkpoint_lock
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
        self.pending = []
        self.next_finding_id = 1
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
            self.pending = data.get("pending", [])
            self.next_finding_id = data.get("next_finding_id", 1)
            if (not isinstance(self.pending, list) or not isinstance(self.next_finding_id, int)
                    or self.next_finding_id < 1 or any(
                        not isinstance(item, dict) or not isinstance(item.get("id"), int)
                        or not isinstance(item.get("finding"), dict)
                        for item in self.pending)):
                raise ValueError("invalid outbox data")
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
            "pending": self.pending, "next_finding_id": self.next_finding_id,
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

    @staticmethod
    def _read_segments(paths):
        """Yield raw lines from ordered retained segments, including .gz archives."""
        for path in paths:
            file_path = Path(path)
            opener = gzip.open if file_path.suffix.lower() == ".gz" else open
            with opener(file_path, "rb") as handle:
                for line in handle:
                    if not line.endswith(b"\n"):
                        raise ValueError("incomplete last line in a log segment")
                    yield line

    def process(self, input_path):
        """Original single-file snapshot interface; retains existing semantics."""
        return self.process_segments([input_path])

    def process_segments(self, paths):
        """Continue through ordered complete segments after verifying past prefix.

        All retained old lines must appear verbatim, in order. Missing or modified
        earlier segments fail closed. This is NOT automatic Wazuh rotation discovery.
        """
        paths = list(paths)
        if not paths:
            raise ValueError("at least one input segment is required")
        resolved = [str(Path(p).resolve()) for p in paths]
        if len(set(resolved)) != len(resolved):
            raise ValueError("duplicate input segment path")
        # Validate full input before committing any new cursor, finding, or state.
        count = 0
        rolling = ZERO_HASH
        verified = self.lines == 0
        for line in self._read_segments(paths):
            count += 1
            if count <= self.lines:
                rolling = hashlib.sha256(bytes.fromhex(rolling) + line).hexdigest()
                if count == self.lines:
                    if rolling != self.digest:
                        raise RuntimeError("historical alert prefix changed, missing, or reordered; refusing replay")
                    verified = True
        if not verified:
            raise RuntimeError("historical alert prefix missing or truncated; refusing replay")

        # A second pass verifies the old prefix again, limiting TOCTOU risks.
        findings = []
        rolling = ZERO_HASH
        for index, line in enumerate(self._read_segments(paths), start=1):
            rolling = hashlib.sha256(bytes.fromhex(rolling) + line).hexdigest()
            if index <= self.lines:
                if index == self.lines and rolling != self.digest:
                    raise RuntimeError("log segment changed during processing; refusing replay")
                continue
            try:
                alert = json.loads(line)
            except (ValueError, UnicodeError):
                alert = None
            batch = self.engine.ingest(self._pseudonymize(alert))
            self.lines = index
            self.digest = rolling
            for finding in batch:
                self.pending.append({"id": self.next_finding_id, "finding": finding})
                self.next_finding_id += 1
            self._write()
            findings.extend(batch)
        return findings

    def pending_findings(self):
        """Sanitized findings awaiting explicit acknowledgement."""
        return list(self.pending)

    def acknowledge(self, finding_id):
        """Only remove an item after a human or downstream consumer handles it."""
        if not isinstance(finding_id, int) or finding_id < 1:
            raise ValueError("invalid finding ID")
        if not any(item["id"] == finding_id for item in self.pending):
            raise ValueError("finding ID is not pending")
        self.pending = [item for item in self.pending if item["id"] != finding_id]
        self._write()


def main():
    parser = argparse.ArgumentParser(description="Read-only checkpointed Wazuh snapshot replay")
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument("--input", help="Single local append-only JSONL snapshot (sensitive)")
    sources.add_argument("--segments", nargs="+", metavar="FILE",
                         help="Oldest-to-newest complete JSONL or .gz segments; retain all history")
    parser.add_argument("--state", required=True, help="Local checkpoint path, outside Git repo")
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--pending", action="store_true", help="List unacknowledged findings")
    options.add_argument("--ack", type=int, metavar="ID", help="Acknowledge one displayed finding ID")
    args = parser.parse_args()
    if not (args.input or args.segments or args.pending or args.ack is not None):
        parser.error("--input, --segments, --pending or --ack is required")
    if (args.input or args.segments) and (args.pending or args.ack is not None):
        parser.error("input sources cannot be combined with --pending or --ack")
    # Hold the lock throughout load, modify, commit and presentation.
    with checkpoint_lock(args.state):
        worker = SnapshotCheckpoint(args.state)
        if args.ack is not None:
            worker.acknowledge(args.ack)
            return
        if args.input:
            worker.process(args.input)
        elif args.segments:
            worker.process_segments(args.segments)
        for item in worker.pending_findings():
            print(json.dumps(item), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print("Checkpoint validation failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
