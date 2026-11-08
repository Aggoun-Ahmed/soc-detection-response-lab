"""OS-backed non-blocking single-writer lock for a local checkpoint.

Lock file is intentionally never deleted, preventing pathname replacement races.
Windows uses msvcrt byte-range locking; POSIX uses flock.
"""
from contextlib import contextmanager
import os
from pathlib import Path


@contextmanager
def checkpoint_lock(state_path):
    lock_path = Path(str(state_path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        # The Windows byte-range API needs a byte to lock.
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"\x00")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError("checkpoint is in use by another process") from exc
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError("checkpoint is in use by another process") from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
