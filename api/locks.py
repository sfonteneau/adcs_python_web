"""Process-safe per-CA operation locks for independent API workers (Linux)."""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path


@contextmanager
def operation_lock(directory: str, scope: str):
    path = Path(directory)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = hashlib.sha256(scope.encode("utf-8")).hexdigest() + ".lock"
    fd = os.open(str(path / name), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
