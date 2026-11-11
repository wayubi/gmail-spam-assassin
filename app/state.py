"""Shared state file and audit log.

One process, several threads: every write goes through a single lock and is
atomic (temp file + rename), so a reader never sees a half-written file.
"""

import json
import os
import tempfile
import threading
from datetime import datetime, timezone

_lock = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path, text):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def read_state(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def update_state(path, **fields):
    with _lock:
        data = read_state(path)
        data.update(fields)
        data["updated"] = now_iso()
        _atomic_write(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
        return data


def append_audit(path, record):
    line = json.dumps(record, ensure_ascii=False, sort_keys=True)
    with _lock:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def tail_jsonl(path, limit):
    """Last `limit` records of a JSONL file, newest last. Never raises."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
