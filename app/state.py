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

# Audit logs are metadata-only but grow quickly. Rotate before they become a
# liability; the reader only ever needs the tail.
MAX_AUDIT_BYTES = 20 * 1024 * 1024
AUDIT_KEEP = 3


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
        _rotate_if_needed(path)
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def append_audit_many(path, records):
    """Write a batch with one open/write/fsync instead of one per record."""
    records = list(records)
    if not records:
        return
    payload = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in records
    )
    with _lock:
        _rotate_if_needed(path)
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())


def _rotate_if_needed(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size < MAX_AUDIT_BYTES:
        return
    for index in range(AUDIT_KEEP - 1, 0, -1):
        older = "%s.%d" % (path, index)
        newer = "%s.%d" % (path, index + 1)
        if os.path.exists(older):
            os.replace(older, newer)
    try:
        os.replace(path, path + ".1")
    except OSError:
        pass


def tail_jsonl(path, limit):
    """Last `limit` records of a JSONL file, newest last. Never raises.

    Reads backwards in blocks instead of loading the whole file, so a large
    audit log costs memory proportional to the requested tail.
    """
    if limit <= 0:
        return []
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            data = b""
            while position > 0 and data.count(b"\n") < limit + 1:
                step = min(8192, position)
                position -= step
                handle.seek(position)
                data = handle.read(step) + data
    except OSError:
        return []
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    if position > 0 and lines:
        lines = lines[1:]  # first line may be a partial record
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
