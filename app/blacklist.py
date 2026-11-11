"""blacklist.txt: one entry per line.

    # comments and blank lines are ignored
    hello@example.com      exact sender address
    @example.com           every sender at that domain

Adds and removes rewrite the file atomically and keep existing comments and
ordering, so hand edits and API calls cannot corrupt each other.
"""

import os
import re
import tempfile
import threading

# Deliberately strict: no whitespace, quotes, backslashes or control characters
# may reach an IMAP search string.
ADDR_RE = re.compile(
    r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

# A wildcard on one of these deletes nearly the whole mailbox. Exact addresses
# at these domains are still allowed; only "@domain" is refused.
FREE_MAIL = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "protonmail.com",
    "proton.me",
    "gmx.com",
    "gmx.de",
    "mail.com",
    "zoho.com",
    "yandex.com",
}

HEADER = (
    "# gmail-spam-assassin blacklist\n"
    "# one entry per line: an exact address (a@b.com) or a whole domain (@b.com)\n"
    "# '#' starts a comment. Messages from these senders are moved to Trash.\n"
)

_lock = threading.Lock()


class InvalidEntry(ValueError):
    pass


def validate(raw, allow_freemail=False):
    """Return the normalised entry or raise InvalidEntry with a reason."""
    entry = (raw or "").strip().lower()
    if not entry:
        raise InvalidEntry("empty")
    if entry.startswith("#"):
        raise InvalidEntry("comment, not an entry")
    for char in entry:
        if char.isspace() or char in "\"'\\":
            raise InvalidEntry("contains whitespace, a quote or a backslash")
        if ord(char) < 32 or ord(char) == 127:
            raise InvalidEntry("contains a control character")
    if entry.startswith("@"):
        domain = entry[1:]
        if not DOMAIN_RE.match(domain):
            raise InvalidEntry("not a valid domain")
        if domain in FREE_MAIL and not allow_freemail:
            raise InvalidEntry(
                "refusing a free-mail domain wildcard; list the exact address instead"
            )
        return "@" + domain
    if "@" not in entry:
        raise InvalidEntry("bare domain: write @domain.com for a whole domain")
    if entry.count("@") != 1:
        raise InvalidEntry("more than one @")
    if not ADDR_RE.match(entry):
        raise InvalidEntry("not a valid address")
    return entry


def parse_text(text, allow_freemail=False):
    entries = []
    errors = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            entry = validate(stripped, allow_freemail)
        except InvalidEntry as exc:
            errors.append({"line": number, "entry": stripped, "reason": str(exc)})
            continue
        if entry not in entries:
            entries.append(entry)
    return entries, errors


def load(path, allow_freemail=False):
    """Read and parse the file. A missing file is an empty blacklist."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except FileNotFoundError:
        return [], []
    return parse_text(text, allow_freemail)


def matches(address, entries):
    """Which entry covers this address, or None."""
    addr = (address or "").strip().lower()
    if not addr or "@" not in addr:
        return None
    if addr in entries:
        return addr
    domain = addr.rsplit("@", 1)[1]
    for entry in entries:
        if entry.startswith("@") and entry[1:] == domain:
            return entry
    return None


def ensure(path, header=HEADER):
    """Create the file with a header if it does not exist yet."""
    if os.path.exists(path):
        return
    with _lock:
        if os.path.exists(path):
            return
        _write(path, header)


def _read_raw(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""


def _write(path, text):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".blacklist-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def add(path, addresses, allow_freemail=False, header=HEADER):
    result = {"added": [], "skipped": [], "errors": []}
    with _lock:
        text = _read_raw(path)
        existing, _ = parse_text(text, allow_freemail)
        new_lines = []
        for raw in addresses:
            try:
                entry = validate(raw, allow_freemail)
            except InvalidEntry as exc:
                result["errors"].append({"entry": raw, "reason": str(exc)})
                continue
            if entry in existing:
                result["skipped"].append(entry)
                continue
            existing.append(entry)
            new_lines.append(entry)
            result["added"].append(entry)
        if new_lines:
            body = text
            if not body.strip():
                body = header
            if body and not body.endswith("\n"):
                body += "\n"
            body += "\n".join(new_lines) + "\n"
            _write(path, body)
    return result


def remove(path, addresses):
    result = {"removed": [], "missing": [], "errors": []}
    with _lock:
        targets = set()
        for raw in addresses:
            entry = (raw or "").strip().lower()
            if not entry:
                result["errors"].append({"entry": raw, "reason": "empty"})
                continue
            targets.add(entry)
        text = _read_raw(path)
        kept = []
        removed = set()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                if stripped.lower() in targets:
                    removed.add(stripped.lower())
                    continue
            kept.append(line)
        for target in sorted(targets):
            if target in removed:
                result["removed"].append(target)
            else:
                result["missing"].append(target)
        if removed:
            body = "\n".join(kept).rstrip("\n") + "\n"
            _write(path, body)
    return result
