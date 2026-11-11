"""Thin, defensive wrapper over imaplib for Gmail.

Three Gmail facts drive this module:

  * labels are folders, and a message has exactly one copy. Deleting is
    therefore "change the labels", not "remove the bytes".
  * deleting with \\Deleted + EXPUNGE is *not* reliable on Gmail. What an
    expunge does is governed by a per-account setting ("When a message is
    marked as deleted and expunged from the last visible IMAP folder") whose
    default is "archive", and whose other options are "move to Trash" and
    "delete forever". Two of the three outcomes are wrong for this app and the
    setting is invisible from here. So EXPUNGE is never issued.
  * moving a message to [Gmail]/Trash is done by COPYing it there. Gmail
    applies the Trash label to the one existing copy, which takes it out of
    All Mail/Inbox and starts the 30-day clock. Nothing in this module ever
    opens [Gmail]/Trash for writing, so nothing here can destroy mail.

Every hit is verified against the parsed From header before anything is
touched, because Gmail's from: search is a substring match.
"""

import email
import imaplib
import re
from datetime import timezone
from email.header import decode_header, make_header
from email.utils import parseaddr

HOST = "imap.gmail.com"
PORT = 993

ALL_MAIL = "[Gmail]/All Mail"
SPAM = "[Gmail]/Spam"
TRASH = "[Gmail]/Trash"
INBOX = "INBOX"

FETCH_ITEMS = (
    "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)] "
    "X-GM-MSGID X-GM-LABELS INTERNALDATE)"
)

SYSTEM_LABELS = {
    "\\inbox": "Inbox",
    "\\spam": "Spam",
    "\\trash": "Trash",
    "\\sent": "Sent",
    "\\draft": "Drafts",
    "\\important": "Important",
    "\\starred": "Starred",
    "\\all": "All Mail",
}


class ImapError(RuntimeError):
    pass


def quote(value):
    """Quote an IMAP string (mailbox name, search term)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def connect(user, password, timeout=60):
    conn = imaplib.IMAP4_SSL(HOST, PORT, timeout=timeout)
    try:
        conn.login(user, password)
    except imaplib.IMAP4.error as exc:
        try:
            conn.shutdown()
        except Exception:
            pass
        raise ImapError("login failed: %s" % exc) from exc
    except Exception as exc:
        try:
            conn.shutdown()
        except Exception:
            pass
        raise ImapError("connection failed: %s" % exc) from exc

    caps = _capabilities(conn)
    # X-GM-RAW is the search syntax this app depends on; without X-GM-EXT-1
    # every search would fail, so refuse up front instead.
    if b"X-GM-EXT-1" not in caps:
        _logout(conn)
        raise ImapError(
            "server does not advertise X-GM-EXT-1 (got: %s); Gmail search "
            "extensions are required" % caps.decode("ascii", "replace")[:200]
        )
    return conn


def _capabilities(conn):
    """Capabilities as advertised *now*.

    Gmail's pre-auth CAPABILITY is a shorter list than the post-LOGIN one, and
    imaplib caches the pre-auth list in conn.capabilities without ever
    refreshing it. Always ask again explicitly.
    """
    try:
        typ, data = conn.capability()
        if typ == "OK" and data and data[-1]:
            value = data[-1]
            if isinstance(value, bytes):
                return value.upper()
            return str(value).upper().encode()
    except Exception:
        pass

    caps = conn.capabilities or ()
    out = []
    for cap in caps:
        out.append(cap if isinstance(cap, bytes) else str(cap).encode())
    return b" ".join(out).upper()


def select(conn, mailbox, readonly=True):
    typ, data = conn.select(quote(mailbox), readonly=readonly)
    if typ != "OK":
        names = list_mailboxes(conn)
        detail = ("; folders available: %s" % ", ".join(names)) if names else ""
        raise ImapError("cannot open %s: %s%s" % (mailbox, data, detail))


def list_mailboxes(conn):
    """Names from LIST, unquoted. Empty list means LIST itself failed."""
    try:
        typ, data = conn.list()
    except Exception:
        return []
    if typ != "OK" or not data:
        return []
    names = []
    for raw in data:
        if not raw:
            continue
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        match = re.match(r'\([^)]*\)\s+(?:"[^"]*"|NIL)\s+(.+)$', line)
        if not match:
            continue
        name = match.group(1).strip()
        if name.startswith('"') and name.endswith('"'):
            name = name[1:-1]
        names.append(name)
    return names


def find_mailbox(conn, suffix, default=None):
    """Resolve a Gmail special folder, or None if the account does not expose it.

    `default` is only used when LIST itself is unavailable (older servers).
    """
    names = list_mailboxes(conn)
    if not names:
        return default
    target = suffix.lower()
    for name in names:
        if name.lower() == target:
            return name
    # Only Gmail's own namespace counts. A user label like "Archive/spam" must
    # never be mistaken for the Spam folder and swept.
    for name in names:
        lowered = name.lower()
        if not (
            lowered.startswith("[gmail]") or lowered.startswith("[google mail]")
        ):
            continue
        if lowered == target or lowered.endswith(target):
            return name
    return None


def find_label(conn, name):
    """Resolve a user-created Gmail label as an IMAP folder, or None.

    Exact match first, then case-insensitive. System folders are never
    returned: pointing QUARANTINE_LABEL at Trash, Spam or All Mail would turn a
    reversible hold into something very different.
    """
    wanted = (name or "").strip()
    if not wanted:
        return None
    names = list_mailboxes(conn)
    for candidate in names:
        if candidate == wanted:
            return candidate
    for candidate in names:
        if candidate.lower() == wanted.lower():
            return candidate
    return None


def search_uids(conn, raw_query, mailbox):
    """Gmail-indexed search. Opens the mailbox read-only."""
    select(conn, mailbox, readonly=True)
    typ, data = conn.uid("SEARCH", "X-GM-RAW", quote(raw_query))
    if typ != "OK":
        raise ImapError("search failed in %s: %s" % (mailbox, data))
    uids = []
    for chunk in data:
        if chunk:
            uids.extend(chunk.split())
    return sorted(int(uid) for uid in uids)


def all_uids(conn, mailbox):
    """Every UID in a mailbox, without Gmail's search syntax. Read-only."""
    select(conn, mailbox, readonly=True)
    typ, data = conn.uid("SEARCH", "ALL")
    if typ != "OK":
        raise ImapError("search ALL failed in %s: %s" % (mailbox, data))
    uids = []
    for chunk in data:
        if chunk:
            uids.extend(chunk.split())
    return sorted(int(uid) for uid in uids)


def fetch_meta(conn, uids, chunk_size=100):
    rows = []
    uids = list(uids)
    for start in range(0, len(uids), chunk_size):
        chunk = uids[start : start + chunk_size]
        uidset = ",".join(str(uid) for uid in chunk)
        typ, data = conn.uid("FETCH", uidset, FETCH_ITEMS)
        if typ != "OK":
            raise ImapError("fetch failed: %s" % (data,))
        rows.extend(_parse_fetch(data))
    return rows


def _parse_fetch(data):
    rows = []
    for item in data:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        meta, body = item
        text = meta.decode("utf-8", "replace") if isinstance(meta, bytes) else str(meta)
        uid = _first_int(r"\bUID (\d+)", text)
        if uid is None:
            continue
        message = None
        if isinstance(body, bytes):
            try:
                message = email.message_from_bytes(body)
            except Exception:
                message = None
        from_name, from_addr = _from(message)
        rows.append(
            {
                "uid": uid,
                "msgid": _first_int(r"X-GM-MSGID (\d+)", text),
                "labels": _labels(text),
                "date": _internaldate(text, message),
                "from_name": from_name,
                "from_addr": from_addr,
                "subject": _subject(message),
            }
        )
    return rows


def _first_int(pattern, text):
    match = re.search(pattern, text)
    return int(match.group(1)) if match else None


def _labels(text):
    match = re.search(r"X-GM-LABELS \((.*?)\)(?:\s|$)", text)
    if not match:
        return []
    inner = match.group(1)
    labels = []
    for quoted, atom in re.findall(r'"((?:[^"\\]|\\.)*)"|([^\s"]+)', inner):
        value = quoted if quoted else atom
        value = re.sub(r"\\(.)", r"\1", value)
        if not value or value.lower() == "\\all":
            continue
        labels.append(SYSTEM_LABELS.get(value.lower(), value))
    return labels


def _internaldate(text, message):
    match = re.search(r'INTERNALDATE "([^"]+)"', text)
    if match:
        raw = match.group(1).strip()
        try:
            from datetime import datetime

            parsed = datetime.strptime(raw, "%d-%b-%Y %H:%M:%S %z")
            return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
    if message is not None:
        raw = message.get("Date")
        if raw:
            try:
                from email.utils import parsedate_to_datetime

                parsed = parsedate_to_datetime(raw)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                pass
    return None


def _from(message):
    if message is None:
        return "", ""
    raw = message.get("From", "") or ""
    name, addr = parseaddr(raw)
    return _decode(name), (addr or "").strip().lower()


def _subject(message):
    if message is None:
        return ""
    raw = message.get("Subject", "") or ""
    return " ".join(_decode(raw).split())


def _decode(value):
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def select_writable(conn, mailbox):
    select(conn, mailbox, readonly=False)


def _store_labels(conn, uids, item, labels, chunk_size=50):
    """Issue +X-GM-LABELS / -X-GM-LABELS for a set of UIDs.

    This is label editing, not deletion: it cannot move anything to Trash or
    out of All Mail by accident, which is why quarantining uses it instead of
    COPY plus a delete.
    """
    total = 0
    uids = list(uids)
    if not uids or not labels:
        return 0
    values = "(" + " ".join(quote(label) for label in labels) + ")"
    for start in range(0, len(uids), chunk_size):
        chunk = uids[start : start + chunk_size]
        uidset = ",".join(str(uid) for uid in chunk)
        typ, data = conn.uid("STORE", uidset, item, values)
        if typ != "OK":
            raise ImapError(
                "%s failed for %s: %s" % (item, uidset, data)
            )
        total += len(chunk)
    return total


def add_labels(conn, uids, labels, chunk_size=50):
    return _store_labels(conn, uids, "+X-GM-LABELS", labels, chunk_size)


def remove_labels(conn, uids, labels, chunk_size=50):
    return _store_labels(conn, uids, "-X-GM-LABELS", labels, chunk_size)


def move_to_trash(conn, uids, trash, chunk_size=50):
    """Move messages to Trash by COPYing them into the Trash mailbox.

    Gmail keeps one copy of each message and treats folders as labels, so a
    COPY into [Gmail]/Trash applies the Trash label to that copy: the message
    leaves All Mail and Inbox and the 30-day deletion clock starts. It is a
    move, not a duplicate, and it is the only deletion mechanism used here.

    The source mailbox must already be selected.
    """
    total = 0
    uids = list(uids)
    for start in range(0, len(uids), chunk_size):
        chunk = uids[start : start + chunk_size]
        uidset = ",".join(str(uid) for uid in chunk)
        typ, data = conn.uid("COPY", uidset, quote(trash))
        if typ != "OK":
            raise ImapError("COPY to %s failed for %s: %s" % (trash, uidset, data))
        total += len(chunk)
    return total


def logout(conn):
    if conn is None:
        return
    try:
        conn.close()
    except Exception:
        pass
    try:
        conn.logout()
    except Exception:
        pass


_logout = logout
