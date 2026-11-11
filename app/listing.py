"""Recent-mail listing for the web page and the API.

Read-only: EXAMINE, BODY.PEEK, never STORE. Listing must not mark mail read.

Two caches, on purpose:

  * raw metadata is expensive (IMAP) and depends only on the folder/window;
  * list membership is cheap and changes whenever a list is edited.

So a list edit never touches IMAP: the flags and whitelist hiding are applied
at response time. Raw rows are invalidated after a live run that changed mail,
or on an explicit Refresh. The shared read-only connection and per-key
single-flight keep parallel browser requests from opening duplicate sessions.
"""

import threading
import time

from . import blacklist, imap, quarantine, whitelist

TTL = 60.0
RAW_LIMIT = 1000

_cache = {}
_inflight = {}
_lock = threading.Lock()

_conn = None
_conn_key = None
_conn_lock = threading.RLock()


def invalidate():
    with _lock:
        _cache.clear()
    _drop_connection()


def _drop_connection():
    global _conn, _conn_key
    with _conn_lock:
        if _conn is not None:
            try:
                imap.logout(_conn)
            except Exception:
                pass
        _conn = None
        _conn_key = None


def _with_connection(cfg, work):
    """Run `work(conn)` on one shared, read-only listing connection."""
    global _conn, _conn_key
    key = (cfg.gmail_user, cfg.gmail_password)
    with _conn_lock:
        if _conn is None or _conn_key != key:
            if _conn is not None:
                try:
                    imap.logout(_conn)
                except Exception:
                    pass
            _conn = imap.connect(cfg.gmail_user, cfg.gmail_password)
            _conn_key = key
        try:
            return work(_conn)
        except Exception:
            try:
                imap.logout(_conn)
            except Exception:
                pass
            _conn = None
            _conn_key = None
            raise


def _cached(key, producer):
    """Per-key single-flight: one producer, all concurrent callers wait."""
    while True:
        with _lock:
            hit = _cache.get(key)
            if hit is not None and hit[0] > time.monotonic():
                return hit[1]
            event = _inflight.get(key)
            leader = event is None
            if leader:
                event = threading.Event()
                _inflight[key] = event
        if leader:
            try:
                value = producer()
                with _lock:
                    _cache[key] = (time.monotonic() + TTL, value)
                return value
            finally:
                with _lock:
                    _inflight.pop(key, None)
                event.set()
        event.wait(60)


def messages(cfg, days=None, limit=None, folder="all"):
    days = cfg.list_days if days is None else days
    limit = 200 if limit is None else limit
    folder = (folder or "all").lower()
    if folder not in ("all", "inbox", "spam"):
        folder = "all"
    raw = _raw(cfg, days, folder)
    entries, _ = blacklist.load(cfg.blacklist_path, cfg.allow_freemail_domains)
    hidden, _ = whitelist.load(cfg.whitelist_path)
    held, _ = quarantine.load(cfg.quarantine_path)
    rows = []
    hidden_count = 0
    for row in raw["rows"]:
        if whitelist.matches(row["from_addr"], hidden):
            hidden_count += 1
            continue
        rows.append(_decorate(row, entries, held))
    return {
        "days": days,
        "folder": folder,
        "scanned": raw["scanned"],
        "count": len(rows[:limit]),
        "hidden": hidden_count,
        "warnings": raw["warnings"],
        "messages": rows[:limit],
    }


def senders(cfg, days=None, limit=None):
    days = cfg.list_days if days is None else days
    limit = 200 if limit is None else limit
    raw = _raw(cfg, days, "all")
    entries, _ = blacklist.load(cfg.blacklist_path, cfg.allow_freemail_domains)
    hidden, _ = whitelist.load(cfg.whitelist_path)
    held, _ = quarantine.load(cfg.quarantine_path)

    groups = {}
    hidden_count = 0
    for row in raw["rows"]:
        if whitelist.matches(row["from_addr"], hidden):
            hidden_count += 1
            continue
        address = row["from_addr"] or "(unknown)"
        group = groups.get(address)
        if group is None:
            group = groups[address] = {
                "address": address,
                "name": row["from_name"],
                "count": 0,
                "latest_subject": row["subject"],
                "latest_date": row["date"],
                "labels": set(),
                "blacklisted": blacklist.matches(address, entries),
                "quarantined": quarantine.matches(address, held),
            }
        group["count"] += 1
        group["labels"].update(row["labels"])
        if row["date"] and (group["latest_date"] or "") < row["date"]:
            group["latest_date"] = row["date"]
            group["latest_subject"] = row["subject"]
            if row["from_name"]:
                group["name"] = row["from_name"]

    items = []
    for group in groups.values():
        group["labels"] = sorted(group["labels"])
        items.append(group)
    items.sort(key=lambda group: (-group["count"], group["address"]))
    items = items[:limit]
    return {
        "days": days,
        "count": len(items),
        "hidden": hidden_count,
        "warnings": raw["warnings"],
        "senders": items,
    }


def _raw(cfg, days, folder):
    return _cached(
        ("raw", days, folder),
        lambda: _with_connection(cfg, lambda conn: _fetch_raw(conn, cfg, days, folder)),
    )


def _fetch_raw(conn, cfg, days, folder):
    warnings = []
    names = imap.list_mailboxes(conn)
    all_mail = imap.match_mailbox(names, "/all mail", imap.ALL_MAIL)
    if not all_mail:
        raise imap.ImapError(
            "cannot find All Mail over IMAP; folders seen: %s"
            % (", ".join(names) or "none")
        )
    targets = []
    if folder in ("all", "inbox"):
        query = "newer_than:%dd" % days
        if folder == "inbox":
            query = "in:inbox " + query
        targets.append((all_mail, "all", query))
    if folder in ("all", "spam"):
        spam = imap.match_mailbox(names, "/spam")
        if spam:
            targets.append((spam, "spam", "newer_than:%dd" % days))
        else:
            warnings.append(
                "[Gmail]/Spam is not exposed over IMAP; spam is not listed. "
                "Enable 'Show in IMAP' for Spam under Gmail Settings > Labels."
            )

    rows = []
    seen = set()
    scanned = 0
    for mailbox, kind, query in targets:
        uids = imap.search_uids(conn, query, mailbox)
        scanned += len(uids)
        for meta in imap.fetch_meta(conn, uids[-RAW_LIMIT:] if uids else []):
            key = meta["msgid"] or ("uid:%s" % meta["uid"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "uid": meta["uid"],
                    "msgid": meta["msgid"],
                    "date": meta["date"],
                    "from_name": meta["from_name"],
                    "from_addr": meta["from_addr"],
                    "subject": meta["subject"],
                    "labels": meta["labels"],
                    "folder": "Spam" if kind == "spam" else "All Mail",
                }
            )
    rows.sort(key=lambda row: row["date"] or "", reverse=True)
    return {
        "rows": rows,
        "scanned": scanned,
        "warnings": warnings,
    }


def _decorate(row, entries, held):
    return dict(
        row,
        blacklisted=blacklist.matches(row["from_addr"], entries),
        quarantined=quarantine.matches(row["from_addr"], held),
    )
