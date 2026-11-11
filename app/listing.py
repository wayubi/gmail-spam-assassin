"""Recent-mail listing for the web page and the API.

Read-only: EXAMINE, BODY.PEEK, never STORE. Listing must not mark mail read.
Results are cached for 60 s so clicking around does not hammer IMAP.
"""

import threading
import time

from . import blacklist, imap, quarantine, whitelist

TTL = 60.0

_cache = {}
_lock = threading.Lock()


def invalidate():
    with _lock:
        _cache.clear()


def _cached(key, producer):
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and hit[0] > now:
            return hit[1]
    value = producer()
    with _lock:
        _cache[key] = (time.monotonic() + TTL, value)
    return value


def messages(cfg, days=None, limit=None, folder="all"):
    days = cfg.list_days if days is None else days
    limit = 200 if limit is None else limit
    folder = (folder or "all").lower()
    if folder not in ("all", "inbox", "spam"):
        folder = "all"
    return _cached(
        ("messages", days, limit, folder),
        lambda: _messages(cfg, days, limit, folder),
    )


def _messages(cfg, days, limit, folder):
    conn = imap.connect(cfg.gmail_user, cfg.gmail_password)
    try:
        entries, _ = blacklist.load(cfg.blacklist_path, cfg.allow_freemail_domains)
        hidden, _ = whitelist.load(cfg.whitelist_path)
        held_senders, _ = quarantine.load(cfg.quarantine_path)
        warnings = []
        all_mail = imap.find_mailbox(conn, "/all mail", imap.ALL_MAIL)
        if not all_mail:
            raise imap.ImapError(
                "cannot find All Mail over IMAP; folders seen: %s"
                % (", ".join(imap.list_mailboxes(conn)) or "none")
            )
        targets = []
        if folder in ("all", "inbox"):
            query = "newer_than:%dd" % days
            if folder == "inbox":
                query = "in:inbox " + query
            targets.append((all_mail, "all", query))
        if folder in ("all", "spam"):
            spam = imap.find_mailbox(conn, "/spam")
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
        hidden_count = 0
        for mailbox, kind, query in targets:
            uids = imap.search_uids(conn, query, mailbox)
            scanned += len(uids)
            for meta in imap.fetch_meta(conn, uids[-limit:] if limit else uids):
                key = meta["msgid"] or ("uid:%s" % meta["uid"])
                if key in seen:
                    continue
                seen.add(key)
                if whitelist.matches(meta["from_addr"], hidden):
                    hidden_count += 1
                    continue
                rows.append(_row(meta, kind, entries, held_senders))
        rows.sort(key=lambda row: row["date"] or "", reverse=True)
        return {
            "days": days,
            "folder": folder,
            "scanned": scanned,
            "count": len(rows[:limit]),
            "hidden": hidden_count,
            "warnings": warnings,
            "messages": rows[:limit],
        }
    finally:
        imap.logout(conn)


def _row(meta, kind, entries, held_senders):
    return {
        "uid": meta["uid"],
        "msgid": meta["msgid"],
        "date": meta["date"],
        "from_name": meta["from_name"],
        "from_addr": meta["from_addr"],
        "subject": meta["subject"],
        "labels": meta["labels"],
        "folder": "Spam" if kind == "spam" else "All Mail",
        "blacklisted": blacklist.matches(meta["from_addr"], entries),
        "quarantined": quarantine.matches(meta["from_addr"], held_senders),
    }


def senders(cfg, days=None, limit=None):
    days = cfg.list_days if days is None else days
    limit = 200 if limit is None else limit
    return _cached(("senders", days, limit), lambda: _senders(cfg, days, limit))


def _senders(cfg, days, limit):
    data = _messages(cfg, days, 1000, "all")
    groups = {}
    for row in data["messages"]:
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
                "blacklisted": row["blacklisted"],
                "quarantined": row["quarantined"],
            }
        group["count"] += 1
        group["labels"].update(row["labels"])
        if row["date"] and (group["latest_date"] or "") < row["date"]:
            group["latest_date"] = row["date"]
            group["latest_subject"] = row["subject"]
            if row["from_name"]:
                group["name"] = row["from_name"]
        if row["blacklisted"]:
            group["blacklisted"] = row["blacklisted"]
        if row["quarantined"]:
            group["quarantined"] = row["quarantined"]

    items = []
    for group in groups.values():
        group["labels"] = sorted(group["labels"])
        items.append(group)
    items.sort(key=lambda group: (-group["count"], group["address"]))
    items = items[:limit]
    return {
        "days": days,
        "count": len(items),
        "hidden": data.get("hidden", 0),
        "warnings": data.get("warnings", []),
        "senders": items,
    }
