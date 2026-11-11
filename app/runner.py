"""One purge run: search, verify, audit, move to Trash.

The run is serialised by a non-blocking lock: if a scheduled run and an API
"run now" collide, the second one returns immediately instead of opening a
second set of IMAP connections.
"""

import threading
import time
import uuid

from . import blacklist, imap, state

# Never fetch more than this many candidates per sender per mailbox in one run.
# Deleting makes the next search smaller, so progress continues either way.
FETCH_CEILING = 2000

_run_lock = threading.Lock()


def busy():
    return _run_lock.locked()


def _covers(entry, address):
    addr = (address or "").strip().lower()
    if not addr or "@" not in addr:
        return False
    if entry.startswith("@"):
        return addr.rsplit("@", 1)[1] == entry[1:]
    return addr == entry


def run_purge(cfg, dry_run=None, reason="manual"):
    dry = cfg.dry_run if dry_run is None else bool(dry_run)
    if not _run_lock.acquire(blocking=False):
        return {"ok": False, "skipped": "another run is already in progress"}

    run_id = uuid.uuid4().hex[:12]
    started = state.now_iso()
    started_monotonic = time.monotonic()
    summary = {
        "run_id": run_id,
        "reason": reason,
        "dry_run": dry,
        "started": started,
        "entries": 0,
        "mailboxes": [],
        "matched": 0,
        "trashed": 0,
        "would_trash": 0,
        "capped": False,
        "blacklist_errors": [],
        "warnings": [],
        "errors": [],
        "ok": False,
    }
    conn = None
    try:
        entries, parse_errors = blacklist.load(
            cfg.blacklist_path, cfg.allow_freemail_domains
        )
        summary["entries"] = len(entries)
        summary["blacklist_errors"] = parse_errors
        if not entries:
            summary["ok"] = True
            summary["note"] = "blacklist is empty; nothing to do"
            return summary

        conn = imap.connect(cfg.gmail_user, cfg.gmail_password)
        available = imap.list_mailboxes(conn)
        all_mail = imap.find_mailbox(conn, "/all mail", imap.ALL_MAIL)
        if not all_mail:
            raise imap.ImapError(
                "cannot find All Mail over IMAP; folders seen: %s"
                % (", ".join(available) if available else "none")
            )
        mailboxes = [all_mail]
        spam = imap.find_mailbox(conn, "/spam")
        if spam:
            mailboxes.append(spam)
        else:
            summary["warnings"].append(
                "[Gmail]/Spam is not exposed over IMAP, so spam is not swept. "
                "Enable 'Show in IMAP' for Spam under Gmail Settings > Labels."
            )
        summary["mailboxes"] = mailboxes
        summary["folders_seen"] = available

        trash = imap.find_mailbox(conn, "/trash")
        if trash:
            summary["trash"] = trash
        else:
            message = (
                "[Gmail]/Trash is not exposed over IMAP, so messages cannot be "
                "moved to Trash. Enable 'Show in IMAP' for Trash under Gmail "
                "Settings > Labels."
            )
            if not dry:
                # Fail closed: without Trash there is no recoverable delete,
                # and this app must never fall back to a permanent one.
                raise imap.ImapError(message)
            summary["warnings"].append(message + " (dry run continues)")

        for entry in entries:
            for mailbox in mailboxes:
                used = summary["trashed"] + summary["would_trash"]
                remaining = cfg.max_delete_per_run - used
                if remaining <= 0:
                    summary["capped"] = True
                    break
                _purge_entry(
                    conn, cfg, entry, mailbox, dry, remaining, run_id, summary, trash
                )
        summary["ok"] = True
    except Exception as exc:  # noqa: BLE001 - the run must always be recorded
        summary["ok"] = False
        summary["errors"].append(str(exc))
        try:
            state.append_audit(
                cfg.audit_path,
                {
                    "kind": "error",
                    "ts": state.now_iso(),
                    "run_id": run_id,
                    "reason": reason,
                    "error": str(exc),
                },
            )
        except Exception:
            pass
    finally:
        imap.logout(conn)
        _run_lock.release()
        summary["duration_s"] = round(time.monotonic() - started_monotonic, 2)
        summary["finished"] = state.now_iso()
        try:
            state.append_audit(cfg.audit_path, dict(summary, kind="summary"))
            state.update_state(
                cfg.state_path,
                last_run=summary["finished"],
                last_run_id=run_id,
                last_reason=reason,
                last_ok=summary["ok"],
                last_dry_run=dry,
                last_trashed=summary["trashed"],
                last_would_trash=summary["would_trash"],
                last_matched=summary["matched"],
                last_entries=summary["entries"],
                last_capped=summary["capped"],
                last_error=(summary["errors"] or [None])[-1],
                last_duration_s=summary["duration_s"],
                heartbeat=state.now_iso(),
            )
        except Exception:
            pass
    return summary


def _purge_entry(conn, cfg, entry, mailbox, dry, budget, run_id, summary, trash):
    query = "from:%s" % (entry[1:] if entry.startswith("@") else entry)
    try:
        uids = imap.search_uids(conn, query, mailbox)
    except imap.ImapError as exc:
        summary["errors"].append("%s in %s: %s" % (entry, mailbox, exc))
        return
    if not uids:
        return

    candidates = uids[-FETCH_CEILING:]
    try:
        metas = imap.fetch_meta(conn, candidates)
    except imap.ImapError as exc:
        summary["errors"].append("fetch in %s: %s" % (mailbox, exc))
        return

    # Gmail's from: search is a substring match; only exact senders qualify.
    hits = [meta for meta in metas if _covers(entry, meta["from_addr"])]
    if not hits:
        return

    summary["matched"] += len(hits)
    limited = hits[:budget]
    if len(hits) > budget:
        summary["capped"] = True

    for meta in limited:
        try:
            state.append_audit(
                cfg.audit_path,
                {
                    "kind": "message",
                    "ts": state.now_iso(),
                    "run_id": run_id,
                    "dry_run": dry,
                    "entry": entry,
                    "folder": mailbox,
                    "uid": meta["uid"],
                    "msgid": meta["msgid"],
                    "from": meta["from_addr"],
                    "from_name": meta["from_name"],
                    "subject": meta["subject"],
                    "date": meta["date"],
                    "action": "would-trash" if dry else "trashed",
                },
            )
        except OSError as exc:
            summary["errors"].append("audit write failed: %s" % exc)
            return

    if dry:
        summary["would_trash"] += len(limited)
        return

    try:
        imap.select_writable(conn, mailbox)
        summary["trashed"] += imap.move_to_trash(
            conn, [meta["uid"] for meta in limited], trash
        )
    except imap.ImapError as exc:
        summary["errors"].append("trash in %s: %s" % (mailbox, exc))
